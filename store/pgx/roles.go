package wardnpgx

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/MogRex-Limited/wardn"
)

// CreateRole implements wardn.Store.
func (s *Store) CreateRole(ctx context.Context, r wardn.CustomRole) error {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO "+s.t.roles+
			" (id, owner_type, owner_id, name, name_key, description, version, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
			r.ID, r.Owner.Type, r.Owner.ID, r.Name, r.NameKey, r.Description, r.Version, r.CreatedAt.UnixMicro(), r.UpdatedAt.UnixMicro())
		if err != nil {
			return nameWriteError{err}
		}
		return s.writeRoleDetails(ctx, tx, r)
	})
	return s.nameTakenOr(ctx, r, err)
}

// UpdateRole implements wardn.Store.
func (s *Store) UpdateRole(ctx context.Context, r wardn.CustomRole, expectedVersion int) error {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE "+s.t.roles+
			" SET name = $1, name_key = $2, description = $3, version = $4, updated_at = $5 WHERE id = $6 AND version = $7",
			r.Name, r.NameKey, r.Description, r.Version, r.UpdatedAt.UnixMicro(), r.ID, expectedVersion)
		if err != nil {
			return nameWriteError{err}
		}
		if tag.RowsAffected() == 0 {
			var exists bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM "+s.t.roles+" WHERE id = $1)", r.ID).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return wardn.ErrRoleNotFound
			}
			return wardn.ErrConflict
		}
		for _, table := range []string{s.t.roleRules, s.t.roleAssignable} {
			if _, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE role_id = $1", r.ID); err != nil {
				return err
			}
		}
		return s.writeRoleDetails(ctx, tx, r)
	})
	return s.nameTakenOr(ctx, r, err)
}

// nameWriteError marks a failed write of a role's name, which may have hit
// the unique name constraint.
type nameWriteError struct{ err error }

func (e nameWriteError) Error() string { return e.err.Error() }
func (e nameWriteError) Unwrap() error { return e.err }

// nameTakenOr returns ErrRoleNameTaken if err is a failed name write and
// another role in r's owner has r's name key. Otherwise it returns err. It
// runs after the failed write has been rolled back, so it also works
// inside an application transaction.
func (s *Store) nameTakenOr(ctx context.Context, r wardn.CustomRole, err error) error {
	var nw nameWriteError
	if !errors.As(err, &nw) {
		return err
	}
	if ctx.Err() != nil {
		return nw.err
	}
	var taken bool
	q := "SELECT EXISTS (SELECT 1 FROM " + s.t.roles + " WHERE owner_type = $1 AND owner_id = $2 AND name_key = $3 AND id <> $4)"
	if s.conn(ctx).QueryRow(ctx, q, r.Owner.Type, r.Owner.ID, r.NameKey, r.ID).Scan(&taken) == nil && taken {
		return wardn.ErrRoleNameTaken
	}
	return nw.err
}

func (s *Store) writeRoleDetails(ctx context.Context, tx pgx.Tx, r wardn.CustomRole) error {
	if len(r.Allow) > 0 {
		positions := make([]int, len(r.Allow))
		for i := range positions {
			positions[i] = i
		}
		if _, err := tx.Exec(ctx, "INSERT INTO "+s.t.roleRules+" (role_id, position, effect, permission)"+
			" SELECT $1, p, 'allow', perm FROM unnest($2::bigint[], $3::varchar[]) AS u(p, perm)",
			r.ID, positions, r.Allow); err != nil {
			return err
		}
	}
	if len(r.AssignableAt) > 0 {
		positions := make([]int, len(r.AssignableAt))
		for i := range positions {
			positions[i] = i
		}
		if _, err := tx.Exec(ctx, "INSERT INTO "+s.t.roleAssignable+" (role_id, position, scope_type)"+
			" SELECT $1, p, st FROM unnest($2::bigint[], $3::varchar[]) AS u(p, st)",
			r.ID, positions, r.AssignableAt); err != nil {
			return err
		}
	}
	return nil
}

// DeleteRole implements wardn.Store.
func (s *Store) DeleteRole(ctx context.Context, id string) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		for _, table := range []string{s.t.roleRules, s.t.roleAssignable, s.t.roles} {
			col := "role_id"
			if table == s.t.roles {
				col = "id"
			}
			if _, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE "+col+" = $1", id); err != nil {
				return err
			}
		}
		return nil
	})
}

// Roles implements wardn.Store.
func (s *Store) Roles(ctx context.Context, ids []string) ([]wardn.CustomRole, error) {
	if len(ids) == 0 {
		return nil, ctx.Err()
	}
	if len(ids) > maxIDs {
		return nil, fmt.Errorf("wardnpgx: %d role IDs in one query; the maximum is %d", len(ids), maxIDs)
	}
	return s.loadRoles(ctx, "id = ANY($1::varchar[])", ids)
}

// RolesOwnedBy implements wardn.Store.
func (s *Store) RolesOwnedBy(ctx context.Context, owners []wardn.Scope) ([]wardn.CustomRole, error) {
	if len(owners) == 0 {
		return nil, ctx.Err()
	}
	if len(owners) > maxIDs {
		return nil, fmt.Errorf("wardnpgx: %d owners in one query; the maximum is %d", len(owners), maxIDs)
	}
	types, ids := make([]string, len(owners)), make([]string, len(owners))
	for i, o := range owners {
		types[i], ids[i] = o.Type, o.ID
	}
	return s.loadRoles(ctx, "(owner_type, owner_id) IN (SELECT * FROM unnest($1::varchar[], $2::varchar[]))", types, ids)
}

// loadRoles reads roles matching where (a fixed fragment; values are in
// args) together with their rules and assignable types.
func (s *Store) loadRoles(ctx context.Context, where string, args ...any) ([]wardn.CustomRole, error) {
	q := s.conn(ctx)
	rows, err := q.Query(ctx, "SELECT id, owner_type, owner_id, name, name_key, description, version, created_at, updated_at FROM "+
		s.t.roles+" WHERE "+where+" ORDER BY id", args...)
	if err != nil {
		return nil, fmt.Errorf("wardnpgx: reading roles: %w", err)
	}
	roles, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (wardn.CustomRole, error) {
		var r wardn.CustomRole
		var created, updated int64
		err := row.Scan(&r.ID, &r.Owner.Type, &r.Owner.ID, &r.Name, &r.NameKey, &r.Description, &r.Version, &created, &updated)
		r.CreatedAt, r.UpdatedAt = time.UnixMicro(created).UTC(), time.UnixMicro(updated).UTC()
		return r, err
	})
	if err != nil {
		return nil, fmt.Errorf("wardnpgx: reading roles: %w", err)
	}
	if len(roles) == 0 {
		return nil, nil
	}
	index := make(map[string]int, len(roles))
	ids := make([]string, len(roles))
	for i, r := range roles {
		index[r.ID], ids[i] = i, r.ID
	}

	rows, err = q.Query(ctx, "SELECT role_id, effect, permission FROM "+s.t.roleRules+
		" WHERE role_id = ANY($1::varchar[]) ORDER BY role_id, position", ids)
	if err != nil {
		return nil, fmt.Errorf("wardnpgx: reading role permissions: %w", err)
	}
	var id, effect, value string
	_, err = pgx.ForEachRow(rows, []any{&id, &effect, &value}, func() error {
		if i, ok := index[id]; ok && effect == "allow" { // custom roles only grant (design decision D2)
			roles[i].Allow = append(roles[i].Allow, value)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("wardnpgx: reading role permissions: %w", err)
	}

	rows, err = q.Query(ctx, "SELECT role_id, scope_type FROM "+s.t.roleAssignable+
		" WHERE role_id = ANY($1::varchar[]) ORDER BY role_id, position", ids)
	if err != nil {
		return nil, fmt.Errorf("wardnpgx: reading role scope types: %w", err)
	}
	_, err = pgx.ForEachRow(rows, []any{&id, &value}, func() error {
		if i, ok := index[id]; ok {
			roles[i].AssignableAt = append(roles[i].AssignableAt, value)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("wardnpgx: reading role scope types: %w", err)
	}
	return roles, nil
}
