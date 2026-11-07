package wardnsql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MogRex-Limited/wardn"
)

// maxIDs bounds the role IDs or owners in one query.
const maxIDs = 256

// placeholders returns "?, ?, ..." for n values.
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}

// CreateRole implements wardn.Store.
func (s *Store) CreateRole(ctx context.Context, r wardn.CustomRole) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, s.d.bind("INSERT INTO "+s.t.roles+
			" (id, owner_type, owner_id, name, name_key, description, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"),
			r.ID, r.Owner.Type, r.Owner.ID, r.Name, r.NameKey, r.Description, r.Version, r.CreatedAt.UnixMicro(), r.UpdatedAt.UnixMicro())
		if err != nil {
			return s.nameTakenOr(ctx, r, err)
		}
		return s.writeRoleDetails(ctx, tx, r)
	})
}

// UpdateRole implements wardn.Store.
func (s *Store) UpdateRole(ctx context.Context, r wardn.CustomRole, expectedVersion int) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, s.d.bind("UPDATE "+s.t.roles+
			" SET name = ?, name_key = ?, description = ?, version = ?, updated_at = ? WHERE id = ? AND version = ?"),
			r.Name, r.NameKey, r.Description, r.Version, r.UpdatedAt.UnixMicro(), r.ID, expectedVersion)
		if err != nil {
			return s.nameTakenOr(ctx, r, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			var exists int
			if err := tx.QueryRowContext(ctx, s.d.bind("SELECT COUNT(*) FROM "+s.t.roles+" WHERE id = ?"), r.ID).Scan(&exists); err != nil {
				return err
			}
			if exists == 0 {
				return wardn.ErrRoleNotFound
			}
			return wardn.ErrConflict
		}
		for _, table := range []string{s.t.roleRules, s.t.roleAssignable} {
			if _, err := tx.ExecContext(ctx, s.d.bind("DELETE FROM "+table+" WHERE role_id = ?"), r.ID); err != nil {
				return err
			}
		}
		return s.writeRoleDetails(ctx, tx, r)
	})
}

// nameTakenOr returns ErrRoleNameTaken if another role in r's owner has r's
// name key (the write failed on the unique constraint), and err otherwise.
// Checking afterwards keeps the store independent of driver error codes;
// the constraint itself guarantees atomicity.
func (s *Store) nameTakenOr(ctx context.Context, r wardn.CustomRole, err error) error {
	if ctx.Err() != nil {
		return err
	}
	var n int
	q := s.d.bind("SELECT COUNT(*) FROM " + s.t.roles + " WHERE owner_type = ? AND owner_id = ? AND name_key = ? AND id <> ?")
	if s.db.QueryRowContext(ctx, q, r.Owner.Type, r.Owner.ID, r.NameKey, r.ID).Scan(&n) == nil && n > 0 {
		return wardn.ErrRoleNameTaken
	}
	return err
}

func (s *Store) writeRoleDetails(ctx context.Context, tx *sql.Tx, r wardn.CustomRole) error {
	insertRule := s.d.bind("INSERT INTO " + s.t.roleRules + " (role_id, position, effect, permission) VALUES (?, ?, ?, ?)")
	for i, p := range r.Allow {
		if _, err := tx.ExecContext(ctx, insertRule, r.ID, i, "allow", p); err != nil {
			return err
		}
	}
	insertType := s.d.bind("INSERT INTO " + s.t.roleAssignable + " (role_id, position, scope_type) VALUES (?, ?, ?)")
	for i, st := range r.AssignableAt {
		if _, err := tx.ExecContext(ctx, insertType, r.ID, i, st); err != nil {
			return err
		}
	}
	return nil
}

// DeleteRole implements wardn.Store.
func (s *Store) DeleteRole(ctx context.Context, id string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for _, table := range []string{s.t.roleRules, s.t.roleAssignable} {
			if _, err := tx.ExecContext(ctx, s.d.bind("DELETE FROM "+table+" WHERE role_id = ?"), id); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, s.d.bind("DELETE FROM "+s.t.roles+" WHERE id = ?"), id)
		return err
	})
}

// Roles implements wardn.Store.
func (s *Store) Roles(ctx context.Context, ids []string) ([]wardn.CustomRole, error) {
	if len(ids) == 0 {
		return nil, ctx.Err()
	}
	if len(ids) > maxIDs {
		return nil, fmt.Errorf("wardnsql: %d role IDs in one query; the maximum is %d", len(ids), maxIDs)
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return s.loadRoles(ctx, "id IN ("+placeholders(len(ids))+")", args)
}

// RolesOwnedBy implements wardn.Store.
func (s *Store) RolesOwnedBy(ctx context.Context, owners []wardn.Scope) ([]wardn.CustomRole, error) {
	if len(owners) == 0 {
		return nil, ctx.Err()
	}
	if len(owners) > maxIDs {
		return nil, fmt.Errorf("wardnsql: %d owners in one query; the maximum is %d", len(owners), maxIDs)
	}
	conds := make([]string, len(owners))
	args := make([]any, 0, 2*len(owners))
	for i, o := range owners {
		conds[i] = "(owner_type = ? AND owner_id = ?)"
		args = append(args, o.Type, o.ID)
	}
	return s.loadRoles(ctx, strings.Join(conds, " OR "), args)
}

// loadRoles reads roles matching where (built only from fixed fragments;
// values are in args) together with their rules and assignable types.
func (s *Store) loadRoles(ctx context.Context, where string, args []any) ([]wardn.CustomRole, error) {
	rows, err := s.db.QueryContext(ctx, s.d.bind("SELECT id, owner_type, owner_id, name, name_key, description, version, created_at, updated_at FROM "+
		s.t.roles+" WHERE "+where+" ORDER BY id"), args...)
	if err != nil {
		return nil, fmt.Errorf("wardnsql: reading roles: %w", err)
	}
	var roles []wardn.CustomRole
	index := map[string]int{}
	err = func() error {
		defer rows.Close() //nolint:errcheck // rows.Err is checked below
		for rows.Next() {
			var r wardn.CustomRole
			var created, updated int64
			if err := rows.Scan(&r.ID, &r.Owner.Type, &r.Owner.ID, &r.Name, &r.NameKey, &r.Description, &r.Version, &created, &updated); err != nil {
				return err
			}
			r.CreatedAt, r.UpdatedAt = time.UnixMicro(created).UTC(), time.UnixMicro(updated).UTC()
			index[r.ID] = len(roles)
			roles = append(roles, r)
		}
		return rows.Err()
	}()
	if err != nil {
		return nil, fmt.Errorf("wardnsql: reading roles: %w", err)
	}
	if len(roles) == 0 {
		return nil, nil
	}

	ids := make([]any, len(roles))
	for i, r := range roles {
		ids[i] = r.ID
	}
	in := "role_id IN (" + placeholders(len(ids)) + ")"
	err = s.eachRow(ctx, "SELECT role_id, effect, permission FROM "+s.t.roleRules+" WHERE "+in+" ORDER BY role_id, position", ids,
		func(rows *sql.Rows) error {
			var id, effect, perm string
			if err := rows.Scan(&id, &effect, &perm); err != nil {
				return err
			}
			if i, ok := index[id]; ok && effect == "allow" { // custom roles only grant (design decision D2)
				roles[i].Allow = append(roles[i].Allow, perm)
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("wardnsql: reading role permissions: %w", err)
	}
	err = s.eachRow(ctx, "SELECT role_id, scope_type FROM "+s.t.roleAssignable+" WHERE "+in+" ORDER BY role_id, position", ids,
		func(rows *sql.Rows) error {
			var id, st string
			if err := rows.Scan(&id, &st); err != nil {
				return err
			}
			if i, ok := index[id]; ok {
				roles[i].AssignableAt = append(roles[i].AssignableAt, st)
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("wardnsql: reading role scope types: %w", err)
	}
	return roles, nil
}

func (s *Store) eachRow(ctx context.Context, query string, args []any, fn func(*sql.Rows) error) error {
	rows, err := s.db.QueryContext(ctx, s.d.bind(query), args...)
	if err != nil {
		return err
	}
	defer rows.Close() //nolint:errcheck // rows.Err is checked below
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// RoleInUse implements wardn.Store.
func (s *Store) RoleInUse(ctx context.Context, role string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, s.d.bind("SELECT 1 FROM "+s.t.assignments+" WHERE role = ? LIMIT 1"), role).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("wardnsql: checking role use: %w", err)
	}
	return true, nil
}

// RevokeRole implements wardn.Store.
func (s *Store) RevokeRole(ctx context.Context, role string) error {
	if _, err := s.db.ExecContext(ctx, s.d.bind("DELETE FROM "+s.t.assignments+" WHERE role = ?"), role); err != nil {
		return fmt.Errorf("wardnsql: revoking role: %w", err)
	}
	return nil
}

// Members implements wardn.Store.
func (s *Store) Members(ctx context.Context, scope wardn.Scope, cursor string, limit int) ([]wardn.Assignment, string, error) {
	afterUser, afterRole, err := wardn.DecodeMemberCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	if limit <= 0 {
		limit = 1
	}
	c := s.d.byteOrder
	query := "SELECT user_id, role, starts_at, expires_at FROM " + s.t.assignments +
		" WHERE scope_type = ? AND scope_id = ? AND (user_id" + c + " > ? OR (user_id = ? AND role" + c + " > ?))" +
		" ORDER BY user_id" + c + ", role" + c + " LIMIT ?"
	args := []any{scope.Type, scope.ID, afterUser, afterUser, afterRole, limit + 1}
	var page []wardn.Assignment
	err = s.eachRow(ctx, query, args, func(rows *sql.Rows) error {
		a := wardn.Assignment{Scope: scope}
		var starts, expires sql.NullInt64
		if err := rows.Scan(&a.User, &a.Role, &starts, &expires); err != nil {
			return err
		}
		a.StartsAt, a.ExpiresAt = fromMicros(starts), fromMicros(expires)
		page = append(page, a)
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("wardnsql: listing members: %w", err)
	}
	next := ""
	if len(page) > limit {
		page = page[:limit]
		last := page[len(page)-1]
		next = wardn.EncodeMemberCursor(last.User, last.Role)
	}
	return page, next, nil
}

// ExpiredUnreported implements wardn.Store.
func (s *Store) ExpiredUnreported(ctx context.Context, t time.Time, limit int) ([]wardn.Assignment, error) {
	if limit <= 0 {
		limit = 1
	}
	query := "SELECT user_id, role, scope_type, scope_id, starts_at, expires_at FROM " + s.t.assignments +
		" WHERE expires_at IS NOT NULL AND expires_at <= ? AND expiry_reported_at IS NULL ORDER BY expires_at LIMIT ?"
	var out []wardn.Assignment
	err := s.eachRow(ctx, query, []any{t.UnixMicro(), limit}, func(rows *sql.Rows) error {
		var a wardn.Assignment
		var starts, expires sql.NullInt64
		if err := rows.Scan(&a.User, &a.Role, &a.Scope.Type, &a.Scope.ID, &starts, &expires); err != nil {
			return err
		}
		a.StartsAt, a.ExpiresAt = fromMicros(starts), fromMicros(expires)
		out = append(out, a)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("wardnsql: finding expired assignments: %w", err)
	}
	return out, nil
}

// MarkExpiryReported implements wardn.Store. The expires_at condition
// leaves an assignment unmarked if it was assigned again with a new window.
func (s *Store) MarkExpiryReported(ctx context.Context, as []wardn.Assignment) error {
	if len(as) == 0 {
		return ctx.Err()
	}
	now := time.Now().UnixMicro()
	update := s.d.bind("UPDATE " + s.t.assignments + " SET expiry_reported_at = ?" +
		" WHERE user_id = ? AND role = ? AND scope_type = ? AND scope_id = ? AND expires_at = ?")
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for _, a := range as {
			if _, err := tx.ExecContext(ctx, update, now, a.User, a.Role, a.Scope.Type, a.Scope.ID, endMicros(a.ExpiresAt)); err != nil {
				return fmt.Errorf("wardnsql: marking expiry: %w", err)
			}
		}
		return nil
	})
}

// RevokeExpired implements wardn.Store: one conditional DELETE, so an
// assignment given a new window meanwhile is left alone.
func (s *Store) RevokeExpired(ctx context.Context, a wardn.Assignment) error {
	_, err := s.db.ExecContext(ctx, s.d.bind("DELETE FROM "+s.t.assignments+
		" WHERE user_id = ? AND role = ? AND scope_type = ? AND scope_id = ? AND expires_at = ?"),
		a.User, a.Role, a.Scope.Type, a.Scope.ID, endMicros(a.ExpiresAt))
	if err != nil {
		return fmt.Errorf("wardnsql: removing expired assignment: %w", err)
	}
	return nil
}

// inTx runs fn in a transaction, committing if it succeeds.
func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
