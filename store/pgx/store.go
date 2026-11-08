// Package wardnpgx is a wardn.Store for PostgreSQL that uses pgx directly,
// for applications built on pgx rather than database/sql.
//
//	pool, _ := pgxpool.New(ctx, dsn)
//	store := wardnpgx.MustNew(pool)
//	w := wardn.MustNew(wardn.Config{File: "wardn.yaml", Store: store})
//
// It can change access inside the application's own pgx transaction, so a
// role assignment commits or rolls back with everything else (Store.WithTx).
//
// It uses the same tables as the SQL store (wardn/store/sql) on PostgreSQL:
// the same names, columns, indexes, schema versions and migration lock. A
// database can move from one store to the other, and both can run against
// it at once. wardn.New creates the tables automatically (see
// Store.Migrate). Every value is passed as a query parameter; table names
// come only from a validated prefix.
package wardnpgx

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/MogRex-Limited/wardn"
)

// DefaultTablePrefix is prepended to the names of wardn's tables. It is the
// SQL store's default too.
const DefaultTablePrefix = "wardn_"

// maxScopes bounds the scopes in one Assignments query, as in the SQL
// store. wardn asks for at most 32 at a time.
const maxScopes = 64

// maxIDs bounds the role IDs or owners in one query.
const maxIDs = 256

// DB is what the store needs from the database: a *pgxpool.Pool (usual) or
// a *pgx.Conn (single-connection tools and tests).
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store is a wardn.Store backed by PostgreSQL through pgx. It is safe for
// concurrent use.
type Store struct {
	db     DB
	prefix string
	t      tables
	q      queries
}

type tables struct {
	assignments, links, migrations   string
	roles, roleRules, roleAssignable string
}

type queries struct {
	assign, revoke, assignments, link, parent   string
	members, expired, markExpiry, revokeExpired string
	roleInUse, revokeRole                       string
}

// Option configures a Store.
type Option func(*options)

type options struct{ prefix string }

// WithTablePrefix sets the prefix of wardn's table names (default
// "wardn_"). It must be 1–32 characters: lowercase letters, digits and '_',
// starting with a letter. Use the same prefix as any SQL store sharing the
// database.
func WithTablePrefix(prefix string) Option {
	return func(o *options) { o.prefix = prefix }
}

// New returns a Store using db. It does not touch the database; call
// Migrate (wardn.New does) to create the tables.
func New(db DB, opts ...Option) (*Store, error) {
	if db == nil {
		return nil, errors.New("wardnpgx: db is nil")
	}
	o := options{prefix: DefaultTablePrefix}
	for _, opt := range opts {
		opt(&o)
	}
	if !validPrefix(o.prefix) {
		return nil, fmt.Errorf("wardnpgx: invalid table prefix %q: use 1-32 lowercase letters, digits and '_', starting with a letter", o.prefix)
	}
	s := &Store{db: db, prefix: o.prefix}
	p := o.prefix
	s.t = tables{
		assignments:    p + "assignments",
		links:          p + "scope_links",
		migrations:     p + "schema_migrations",
		roles:          p + "roles",
		roleRules:      p + "role_rules",
		roleAssignable: p + "role_assignable",
	}
	a := s.t.assignments
	s.q = queries{
		assign: "INSERT INTO " + a +
			" (user_id, role, scope_type, scope_id, starts_at, expires_at, created_at, updated_at, expiry_reported_at)" +
			" VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL)" +
			" ON CONFLICT (user_id, scope_type, scope_id, role) DO UPDATE SET starts_at = excluded.starts_at," +
			" expires_at = excluded.expires_at, updated_at = excluded.updated_at, expiry_reported_at = excluded.expiry_reported_at",
		revoke: "DELETE FROM " + a + " WHERE user_id = $1 AND role = $2 AND scope_type = $3 AND scope_id = $4",
		assignments: "SELECT role, scope_type, scope_id, starts_at, expires_at FROM " + a +
			" WHERE user_id = $1 AND (scope_type, scope_id) IN (SELECT * FROM unnest($2::varchar[], $3::varchar[]))",
		link: "INSERT INTO " + s.t.links + " (child_type, child_id, parent_type, parent_id, updated_at) VALUES ($1, $2, $3, $4, $5)" +
			" ON CONFLICT (child_type, child_id) DO UPDATE SET parent_type = excluded.parent_type," +
			" parent_id = excluded.parent_id, updated_at = excluded.updated_at",
		parent: "SELECT parent_type, parent_id FROM " + s.t.links + " WHERE child_type = $1 AND child_id = $2",
		// COLLATE "C": byte order, so pages are stable and identical to the
		// SQL store's on every database.
		members: "SELECT user_id, role, starts_at, expires_at FROM " + a +
			` WHERE scope_type = $1 AND scope_id = $2 AND (user_id COLLATE "C" > $3 OR (user_id = $3 AND role COLLATE "C" > $4))` +
			` ORDER BY user_id COLLATE "C", role COLLATE "C" LIMIT $5`,
		expired: "SELECT user_id, role, scope_type, scope_id, starts_at, expires_at FROM " + a +
			" WHERE expires_at IS NOT NULL AND expires_at <= $1 AND expiry_reported_at IS NULL ORDER BY expires_at LIMIT $2",
		markExpiry: "UPDATE " + a + " SET expiry_reported_at = $1" +
			" WHERE user_id = $2 AND role = $3 AND scope_type = $4 AND scope_id = $5 AND expires_at = $6",
		revokeExpired: "DELETE FROM " + a +
			" WHERE user_id = $1 AND role = $2 AND scope_type = $3 AND scope_id = $4 AND expires_at = $5",
		roleInUse:  "SELECT EXISTS (SELECT 1 FROM " + a + " WHERE role = $1)",
		revokeRole: "DELETE FROM " + a + " WHERE role = $1",
	}
	return s, nil
}

// MustNew is like New but panics on error, for use in main().
func MustNew(db DB, opts ...Option) *Store {
	s, err := New(db, opts...)
	if err != nil {
		panic(err)
	}
	return s
}

// TablePrefix returns the prefix of the store's table names.
func (s *Store) TablePrefix() string { return s.prefix }

func validPrefix(p string) bool {
	if p == "" || len(p) > 32 || p[0] < 'a' || p[0] > 'z' {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// Assign implements wardn.Store.
func (s *Store) Assign(ctx context.Context, a wardn.Assignment) error {
	now := time.Now().UnixMicro()
	err := s.exec(ctx, s.q.assign, a.User, a.Role, a.Scope.Type, a.Scope.ID,
		startMicros(a.StartsAt), endMicros(a.ExpiresAt), now, now)
	if err != nil {
		return fmt.Errorf("wardnpgx: assign: %w", err)
	}
	return nil
}

// Revoke implements wardn.Store.
func (s *Store) Revoke(ctx context.Context, user, role string, scope wardn.Scope) error {
	if err := s.exec(ctx, s.q.revoke, user, role, scope.Type, scope.ID); err != nil {
		return fmt.Errorf("wardnpgx: revoke: %w", err)
	}
	return nil
}

// Assignments implements wardn.Store.
func (s *Store) Assignments(ctx context.Context, user string, scopes []wardn.Scope) ([]wardn.Assignment, error) {
	if len(scopes) == 0 {
		return nil, ctx.Err()
	}
	if len(scopes) > maxScopes {
		return nil, fmt.Errorf("wardnpgx: %d scopes in one query; the maximum is %d", len(scopes), maxScopes)
	}
	types, ids := make([]string, len(scopes)), make([]string, len(scopes))
	for i, sc := range scopes {
		types[i], ids[i] = sc.Type, sc.ID
	}
	rows, err := s.conn(ctx).Query(ctx, s.q.assignments, user, types, ids)
	if err != nil {
		return nil, fmt.Errorf("wardnpgx: reading assignments: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (wardn.Assignment, error) {
		a := wardn.Assignment{User: user}
		var starts, expires *int64
		err := row.Scan(&a.Role, &a.Scope.Type, &a.Scope.ID, &starts, &expires)
		a.StartsAt, a.ExpiresAt = fromMicros(starts), fromMicros(expires)
		return a, err
	})
	if err != nil {
		return nil, fmt.Errorf("wardnpgx: reading assignments: %w", err)
	}
	return out, nil
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
	rows, err := s.conn(ctx).Query(ctx, s.q.members, scope.Type, scope.ID, afterUser, afterRole, limit+1)
	if err != nil {
		return nil, "", fmt.Errorf("wardnpgx: listing members: %w", err)
	}
	page, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (wardn.Assignment, error) {
		a := wardn.Assignment{Scope: scope}
		var starts, expires *int64
		err := row.Scan(&a.User, &a.Role, &starts, &expires)
		a.StartsAt, a.ExpiresAt = fromMicros(starts), fromMicros(expires)
		return a, err
	})
	if err != nil {
		return nil, "", fmt.Errorf("wardnpgx: listing members: %w", err)
	}
	next := ""
	if len(page) > limit {
		page = page[:limit]
		last := page[len(page)-1]
		next = wardn.EncodeMemberCursor(last.User, last.Role)
	}
	return page, next, nil
}

// RoleInUse implements wardn.Store.
func (s *Store) RoleInUse(ctx context.Context, role string) (bool, error) {
	var used bool
	if err := s.conn(ctx).QueryRow(ctx, s.q.roleInUse, role).Scan(&used); err != nil {
		return false, fmt.Errorf("wardnpgx: checking role use: %w", err)
	}
	return used, nil
}

// RevokeRole implements wardn.Store.
func (s *Store) RevokeRole(ctx context.Context, role string) error {
	if err := s.exec(ctx, s.q.revokeRole, role); err != nil {
		return fmt.Errorf("wardnpgx: revoking role: %w", err)
	}
	return nil
}

// ExpiredUnreported implements wardn.Store.
func (s *Store) ExpiredUnreported(ctx context.Context, t time.Time, limit int) ([]wardn.Assignment, error) {
	if limit <= 0 {
		limit = 1
	}
	rows, err := s.conn(ctx).Query(ctx, s.q.expired, t.UnixMicro(), limit)
	if err != nil {
		return nil, fmt.Errorf("wardnpgx: finding expired assignments: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (wardn.Assignment, error) {
		var a wardn.Assignment
		var starts, expires *int64
		err := row.Scan(&a.User, &a.Role, &a.Scope.Type, &a.Scope.ID, &starts, &expires)
		a.StartsAt, a.ExpiresAt = fromMicros(starts), fromMicros(expires)
		return a, err
	})
	if err != nil {
		return nil, fmt.Errorf("wardnpgx: finding expired assignments: %w", err)
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
	return s.inTx(ctx, func(tx pgx.Tx) error {
		for _, a := range as {
			if _, err := tx.Exec(ctx, s.q.markExpiry, now, a.User, a.Role, a.Scope.Type, a.Scope.ID, endMicros(a.ExpiresAt)); err != nil {
				return fmt.Errorf("wardnpgx: marking expiry: %w", err)
			}
		}
		return nil
	})
}

// RevokeExpired implements wardn.Store: one conditional DELETE, so an
// assignment given a new window meanwhile is left alone.
func (s *Store) RevokeExpired(ctx context.Context, a wardn.Assignment) error {
	err := s.exec(ctx, s.q.revokeExpired, a.User, a.Role, a.Scope.Type, a.Scope.ID, endMicros(a.ExpiresAt))
	if err != nil {
		return fmt.Errorf("wardnpgx: removing expired assignment: %w", err)
	}
	return nil
}

// Link implements wardn.Store.
func (s *Store) Link(ctx context.Context, child, parent wardn.Scope) error {
	err := s.exec(ctx, s.q.link, child.Type, child.ID, parent.Type, parent.ID, time.Now().UnixMicro())
	if err != nil {
		return fmt.Errorf("wardnpgx: link: %w", err)
	}
	return nil
}

// Parent implements wardn.Store.
func (s *Store) Parent(ctx context.Context, child wardn.Scope) (wardn.Scope, bool, error) {
	var p wardn.Scope
	err := s.conn(ctx).QueryRow(ctx, s.q.parent, child.Type, child.ID).Scan(&p.Type, &p.ID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return wardn.Scope{}, false, nil
	case err != nil:
		return wardn.Scope{}, false, fmt.Errorf("wardnpgx: reading parent: %w", err)
	}
	return p, true, nil
}

// Times are stored as Unix microseconds, as in the SQL store. Rounding
// never widens a window: a start is rounded up and an end is rounded down.

func startMicros(t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	us := t.UnixMicro()
	if time.UnixMicro(us).Before(t) {
		us++
	}
	return &us
}

func endMicros(t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	us := t.UnixMicro() // rounds down
	return &us
}

func fromMicros(v *int64) time.Time {
	if v == nil {
		return time.Time{}
	}
	return time.UnixMicro(*v).UTC()
}

var (
	_ wardn.Store    = (*Store)(nil)
	_ wardn.TxStore  = (*Store)(nil)
	_ wardn.Migrator = (*Store)(nil)
)
