// Package wardnsql is a wardn.Store for SQL databases: PostgreSQL, MySQL,
// MariaDB and SQLite. It uses database/sql, so it works with the driver
// your application already uses and adds no dependencies of its own.
//
//	db, _ := sql.Open("pgx", dsn)
//	w := wardn.MustNew(wardn.Config{
//		File:  "wardn.yaml",
//		Store: wardnsql.MustNew(db),
//	})
//
// wardn.New creates the tables automatically (see Store.Migrate). Every
// value is passed as a query parameter; table names come only from a
// validated prefix.
//
// SQLite: set a busy timeout in the DSN (for example
// "file:wardn.db?_pragma=busy_timeout(5000)" with modernc.org/sqlite) so
// concurrent writers wait instead of failing.
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

// DefaultTablePrefix is prepended to the names of wardn's tables.
const DefaultTablePrefix = "wardn_"

// maxScopes bounds the scopes in one Assignments query. A scope chain is
// never longer than the policy's scope-type depth plus two.
const maxScopes = 64

// Store is a wardn.Store backed by a SQL database. It is safe for
// concurrent use.
type Store struct {
	db     *sql.DB
	d      dialect
	prefix string
	t      tables
	q      queries
}

type tables struct {
	assignments, links, migrations   string
	roles, roleRules, roleAssignable string
}

type queries struct {
	assign, revoke, link, parent string
	selectAssignments            string
}

// Option configures a Store.
type Option func(*options)

type options struct {
	dialect Dialect
	prefix  string
}

// WithDialect sets the SQL dialect instead of detecting it from the driver.
func WithDialect(d Dialect) Option {
	return func(o *options) { o.dialect = d }
}

// WithTablePrefix sets the prefix of wardn's table names (default "wardn_").
// It must be 1–32 characters: lowercase letters, digits and '_', starting
// with a letter.
func WithTablePrefix(prefix string) Option {
	return func(o *options) { o.prefix = prefix }
}

// New returns a Store using db. It does not touch the database; call
// Migrate (wardn.New does) to create the tables.
func New(db *sql.DB, opts ...Option) (*Store, error) {
	if db == nil {
		return nil, errors.New("wardnsql: db is nil")
	}
	o := options{prefix: DefaultTablePrefix}
	for _, opt := range opts {
		opt(&o)
	}
	if !validPrefix(o.prefix) {
		return nil, fmt.Errorf("wardnsql: invalid table prefix %q: use 1-32 lowercase letters, digits and '_', starting with a letter", o.prefix)
	}
	kind := o.dialect
	if kind == DetectDialect {
		var err error
		if kind, err = detect(db.Driver()); err != nil {
			return nil, err
		}
	}
	d, err := dialectFor(kind)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, d: d, prefix: o.prefix}
	s.t = tables{
		assignments:    o.prefix + "assignments",
		links:          o.prefix + "scope_links",
		migrations:     o.prefix + "schema_migrations",
		roles:          o.prefix + "roles",
		roleRules:      o.prefix + "role_rules",
		roleAssignable: o.prefix + "role_assignable",
	}
	s.q = queries{
		assign: d.bind("INSERT INTO " + s.t.assignments +
			" (user_id, role, scope_type, scope_id, starts_at, expires_at, created_at, updated_at, expiry_reported_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL) " +
			d.upsert([]string{"user_id", "scope_type", "scope_id", "role"}, []string{"starts_at", "expires_at", "updated_at", "expiry_reported_at"})),
		revoke: d.bind("DELETE FROM " + s.t.assignments +
			" WHERE user_id = ? AND role = ? AND scope_type = ? AND scope_id = ?"),
		selectAssignments: "SELECT role, scope_type, scope_id, starts_at, expires_at FROM " + s.t.assignments + " WHERE user_id = ? AND (",
		link: d.bind("INSERT INTO " + s.t.links +
			" (child_type, child_id, parent_type, parent_id, updated_at) VALUES (?, ?, ?, ?, ?) " +
			d.upsert([]string{"child_type", "child_id"}, []string{"parent_type", "parent_id", "updated_at"})),
		parent: d.bind("SELECT parent_type, parent_id FROM " + s.t.links + " WHERE child_type = ? AND child_id = ?"),
	}
	return s, nil
}

// MustNew is like New but panics on error, for use in main().
func MustNew(db *sql.DB, opts ...Option) *Store {
	s, err := New(db, opts...)
	if err != nil {
		panic(err)
	}
	return s
}

// TablePrefix returns the prefix of the store's table names.
func (s *Store) TablePrefix() string { return s.prefix }

// Dialect returns the SQL dialect the store uses.
func (s *Store) Dialect() Dialect { return s.d.kind }

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
	_, err := s.db.ExecContext(ctx, s.q.assign,
		a.User, a.Role, a.Scope.Type, a.Scope.ID,
		startMicros(a.StartsAt), endMicros(a.ExpiresAt), now, now)
	if err != nil {
		return fmt.Errorf("wardnsql: assign: %w", err)
	}
	return nil
}

// Revoke implements wardn.Store.
func (s *Store) Revoke(ctx context.Context, user, role string, scope wardn.Scope) error {
	if _, err := s.db.ExecContext(ctx, s.q.revoke, user, role, scope.Type, scope.ID); err != nil {
		return fmt.Errorf("wardnsql: revoke: %w", err)
	}
	return nil
}

// Assignments implements wardn.Store.
func (s *Store) Assignments(ctx context.Context, user string, scopes []wardn.Scope) ([]wardn.Assignment, error) {
	if len(scopes) == 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if len(scopes) > maxScopes {
		return nil, fmt.Errorf("wardnsql: %d scopes in one query; the maximum is %d", len(scopes), maxScopes)
	}
	// The query text depends only on the number of scopes; values are
	// always parameters.
	var b strings.Builder
	b.WriteString(s.q.selectAssignments)
	args := make([]any, 0, 1+2*len(scopes))
	args = append(args, user)
	for i, sc := range scopes {
		if i > 0 {
			b.WriteString(" OR ")
		}
		b.WriteString("(scope_type = ? AND scope_id = ?)")
		args = append(args, sc.Type, sc.ID)
	}
	b.WriteString(")")

	rows, err := s.db.QueryContext(ctx, s.d.bind(b.String()), args...)
	if err != nil {
		return nil, fmt.Errorf("wardnsql: reading assignments: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows.Err is checked below
	var out []wardn.Assignment
	for rows.Next() {
		a := wardn.Assignment{User: user}
		var starts, expires sql.NullInt64
		if err := rows.Scan(&a.Role, &a.Scope.Type, &a.Scope.ID, &starts, &expires); err != nil {
			return nil, fmt.Errorf("wardnsql: reading assignments: %w", err)
		}
		a.StartsAt, a.ExpiresAt = fromMicros(starts), fromMicros(expires)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("wardnsql: reading assignments: %w", err)
	}
	return out, nil
}

// Link implements wardn.Store.
func (s *Store) Link(ctx context.Context, child, parent wardn.Scope) error {
	_, err := s.db.ExecContext(ctx, s.q.link, child.Type, child.ID, parent.Type, parent.ID, time.Now().UnixMicro())
	if err != nil {
		return fmt.Errorf("wardnsql: link: %w", err)
	}
	return nil
}

// Parent implements wardn.Store.
func (s *Store) Parent(ctx context.Context, child wardn.Scope) (wardn.Scope, bool, error) {
	var p wardn.Scope
	err := s.db.QueryRowContext(ctx, s.q.parent, child.Type, child.ID).Scan(&p.Type, &p.ID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return wardn.Scope{}, false, nil
	case err != nil:
		return wardn.Scope{}, false, fmt.Errorf("wardnsql: reading parent: %w", err)
	}
	return p, true, nil
}

// Times are stored as Unix microseconds, which every database stores
// exactly and compares cheaply. Rounding never widens a window: a start is
// rounded up and an end is rounded down.

func startMicros(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	us := t.UnixMicro()
	if time.UnixMicro(us).Before(t) {
		us++
	}
	return sql.NullInt64{Int64: us, Valid: true}
}

func endMicros(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.UnixMicro(), Valid: true} // UnixMicro rounds down
}

func fromMicros(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.UnixMicro(v.Int64).UTC()
}

var (
	_ wardn.Store    = (*Store)(nil)
	_ wardn.Migrator = (*Store)(nil)
)
