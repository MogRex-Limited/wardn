package wardnsql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"sync"
	"time"
)

// ErrSchemaTooNew reports a database whose wardn schema was created by a
// newer release of wardn than the one running. Upgrade wardn rather than
// running an older release against it.
var ErrSchemaTooNew = errors.New("wardnsql: database schema is newer than this release of wardn supports")

// step is one schema change. If done is set and reports true, the change is
// already in place and is skipped: every step must be safe to run twice,
// because MySQL cannot run DDL inside a transaction, so a migration
// interrupted halfway is simply run again.
type step struct {
	sql  string
	done func(ctx context.Context, q querier) (bool, error)
}

// LatestSchemaVersion is the schema version this release migrates to.
const LatestSchemaVersion = 2

// migrations returns the schema changes, in order. Migration N brings the
// schema to version N. Released migrations are never edited, only appended.
func (s *Store) migrations() [][]step {
	return [][]step{s.migrationV1(), s.migrationV2()}
}

// migrationV1: assignments and scope links (M3).
func (s *Store) migrationV1() []step {
	d, t := s.d, s.t
	assignmentIndex := "INDEX " + t.assignments + "_scope (scope_type, scope_id)"
	assignments := `CREATE TABLE IF NOT EXISTS ` + t.assignments + ` (
		user_id    ` + d.id + ` NOT NULL,
		role       ` + d.id + ` NOT NULL,
		scope_type ` + d.name + ` NOT NULL,
		scope_id   ` + d.id + ` NOT NULL,
		starts_at  ` + d.integer + ` NULL,
		expires_at ` + d.integer + ` NULL,
		created_at ` + d.integer + ` NOT NULL,
		updated_at ` + d.integer + ` NOT NULL,
		PRIMARY KEY (user_id, scope_type, scope_id, role)`
	if d.inlineIndexes {
		assignments += ",\n\t\t" + assignmentIndex
	}
	assignments += "\n\t)" + d.tableSuffix

	links := `CREATE TABLE IF NOT EXISTS ` + t.links + ` (
		child_type  ` + d.name + ` NOT NULL,
		child_id    ` + d.id + ` NOT NULL,
		parent_type ` + d.name + ` NOT NULL,
		parent_id   ` + d.id + ` NOT NULL,
		updated_at  ` + d.integer + ` NOT NULL,
		PRIMARY KEY (child_type, child_id)
	)` + d.tableSuffix

	v1 := []step{{sql: assignments}, {sql: links}}
	if !d.inlineIndexes {
		v1 = append(v1, step{sql: "CREATE INDEX IF NOT EXISTS " + t.assignments + "_scope ON " + t.assignments + " (scope_type, scope_id)"})
	}
	return v1
}

// migrationV2: custom roles, and expiry reporting on assignments (M5).
func (s *Store) migrationV2() []step {
	d, t := s.d, s.t
	roles := `CREATE TABLE IF NOT EXISTS ` + t.roles + ` (
		id          ` + d.id + ` NOT NULL PRIMARY KEY,
		owner_type  ` + d.name + ` NOT NULL,
		owner_id    ` + d.id + ` NOT NULL,
		name        ` + d.id + ` NOT NULL,
		name_key    ` + d.id + ` NOT NULL,
		description ` + d.text + ` NOT NULL,
		version     ` + d.integer + ` NOT NULL,
		created_at  ` + d.integer + ` NOT NULL,
		updated_at  ` + d.integer + ` NOT NULL,
		UNIQUE (owner_type, owner_id, name_key)
	)` + d.tableSuffix
	// effect is "allow" or "deny". Custom roles only grant in this release
	// (design decision D2), but the column exists so enabling denies later
	// needs no schema change.
	rules := `CREATE TABLE IF NOT EXISTS ` + t.roleRules + ` (
		role_id    ` + d.id + ` NOT NULL,
		position   ` + d.integer + ` NOT NULL,
		effect     ` + d.name + ` NOT NULL,
		permission ` + d.perm + ` NOT NULL,
		PRIMARY KEY (role_id, position)
	)` + d.tableSuffix
	assignable := `CREATE TABLE IF NOT EXISTS ` + t.roleAssignable + ` (
		role_id    ` + d.id + ` NOT NULL,
		position   ` + d.integer + ` NOT NULL,
		scope_type ` + d.name + ` NOT NULL,
		PRIMARY KEY (role_id, position)
	)` + d.tableSuffix
	return []step{
		{sql: roles},
		{sql: rules},
		{sql: assignable},
		{
			sql:  "ALTER TABLE " + t.assignments + " ADD COLUMN expiry_reported_at " + d.integer + " NULL",
			done: s.columnExists(t.assignments, "expiry_reported_at"),
		},
		s.index(t.assignments+"_expiry", t.assignments, "expires_at"),
		s.index(t.assignments+"_role", t.assignments, "role"),
	}
}

// index returns a step creating an index if it does not exist.
func (s *Store) index(name, table, columns string) step {
	if s.d.kind == MySQL { // no CREATE INDEX IF NOT EXISTS
		return step{
			sql:  "CREATE INDEX " + name + " ON " + table + " (" + columns + ")",
			done: s.indexExists(table, name),
		}
	}
	return step{sql: "CREATE INDEX IF NOT EXISTS " + name + " ON " + table + " (" + columns + ")"}
}

func (s *Store) columnExists(table, column string) func(context.Context, querier) (bool, error) {
	return func(ctx context.Context, q querier) (bool, error) {
		var query string
		switch s.d.kind {
		case Postgres:
			query = "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2"
		case MySQL:
			query = "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?"
		case SQLite:
			query = "SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?"
		case DetectDialect:
			return false, fmt.Errorf("wardnsql: unsupported dialect %v", s.d.kind)
		}
		var n int
		err := q.QueryRowContext(ctx, query, table, column).Scan(&n)
		return n > 0, err
	}
}

func (s *Store) indexExists(table, index string) func(context.Context, querier) (bool, error) {
	return func(ctx context.Context, q querier) (bool, error) {
		var n int
		err := q.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?",
			table, index).Scan(&n)
		return n > 0, err
	}
}

// sqliteMigrations serialises migrations within a process: SQLite has no
// advisory locks, and its schema statements are idempotent.
var sqliteMigrations sync.Mutex

// Migrate creates or upgrades the store's tables. It is safe to run
// concurrently from several application instances: Postgres and MySQL
// migrations hold a database lock, and every statement is idempotent.
// wardn.New calls it automatically unless Config.ManualMigrations is set.
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("wardnsql: migrate: %w", err)
	}
	defer conn.Close() //nolint:errcheck // returning the connection to the pool; nothing to recover

	unlock, err := s.lock(ctx, conn)
	if err != nil {
		return err
	}
	defer unlock()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+s.t.migrations+` (
		version    `+s.d.integer+` NOT NULL PRIMARY KEY,
		applied_at `+s.d.integer+` NOT NULL
	)`+s.d.tableSuffix); err != nil {
		return fmt.Errorf("wardnsql: migrate: creating version table: %w", err)
	}
	current, err := s.schemaVersion(ctx, conn)
	if err != nil {
		return err
	}
	all := s.migrations()
	if current > len(all) {
		return fmt.Errorf("%w (database is at version %d, this release supports up to %d)", ErrSchemaTooNew, current, len(all))
	}
	for v := current + 1; v <= len(all); v++ {
		if err := s.apply(ctx, conn, v, all[v-1]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) apply(ctx context.Context, conn *sql.Conn, version int, steps []step) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("wardnsql: migration %d: %w", version, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	for _, st := range steps {
		if st.done != nil {
			done, err := st.done(ctx, tx)
			if err != nil {
				return fmt.Errorf("wardnsql: migration %d: %w", version, err)
			}
			if done {
				continue
			}
		}
		if _, err := tx.ExecContext(ctx, st.sql); err != nil {
			return fmt.Errorf("wardnsql: migration %d: %w", version, err)
		}
	}
	insert := s.d.bind("INSERT INTO " + s.t.migrations + " (version, applied_at) VALUES (?, ?)")
	if _, err := tx.ExecContext(ctx, insert, version, time.Now().UnixMicro()); err != nil {
		return fmt.Errorf("wardnsql: migration %d: recording version: %w", version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("wardnsql: migration %d: %w", version, err)
	}
	return nil
}

// SchemaVersion returns the version of the store's schema in the
// database, or 0 if it has never been migrated.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return 0, fmt.Errorf("wardnsql: %w", err)
	}
	defer conn.Close() //nolint:errcheck // returning the connection to the pool
	exists, err := s.tableExists(ctx, conn, s.t.migrations)
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	return s.schemaVersion(ctx, conn)
}

// tableExists reports whether the named table exists in the current
// database or schema.
func (s *Store) tableExists(ctx context.Context, conn *sql.Conn, table string) (bool, error) {
	var query string
	switch s.d.kind {
	case Postgres:
		query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1"
	case MySQL:
		query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?"
	case SQLite:
		query = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?"
	case DetectDialect:
		return false, fmt.Errorf("wardnsql: unsupported dialect %v", s.d.kind)
	}
	var n int
	if err := conn.QueryRowContext(ctx, query, table).Scan(&n); err != nil {
		return false, fmt.Errorf("wardnsql: checking for table %s: %w", table, err)
	}
	return n > 0, nil
}

func (s *Store) schemaVersion(ctx context.Context, conn *sql.Conn) (int, error) {
	var v sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT MAX(version) FROM "+s.t.migrations).Scan(&v); err != nil {
		return 0, fmt.Errorf("wardnsql: reading schema version: %w", err)
	}
	return int(v.Int64), nil
}

// lock takes a database-wide migration lock on conn and returns a function
// that releases it.
func (s *Store) lock(ctx context.Context, conn *sql.Conn) (func(), error) {
	name := "wardn_migrate_" + strings.TrimSuffix(s.prefix, "_")
	switch s.d.kind {
	case Postgres:
		h := fnv.New64a()
		_, _ = h.Write([]byte(name))
		key := int64(h.Sum64() >> 1) // shifted right, so it fits in int64
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
			return nil, fmt.Errorf("wardnsql: migrate: taking lock: %w", err)
		}
		return func() { s.unlock(ctx, conn, "SELECT pg_advisory_unlock($1)", key) }, nil
	case MySQL:
		var got sql.NullInt64
		if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, 60)", name).Scan(&got); err != nil {
			return nil, fmt.Errorf("wardnsql: migrate: taking lock: %w", err)
		}
		if got.Int64 != 1 {
			return nil, errors.New("wardnsql: migrate: timed out waiting for another instance's migration")
		}
		return func() { s.unlock(ctx, conn, "SELECT RELEASE_LOCK(?)", name) }, nil
	case SQLite:
		sqliteMigrations.Lock()
		return sqliteMigrations.Unlock, nil
	case DetectDialect:
	}
	return nil, fmt.Errorf("wardnsql: unsupported dialect %v", s.d.kind)
}

// unlock releases a session lock. If that fails, the connection is
// discarded instead of returned to the pool, so a lock can never outlive
// the migration on a reused connection. It runs even if ctx was canceled.
func (s *Store) unlock(ctx context.Context, conn *sql.Conn, query string, arg any) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if _, err := conn.ExecContext(ctx, query, arg); err != nil {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	}
}
