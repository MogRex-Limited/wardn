package wardnpgx

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrSchemaTooNew reports a database whose wardn schema was created by a
// newer release of wardn than the one running. Upgrade wardn rather than
// running an older release against it.
var ErrSchemaTooNew = errors.New("wardnpgx: database schema is newer than this release of wardn supports")

// LatestSchemaVersion is the schema version this release migrates to. It
// is always the SQL store's: the two share the schema.
const LatestSchemaVersion = 2

// migrations returns the schema changes, in order: migration N brings the
// schema to version N. They create exactly what the SQL store creates on
// PostgreSQL (tests/integration compares the two), and every statement is
// idempotent, so either store may migrate a database the other created.
func (s *Store) migrations() [][]string {
	t := s.t
	const id, name, integer, perm, text = "VARCHAR(256)", "VARCHAR(64)", "BIGINT", "VARCHAR(128)", "VARCHAR(512)"
	v1 := []string{
		`CREATE TABLE IF NOT EXISTS ` + t.assignments + ` (
		user_id    ` + id + ` NOT NULL,
		role       ` + id + ` NOT NULL,
		scope_type ` + name + ` NOT NULL,
		scope_id   ` + id + ` NOT NULL,
		starts_at  ` + integer + ` NULL,
		expires_at ` + integer + ` NULL,
		created_at ` + integer + ` NOT NULL,
		updated_at ` + integer + ` NOT NULL,
		PRIMARY KEY (user_id, scope_type, scope_id, role)
	)`,
		`CREATE TABLE IF NOT EXISTS ` + t.links + ` (
		child_type  ` + name + ` NOT NULL,
		child_id    ` + id + ` NOT NULL,
		parent_type ` + name + ` NOT NULL,
		parent_id   ` + id + ` NOT NULL,
		updated_at  ` + integer + ` NOT NULL,
		PRIMARY KEY (child_type, child_id)
	)`,
		"CREATE INDEX IF NOT EXISTS " + t.assignments + "_scope ON " + t.assignments + " (scope_type, scope_id)",
	}
	v2 := []string{
		`CREATE TABLE IF NOT EXISTS ` + t.roles + ` (
		id          ` + id + ` NOT NULL PRIMARY KEY,
		owner_type  ` + name + ` NOT NULL,
		owner_id    ` + id + ` NOT NULL,
		name        ` + id + ` NOT NULL,
		name_key    ` + id + ` NOT NULL,
		description ` + text + ` NOT NULL,
		version     ` + integer + ` NOT NULL,
		created_at  ` + integer + ` NOT NULL,
		updated_at  ` + integer + ` NOT NULL,
		UNIQUE (owner_type, owner_id, name_key)
	)`,
		`CREATE TABLE IF NOT EXISTS ` + t.roleRules + ` (
		role_id    ` + id + ` NOT NULL,
		position   ` + integer + ` NOT NULL,
		effect     ` + name + ` NOT NULL,
		permission ` + perm + ` NOT NULL,
		PRIMARY KEY (role_id, position)
	)`,
		`CREATE TABLE IF NOT EXISTS ` + t.roleAssignable + ` (
		role_id    ` + id + ` NOT NULL,
		position   ` + integer + ` NOT NULL,
		scope_type ` + name + ` NOT NULL,
		PRIMARY KEY (role_id, position)
	)`,
		"ALTER TABLE " + t.assignments + " ADD COLUMN IF NOT EXISTS expiry_reported_at " + integer + " NULL",
		"CREATE INDEX IF NOT EXISTS " + t.assignments + "_expiry ON " + t.assignments + " (expires_at)",
		"CREATE INDEX IF NOT EXISTS " + t.assignments + "_role ON " + t.assignments + " (role)",
	}
	return [][]string{v1, v2}
}

// lockKey is the advisory lock that serialises migrations. It is the SQL
// store's key, so the two stores never migrate the same tables at once.
func (s *Store) lockKey() int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("wardn_migrate_" + strings.TrimSuffix(s.prefix, "_")))
	return int64(h.Sum64() >> 1) // shifted right, so it fits in int64
}

// Migrate creates or upgrades the store's tables, in one transaction that
// holds an advisory lock. It is safe to run concurrently from several
// application instances, and alongside the SQL store's Migrate. It never
// uses an application transaction from ctx. wardn.New calls it
// automatically unless Config.ManualMigrations is set.
func (s *Store) Migrate(ctx context.Context) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", s.lockKey()); err != nil {
			return fmt.Errorf("wardnpgx: migrate: taking lock: %w", err)
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS `+s.t.migrations+` (
		version    BIGINT NOT NULL PRIMARY KEY,
		applied_at BIGINT NOT NULL
	)`); err != nil {
			return fmt.Errorf("wardnpgx: migrate: creating version table: %w", err)
		}
		current, err := s.schemaVersion(ctx, tx)
		if err != nil {
			return err
		}
		all := s.migrations()
		if current > len(all) {
			return fmt.Errorf("%w (database is at version %d, this release supports up to %d)", ErrSchemaTooNew, current, len(all))
		}
		for v := current + 1; v <= len(all); v++ {
			for _, stmt := range all[v-1] {
				if _, err := tx.Exec(ctx, stmt); err != nil {
					return fmt.Errorf("wardnpgx: migration %d: %w", v, err)
				}
			}
			if _, err := tx.Exec(ctx, "INSERT INTO "+s.t.migrations+" (version, applied_at) VALUES ($1, $2)", v, time.Now().UnixMicro()); err != nil {
				return fmt.Errorf("wardnpgx: migration %d: recording version: %w", v, err)
			}
		}
		return nil
	})
}

// SchemaVersion returns the version of the store's schema in the
// database, or 0 if it has never been migrated.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var exists bool
	err := s.db.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1)",
		s.t.migrations).Scan(&exists)
	if err != nil {
		return 0, fmt.Errorf("wardnpgx: checking for table %s: %w", s.t.migrations, err)
	}
	if !exists {
		return 0, nil
	}
	return s.schemaVersion(ctx, s.db)
}

func (s *Store) schemaVersion(ctx context.Context, q DB) (int, error) {
	var v *int64
	if err := q.QueryRow(ctx, "SELECT MAX(version) FROM "+s.t.migrations).Scan(&v); err != nil {
		return 0, fmt.Errorf("wardnpgx: reading schema version: %w", err)
	}
	if v == nil {
		return 0, nil
	}
	return int(*v), nil
}
