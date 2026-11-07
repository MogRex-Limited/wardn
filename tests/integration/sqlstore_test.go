package integration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/MogRex-Limited/wardn"
	wardnsql "github.com/MogRex-Limited/wardn/store/sql"
	"github.com/MogRex-Limited/wardn/storetest"
)

// database is one database server under test.
type database struct {
	name    string
	dialect wardnsql.Dialect
	open    func(t *testing.T) *sql.DB
}

func databases(t *testing.T) []database {
	dbs := []database{{
		name:    "sqlite",
		dialect: wardnsql.SQLite,
		open: func(t *testing.T) *sql.DB {
			path := filepath.Join(t.TempDir(), "wardn.db")
			return openDB(t, "sqlite", "file:"+path+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
		},
	}}
	for _, server := range []struct {
		name, env, driver string
		dialect           wardnsql.Dialect
	}{
		{"postgres", "WARDN_TEST_POSTGRES_DSN", "pgx", wardnsql.Postgres},
		{"mysql", "WARDN_TEST_MYSQL_DSN", "mysql", wardnsql.MySQL},
		{"mariadb", "WARDN_TEST_MARIADB_DSN", "mysql", wardnsql.MySQL},
	} {
		dsn := os.Getenv(server.env)
		if dsn == "" {
			// CI sets WARDN_TEST_REQUIRE_ALL so a misconfigured job fails
			// instead of quietly testing SQLite only.
			if os.Getenv("WARDN_TEST_REQUIRE_ALL") != "" {
				t.Fatalf("%s: %s is not set, but WARDN_TEST_REQUIRE_ALL is", server.name, server.env)
			}
			t.Logf("%s: skipped (set %s to run)", server.name, server.env)
			continue
		}
		var (
			once sync.Once
			db   *sql.DB
		)
		dbs = append(dbs, database{name: server.name, dialect: server.dialect, open: func(t *testing.T) *sql.DB {
			once.Do(func() { db = openDB(t, server.driver, dsn) }) // one pool per server
			return db
		}})
	}
	return dbs
}

func openDB(t *testing.T, driver, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatalf("open %s: %v", driver, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping %s: %v", driver, err)
	}
	return db
}

var (
	runID   = strconv.FormatInt(time.Now().UnixNano()%(1<<40), 36)
	prefixN atomic.Int64
)

// freshPrefix returns a table prefix no other test has used, so every test
// gets empty tables on a shared server.
func freshPrefix() string {
	return fmt.Sprintf("t%s_%d_", runID, prefixN.Add(1))
}

func newStore(t *testing.T, db *sql.DB) *wardnsql.Store {
	t.Helper()
	s, err := wardnsql.New(db, wardnsql.WithTablePrefix(freshPrefix()))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

func TestConformance(t *testing.T) {
	for _, d := range databases(t) {
		t.Run(d.name, func(t *testing.T) {
			db := d.open(t)
			storetest.Run(t, func(t *testing.T) wardn.Store {
				if d.name == "sqlite" {
					db = d.open(t) // a new file per test
				}
				return newStore(t, db)
			})
		})
	}
}

func TestDialectDetection(t *testing.T) {
	for _, d := range databases(t) {
		t.Run(d.name, func(t *testing.T) {
			s, err := wardnsql.New(d.open(t))
			if err != nil {
				t.Fatal(err)
			}
			if s.Dialect() != d.dialect {
				t.Fatalf("detected %v, want %v", s.Dialect(), d.dialect)
			}
		})
	}
}

func TestMigrations(t *testing.T) {
	for _, d := range databases(t) {
		t.Run(d.name, func(t *testing.T) {
			ctx := context.Background()
			db := d.open(t)
			s, err := wardnsql.New(db, wardnsql.WithTablePrefix(freshPrefix()))
			if err != nil {
				t.Fatal(err)
			}
			if v, err := s.SchemaVersion(ctx); err != nil || v != 0 {
				t.Fatalf("before migrating: version %d, %v; want 0", v, err)
			}

			// Many instances starting at once.
			var wg sync.WaitGroup
			errs := make(chan error, 8)
			for range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := s.Migrate(ctx); err != nil {
						errs <- err
					}
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Fatalf("concurrent Migrate: %v", err)
			}
			if v, err := s.SchemaVersion(ctx); err != nil || v != wardnsql.LatestSchemaVersion {
				t.Fatalf("after migrating: version %d, %v; want %d", v, err, wardnsql.LatestSchemaVersion)
			}

			// Running again is a no-op.
			if err := s.Migrate(ctx); err != nil {
				t.Fatalf("re-running Migrate: %v", err)
			}

			// An interrupted migration (schema changed, version not yet
			// recorded, as can happen on MySQL, which cannot run DDL in a
			// transaction) must be safe to run again.
			for v := wardnsql.LatestSchemaVersion; v > 1; v-- {
				if _, err := db.ExecContext(ctx, "DELETE FROM "+s.TablePrefix()+"schema_migrations WHERE version = "+strconv.Itoa(v)); err != nil { //nolint:gosec // G202: test-generated prefix and integer
					t.Fatal(err)
				}
			}
			if err := s.Migrate(ctx); err != nil {
				t.Fatalf("re-running interrupted migrations: %v", err)
			}
			if v, _ := s.SchemaVersion(ctx); v != wardnsql.LatestSchemaVersion {
				t.Fatalf("after re-running: version %d", v)
			}
		})
	}
}

func TestSchemaTooNew(t *testing.T) {
	for _, d := range databases(t) {
		t.Run(d.name, func(t *testing.T) {
			ctx := context.Background()
			db := d.open(t)
			prefix := freshPrefix()
			s, err := wardnsql.New(db, wardnsql.WithTablePrefix(prefix))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			// Simulate a newer wardn having migrated this database.
			insert := "INSERT INTO " + prefix + "schema_migrations (version, applied_at) VALUES (99, 0)" //nolint:gosec // G202: prefix is generated by the test, not user input
			if _, err := db.ExecContext(ctx, insert); err != nil {
				t.Fatal(err)
			}
			if err := s.Migrate(ctx); !errors.Is(err, wardnsql.ErrSchemaTooNew) {
				t.Fatalf("Migrate on a newer schema: %v, want ErrSchemaTooNew", err)
			}
			_, err = wardn.New(wardn.Config{Policy: policy(t), Store: s})
			if !errors.Is(err, wardnsql.ErrSchemaTooNew) {
				t.Fatalf("wardn.New on a newer schema: %v, want ErrSchemaTooNew", err)
			}
		})
	}
}

func TestNewMigratesAutomatically(t *testing.T) {
	for _, d := range databases(t) {
		t.Run(d.name, func(t *testing.T) {
			ctx := context.Background()
			db := d.open(t)

			auto, _ := wardnsql.New(db, wardnsql.WithTablePrefix(freshPrefix()))
			if _, err := wardn.New(wardn.Config{Policy: policy(t), Store: auto}); err != nil {
				t.Fatal(err)
			}
			if v, _ := auto.SchemaVersion(ctx); v != wardnsql.LatestSchemaVersion {
				t.Fatalf("wardn.New did not migrate: version %d", v)
			}

			manual, _ := wardnsql.New(db, wardnsql.WithTablePrefix(freshPrefix()))
			if _, err := wardn.New(wardn.Config{Policy: policy(t), Store: manual, ManualMigrations: true}); err != nil {
				t.Fatal(err)
			}
			if v, _ := manual.SchemaVersion(ctx); v != 0 {
				t.Fatalf("ManualMigrations: tables were created anyway (version %d)", v)
			}
		})
	}
}

// TestFailClosedWhenDatabaseDown: a closed database must make every check
// deny with an error (threat model T08).
func TestFailClosedWhenDatabaseDown(t *testing.T) {
	db := openDB(t, "sqlite", "file:"+filepath.Join(t.TempDir(), "down.db"))
	s := newStore(t, db)
	w, err := wardn.New(wardn.Config{Policy: policy(t), Store: s})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := w.System().Assign(ctx, "ada", "admin", wardn.Global); err != nil {
		t.Fatal(err)
	}
	if !w.Can(ctx, "ada", "doc:read", wardn.Global) {
		t.Fatal("setup: admin denied")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	d, err := w.Check(ctx, "ada", "doc:read", wardn.Global)
	if err == nil || d.Allowed {
		t.Fatalf("database closed: %+v, %v; want deny with error", d, err)
	}
}

func policy(t *testing.T) *wardn.Policy {
	t.Helper()
	p, err := wardn.ParsePolicy([]byte("permissions:\n  doc:read: Read documents\nroles:\n  admin: [\"*\"]\n"), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return p
}
