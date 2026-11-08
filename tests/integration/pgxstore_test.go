package integration

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/MogRex-Limited/wardn"
	wardnpgx "github.com/MogRex-Limited/wardn/store/pgx"
	wardnsql "github.com/MogRex-Limited/wardn/store/sql"
)

// postgres returns the PostgreSQL database under test, or skips.
func postgres(t *testing.T) database {
	t.Helper()
	for _, d := range databases(t) {
		if d.name == "postgres" {
			return d
		}
	}
	t.Skip("PostgreSQL not configured")
	return database{}
}

// pgxPool connects pgx to the same PostgreSQL server.
func pgxPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), os.Getenv("WARDN_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// TestPgxAndSQLStoresShareTheSchema: the two PostgreSQL stores must create
// exactly the same tables, columns and indexes, so a database can move
// from one to the other, or serve both at once.
func TestPgxAndSQLStoresShareTheSchema(t *testing.T) {
	d := postgres(t)
	ctx := context.Background()
	db := d.open(t)
	viaSQL := newStore(t, db)
	viaPgx := wardnpgx.MustNew(pgxPool(t), wardnpgx.WithTablePrefix(freshPrefix()))
	if err := viaPgx.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if v, _ := viaPgx.SchemaVersion(ctx); v != wardnsql.LatestSchemaVersion || wardnpgx.LatestSchemaVersion != wardnsql.LatestSchemaVersion {
		t.Fatalf("schema versions differ: pgx %d (latest %d), sql latest %d", v, wardnpgx.LatestSchemaVersion, wardnsql.LatestSchemaVersion)
	}

	describe := func(prefix string) string {
		t.Helper()
		var b strings.Builder
		rows, err := db.QueryContext(ctx, `
			SELECT table_name, column_name, data_type, COALESCE(character_maximum_length, 0), is_nullable, ordinal_position
			FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name LIKE $1
			ORDER BY table_name, ordinal_position`, prefix+"%")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close() //nolint:errcheck // test
		for rows.Next() {
			var table, column, typ, nullable string
			var length, pos int
			if err := rows.Scan(&table, &column, &typ, &length, &nullable, &pos); err != nil {
				t.Fatal(err)
			}
			b.WriteString(strings.TrimPrefix(table, prefix) + " " + column + " " + typ + " " + strconv.Itoa(length) + " " + nullable + " " + strconv.Itoa(pos) + "\n")
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		idx, err := db.QueryContext(ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname = current_schema() AND tablename LIKE $1 ORDER BY indexname`, prefix+"%")
		if err != nil {
			t.Fatal(err)
		}
		defer idx.Close() //nolint:errcheck // test
		for idx.Next() {
			var def string
			if err := idx.Scan(&def); err != nil {
				t.Fatal(err)
			}
			b.WriteString(strings.ReplaceAll(def, prefix, "") + "\n")
		}
		if err := idx.Err(); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	a, b := describe(viaSQL.TablePrefix()), describe(viaPgx.TablePrefix())
	if a == "" || a != b {
		t.Fatalf("schemas differ:\n--- wardnsql\n%s\n--- wardnpgx\n%s", a, b)
	}
}

// TestPgxAndSQLStoresShareTheData: what one store writes, the other reads,
// and each accepts the other's migrated tables.
func TestPgxAndSQLStoresShareTheData(t *testing.T) {
	d := postgres(t)
	ctx := context.Background()
	db := d.open(t)
	viaSQL := newStore(t, db)
	viaPgx := wardnpgx.MustNew(pgxPool(t), wardnpgx.WithTablePrefix(viaSQL.TablePrefix()))
	if err := viaPgx.Migrate(ctx); err != nil {
		t.Fatalf("pgx store migrating the SQL store's tables: %v", err)
	}
	p, err := wardn.ParsePolicy([]byte(txPolicy), "wardn.yaml")
	if err != nil {
		t.Fatal(err)
	}
	wSQL := wardn.MustNew(wardn.Config{Policy: p, Store: viaSQL})
	wPgx := wardn.MustNew(wardn.Config{Policy: p, Store: viaPgx})
	org, product := wardn.NewScope("organisation", "acme"), wardn.NewScope("product", "helpdesk")
	until := time.Now().Add(time.Hour)

	if err := wSQL.Link(ctx, product, org); err != nil {
		t.Fatal(err)
	}
	if err := wSQL.System().Assign(ctx, "kemi", "agent", product, wardn.Until(until)); err != nil {
		t.Fatal(err)
	}
	role, err := wPgx.System().CreateRole(ctx, org, wardn.RoleSpec{Name: "Triage", Allow: []string{"ticket:read"}, AssignableAt: []string{"product"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := wPgx.System().Assign(ctx, "tolu", role.ID, product); err != nil {
		t.Fatal(err)
	}

	for name, w := range map[string]*wardn.Warden{"sql": wSQL, "pgx": wPgx} {
		if !w.Can(ctx, "kemi", "ticket:reply", product) || !w.Can(ctx, "tolu", "ticket:read", product) || w.Can(ctx, "tolu", "ticket:reply", product) {
			t.Errorf("%s store reads the other's data differently", name)
		}
		got, err := w.CustomRole(ctx, role.ID)
		if err != nil || got.Name != "Triage" || len(got.Allow) != 1 {
			t.Errorf("%s store: custom role = %+v, %v", name, got, err)
		}
		as, err := w.RolesOf(ctx, "kemi", product)
		if err != nil || len(as) != 1 || !as[0].ExpiresAt.Equal(until.Truncate(time.Microsecond)) {
			t.Errorf("%s store: time window = %+v, %v", name, as, err)
		}
	}
}
