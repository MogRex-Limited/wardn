package integration

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"

	"github.com/MogRex-Limited/wardn"
)

// TestPostgresRowLevelSecurity follows the "Row-level security" guide: the
// application connects as a role without DDL rights or BYPASSRLS, its own
// tables have forced row-level security keyed by a per-transaction
// setting, and wardn's tables are granted to it without row-level
// security. wardn must work inside the tenant transaction, and a ParentOf
// that reads a protected table must fail closed outside it.
func TestPostgresRowLevelSecurity(t *testing.T) {
	var pg *database
	for _, d := range databases(t) {
		if d.name == "postgres" {
			pg = &d
		}
	}
	if pg == nil {
		t.Skip("PostgreSQL not configured")
	}
	ctx := context.Background()
	db := pg.open(t)
	store := newStore(t, db) // migrated by the owner, as a deploy job would
	prefix := store.TablePrefix()
	role, products := prefix+"app", prefix+"products"

	exec := func(q string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec("CREATE ROLE " + role + " NOLOGIN NOBYPASSRLS")
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DROP OWNED BY "+role)
		_, _ = db.ExecContext(ctx, "DROP ROLE "+role)
	})
	exec("CREATE TABLE " + products + " (id text PRIMARY KEY, organization_id text NOT NULL)")
	exec("ALTER TABLE " + products + " ENABLE ROW LEVEL SECURITY")
	exec("ALTER TABLE " + products + " FORCE ROW LEVEL SECURITY")
	exec("CREATE POLICY tenant ON " + products + " USING (organization_id = current_setting('app.organization_id', true))")
	exec("GRANT SELECT, INSERT ON " + products + " TO " + role)
	for _, table := range []string{"assignments", "scope_links", "roles", "role_rules", "role_assignable"} {
		exec("GRANT SELECT, INSERT, UPDATE, DELETE ON " + prefix + table + " TO " + role)
	}
	exec("GRANT SELECT ON " + prefix + "schema_migrations TO " + role)

	// Outside a transaction, the application's connection is the
	// restricted role too. (The test's own login is a superuser, which
	// always bypasses row-level security.)
	appConn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = appConn.ExecContext(context.Background(), "RESET ROLE")
		_ = appConn.Close()
	})
	if _, err := appConn.ExecContext(ctx, "SET ROLE "+role); err != nil {
		t.Fatal(err)
	}

	p, err := wardn.ParsePolicy([]byte(txPolicy), "wardn.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var tx *sql.Tx // the tenant transaction ParentOf reads through, when there is one
	w, err := wardn.New(wardn.Config{
		Policy: p, Store: store, ManualMigrations: true,
		ParentOf: func(ctx context.Context, child wardn.Scope) (wardn.Scope, bool, error) {
			if child.Type != "product" {
				return wardn.Scope{}, false, nil
			}
			q := appConn.QueryRowContext
			if tx != nil && store.InTx(ctx) {
				q = tx.QueryRowContext
			}
			var org string
			err := q(ctx, "SELECT organization_id FROM "+products+" WHERE id = $1", child.ID).Scan(&org)
			if errors.Is(err, sql.ErrNoRows) {
				return wardn.Scope{}, false, nil
			}
			return wardn.NewScope("organisation", org), err == nil, err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	org, product := wardn.NewScope("organisation", "acme"), wardn.NewScope("product", "helpdesk")

	// The tenant transaction: restricted role, tenant set for this
	// transaction only, as an application's InTenantTx helper would.
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	for _, q := range []string{"SET LOCAL ROLE " + role, "SELECT set_config('app.organization_id', 'acme', true)"} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO "+products+" (id, organization_id) VALUES ('helpdesk', 'acme')"); err != nil { //nolint:gosec // G202: test-generated table name
		t.Fatal(err)
	}
	txCtx, ended := w.Transaction(store.WithTx(ctx, tx))
	if err := w.System().Assign(txCtx, "ada", "owner", org); err != nil {
		t.Fatalf("Assign as the restricted role: %v", err)
	}
	if !w.Can(txCtx, "ada", "ticket:reply", product) {
		t.Fatal("inside the tenant transaction, the owner cannot act on the organisation's product")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := ended(ctx); err != nil {
		t.Fatal(err)
	}
	tx = nil

	// Outside any tenant transaction, the policy hides the product, so its
	// organisation cannot be read, and the check fails closed instead of
	// guessing.
	d, err := w.Check(ctx, "ada", "ticket:reply", product)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed {
		t.Fatalf("ParentOf read a protected table without a tenant, and still allowed: %s", d.Reason)
	}
}

// TestPgxSharesTheTransaction follows the "Using pgx" section of the
// transactions guide: pgx queries run through Conn.Raw on the connection
// that holds wardn's transaction, so they commit and roll back together.
func TestPgxSharesTheTransaction(t *testing.T) {
	var pg *database
	for _, d := range databases(t) {
		if d.name == "postgres" {
			pg = &d
		}
	}
	if pg == nil {
		t.Skip("PostgreSQL not configured")
	}
	ctx := context.Background()
	s := newTxSetup(t, *pg)
	product := wardn.NewScope("product", "helpdesk")

	for _, commit := range []bool{false, true} {
		conn, err := s.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		txCtx, ended := s.w.Transaction(s.store.WithTx(ctx, tx))
		if err := s.w.System().Assign(txCtx, "kemi", "agent", product); err != nil {
			t.Fatal(err)
		}
		err = conn.Raw(func(dc any) error {
			pgxConn := dc.(*stdlib.Conn).Conn()
			_, err := pgxConn.Exec(ctx, "INSERT INTO "+s.table+" (user_id) VALUES ($1)", "kemi")
			return err
		})
		if err != nil {
			t.Fatalf("pgx query inside the transaction: %v", err)
		}
		if commit {
			err = tx.Commit()
		} else {
			err = tx.Rollback()
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := ended(ctx); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()

		want := 0
		if commit {
			want = 1
		}
		if got := s.members(t); got != want {
			t.Fatalf("commit=%v: %d rows written through pgx, want %d", commit, got, want)
		}
		if s.w.Can(ctx, "kemi", "ticket:reply", product) != commit {
			t.Fatalf("commit=%v: wardn's assignment did not follow the transaction", commit)
		}
	}
}
