package wardnpgx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/storetest"
)

var (
	poolOnce sync.Once
	pool     *pgxpool.Pool
	errPool  error
	runID    = strconv.FormatInt(time.Now().UnixNano()%(1<<40), 36)
	prefixN  atomic.Int64
)

// testPool connects to WARDN_TEST_POSTGRES_DSN (make integration starts
// PostgreSQL), or skips.
func testPool(tb testing.TB) *pgxpool.Pool {
	tb.Helper()
	dsn := os.Getenv("WARDN_TEST_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("WARDN_TEST_REQUIRE_ALL") != "" {
			tb.Fatal("WARDN_TEST_POSTGRES_DSN is not set, but WARDN_TEST_REQUIRE_ALL is")
		}
		tb.Skip("set WARDN_TEST_POSTGRES_DSN to run (make integration starts PostgreSQL)")
	}
	poolOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		pool, errPool = pgxpool.New(ctx, dsn)
		if errPool == nil {
			errPool = pool.Ping(ctx)
		}
	})
	if errPool != nil {
		tb.Fatalf("connecting to PostgreSQL: %v", errPool)
	}
	return pool
}

// freshPrefix returns a table prefix no other test has used.
func freshPrefix() string {
	return fmt.Sprintf("p%s_%d_", runID, prefixN.Add(1))
}

func newStore(tb testing.TB) *Store {
	tb.Helper()
	s, err := New(testPool(tb), WithTablePrefix(freshPrefix()))
	if err != nil {
		tb.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		tb.Fatalf("Migrate: %v", err)
	}
	return s
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) wardn.Store { return newStore(t) })
}

func BenchmarkStore(b *testing.B) {
	storetest.Bench(b, func(b *testing.B) wardn.Store { return newStore(b) })
}

func TestNewErrors(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("nil db accepted")
	}
	var db DB = (*pgxpool.Pool)(nil)
	for _, p := range []string{"", "Wardn_", "1x_", "wardn-", "wardn_; DROP TABLE x; --", "w.x_", "abcdefghijklmnopqrstuvwxyz0123456"} {
		if _, err := New(db, WithTablePrefix(p)); err == nil {
			t.Errorf("table prefix %q accepted", p)
		}
	}
	s, err := New(db)
	if err != nil || s.TablePrefix() != DefaultTablePrefix {
		t.Errorf("default prefix: %v, %v", s, err)
	}
	defer func() {
		if recover() == nil {
			t.Error("MustNew did not panic")
		}
	}()
	MustNew(nil)
}

func TestMigrate(t *testing.T) {
	ctx := context.Background()
	s, err := New(testPool(t), WithTablePrefix(freshPrefix()))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := s.SchemaVersion(ctx); err != nil || v != 0 {
		t.Fatalf("before migrating: %d, %v", v, err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 { // many instances starting at once
		wg.Go(func() {
			if err := s.Migrate(ctx); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Migrate: %v", err)
	}
	if v, err := s.SchemaVersion(ctx); err != nil || v != LatestSchemaVersion {
		t.Fatalf("after migrating: %d, %v", v, err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("re-running: %v", err)
	}
	if _, err := testPool(t).Exec(ctx, "INSERT INTO "+s.t.migrations+" (version, applied_at) VALUES (99, 0)"); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("schema too new: %v", err)
	}
}

const txPolicy = `
scopes:
  organisation: {}
  product: { parent: organisation }
permissions:
  ticket:read:  Read tickets
  ticket:reply: Reply to tickets
roles:
  owner:
    assignable_at: [organisation]
    allow: ["*"]
  agent:
    assignable_at: [product]
    allow: [ticket:read, ticket:reply]
`

func newWarden(t *testing.T, s *Store) *wardn.Warden {
	t.Helper()
	p, err := wardn.ParsePolicy([]byte(txPolicy), "wardn.yaml")
	if err != nil {
		t.Fatal(err)
	}
	w, err := wardn.New(wardn.Config{Policy: p, Store: s, Cache: wardn.NewMemoryCache()})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// appTable creates an application table next to wardn's.
func appTable(t *testing.T, s *Store) string {
	t.Helper()
	table := s.TablePrefix() + "app_members"
	if _, err := testPool(t).Exec(context.Background(), "CREATE TABLE "+table+" (user_id text NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	return table
}

func count(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := testPool(t).QueryRow(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAppTransaction_CommitAndRollback(t *testing.T) {
	s := newStore(t)
	w := newWarden(t, s)
	table := appTable(t, s)
	ctx := context.Background()
	org, product := wardn.NewScope("organisation", "acme"), wardn.NewScope("product", "helpdesk")
	if err := w.Link(ctx, product, org); err != nil {
		t.Fatal(err)
	}
	w.Can(ctx, "kemi", "ticket:reply", product) // cache "no access"

	for _, commit := range []bool{false, true} {
		wctx, ended := w.Transaction(ctx)
		err := pgx.BeginFunc(ctx, testPool(t), func(tx pgx.Tx) error {
			txCtx := s.WithTx(wctx, tx)
			if _, err := tx.Exec(txCtx, "INSERT INTO "+table+" (user_id) VALUES ($1)", "kemi"); err != nil {
				return err
			}
			if err := w.System().Assign(txCtx, "kemi", "agent", product); err != nil {
				return err
			}
			if !w.Can(txCtx, "kemi", "ticket:reply", product) {
				t.Error("the transaction does not see its own assignment")
			}
			if w.Can(ctx, "kemi", "ticket:reply", product) {
				t.Error("an uncommitted assignment is visible outside the transaction")
			}
			if !commit {
				return errRollback
			}
			return nil
		})
		if err != nil && !errors.Is(err, errRollback) {
			t.Fatal(err)
		}
		if err := ended(ctx); err != nil {
			t.Fatal(err)
		}
		want := 0
		if commit {
			want = 1
		}
		if got := count(t, table); got != want {
			t.Fatalf("commit=%v: %d application rows, want %d", commit, got, want)
		}
		if w.Can(ctx, "kemi", "ticket:reply", product) != commit {
			t.Fatalf("commit=%v: access did not follow the transaction (or the cache kept the old state)", commit)
		}
	}
}

var errRollback = errors.New("roll back")

func TestAppTransaction_FailedWriteKeepsItUsable(t *testing.T) {
	s := newStore(t)
	w := newWarden(t, s)
	table := appTable(t, s)
	ctx := context.Background()
	org := wardn.NewScope("organisation", "acme")
	spec := wardn.RoleSpec{Name: "Triage", Allow: []string{"ticket:read"}, AssignableAt: []string{"product"}}

	wctx, ended := w.Transaction(ctx)
	var created wardn.CustomRole
	err := pgx.BeginFunc(ctx, testPool(t), func(tx pgx.Tx) error {
		txCtx := s.WithTx(wctx, tx)
		var err error
		if created, err = w.System().CreateRole(txCtx, org, spec); err != nil {
			return err
		}
		// Without a savepoint, this failure would abort the transaction.
		if _, err := w.System().CreateRole(txCtx, org, spec); !errors.Is(err, wardn.ErrRoleNameTaken) {
			t.Errorf("duplicate role name: %v, want ErrRoleNameTaken", err)
		}
		_, err = tx.Exec(txCtx, "INSERT INTO "+table+" (user_id) VALUES ($1)", "kemi")
		return err
	})
	if err != nil {
		t.Fatalf("transaction unusable after wardn's failed write: %v", err)
	}
	if err := ended(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := w.CustomRole(ctx, created.ID); err != nil {
		t.Fatalf("the first role was lost: %v", err)
	}
	if count(t, table) != 1 {
		t.Fatal("the application's row was lost")
	}
}

func TestAppTransaction_BelongsToOneStore(t *testing.T) {
	a, b := newStore(t), newStore(t)
	ctx := context.Background()
	err := pgx.BeginFunc(ctx, testPool(t), func(tx pgx.Tx) error {
		txCtx := a.WithTx(ctx, tx)
		if !a.InTx(txCtx) || b.InTx(txCtx) {
			t.Errorf("InTx: a=%v b=%v; want true, false", a.InTx(txCtx), b.InTx(txCtx))
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatal(err)
	}
	if a.InTx(a.WithTx(ctx, nil)) {
		t.Fatal("a nil transaction counts as one")
	}
}

func TestAppTransaction_WithoutWardenTransaction(t *testing.T) {
	s := newStore(t)
	w := newWarden(t, s)
	ctx := context.Background()
	err := pgx.BeginFunc(ctx, testPool(t), func(tx pgx.Tx) error {
		if err := w.System().Assign(s.WithTx(ctx, tx), "kemi", "owner", wardn.NewScope("organisation", "acme")); !errors.Is(err, wardn.ErrNoTransaction) {
			t.Errorf("change without Warden.Transaction: %v, want ErrNoTransaction", err)
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatal(err)
	}
}

func TestCheckEach(t *testing.T) {
	s := newStore(t)
	w := newWarden(t, s)
	ctx := context.Background()
	org := wardn.NewScope("organisation", "acme")
	var products []wardn.Scope
	for i := range 100 {
		p := wardn.NewScope("product", fmt.Sprintf("p%03d", i))
		if err := w.Link(ctx, p, org); err != nil {
			t.Fatal(err)
		}
		if i%3 == 0 {
			if err := w.System().Assign(ctx, "kemi", "agent", p); err != nil {
				t.Fatal(err)
			}
		}
		products = append(products, p)
	}
	got := w.CanEach(ctx, "kemi", "ticket:reply", products)
	for i, p := range products {
		if got[i] != (i%3 == 0) {
			t.Fatalf("CanEach[%s] = %v", p, got[i])
		}
	}
}

func TestRunInTx(t *testing.T) {
	s := newStore(t)
	w := newWarden(t, s)
	table := appTable(t, s)
	ctx := context.Background()
	org, product := wardn.NewScope("organisation", "acme"), wardn.NewScope("product", "helpdesk")
	if err := w.Link(ctx, product, org); err != nil {
		t.Fatal(err)
	}
	addMember := func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO "+table+" (user_id) VALUES ($1)", "kemi"); err != nil {
			return err
		}
		return w.System().Assign(ctx, "kemi", "agent", product)
	}
	w.Can(ctx, "kemi", "ticket:reply", product) // cache "no access"

	// fn fails: everything rolls back.
	err := s.RunInTx(ctx, w, pgx.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		if err := addMember(ctx, tx); err != nil {
			return err
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatalf("fn's error: %v", err)
	}
	if count(t, table) != 0 || w.Can(ctx, "kemi", "ticket:reply", product) {
		t.Fatal("a failed fn left the row or the access behind")
	}

	// fn panics: rolls back, and the panic reaches the caller.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic was swallowed")
			}
		}()
		_ = s.RunInTx(ctx, w, pgx.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
			if err := addMember(ctx, tx); err != nil {
				return err
			}
			panic("boom")
		})
	}()
	if count(t, table) != 0 || w.Can(ctx, "kemi", "ticket:reply", product) {
		t.Fatal("a panicking fn left the row or the access behind")
	}

	// fn succeeds, with options: commits, and the cache follows.
	opts := pgx.TxOptions{IsoLevel: pgx.Serializable}
	err = s.RunInTx(ctx, w, opts, func(txCtx context.Context, tx pgx.Tx) error {
		if err := addMember(txCtx, tx); err != nil {
			return err
		}
		// Outside the transaction: caches "no access" until RunInTx ends
		// wardn's transaction after the commit.
		if w.Can(ctx, "kemi", "ticket:reply", product) {
			t.Error("an uncommitted assignment is visible outside the transaction")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count(t, table) != 1 {
		t.Fatal("the commit lost the application's row")
	}
	if !w.Can(ctx, "kemi", "ticket:reply", product) {
		t.Fatal("committed access is not visible: the cache kept the old state")
	}

	if err := s.RunInTx(ctx, nil, pgx.TxOptions{}, addMember); err == nil {
		t.Error("a nil Warden accepted")
	}
	if err := s.RunInTx(ctx, w, pgx.TxOptions{}, nil); err == nil {
		t.Error("a nil function accepted")
	}
}
