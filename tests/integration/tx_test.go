package integration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/MogRex-Limited/wardn"
	wardnsql "github.com/MogRex-Limited/wardn/store/sql"
)

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

// txSetup is a Warden over a fresh SQL store with a memory cache, plus an
// application table next to wardn's, written in the same transactions.
type txSetup struct {
	db    *sql.DB
	store *wardnsql.Store
	w     *wardn.Warden
	table string
}

func newTxSetup(t *testing.T, d database) *txSetup {
	t.Helper()
	db := d.open(t)
	store := newStore(t, db)
	p, err := wardn.ParsePolicy([]byte(txPolicy), "wardn.yaml")
	if err != nil {
		t.Fatal(err)
	}
	w, err := wardn.New(wardn.Config{Policy: p, Store: store, Cache: wardn.NewMemoryCache()})
	if err != nil {
		t.Fatal(err)
	}
	table := store.TablePrefix() + "app_members"
	if _, err := db.ExecContext(context.Background(), "CREATE TABLE "+table+" (user_id VARCHAR(64) NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	return &txSetup{db: db, store: store, w: w, table: table}
}

// insertMember is the application's INSERT, in the database's placeholder
// syntax.
func (s *txSetup) insertMember() string {
	if s.store.Dialect() == wardnsql.Postgres {
		return "INSERT INTO " + s.table + " (user_id) VALUES ($1)"
	}
	return "INSERT INTO " + s.table + " (user_id) VALUES (?)"
}

func (s *txSetup) members(t *testing.T) int {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+s.table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// addMember writes the application's row and wardn's assignment in one
// transaction, as an application's "add member" would.
func (s *txSetup) addMember(ctx context.Context, t *testing.T, user string, product wardn.Scope, commit bool) {
	t.Helper()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	txCtx, ended := s.w.Transaction(s.store.WithTx(ctx, tx))
	if _, err := tx.ExecContext(txCtx, s.insertMember(), user); err != nil {
		t.Fatal(err)
	}
	if err := s.w.System().Assign(txCtx, user, "agent", product); err != nil {
		t.Fatal(err)
	}
	if !s.w.Can(txCtx, user, "ticket:reply", product) {
		t.Error("the transaction does not see its own assignment")
	}
	if s.w.Can(ctx, user, "ticket:reply", product) {
		t.Error("an uncommitted assignment is visible outside the transaction")
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
}

func TestAppTransaction_CommitAndRollback(t *testing.T) {
	for _, d := range databases(t) {
		t.Run(d.name, func(t *testing.T) {
			s := newTxSetup(t, d)
			ctx := context.Background()
			org, product := wardn.NewScope("organisation", "acme"), wardn.NewScope("product", "helpdesk")
			if err := s.w.Link(ctx, product, org); err != nil {
				t.Fatal(err)
			}

			s.w.Can(ctx, "kemi", "ticket:reply", product) // cache "no access"
			s.addMember(ctx, t, "kemi", product, false)
			if s.members(t) != 0 || s.w.Can(ctx, "kemi", "ticket:reply", product) {
				t.Fatal("rollback left the member or the access behind")
			}

			s.addMember(ctx, t, "kemi", product, true)
			if s.members(t) != 1 {
				t.Fatal("commit lost the application's row")
			}
			if !s.w.Can(ctx, "kemi", "ticket:reply", product) {
				t.Fatal("committed access is not visible: the cache kept the old state")
			}
		})
	}
}

func TestAppTransaction_FailedWriteKeepsItUsable(t *testing.T) {
	for _, d := range databases(t) {
		t.Run(d.name, func(t *testing.T) {
			s := newTxSetup(t, d)
			ctx := context.Background()
			org := wardn.NewScope("organisation", "acme")
			spec := wardn.RoleSpec{Name: "Triage", Allow: []string{"ticket:read"}, AssignableAt: []string{"product"}}

			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback() //nolint:errcheck // no-op after Commit
			txCtx, ended := s.w.Transaction(s.store.WithTx(ctx, tx))
			created, err := s.w.System().CreateRole(txCtx, org, spec)
			if err != nil {
				t.Fatal(err)
			}
			// Same name: fails on the unique constraint. On PostgreSQL that
			// would abort the whole transaction without wardn's savepoint.
			if _, err := s.w.System().CreateRole(txCtx, org, spec); !errors.Is(err, wardn.ErrRoleNameTaken) {
				t.Fatalf("duplicate role name: %v, want ErrRoleNameTaken", err)
			}
			if _, err := tx.ExecContext(txCtx, s.insertMember(), "kemi"); err != nil {
				t.Fatalf("transaction unusable after wardn's failed write: %v", err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := ended(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := s.w.CustomRole(ctx, created.ID); err != nil {
				t.Fatalf("the first role was lost: %v", err)
			}
			if s.members(t) != 1 {
				t.Fatalf("after commit: %d members, want 1", s.members(t))
			}
		})
	}
}

func TestAppTransaction_BelongsToOneStore(t *testing.T) {
	for _, d := range databases(t) {
		t.Run(d.name, func(t *testing.T) {
			db := d.open(t)
			a, b := newStore(t, db), newStore(t, db)
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback() //nolint:errcheck // test cleanup
			ctx := a.WithTx(context.Background(), tx)
			if !a.InTx(ctx) || b.InTx(ctx) {
				t.Fatalf("InTx: a=%v b=%v; want true, false", a.InTx(ctx), b.InTx(ctx))
			}
			if a.InTx(a.WithTx(context.Background(), nil)) {
				t.Fatal("a nil transaction counts as one")
			}
		})
	}
}

// TestCheckEachSQL filters a long list in a few queries, beyond the SQL
// store's 64-scope limit per query.
func TestCheckEachSQL(t *testing.T) {
	for _, d := range databases(t) {
		t.Run(d.name, func(t *testing.T) {
			s := newTxSetup(t, d)
			ctx := context.Background()
			org := wardn.NewScope("organisation", "acme")
			var products []wardn.Scope
			for i := range 150 {
				p := wardn.NewScope("product", fmt.Sprintf("p%03d", i))
				if err := s.w.Link(ctx, p, org); err != nil {
					t.Fatal(err)
				}
				if i%3 == 0 {
					if err := s.w.System().Assign(ctx, "kemi", "agent", p); err != nil {
						t.Fatal(err)
					}
				}
				products = append(products, p)
			}
			for pass := range 2 { // the second reads the cache
				got := s.w.CanEach(ctx, "kemi", "ticket:reply", products)
				for i, p := range products {
					if want := i%3 == 0; got[i] != want {
						t.Fatalf("pass %d: CanEach[%s] = %v, want %v", pass, p, got[i], want)
					}
				}
			}
		})
	}
}

func TestRunInTx(t *testing.T) {
	for _, d := range databases(t) {
		t.Run(d.name, func(t *testing.T) {
			s := newTxSetup(t, d)
			ctx := context.Background()
			org, product := wardn.NewScope("organisation", "acme"), wardn.NewScope("product", "helpdesk")
			if err := s.w.Link(ctx, product, org); err != nil {
				t.Fatal(err)
			}
			addMember := func(ctx context.Context, tx *sql.Tx) error {
				if _, err := tx.ExecContext(ctx, s.insertMember(), "kemi"); err != nil {
					return err
				}
				return s.w.System().Assign(ctx, "kemi", "agent", product)
			}
			errRollback := errors.New("roll back")
			s.w.Can(ctx, "kemi", "ticket:reply", product) // cache "no access"

			err := s.store.RunInTx(ctx, s.w, nil, func(ctx context.Context, tx *sql.Tx) error {
				if err := addMember(ctx, tx); err != nil {
					return err
				}
				if !s.w.Can(ctx, "kemi", "ticket:reply", product) {
					t.Error("the transaction does not see its own assignment")
				}
				return errRollback
			})
			if !errors.Is(err, errRollback) {
				t.Fatalf("fn's error: %v", err)
			}
			if s.members(t) != 0 || s.w.Can(ctx, "kemi", "ticket:reply", product) {
				t.Fatal("a failed fn left the row or the access behind")
			}

			func() {
				defer func() {
					if recover() == nil {
						t.Error("the panic was swallowed")
					}
				}()
				_ = s.store.RunInTx(ctx, s.w, nil, func(ctx context.Context, tx *sql.Tx) error {
					if err := addMember(ctx, tx); err != nil {
						return err
					}
					panic("boom")
				})
			}()
			if s.members(t) != 0 || s.w.Can(ctx, "kemi", "ticket:reply", product) {
				t.Fatal("a panicking fn left the row or the access behind")
			}

			err = s.store.RunInTx(ctx, s.w, &sql.TxOptions{}, func(txCtx context.Context, tx *sql.Tx) error {
				if err := addMember(txCtx, tx); err != nil {
					return err
				}
				// Outside the transaction: caches "no access" until RunInTx
				// ends wardn's transaction after the commit.
				if s.w.Can(ctx, "kemi", "ticket:reply", product) {
					t.Error("an uncommitted assignment is visible outside the transaction")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if s.members(t) != 1 {
				t.Fatal("the commit lost the application's row")
			}
			if !s.w.Can(ctx, "kemi", "ticket:reply", product) {
				t.Fatal("committed access is not visible: the cache kept the old state")
			}
			if err := s.store.RunInTx(ctx, nil, nil, addMember); err == nil {
				t.Error("a nil Warden accepted")
			}
		})
	}
}
