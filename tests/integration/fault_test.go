package integration

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"modernc.org/sqlite"

	"github.com/MogRex-Limited/wardn"
	wardnsql "github.com/MogRex-Limited/wardn/store/sql"
)

// A database/sql driver that wraps SQLite and fails the n-th operation
// (statement, transaction begin or commit), to prove that a failure part
// way through a multi-statement write never leaves a half-written record.

var errDBFault = errors.New("injected database fault")

type faultControl struct {
	mu          sync.Mutex
	calls, fail int
}

func (f *faultControl) tick() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail > 0 && f.calls == f.fail {
		return errDBFault
	}
	return nil
}

func (f *faultControl) arm(n int) { f.mu.Lock(); f.calls, f.fail = 0, n; f.mu.Unlock() }

func (f *faultControl) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

type faultConnector struct {
	dsn string
	ctl *faultControl
}

func (c *faultConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := (&sqlite.Driver{}).Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &faultConn{Conn: conn, ctl: c.ctl}, nil
}

func (c *faultConnector) Driver() driver.Driver { return &sqlite.Driver{} }

type faultConn struct {
	driver.Conn
	ctl *faultControl
}

func (c *faultConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.ctl.tick(); err != nil {
		return nil, err
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}

func (c *faultConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if err := c.ctl.tick(); err != nil {
		return nil, err
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}

func (c *faultConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if err := c.ctl.tick(); err != nil {
		return nil, err
	}
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &faultTx{Tx: tx, ctl: c.ctl}, nil
}

type faultTx struct {
	driver.Tx
	ctl *faultControl
}

func (t *faultTx) Commit() error {
	if err := t.ctl.tick(); err != nil {
		_ = t.Rollback()
		return err
	}
	return t.Tx.Commit()
}

var faultDBSeq atomic.Int64

// faultStore returns a migrated SQL store on a fresh SQLite file, and its
// fault control.
func faultSQLStore(ctx context.Context, t *testing.T) (*wardnsql.Store, *faultControl) {
	t.Helper()
	ctl := &faultControl{}
	path := filepath.Join(t.TempDir(), fmt.Sprintf("fault%d.db", faultDBSeq.Add(1)))
	db := sql.OpenDB(&faultConnector{dsn: "file:" + path + "?_pragma=busy_timeout(10000)", ctl: ctl})
	t.Cleanup(func() { _ = db.Close() })
	s, err := wardnsql.New(db, wardnsql.WithDialect(wardnsql.SQLite))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return s, ctl
}

var (
	faultOwner = wardn.NewScope("organisation", "o1")
	created    = time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)
)

func faultRole(id, name string, version int, allow ...string) wardn.CustomRole {
	return wardn.CustomRole{ID: id, Owner: faultOwner, Name: name, NameKey: name, Allow: allow,
		AssignableAt: []string{"organisation", "branch"}, Version: version, CreatedAt: created, UpdatedAt: created}
}

// roleState reads a role: (exists, its content as one comparable string).
func roleState(ctx context.Context, t *testing.T, s *wardnsql.Store, ctl *faultControl) (bool, string) {
	const id = "cr-a"
	t.Helper()
	ctl.arm(0)
	rs, err := s.Roles(ctx, []string{id})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) == 0 {
		return false, ""
	}
	r := rs[0]
	return true, fmt.Sprintf("%s|%d|%v|%v", r.Name, r.Version, r.Allow, r.AssignableAt)
}

// TestSQLFaults_RoleWritesAreAtomic: with each database operation failing
// in turn, a custom role is always either entirely old or entirely new.
func TestSQLFaults_RoleWritesAreAtomic(t *testing.T) {
	ctx := context.Background()
	v1 := faultRole("cr-a", "desk", 1, "loan:view", "customer:view", "report:export")
	v2 := faultRole("cr-a", "desk two", 2, "loan:approve")
	v2.AssignableAt = []string{"branch"}

	ops := []struct {
		name  string
		setup func(*wardnsql.Store) error
		run   func(*wardnsql.Store) error
		// acceptable states after a failure: before and after
		before, after func() (bool, string)
	}{
		{
			name:  "CreateRole",
			setup: func(*wardnsql.Store) error { return nil },
			run:   func(s *wardnsql.Store) error { return s.CreateRole(ctx, v1) },
		},
		{
			name:  "UpdateRole",
			setup: func(s *wardnsql.Store) error { return s.CreateRole(ctx, v1) },
			run:   func(s *wardnsql.Store) error { return s.UpdateRole(ctx, v2, 1) },
		},
		{
			name:  "DeleteRole",
			setup: func(s *wardnsql.Store) error { return s.CreateRole(ctx, v1) },
			run:   func(s *wardnsql.Store) error { return s.DeleteRole(ctx, "cr-a") },
		},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			// Clean run: the states before and after, and the number of
			// database operations.
			s, ctl := faultSQLStore(ctx, t)
			if err := op.setup(s); err != nil {
				t.Fatal(err)
			}
			_, beforeState := roleState(ctx, t, s, ctl)
			beforeExists, _ := roleState(ctx, t, s, ctl)
			ctl.arm(0)
			if err := op.run(s); err != nil {
				t.Fatal(err)
			}
			calls := ctl.count()
			afterExists, afterState := roleState(ctx, t, s, ctl)

			for n := 1; n <= calls; n++ {
				s, ctl := faultSQLStore(ctx, t)
				if err := op.setup(s); err != nil {
					t.Fatal(err)
				}
				ctl.arm(n)
				err := op.run(s)
				if err == nil {
					t.Fatalf("operation %d/%d failed but the write reported success", n, calls)
				}
				exists, state := roleState(ctx, t, s, ctl)
				okBefore := exists == beforeExists && state == beforeState
				okAfter := exists == afterExists && state == afterState
				if !okBefore && !okAfter {
					t.Fatalf("operation %d/%d failed and left a half-written role: exists=%v %q\n before: %v %q\n after:  %v %q",
						n, calls, exists, state, beforeExists, beforeState, afterExists, afterState)
				}
			}
			t.Logf("%d database operations, each failed in turn: always all-or-nothing", calls)
		})
	}
}

// TestSQLFaults_Warden: Warden operations over a faulty SQL store never
// report success on failure, and never allow on error.
func TestSQLFaults_Warden(t *testing.T) {
	ctx := context.Background()
	p, err := wardn.ParsePolicy([]byte(chiPolicy), "wardn.yaml")
	if err != nil {
		t.Fatal(err)
	}
	branch := wardn.NewScope("branch", "lagos")
	setup := func(t *testing.T) (*wardn.Warden, *faultControl) {
		t.Helper()
		s, ctl := faultSQLStore(ctx, t)
		w := wardn.MustNew(wardn.Config{Policy: p, Store: s}) //nolint:contextcheck // New takes no context by design
		if err := w.Link(ctx, branch, faultOwner); err != nil {
			t.Fatal(err)
		}
		if err := w.System().Assign(ctx, "ada", "org_admin", faultOwner); err != nil {
			t.Fatal(err)
		}
		return w, ctl
	}
	actions := map[string]func(*wardn.Warden) error{
		"check": func(w *wardn.Warden) error {
			d, err := w.Check(ctx, "ada", "loan:approve", branch)
			if err == nil && !d.Allowed {
				return errors.New("denied without error")
			}
			if err != nil && d.Allowed {
				t.Fatal("allowed with an error")
			}
			return err
		},
		"assign": func(w *wardn.Warden) error { return w.Assign(wardn.WithUser(ctx, "ada"), "bayo", "teller", branch) },
		"create": func(w *wardn.Warden) error {
			_, err := w.CreateRole(wardn.WithUser(ctx, "ada"), faultOwner, wardn.RoleSpec{Name: "Desk", Allow: []string{"loan:create"}})
			return err
		},
	}
	names := make([]string, 0, len(actions))
	for k := range actions {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, name := range names {
		act := actions[name]
		t.Run(name, func(t *testing.T) {
			w, ctl := setup(t)
			ctl.arm(0)
			if err := act(w); err != nil {
				t.Fatal(err)
			}
			calls := ctl.count()
			for n := 1; n <= calls; n++ {
				w, ctl := setup(t)
				ctl.arm(n)
				if err := act(w); err == nil {
					t.Fatalf("database operation %d/%d failed but %s succeeded", n, calls, name)
				}
			}
		})
	}
}
