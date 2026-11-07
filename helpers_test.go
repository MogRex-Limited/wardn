package wardn

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// bankYAML is a realistic multi-level policy used across tests.
const bankYAML = `version: 1
scopes:
  organisation: {}
  region: { parent: organisation }
  branch: { parent: region }
permissions:
  customer:view: View customers
  customer:edit: Edit customers
  loan:create: Create loans
  loan:view: View loans
  loan:approve: Approve loans
  report:export: Export reports
roles:
  super_admin:
    description: Everything, everywhere
    allow: ["*"]
    assignable_at: [global]
  org_admin:
    allow: ["*"]
    assignable_at: [organisation]
  ops_admin:
    description: Everything except approving loans
    allow: ["*"]
    deny: [loan:approve]
  teller:
    assignable_at: [branch]
    allow: [customer:view, loan:create, loan:view]
  branch_manager:
    description: Runs one branch, including its roles
    assignable_at: [branch]
    allow: [customer:view, customer:edit, "loan:*", wardn:roles.assign, wardn:roles.manage]
  loan_officer: ["loan:*"]
  auditor: [customer:view, loan:view, report:export]
  suspended:
    deny: ["*"]
`

var (
	org1    = NewScope("organisation", "o1")
	region1 = NewScope("region", "r1")
	branch1 = NewScope("branch", "b1")
	org2    = NewScope("organisation", "o2")
	region2 = NewScope("region", "r2")
	branch2 = NewScope("branch", "b2")
)

var t0 = time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)

// fakeClock is a settable clock for tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func mustParse(t testing.TB, src string) *Policy {
	t.Helper()
	p, err := ParsePolicy([]byte(src), "test.yaml")
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	return p
}

// newBank returns a Warden for bankYAML with a fake clock at t0, and the
// standard hierarchy linked: b1 → r1 → o1 and b2 → r2 → o2.
func newBank(t testing.TB, mod ...func(*Config)) (*Warden, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: t0}
	cfg := Config{Policy: mustParse(t, bankYAML), Clock: clock}
	for _, m := range mod {
		m(&cfg)
	}
	w, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if cfg.ParentOf == nil {
		ctx := context.Background()
		for _, l := range [][2]Scope{{branch1, region1}, {region1, org1}, {branch2, region2}, {region2, org2}} {
			if err := w.Link(ctx, l[0], l[1]); err != nil {
				t.Fatalf("Link: %v", err)
			}
		}
	}
	return w, clock
}

func assign(t testing.TB, w *Warden, user, role string, scope Scope, opts ...AssignOption) {
	t.Helper()
	if err := w.System().Assign(context.Background(), user, role, scope, opts...); err != nil {
		t.Fatalf("Assign(%s, %s, %s): %v", user, role, scope, err)
	}
}

func wantCan(t testing.TB, w *Warden, user, perm string, scope Scope, want bool) {
	t.Helper()
	d, err := w.Check(context.Background(), user, perm, scope)
	if err != nil {
		t.Fatalf("Check(%s, %s, %s): unexpected error: %v", user, perm, scope, err)
	}
	if d.Allowed != want {
		t.Fatalf("Check(%s, %s, %s) = %v, want %v (reason: %s)", user, perm, scope, d.Allowed, want, d.Reason)
	}
	if got := w.Can(context.Background(), user, perm, scope); got != want {
		t.Fatalf("Can(%s, %s, %s) = %v, but Check said %v", user, perm, scope, got, want)
	}
}

var errStore = errors.New("store unavailable")

// faultyStore wraps a Store and fails selected operations.
type faultyStore struct {
	Store
	failAssignments, failParent, failAssign, failRevoke, failLink bool
}

func (f *faultyStore) Assignments(ctx context.Context, user string, scopes []Scope) ([]Assignment, error) {
	if f.failAssignments {
		return nil, errStore
	}
	return f.Store.Assignments(ctx, user, scopes)
}

func (f *faultyStore) Parent(ctx context.Context, child Scope) (Scope, bool, error) {
	if f.failParent {
		return Scope{}, false, errStore
	}
	return f.Store.Parent(ctx, child)
}

func (f *faultyStore) Assign(ctx context.Context, a Assignment) error {
	if f.failAssign {
		return errStore
	}
	return f.Store.Assign(ctx, a)
}

func (f *faultyStore) Revoke(ctx context.Context, user, role string, scope Scope) error {
	if f.failRevoke {
		return errStore
	}
	return f.Store.Revoke(ctx, user, role, scope)
}

func (f *faultyStore) Link(ctx context.Context, child, parent Scope) error {
	if f.failLink {
		return errStore
	}
	return f.Store.Link(ctx, child, parent)
}

// countingStore counts store reads, to test memoisation.
type countingStore struct {
	Store
	mu                   sync.Mutex
	assignments, parents int
}

func (c *countingStore) Assignments(ctx context.Context, user string, scopes []Scope) ([]Assignment, error) {
	c.mu.Lock()
	c.assignments++
	c.mu.Unlock()
	return c.Store.Assignments(ctx, user, scopes)
}

func (c *countingStore) Parent(ctx context.Context, child Scope) (Scope, bool, error) {
	c.mu.Lock()
	c.parents++
	c.mu.Unlock()
	return c.Store.Parent(ctx, child)
}
