package wardn

// Tests named TestThreat_<ID>_... prove the mitigations listed in
// docs/THREAT_MODEL.md. Every threat must have at least one before v1.0.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// leakyStore ignores the requested user and scopes and returns every
// assignment it holds: a buggy or malicious Store.
type leakyStore struct {
	*MemoryStore
	all []Assignment
}

func (l *leakyStore) Assign(ctx context.Context, a Assignment) error {
	l.all = append(l.all, a)
	return l.MemoryStore.Assign(ctx, a)
}

func (l *leakyStore) Assignments(context.Context, string, []Scope) ([]Assignment, error) {
	return l.all, nil
}

func TestThreat_T01_CrossTenantAccessDenied(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "admin_a", "org_admin", org1)
	assign(t, w, "admin_a", "teller", branch1)
	for _, s := range []Scope{org2, region2, branch2} {
		for _, p := range []string{"customer:view", "loan:approve", PermRolesAssign} {
			wantCan(t, w, "admin_a", p, s, false)
		}
	}
}

func TestThreat_T01_StoreLeakIgnored(t *testing.T) {
	ls := &leakyStore{MemoryStore: NewMemoryStore()}
	w, _ := newBank(t, func(c *Config) { c.Store = ls })
	assign(t, w, "admin_a", "org_admin", org1)
	assign(t, w, "victim", "teller", branch2)
	// The store returns other users' and other tenants' assignments; wardn
	// must ignore them.
	wantCan(t, w, "admin_a", "loan:approve", branch2, false)
	wantCan(t, w, "intruder", "loan:create", branch2, false)
	wantCan(t, w, "victim", "loan:create", branch2, true)
}

func TestThreat_T07_DenyCannotBeBypassed(t *testing.T) {
	w, _ := newBank(t)
	ctx := context.Background()
	assign(t, w, "u", "suspended", org1)
	// Pile on every allowing role at every level.
	assign(t, w, "u", "super_admin", Global)
	assign(t, w, "u", "org_admin", org1)
	assign(t, w, "u", "loan_officer", region1)
	assign(t, w, "u", "teller", branch1)
	for _, p := range w.Catalog() {
		if w.Can(ctx, "u", p.Name, branch1) {
			t.Errorf("%s allowed despite deny", p.Name)
		}
	}
	perms, err := w.PermissionsOf(ctx, "u", branch1)
	if err != nil || len(perms) != 0 {
		t.Errorf("PermissionsOf = %v, %v", perms, err)
	}
}

func TestThreat_T08_FailClosedOnEveryErrorPath(t *testing.T) {
	// See also TestRule5_FailClosed. Here: errors never yield Allowed.
	fs := &faultyStore{Store: NewMemoryStore(), failAssignments: true}
	w, _ := newBank(t, func(c *Config) { c.Store = fs })
	inputs := []struct {
		user, perm string
		scope      Scope
	}{
		{"u", "customer:view", branch1}, // store error
		{"", "customer:view", branch1},  // invalid user
		{"u", "nope:nope", branch1},     // undefined permission
		{"u", "*", branch1},             // wildcard
		{"u", "customer:view", NewScope("x", "y")},
		{"u", "customer:view", NewScope("branch", "bad\x00id")},
	}
	for _, in := range inputs {
		d, err := w.Check(context.Background(), in.user, in.perm, in.scope)
		if err == nil || d.Allowed {
			t.Errorf("Check(%q, %q, %v) = %+v, %v; want deny with error", in.user, in.perm, in.scope, d, err)
		}
	}
}

func TestThreat_T09_RevokedAccessStopsImmediately(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "u", "teller", branch1)
	wantCan(t, w, "u", "loan:create", branch1, true)
	if err := w.System().Revoke(context.Background(), "u", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	wantCan(t, w, "u", "loan:create", branch1, false)
}

// Each instance decides by its own clock, and nothing it shares with other
// instances (store or cache) carries a decision or a time: an instance
// whose clock is off is wrong by at most its skew, never longer.
func TestThreat_T19_ClockSkewIsBoundedBySkew(t *testing.T) {
	const skew = 2 * time.Second
	store, cache := NewMemoryStore(), NewMemoryCache()
	shared := func(c *Config) { c.Store, c.Cache = store, cache }
	exact, exactClock := newBank(t, shared)
	slow, slowClock := newBank(t, shared) // same store and cache, separate clock
	slowClock.Advance(-skew)

	start, end := t0.Add(time.Hour), t0.Add(2*time.Hour)
	assign(t, exact, "temp", "loan_officer", branch1, From(start), Until(end))
	at := func(tm time.Time) { // move both clocks; slow stays skew behind
		exactClock.Advance(tm.Sub(exactClock.Now()))
		slowClock.Advance(tm.Add(-skew).Sub(slowClock.Now()))
	}

	at(start)
	wantCan(t, exact, "temp", "loan:approve", branch1, true)
	wantCan(t, slow, "temp", "loan:approve", branch1, false) // starts late...
	at(start.Add(skew))
	wantCan(t, slow, "temp", "loan:approve", branch1, true) // ...by exactly the skew

	at(end) // both instances have the assignment cached by now
	wantCan(t, exact, "temp", "loan:approve", branch1, false)
	wantCan(t, slow, "temp", "loan:approve", branch1, true) // ends late...
	at(end.Add(skew))
	wantCan(t, slow, "temp", "loan:approve", branch1, false) // ...by exactly the skew
}

func TestThreat_T09_ExpiredAccessStopsWithoutCleanup(t *testing.T) {
	w, clock := newBank(t)
	assign(t, w, "temp", "loan_officer", branch1, Until(t0.Add(time.Hour)))
	ctx := w.WithMemo(context.Background())
	wantCanCtx(ctx, t, w, "temp", "loan:approve", branch1, true)
	clock.Advance(time.Hour)
	// Same request, memoised assignments: expiry still applies.
	wantCanCtx(ctx, t, w, "temp", "loan:approve", branch1, false)
}

func TestThreat_T10_DeletedRoleGrantsNothing(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	w1, _ := newBank(t, func(c *Config) { c.Store = store })
	assign(t, w1, "u", "auditor", Global)
	wantCan(t, w1, "u", "report:export", Global, true)

	// Redeploy with the auditor role removed from the policy.
	p := mustParse(t, bankYAML)
	delete(p.Roles, "auditor")
	w2, err := New(Config{Policy: p, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if w2.Can(ctx, "u", "report:export", Global) {
		t.Fatal("removed role still grants access")
	}
}

// corruptStore returns a parent of the wrong type.
type corruptStore struct{ *MemoryStore }

func (c corruptStore) Parent(context.Context, Scope) (Scope, bool, error) {
	return org2, true, nil // a branch's parent must be a region
}

func TestThreat_T11_CorruptLinkFailsClosed(t *testing.T) {
	w, err := New(Config{Policy: mustParse(t, bankYAML), Store: corruptStore{NewMemoryStore()}})
	if err != nil {
		t.Fatal(err)
	}
	assign(t, w, "admin_b", "org_admin", org2)
	d, err := w.Check(context.Background(), "admin_b", "loan:approve", branch1)
	if !errors.Is(err, ErrInvalidLink) || d.Allowed {
		t.Fatalf("got %+v, %v; want deny with ErrInvalidLink", d, err)
	}
}

func TestThreat_T11_LinkMustMatchPolicy(t *testing.T) {
	w, _ := newBank(t)
	// An attacker-chosen link that skips the hierarchy is rejected.
	if err := w.Link(context.Background(), branch1, org2); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("err = %v", err)
	}
}

func TestThreat_T12_HierarchyLookupsAreBounded(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	// A misbehaving resolver that always claims another parent.
	w, _ := newBank(t, func(c *Config) {
		c.ParentOf = func(_ context.Context, s Scope) (Scope, bool, error) {
			mu.Lock()
			calls++
			mu.Unlock()
			switch s.Type {
			case "branch":
				return NewScope("region", s.ID+"x"), true, nil
			default:
				return NewScope("organisation", s.ID+"x"), true, nil
			}
		}
	})
	w.Can(context.Background(), "u", "loan:view", branch1)
	if calls > 2 { // branch → region → organisation, then stop
		t.Fatalf("%d parent lookups for a 3-level hierarchy", calls)
	}
}

func TestThreat_T13_ScopeIdentityIsExact(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "u", "org_admin", NewScope("organisation", "o1"))
	look := []Scope{
		NewScope("organisation", "O1"),
		NewScope("organisation", "o1:x"),
		NewScope("organisation", "ｏ1"), // fullwidth o
	}
	for _, s := range look {
		wantCan(t, w, "u", "loan:view", s, false)
	}
	for _, bad := range []string{"o1 ", " o1", "o1\u200b", "o\u202e1", "o1\n"} {
		_, err := w.Check(context.Background(), "u", "loan:view", NewScope("organisation", bad))
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("scope ID %q accepted: %v", bad, err)
		}
		if err := w.System().Assign(context.Background(), bad, "auditor", Global); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("user ID %q accepted: %v", bad, err)
		}
	}
}

func TestThreat_T14_PermissionSpoofingRejected(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "root", "super_admin", Global)
	for _, p := range []string{"loan:approve ", "Loan:approve", "lоan:approve", "loan:approve\x00", "loan:approve:x"} {
		d, err := w.Check(context.Background(), "root", p, Global)
		if err == nil || d.Allowed {
			t.Errorf("Check(%q) = %+v, %v; want error", p, d, err)
		}
	}
	src := "permissions:\n  lоan:approve: Look-alike\nroles:\n  x: [lоan:approve]\n"
	if _, err := ParsePolicy([]byte(src), "t.yaml"); err == nil {
		if err := mustParse(t, src).Validate(); err == nil {
			t.Error("look-alike permission accepted in policy")
		}
	}
}

func TestThreat_T16_TyposFailLoudly(t *testing.T) {
	w, _ := newBank(t)
	_, err := w.Check(context.Background(), "u", "loan:aprove", branch1)
	if err == nil || !strings.Contains(err.Error(), `did you mean "loan:approve"`) {
		t.Errorf("Check typo: %v", err)
	}
	err = w.System().Assign(context.Background(), "u", "tellr", branch1)
	if err == nil || !strings.Contains(err.Error(), `did you mean "teller"`) {
		t.Errorf("Assign typo: %v", err)
	}
	_, err = ParsePolicy([]byte("permissions:\n  a:b: X\nrole:\n  x: [a:b]\n"), "t.yaml")
	if err == nil || !strings.Contains(err.Error(), `did you mean "roles"`) {
		t.Errorf("policy typo: %v", err)
	}
}

func TestThreat_T18_GlobalCheckUsesOnlyGlobalAssignments(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "u", "org_admin", org1)
	assign(t, w, "u", "teller", branch1)
	for _, p := range []string{"customer:view", "loan:approve"} {
		wantCan(t, w, "u", p, Global, false)
	}
}

func TestThreat_T23_OversizedInputsRejected(t *testing.T) {
	w, _ := newBank(t)
	long := strings.Repeat("x", maxIDLen+1)
	if _, err := w.Check(context.Background(), long, "loan:view", Global); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("long user ID: %v", err)
	}
	if _, err := w.Check(context.Background(), "u", "loan:view", NewScope("branch", long)); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("long scope ID: %v", err)
	}
	if _, err := w.Check(context.Background(), "u", "a:"+long, Global); err == nil {
		t.Error("long permission accepted")
	}
	if _, err := ParsePolicy(make([]byte, maxPolicySize+1), "big.yaml"); err == nil {
		t.Error("oversized policy accepted")
	}
	// Alias expansion ("billion laughs") is rejected before expansion.
	bomb := "a: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\nroles: *c\n"
	if _, err := ParsePolicy([]byte(bomb), "bomb.yaml"); err == nil || !strings.Contains(err.Error(), "aliases") {
		t.Errorf("alias bomb: %v", err)
	}
}

func TestThreat_T25_ConcurrentUseIsSafe(t *testing.T) {
	w, _ := newBank(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			user := []string{"a", "b"}[i%2]
			for range 200 {
				_ = w.System().Assign(ctx, user, "teller", branch1)
				_ = w.Can(ctx, user, "loan:create", branch1)
				_, _ = w.PermissionsOf(ctx, user, branch1)
				_ = w.System().Revoke(ctx, user, "teller", branch1)
			}
		})
	}
	// A shared per-request memo used from several goroutines.
	mctx := w.WithMemo(ctx)
	for range 4 {
		wg.Go(func() {
			for range 200 {
				_ = w.Can(mctx, "a", "loan:create", branch1)
				_ = w.System().Assign(mctx, "c", "auditor", Global)
			}
		})
	}
	wg.Wait()
}

func TestThreat_T25_PolicyChangesAfterNewHaveNoEffect(t *testing.T) {
	p := mustParse(t, bankYAML)
	w, err := New(Config{Policy: p})
	if err != nil {
		t.Fatal(err)
	}
	assign(t, w, "u", "teller", branch1)
	// Mutating the Policy after New must not change the running Warden.
	r := p.Roles["teller"]
	r.Allow[0] = "loan:approve"
	r.Allow = append(r.Allow, "report:export")
	p.Roles["teller"] = r
	p.Roles["evil"] = Role{Allow: []string{"*"}}
	p.Permissions["evil:perm"] = "x"

	wantCan(t, w, "u", "loan:approve", branch1, false)
	wantCan(t, w, "u", "report:export", branch1, false)
	if err := w.System().Assign(context.Background(), "u", "evil", Global); err == nil {
		t.Error("role added after New is assignable")
	}
}
