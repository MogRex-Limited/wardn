package wardn

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// Rule 1: default deny.
func TestRule1_DefaultDeny(t *testing.T) {
	w, _ := newBank(t)
	wantCan(t, w, "nobody", "customer:view", branch1, false)
	wantCan(t, w, "nobody", "customer:view", Global, false)

	d, _ := w.Check(context.Background(), "nobody", "loan:approve", branch1)
	if d.Role != "" || d.Rule != "" || !strings.Contains(d.Reason, "no role grants") {
		t.Errorf("decision = %+v", d)
	}
}

// Rule 2: roles inherit downward through linked scopes.
func TestRule2_Inheritance(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "ada", "org_admin", org1)
	for _, s := range []Scope{org1, region1, branch1} {
		wantCan(t, w, "ada", "loan:approve", s, true)
	}
	// Not upward, not sideways, not to Global.
	wantCan(t, w, "ada", "loan:approve", org2, false)
	wantCan(t, w, "ada", "loan:approve", branch2, false)
	wantCan(t, w, "ada", "loan:approve", Global, false)

	d, _ := w.Check(context.Background(), "ada", "loan:approve", branch1)
	if d.Role != "org_admin" || d.At != org1 || d.Rule != "*" {
		t.Errorf("decision = %+v", d)
	}

	// A role at a middle level applies below it but not above.
	assign(t, w, "bo", "auditor", region1)
	wantCan(t, w, "bo", "report:export", branch1, true)
	wantCan(t, w, "bo", "report:export", region1, true)
	wantCan(t, w, "bo", "report:export", org1, false)
}

// Global assignments apply everywhere.
func TestRule2_GlobalAppliesEverywhere(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "root", "super_admin", Global)
	for _, s := range []Scope{Global, org1, region2, branch1, NewScope("branch", "unlinked")} {
		wantCan(t, w, "root", "loan:approve", s, true)
		wantCan(t, w, "root", PermRolesManage, s, true)
	}
}

// Rule 3: allows from several roles accumulate.
func TestRule3_AllowsAccumulate(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "cy", "teller", branch1)
	assign(t, w, "cy", "auditor", region1)
	wantCan(t, w, "cy", "loan:create", branch1, true)   // teller
	wantCan(t, w, "cy", "report:export", branch1, true) // auditor, inherited
	wantCan(t, w, "cy", "loan:approve", branch1, false) // neither

	perms, err := w.PermissionsOf(context.Background(), "cy", branch1)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"customer:view", "loan:create", "loan:view", "report:export"}
	if !slices.Equal(perms, want) {
		t.Errorf("PermissionsOf = %v, want %v", perms, want)
	}
}

// Rule 4: deny wins over any allow, from any role, at any level.
func TestRule4_DenyWins(t *testing.T) {
	w, _ := newBank(t)

	// Within one role.
	assign(t, w, "di", "ops_admin", org1)
	wantCan(t, w, "di", "loan:create", branch1, true)
	wantCan(t, w, "di", "loan:approve", branch1, false)

	// Across roles: a nearer allow does not beat a farther deny.
	assign(t, w, "di", "loan_officer", branch1)
	wantCan(t, w, "di", "loan:approve", branch1, false)
	d, _ := w.Check(context.Background(), "di", "loan:approve", branch1)
	if d.Role != "ops_admin" || d.At != org1 || d.Rule != "loan:approve" || !strings.Contains(d.Reason, "denied by role") {
		t.Errorf("deny decision must name its source: %+v", d)
	}

	// A global super_admin does not override a deny.
	assign(t, w, "di", "super_admin", Global)
	wantCan(t, w, "di", "loan:approve", branch1, false)

	// A deny-only role blocks everything, even for a super admin.
	assign(t, w, "ed", "super_admin", Global)
	assign(t, w, "ed", "suspended", branch1)
	wantCan(t, w, "ed", "customer:view", branch1, false)
	wantCan(t, w, "ed", "customer:view", branch2, true) // only where suspended applies
}

// Rule 5: fail closed on store errors.
func TestRule5_FailClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault func(*faultyStore)
	}{
		{"assignments", func(f *faultyStore) { f.failAssignments = true }},
		{"parent", func(f *faultyStore) { f.failParent = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := &faultyStore{Store: NewMemoryStore()}
			w, _ := newBank(t, func(c *Config) { c.Store = fs })
			assign(t, w, "root", "super_admin", Global)
			tc.fault(fs)

			d, err := w.Check(context.Background(), "root", "customer:view", branch1)
			if !errors.Is(err, errStore) {
				t.Fatalf("err = %v, want store error", err)
			}
			if d.Allowed {
				t.Fatal("allowed on store error")
			}
			if w.Can(context.Background(), "root", "customer:view", branch1) ||
				w.CanAny(context.Background(), "root", branch1, "customer:view") ||
				w.CanAll(context.Background(), "root", branch1, "customer:view") {
				t.Fatal("Can/CanAny/CanAll allowed on store error")
			}
			if _, err := w.PermissionsOf(context.Background(), "root", branch1); err == nil {
				t.Fatal("PermissionsOf: no error")
			}
			if _, err := w.RolesOf(context.Background(), "root", branch1); err == nil {
				t.Fatal("RolesOf: no error")
			}
		})
	}

	t.Run("ParentOf", func(t *testing.T) {
		w, _ := newBank(t, func(c *Config) {
			c.ParentOf = func(context.Context, Scope) (Scope, bool, error) { return Scope{}, false, errStore }
		})
		assign(t, w, "root", "super_admin", Global)
		if d, err := w.Check(context.Background(), "root", "customer:view", branch1); !errors.Is(err, errStore) || d.Allowed {
			t.Fatalf("got %+v, %v", d, err)
		}
		// Global checks need no parent lookup.
		wantCan(t, w, "root", "customer:view", Global, true)
	})
}

// Rule 6: an assignment whose role no longer exists grants nothing.
func TestRule6_DanglingRole(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Assign(context.Background(), Assignment{User: "fay", Role: "retired_role", Scope: Global}); err != nil {
		t.Fatal(err)
	}
	w, _ := newBank(t, func(c *Config) { c.Store = store })
	wantCan(t, w, "fay", "customer:view", Global, false)
	roles, err := w.RolesOf(context.Background(), "fay", Global)
	if err != nil || len(roles) != 0 {
		t.Fatalf("RolesOf = %v, %v", roles, err)
	}
	// It can still be revoked, to clean up.
	if err := w.System().Revoke(context.Background(), "fay", "retired_role", Global); err != nil {
		t.Fatal(err)
	}
}

// Rule 7: time windows are enforced on every check.
func TestRule7_TimeWindows(t *testing.T) {
	w, clock := newBank(t)
	assign(t, w, "gus", "loan_officer", branch1, From(t0.Add(24*time.Hour)), Until(t0.Add(72*time.Hour)))

	wantCan(t, w, "gus", "loan:approve", branch1, false) // not started
	clock.Advance(24 * time.Hour)
	wantCan(t, w, "gus", "loan:approve", branch1, true) // exactly at start: inclusive
	clock.Advance(48*time.Hour - time.Nanosecond)
	wantCan(t, w, "gus", "loan:approve", branch1, true) // last instant
	clock.Advance(time.Nanosecond)
	wantCan(t, w, "gus", "loan:approve", branch1, false) // exactly at expiry: exclusive

	// Only an upper bound.
	assign(t, w, "hal", "teller", branch1, Until(clock.Now().Add(time.Hour)))
	wantCan(t, w, "hal", "loan:create", branch1, true)
	clock.Advance(time.Hour)
	wantCan(t, w, "hal", "loan:create", branch1, false)

	// Re-assigning replaces the window: permanent again.
	assign(t, w, "hal", "teller", branch1)
	wantCan(t, w, "hal", "loan:create", branch1, true)
}

// A role that the policy no longer allows at a scope stops applying there.
func TestAssignableAtEnforcedAtCheck(t *testing.T) {
	store := NewMemoryStore()
	// Simulates an assignment made before assignable_at was tightened.
	if err := store.Assign(context.Background(), Assignment{User: "ivy", Role: "teller", Scope: org1}); err != nil {
		t.Fatal(err)
	}
	w, _ := newBank(t, func(c *Config) { c.Store = store })
	wantCan(t, w, "ivy", "loan:create", branch1, false)
}

func TestUnlinkedScopeInheritsOnlyGlobal(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "jo", "org_admin", org1)
	assign(t, w, "jo", "auditor", Global)
	orphan := NewScope("branch", "orphan")
	wantCan(t, w, "jo", "loan:approve", orphan, false) // org role not inherited
	wantCan(t, w, "jo", "report:export", orphan, true) // global still applies
}

func TestParentOf(t *testing.T) {
	parents := map[Scope]Scope{branch1: region1, region1: org1}
	calls := 0
	w, _ := newBank(t, func(c *Config) {
		c.ParentOf = func(_ context.Context, s Scope) (Scope, bool, error) {
			calls++
			p, ok := parents[s]
			return p, ok, nil
		}
	})
	assign(t, w, "kai", "org_admin", org1)
	wantCan(t, w, "kai", "loan:approve", branch1, true)
	if calls == 0 {
		t.Error("ParentOf was not called")
	}
	if err := w.Link(context.Background(), branch2, region2); !errors.Is(err, ErrLinksExternal) {
		t.Errorf("Link with ParentOf: %v", err)
	}
}

func TestCheckInputErrors(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "root", "super_admin", Global)
	ctx := context.Background()

	_, err := w.Check(ctx, "root", "loan:aprove", branch1)
	var ue *UndefinedError
	if !errors.As(err, &ue) || ue.Kind != "permission" || ue.Suggestion != "loan:approve" {
		t.Fatalf("undefined permission: %v", err)
	}
	if want := `wardn: permission "loan:aprove" is not defined; did you mean "loan:approve"?`; err.Error() != want {
		t.Errorf("message = %q, want %q", err.Error(), want)
	}

	if _, err := w.Check(ctx, "root", "loan:*", branch1); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("wildcard check: %v", err)
	}
	if _, err := w.Check(ctx, "root", "loan:approve", NewScope("brnach", "b1")); !errors.As(err, &ue) || ue.Suggestion != "branch" {
		t.Errorf("undefined scope type: %v", err)
	}
	if _, err := w.Check(ctx, "root", "loan:approve", Scope{ID: "x"}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("scope without type: %v", err)
	}
	if _, err := w.Check(ctx, "root", "loan:approve", NewScope("branch", "")); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("scope without ID: %v", err)
	}
	if _, err := w.Check(ctx, "", "loan:approve", branch1); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("empty user: %v", err)
	}
	if w.CanAny(ctx, "root", branch1, "loan:approve", "loan:typo") {
		t.Error("CanAny with an undefined permission returned true")
	}
	if w.CanAll(ctx, "root", branch1) {
		t.Error("CanAll with no permissions returned true")
	}
}

func TestCanAnyCanAll(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "lu", "teller", branch1)
	ctx := context.Background()
	if !w.CanAny(ctx, "lu", branch1, "loan:approve", "loan:create") {
		t.Error("CanAny: want true")
	}
	if w.CanAny(ctx, "lu", branch1, "loan:approve", "report:export") {
		t.Error("CanAny: want false")
	}
	if !w.CanAll(ctx, "lu", branch1, "loan:create", "loan:view") {
		t.Error("CanAll: want true")
	}
	if w.CanAll(ctx, "lu", branch1, "loan:create", "loan:approve") {
		t.Error("CanAll: want false")
	}
}

func TestRolesOf(t *testing.T) {
	w, clock := newBank(t)
	until := t0.Add(time.Hour)
	assign(t, w, "mo", "teller", branch1, Until(until))
	assign(t, w, "mo", "auditor", org1)
	assign(t, w, "mo", "loan_officer", branch2) // elsewhere
	roles, err := w.RolesOf(context.Background(), "mo", branch1)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 || roles[0].Role != "teller" || roles[1].Role != "auditor" || !roles[0].ExpiresAt.Equal(until) {
		t.Fatalf("RolesOf = %+v", roles)
	}
	clock.Advance(time.Hour)
	roles, _ = w.RolesOf(context.Background(), "mo", branch1)
	if len(roles) != 1 || roles[0].Role != "auditor" {
		t.Fatalf("after expiry RolesOf = %+v", roles)
	}
}

func TestOnDecision(t *testing.T) {
	var got []Decision
	var errs []error
	w, _ := newBank(t, func(c *Config) {
		c.OnDecision = func(_ context.Context, d Decision, err error) {
			got = append(got, d)
			errs = append(errs, err)
		}
	})
	assign(t, w, "ned", "teller", branch1)
	ctx := context.Background()
	w.Can(ctx, "ned", "loan:create", branch1)
	w.CanAll(ctx, "ned", branch1, "loan:create", "loan:approve")
	w.Can(ctx, "ned", "loan:typo", branch1)

	if len(got) != 4 {
		t.Fatalf("got %d decisions, want 4", len(got))
	}
	if !got[0].Allowed || got[2].Allowed || got[2].Permission != "loan:approve" {
		t.Errorf("decisions = %+v", got)
	}
	if errs[3] == nil || got[3].Allowed || !strings.Contains(got[3].Reason, "error") {
		t.Errorf("error decision = %+v, %v", got[3], errs[3])
	}
}

func TestMemo(t *testing.T) {
	cs := &countingStore{Store: NewMemoryStore()}
	w, _ := newBank(t, func(c *Config) { c.Store = cs })
	assign(t, w, "ola", "teller", branch1)

	ctx := w.WithMemo(context.Background())
	if w.WithMemo(ctx) != ctx {
		t.Error("WithMemo is not idempotent")
	}
	cs.assignments, cs.parents = 0, 0
	for range 5 {
		wantCanCtx(ctx, t, w, "ola", "loan:create", branch1, true)
	}
	if cs.assignments != 1 || cs.parents != 2 {
		t.Errorf("with memo: %d assignment reads, %d parent reads; want 1 and 2", cs.assignments, cs.parents)
	}

	// A change within the request is visible to later checks in it.
	if err := w.System().Revoke(ctx, "ola", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	wantCanCtx(ctx, t, w, "ola", "loan:create", branch1, false)

	// Without a memo, every check reads the store: revocations apply at once.
	cs.assignments = 0
	for range 3 {
		w.Can(context.Background(), "ola", "loan:create", branch1)
	}
	if cs.assignments != 3 {
		t.Errorf("without memo: %d assignment reads, want 3", cs.assignments)
	}

	// Two Wardens sharing a context never share memoised results.
	w2, _ := newBank(t)
	ctx2 := w2.WithMemo(ctx)
	if w2.memoFrom(ctx2) == w.memoFrom(ctx2) {
		t.Error("Wardens share a memo")
	}
}

func wantCanCtx(ctx context.Context, t *testing.T, w *Warden, user, perm string, scope Scope, want bool) {
	t.Helper()
	if got := w.Can(ctx, user, perm, scope); got != want {
		d, err := w.Check(ctx, user, perm, scope)
		t.Fatalf("Can(%s, %s, %s) = %v, want %v (%s, %v)", user, perm, scope, got, want, d.Reason, err)
	}
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()
	if _, ok := UserOf(ctx); ok {
		t.Error("UserOf on empty context")
	}
	if _, ok := UserOf(WithUser(ctx, "")); ok {
		t.Error("UserOf accepted empty user")
	}
	if id, ok := UserOf(WithUser(ctx, "u1")); !ok || id != "u1" {
		t.Errorf("UserOf = %q, %v", id, ok)
	}
	if _, ok := ScopeOf(ctx); ok {
		t.Error("ScopeOf on empty context")
	}
	if s, ok := ScopeOf(WithScope(ctx, branch1)); !ok || s != branch1 {
		t.Errorf("ScopeOf = %v, %v", s, ok)
	}
}
