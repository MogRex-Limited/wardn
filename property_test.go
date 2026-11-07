package wardn

import (
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
)

// The property test generates random worlds (policies, hierarchies,
// assignments, time windows) and checks the engine against a deliberately
// naive reference implementation of the evaluation rules in DESIGN.md §5.
// The reference shares no code with the engine.

type world struct {
	policy      *Policy
	links       map[Scope]Scope
	assignments []Assignment
	scopes      []Scope
	users       []string
}

var (
	propResources = []string{"loan", "loans", "customer", "report"} // "loan"/"loans" probes wildcard boundaries
	propActions   = []string{"view", "edit", "approve"}
)

func randomWorld(r *rand.Rand) *world {
	p := &Policy{
		Scopes: map[string]ScopeType{
			"organisation": {},
			"region":       {Parent: "organisation"},
			"branch":       {Parent: "region"},
			"team":         {}, // a second, unrelated tree
		},
		Permissions: map[string]string{},
		Roles:       map[string]Role{},
	}
	for _, res := range propResources {
		for _, act := range propActions {
			if r.IntN(3) > 0 {
				p.Permissions[res+":"+act] = "generated"
			}
		}
	}
	if len(p.Permissions) == 0 {
		p.Permissions["loan:view"] = "generated"
	}
	perms := slices.Sorted(func(yield func(string) bool) {
		for k := range p.Permissions {
			if !yield(k) {
				return
			}
		}
	})
	patterns := slices.Clone(perms)
	for _, res := range propResources {
		if slices.ContainsFunc(perms, func(s string) bool { return strings.HasPrefix(s, res+":") }) {
			patterns = append(patterns, res+":*")
		}
	}
	patterns = append(patterns, "*", PermRolesManage, PermRolesAssign)

	scopeTypes := []string{globalName, "organisation", "region", "branch", "team"}
	for i := range 1 + r.IntN(5) {
		var role Role
		for range 1 + r.IntN(3) {
			role.Allow = appendUnique(role.Allow, patterns[r.IntN(len(patterns))])
		}
		if r.IntN(3) == 0 {
			role.Deny = appendUnique(role.Deny, patterns[r.IntN(len(patterns))])
		}
		role.Allow = slices.DeleteFunc(role.Allow, func(s string) bool { return slices.Contains(role.Deny, s) })
		if len(role.Allow) == 0 && len(role.Deny) == 0 {
			role.Allow = []string{perms[0]}
		}
		if r.IntN(3) == 0 {
			for range 1 + r.IntN(2) {
				role.AssignableAt = appendUnique(role.AssignableAt, scopeTypes[r.IntN(len(scopeTypes))])
			}
		}
		p.Roles[fmt.Sprintf("role%d", i)] = role
	}

	w := &world{policy: p, links: map[Scope]Scope{}, users: []string{"u0", "u1", "u2"}}
	orgs := []Scope{NewScope("organisation", "o0"), NewScope("organisation", "o1")}
	regions := []Scope{NewScope("region", "r0"), NewScope("region", "r1"), NewScope("region", "r2")}
	branches := []Scope{NewScope("branch", "b0"), NewScope("branch", "b1"), NewScope("branch", "b2"), NewScope("branch", "b3")}
	for _, reg := range regions {
		if r.IntN(5) > 0 {
			w.links[reg] = orgs[r.IntN(len(orgs))]
		}
	}
	for _, b := range branches {
		if r.IntN(5) > 0 {
			w.links[b] = regions[r.IntN(len(regions))]
		}
	}
	w.scopes = slices.Concat([]Scope{Global, NewScope("team", "t0")}, orgs, regions, branches)

	roleNames := append(slices.Sorted(func(yield func(string) bool) {
		for k := range p.Roles {
			if !yield(k) {
				return
			}
		}
	}), "ghost_role") // never defined: rule 6
	seen := map[string]bool{}
	for range 6 + r.IntN(14) {
		a := Assignment{
			User:  w.users[r.IntN(len(w.users))],
			Role:  roleNames[r.IntN(len(roleNames))],
			Scope: w.scopes[r.IntN(len(w.scopes))],
		}
		switch r.IntN(8) {
		case 0:
			a.ExpiresAt = t0 // expired exactly now
		case 1:
			a.StartsAt = t0.Add(time.Second) // not yet started
		case 2:
			a.StartsAt, a.ExpiresAt = t0.Add(-time.Hour), t0.Add(time.Hour) // active
		}
		key := a.User + "\x00" + a.Role + "\x00" + a.Scope.Type + "\x00" + a.Scope.ID
		if seen[key] {
			continue // the store keeps one assignment per (user, role, scope)
		}
		seen[key] = true
		w.assignments = append(w.assignments, a)
	}
	return w
}

func appendUnique(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

// referenceAllowed is the naive reference implementation of DESIGN.md §5.
func (w *world) referenceAllowed(user, perm string, scope Scope, now time.Time) bool {
	chain := []Scope{scope}
	if !scope.IsGlobal() {
		for cur := scope; ; {
			parent, ok := w.links[cur]
			if !ok {
				break
			}
			chain = append(chain, parent)
			cur = parent
		}
		chain = append(chain, Global)
	}
	denied, allowed := false, false
	for _, a := range w.assignments {
		if a.User != user || !slices.Contains(chain, a.Scope) {
			continue
		}
		if !a.StartsAt.IsZero() && now.Before(a.StartsAt) {
			continue
		}
		if !a.ExpiresAt.IsZero() && !now.Before(a.ExpiresAt) {
			continue
		}
		role, ok := w.policy.Roles[a.Role]
		if !ok {
			continue
		}
		typ := a.Scope.Type
		if a.Scope.IsGlobal() {
			typ = globalName
		}
		if len(role.AssignableAt) > 0 && !slices.Contains(role.AssignableAt, typ) {
			continue
		}
		for _, d := range role.Deny {
			denied = denied || naiveMatch(d, perm)
		}
		for _, al := range role.Allow {
			allowed = allowed || naiveMatch(al, perm)
		}
	}
	return allowed && !denied
}

func naiveMatch(pattern, perm string) bool {
	if pattern == "*" || pattern == perm {
		return true
	}
	return strings.HasSuffix(pattern, ":*") && strings.HasPrefix(perm, pattern[:len(pattern)-1])
}

func TestProperty_EngineMatchesReference(t *testing.T) {
	const worlds = 400
	var checks, allows, denies int
	for seed := range uint64(worlds) {
		r := rand.New(rand.NewPCG(seed, 0x77617264)) //nolint:gosec // G404: seeded for reproducible tests, not security
		wd := randomWorld(r)
		if err := wd.policy.Validate(); err != nil {
			t.Fatalf("seed %d: generator produced an invalid policy: %v", seed, err)
		}
		store := NewMemoryStore()
		ctx := context.Background()
		for child, parent := range wd.links {
			_ = store.Link(ctx, child, parent)
		}
		for _, a := range wd.assignments {
			_ = store.Assign(ctx, a)
		}
		w, err := New(Config{Policy: wd.policy, Store: store, Clock: &fakeClock{now: t0}})
		if err != nil {
			t.Fatalf("seed %d: New: %v", seed, err)
		}
		memoCtx := w.WithMemo(ctx)

		for _, user := range wd.users {
			for _, scope := range wd.scopes {
				var wantPerms []string
				for _, perm := range w.policy.permList {
					want := wd.referenceAllowed(user, perm, scope, t0)
					d, err := w.Check(ctx, user, perm, scope)
					if err != nil {
						t.Fatalf("seed %d: Check(%s, %s, %s): %v", seed, user, perm, scope, err)
					}
					checks++
					if d.Allowed != want {
						t.Fatalf("seed %d: Check(%s, %s, %s) = %v, reference says %v\nreason: %s\npolicy: %+v\nassignments: %+v\nlinks: %v",
							seed, user, perm, scope, d.Allowed, want, d.Reason, wd.policy.Roles, wd.assignments, wd.links)
					}
					if got := w.Can(memoCtx, user, perm, scope); got != want {
						t.Fatalf("seed %d: memoised Can(%s, %s, %s) = %v, want %v", seed, user, perm, scope, got, want)
					}
					checkDecisionExplains(t, seed, wd, d)
					if want {
						allows++
						wantPerms = append(wantPerms, perm)
					} else {
						denies++
					}
				}
				got, err := w.PermissionsOf(ctx, user, scope)
				if err != nil || !slices.Equal(got, wantPerms) {
					t.Fatalf("seed %d: PermissionsOf(%s, %s) = %v, %v; want %v", seed, user, scope, got, err, wantPerms)
				}
			}
		}
	}
	// Guard against a generator that only ever produces one outcome.
	if allows < checks/20 || denies < checks/20 {
		t.Fatalf("unbalanced coverage: %d checks, %d allows, %d denies", checks, allows, denies)
	}
	t.Logf("%d worlds, %d checks: %d allowed, %d denied", worlds, checks, allows, denies)
}

// checkDecisionExplains verifies that a decision's explanation is true: the
// named role exists and its named rule really matches the permission.
func checkDecisionExplains(t *testing.T, seed uint64, wd *world, d Decision) {
	t.Helper()
	if d.Role == "" {
		if d.Allowed {
			t.Fatalf("seed %d: allowed without a role: %+v", seed, d)
		}
		return
	}
	role, ok := wd.policy.Roles[d.Role]
	if !ok {
		t.Fatalf("seed %d: decision names unknown role: %+v", seed, d)
	}
	rules := role.Deny
	if d.Allowed {
		rules = role.Allow
	}
	if !slices.Contains(rules, d.Rule) || !naiveMatch(d.Rule, d.Permission) {
		t.Fatalf("seed %d: decision rule does not explain the outcome: %+v (role %+v)", seed, d, role)
	}
}
