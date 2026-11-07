package wardn

import (
	"context"
	"math/rand/v2"
	"slices"
	"testing"
)

// TestProperty_GuardNeverEscalates attacks the escalation guard with random
// worlds. An actor with random roles tries random assignments. Whenever the
// guard allows one, the independent reference implementation must confirm
// that the actor held wardn:roles.assign there and every permission the
// role grants. For roles without wildcards, the guard must also allow every
// assignment that passes those checks, so it is not merely refusing
// everything.
func TestProperty_GuardNeverEscalates(t *testing.T) {
	worlds := 300
	if testing.Short() {
		worlds = 60
	}
	var allowed, refused int
	for seed := range uint64(worlds) {
		r := rand.New(rand.NewPCG(seed, 0x6775617264)) //nolint:gosec // G404: seeded for reproducible tests, not security
		wd := randomWorld(r)
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
			t.Fatalf("seed %d: %v", seed, err)
		}
		actor := wd.users[0]
		roleNames := slices.Sorted(func(yield func(string) bool) {
			for k := range wd.policy.Roles {
				if !yield(k) {
					return
				}
			}
		})

		for range 40 {
			role := roleNames[r.IntN(len(roleNames))]
			scope := wd.scopes[r.IntN(len(wd.scopes))]
			target := "target"

			// What the reference says, before the attempt.
			canAssign := wd.referenceAllowed(actor, PermRolesAssign, scope, t0)
			holdsAll, hasWildcard := true, false
			// The actor must hold what the role grants and what it denies.
			for _, p := range slices.Concat(wd.policy.Roles[role].Allow, wd.policy.Roles[role].Deny) {
				hasWildcard = hasWildcard || isWildcard(p)
				for _, perm := range w.policy.permList {
					if naiveMatch(p, perm) && !wd.referenceAllowed(actor, perm, scope, t0) {
						holdsAll = false
					}
				}
			}
			assignable := len(wd.policy.Roles[role].AssignableAt) == 0 || slices.Contains(wd.policy.Roles[role].AssignableAt, scopeTypeName(scope))

			err := w.Assign(WithUser(ctx, actor), target, role, scope)
			if err == nil {
				allowed++
				if !canAssign || !holdsAll {
					t.Fatalf("seed %d: ESCALATION: %s assigned %q at %s (can assign: %v, holds all: %v)\nroles: %+v\nassignments: %+v",
						seed, actor, role, scope, canAssign, holdsAll, wd.policy.Roles, wd.assignments)
				}
				_ = store.Revoke(ctx, target, role, scope) // keep the world unchanged
				continue
			}
			refused++
			if canAssign && holdsAll && assignable && !hasWildcard {
				t.Fatalf("seed %d: guard refused a legitimate assignment of %q at %s: %v", seed, role, scope, err)
			}
		}
	}
	if allowed < worlds/6 || refused < worlds/6 {
		t.Fatalf("unbalanced: %d allowed, %d refused", allowed, refused)
	}
	t.Logf("%d worlds: %d assignments allowed, %d refused, no escalation", worlds, allowed, refused)
}
