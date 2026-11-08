package wardn

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"testing"
)

// TestProperty_CheckEachMatchesCheck: CheckEach must decide every scope
// exactly as Check does, with the same explanation, with and without a
// cache, and in any order, including duplicates.
func TestProperty_CheckEachMatchesCheck(t *testing.T) {
	worlds := 200
	if testing.Short() {
		worlds = 20
	}
	var checks int
	for seed := range uint64(worlds) {
		r := rand.New(rand.NewPCG(seed, 0x65616368)) //nolint:gosec // G404: seeded for reproducible tests, not security
		wd := randomWorld(r)
		store := NewMemoryStore()
		ctx := context.Background()
		for child, parent := range wd.links {
			_ = store.Link(ctx, child, parent)
		}
		for _, a := range wd.assignments {
			_ = store.Assign(ctx, a)
		}
		plain, err := New(Config{Policy: wd.policy, Store: store, Clock: &fakeClock{now: t0}})
		if err != nil {
			t.Fatalf("seed %d: New: %v", seed, err)
		}
		withCache, err := New(Config{Policy: wd.policy, Store: store, Clock: &fakeClock{now: t0}, Cache: NewMemoryCache()})
		if err != nil {
			t.Fatalf("seed %d: New: %v", seed, err)
		}
		// Shuffled, with duplicates.
		scopes := append(slices.Clone(wd.scopes), wd.scopes[:len(wd.scopes)/2]...)
		r.Shuffle(len(scopes), func(i, j int) { scopes[i], scopes[j] = scopes[j], scopes[i] })

		for _, user := range wd.users {
			for _, perm := range plain.policy.permList {
				for name, w := range map[string]*Warden{"plain": plain, "cached": withCache} {
					for pass := range 2 { // the second pass reads the cache
						ds, err := w.CheckEach(ctx, user, perm, scopes)
						if err != nil {
							t.Fatalf("seed %d: %s CheckEach(%s, %s): %v", seed, name, user, perm, err)
						}
						can := w.CanEach(ctx, user, perm, scopes)
						for i, s := range scopes {
							want, err := plain.Check(ctx, user, perm, s)
							if err != nil {
								t.Fatal(err)
							}
							if ds[i] != want || can[i] != want.Allowed {
								t.Fatalf("seed %d: %s pass %d: CheckEach(%s, %s)[%s] = %+v (CanEach %v), Check = %+v",
									seed, name, pass, user, perm, s, ds[i], can[i], want)
							}
							checks++
						}
					}
				}
			}
		}
	}
	t.Logf("%d worlds, %d scope decisions compared", worlds, checks)
}

func TestCheckEachReadsTogether(t *testing.T) {
	counting := &countingStore{Store: NewMemoryStore()}
	w, _ := newBank(t, func(c *Config) { c.Store = counting })
	assign(t, w, "seun", "auditor", region1)
	assign(t, w, "seun", "teller", branch2)

	// Forty branches under one region, plus the two from the bank.
	scopes := []Scope{branch1, branch2, region1, org2}
	for i := range 40 {
		b := NewScope("branch", "x"+string(rune('a'+i%26))+string(rune('a'+i/26)))
		if err := w.Link(context.Background(), b, region1); err != nil {
			t.Fatal(err)
		}
		scopes = append(scopes, b)
	}
	counting.assignments, counting.parents = 0, 0

	got := w.CanEach(context.Background(), "seun", "loan:view", scopes)
	counting.mu.Lock()
	reads := counting.assignments
	counting.mu.Unlock()
	// 44 scopes and their ancestors are 49 distinct scopes: two batches of
	// at most 32, rather than one read per scope.
	if reads != 2 {
		t.Errorf("CheckEach read assignments %d times for 44 scopes, want 2", reads)
	}
	for i, s := range scopes {
		if got[i] != w.Can(context.Background(), "seun", "loan:view", s) {
			t.Errorf("CanEach and Can disagree at %s", s)
		}
	}
	if !got[0] || !got[1] || !got[2] || got[3] {
		t.Errorf("CanEach = %v", got[:4])
	}
}

func TestCheckEachStoreCalls(t *testing.T) {
	counting := &countingStore{Store: NewMemoryStore()}
	w, _ := newBank(t, func(c *Config) { c.Store = counting })
	scopes := []Scope{branch1, region1, org1, branch2, region2, org2, Global}
	counting.assignments, counting.parents = 0, 0
	w.CanEach(context.Background(), "seun", "loan:view", scopes)
	if counting.assignments != 1 {
		t.Errorf("%d assignment reads for 7 scopes, want 1", counting.assignments)
	}
	if counting.parents > 4 {
		t.Errorf("%d parent reads, want each parent read once (4)", counting.parents)
	}
}

func TestCheckEachErrorsDenyEverything(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "ada", "org_admin", org1)
	ctx := context.Background()
	tooMany := make([]Scope, MaxCheckEach+1)
	for i := range tooMany {
		tooMany[i] = org1
	}
	for name, tc := range map[string]struct {
		user, perm string
		scopes     []Scope
		want       error
	}{
		"undefined permission": {"ada", "loan:destroy", []Scope{org1}, nil},
		"wildcard permission":  {"ada", "loan:*", []Scope{org1}, ErrInvalidInput},
		"invalid user":         {"", "loan:view", []Scope{org1}, ErrInvalidInput},
		"invalid scope":        {"ada", "loan:view", []Scope{org1, {Type: "branch"}}, ErrInvalidInput},
		"too many scopes":      {"ada", "loan:view", tooMany, ErrInvalidInput},
	} {
		ds, err := w.CheckEach(ctx, tc.user, tc.perm, tc.scopes)
		if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
		if len(ds) != len(tc.scopes) {
			t.Errorf("%s: %d decisions for %d scopes", name, len(ds), len(tc.scopes))
		}
		for _, d := range ds {
			if d.Allowed {
				t.Errorf("%s: allowed despite the error", name)
			}
		}
		if slices.Contains(w.CanEach(ctx, tc.user, tc.perm, tc.scopes), true) {
			t.Errorf("%s: CanEach allowed despite the error", name)
		}
	}

	faulty := &faultyStore{Store: NewMemoryStore()}
	w2, _ := newBank(t, func(c *Config) { c.Store = faulty })
	assign(t, w2, "ada", "org_admin", org1)
	faulty.failAssignments = true
	if _, err := w2.CheckEach(ctx, "ada", "loan:view", []Scope{org1, branch1}); !errors.Is(err, errStore) {
		t.Errorf("store failure: %v", err)
	}
}

func TestCheckEachEmptyAndAudited(t *testing.T) {
	var decisions int
	w, _ := newBank(t, func(c *Config) {
		c.OnDecision = func(context.Context, Decision, error) { decisions++ }
	})
	ds, err := w.CheckEach(context.Background(), "ada", "loan:view", nil)
	if err != nil || ds == nil || len(ds) != 0 {
		t.Errorf("empty CheckEach = %v, %v", ds, err)
	}
	w.CanEach(context.Background(), "ada", "loan:view", []Scope{org1, branch1, branch1})
	if decisions != 3 {
		t.Errorf("OnDecision called %d times for 3 scopes", decisions)
	}
}
