package wardn

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// cachedBank returns two Wardens (two "instances" of the application)
// sharing one store and one cache.
func cachedBank(t *testing.T) (a, b *Warden, store *countingStore, clock *fakeClock) {
	t.Helper()
	store = &countingStore{Store: NewMemoryStore()}
	cache := NewMemoryCache()
	a, clock = newBank(t, func(c *Config) { c.Store = store; c.Cache = cache })
	b, err := New(Config{Policy: mustParse(t, bankYAML), Store: store, Cache: cache, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return a, b, store, clock
}

func TestCacheServesRepeatedReads(t *testing.T) {
	a, _, store, _ := cachedBank(t)
	assign(t, a, "u", "teller", branch1)
	wantCan(t, a, "u", "loan:create", branch1, true) // fills the cache
	store.assignments, store.parents = 0, 0
	for range 5 { // separate requests: no per-request memo
		wantCan(t, a, "u", "loan:create", branch1, true)
	}
	if store.assignments != 0 || store.parents != 0 {
		t.Fatalf("cached reads still hit the store: %d assignment and %d parent reads", store.assignments, store.parents)
	}
}

func TestCacheChangesVisibleOnEveryInstanceImmediately(t *testing.T) {
	a, b, _, _ := cachedBank(t)
	ctx := context.Background()

	assign(t, a, "u", "teller", branch1)
	wantCan(t, b, "u", "loan:create", branch1, true) // B caches the grant
	if err := a.System().Revoke(ctx, "u", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	wantCan(t, b, "u", "loan:create", branch1, false) // revocation on A is seen by B at once (T09)

	// Custom role edits and deletions.
	r := mustCreate(t, a, org1, RoleSpec{Name: "Desk", Allow: []string{"loan:view"}, AssignableAt: []string{"branch"}})
	assign(t, a, "v", r.ID, branch1)
	wantCan(t, b, "v", "loan:view", branch1, true)
	wantCan(t, b, "v", "loan:create", branch1, false)
	if _, err := a.System().UpdateRole(ctx, r.ID, RoleSpec{Name: "Desk", Allow: []string{"loan:create"}, AssignableAt: []string{"branch"}}, 1); err != nil {
		t.Fatal(err)
	}
	wantCan(t, b, "v", "loan:view", branch1, false)
	wantCan(t, b, "v", "loan:create", branch1, true)
	if err := a.System().DeleteRole(ctx, r.ID, Cascade()); err != nil {
		t.Fatal(err)
	}
	wantCan(t, b, "v", "loan:create", branch1, false)

	// Moving a branch to another region in the same organisation.
	assign(t, a, "w", "auditor", region1)
	wantCan(t, b, "w", "report:export", branch1, true)
	if err := a.Link(ctx, branch1, NewScope("region", "r1b")); err != nil {
		t.Fatal(err)
	}
	wantCan(t, b, "w", "report:export", branch1, false)

	// Moving a branch into another region of the same organisation: the
	// cached assignment list for the branch lacks the new region's roles,
	// so without invalidation the user would be wrongly denied.
	r1c := NewScope("region", "r1c")
	if err := a.Link(ctx, r1c, org1); err != nil {
		t.Fatal(err)
	}
	b2 := NewScope("branch", "b2c")
	if err := a.Link(ctx, b2, region1); err != nil {
		t.Fatal(err)
	}
	assign(t, a, "y", "auditor", r1c)
	wantCan(t, b, "y", "report:export", b2, false) // cached for b2c under org1
	if err := a.Link(ctx, b2, r1c); err != nil {
		t.Fatal(err)
	}
	wantCan(t, b, "y", "report:export", b2, true)

	// Global changes.
	assign(t, a, "x", "super_admin", Global)
	wantCan(t, b, "x", "loan:approve", branch2, true)
	if err := a.System().Revoke(ctx, "x", "super_admin", Global); err != nil {
		t.Fatal(err)
	}
	wantCan(t, b, "x", "loan:approve", branch2, false)
}

func TestCacheNeverExtendsTimeLimitedAccess(t *testing.T) {
	a, b, _, clock := cachedBank(t)
	assign(t, a, "temp", "teller", branch1, Until(t0.Add(time.Minute)))
	wantCan(t, b, "temp", "loan:create", branch1, true) // cached, with a 5s TTL on the real clock
	clock.Advance(time.Minute)
	wantCan(t, b, "temp", "loan:create", branch1, false) // the cached data is still evaluated against the clock
}

func TestCacheTTLIsTheSafetyNetForDirectWrites(t *testing.T) {
	now := t0
	var mu sync.Mutex
	cache := NewMemoryCache(WithCacheClock(func() time.Time { mu.Lock(); defer mu.Unlock(); return now }))
	store := NewMemoryStore()
	w, _ := newBank(t, func(c *Config) { c.Store = store; c.Cache = cache; c.CacheTTL = 10 * time.Second })
	ctx := context.Background()

	assign(t, w, "u", "teller", branch1)
	wantCan(t, w, "u", "loan:create", branch1, true)
	// A change made directly in the store, behind wardn's back.
	if err := store.Revoke(ctx, "u", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	wantCan(t, w, "u", "loan:create", branch1, true) // stale: wardn could not know
	if err := w.InvalidateCache(ctx, branch1); err != nil {
		t.Fatal(err)
	}
	wantCan(t, w, "u", "loan:create", branch1, false) // fixed at once

	assign(t, w, "v", "teller", branch1)
	wantCan(t, w, "v", "loan:create", branch1, true)
	if err := store.Revoke(ctx, "v", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(10 * time.Second)
	mu.Unlock()
	wantCan(t, w, "v", "loan:create", branch1, false) // or at most one TTL later
}

// failingCache wraps a cache and fails chosen operations.
type failingCache struct {
	Cache
	failGet, failIncr bool
	incrCalls         int
	failIncrAfter     int // fail Incr calls after this many succeed (0: never)
}

func (f *failingCache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if f.failGet {
		return nil, false, errors.New("cache down")
	}
	return f.Cache.Get(ctx, key)
}

func (f *failingCache) Incr(ctx context.Context, keys []string) error {
	f.incrCalls++
	if f.failIncr || (f.failIncrAfter > 0 && f.incrCalls > f.failIncrAfter) {
		return errors.New("cache down")
	}
	return f.Cache.Incr(ctx, keys)
}

func TestCacheFailures(t *testing.T) {
	fc := &failingCache{Cache: NewMemoryCache()}
	w, _ := newBank(t, func(c *Config) { c.Cache = fc })
	assign(t, w, "u", "teller", branch1)

	// Reads: a failing cache falls back to the store, and stays correct.
	fc.failGet = true
	wantCan(t, w, "u", "loan:create", branch1, true)
	wantCan(t, w, "u", "loan:approve", branch1, false)
	fc.failGet = false

	// Writes: if the cache cannot be invalidated first, nothing changes.
	fc.failIncr = true
	if err := w.System().Revoke(context.Background(), "u", "teller", branch1); err == nil {
		t.Fatal("change made although the cache could not be invalidated")
	}
	fc.failIncr = false
	wantCan(t, w, "u", "loan:create", branch1, true)

	// If only the second invalidation fails, the change is saved and the
	// caller is told the cache may be stale for up to the TTL.
	fc.incrCalls, fc.failIncrAfter = 0, 1
	err := w.System().Revoke(context.Background(), "u", "teller", branch1)
	if !errors.Is(err, ErrCacheInvalidation) {
		t.Fatalf("err = %v, want ErrCacheInvalidation", err)
	}
	fc.failIncrAfter = 0
	if as, _ := w.store.Assignments(context.Background(), "u", []Scope{branch1}); len(as) != 0 {
		t.Fatal("change not saved")
	}
}

func TestThreat_T24_CacheContentsAreValidated(t *testing.T) {
	cache := NewMemoryCache()
	w, _ := newBank(t, func(c *Config) { c.Cache = cache })
	assign(t, w, "victim", "teller", branch1)
	wantCan(t, w, "victim", "loan:create", branch1, true)
	ctx := context.Background()

	// Keys never contain IDs (personal data) or attacker-chosen separators.
	for k := range cache.entries {
		if strings.Contains(k, "victim") || strings.Contains(k, "branch") || strings.Contains(k, "teller") {
			t.Errorf("cache key reveals an ID: %s", k)
		}
	}

	// Corrupt every entry: wardn treats undecodable values as misses.
	for k := range cache.entries {
		_ = cache.Set(ctx, k, []byte("{not json"), time.Minute)
	}
	wantCan(t, w, "victim", "loan:create", branch1, true)
	wantCan(t, w, "victim", "loan:approve", branch1, false)

	// Entries holding another user's or another tenant's assignments are
	// filtered out, as store results are.
	forged, err := json.Marshal([]Assignment{
		{User: "attacker", Role: "super_admin", Scope: Global},
		{User: "victim", Role: "org_admin", Scope: org2},
	})
	if err != nil {
		t.Fatal(err)
	}
	for k := range cache.entries {
		if strings.HasPrefix(k, "assignments:") {
			_ = cache.Set(ctx, k, forged, time.Minute)
		}
	}
	wantCan(t, w, "victim", "loan:approve", branch1, false)
}

func TestCacheConfig(t *testing.T) {
	for _, ttl := range []time.Duration{-time.Second, maxCacheTTL + time.Second} {
		if _, err := New(Config{Policy: mustParse(t, bankYAML), Cache: NewMemoryCache(), CacheTTL: ttl}); err == nil {
			t.Errorf("CacheTTL %s accepted", ttl)
		}
	}
	w, _ := newBank(t)
	if err := w.InvalidateCache(context.Background(), branch1); err != nil { // no cache: no-op
		t.Fatal(err)
	}
	w, _ = newBank(t, func(c *Config) { c.Cache = NewMemoryCache() })
	if err := w.InvalidateCache(context.Background(), NewScope("nope", "x")); err == nil {
		t.Error("invalid scope accepted")
	}
}

func TestMemoryCacheEviction(t *testing.T) {
	c := NewMemoryCache(WithMaxEntries(3))
	ctx := context.Background()
	for i := range 10 {
		if err := c.Set(ctx, string(rune('a'+i)), []byte("x"), time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.entries) > 3 {
		t.Fatalf("%d entries, max 3", len(c.entries))
	}
}

// TestProperty_CacheNeverStale applies random changes through two instances
// sharing a store and a cache, and after every change checks both against
// the reference implementation.
func TestProperty_CacheNeverStale(t *testing.T) {
	worlds := 60
	if testing.Short() {
		worlds = 10
	}
	checks := 0
	for seed := range uint64(worlds) {
		r := rand.New(rand.NewPCG(seed, 0x6361636865)) //nolint:gosec // G404: seeded for reproducible tests, not security
		wd := randomWorld(r)
		store, cache := NewMemoryStore(), NewMemoryCache()
		clock := &fakeClock{now: t0}
		ctx := context.Background()
		for child, parent := range wd.links {
			_ = store.Link(ctx, child, parent)
		}
		for _, a := range wd.assignments {
			_ = store.Assign(ctx, a)
		}
		var instances []*Warden
		for range 2 {
			w, err := New(Config{Policy: wd.policy, Store: store, Cache: cache, Clock: clock})
			if err != nil {
				t.Fatal(err)
			}
			instances = append(instances, w)
		}
		roles := slices.Sorted(func(yield func(string) bool) {
			for k := range wd.policy.Roles {
				if !yield(k) {
					return
				}
			}
		})
		var nonGlobal []Scope
		for _, s := range wd.scopes {
			if s.Type == "region" || s.Type == "branch" {
				nonGlobal = append(nonGlobal, s)
			}
		}
		parentsOf := map[string][]Scope{}
		for _, s := range wd.scopes {
			parentsOf[s.Type] = append(parentsOf[s.Type], s)
		}

		for step := range 30 {
			w := instances[step%2]
			switch r.IntN(3) {
			case 0: // assign
				a := Assignment{User: wd.users[r.IntN(len(wd.users))], Role: roles[r.IntN(len(roles))], Scope: wd.scopes[r.IntN(len(wd.scopes))]}
				if w.System().Assign(ctx, a.User, a.Role, a.Scope) == nil {
					wd.assignments = slices.DeleteFunc(wd.assignments, func(x Assignment) bool {
						return x.User == a.User && x.Role == a.Role && x.Scope == a.Scope
					})
					wd.assignments = append(wd.assignments, a)
				}
			case 1: // revoke
				if len(wd.assignments) > 0 {
					a := wd.assignments[r.IntN(len(wd.assignments))]
					if err := w.System().Revoke(ctx, a.User, a.Role, a.Scope); err != nil {
						t.Fatal(err)
					}
					wd.assignments = slices.DeleteFunc(wd.assignments, func(x Assignment) bool {
						return x.User == a.User && x.Role == a.Role && x.Scope == a.Scope
					})
				}
			case 2: // move a region or branch
				child := nonGlobal[r.IntN(len(nonGlobal))]
				want := map[string]string{"region": "organisation", "branch": "region"}[child.Type]
				parent := parentsOf[want][r.IntN(len(parentsOf[want]))]
				if err := w.Link(ctx, child, parent); err != nil {
					t.Fatal(err)
				}
				wd.links[child] = parent
			}
			// Both instances must agree with the reference right away.
			for range 20 {
				user := wd.users[r.IntN(len(wd.users))]
				scope := wd.scopes[r.IntN(len(wd.scopes))]
				perm := instances[0].policy.permList[r.IntN(len(instances[0].policy.permList))]
				want := wd.referenceAllowed(user, perm, scope, t0)
				for i, inst := range instances {
					if got := inst.Can(ctx, user, perm, scope); got != want {
						t.Fatalf("seed %d step %d: instance %d says %v for (%s, %s, %s), reference says %v",
							seed, step, i, got, user, perm, scope, want)
					}
					checks++
				}
			}
		}
	}
	t.Logf("%d worlds, %d checks after random changes: no stale answer", worlds, checks)
}

// hookStore runs beforeWrite just before each Revoke reaches the store:
// the moment between wardn's first cache invalidation and its write.
type hookStore struct {
	Store
	beforeWrite func()
}

func (h *hookStore) Revoke(ctx context.Context, user, role string, scope Scope) error {
	if h.beforeWrite != nil {
		f := h.beforeWrite
		h.beforeWrite = nil
		f()
	}
	return h.Store.Revoke(ctx, user, role, scope)
}

// TestCacheReaderBetweenInvalidationAndWrite reproduces the race that the
// second invalidation exists for: another instance reads (and caches) the
// old data after the first invalidation but before the write lands. After
// the write, that entry must be unreachable.
func TestCacheReaderBetweenInvalidationAndWrite(t *testing.T) {
	store := &hookStore{Store: NewMemoryStore()}
	cache := NewMemoryCache()
	a, clock := newBank(t, func(c *Config) { c.Store = store; c.Cache = cache })
	b, err := New(Config{Policy: mustParse(t, bankYAML), Store: store, Cache: cache, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	assign(t, a, "u", "teller", branch1)
	store.beforeWrite = func() {
		// Instance B reads now: it sees the old data and caches it under
		// the counters as they are after the first invalidation.
		if !b.Can(context.Background(), "u", "loan:create", branch1) {
			t.Error("setup: B should still see the grant before the write")
		}
	}
	if err := a.System().Revoke(context.Background(), "u", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	wantCan(t, b, "u", "loan:create", branch1, false)
}

// TestCacheForgeryRejected: a forged entry, laid out like a sealed one but
// without the secret, is never used.
func TestCacheForgeryRejected(t *testing.T) {
	cache := NewMemoryCache()
	w, _ := newBank(t, func(c *Config) { c.Cache = cache })
	assign(t, w, "tia", "teller", branch1)
	wantCan(t, w, "tia", "loan:approve", branch1, false) // fills the cache
	forged := append(make([]byte, 32), []byte(`[{"user":"tia","role":"super_admin","scope":{"type":"","id":""}}]`)...)
	cache.mu.Lock()
	for k, e := range cache.entries {
		e.value = forged
		cache.entries[k] = e
	}
	cache.mu.Unlock()
	wantCan(t, w, "tia", "loan:approve", branch1, false)
}
