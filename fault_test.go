package wardn

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Fault injection: every operation is run once per store (or cache) call it
// makes, with that one call failing. Invariants:
//
//   - The operation reports an error. Nothing fails silently.
//   - A read never returns Allowed with an error (fail closed).
//   - After a failed change, every permission anyone holds was held before
//     the change, or would be held after it succeeded. A failure may leave
//     a change half-done, but never grants access that neither state grants.
//   - With a cache, answers always match the store's truth afterwards.

var errInjected = errors.New("injected fault")

// faultStore fails its fail-th call (counting every method; 0 never fails).
type faultStore struct {
	Store
	mu          sync.Mutex
	calls, fail int
}

func (f *faultStore) tick() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail > 0 && f.calls == f.fail {
		return errInjected
	}
	return nil
}

func (f *faultStore) arm(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls, f.fail = 0, n
}

func (f *faultStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *faultStore) Assign(ctx context.Context, a Assignment) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.Store.Assign(ctx, a)
}

func (f *faultStore) Revoke(ctx context.Context, u, r string, s Scope) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.Store.Revoke(ctx, u, r, s)
}

func (f *faultStore) Assignments(ctx context.Context, u string, s []Scope) ([]Assignment, error) {
	if err := f.tick(); err != nil {
		return nil, err
	}
	return f.Store.Assignments(ctx, u, s)
}

func (f *faultStore) Members(ctx context.Context, s Scope, c string, n int) ([]Assignment, string, error) {
	if err := f.tick(); err != nil {
		return nil, "", err
	}
	return f.Store.Members(ctx, s, c, n)
}

func (f *faultStore) RoleInUse(ctx context.Context, r string) (bool, error) {
	if err := f.tick(); err != nil {
		return false, err
	}
	return f.Store.RoleInUse(ctx, r)
}

func (f *faultStore) RevokeRole(ctx context.Context, r string) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.Store.RevokeRole(ctx, r)
}

func (f *faultStore) ExpiredUnreported(ctx context.Context, t time.Time, n int) ([]Assignment, error) {
	if err := f.tick(); err != nil {
		return nil, err
	}
	return f.Store.ExpiredUnreported(ctx, t, n)
}

func (f *faultStore) MarkExpiryReported(ctx context.Context, as []Assignment) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.Store.MarkExpiryReported(ctx, as)
}

func (f *faultStore) RevokeExpired(ctx context.Context, a Assignment) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.Store.RevokeExpired(ctx, a)
}

func (f *faultStore) CreateRole(ctx context.Context, r CustomRole) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.Store.CreateRole(ctx, r)
}

func (f *faultStore) UpdateRole(ctx context.Context, r CustomRole, v int) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.Store.UpdateRole(ctx, r, v)
}

func (f *faultStore) DeleteRole(ctx context.Context, id string) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.Store.DeleteRole(ctx, id)
}

func (f *faultStore) Roles(ctx context.Context, ids []string) ([]CustomRole, error) {
	if err := f.tick(); err != nil {
		return nil, err
	}
	return f.Store.Roles(ctx, ids)
}

func (f *faultStore) RolesOwnedBy(ctx context.Context, o []Scope) ([]CustomRole, error) {
	if err := f.tick(); err != nil {
		return nil, err
	}
	return f.Store.RolesOwnedBy(ctx, o)
}

func (f *faultStore) Link(ctx context.Context, c, p Scope) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.Store.Link(ctx, c, p)
}

func (f *faultStore) Parent(ctx context.Context, c Scope) (Scope, bool, error) {
	if err := f.tick(); err != nil {
		return Scope{}, false, err
	}
	return f.Store.Parent(ctx, c)
}

// faultCache fails its fail-th call.
type faultCache struct {
	Cache
	mu          sync.Mutex
	calls, fail int
}

func (f *faultCache) tick() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail > 0 && f.calls == f.fail {
		return errInjected
	}
	return nil
}

func (f *faultCache) arm(n int) { f.mu.Lock(); f.calls, f.fail = 0, n; f.mu.Unlock() }

func (f *faultCache) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

func (f *faultCache) Get(ctx context.Context, k string) ([]byte, bool, error) {
	if err := f.tick(); err != nil {
		return nil, false, err
	}
	return f.Cache.Get(ctx, k)
}

func (f *faultCache) Set(ctx context.Context, k string, v []byte, ttl time.Duration) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.Cache.Set(ctx, k, v, ttl)
}

func (f *faultCache) Counters(ctx context.Context, ks []string) ([]uint64, error) {
	if err := f.tick(); err != nil {
		return nil, err
	}
	return f.Cache.Counters(ctx, ks)
}

func (f *faultCache) Incr(ctx context.Context, ks []string) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.Cache.Incr(ctx, ks)
}

// faultWorld is a bank with a fault-injecting store, an optional
// fault-injecting cache, and a set of users with roles.
type faultWorld struct {
	w     *Warden
	store *faultStore
	cache *faultCache
	clock *fakeClock
	ids   map[string]string // named custom role IDs
}

var (
	faultUsers  = []string{"root", "mgr", "tia", "ops", "temp", "x"}
	faultScopes = []Scope{Global, org1, region1, branch1, org2, branch2, NewScope("branch", "b3")}
)

func newFaultWorld(t *testing.T, withCache bool) *faultWorld {
	t.Helper()
	fs := &faultStore{Store: NewMemoryStore()}
	fw := &faultWorld{store: fs, ids: map[string]string{}}
	fw.w, fw.clock = newBank(t, func(c *Config) {
		c.Store = fs
		if withCache {
			fw.cache = &faultCache{Cache: NewMemoryCache()}
			c.Cache = fw.cache
		}
	})
	sys := fw.w.System()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(sys.Assign(ctx, "root", "super_admin", Global))
	must(sys.Assign(ctx, "mgr", "branch_manager", branch1))
	must(sys.Assign(ctx, "tia", "teller", branch1))
	must(sys.Assign(ctx, "ops", "ops_admin", org1))
	must(sys.Assign(ctx, "temp", "loan_officer", branch1, Until(t0.Add(time.Hour))))
	desk, err := sys.CreateRole(ctx, org1, RoleSpec{Name: "Desk", Allow: []string{"loan:view", "customer:view"}, AssignableAt: []string{"branch"}})
	must(err)
	fw.ids["desk"] = desk.ID
	must(sys.Assign(ctx, "tia", desk.ID, branch1))
	must(sys.Assign(ctx, "x", desk.ID, branch1))
	return fw
}

type access struct {
	user, perm string
	scope      Scope
}

// snapshot records every permission every user holds at every scope.
func (fw *faultWorld) snapshot(t *testing.T) map[access]bool {
	t.Helper()
	fw.store.arm(0)
	if fw.cache != nil {
		fw.cache.arm(0)
	}
	out := map[access]bool{}
	for _, u := range faultUsers {
		for _, s := range faultScopes {
			perms, err := fw.w.PermissionsOf(context.Background(), u, s)
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			for _, p := range perms {
				out[access{u, p, s}] = true
			}
		}
	}
	return out
}

// storeTruth is the snapshot computed without any cache.
func (fw *faultWorld) storeTruth(t *testing.T) map[access]bool {
	t.Helper()
	fw.store.arm(0)
	plain, err := New(Config{Policy: mustParse(t, bankYAML), Store: fw.store.Store, Clock: fw.clock})
	if err != nil {
		t.Fatal(err)
	}
	return (&faultWorld{w: plain, store: &faultStore{Store: fw.store.Store}}).snapshot(t)
}

type faultOp struct {
	name string
	run  func(ctx context.Context, fw *faultWorld) error
}

var faultOps = []faultOp{
	{"Assign", func(ctx context.Context, fw *faultWorld) error {
		return fw.w.Assign(WithUser(ctx, "mgr"), "x", "teller", branch1)
	}},
	{"AssignCustom", func(ctx context.Context, fw *faultWorld) error {
		return fw.w.Assign(WithUser(ctx, "root"), "temp", fw.ids["desk"], branch1) // temp gains customer:view
	}},
	{"Revoke", func(ctx context.Context, fw *faultWorld) error {
		return fw.w.Revoke(WithUser(ctx, "mgr"), "tia", "teller", branch1)
	}},
	{"CreateRole", func(ctx context.Context, fw *faultWorld) error {
		_, err := fw.w.CreateRole(WithUser(ctx, "mgr"), branch1, RoleSpec{Name: "New", Allow: []string{"loan:create"}})
		return err
	}},
	{"UpdateRole", func(ctx context.Context, fw *faultWorld) error {
		_, err := fw.w.UpdateRole(WithUser(ctx, "root"), fw.ids["desk"],
			RoleSpec{Name: "Desk", Allow: []string{"loan:view", "loan:approve"}, AssignableAt: []string{"branch"}}, 1)
		return err
	}},
	{"DeleteRoleCascade", func(ctx context.Context, fw *faultWorld) error {
		return fw.w.DeleteRole(WithUser(ctx, "root"), fw.ids["desk"], Cascade())
	}},
	{"Link", func(ctx context.Context, fw *faultWorld) error {
		return fw.w.Link(ctx, branch1, region2) // move b1 into the other organisation
	}},
	{"SweepRemove", func(ctx context.Context, fw *faultWorld) error {
		fw.clock.Advance(2 * time.Hour)
		_, err := fw.w.SweepExpired(ctx, RemoveExpired())
		return err
	}},
}

// TestFaultInjection_Store: every management operation, with each store
// call failing in turn.
func TestFaultInjection_Store(t *testing.T) {
	for _, op := range faultOps {
		t.Run(op.name, func(t *testing.T) {
			ctx := context.Background()
			// A clean run: how many store calls, and the state on success.
			clean := newFaultWorld(t, false)
			before := clean.snapshot(t)
			clean.store.arm(0)
			if err := op.run(ctx, clean); err != nil {
				t.Fatalf("clean run failed: %v", err)
			}
			calls := clean.store.count()
			after := clean.snapshot(t)
			if calls == 0 {
				t.Fatal("operation made no store calls")
			}
			changed := 0
			for a := range after {
				if !before[a] {
					changed++
				}
			}
			for a := range before {
				if !after[a] {
					changed++
				}
			}
			t.Logf("%d store calls; %d accesses change on success", calls, changed)

			for n := 1; n <= calls; n++ {
				fw := newFaultWorld(t, false)
				fw.store.arm(n)
				err := op.run(ctx, fw)
				if err == nil {
					t.Fatalf("call %d/%d failed but the operation reported success", n, calls)
				}
				now := fw.snapshot(t)
				for a := range now {
					if !before[a] && !after[a] {
						t.Fatalf("call %d/%d failed and left access neither state grants: %+v (err: %v)", n, calls, a, err)
					}
				}
			}
		})
	}
}

// TestFaultInjection_Reads: a read with any store call failing returns an
// error and never allows.
func TestFaultInjection_Reads(t *testing.T) {
	ctx := context.Background()
	fw := newFaultWorld(t, false)
	for _, s := range []Scope{branch1, Global} {
		fw.store.arm(0)
		if _, err := fw.w.Check(ctx, "root", "loan:approve", s); err != nil {
			t.Fatal(err)
		}
		calls := fw.store.count()
		for n := 1; n <= calls; n++ {
			fw.store.arm(n)
			d, err := fw.w.Check(ctx, "root", "loan:approve", s)
			if err == nil || d.Allowed {
				t.Fatalf("%s: call %d/%d failed: Check = %+v, %v", s, n, calls, d, err)
			}
		}
	}
	// Admin-screen reads report errors rather than partial answers.
	reads := map[string]func() error{
		"PermissionsOf":   func() error { _, err := fw.w.PermissionsOf(ctx, "tia", branch1); return err },
		"RolesOf":         func() error { _, err := fw.w.RolesOf(ctx, "tia", branch1); return err },
		"Roles":           func() error { _, err := fw.w.Roles(ctx, branch1); return err },
		"AssignableRoles": func() error { _, err := fw.w.AssignableRoles(WithUser(ctx, "mgr"), branch1); return err },
		"Members":         func() error { _, _, err := fw.w.Members(ctx, branch1, "", 10); return err },
		"CustomRole":      func() error { _, err := fw.w.CustomRole(ctx, fw.ids["desk"]); return err },
	}
	for name, read := range reads {
		fw.store.arm(0)
		if err := read(); err != nil {
			t.Fatalf("%s clean: %v", name, err)
		}
		calls := fw.store.count()
		for n := 1; n <= calls; n++ {
			fw.store.arm(n)
			if err := read(); err == nil {
				t.Fatalf("%s: call %d/%d failed but no error was reported", name, n, calls)
			}
		}
	}
}

// TestFaultInjection_Cache: every operation, with each cache call failing
// in turn. Afterwards, cached answers must match the store exactly.
func TestFaultInjection_Cache(t *testing.T) {
	for _, op := range faultOps {
		t.Run(op.name, func(t *testing.T) {
			ctx := context.Background()
			probe := newFaultWorld(t, true)
			_ = probe.snapshot(t) // warm the cache, as in production
			probe.cache.arm(0)
			if err := op.run(ctx, probe); err != nil {
				t.Fatalf("clean run failed: %v", err)
			}
			calls := probe.cache.count()
			for n := 1; n <= calls; n++ {
				fw := newFaultWorld(t, true)
				_ = fw.snapshot(t)
				fw.cache.arm(n)
				_ = op.run(ctx, fw) // may fail (fail closed) or succeed (cache read errors fall back)
				got, want := fw.snapshot(t), fw.storeTruth(t)
				if diff := diffAccess(got, want); diff != "" {
					t.Fatalf("cache call %d/%d failed; cached answers differ from the store:\n%s", n, calls, diff)
				}
			}
		})
	}
}

func diffAccess(got, want map[access]bool) string {
	var out string
	for a := range got {
		if !want[a] {
			out += fmt.Sprintf("  stale grant: %+v\n", a)
		}
	}
	for a := range want {
		if !got[a] {
			out += fmt.Sprintf("  missing grant: %+v\n", a)
		}
	}
	return out
}
