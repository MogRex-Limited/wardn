package storetest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/MogRex-Limited/wardn"
)

// The bank the benchmarks run against: the shape of the multi-branch bank
// reference application, at the size of a real one.
const (
	benchOrgs           = 4  // tenants
	benchRegionsPerOrg  = 10 // 40 regions
	benchBranchesPerReg = 25 // 1,000 branches
	benchStaffPerBranch = 20 // 20,000 staff
	benchAdminsPerOrg   = 3
	benchDeskPerOrg     = 10 // holders of a custom role at the organisation
)

const benchPolicy = `version: 1
scopes:
  organisation: {}
  region: { parent: organisation }
  branch: { parent: region }
permissions:
  customer:view: View customers
  customer:edit: Edit customers
  loan:view: View loans
  loan:create: Create loans
  loan:approve: Approve loans
  report:export: Export reports
roles:
  org_admin:
    assignable_at: [organisation]
    allow: ["*"]
  branch_manager:
    assignable_at: [branch]
    allow: [customer:view, customer:edit, "loan:*", wardn:roles.assign]
  teller:
    assignable_at: [branch]
    allow: [customer:view, loan:view, loan:create]
  regional_auditor:
    assignable_at: [region]
    allow: [customer:view, loan:view, report:export]
`

var benchT0 = time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)

type benchClock struct{}

func (benchClock) Now() time.Time { return benchT0 }

// benchCase is one user and the scope they act in.
type benchCase struct {
	user  string
	scope wardn.Scope
}

func benchOrg(o int) wardn.Scope { return wardn.NewScope("organisation", fmt.Sprintf("o%d", o)) }
func benchRegion(o, r int) wardn.Scope {
	return wardn.NewScope("region", fmt.Sprintf("o%d-r%d", o, r))
}

func benchBranch(o, r, b int) wardn.Scope {
	return wardn.NewScope("branch", fmt.Sprintf("o%d-r%d-b%d", o, r, b))
}

func benchStaff(o, r, b, s int) string { return fmt.Sprintf("o%d-r%d-b%d-s%d", o, r, b, s) }

// benchCases is how many cases each benchmark cycles through (a power of
// two, indexed with i&(benchCases-1)).
const benchCases = 1024

// spread returns benchCases cases spread evenly over the bank's branches.
func spread(pick func(o, r, b, i int) benchCase) []benchCase {
	out := make([]benchCase, benchCases)
	for i := range out {
		k := i * 7919 // a prime, so consecutive cases land in unrelated branches
		o := k % benchOrgs
		r := (k / benchOrgs) % benchRegionsPerOrg
		b := (k / (benchOrgs * benchRegionsPerOrg)) % benchBranchesPerReg
		out[i] = pick(o, r, b, i)
	}
	return out
}

// Bench runs wardn's benchmarks against a store. newStore must return a
// new, empty store; it is called once.
//
// The data is a bank with 4 organisations, 40 regions, 1,000 branches and
// about 20,000 assignments. Each check is a full permission check through
// a Warden, as an application makes it, so the numbers include wardn's
// evaluation and every store read it needs:
//
//	func BenchmarkMyStore(b *testing.B) {
//		storetest.Bench(b, func(b *testing.B) wardn.Store { return mystore.New(...) })
//	}
//
// Seeding takes a few seconds on a database server; run with -run '^$'.
func Bench(b *testing.B, newStore func(b *testing.B) wardn.Store) {
	b.Helper()
	ctx := context.Background()
	store := newStore(b)
	policy, err := wardn.ParsePolicy([]byte(benchPolicy), "bench.yaml")
	if err != nil {
		b.Fatal(err)
	}
	newWarden := func(cache bool) *wardn.Warden {
		cfg := wardn.Config{Policy: policy, Store: store, Clock: benchClock{}}
		if cache {
			cfg.Cache = wardn.NewMemoryCache()
			cfg.CacheSecret = []byte("wardn benchmark cache secret, 32+ bytes")
		}
		w, err := wardn.New(cfg)
		if err != nil {
			b.Fatal(err)
		}
		return w
	}
	w, cached := newWarden(false), newWarden(true)
	seedBench(ctx, b, w, store)

	tellers := spread(func(o, r, br, i int) benchCase {
		return benchCase{benchStaff(o, r, br, 1+i%(benchStaffPerBranch-1)), benchBranch(o, r, br)}
	})
	admins := spread(func(o, r, br, i int) benchCase {
		return benchCase{fmt.Sprintf("o%d-admin%d", o, i%benchAdminsPerOrg), benchBranch(o, r, br)}
	})
	desk := spread(func(o, r, br, i int) benchCase {
		return benchCase{fmt.Sprintf("o%d-desk%d", o, i%benchDeskPerOrg), benchBranch(o, r, br)}
	})
	// Tellers looking at a branch of another organisation.
	strangers := spread(func(o, r, br, i int) benchCase {
		return benchCase{benchStaff(o, r, br, 1+i%(benchStaffPerBranch-1)), benchBranch((o+1)%benchOrgs, r, br)}
	})

	// The numbers are only meaningful if the answers are right.
	for _, c := range []struct {
		name  string
		cases []benchCase
		perm  string
		want  bool
	}{
		{"teller", tellers, "loan:view", true},
		{"admin", admins, "loan:approve", true},
		{"desk", desk, "loan:approve", true},
		{"stranger", strangers, "loan:view", false},
	} {
		for _, k := range c.cases[:16] {
			for _, ww := range []*wardn.Warden{w, cached} {
				d, err := ww.Check(ctx, k.user, c.perm, k.scope)
				if err != nil || d.Allowed != c.want {
					b.Fatalf("%s: Check(%s, %s, %s) = %v, %v; want %v", c.name, k.user, c.perm, k.scope, d.Allowed, err, c.want)
				}
			}
		}
	}

	can := func(w *wardn.Warden, cases []benchCase, perm string) func(b *testing.B) {
		return func(b *testing.B) {
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				k := cases[i&(benchCases-1)]
				w.Can(ctx, k.user, perm, k.scope)
				i++
			}
		}
	}
	// Ten checks while handling one request, as a page that shows or hides
	// actions does: wardn reads each scope and assignment once.
	request := func(w *wardn.Warden) func(b *testing.B) {
		perms := []string{"customer:view", "customer:edit", "loan:view", "loan:create", "loan:approve", "report:export"}
		return func(b *testing.B) {
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				k := tellers[i&(benchCases-1)]
				rctx := w.WithMemo(ctx)
				for j := range 10 {
					w.Can(rctx, k.user, perms[j%len(perms)], k.scope)
				}
				i++
			}
		}
	}
	parallel := func(w *wardn.Warden) func(b *testing.B) {
		return func(b *testing.B) {
			b.ReportAllocs()
			var next sync.Mutex
			n := 0
			b.RunParallel(func(pb *testing.PB) {
				next.Lock()
				i := n * 131
				n++
				next.Unlock()
				for pb.Next() {
					k := tellers[i&(benchCases-1)]
					w.Can(ctx, k.user, "loan:view", k.scope)
					i++
				}
			})
		}
	}

	for _, v := range []struct {
		name string
		w    *wardn.Warden
	}{{"Store", w}, {"Cached", cached}} {
		b.Run(v.name+"/Can/role-at-branch", can(v.w, tellers, "loan:view"))
		b.Run(v.name+"/Can/inherited-from-organisation", can(v.w, admins, "loan:approve"))
		b.Run(v.name+"/Can/custom-role", can(v.w, desk, "loan:approve"))
		b.Run(v.name+"/Can/denied-other-tenant", can(v.w, strangers, "loan:view"))
		b.Run(v.name+"/Request-10-checks", request(v.w))
		b.Run(v.name+"/Can/parallel", parallel(v.w))
	}

	// A real change every time: the window differs from the stored one.
	b.Run("Store/Assign", func(b *testing.B) {
		b.ReportAllocs()
		sys := w.System()
		i := 0
		for b.Loop() {
			k := tellers[i&(benchCases-1)]
			if err := sys.Assign(ctx, k.user, "teller", k.scope, wardn.Until(benchT0.Add(time.Duration(i+1)*time.Hour))); err != nil {
				b.Fatal(err)
			}
			i++
		}
	})
}

// seedBench writes the bank through the store, in parallel.
func seedBench(ctx context.Context, b *testing.B, w *wardn.Warden, s wardn.Store) {
	b.Helper()
	jobs := make(chan func() error, 256)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	for range 8 {
		wg.Go(func() {
			for job := range jobs {
				if err := job(); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
				}
			}
		})
	}
	assign := func(user, role string, scope wardn.Scope) {
		jobs <- func() error { return s.Assign(ctx, wardn.Assignment{User: user, Role: role, Scope: scope}) }
	}
	link := func(child, parent wardn.Scope) {
		jobs <- func() error { return s.Link(ctx, child, parent) }
	}

	roles := make([]string, benchOrgs)
	for o := range benchOrgs {
		role, err := w.System().CreateRole(ctx, benchOrg(o), wardn.RoleSpec{
			Name: "Loan Desk", Allow: []string{"loan:*", "customer:view"}, AssignableAt: []string{"organisation"},
		})
		if err != nil {
			b.Fatal(err)
		}
		roles[o] = role.ID
	}
	for o := range benchOrgs {
		for a := range benchAdminsPerOrg {
			assign(fmt.Sprintf("o%d-admin%d", o, a), "org_admin", benchOrg(o))
		}
		for d := range benchDeskPerOrg {
			assign(fmt.Sprintf("o%d-desk%d", o, d), roles[o], benchOrg(o))
		}
		for r := range benchRegionsPerOrg {
			link(benchRegion(o, r), benchOrg(o))
			assign(fmt.Sprintf("o%d-r%d-auditor", o, r), "regional_auditor", benchRegion(o, r))
			for br := range benchBranchesPerReg {
				link(benchBranch(o, r, br), benchRegion(o, r))
				for st := range benchStaffPerBranch {
					role := "teller"
					if st == 0 {
						role = "branch_manager"
					}
					assign(benchStaff(o, r, br, st), role, benchBranch(o, r, br))
				}
			}
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		b.Fatalf("seeding the benchmark bank: %v", firstErr)
	}
}
