package wardntest_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/wardntest"
)

const policy = "testdata/wardn.yaml"

var branch = wardn.NewScope("branch", "b1")

func TestNewAndAsRole(t *testing.T) {
	w := wardntest.New(t, policy)
	req := wardntest.AsRole(t, w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil), "auditor")
	user, ok := wardn.UserOf(req.Context())
	if !ok {
		t.Fatal("no user in request context")
	}
	if !w.Can(req.Context(), user, "customer:view", branch) {
		t.Error("auditor cannot view customers")
	}
	if w.Can(req.Context(), user, "loan:approve", branch) {
		t.Error("auditor can approve loans")
	}

	req = wardntest.AsRoleIn(t, w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil), branch, "teller")
	teller, _ := wardn.UserOf(req.Context())
	if teller == user {
		t.Error("users are not fresh")
	}
	if !w.Can(context.Background(), teller, "loan:create", branch) {
		t.Error("teller cannot create loans in their branch")
	}
}

func TestAllowAll(t *testing.T) {
	w := wardntest.AllowAll(t, policy)
	ctx := context.Background()
	for _, s := range []wardn.Scope{wardn.Global, branch} {
		if !w.Can(ctx, "anyone", "loan:approve", s) {
			t.Errorf("AllowAll denied at %s", s)
		}
	}
	// Typos still fail.
	if _, err := w.Check(ctx, "anyone", "loan:aprove", branch); err == nil {
		t.Error("AllowAll accepted an undefined permission")
	}
}

func TestClock(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := wardntest.NewClock(start)
	w := wardntest.New(t, policy, wardntest.WithClock(clock))
	ctx := context.Background()
	user := wardntest.NewUser(t, w, wardn.Global)
	if err := w.System().Assign(ctx, user, "auditor", wardn.Global, wardn.Until(start.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if !w.Can(ctx, user, "customer:view", wardn.Global) {
		t.Fatal("denied before expiry")
	}
	clock.Advance(time.Hour)
	if w.Can(ctx, user, "customer:view", wardn.Global) {
		t.Fatal("allowed after expiry")
	}
	clock.Set(start)
	if !clock.Now().Equal(start) || !w.Can(ctx, user, "customer:view", wardn.Global) {
		t.Fatal("Set did not move the clock back")
	}
}

func TestWithStore(t *testing.T) {
	store := wardn.NewMemoryStore()
	if err := store.Assign(context.Background(), wardn.Assignment{User: "u", Role: "admin", Scope: wardn.Global}); err != nil {
		t.Fatal(err)
	}
	w := wardntest.New(t, policy, wardntest.WithStore(store))
	if !w.Can(context.Background(), "u", "loan:approve", branch) {
		t.Error("store contents not used")
	}
}

// fakeT records fatal errors instead of stopping the test.
type fakeT struct {
	testing.TB
	failed bool
	msg    string
}

func (f *fakeT) Helper() {}

func (f *fakeT) Fatalf(format string, args ...any) {
	f.failed = true
	f.msg = fmt.Sprintf(format, args...)
	panic(f)
}

func expectFatal(t *testing.T, name string, fn func(tb testing.TB)) {
	t.Helper()
	ft := &fakeT{TB: t}
	func() {
		defer func() {
			if r := recover(); r != nil && r != ft {
				panic(r)
			}
		}()
		fn(ft)
	}()
	if !ft.failed {
		t.Errorf("%s: expected the test to fail", name)
	}
}

func TestFailures(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("roles: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	clash := filepath.Join(dir, "clash.yaml")
	if err := os.WriteFile(clash, []byte("permissions:\n  a:b: X\nroles:\n  wardntest_allow_all: [a:b]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := wardntest.New(t, policy)

	expectFatal(t, "missing file", func(tb testing.TB) { wardntest.New(tb, filepath.Join(dir, "missing.yaml")) })
	expectFatal(t, "invalid policy", func(tb testing.TB) { wardntest.New(tb, bad) })
	expectFatal(t, "AllowAll missing file", func(tb testing.TB) { wardntest.AllowAll(tb, filepath.Join(dir, "missing.yaml")) })
	expectFatal(t, "AllowAll role clash", func(tb testing.TB) { wardntest.AllowAll(tb, clash) })
	expectFatal(t, "undefined role", func(tb testing.TB) { wardntest.NewUser(tb, w, wardn.Global, "nope") })
	expectFatal(t, "role not assignable globally", func(tb testing.TB) {
		wardntest.AsRole(tb, w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil), "teller")
	})
}

// TestThreat_T17_AuditRoutesFindsUnprotectedRoute: a forgotten Require is
// reported, and so is an audit whose probe user was never authenticated.
func TestThreat_T17_AuditRoutesFindsUnprotectedRoute(t *testing.T) {
	w := wardntest.New(t, policy)
	ok := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })
	mux := http.NewServeMux()
	mux.Handle("GET /protected", w.Require("loan:create")(ok))
	mux.Handle("GET /forgotten", ok) // the bug AuditRoutes exists to catch
	mux.Handle("GET /me", ok)        // deliberately open to any signed-in user
	routes := []wardntest.Route{{"GET", "/protected"}, {"GET", "/forgotten"}, {"GET", "/me"}}

	ft := &auditT{TB: t}
	wardntest.AuditRoutes(ft, mux, nil, routes, wardntest.Route{Method: "GET", Path: "/me"})
	if len(ft.errors) != 1 || !strings.Contains(ft.errors[0], "GET /forgotten answered 200") {
		t.Fatalf("errors = %q", ft.errors)
	}

	// An authenticate function that doesn't authenticate is reported, not
	// mistaken for protection.
	ft = &auditT{TB: t}
	noAuth := func(r *http.Request, _ string) *http.Request { return r }
	wardntest.AuditRoutes(ft, mux, noAuth, routes[:1])
	if len(ft.errors) != 1 || !strings.Contains(ft.errors[0], "answered 401") {
		t.Fatalf("errors = %q", ft.errors)
	}

	expectFatal(t, "no routes", func(tb testing.TB) { wardntest.AuditRoutes(tb, mux, nil, nil) })
}

// auditT records Errorf calls.
type auditT struct {
	testing.TB
	errors []string
}

func (a *auditT) Helper() {}

func (a *auditT) Errorf(format string, args ...any) {
	a.errors = append(a.errors, fmt.Sprintf(format, args...))
}
