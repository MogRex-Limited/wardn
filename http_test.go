package wardn

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// authAs is a stand-in for the application's authentication middleware.
func authAs(user string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if user != "" {
				r = r.WithContext(WithUser(r.Context(), user))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// okHandler records whether it ran.
type okHandler struct{ ran bool }

func (h *okHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h.ran = true
	w.WriteHeader(http.StatusNoContent)
}

func serve(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
	return rec
}

// bankMux mounts /branches/{branchID}/loans behind ScopeFrom and Require.
func bankMux(w *Warden, user string, mw func(http.Handler) http.Handler, h http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /branches/{branchID}/loans", w.ScopeFrom("branch", PathValue("branchID"))(mw(h)))
	mux.Handle("GET /global", mw(h))
	return authAs(user)(mux)
}

func TestRequire(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "teller1", "teller", branch1)

	tests := []struct {
		name, user, path string
		mw               func(http.Handler) http.Handler
		want             int
	}{
		{"granted in scope", "teller1", "/branches/b1/loans", w.Require("loan:create"), http.StatusNoContent},
		{"all required: one missing", "teller1", "/branches/b1/loans", w.Require("loan:create", "loan:approve"), http.StatusForbidden},
		{"all required: all held", "teller1", "/branches/b1/loans", w.Require("loan:create", "loan:view"), http.StatusNoContent},
		{"any: one held", "teller1", "/branches/b1/loans", w.RequireAny("loan:approve", "loan:create"), http.StatusNoContent},
		{"any: none held", "teller1", "/branches/b1/loans", w.RequireAny("loan:approve", "report:export"), http.StatusForbidden},
		{"other branch", "teller1", "/branches/b2/loans", w.Require("loan:create"), http.StatusForbidden},
		{"no user", "", "/branches/b1/loans", w.Require("loan:create"), http.StatusUnauthorized},
		{"unknown user", "stranger", "/branches/b1/loans", w.Require("loan:create"), http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &okHandler{}
			rec := serve(t, bankMux(w, tt.user, tt.mw, h), tt.path)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.want, rec.Body)
			}
			if h.ran != (tt.want == http.StatusNoContent) {
				t.Fatalf("handler ran = %v with status %d", h.ran, rec.Code)
			}
		})
	}
}

func TestRequireMemoisesPerRequest(t *testing.T) {
	cs := &countingStore{Store: NewMemoryStore()}
	w, _ := newBank(t, func(c *Config) { c.Store = cs })
	assign(t, w, "teller1", "teller", branch1)
	cs.assignments = 0

	// Three Require layers and an in-handler check share one store read.
	var inHandler bool
	h := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		inHandler = w.Can(r.Context(), "teller1", "loan:view", branch1)
		rw.WriteHeader(http.StatusNoContent)
	})
	chain := w.Require("loan:create")(w.Require("loan:view")(w.RequireAny("customer:view")(h)))
	if rec := serve(t, bankMux(w, "teller1", func(h http.Handler) http.Handler { return h }, chain), "/branches/b1/loans"); rec.Code != http.StatusNoContent {
		t.Fatalf("status %d", rec.Code)
	}
	if !inHandler || cs.assignments != 1 {
		t.Fatalf("in-handler check %v, store reads %d; want true, 1", inHandler, cs.assignments)
	}
}

func TestScopeFrom(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "teller1", "teller", branch1)
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/branches/b1/loans", http.StatusNoContent},
		{"/branches/%20b1/loans", http.StatusBadRequest}, // leading space
		{"/branches/b1%00/loans", http.StatusBadRequest}, // NUL byte
		{"/branches/b%E2%80%8B1/loans", http.StatusBadRequest},
	} {
		h := &okHandler{}
		rec := serve(t, bankMux(w, "teller1", w.Require("loan:create"), h), tc.path)
		if rec.Code != tc.want || h.ran != (tc.want == http.StatusNoContent) {
			t.Errorf("%s: status %d, handler ran %v; want %d", tc.path, rec.Code, h.ran, tc.want)
		}
	}

	// A missing path parameter (wrong name, or ScopeFrom placed before
	// routing) is a 400, never a silent fallback to Global.
	assign(t, w, "root", "super_admin", Global)
	h := &okHandler{}
	mw := w.ScopeFrom("branch", PathValue("typo"))(w.Require("loan:create")(h))
	if rec := serve(t, authAs("root")(mw), "/x"); rec.Code != http.StatusBadRequest || h.ran {
		t.Errorf("missing scope ID: status %d, handler ran %v", rec.Code, h.ran)
	}
}

func TestRegistrationPanics(t *testing.T) {
	w, _ := newBank(t)
	for name, fn := range map[string]func(){
		"undefined permission": func() { w.Require("loan:aprove") },
		"wildcard":             func() { w.Require("loan:*") },
		"no permissions":       func() { w.RequireAny() },
		"undefined scope type": func() { w.ScopeFrom("brnch", PathValue("id")) },
		"nil ID function":      func() { w.ScopeFrom("branch", nil) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("did not panic")
				}
			}()
			fn()
		})
	}
}

func TestThreat_T16_TypoInRouteFailsAtStartup(t *testing.T) {
	w, _ := newBank(t)
	defer func() {
		msg, _ := recover().(string)
		if !strings.Contains(msg, `did you mean "loan:approve"?`) || !strings.Contains(msg, "Require") {
			t.Fatalf("panic message = %q", msg)
		}
	}()
	w.Require("loan:aprove")
}

func TestThreat_T08_HTTPFailsClosedOnStoreError(t *testing.T) {
	fs := &faultyStore{Store: NewMemoryStore()}
	w, _ := newBank(t, func(c *Config) { c.Store = fs })
	assign(t, w, "root", "super_admin", Global)
	fs.failAssignments = true
	h := &okHandler{}
	rec := serve(t, bankMux(w, "root", w.Require("loan:create"), h), "/branches/b1/loans")
	if rec.Code != http.StatusInternalServerError || h.ran {
		t.Fatalf("store error: status %d, handler ran %v", rec.Code, h.ran)
	}
	if strings.Contains(rec.Body.String(), errStore.Error()) {
		t.Fatalf("internal error leaked to client: %s", rec.Body)
	}
}

func TestThreat_T18_NoScopeMeansGlobalOnly(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "admin1", "org_admin", org1)
	h := &okHandler{}
	// A route without ScopeFrom checks at Global, where an organisation
	// admin has nothing.
	if rec := serve(t, bankMux(w, "admin1", w.Require("loan:approve"), h), "/global"); rec.Code != http.StatusForbidden || h.ran {
		t.Fatalf("status %d, handler ran %v", rec.Code, h.ran)
	}
}

func TestThreat_T20_ErrorResponsesRevealNothing(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "teller1", "teller", branch1)
	cases := []struct {
		user, path string
		want       int
	}{
		{"teller1", "/branches/b1/loans", http.StatusForbidden},
		{"", "/branches/b1/loans", http.StatusUnauthorized},
		{"teller1", "/branches/%20b1/loans", http.StatusBadRequest},
	}
	for _, c := range cases {
		rec := serve(t, bankMux(w, c.user, w.Require("loan:approve"), &okHandler{}), c.path)
		body, _ := io.ReadAll(rec.Body)
		if rec.Code != c.want {
			t.Fatalf("status %d, want %d", rec.Code, c.want)
		}
		for _, secret := range []string{"loan", "approve", "teller", "branch", "b1", "role", "scope", "permission"} {
			if strings.Contains(strings.ToLower(string(body)), secret) {
				t.Errorf("%d response reveals %q: %s", c.want, secret, body)
			}
		}
		if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" ||
			rec.Header().Get("X-Content-Type-Options") != "nosniff" ||
			rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("headers = %v", rec.Header())
		}
	}
}

func TestCustomUserFromAndOnError(t *testing.T) {
	var gotErr error
	w, _ := newBank(t, func(c *Config) {
		c.UserFrom = func(r *http.Request) (string, bool) {
			u := r.Header.Get("X-Test-User")
			return u, u != ""
		}
		c.OnError = func(rw http.ResponseWriter, _ *http.Request, err error) {
			gotErr = err
			rw.WriteHeader(HTTPStatus(err) + 1) // proves the custom handler ran
		}
	})
	assign(t, w, "teller1", "teller", branch1)
	mux := http.NewServeMux()
	mux.Handle("GET /branches/{branchID}/loans", w.ScopeFrom("branch", PathValue("branchID"))(w.Require("loan:approve")(&okHandler{})))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/branches/b1/loans", nil)
	req.Header.Set("X-Test-User", "teller1")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var denied *DeniedError
	if rec.Code != http.StatusForbidden+1 || !errors.As(gotErr, &denied) || !errors.Is(gotErr, ErrDenied) {
		t.Fatalf("status %d, err %v", rec.Code, gotErr)
	}
	if len(denied.Decisions) != 1 || denied.Decisions[0].Permission != "loan:approve" || !strings.Contains(denied.Error(), "no role grants") {
		t.Fatalf("decisions = %+v", denied.Decisions)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/branches/b1/loans", nil))
	if !errors.Is(gotErr, ErrUnauthenticated) {
		t.Fatalf("no header: err %v", gotErr)
	}
}

func TestHTTPStatus(t *testing.T) {
	for err, want := range map[error]int{
		nil:                           http.StatusOK,
		ErrUnauthenticated:            http.StatusUnauthorized,
		&DeniedError{}:                http.StatusForbidden,
		invalidf("x"):                 http.StatusBadRequest,
		errStore:                      http.StatusInternalServerError,
		&UndefinedError{Kind: "role"}: http.StatusInternalServerError,
		ErrEscalation:                 http.StatusForbidden,
		ErrNotAssignable:              http.StatusBadRequest,
		ErrRoleNotFound:               http.StatusNotFound,
		ErrConflict:                   http.StatusConflict,
		ErrRoleNameTaken:              http.StatusConflict,
		ErrRoleInUse:                  http.StatusConflict,
		context.Canceled:              http.StatusInternalServerError,
	} {
		if got := HTTPStatus(err); got != want {
			t.Errorf("HTTPStatus(%v) = %d, want %d", err, got, want)
		}
	}
}

// TestScopeFromAloneValidates: ScopeFrom rejects a bad ID itself, so a
// handler that reads the scope from the context (wardn.ScopeOf) to load
// tenant data never sees an invalid ID, with or without Require.
func TestScopeFromAloneValidates(t *testing.T) {
	w, _ := newBank(t)
	var seen []Scope
	h := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		s, _ := ScopeOf(r.Context())
		seen = append(seen, s)
		rw.WriteHeader(http.StatusNoContent)
	})
	mux := http.NewServeMux()
	mux.Handle("GET /branches/{branchID}/report", w.ScopeFrom("branch", PathValue("branchID"))(h))
	for path, want := range map[string]int{
		"/branches/b1/report":          http.StatusNoContent,
		"/branches/%20b1/report":       http.StatusBadRequest,
		"/branches/b1%00/report":       http.StatusBadRequest,
		"/branches/b%E2%80%AE1/report": http.StatusBadRequest,
	} {
		if rec := serve(t, mux, path); rec.Code != want {
			t.Errorf("%s: status %d, want %d", path, rec.Code, want)
		}
	}
	if len(seen) != 1 || seen[0] != branch1 {
		t.Fatalf("handler saw scopes %v; only the valid one may reach it", seen)
	}
}
