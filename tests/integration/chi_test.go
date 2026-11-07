package integration

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/wardntest"
)

const chiPolicy = `
scopes:
  organisation: {}
  branch: { parent: organisation }
permissions:
  customer:view: View customers
  loan:create:   Create loans
  loan:approve:  Approve loans
roles:
  org_admin:
    assignable_at: [organisation]
    allow: ["*"]
  teller:
    assignable_at: [branch]
    allow: [customer:view, loan:create]
`

// TestChi runs the documented chi patterns: ScopeFrom inside r.Route,
// Require through r.With, and nested scopes.
func TestChi(t *testing.T) {
	p, err := wardn.ParsePolicy([]byte(chiPolicy), "wardn.yaml")
	if err != nil {
		t.Fatal(err)
	}
	w := wardn.MustNew(wardn.Config{Policy: p})
	ctx := t.Context()
	org, branch := wardn.NewScope("organisation", "acme"), wardn.NewScope("branch", "lagos")
	if err := w.Link(ctx, branch, org); err != nil {
		t.Fatal(err)
	}
	if err := w.System().Assign(ctx, "ada", "org_admin", org); err != nil {
		t.Fatal(err)
	}
	if err := w.System().Assign(ctx, "bayo", "teller", branch); err != nil {
		t.Fatal(err)
	}

	ok := func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusNoContent) }
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler { // stand-in for real authentication
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if u := req.Header.Get("X-User"); u != "" {
				req = req.WithContext(wardn.WithUser(req.Context(), u))
			}
			next.ServeHTTP(rw, req)
		})
	})
	r.Route("/orgs/{orgID}", func(r chi.Router) {
		r.Use(w.ScopeFrom("organisation", wardn.PathValue("orgID")))
		r.With(w.Require("customer:view")).Get("/customers", ok)

		r.Route("/branches/{branchID}", func(r chi.Router) {
			r.Use(w.ScopeFrom("branch", wardn.PathValue("branchID"))) // the innermost scope wins
			r.With(w.Require("loan:create")).Post("/loans", ok)
			r.With(w.Require("loan:approve")).Post("/loans/{id}/approve", ok)
		})
	})

	tests := []struct {
		user, method, path string
		want               int
	}{
		{"ada", http.MethodGet, "/orgs/acme/customers", http.StatusNoContent},
		{"ada", http.MethodPost, "/orgs/acme/branches/lagos/loans/7/approve", http.StatusNoContent}, // inherited
		{"ada", http.MethodGet, "/orgs/globex/customers", http.StatusForbidden},                     // other tenant
		{"bayo", http.MethodPost, "/orgs/acme/branches/lagos/loans", http.StatusNoContent},
		{"bayo", http.MethodPost, "/orgs/acme/branches/lagos/loans/7/approve", http.StatusForbidden},
		{"bayo", http.MethodPost, "/orgs/acme/branches/abuja/loans", http.StatusForbidden}, // other branch
		{"bayo", http.MethodGet, "/orgs/acme/customers", http.StatusForbidden},             // teller role is branch-level
		{"", http.MethodGet, "/orgs/acme/customers", http.StatusUnauthorized},
	}
	for _, tt := range tests {
		req := httptest.NewRequestWithContext(ctx, tt.method, tt.path, nil)
		if tt.user != "" {
			req.Header.Set("X-User", tt.user)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Errorf("%s %s %s: status %d, want %d", tt.user, tt.method, tt.path, rec.Code, tt.want)
		}
	}

	// Every route must deny a signed-in user with no roles (threat model T17).
	wardntest.AuditRoutes(t, r, func(req *http.Request, user string) *http.Request {
		req.Header.Set("X-User", user)
		return req
	}, chiRoutes(t, r))
}

var chiParam = regexp.MustCompile(`\{[^}]+\}`)

// chiRoutes lists a chi router's routes with path parameters filled in.
func chiRoutes(t *testing.T, r chi.Routes) []wardntest.Route {
	t.Helper()
	var routes []wardntest.Route
	err := chi.Walk(r, func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, wardntest.Route{Method: method, Path: chiParam.ReplaceAllString(pattern, "x")})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return routes
}
