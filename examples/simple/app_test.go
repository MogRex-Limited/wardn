package main

import (
	"net/http"
	"testing"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/examples/internal/demotest"
	"github.com/MogRex-Limited/wardn/examples/simple/perm"
	"github.com/MogRex-Limited/wardn/wardntest"
)

func newSimple(t *testing.T) demotest.Client {
	t.Helper()
	policy, err := Policy()
	if err != nil {
		t.Fatal(err)
	}
	w := wardntest.NewFromPolicy(t, policy)
	if err := w.System().Assign(t.Context(), "root", perm.RoleAdmin, wardn.Global); err != nil {
		t.Fatal(err)
	}
	c := demotest.Client{T: t, H: NewApp(w).Router()}
	c.Want("root", "PUT", "/users/ed/roles/editor", "", http.StatusNoContent)
	c.Want("root", "PUT", "/users/vi/roles/viewer", "", http.StatusNoContent)
	return c
}

func TestRoles(t *testing.T) {
	c := newSimple(t)
	c.Want("ed", "PUT", "/articles/a1", `{"title":"Hello"}`, http.StatusNoContent)
	c.Want("ed", "POST", "/articles/a1/publish", "", http.StatusOK)
	c.Want("vi", "GET", "/articles", "", http.StatusOK)
	c.Want("vi", "PUT", "/articles/a2", `{"title":"Nope"}`, http.StatusForbidden)
	c.Want("", "GET", "/articles", "", http.StatusUnauthorized)
}

func TestOnlyAdminsAssignRoles(t *testing.T) {
	c := newSimple(t)
	c.Want("ed", "PUT", "/users/vi/roles/editor", "", http.StatusForbidden)
	c.Want("root", "PUT", "/users/vi/roles/admin", "", http.StatusNoContent)
	c.Want("vi", "PUT", "/users/x/roles/viewer", "", http.StatusNoContent)
}

func TestEveryRouteIsProtected(t *testing.T) {
	demotest.AuditAllRoutes(t, newSimple(t).H)
}

func TestGeneratedNamesAreCurrent(t *testing.T) { demotest.GeneratedNamesAreCurrent(t) }
