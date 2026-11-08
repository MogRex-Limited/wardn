package main

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/examples/internal/demotest"
	"github.com/MogRex-Limited/wardn/wardntest"
)

// newSaaS returns the product with two customers:
//
//	olu   owns workspace acme   (projects p-42, p-43)
//	gina  owns workspace globex
func newSaaS(t *testing.T) demotest.Client {
	t.Helper()
	policy, err := Policy()
	if err != nil {
		t.Fatal(err)
	}
	w := wardntest.NewFromPolicy(t, policy)
	c := demotest.Client{T: t, H: (&App{w: w, data: NewData()}).Router()}
	c.Want("olu", "POST", "/signup", `{"workspace":"acme"}`, http.StatusCreated)
	c.Want("gina", "POST", "/signup", `{"workspace":"globex"}`, http.StatusCreated)
	c.Want("olu", "POST", "/workspaces/acme/projects", `{"id":"p-42"}`, http.StatusCreated)
	c.Want("olu", "POST", "/workspaces/acme/projects", `{"id":"p-43"}`, http.StatusCreated)
	return c
}

func TestOwnersAreIsolated(t *testing.T) {
	c := newSaaS(t)
	c.Want("olu", "GET", "/workspaces/acme/projects", "", http.StatusOK)
	c.Want("olu", "GET", "/workspaces/globex/projects", "", http.StatusForbidden)
	c.Want("gina", "PUT", "/workspaces/acme/billing", `{"plan":"free"}`, http.StatusForbidden)
}

func TestSignupCannotTakeOverAWorkspace(t *testing.T) {
	c := newSaaS(t)
	c.Want("mallory", "POST", "/signup", `{"workspace":"acme"}`, http.StatusConflict)
	c.Want("mallory", "GET", "/workspaces/acme/projects", "", http.StatusForbidden)
}

func TestMembers(t *testing.T) {
	c := newSaaS(t)
	c.Want("olu", "POST", "/workspaces/acme/invites/mo", "", http.StatusNoContent)
	c.Want("mo", "GET", "/workspaces/acme/projects", "", http.StatusOK)
	c.Want("mo", "POST", "/workspaces/acme/projects", `{"id":"p-44"}`, http.StatusCreated)
	c.Want("mo", "POST", "/workspaces/acme/invites/friend", "", http.StatusForbidden) // no member:invite
	c.Want("mo", "PUT", "/workspaces/acme/billing", `{"plan":"pro"}`, http.StatusForbidden)
}

// TestProjectLevelAccess: a contractor can edit one project and nothing else.
func TestProjectLevelAccess(t *testing.T) {
	c := newSaaS(t)
	c.Want("olu", "PUT", "/workspaces/acme/projects/p-42/editors/con", "", http.StatusNoContent)
	c.Want("con", "PUT", "/workspaces/acme/projects/p-42/", "", http.StatusOK)
	c.Want("con", "PUT", "/workspaces/acme/projects/p-43/", "", http.StatusForbidden)
	c.Want("con", "GET", "/workspaces/acme/projects", "", http.StatusForbidden) // project-level only
}

func TestThreat_T02_ConfusedDeputy(t *testing.T) {
	c := newSaaS(t)
	// gina owns globex; p-42 belongs to acme. Through globex's URL she is
	// refused, exactly as for a project that does not exist, so she can't
	// learn which project IDs exist.
	c.Want("gina", "PUT", "/workspaces/globex/projects/p-42/", "", http.StatusForbidden)
	c.Want("gina", "PUT", "/workspaces/globex/projects/no-such/", "", http.StatusForbidden)
	c.Want("gina", "PUT", "/workspaces/globex/projects/p-42/editors/gina", "", http.StatusForbidden)

	// olu is also an editor of a Globex project. Naming it through Acme's
	// URL, he is authorized for the project but the URL and the record
	// disagree, so it is not found.
	c.Want("gina", "POST", "/workspaces/globex/projects", `{"id":"g-1"}`, http.StatusCreated)
	c.Want("gina", "PUT", "/workspaces/globex/projects/g-1/editors/olu", "", http.StatusNoContent)
	c.Want("olu", "PUT", "/workspaces/globex/projects/g-1/", "", http.StatusOK)
	c.Want("olu", "PUT", "/workspaces/acme/projects/g-1/", "", http.StatusNotFound)
}

// TestCustomerDefinedRoles: each customer's roles stay in their workspace.
func TestCustomerDefinedRoles(t *testing.T) {
	c := newSaaS(t)
	var role wardn.CustomRole
	resp := c.Want("olu", "POST", "/workspaces/acme/roles", `{"name":"Billing Admin","allow":["billing:manage","project:view"]}`, http.StatusCreated)
	if err := json.Unmarshal([]byte(resp), &role); err != nil {
		t.Fatal(err)
	}
	c.Want("olu", "PUT", "/workspaces/acme/members/bob/roles/"+role.ID, "", http.StatusNoContent)
	c.Want("bob", "PUT", "/workspaces/acme/billing", `{"plan":"pro"}`, http.StatusOK)
	c.Want("bob", "POST", "/workspaces/acme/invites/x", "", http.StatusForbidden)

	// Globex can't see Acme's role, can't assign it, and may use the same name.
	var globexRoles []wardn.RoleInfo
	if err := json.Unmarshal([]byte(c.Want("gina", "GET", "/workspaces/globex/roles", "", http.StatusOK)), &globexRoles); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(globexRoles, func(r wardn.RoleInfo) bool { return r.ID == role.ID }) {
		t.Fatal("Acme's custom role is visible in Globex")
	}
	c.Want("gina", "PUT", "/workspaces/globex/members/x/roles/"+role.ID, "", http.StatusBadRequest)
	c.Want("gina", "POST", "/workspaces/globex/roles", `{"name":"Billing Admin","allow":["billing:manage"]}`, http.StatusCreated)

	// A name that impersonates a system role is refused.
	c.Want("olu", "POST", "/workspaces/acme/roles", `{"name":"Workspace Owner","allow":["project:view"]}`, http.StatusConflict)
}

func TestEveryRouteIsProtected(t *testing.T) {
	c := newSaaS(t)
	demotest.AuditAllRoutes(t, c.H, wardntest.Route{Method: "POST", Path: "/signup"})
}

func TestGeneratedNamesAreCurrent(t *testing.T) { demotest.GeneratedNamesAreCurrent(t) }
