package main

import (
	_ "embed"
	"errors"
	"net/http"
	"slices"
	"sync"

	"github.com/go-chi/chi/v5"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/examples/internal/demo"
	"github.com/MogRex-Limited/wardn/examples/saas/perm"
)

//go:generate go run github.com/MogRex-Limited/wardn/cmd/wardn gen -f wardn.yaml -o perm/perm.go

//go:embed wardn.yaml
var policyFile []byte

// Policy returns the product's authorization policy.
func Policy() (*wardn.Policy, error) {
	return wardn.ParsePolicy(policyFile, "wardn.yaml")
}

// Data is the product's own data, kept in memory for the demo.
type Data struct {
	mu         sync.Mutex
	workspaces map[string]bool
	projects   map[string]string // project → workspace
	billing    map[string]string // workspace → plan
}

// NewData returns empty product data.
func NewData() *Data {
	return &Data{workspaces: map[string]bool{}, projects: map[string]string{}, billing: map[string]string{}}
}

// App wires the product's routes to wardn.
type App struct {
	w    *wardn.Warden
	data *Data
}

// Router returns the product's HTTP API.
func (a *App) Router() http.Handler {
	w := a.w
	r := chi.NewRouter()
	r.Use(demo.Auth)

	// Open to every signed-in user: create a workspace and own it.
	r.Post("/signup", a.signup)

	r.Route("/workspaces/{ws}", func(r chi.Router) {
		r.Use(w.ScopeFrom("workspace", wardn.PathValue("ws")))
		r.With(w.Require(perm.ProjectView)).Get("/projects", a.listProjects)
		r.With(w.Require(perm.ProjectCreate)).Post("/projects", a.createProject)
		r.With(w.Require(perm.MemberInvite)).Post("/invites/{user}", a.invite)
		r.With(w.Require(perm.BillingManage)).Put("/billing", a.updateBilling)
		r.With(w.Require(perm.WardnRolesManage)).Post("/roles", a.createRole)
		r.With(w.Require(perm.WardnRolesAssign)).Get("/roles", a.assignableRoles)
		r.With(w.Require(perm.WardnRolesAssign)).Put("/members/{user}/roles/{role}", a.assignInWorkspace)

		r.Route("/projects/{p}", func(r chi.Router) {
			// Authorize first, against the project's own scope (linked to
			// its real workspace), then check the project belongs to the
			// workspace in the URL. In the other order, 404 versus 403 would
			// tell anyone which project IDs exist.
			r.Use(w.ScopeFrom("project", wardn.PathValue("p")))
			r.With(w.Require(perm.ProjectEdit), a.projectInWorkspace).Put("/", a.editProject)
			r.With(w.Require(perm.WardnRolesAssign), a.projectInWorkspace).Put("/editors/{user}", a.addEditor)
		})
	})
	return r
}

var errTaken = errors.New("workspace already exists")

// signup creates a workspace for the signed-in user. Nobody holds any role
// in a brand-new workspace yet, so the first owner is assigned with System().
func (a *App) signup(w http.ResponseWriter, r *http.Request) {
	user := demo.User(r)
	if user == "" {
		demo.Error(w, wardn.ErrUnauthenticated)
		return
	}
	var body struct {
		Workspace string `json:"workspace"`
	}
	if err := demo.Decode(w, r, &body); err != nil || body.Workspace == "" {
		demo.Error(w, demo.ErrBadBody)
		return
	}
	a.data.mu.Lock()
	taken := a.data.workspaces[body.Workspace]
	a.data.workspaces[body.Workspace] = true
	a.data.mu.Unlock()
	if taken { // never hand an existing tenant to someone new
		demo.JSON(w, http.StatusConflict, map[string]string{"error": errTaken.Error()})
		return
	}
	if err := a.w.System().Assign(r.Context(), user, perm.RoleWorkspaceOwner, perm.ScopeWorkspace(body.Workspace)); err != nil {
		demo.Error(w, err)
		return
	}
	demo.JSON(w, http.StatusCreated, map[string]string{"workspace": body.Workspace, "owner": user})
}

func (a *App) createProject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := demo.Decode(w, r, &body); err != nil || body.ID == "" {
		demo.Error(w, demo.ErrBadBody)
		return
	}
	ws := r.PathValue("ws")
	a.data.mu.Lock()
	_, exists := a.data.projects[body.ID]
	if !exists {
		a.data.projects[body.ID] = ws
	}
	a.data.mu.Unlock()
	if exists {
		demo.JSON(w, http.StatusConflict, map[string]string{"error": "project already exists"})
		return
	}
	if err := a.w.Link(r.Context(), perm.ScopeProject(body.ID), perm.ScopeWorkspace(ws)); err != nil {
		demo.Error(w, err)
		return
	}
	demo.JSON(w, http.StatusCreated, map[string]string{"project": body.ID})
}

func (a *App) listProjects(w http.ResponseWriter, r *http.Request) {
	ws := r.PathValue("ws")
	a.data.mu.Lock()
	out := []string{}
	for p, owner := range a.data.projects {
		if owner == ws {
			out = append(out, p)
		}
	}
	a.data.mu.Unlock()
	slices.Sort(out)
	demo.JSON(w, http.StatusOK, out)
}

func (a *App) projectInWorkspace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.data.mu.Lock()
		ws, ok := a.data.projects[r.PathValue("p")]
		a.data.mu.Unlock()
		if !ok || ws != r.PathValue("ws") {
			demo.Error(w, demo.ErrNotFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) editProject(w http.ResponseWriter, r *http.Request) {
	demo.JSON(w, http.StatusOK, map[string]string{"project": r.PathValue("p"), "status": "saved"})
}

func (a *App) addEditor(w http.ResponseWriter, r *http.Request) {
	if err := a.w.Assign(r.Context(), r.PathValue("user"), perm.RoleProjectEditor, perm.ScopeProject(r.PathValue("p"))); err != nil {
		demo.Error(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) invite(w http.ResponseWriter, r *http.Request) {
	if err := a.w.Assign(r.Context(), r.PathValue("user"), perm.RoleWorkspaceMember, perm.ScopeWorkspace(r.PathValue("ws"))); err != nil {
		demo.Error(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) updateBilling(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Plan string `json:"plan"`
	}
	if err := demo.Decode(w, r, &body); err != nil {
		demo.Error(w, err)
		return
	}
	a.data.mu.Lock()
	a.data.billing[r.PathValue("ws")] = body.Plan
	a.data.mu.Unlock()
	demo.JSON(w, http.StatusOK, body)
}

// createRole lets a customer define their own role, visible only in their
// workspace.
func (a *App) createRole(w http.ResponseWriter, r *http.Request) {
	var spec wardn.RoleSpec
	if err := demo.Decode(w, r, &spec); err != nil {
		demo.Error(w, err)
		return
	}
	role, err := a.w.CreateRole(r.Context(), perm.ScopeWorkspace(r.PathValue("ws")), spec)
	if err != nil {
		demo.Error(w, err)
		return
	}
	demo.JSON(w, http.StatusCreated, role)
}

// assignableRoles fills the "assign role" picker with only the roles the
// signed-in user may hand out here.
func (a *App) assignableRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := a.w.AssignableRoles(r.Context(), perm.ScopeWorkspace(r.PathValue("ws")))
	if err != nil {
		demo.Error(w, err)
		return
	}
	demo.JSON(w, http.StatusOK, roles)
}

func (a *App) assignInWorkspace(w http.ResponseWriter, r *http.Request) {
	if err := a.w.Assign(r.Context(), r.PathValue("user"), r.PathValue("role"), perm.ScopeWorkspace(r.PathValue("ws"))); err != nil {
		demo.Error(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
