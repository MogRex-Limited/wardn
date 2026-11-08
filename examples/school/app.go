package main

import (
	"context"
	_ "embed"
	"net/http"
	"slices"
	"sync"

	"github.com/go-chi/chi/v5"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/examples/internal/demo"
	"github.com/MogRex-Limited/wardn/examples/school/perm"
)

//go:generate go run github.com/MogRex-Limited/wardn/cmd/wardn gen -f wardn.yaml -o perm/perm.go

//go:embed wardn.yaml
var policyFile []byte

// Policy returns the school system's authorization policy.
func Policy() (*wardn.Policy, error) {
	return wardn.ParsePolicy(policyFile, "wardn.yaml")
}

// Data is the school system's own data. It is the single source of truth
// for which school a class belongs to: wardn asks it through ParentOf.
type Data struct {
	mu      sync.Mutex
	classes map[string]string            // class → school
	grades  map[string]map[string]string // class → student → grade
}

// NewData returns empty school data.
func NewData() *Data {
	return &Data{classes: map[string]string{}, grades: map[string]map[string]string{}}
}

// ParentOf tells wardn which school a class is in. Nothing about the
// hierarchy is stored twice.
func (d *Data) ParentOf(_ context.Context, s wardn.Scope) (wardn.Scope, bool, error) {
	if s.Type != "class" {
		return wardn.Scope{}, false, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	school, ok := d.classes[s.ID]
	return perm.ScopeSchool(school), ok, nil
}

// MoveClass moves a class to another school. Because wardn reads parents
// through ParentOf, access follows on the next request.
func (d *Data) MoveClass(class, school string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.classes[class] = school
}

// App wires the school system's routes to wardn.
type App struct {
	w    *wardn.Warden
	data *Data
}

// Router returns the school system's HTTP API.
func (a *App) Router() http.Handler {
	w := a.w
	r := chi.NewRouter()
	r.Use(demo.Auth)

	r.Route("/schools/{school}", func(r chi.Router) {
		r.Use(w.ScopeFrom("school", wardn.PathValue("school")))
		r.With(w.Require(perm.ClassCreate)).Post("/classes", a.createClass)
	})
	r.Route("/classes/{class}", func(r chi.Router) {
		r.Use(w.ScopeFrom("class", wardn.PathValue("class")))
		r.With(w.RequireAny(perm.GradeView, perm.GradeViewOwn)).Get("/grades", a.grades)
		r.With(w.Require(perm.GradeEdit)).Put("/grades/{student}", a.setGrade)
		r.With(w.Require(perm.WardnRolesAssign)).Put("/teachers/{user}", a.assigner(perm.RoleTeacher))
		r.With(w.Require(perm.WardnRolesAssign)).Put("/students/{user}", a.assigner(perm.RoleStudent))
	})
	return r
}

func (a *App) createClass(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := demo.Decode(w, r, &body); err != nil || body.ID == "" {
		demo.Error(w, demo.ErrBadBody)
		return
	}
	a.data.mu.Lock()
	_, exists := a.data.classes[body.ID]
	if !exists {
		a.data.classes[body.ID] = r.PathValue("school")
	}
	a.data.mu.Unlock()
	if exists {
		demo.JSON(w, http.StatusConflict, map[string]string{"error": "class already exists"})
		return
	}
	demo.JSON(w, http.StatusCreated, map[string]string{"class": body.ID})
}

type grade struct {
	Student string `json:"student"`
	Grade   string `json:"grade"`
}

// grades shows every grade to those who may view them all, and only their
// own to everyone else: a business rule built on two wardn permissions.
func (a *App) grades(w http.ResponseWriter, r *http.Request) {
	class, user := r.PathValue("class"), demo.User(r)
	seeAll := a.w.Can(r.Context(), user, perm.GradeView, perm.ScopeClass(class))
	a.data.mu.Lock()
	out := []grade{}
	for student, g := range a.data.grades[class] {
		if seeAll || student == user {
			out = append(out, grade{Student: student, Grade: g})
		}
	}
	a.data.mu.Unlock()
	slices.SortFunc(out, func(x, y grade) int {
		switch {
		case x.Student < y.Student:
			return -1
		case x.Student > y.Student:
			return 1
		}
		return 0
	})
	demo.JSON(w, http.StatusOK, out)
}

func (a *App) setGrade(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Grade string `json:"grade"`
	}
	if err := demo.Decode(w, r, &body); err != nil || body.Grade == "" {
		demo.Error(w, demo.ErrBadBody)
		return
	}
	class := r.PathValue("class")
	a.data.mu.Lock()
	if a.data.grades[class] == nil {
		a.data.grades[class] = map[string]string{}
	}
	a.data.grades[class][r.PathValue("student")] = body.Grade
	a.data.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) assigner(role string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := a.w.Assign(r.Context(), r.PathValue("user"), role, perm.ScopeClass(r.PathValue("class"))); err != nil {
			demo.Error(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
