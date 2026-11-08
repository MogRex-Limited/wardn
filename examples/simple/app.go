package main

import (
	_ "embed"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/examples/internal/demo"
	"github.com/MogRex-Limited/wardn/examples/simple/perm"
)

//go:generate go run github.com/MogRex-Limited/wardn/cmd/wardn gen -f wardn.yaml -o perm/perm.go

//go:embed wardn.yaml
var policyFile []byte

// Policy returns the app's authorization policy.
func Policy() (*wardn.Policy, error) {
	return wardn.ParsePolicy(policyFile, "wardn.yaml")
}

// Article is a piece of content.
type Article struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Published bool   `json:"published"`
}

// App is an internal publishing tool with no tenants: every role is global.
type App struct {
	w        *wardn.Warden
	mu       sync.Mutex
	articles map[string]*Article
}

// NewApp returns the app.
func NewApp(w *wardn.Warden) *App {
	return &App{w: w, articles: map[string]*Article{}}
}

// Router returns the app's HTTP API. No ScopeFrom: every check happens at
// global, where every assignment lives.
func (a *App) Router() http.Handler {
	w := a.w
	r := chi.NewRouter()
	r.Use(demo.Auth)
	r.With(w.Require(perm.ArticleView)).Get("/articles", a.list)
	r.With(w.Require(perm.ArticleEdit)).Put("/articles/{id}", a.save)
	r.With(w.Require(perm.ArticlePublish)).Post("/articles/{id}/publish", a.publish)
	r.With(w.Require(perm.WardnRolesAssign)).Put("/users/{user}/roles/{role}", a.assign)
	return r
}

func (a *App) list(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	out := []Article{}
	for _, art := range a.articles {
		out = append(out, *art)
	}
	a.mu.Unlock()
	demo.JSON(w, http.StatusOK, out)
}

func (a *App) save(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Title string `json:"title"`
	}
	if err := demo.Decode(w, r, &body); err != nil {
		demo.Error(w, err)
		return
	}
	id := r.PathValue("id")
	a.mu.Lock()
	a.articles[id] = &Article{ID: id, Title: body.Title}
	a.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) publish(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	art := a.articles[r.PathValue("id")]
	if art == nil {
		demo.Error(w, demo.ErrNotFound)
		return
	}
	art.Published = true
	demo.JSON(w, http.StatusOK, art)
}

func (a *App) assign(w http.ResponseWriter, r *http.Request) {
	if err := a.w.Assign(r.Context(), r.PathValue("user"), r.PathValue("role"), wardn.Global); err != nil {
		demo.Error(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
