package wardn

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
)

// HTTP errors passed to Config.OnError. Test for them with errors.Is.
var (
	// ErrUnauthenticated reports a request with no authenticated user.
	ErrUnauthenticated = errors.New("wardn: no authenticated user")

	// ErrDenied reports a request whose user lacks the required permissions.
	// The error is a *DeniedError carrying the decisions.
	ErrDenied = errors.New("wardn: permission denied")
)

// DeniedError is returned when a request is denied. It wraps ErrDenied and
// carries the decisions, so a custom OnError can log why.
type DeniedError struct {
	Decisions []Decision
}

func (e *DeniedError) Error() string {
	reasons := make([]string, len(e.Decisions))
	for i, d := range e.Decisions {
		reasons[i] = d.Reason
	}
	return "wardn: permission denied: " + strings.Join(reasons, "; ")
}

// Unwrap makes errors.Is(err, ErrDenied) true.
func (e *DeniedError) Unwrap() error { return ErrDenied }

// HTTPStatus returns the HTTP status code for an error from wardn: 401 when
// no user is authenticated; 403 when denied or when the escalation guard
// refuses; 400 for invalid input; 404 for an unknown custom role (also what
// an actor without wardn:roles.manage sees for an existing one); 409 for an
// edit conflict, a taken name or a role still in use; and 500 for anything
// else, such as a store failure. Admin APIs can use it for management
// errors too.
func HTTPStatus(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrUnauthenticated):
		return http.StatusUnauthorized
	case errors.Is(err, ErrDenied), errors.Is(err, ErrEscalation):
		return http.StatusForbidden
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrNotAssignable):
		return http.StatusBadRequest
	case errors.Is(err, ErrRoleNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrConflict), errors.Is(err, ErrRoleNameTaken), errors.Is(err, ErrRoleInUse), errors.Is(err, ErrAlreadyLinked):
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}

// defaultOnError writes a generic JSON error. It never reveals which
// permission or role was missing (threat model T20); OnDecision receives
// the details.
func defaultOnError(w http.ResponseWriter, _ *http.Request, err error) {
	status := HTTPStatus(err)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	body := map[int]string{
		http.StatusUnauthorized: "unauthenticated",
		http.StatusForbidden:    "forbidden",
		http.StatusBadRequest:   "bad request",
	}[status]
	if body == "" {
		body = "internal error"
	}
	_, _ = fmt.Fprintf(w, "{\"error\":%q}\n", body)
}

// Require returns middleware that lets a request through only if its user
// holds every one of the permissions at the request's scope. It works with
// net/http, chi, and any router that uses func(http.Handler) http.Handler.
//
// The user comes from Config.UserFrom, or from the context (see WithUser).
// The scope comes from ScopeFrom middleware, or is Global if none is set.
//
// Require panics if a permission is not in the policy, so a typo stops the
// application when routes are registered rather than denying users later.
func (w *Warden) Require(permissions ...string) func(http.Handler) http.Handler {
	return w.require("Require", permissions, false)
}

// RequireAny is like Require, but one of the permissions is enough.
func (w *Warden) RequireAny(permissions ...string) func(http.Handler) http.Handler {
	return w.require("RequireAny", permissions, true)
}

func (w *Warden) require(name string, permissions []string, needAny bool) func(http.Handler) http.Handler {
	if len(permissions) == 0 {
		panic(fmt.Sprintf("wardn: %s needs at least one permission", name))
	}
	for _, p := range permissions {
		if err := w.checkPermission(p); err != nil {
			panic(fmt.Sprintf("%v (in %s)", err, name))
		}
	}
	perms := slices.Clone(permissions)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			ctx := w.WithMemo(r.Context())
			user, ok := w.userOf(r)
			if !ok {
				w.onError(rw, r, ErrUnauthenticated)
				return
			}
			scope, ok := ScopeOf(ctx)
			if !ok {
				scope = Global // only global assignments apply (threat model T18)
			}
			ds, err := w.checkMany(ctx, user, scope, perms)
			if err != nil {
				w.onError(rw, r, err)
				return
			}
			allowed := !needAny
			for _, d := range ds {
				if needAny && d.Allowed {
					allowed = true
				}
				if !needAny && !d.Allowed {
					allowed = false
				}
			}
			if !allowed {
				w.onError(rw, r, &DeniedError{Decisions: ds})
				return
			}
			next.ServeHTTP(rw, r.WithContext(ctx))
		})
	}
}

// ScopeFrom returns middleware that sets the request's scope to the given
// scope type, with the ID taken from the request by id (for example
// PathValue("orgID")). Place it where the ID is available: with chi,
// inside r.Route or r.With, after routing.
//
// A missing or invalid ID is answered with 400 Bad Request; the request
// never reaches Require. ScopeFrom panics if scopeType is not declared in
// the policy.
func (w *Warden) ScopeFrom(scopeType string, id func(*http.Request) string) func(http.Handler) http.Handler {
	if _, ok := w.policy.scopeTypes[scopeType]; !ok {
		types := slices.Sorted(maps.Keys(w.policy.scopeTypes))
		panic((&UndefinedError{Kind: "scope type", Name: scopeType, Suggestion: suggest(scopeType, types)}).Error() + " (in ScopeFrom)")
	}
	if id == nil {
		panic("wardn: ScopeFrom needs a function that returns the scope ID")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			scope := NewScope(scopeType, id(r))
			if err := w.validateScope(scope); err != nil {
				w.onError(rw, r, err)
				return
			}
			ctx := WithScope(w.WithMemo(r.Context()), scope)
			next.ServeHTTP(rw, r.WithContext(ctx))
		})
	}
}

// PathValue returns a function that reads a path parameter, for use with
// ScopeFrom. It works with net/http's ServeMux and with chi.
func PathValue(name string) func(*http.Request) string {
	return func(r *http.Request) string { return r.PathValue(name) }
}

func (w *Warden) userOf(r *http.Request) (string, bool) {
	if w.userFrom != nil {
		user, ok := w.userFrom(r)
		return user, ok && user != ""
	}
	return UserOf(r.Context())
}

func (w *Warden) onError(rw http.ResponseWriter, r *http.Request, err error) {
	if w.errorHandler != nil {
		w.errorHandler(rw, r, err)
		return
	}
	defaultOnError(rw, r, err)
}
