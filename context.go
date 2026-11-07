package wardn

import (
	"context"
	"sync"
)

type userKey struct{}

type scopeKey struct{}

// WithUser returns a copy of ctx carrying the authenticated user's ID. The
// product's authentication middleware calls this; wardn's HTTP middleware
// reads it.
func WithUser(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userKey{}, userID)
}

// UserOf returns the user ID stored by WithUser.
func UserOf(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(userKey{}).(string)
	return id, ok && id != ""
}

// WithScope returns a copy of ctx carrying the scope a request acts in.
func WithScope(ctx context.Context, s Scope) context.Context {
	return context.WithValue(ctx, scopeKey{}, s)
}

// ScopeOf returns the scope stored by WithScope.
func ScopeOf(ctx context.Context) (Scope, bool) {
	s, ok := ctx.Value(scopeKey{}).(Scope)
	return s, ok
}

// memoKey identifies one Warden's memo in a context, so two Wardens sharing
// a context never share results.
type memoKey struct{ w *Warden }

// memo caches store reads for the lifetime of one request. A request sees
// one consistent view and is short-lived, so this is always safe; it never
// outlives the request (design decision D1). Time windows are still
// evaluated on every check.
type memo struct {
	mu          sync.Mutex
	parents     map[Scope]parentResult
	assignments map[assignmentsKey][]Assignment
}

type parentResult struct {
	parent Scope
	ok     bool
}

type assignmentsKey struct {
	user  string
	scope Scope // the requested scope; its chain is derived from it
}

// WithMemo returns a copy of ctx in which this Warden memoises store reads,
// so repeated checks in one request do not repeat queries. Use it for the
// lifetime of a single request only. wardn's HTTP middleware does this
// automatically.
func (w *Warden) WithMemo(ctx context.Context) context.Context {
	if w.memoFrom(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, memoKey{w}, &memo{
		parents:     map[Scope]parentResult{},
		assignments: map[assignmentsKey][]Assignment{},
	})
}

func (w *Warden) memoFrom(ctx context.Context) *memo {
	m, _ := ctx.Value(memoKey{w}).(*memo)
	return m
}

// forget clears the memo after a change, so a request that changes
// assignments or links and then checks access sees its own change.
func (m *memo) forget() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	clear(m.parents)
	clear(m.assignments)
}
