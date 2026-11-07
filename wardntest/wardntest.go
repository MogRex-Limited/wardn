// Package wardntest helps test code that uses wardn, without a database.
//
// Use New with the application's real policy file, so tests catch typos in
// permission names exactly as production would:
//
//	w := wardntest.New(t, "../wardn.yaml")
//	req = wardntest.AsRole(t, w, req, "auditor")
//
// Use AllowAll when authorization is not what the test is about.
package wardntest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MogRex-Limited/wardn"
)

// Option configures a test Warden.
type Option func(*wardn.Config)

// WithClock makes the Warden use clock, typically a *Clock, so tests can
// move time forward to test time-limited access.
func WithClock(clock wardn.Clock) Option {
	return func(c *wardn.Config) { c.Clock = clock }
}

// WithStore makes the Warden use store instead of a fresh MemoryStore.
func WithStore(store wardn.Store) Option {
	return func(c *wardn.Config) { c.Store = store }
}

// New returns a Warden for the policy file, backed by an in-memory store.
// It fails the test if the policy is invalid.
func New(t testing.TB, policyFile string, opts ...Option) *wardn.Warden {
	t.Helper()
	p, err := wardn.LoadPolicyFile(policyFile)
	if err != nil {
		t.Fatalf("wardntest: %v", err)
	}
	return NewFromPolicy(t, p, opts...)
}

// NewFromPolicy returns a Warden for a policy defined in Go, backed by an
// in-memory store. It fails the test if the policy is invalid.
func NewFromPolicy(t testing.TB, p *wardn.Policy, opts ...Option) *wardn.Warden {
	t.Helper()
	cfg := wardn.Config{Policy: p, Store: wardn.NewMemoryStore()}
	for _, opt := range opts {
		opt(&cfg)
	}
	w, err := wardn.New(cfg)
	if err != nil {
		t.Fatalf("wardntest: %v", err)
	}
	return w
}

// allowAllRole is the role AllowAll adds to the policy.
const allowAllRole = "wardntest_allow_all"

// AllowAll returns a Warden for the policy file that allows every user
// every permission everywhere. Permission names are still checked against
// the policy, so typos still fail.
func AllowAll(t testing.TB, policyFile string) *wardn.Warden {
	t.Helper()
	p, err := wardn.LoadPolicyFile(policyFile)
	if err != nil {
		t.Fatalf("wardntest: %v", err)
	}
	if _, exists := p.Roles[allowAllRole]; exists {
		t.Fatalf("wardntest: the policy already defines a role named %q", allowAllRole)
	}
	p.Roles[allowAllRole] = wardn.Role{Allow: []string{"*"}}
	return NewFromPolicy(t, p, WithStore(allowAllStore{wardn.NewMemoryStore()}))
}

// allowAllStore reports that every user holds allowAllRole globally.
type allowAllStore struct{ *wardn.MemoryStore }

func (allowAllStore) Assignments(_ context.Context, user string, _ []wardn.Scope) ([]wardn.Assignment, error) {
	return []wardn.Assignment{{User: user, Role: allowAllRole, Scope: wardn.Global}}, nil
}

var userSeq atomic.Uint64

// NewUser creates a fresh user ID holding roles at scope, and returns it.
func NewUser(t testing.TB, w *wardn.Warden, scope wardn.Scope, roles ...string) string {
	t.Helper()
	return newUser(t.Context(), t, w, scope, roles)
}

func newUser(ctx context.Context, t testing.TB, w *wardn.Warden, scope wardn.Scope, roles []string) string {
	t.Helper()
	user := fmt.Sprintf("wardntest-user-%d", userSeq.Add(1))
	for _, role := range roles {
		if err := w.System().Assign(ctx, user, role, scope); err != nil {
			if errors.Is(err, wardn.ErrNotAssignable) && scope.IsGlobal() {
				t.Fatalf("wardntest: %v (use AsRoleIn or NewUser with a scope where the role is assignable)", err)
			}
			t.Fatalf("wardntest: %v", err)
		}
	}
	return user
}

// AsRole returns a copy of r made by a fresh user who holds roles globally,
// as if the application's authentication middleware had run.
func AsRole(t testing.TB, w *wardn.Warden, r *http.Request, roles ...string) *http.Request {
	t.Helper()
	return AsRoleIn(t, w, r, wardn.Global, roles...)
}

// AsRoleIn is like AsRole, but the roles are held at scope.
func AsRoleIn(t testing.TB, w *wardn.Warden, r *http.Request, scope wardn.Scope, roles ...string) *http.Request {
	t.Helper()
	user := newUser(r.Context(), t, w, scope, roles)
	return r.WithContext(wardn.WithUser(r.Context(), user))
}

// Clock is a fake clock that only moves when told to. It is safe for
// concurrent use.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// NewClock returns a Clock set to start.
func NewClock(start time.Time) *Clock {
	return &Clock{now: start}
}

// Now returns the clock's current time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Set moves the clock to t.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}
