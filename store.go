package wardn

import (
	"context"
	"slices"
	"sync"
	"time"
)

// Assignment records that a user holds a role in a scope, optionally only
// within a time window.
type Assignment struct {
	User  string
	Role  string // a system role name
	Scope Scope

	// StartsAt and ExpiresAt bound when the assignment applies. The zero
	// time means "no bound". The window is half-open: it applies from
	// StartsAt (inclusive) until ExpiresAt (exclusive).
	StartsAt  time.Time
	ExpiresAt time.Time
}

// activeAt reports whether the assignment's time window includes t.
func (a Assignment) activeAt(t time.Time) bool {
	if !a.StartsAt.IsZero() && t.Before(a.StartsAt) {
		return false
	}
	if !a.ExpiresAt.IsZero() && !t.Before(a.ExpiresAt) {
		return false
	}
	return true
}

// Store persists assignments and scope links. wardn's core does all the
// authorization logic (inheritance, wildcards, deny-wins, time windows), so
// a Store only saves and loads records.
//
// Implementations must be safe for concurrent use, must honour context
// cancellation, and must compare IDs exactly, byte for byte (no case- or
// accent-insensitive matching). Every method must either succeed completely
// or return an error; wardn treats any error as "deny". Stores may round
// times to a coarser precision, but never in a direction that widens a time
// window. The storetest package checks all of this.
type Store interface {
	// Assign saves an assignment. There is at most one assignment per
	// (user, role, scope): assigning again replaces the time window.
	Assign(ctx context.Context, a Assignment) error

	// Revoke deletes the assignment of role to user at scope, if any.
	// Revoking an assignment that does not exist is not an error.
	Revoke(ctx context.Context, user, role string, scope Scope) error

	// Assignments returns the user's assignments at any of the given
	// scopes, regardless of time window. It must never return assignments
	// for other users or other scopes.
	Assignments(ctx context.Context, user string, scopes []Scope) ([]Assignment, error)

	// Link records that parent is the parent of child, replacing any
	// existing parent.
	Link(ctx context.Context, child, parent Scope) error

	// Parent returns child's parent, and false if none is recorded.
	Parent(ctx context.Context, child Scope) (Scope, bool, error)
}

// Migrator is implemented by stores that manage their own database schema.
// New calls Migrate at startup unless Config.ManualMigrations is set.
type Migrator interface {
	Migrate(ctx context.Context) error
}

// MemoryStore is a Store that keeps everything in memory. Its contents are
// lost when the process exits, so it is meant for tests, examples and
// demos. Use a database-backed Store in production.
type MemoryStore struct {
	mu      sync.RWMutex
	byUser  map[string]map[assignmentKey]Assignment
	parents map[Scope]Scope
}

type assignmentKey struct {
	role  string
	scope Scope
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byUser:  map[string]map[assignmentKey]Assignment{},
		parents: map[Scope]Scope{},
	}
}

// Assign implements Store.
func (m *MemoryStore) Assign(ctx context.Context, a Assignment) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	user := m.byUser[a.User]
	if user == nil {
		user = map[assignmentKey]Assignment{}
		m.byUser[a.User] = user
	}
	user[assignmentKey{role: a.Role, scope: a.Scope}] = a
	return nil
}

// Revoke implements Store.
func (m *MemoryStore) Revoke(ctx context.Context, user, role string, scope Scope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byUser[user], assignmentKey{role: role, scope: scope})
	if len(m.byUser[user]) == 0 {
		delete(m.byUser, user)
	}
	return nil
}

// Assignments implements Store.
func (m *MemoryStore) Assignments(ctx context.Context, user string, scopes []Scope) ([]Assignment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Assignment
	for key, a := range m.byUser[user] {
		if slices.Contains(scopes, key.scope) {
			out = append(out, a)
		}
	}
	return out, nil
}

// Link implements Store.
func (m *MemoryStore) Link(ctx context.Context, child, parent Scope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.parents[child] = parent
	return nil
}

// Parent implements Store.
func (m *MemoryStore) Parent(ctx context.Context, child Scope) (Scope, bool, error) {
	if err := ctx.Err(); err != nil {
		return Scope{}, false, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.parents[child]
	return p, ok, nil
}
