package wardn

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
)

// Store errors. Stores return these (possibly wrapped) so wardn can react.
var (
	// ErrRoleNameTaken: a custom role with the same normalised name already
	// exists in the owner scope.
	ErrRoleNameTaken = errors.New("wardn: a role with this name already exists here")

	// ErrRoleNotFound: no custom role has the given ID.
	ErrRoleNotFound = errors.New("wardn: role not found")

	// ErrConflict: the role was changed by someone else since it was read.
	ErrConflict = errors.New("wardn: role was changed by someone else; reload and try again")
)

// Assignment records that a user holds a role in a scope, optionally only
// within a time window.
type Assignment struct {
	User  string `json:"user"`
	Role  string `json:"role"` // a system role name, or a custom role ID ("cr-...")
	Scope Scope  `json:"scope"`

	// StartsAt and ExpiresAt bound when the assignment applies. The zero
	// time means "no bound". The window is half-open: it applies from
	// StartsAt (inclusive) until ExpiresAt (exclusive).
	StartsAt  time.Time `json:"starts_at,omitzero"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
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

// Store persists assignments, custom roles and scope links. wardn's core
// does all the authorization logic (inheritance, wildcards, deny-wins, time
// windows, the escalation guard), so a Store only saves and loads records.
//
// Implementations must be safe for concurrent use, must honour context
// cancellation, and must compare IDs exactly, byte for byte (no case- or
// accent-insensitive matching). Every method must either succeed completely
// or return an error; wardn treats any error as "deny". Stores may round
// times to a coarser precision, but never in a direction that widens a time
// window. The storetest package checks all of this.
type Store interface {
	AssignmentStore
	RoleStore
	ScopeStore
}

// AssignmentStore persists role assignments.
type AssignmentStore interface {
	// Assign saves an assignment. There is at most one assignment per
	// (user, role, scope): assigning again replaces the time window and
	// clears any expiry report.
	Assign(ctx context.Context, a Assignment) error

	// Revoke deletes the assignment of role to user at scope, if any.
	// Revoking an assignment that does not exist is not an error.
	Revoke(ctx context.Context, user, role string, scope Scope) error

	// Assignments returns the user's assignments at any of the given
	// scopes, regardless of time window. It must never return assignments
	// for other users or other scopes.
	Assignments(ctx context.Context, user string, scopes []Scope) ([]Assignment, error)

	// Members returns up to limit assignments at exactly scope, ordered by
	// user then role, starting after cursor ("" for the first page). It
	// returns the cursor for the next page, or "" after the last page.
	// Cursors are opaque to callers.
	Members(ctx context.Context, scope Scope, cursor string, limit int) ([]Assignment, string, error)

	// RoleInUse reports whether any assignment refers to role.
	RoleInUse(ctx context.Context, role string) (bool, error)

	// RevokeRole deletes every assignment of role.
	RevokeRole(ctx context.Context, role string) error

	// ExpiredUnreported returns up to limit assignments whose ExpiresAt is
	// at or before t and that have not been marked as reported.
	ExpiredUnreported(ctx context.Context, t time.Time, limit int) ([]Assignment, error)

	// MarkExpiryReported records that the given assignments' expiry was
	// reported. An assignment whose time window has changed since it was
	// read (it was assigned again) must not be marked.
	MarkExpiryReported(ctx context.Context, as []Assignment) error
}

// RoleStore persists custom roles.
type RoleStore interface {
	// CreateRole saves a new custom role. It returns ErrRoleNameTaken if a
	// role with the same Owner and NameKey exists; the check and the write
	// must be atomic.
	CreateRole(ctx context.Context, r CustomRole) error

	// UpdateRole replaces a custom role if its stored version equals
	// expectedVersion, and returns ErrConflict otherwise, ErrRoleNotFound if
	// it does not exist, or ErrRoleNameTaken. r.Version is the new version.
	UpdateRole(ctx context.Context, r CustomRole, expectedVersion int) error

	// DeleteRole deletes a custom role. Deleting a role that does not exist
	// is not an error.
	DeleteRole(ctx context.Context, id string) error

	// Roles returns the custom roles with the given IDs, omitting IDs that
	// do not exist.
	Roles(ctx context.Context, ids []string) ([]CustomRole, error)

	// RolesOwnedBy returns the custom roles owned by any of the scopes.
	RolesOwnedBy(ctx context.Context, owners []Scope) ([]CustomRole, error)
}

// ScopeStore persists the scope hierarchy.
type ScopeStore interface {
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
	mu       sync.RWMutex
	byUser   map[string]map[assignmentKey]*memAssignment
	parents  map[Scope]Scope
	roles    map[string]CustomRole
	roleKeys map[roleNameIndex]string // (owner, name key) → role ID
}

type assignmentKey struct {
	role  string
	scope Scope
}

type memAssignment struct {
	a        Assignment
	reported bool
}

type roleNameIndex struct {
	owner Scope
	key   string
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byUser:   map[string]map[assignmentKey]*memAssignment{},
		parents:  map[Scope]Scope{},
		roles:    map[string]CustomRole{},
		roleKeys: map[roleNameIndex]string{},
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
		user = map[assignmentKey]*memAssignment{}
		m.byUser[a.User] = user
	}
	user[assignmentKey{role: a.Role, scope: a.Scope}] = &memAssignment{a: a}
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
	for key, ma := range m.byUser[user] {
		if slices.Contains(scopes, key.scope) {
			out = append(out, ma.a)
		}
	}
	return out, nil
}

// Members implements Store.
func (m *MemoryStore) Members(ctx context.Context, scope Scope, cursor string, limit int) ([]Assignment, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	afterUser, afterRole, err := decodeMemberCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	m.mu.RLock()
	var all []Assignment
	for _, roles := range m.byUser {
		for key, ma := range roles {
			if key.scope == scope {
				all = append(all, ma.a)
			}
		}
	}
	m.mu.RUnlock()
	slices.SortFunc(all, func(a, b Assignment) int {
		return cmp.Or(strings.Compare(a.User, b.User), strings.Compare(a.Role, b.Role))
	})
	start := 0
	if cursor != "" {
		start, _ = slices.BinarySearchFunc(all, Assignment{User: afterUser, Role: afterRole}, func(a, b Assignment) int {
			return cmp.Or(strings.Compare(a.User, b.User), strings.Compare(a.Role, b.Role))
		})
		if start < len(all) && all[start].User == afterUser && all[start].Role == afterRole {
			start++
		}
	}
	if limit <= 0 {
		limit = 1
	}
	end := min(start+limit, len(all))
	page := all[start:end]
	next := ""
	if end < len(all) && len(page) > 0 {
		last := page[len(page)-1]
		next = EncodeMemberCursor(last.User, last.Role)
	}
	return page, next, nil
}

// EncodeMemberCursor builds a Members cursor from the last user and role of
// a page. Stores may use it, or any opaque encoding of their own.
func EncodeMemberCursor(user, role string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(user + "\x00" + role))
}

func decodeMemberCursor(cursor string) (user, role string, err error) {
	if cursor == "" {
		return "", "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", "", invalidf("invalid cursor")
	}
	user, role, ok := strings.Cut(string(b), "\x00")
	if !ok {
		return "", "", invalidf("invalid cursor")
	}
	return user, role, nil
}

// DecodeMemberCursor parses a cursor made by EncodeMemberCursor.
func DecodeMemberCursor(cursor string) (user, role string, err error) {
	return decodeMemberCursor(cursor)
}

// RoleInUse implements Store.
func (m *MemoryStore) RoleInUse(ctx context.Context, role string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, roles := range m.byUser {
		for key := range roles {
			if key.role == role {
				return true, nil
			}
		}
	}
	return false, nil
}

// RevokeRole implements Store.
func (m *MemoryStore) RevokeRole(ctx context.Context, role string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for user, roles := range m.byUser {
		for key := range roles {
			if key.role == role {
				delete(roles, key)
			}
		}
		if len(roles) == 0 {
			delete(m.byUser, user)
		}
	}
	return nil
}

// ExpiredUnreported implements Store.
func (m *MemoryStore) ExpiredUnreported(ctx context.Context, t time.Time, limit int) ([]Assignment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Assignment
	for _, roles := range m.byUser {
		for _, ma := range roles {
			if !ma.reported && !ma.a.ExpiresAt.IsZero() && !ma.a.ExpiresAt.After(t) {
				out = append(out, ma.a)
			}
		}
	}
	slices.SortFunc(out, func(a, b Assignment) int { return a.ExpiresAt.Compare(b.ExpiresAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// MarkExpiryReported implements Store.
func (m *MemoryStore) MarkExpiryReported(ctx context.Context, as []Assignment) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range as {
		ma := m.byUser[a.User][assignmentKey{role: a.Role, scope: a.Scope}]
		if ma != nil && ma.a.ExpiresAt.Equal(a.ExpiresAt) {
			ma.reported = true
		}
	}
	return nil
}

// CreateRole implements Store.
func (m *MemoryStore) CreateRole(ctx context.Context, r CustomRole) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := roleNameIndex{owner: r.Owner, key: r.NameKey}
	if _, taken := m.roleKeys[idx]; taken {
		return ErrRoleNameTaken
	}
	m.roles[r.ID] = cloneRole(r)
	m.roleKeys[idx] = r.ID
	return nil
}

// UpdateRole implements Store.
func (m *MemoryStore) UpdateRole(ctx context.Context, r CustomRole, expectedVersion int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.roles[r.ID]
	switch {
	case !ok:
		return ErrRoleNotFound
	case old.Version != expectedVersion:
		return ErrConflict
	}
	idx := roleNameIndex{owner: old.Owner, key: r.NameKey}
	if id, taken := m.roleKeys[idx]; taken && id != r.ID {
		return ErrRoleNameTaken
	}
	delete(m.roleKeys, roleNameIndex{owner: old.Owner, key: old.NameKey})
	r.Owner, r.CreatedAt = old.Owner, old.CreatedAt // immutable
	m.roles[r.ID] = cloneRole(r)
	m.roleKeys[idx] = r.ID
	return nil
}

// DeleteRole implements Store.
func (m *MemoryStore) DeleteRole(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.roles[id]; ok {
		delete(m.roleKeys, roleNameIndex{owner: old.Owner, key: old.NameKey})
		delete(m.roles, id)
	}
	return nil
}

// Roles implements Store.
func (m *MemoryStore) Roles(ctx context.Context, ids []string) ([]CustomRole, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []CustomRole
	for _, id := range ids {
		if r, ok := m.roles[id]; ok {
			out = append(out, cloneRole(r))
		}
	}
	return out, nil
}

// RolesOwnedBy implements Store.
func (m *MemoryStore) RolesOwnedBy(ctx context.Context, owners []Scope) ([]CustomRole, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []CustomRole
	for _, r := range m.roles {
		if slices.Contains(owners, r.Owner) {
			out = append(out, cloneRole(r))
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

func cloneRole(r CustomRole) CustomRole {
	r.Allow = slices.Clone(r.Allow)
	r.AssignableAt = slices.Clone(r.AssignableAt)
	return r
}
