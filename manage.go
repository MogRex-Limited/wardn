package wardn

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// System performs management operations without the escalation guard, for
// code that has no human actor: seeding the first administrator, data
// migrations and background jobs. Calls to it should stand out in code
// review. Every change is still audited, with Event.System set.
type System struct {
	w *Warden
}

// System returns the unguarded management handle. Requests made on behalf
// of a user must use the guarded methods on Warden instead.
func (w *Warden) System() *System {
	return &System{w: w}
}

// actor identifies who is making a change, and whether the escalation
// guard applies.
type actor struct {
	id      string
	guarded bool
}

// systemActor makes unguarded changes; its events have System set and no
// Actor, so they cannot be confused with a user whose ID is "system".
var systemActor = actor{}

func actorFrom(ctx context.Context) (actor, error) {
	id, ok := UserOf(ctx)
	if !ok {
		return actor{}, fmt.Errorf("%w: management calls need the acting user in the context (wardn.WithUser); use System() for jobs with no user", ErrUnauthenticated)
	}
	if err := validateID("user", id); err != nil {
		return actor{}, invalidf("acting user: %v", err)
	}
	return actor{id: id, guarded: true}, nil
}

// AssignOption configures an assignment.
type AssignOption func(*Assignment)

// From makes an assignment apply only from t onwards.
func From(t time.Time) AssignOption {
	return func(a *Assignment) { a.StartsAt = t }
}

// Until makes an assignment stop applying at t.
func Until(t time.Time) AssignOption {
	return func(a *Assignment) { a.ExpiresAt = t }
}

// ---------------------------------------------------------------------------
// Guarded API: the acting user comes from the context (WithUser).

// Assign gives user the role at scope, on behalf of the user in ctx. The
// actor needs wardn:roles.assign at scope and must hold every permission
// the role grants there (the escalation guard). role is a system role name
// or a custom role ID. Assigning again replaces the time window.
func (w *Warden) Assign(ctx context.Context, user, role string, scope Scope, opts ...AssignOption) error {
	a, err := actorFrom(ctx)
	if err != nil {
		return err
	}
	return w.assign(ctx, a, user, role, scope, opts)
}

// Revoke removes role from user at scope, on behalf of the user in ctx,
// under the same guard as Assign, so a lower administrator cannot strip a
// higher one (threat model T04).
func (w *Warden) Revoke(ctx context.Context, user, role string, scope Scope) error {
	a, err := actorFrom(ctx)
	if err != nil {
		return err
	}
	return w.revoke(ctx, a, user, role, scope)
}

// CreateRole creates a custom role owned by owner, on behalf of the user in
// ctx. The actor needs wardn:roles.manage at owner and must hold every
// permission in the role.
func (w *Warden) CreateRole(ctx context.Context, owner Scope, spec RoleSpec) (CustomRole, error) {
	a, err := actorFrom(ctx)
	if err != nil {
		return CustomRole{}, err
	}
	return w.createRole(ctx, a, owner, spec)
}

// UpdateRole replaces a custom role's name, description and permissions,
// on behalf of the user in ctx. version must be the version the caller read;
// if the role changed since, ErrConflict is returned. The actor needs
// wardn:roles.manage at the role's owner and must hold every permission in
// both the old and the new role.
func (w *Warden) UpdateRole(ctx context.Context, id string, spec RoleSpec, version int) (CustomRole, error) {
	a, err := actorFrom(ctx)
	if err != nil {
		return CustomRole{}, err
	}
	return w.updateRole(ctx, a, id, spec, version)
}

// DeleteOption configures DeleteRole.
type DeleteOption func(*deleteOptions)

type deleteOptions struct{ cascade bool }

// Cascade makes DeleteRole also revoke every assignment of the role.
// Without it, deleting a role that is still assigned fails with
// ErrRoleInUse.
func Cascade() DeleteOption {
	return func(o *deleteOptions) { o.cascade = true }
}

// DeleteRole deletes a custom role, on behalf of the user in ctx, under the
// same guard as UpdateRole.
func (w *Warden) DeleteRole(ctx context.Context, id string, opts ...DeleteOption) error {
	a, err := actorFrom(ctx)
	if err != nil {
		return err
	}
	return w.deleteRole(ctx, a, id, opts)
}

// ---------------------------------------------------------------------------
// Unguarded API.

// Assign gives user the role at scope without the escalation guard.
func (s *System) Assign(ctx context.Context, user, role string, scope Scope, opts ...AssignOption) error {
	return s.w.assign(ctx, systemActor, user, role, scope, opts)
}

// Revoke removes role from user at scope without the escalation guard.
func (s *System) Revoke(ctx context.Context, user, role string, scope Scope) error {
	return s.w.revoke(ctx, systemActor, user, role, scope)
}

// CreateRole creates a custom role without the escalation guard.
func (s *System) CreateRole(ctx context.Context, owner Scope, spec RoleSpec) (CustomRole, error) {
	return s.w.createRole(ctx, systemActor, owner, spec)
}

// UpdateRole updates a custom role without the escalation guard.
func (s *System) UpdateRole(ctx context.Context, id string, spec RoleSpec, version int) (CustomRole, error) {
	return s.w.updateRole(ctx, systemActor, id, spec, version)
}

// DeleteRole deletes a custom role without the escalation guard.
func (s *System) DeleteRole(ctx context.Context, id string, opts ...DeleteOption) error {
	return s.w.deleteRole(ctx, systemActor, id, opts)
}

// ---------------------------------------------------------------------------
// Implementation.

// resolvedRole is a role looked up for a management operation.
type resolvedRole struct {
	compiled *compiledRole
	custom   *CustomRole // nil for system roles
}

// resolveRole finds a system role by name or a custom role by ID.
func (w *Warden) resolveRole(ctx context.Context, role string) (*resolvedRole, error) {
	if r := w.policy.roles[role]; r != nil {
		return &resolvedRole{compiled: r}, nil
	}
	if isCustomRoleID(role) {
		if err := validateID("role", role); err != nil {
			return nil, invalidf("%v", err)
		}
		roles, err := w.customRoles(ctx, []string{role}, nil)
		if err != nil {
			return nil, err
		}
		if cr := roles[role]; cr != nil {
			return &resolvedRole{compiled: w.policy.compileCustomRole(cr), custom: cr}, nil
		}
		return nil, fmt.Errorf("%w: %s", ErrRoleNotFound, role)
	}
	return nil, &UndefinedError{Kind: "role", Name: role, Suggestion: suggest(role, w.policy.roleNames)}
}

// checkAssignable verifies that a role may be assigned at scope.
func (w *Warden) checkAssignable(ctx context.Context, r *resolvedRole, scope Scope) error {
	if !r.compiled.assignableAtScope(scope) {
		return fmt.Errorf("%w: role %s cannot be assigned at %s; it is assignable at: %s",
			ErrNotAssignable, r.compiled.label(), scope, strings.Join(r.compiled.assignableList(), ", "))
	}
	if r.custom != nil {
		chain, err := w.chain(ctx, scope)
		if err != nil {
			return err
		}
		if !slices.Contains(chain, r.custom.Owner) {
			return fmt.Errorf("%w: role %s belongs to %s and can only be assigned inside it", ErrNotAssignable, r.compiled.label(), r.custom.Owner)
		}
	}
	return nil
}

// guard enforces the escalation guard: the actor must hold the management
// permission at scope, and every pattern in each list.
func (w *Warden) guard(ctx context.Context, a actor, scope Scope, mgmtPerm string, patternLists ...[]string) error {
	if !a.guarded {
		return nil
	}
	gs, err := w.grants(ctx, a.id, scope)
	if err != nil {
		return err
	}
	if d := evaluate(gs, Decision{User: a.id, Permission: mgmtPerm, Scope: scope}); !d.Allowed {
		return &DeniedError{Decisions: []Decision{d}}
	}
	for _, list := range patternLists {
		for _, p := range list {
			if !holds(gs, p) {
				return fmt.Errorf("%w: %q at %s", ErrEscalation, p, scope)
			}
		}
	}
	return nil
}

// holds reports whether the grants give everything pattern covers. A
// concrete permission must be allowed. A wildcard needs an allow that
// covers the whole wildcard and no deny overlapping any part of it, so a
// role written today cannot pick up permissions the actor lacks, now or
// when the catalog grows (threat model T06).
func holds(gs []grant, pattern string) bool {
	if !isWildcard(pattern) {
		return evaluate(gs, Decision{Permission: pattern}).Allowed
	}
	covered := false
	for _, g := range gs {
		for _, d := range g.role.deny {
			if covers(d, pattern) || covers(pattern, d) {
				return false
			}
		}
		for _, al := range g.role.allow {
			if covers(al, pattern) {
				covered = true
			}
		}
	}
	return covered
}

// covers reports whether every permission p matches is matched by q.
func covers(q, p string) bool {
	switch {
	case q == "*":
		return true
	case p == "*":
		return false
	case isWildcard(q):
		return strings.HasPrefix(p, strings.TrimSuffix(q, "*"))
	}
	return q == p
}

func (w *Warden) assign(ctx context.Context, a actor, user, role string, scope Scope, opts []AssignOption) error {
	if err := validateID("user", user); err != nil {
		return invalidf("%v", err)
	}
	if err := w.validateScope(scope); err != nil {
		return err
	}
	// Refuse actors without the management permission before revealing
	// anything about the role, such as whether it exists.
	if err := w.guard(ctx, a, scope, PermRolesAssign); err != nil {
		return err
	}
	r, err := w.resolveRole(ctx, role)
	if err != nil {
		return err
	}
	if err := w.checkAssignable(ctx, r, scope); err != nil {
		return err
	}
	as := Assignment{User: user, Role: role, Scope: scope}
	for _, opt := range opts {
		opt(&as)
	}
	for _, tm := range []time.Time{as.StartsAt, as.ExpiresAt} {
		if !tm.IsZero() && (tm.Year() < 1 || tm.Year() > 9999) {
			return invalidf("time %s is outside years 1 to 9999", tm.Format(time.RFC3339))
		}
	}
	if !as.StartsAt.IsZero() && !as.ExpiresAt.IsZero() && !as.ExpiresAt.After(as.StartsAt) {
		return invalidf("time window ends (%s) before it starts (%s)", as.ExpiresAt.Format(time.RFC3339), as.StartsAt.Format(time.RFC3339))
	}
	if !as.ExpiresAt.IsZero() && !as.ExpiresAt.After(w.clock.Now()) {
		return invalidf("assignment would already be expired (%s)", as.ExpiresAt.Format(time.RFC3339))
	}
	// A role's denies count too: assigning it restricts, revoking it lifts
	// restrictions, and neither may reach beyond what the actor holds
	// (security review F1).
	if err := w.guard(ctx, a, scope, PermRolesAssign, r.compiled.allow, r.compiled.deny); err != nil {
		return err
	}
	// Assigning exactly what is already there changes nothing, so it is not
	// written or audited again: seeding on every start stays quiet.
	existing, err := w.store.Assignments(ctx, user, []Scope{scope})
	if err != nil {
		return fmt.Errorf("wardn: reading current assignments: %w", err)
	}
	if slices.ContainsFunc(existing, func(e Assignment) bool {
		return e.User == user && e.Role == role && e.Scope == scope &&
			e.StartsAt.Equal(as.StartsAt) && e.ExpiresAt.Equal(as.ExpiresAt)
	}) {
		return nil
	}
	return w.change(ctx, Event{Type: EventAssigned, Actor: a.id, System: !a.guarded, User: user, Role: role, Scope: scope, StartsAt: as.StartsAt, ExpiresAt: as.ExpiresAt},
		func() error { return w.store.Assign(ctx, as) })
}

func (w *Warden) revoke(ctx context.Context, a actor, user, role string, scope Scope) error {
	if err := validateID("user", user); err != nil {
		return invalidf("%v", err)
	}
	if err := validateID("role", role); err != nil {
		return invalidf("%v", err)
	}
	if err := w.validateScope(scope); err != nil {
		return err
	}
	if err := w.guard(ctx, a, scope, PermRolesAssign); err != nil {
		return err
	}
	var allow, deny []string
	r, err := w.resolveRole(ctx, role)
	var ue *UndefinedError
	switch {
	case err == nil:
		allow, deny = r.compiled.allow, r.compiled.deny
	case errors.Is(err, ErrRoleNotFound), errors.As(err, &ue):
		// The role no longer exists, so it grants nothing: revoking the
		// leftover assignment only needs wardn:roles.assign.
	default:
		return err
	}
	if err := w.guard(ctx, a, scope, PermRolesAssign, allow, deny); err != nil {
		return err
	}
	return w.change(ctx, Event{Type: EventRevoked, Actor: a.id, System: !a.guarded, User: user, Role: role, Scope: scope},
		func() error { return w.store.Revoke(ctx, user, role, scope) })
}

func (w *Warden) createRole(ctx context.Context, a actor, owner Scope, spec RoleSpec) (CustomRole, error) {
	if err := w.validateScope(owner); err != nil {
		return CustomRole{}, err
	}
	if err := w.guard(ctx, a, owner, PermRolesManage); err != nil {
		return CustomRole{}, err
	}
	r, err := w.checkRoleSpec(ctx, owner, spec, "")
	if err != nil {
		return CustomRole{}, err
	}
	if err := w.guard(ctx, a, owner, PermRolesManage, r.Allow); err != nil {
		return CustomRole{}, err
	}
	if r.ID, err = newCustomRoleID(); err != nil {
		return CustomRole{}, err
	}
	now := w.clock.Now()
	r.Version, r.CreatedAt, r.UpdatedAt = 1, now, now
	after := cloneRole(r)
	err = w.change(ctx, Event{Type: EventRoleCreated, Actor: a.id, System: !a.guarded, Role: r.ID, Scope: owner, After: &after},
		func() error { return w.store.CreateRole(ctx, r) })
	if err != nil {
		return CustomRole{}, err
	}
	return r, nil
}

func (w *Warden) updateRole(ctx context.Context, a actor, id string, spec RoleSpec, version int) (CustomRole, error) {
	old, err := w.loadManagedRole(ctx, a, id)
	if err != nil {
		return CustomRole{}, err
	}
	if old.Version != version {
		return CustomRole{}, ErrConflict
	}
	r, err := w.checkRoleSpec(ctx, old.Owner, spec, id)
	if err != nil {
		return CustomRole{}, err
	}
	// The actor must hold everything in the old role too, so nobody can
	// strip a role they could not have granted (the mirror of T04).
	if err := w.guard(ctx, a, old.Owner, PermRolesManage, old.Allow, r.Allow); err != nil {
		return CustomRole{}, err
	}
	r.ID, r.Version, r.CreatedAt, r.UpdatedAt = old.ID, old.Version+1, old.CreatedAt, w.clock.Now()
	before, after := cloneRole(*old), cloneRole(r)
	err = w.change(ctx, Event{Type: EventRoleUpdated, Actor: a.id, System: !a.guarded, Role: id, Scope: old.Owner, Before: &before, After: &after},
		func() error { return w.store.UpdateRole(ctx, r, version) })
	if err != nil {
		return CustomRole{}, err
	}
	return r, nil
}

func (w *Warden) deleteRole(ctx context.Context, a actor, id string, opts []DeleteOption) error {
	var o deleteOptions
	for _, opt := range opts {
		opt(&o)
	}
	old, err := w.loadManagedRole(ctx, a, id)
	if errors.Is(err, ErrRoleNotFound) && !a.guarded {
		return nil // already gone; System() deletes are idempotent
	}
	if err != nil {
		return err
	}
	if err := w.guard(ctx, a, old.Owner, PermRolesManage, old.Allow); err != nil {
		return err
	}
	inUse, err := w.store.RoleInUse(ctx, id)
	if err != nil {
		return fmt.Errorf("wardn: checking role assignments: %w", err)
	}
	if inUse && !o.cascade {
		return fmt.Errorf("%w: %q (%s); revoke its assignments first, or pass wardn.Cascade()", ErrRoleInUse, old.Name, id)
	}
	before := cloneRole(*old)
	return w.change(ctx, Event{Type: EventRoleDeleted, Actor: a.id, System: !a.guarded, Role: id, Scope: old.Owner, Before: &before}, func() error {
		// Delete the role first: from that moment its assignments grant
		// nothing (rule 6), so a failure while revoking them is harmless.
		if err := w.store.DeleteRole(ctx, id); err != nil {
			return err
		}
		if o.cascade {
			return w.store.RevokeRole(ctx, id)
		}
		return nil
	})
}

// loadManagedRole loads a role for an update or deletion. For a guarded
// actor it checks wardn:roles.manage at the role's owner before anything
// else, and answers a denied actor exactly as if the role did not exist,
// so nobody without that permission learns whether a role ID exists, its
// version, or anything about it (security review F5).
func (w *Warden) loadManagedRole(ctx context.Context, a actor, id string) (*CustomRole, error) {
	notFound := fmt.Errorf("%w: %s", ErrRoleNotFound, id)
	old, err := w.loadCustomRole(ctx, id)
	if errors.Is(err, ErrRoleNotFound) {
		return nil, notFound
	}
	if err != nil {
		return nil, err
	}
	if err := w.guard(ctx, a, old.Owner, PermRolesManage); err != nil {
		var denied *DeniedError
		if errors.As(err, &denied) {
			return nil, notFound
		}
		return nil, err
	}
	return old, nil
}

func (w *Warden) loadCustomRole(ctx context.Context, id string) (*CustomRole, error) {
	if !isCustomRoleID(id) || validateID("role", id) != nil {
		return nil, fmt.Errorf("%w: %q is not a custom role ID", ErrRoleNotFound, id)
	}
	w.memoFrom(ctx).forget() // management reads the latest version
	roles, err := w.customRoles(ctx, []string{id}, nil)
	if err != nil {
		return nil, err
	}
	if roles[id] == nil {
		return nil, fmt.Errorf("%w: %s", ErrRoleNotFound, id)
	}
	return roles[id], nil
}

// checkRoleSpec validates a role spec for owner and returns the role it
// describes (without ID, version or times). selfID is the role being
// updated, if any.
func (w *Warden) checkRoleSpec(ctx context.Context, owner Scope, spec RoleSpec, selfID string) (CustomRole, error) {
	if len(spec.Deny) > 0 {
		return CustomRole{}, invalidf("custom roles cannot contain deny rules (role %q); remove Deny or use a system role", spec.Name)
	}
	if err := validateRoleName(spec.Name); err != nil {
		return CustomRole{}, err
	}
	if err := validDescription(spec.Description); err != nil {
		return CustomRole{}, invalidf("%v", err)
	}
	switch {
	case len(spec.Allow) == 0:
		return CustomRole{}, invalidf("role %q grants nothing; add permissions to Allow", spec.Name)
	case len(spec.Allow) > maxRolePatterns:
		return CustomRole{}, invalidf("role %q has more than %d permissions", spec.Name, maxRolePatterns)
	}
	seen := map[string]bool{}
	for _, p := range spec.Allow {
		switch {
		case seen[p]:
			return CustomRole{}, invalidf("%q is listed more than once", p)
		case !validPattern(p):
			return CustomRole{}, invalidf("invalid permission pattern %q", p)
		case isWildcard(p):
			if !slices.ContainsFunc(w.policy.permList, func(perm string) bool { return matches(p, perm) }) {
				return CustomRole{}, invalidf("%q matches no permission in the catalog", p)
			}
		default:
			if err := w.checkPermission(p); err != nil {
				return CustomRole{}, err
			}
		}
		seen[p] = true
	}

	assignable := spec.AssignableAt
	if len(assignable) == 0 {
		assignable = []string{scopeTypeName(owner)}
	}
	for _, t := range assignable {
		if !w.typeWithin(t, owner) {
			return CustomRole{}, fmt.Errorf("%w: a role owned by %s cannot be assignable at %q; use %s or a scope type inside it",
				ErrNotAssignable, owner, t, scopeTypeName(owner))
		}
	}

	key := roleNameKey(spec.Name)
	for name := range w.policy.roles {
		if roleNameKey(name) == key {
			return CustomRole{}, fmt.Errorf("%w: %q looks the same as the system role %q", ErrRoleNameTaken, spec.Name, name)
		}
	}
	// Names must also be unique against roles owned by ancestors, which are
	// visible in the same places. The store enforces uniqueness within the
	// owner atomically.
	chain, err := w.chain(ctx, owner)
	if err != nil {
		return CustomRole{}, err
	}
	if selfID == "" { // creating: bound the roles per owner (security review F9)
		own, err := w.store.RolesOwnedBy(ctx, []Scope{owner})
		if err != nil {
			return CustomRole{}, fmt.Errorf("wardn: counting roles: %w", err)
		}
		if len(own) >= maxRolesPerOwner {
			return CustomRole{}, invalidf("%s already has %d custom roles, the maximum", owner, maxRolesPerOwner)
		}
	}
	visible, err := w.store.RolesOwnedBy(ctx, chain[1:])
	if err != nil {
		return CustomRole{}, fmt.Errorf("wardn: checking role names: %w", err)
	}
	for _, r := range visible {
		if r.NameKey == key && r.ID != selfID {
			return CustomRole{}, fmt.Errorf("%w: %q looks the same as the role %q owned by %s", ErrRoleNameTaken, spec.Name, r.Name, r.Owner)
		}
	}

	return CustomRole{
		Owner:        owner,
		Name:         spec.Name,
		NameKey:      key,
		Description:  spec.Description,
		Allow:        slices.Clone(spec.Allow),
		AssignableAt: slices.Clone(assignable),
	}, nil
}

// typeWithin reports whether scope type t (or "global") is owner's type or
// a type nested inside it.
func (w *Warden) typeWithin(t string, owner Scope) bool {
	if owner.IsGlobal() {
		return t == globalName || w.policy.scopeTypes[t] != nil
	}
	for cur := t; cur != ""; {
		if cur == owner.Type {
			return true
		}
		st := w.policy.scopeTypes[cur]
		if st == nil {
			return false
		}
		cur = st.parent
	}
	return false
}

// Link records that parent is the parent of child, so roles assigned at
// parent (and its ancestors) apply in child. The parent's type must be the
// one the policy declares for child.
//
// Link never changes an existing parent. Linking a scope to the parent it
// already has does nothing, so it is safe to call on every start. Linking
// it to a different parent fails with ErrAlreadyLinked (which also matches
// ErrInvalidLink): two tenants that
// reuse the same ID ("cardiology" in two hospitals) would otherwise move
// one tenant's scope under the other's administrators. Use Move to change
// a parent on purpose.
//
// Link is plumbing for the application's backend, called when it creates an
// entity. Never expose it directly to end users: whoever controls links
// controls inheritance (threat model T11). Every link is audited.
func (w *Warden) Link(ctx context.Context, child, parent Scope) error {
	return w.link(ctx, child, parent, false)
}

// Move changes child's parent, for example when a branch moves to another
// region. Roles inherited from the old parent stop applying, and those of
// the new parent start, on the next check. Moving a scope that has no
// parent yet links it. Every move is audited.
func (w *Warden) Move(ctx context.Context, child, newParent Scope) error {
	return w.link(ctx, child, newParent, true)
}

func (w *Warden) link(ctx context.Context, child, parent Scope, move bool) error {
	if w.parentOf != nil {
		return ErrLinksExternal
	}
	if child.IsGlobal() || parent.IsGlobal() {
		return fmt.Errorf("%w: global cannot be linked; top-level scopes are already inside global", ErrInvalidLink)
	}
	if err := w.validateScope(child); err != nil {
		return err
	}
	if err := w.validateScope(parent); err != nil {
		return err
	}
	want := w.policy.scopeTypes[child.Type].parent
	switch {
	case want == "":
		return fmt.Errorf("%w: %s is a top-level scope type and has no parent", ErrInvalidLink, child.Type)
	case parent.Type != want:
		return fmt.Errorf("%w: cannot link %s to %s; a %s's parent must be a %s",
			ErrInvalidLink, child, parent, child.Type, want)
	}
	current, linked, err := w.store.Parent(ctx, child)
	if err != nil {
		return fmt.Errorf("wardn: reading current parent: %w", err)
	}
	switch {
	case linked && current == parent:
		return nil // already so: nothing to change, nothing to audit
	case linked && !move:
		return fmt.Errorf("%w (%w): %s is already inside %s; if two tenants use the same ID, make IDs unique (for example \"%s/%s\"); to move it on purpose, use Move",
			ErrAlreadyLinked, ErrInvalidLink, child, current, current.ID, child.ID)
	}
	ev := Event{Type: EventLinked, System: true, Scope: child, Parent: parent}
	if id, ok := UserOf(ctx); ok {
		ev.Actor, ev.System = id, false
	}
	return w.change(ctx, ev,
		func() error { return w.store.Link(ctx, child, parent) })
}

// Now returns the current time on the Warden's clock (Config.Clock). Use it
// when your code computes a time window, such as Until(w.Now().Add(72 *
// time.Hour)), so tests that move wardn's clock move yours too.
func (w *Warden) Now() time.Time {
	return w.clock.Now()
}
