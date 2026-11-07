package wardn

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
)

// Decision is the outcome of an authorization check, with the reason.
type Decision struct {
	Allowed    bool
	User       string
	Permission string
	Scope      Scope // the scope that was checked

	// Role is the role that decided the outcome: the role whose deny rule
	// matched, or the role that granted the permission. Empty when no role
	// matched or an error occurred.
	Role string
	// At is the scope where Role is assigned: Scope itself or an ancestor.
	At Scope
	// Rule is the allow or deny pattern that matched, e.g. "loan:*".
	Rule string
	// Reason explains the decision in words, for logs and debugging.
	Reason string
}

// Can reports whether user holds permission at scope. It returns false on
// any error, including an undefined permission; use Check to see why.
func (w *Warden) Can(ctx context.Context, user, permission string, scope Scope) bool {
	d, err := w.Check(ctx, user, permission, scope)
	return err == nil && d.Allowed
}

// CanAny reports whether user holds at least one of the permissions at
// scope. It returns false if any permission is undefined, or on any error.
func (w *Warden) CanAny(ctx context.Context, user string, scope Scope, permissions ...string) bool {
	ds, err := w.checkMany(ctx, user, scope, permissions)
	return err == nil && slices.ContainsFunc(ds, func(d Decision) bool { return d.Allowed })
}

// CanAll reports whether user holds every one of the permissions at scope.
// It returns false if the list is empty, if any permission is undefined, or
// on any error.
func (w *Warden) CanAll(ctx context.Context, user string, scope Scope, permissions ...string) bool {
	ds, err := w.checkMany(ctx, user, scope, permissions)
	return err == nil && len(ds) > 0 && !slices.ContainsFunc(ds, func(d Decision) bool { return !d.Allowed })
}

// Check decides whether user holds permission at scope and explains why.
// Errors (an undefined permission, an invalid scope, a store failure) are
// returned with a Decision that denies: wardn always fails closed.
func (w *Warden) Check(ctx context.Context, user, permission string, scope Scope) (Decision, error) {
	ds, err := w.checkMany(ctx, user, scope, []string{permission})
	if err != nil {
		d := Decision{User: user, Permission: permission, Scope: scope, Reason: "error: " + err.Error()}
		return d, err
	}
	return ds[0], nil
}

func (w *Warden) checkMany(ctx context.Context, user string, scope Scope, permissions []string) ([]Decision, error) {
	ds, err := w.decide(ctx, user, scope, permissions)
	if w.onDecision != nil {
		if err != nil {
			for _, p := range permissions {
				w.onDecision(ctx, Decision{User: user, Permission: p, Scope: scope, Reason: "error: " + err.Error()}, err)
			}
		} else {
			for _, d := range ds {
				w.onDecision(ctx, d, nil)
			}
		}
	}
	return ds, err
}

func (w *Warden) decide(ctx context.Context, user string, scope Scope, permissions []string) ([]Decision, error) {
	for _, p := range permissions {
		if err := w.checkPermission(p); err != nil {
			return nil, err
		}
	}
	gs, err := w.grants(ctx, user, scope)
	if err != nil {
		return nil, err
	}
	ds := make([]Decision, len(permissions))
	for i, p := range permissions {
		ds[i] = evaluate(gs, Decision{User: user, Permission: p, Scope: scope})
	}
	return ds, nil
}

// checkPermission verifies that perm is a concrete permission in the
// catalog (threat model T16).
func (w *Warden) checkPermission(perm string) error {
	if _, ok := w.policy.permissions[perm]; ok {
		return nil
	}
	if isWildcard(perm) {
		return invalidf("cannot check wildcard %q; check a concrete permission", perm)
	}
	return &UndefinedError{Kind: "permission", Name: perm, Suggestion: suggest(perm, w.policy.permList)}
}

// grant is a role that applies to the user at the checked scope.
type grant struct {
	role       *compiledRole
	assignment Assignment
	at         Scope
	depth      int // 0 for the checked scope, increasing towards Global
}

// grants returns the roles that apply to user at scope right now, ordered
// from the nearest scope outwards, then by role name.
func (w *Warden) grants(ctx context.Context, user string, scope Scope) ([]grant, error) {
	if err := validateID("user", user); err != nil {
		return nil, invalidf("%v", err)
	}
	if err := w.validateScope(scope); err != nil {
		return nil, err
	}
	chain, err := w.chain(ctx, scope)
	if err != nil {
		return nil, err
	}
	assignments, err := w.assignments(ctx, user, scope, chain)
	if err != nil {
		return nil, err
	}

	depthOf := make(map[Scope]int, len(chain))
	for i, s := range chain {
		depthOf[s] = i
	}
	now := w.clock.Now()
	active := make([]Assignment, 0, len(assignments))
	var customIDs []string
	for _, a := range assignments {
		_, inChain := depthOf[a.Scope]
		switch {
		case a.User != user, !inChain:
			continue // never trust a store to filter correctly (T01)
		case !a.activeAt(now):
			continue // rule 7: outside its time window (T09)
		}
		active = append(active, a)
		if isCustomRoleID(a.Role) {
			customIDs = append(customIDs, a.Role)
		}
	}
	customs, err := w.customRoles(ctx, customIDs)
	if err != nil {
		return nil, err
	}

	gs := make([]grant, 0, len(active))
	for _, a := range active {
		depth := depthOf[a.Scope]
		role := w.policy.roles[a.Role]
		if cr := customs[a.Role]; cr != nil && isCustomRoleID(a.Role) {
			role = w.policy.compileCustomRole(cr)
			// A custom role applies only within its owner's subtree: the
			// owner must be the assignment's scope or one of its ancestors.
			if ownerDepth, ok := depthOf[cr.Owner]; !ok || ownerDepth < depth {
				continue
			}
		}
		if role == nil {
			continue // rule 6: the role no longer exists (T10)
		}
		if !role.assignableAtScope(a.Scope) {
			continue // the policy no longer allows this role here
		}
		gs = append(gs, grant{role: role, assignment: a, at: a.Scope, depth: depth})
	}
	slices.SortFunc(gs, func(a, b grant) int {
		return cmp.Or(cmp.Compare(a.depth, b.depth), cmp.Compare(a.role.name, b.role.name))
	})
	return gs, nil
}

// evaluate applies the evaluation rules to one permission: deny wins, then
// any allow grants, otherwise deny by default.
func evaluate(gs []grant, d Decision) Decision {
	for _, g := range gs {
		if rule, ok := firstMatch(g.role.deny, d.Permission); ok {
			d.Role, d.At, d.Rule = g.role.name, g.at, rule
			d.Reason = fmt.Sprintf("denied by role %s at %s (rule %q)", g.role.label(), g.at, rule)
			return d
		}
	}
	for _, g := range gs {
		if rule, ok := firstMatch(g.role.allow, d.Permission); ok {
			d.Allowed = true
			d.Role, d.At, d.Rule = g.role.name, g.at, rule
			d.Reason = fmt.Sprintf("granted by role %s at %s (rule %q)", g.role.label(), g.at, rule)
			return d
		}
	}
	d.Reason = fmt.Sprintf("no role grants %q at %s", d.Permission, d.Scope)
	return d
}

// validateScope checks that s is Global or has a declared type and a valid
// ID.
func (w *Warden) validateScope(s Scope) error {
	if s.IsGlobal() {
		return nil
	}
	if _, ok := w.policy.scopeTypes[s.Type]; !ok {
		if s.Type == "" {
			return invalidf("scope has an ID but no type")
		}
		types := slices.Sorted(maps.Keys(w.policy.scopeTypes))
		return &UndefinedError{Kind: "scope type", Name: s.Type, Suggestion: suggest(s.Type, types)}
	}
	if err := validateID("scope", s.ID); err != nil {
		return invalidf("%s: %v", s.Type, err)
	}
	return nil
}

// chain returns scope followed by its ancestors, ending with Global. A
// scope whose parent is unknown inherits only from Global (fails closed).
func (w *Warden) chain(ctx context.Context, scope Scope) ([]Scope, error) {
	if scope.IsGlobal() {
		return []Scope{Global}, nil
	}
	chain := make([]Scope, 1, w.policy.maxDepth+2)
	chain[0] = scope
	cur := scope
	// Each step moves to the declared parent type, so the loop is bounded
	// by the depth of the scope type tree (threat model T12).
	for range w.policy.maxDepth {
		want := w.policy.scopeTypes[cur.Type].parent
		if want == "" {
			break
		}
		parent, ok, err := w.parent(ctx, cur)
		if err != nil {
			return nil, fmt.Errorf("wardn: resolving parent of %s: %w", cur, err)
		}
		if !ok {
			break
		}
		if parent.Type != want {
			return nil, fmt.Errorf("%w: parent of %s is %s, but the policy says a %s's parent is a %s",
				ErrInvalidLink, cur, parent, cur.Type, want)
		}
		if err := validateID("scope", parent.ID); err != nil {
			return nil, fmt.Errorf("%w: parent of %s: %w", ErrInvalidLink, cur, err)
		}
		chain = append(chain, parent)
		cur = parent
	}
	return append(chain, Global), nil
}

func (w *Warden) parent(ctx context.Context, child Scope) (Scope, bool, error) {
	m := w.memoFrom(ctx)
	if m != nil {
		m.mu.Lock()
		r, hit := m.parents[child]
		m.mu.Unlock()
		if hit {
			return r.parent, r.ok, nil
		}
	}
	var (
		p   Scope
		ok  bool
		err error
	)
	if w.parentOf != nil {
		p, ok, err = w.parentOf(ctx, child)
	} else {
		p, ok, err = w.store.Parent(ctx, child)
	}
	if err != nil {
		return Scope{}, false, err
	}
	if m != nil {
		m.mu.Lock()
		m.parents[child] = parentResult{parent: p, ok: ok}
		m.mu.Unlock()
	}
	return p, ok, nil
}

func (w *Warden) assignments(ctx context.Context, user string, scope Scope, chain []Scope) ([]Assignment, error) {
	m := w.memoFrom(ctx)
	key := assignmentsKey{user: user, scope: scope}
	if m != nil {
		m.mu.Lock()
		as, hit := m.assignments[key]
		m.mu.Unlock()
		if hit {
			return as, nil
		}
	}
	as, err := w.store.Assignments(ctx, user, slices.Clone(chain))
	if err != nil {
		return nil, fmt.Errorf("wardn: loading assignments: %w", err)
	}
	if m != nil {
		m.mu.Lock()
		m.assignments[key] = as
		m.mu.Unlock()
	}
	return as, nil
}

// customRoles loads custom roles by ID, using the request memo. Missing
// roles map to nil.
func (w *Warden) customRoles(ctx context.Context, ids []string) (map[string]*CustomRole, error) {
	out := make(map[string]*CustomRole, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	m := w.memoFrom(ctx)
	var missing []string
	if m != nil {
		m.mu.Lock()
		for _, id := range ids {
			if r, hit := m.customRoles[id]; hit {
				out[id] = r
			} else {
				missing = append(missing, id)
			}
		}
		m.mu.Unlock()
	} else {
		missing = ids
	}
	if len(missing) == 0 {
		return out, nil
	}
	slices.Sort(missing)
	missing = slices.Compact(missing)
	found, err := w.store.Roles(ctx, missing)
	if err != nil {
		return nil, fmt.Errorf("wardn: loading custom roles: %w", err)
	}
	for i := range found {
		r := found[i]
		if slices.Contains(missing, r.ID) { // never trust a store to filter correctly
			out[r.ID] = &r
		}
	}
	if m != nil {
		m.mu.Lock()
		for _, id := range missing {
			m.customRoles[id] = out[id]
		}
		m.mu.Unlock()
	}
	return out, nil
}

// RolesOf returns the user's assignments that apply at scope right now,
// including those inherited from ancestor scopes and Global, nearest first.
func (w *Warden) RolesOf(ctx context.Context, user string, scope Scope) ([]Assignment, error) {
	gs, err := w.grants(ctx, user, scope)
	if err != nil {
		return nil, err
	}
	out := make([]Assignment, len(gs))
	for i, g := range gs {
		out[i] = g.assignment
	}
	return out, nil
}

// PermissionsOf returns every catalog permission the user holds at scope
// right now, sorted. Frontends use it to show or hide actions.
func (w *Warden) PermissionsOf(ctx context.Context, user string, scope Scope) ([]string, error) {
	gs, err := w.grants(ctx, user, scope)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range w.policy.permList {
		if evaluate(gs, Decision{Permission: p}).Allowed {
			out = append(out, p)
		}
	}
	return out, nil
}
