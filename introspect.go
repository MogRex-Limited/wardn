package wardn

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
)

// RoleInfo describes a role for admin screens.
type RoleInfo struct {
	ID           string   `json:"id"`   // system role name, or custom role ID
	Name         string   `json:"name"` // display name (the system role name for system roles)
	Description  string   `json:"description"`
	Allow        []string `json:"allow"`
	Deny         []string `json:"deny,omitempty"`          // system roles only
	AssignableAt []string `json:"assignable_at,omitempty"` // empty: anywhere
	Custom       bool     `json:"custom"`
	Owner        Scope    `json:"owner,omitzero"`   // custom roles only
	Version      int      `json:"version,omitzero"` // custom roles only
}

// Roles returns the roles that can be assigned at scope: system roles whose
// assignable_at allows it, and custom roles owned by scope or an ancestor
// that are assignable at its type. System roles come first, then custom
// roles, each sorted by name.
func (w *Warden) Roles(ctx context.Context, scope Scope) ([]RoleInfo, error) {
	if err := w.validateScope(scope); err != nil {
		return nil, err
	}
	var out []RoleInfo
	for _, name := range w.policy.roleNames {
		r := w.policy.roles[name]
		if !r.assignableAtScope(scope) {
			continue
		}
		var assignable []string
		if r.assignableAt != nil {
			assignable = r.assignableList()
		}
		out = append(out, RoleInfo{ID: name, Name: name, Description: r.description,
			Allow: slices.Clone(r.allow), Deny: slices.Clone(r.deny), AssignableAt: assignable})
	}
	chain, err := w.chain(ctx, scope)
	if err != nil {
		return nil, err
	}
	customs, err := w.store.RolesOwnedBy(ctx, chain)
	if err != nil {
		return nil, fmt.Errorf("wardn: listing custom roles: %w", err)
	}
	slices.SortFunc(customs, func(a, b CustomRole) int { return strings.Compare(a.NameKey, b.NameKey) })
	for i := range customs {
		cr := &customs[i]
		if !slices.Contains(chain, cr.Owner) { // never trust a store to filter correctly
			continue
		}
		c := w.policy.compileCustomRole(cr)
		if !c.assignableAtScope(scope) {
			continue
		}
		out = append(out, RoleInfo{ID: cr.ID, Name: cr.Name, Description: cr.Description, Allow: c.allow,
			AssignableAt: slices.Clone(cr.AssignableAt), Custom: true, Owner: cr.Owner, Version: cr.Version})
	}
	return out, nil
}

// AssignableRoles returns the roles the user in ctx may assign at scope:
// those from Roles that pass the escalation guard. Use it to fill the role
// picker in an admin screen, so people only see roles they can grant.
func (w *Warden) AssignableRoles(ctx context.Context, scope Scope) ([]RoleInfo, error) {
	a, err := actorFrom(ctx)
	if err != nil {
		return nil, err
	}
	roles, err := w.Roles(ctx, scope)
	if err != nil {
		return nil, err
	}
	gs, err := w.grants(ctx, a.id, scope)
	if err != nil {
		return nil, err
	}
	if !evaluate(gs, Decision{Permission: PermRolesAssign}).Allowed {
		return nil, nil
	}
	// A role is offered only if the actor holds everything it grants.
	// Deny-only roles (such as "suspended") grant nothing, so they pass.
	return slices.DeleteFunc(roles, func(r RoleInfo) bool {
		return slices.ContainsFunc(r.Allow, func(p string) bool { return !holds(gs, p) })
	}), nil
}

// CustomRole returns a custom role by ID, for example to fill an edit form.
// Pass its Version to UpdateRole.
func (w *Warden) CustomRole(ctx context.Context, id string) (CustomRole, error) {
	r, err := w.loadCustomRole(ctx, id)
	if err != nil {
		return CustomRole{}, err
	}
	return cloneRole(*r), nil
}

// maxMembersPage bounds one page of Members (threat model T23).
const maxMembersPage = 500

// Members returns one page of the assignments made at exactly scope
// (not inherited ones), ordered by user then role, for admin screens.
// Pass "" as cursor for the first page and the returned cursor for the
// next; it is "" after the last page. limit is capped at 500.
//
// Members does not check who is asking: protect the route that exposes it
// with Require.
func (w *Warden) Members(ctx context.Context, scope Scope, cursor string, limit int) ([]Assignment, string, error) {
	if err := w.validateScope(scope); err != nil {
		return nil, "", err
	}
	if limit <= 0 || limit > maxMembersPage {
		limit = maxMembersPage
	}
	page, next, err := w.store.Members(ctx, scope, cursor, limit)
	if err != nil {
		return nil, "", fmt.Errorf("wardn: listing members: %w", err)
	}
	return slices.DeleteFunc(page, func(a Assignment) bool { return a.Scope != scope }), next, nil
}

// SweepOption configures SweepExpired.
type SweepOption func(*sweepOptions)

type sweepOptions struct{ remove bool }

// RemoveExpired makes SweepExpired also delete the expired assignments it
// reports. Without it they stay (harmlessly, since they grant nothing).
func RemoveExpired() SweepOption {
	return func(o *sweepOptions) { o.remove = true }
}

const sweepBatch = 500

// SweepExpired reports every assignment that has expired since the last
// sweep through Config.OnChange (as EventExpired), for the audit trail, and
// returns how many it reported. Expired assignments stop working on their
// own (evaluation rule 7); the sweep only records that they did. If
// OnChange fails, the sweep stops and those assignments are reported again
// next time.
func (w *Warden) SweepExpired(ctx context.Context, opts ...SweepOption) (int, error) {
	var o sweepOptions
	for _, opt := range opts {
		opt(&o)
	}
	now := w.clock.Now()
	total := 0
	for range 10_000 { // a bound, in case a store never marks anything
		batch, err := w.store.ExpiredUnreported(ctx, now, sweepBatch)
		if err != nil {
			return total, fmt.Errorf("wardn: finding expired assignments: %w", err)
		}
		for _, a := range batch {
			if w.onChange != nil {
				ev := Event{Type: EventExpired, Actor: SystemActor, At: now, User: a.User, Role: a.Role,
					Scope: a.Scope, StartsAt: a.StartsAt, ExpiresAt: a.ExpiresAt}
				if err := w.onChange(ctx, ev); err != nil {
					return total, fmt.Errorf("%w: %w", ErrAuditRejected, err)
				}
			}
		}
		if err := w.store.MarkExpiryReported(ctx, batch); err != nil {
			return total, fmt.Errorf("wardn: marking expired assignments: %w", err)
		}
		if o.remove {
			for _, a := range batch {
				// Removing an expired assignment changes no decision, but it
				// changes cached data, so it goes through the same path as
				// any other change (minus the audit event, already sent).
				ev := Event{Type: EventExpired, Scope: a.Scope}
				counters, err := w.countersFor(ctx, ev)
				if err != nil {
					return total, err
				}
				if err := w.store.Revoke(ctx, a.User, a.Role, a.Scope); err != nil {
					return total, fmt.Errorf("wardn: removing expired assignment: %w", err)
				}
				if len(counters) > 0 {
					if err := w.cache.Incr(ctx, counters); err != nil {
						return total, fmt.Errorf("%w: %w", ErrCacheInvalidation, err)
					}
				}
			}
		}
		total += len(batch)
		if len(batch) < sweepBatch {
			return total, nil
		}
	}
	return total, fmt.Errorf("wardn: stopped sweeping after %d assignments; the store may not be marking them", total)
}

// RunExpiry calls SweepExpired every interval until ctx is done, passing
// errors to onError (which may be nil). Run it in its own goroutine, on one
// instance or on all: reporting is idempotent.
func (w *Warden) RunExpiry(ctx context.Context, interval time.Duration, onError func(error), opts ...SweepOption) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := w.SweepExpired(ctx, opts...); err != nil && onError != nil && ctx.Err() == nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
