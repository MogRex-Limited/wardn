package wardn

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// System performs management operations without the escalation guard, for
// code that has no human actor: seeding the first administrator, data
// migrations and background jobs. Calls to it should stand out in code
// review. Obtain one with Warden.System.
type System struct {
	w *Warden
}

// System returns the unguarded management handle. Use it only where no
// user is acting; requests made on behalf of a user go through the guarded
// methods (coming with custom roles in a later release).
func (w *Warden) System() *System {
	return &System{w: w}
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

// Assign gives user the system role at scope. Assigning a role the user
// already holds there replaces its time window.
func (s *System) Assign(ctx context.Context, user, role string, scope Scope, opts ...AssignOption) error {
	w := s.w
	if err := validateID("user", user); err != nil {
		return invalidf("%v", err)
	}
	r := w.policy.roles[role]
	if r == nil {
		return &UndefinedError{Kind: "role", Name: role, Suggestion: suggest(role, w.policy.roleNames)}
	}
	if err := w.validateScope(scope); err != nil {
		return err
	}
	if !r.assignableAtScope(scope) {
		return fmt.Errorf("%w: role %q cannot be assigned at %s; it is assignable at: %s",
			ErrNotAssignable, role, scope, strings.Join(r.assignableList(), ", "))
	}

	a := Assignment{User: user, Role: role, Scope: scope}
	for _, opt := range opts {
		opt(&a)
	}
	if !a.StartsAt.IsZero() && !a.ExpiresAt.IsZero() && !a.ExpiresAt.After(a.StartsAt) {
		return invalidf("time window ends (%s) before it starts (%s)", a.ExpiresAt.Format(time.RFC3339), a.StartsAt.Format(time.RFC3339))
	}
	if !a.ExpiresAt.IsZero() && !a.ExpiresAt.After(w.clock.Now()) {
		return invalidf("assignment would already be expired (%s)", a.ExpiresAt.Format(time.RFC3339))
	}

	if err := w.store.Assign(ctx, a); err != nil {
		return fmt.Errorf("wardn: saving assignment: %w", err)
	}
	w.memoFrom(ctx).forget()
	return nil
}

// Revoke removes role from user at scope. Revoking an assignment that does
// not exist is not an error, and roles no longer in the policy can still be
// revoked, so stale assignments can be cleaned up.
func (s *System) Revoke(ctx context.Context, user, role string, scope Scope) error {
	w := s.w
	if err := validateID("user", user); err != nil {
		return invalidf("%v", err)
	}
	if err := validateID("role", role); err != nil {
		return invalidf("%v", err)
	}
	if err := w.validateScope(scope); err != nil {
		return err
	}
	if err := w.store.Revoke(ctx, user, role, scope); err != nil {
		return fmt.Errorf("wardn: revoking assignment: %w", err)
	}
	w.memoFrom(ctx).forget()
	return nil
}

// Link records that parent is the parent of child, so roles assigned at
// parent (and its ancestors) apply in child. Linking again replaces the
// parent. The parent's type must be the one the policy declares for child.
//
// Link is plumbing for the application's backend, called when it creates or
// moves an entity. Never expose it directly to end users: whoever controls
// links controls inheritance (threat model T11).
func (w *Warden) Link(ctx context.Context, child, parent Scope) error {
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
	if err := w.store.Link(ctx, child, parent); err != nil {
		return fmt.Errorf("wardn: saving link: %w", err)
	}
	w.memoFrom(ctx).forget()
	return nil
}
