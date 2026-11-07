package wardn

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// EventType names a kind of change.
type EventType string

// Event types.
const (
	EventAssigned    EventType = "assignment.created"
	EventRevoked     EventType = "assignment.revoked"
	EventExpired     EventType = "assignment.expired"
	EventRoleCreated EventType = "role.created"
	EventRoleUpdated EventType = "role.updated"
	EventRoleDeleted EventType = "role.deleted"
	EventLinked      EventType = "scope.linked"
)

// Event describes a change to who can do what, for the audit trail
// (Config.OnChange). Fields that do not apply to a type are zero.
type Event struct {
	Type EventType
	// Actor is the acting user's ID. It is empty when System is true.
	Actor string
	// System is true for changes made through Warden.System and by the
	// expiry sweeper, where no user is acting.
	System bool
	At     time.Time

	User   string // assignments: whose access changed
	Role   string // assignments and roles: system role name or custom role ID
	Scope  Scope  // assignments: where; roles: the owner; links: the child
	Parent Scope  // links: the new parent

	StartsAt  time.Time // assignments: the time window
	ExpiresAt time.Time

	Before *CustomRole // role updates and deletions
	After  *CustomRole // role creations and updates

	// Err is set when OnChange is called a second time for the same change
	// because it failed after OnChange approved it. A failed change may
	// have been partly applied (for example, a cascade deletion that deleted
	// the role but not all its assignments); the store is the source of
	// truth. OnChange's return value is ignored on that call.
	Err error
}

// ErrAuditRejected wraps an error returned by Config.OnChange, which stops
// the change (fail closed).
var ErrAuditRejected = errors.New("wardn: the audit hook rejected the change")

// change records ev and then applies write. The audit hook runs first and
// can veto the change, so nothing changes without being recorded (threat
// model T21). If the write then fails, the hook is told, so the audit trail
// shows that the change did not happen.
func (w *Warden) change(ctx context.Context, ev Event, write func() error) error {
	ev.At = w.clock.Now()
	counters, err := w.countersFor(ctx, ev)
	if err != nil {
		return err
	}
	// Invalidate before writing, so that if invalidation fails nothing
	// changes. This happens before the audit hook, so the hook never
	// records a change that is then abandoned (security review F3).
	if len(counters) > 0 {
		if err := w.cache.Incr(ctx, counters); err != nil {
			return fmt.Errorf("wardn: invalidating cache before %s: %w", ev.Type, err)
		}
	}
	if w.onChange != nil {
		if err := w.onChange(ctx, ev); err != nil {
			return fmt.Errorf("%w: %w", ErrAuditRejected, err)
		}
	}
	writeErr := write()
	w.memoFrom(ctx).forget()
	// Invalidate again after writing, so an entry a concurrent reader cached
	// from the old data in between is never reachable. This runs even if the
	// write failed: it may have been partly applied (security review F2).
	var cacheErr error
	if len(counters) > 0 {
		if err := w.cache.Incr(ctx, counters); err != nil {
			cacheErr = fmt.Errorf("%w (%s): %w", ErrCacheInvalidation, ev.Type, err)
		}
	}
	if writeErr != nil {
		if w.onChange != nil {
			ev.Err = writeErr
			_ = w.onChange(ctx, ev)
		}
		if errors.Is(writeErr, ErrRoleNameTaken) || errors.Is(writeErr, ErrConflict) || errors.Is(writeErr, ErrRoleNotFound) {
			return errors.Join(writeErr, cacheErr)
		}
		return errors.Join(fmt.Errorf("wardn: saving %s: %w", ev.Type, writeErr), cacheErr)
	}
	return cacheErr
}
