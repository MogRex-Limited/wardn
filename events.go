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
	Type  EventType
	Actor string // the acting user's ID, or SystemActor
	At    time.Time

	User   string // assignments: whose access changed
	Role   string // assignments and roles: system role name or custom role ID
	Scope  Scope  // assignments: where; roles: the owner; links: the child
	Parent Scope  // links: the new parent

	StartsAt  time.Time // assignments: the time window
	ExpiresAt time.Time

	Before *CustomRole // role updates and deletions
	After  *CustomRole // role creations and updates

	// Err is set when OnChange is called a second time for the same change
	// because the store failed after OnChange approved it: the change did
	// not happen. OnChange's return value is ignored on that call.
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
	if w.onChange != nil {
		if err := w.onChange(ctx, ev); err != nil {
			return fmt.Errorf("%w: %w", ErrAuditRejected, err)
		}
	}
	// Invalidate before writing (if that fails, nothing changes) and again
	// after, so an entry cached from the old data by a concurrent reader
	// between the two is never reachable.
	if len(counters) > 0 {
		if err := w.cache.Incr(ctx, counters); err != nil {
			return fmt.Errorf("wardn: invalidating cache before %s: %w", ev.Type, err)
		}
	}
	if err := write(); err != nil {
		if w.onChange != nil {
			ev.Err = err
			_ = w.onChange(ctx, ev)
		}
		if errors.Is(err, ErrRoleNameTaken) || errors.Is(err, ErrConflict) || errors.Is(err, ErrRoleNotFound) {
			return err
		}
		return fmt.Errorf("wardn: saving %s: %w", ev.Type, err)
	}
	w.memoFrom(ctx).forget()
	if len(counters) > 0 {
		if err := w.cache.Incr(ctx, counters); err != nil {
			return fmt.Errorf("%w (%s): %w", ErrCacheInvalidation, ev.Type, err)
		}
	}
	return nil
}
