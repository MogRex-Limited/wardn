package wardn

import (
	"context"
	"encoding/json"
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
	EventMoved       EventType = "scope.moved"
)

// Event describes a change to who can do what, for the audit trail
// (Config.OnChange). Fields that do not apply to a type are zero.
//
// Events marshal to JSON with stable snake_case field names, leaving out
// fields that do not apply; Err is written as its message ("error").
type Event struct {
	Type EventType `json:"type"`
	// Actor is the acting user's ID. It is empty when System is true.
	Actor string `json:"actor,omitempty"`
	// System is true for changes made through Warden.System and by the
	// expiry sweeper, where no user is acting.
	System bool      `json:"system"`
	At     time.Time `json:"at,omitzero"`

	User   string `json:"user,omitempty"`  // assignments: whose access changed
	Role   string `json:"role,omitempty"`  // assignments and roles: system role name or custom role ID
	Scope  Scope  `json:"scope,omitzero"`  // assignments: where; roles: the owner; links and moves: the child
	Parent Scope  `json:"parent,omitzero"` // links and moves: the new parent
	// PreviousParent is the parent before a move (EventMoved).
	PreviousParent Scope `json:"previous_parent,omitzero"`

	StartsAt  time.Time `json:"starts_at,omitzero"` // assignments: the time window
	ExpiresAt time.Time `json:"expires_at,omitzero"`

	Before *CustomRole `json:"before,omitempty"` // role updates and deletions
	After  *CustomRole `json:"after,omitempty"`  // role creations and updates

	// Err is set when OnChange is called a second time for the same change
	// because it failed after OnChange approved it. A failed change may
	// have been partly applied (for example, a cascade deletion that deleted
	// the role but not all its assignments); the store is the source of
	// truth. OnChange's return value is ignored on that call.
	Err error `json:"-"`
}

// MarshalJSON writes the event with Err as its message, under "error".
func (e Event) MarshalJSON() ([]byte, error) {
	type plain Event // without methods, so this does not recurse
	out := struct {
		plain
		Error string `json:"error,omitempty"`
	}{plain: plain(e)}
	if e.Err != nil {
		out.Error = e.Err.Error()
	}
	return json.Marshal(out)
}

// UnmarshalJSON reads an event written by MarshalJSON. A recorded error
// comes back as an error with the same message.
func (e *Event) UnmarshalJSON(data []byte) error {
	type plain Event
	var in struct {
		plain
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	*e = Event(in.plain)
	if in.Error != "" {
		e.Err = errors.New(in.Error)
	}
	return nil
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
	pending, inTx := w.pendingFrom(ctx), w.inAppTx(ctx)
	switch {
	case inTx && pending == nil:
		return ErrNoTransaction
	case !inTx && pending != nil:
		return fmt.Errorf("%w: the context from Warden.Transaction carries no transaction for the store", ErrNoTransaction)
	}
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
	// Inside an application transaction, the write becomes visible only at
	// commit, so this waits until the transaction ends.
	var cacheErr error
	if len(counters) > 0 && (pending == nil || !pending.add(counters)) {
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
