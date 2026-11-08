package wardn_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/wardntest"
)

// The promises in docs/STABILITY.md that the Go compiler cannot check:
// names that end up in other systems (audit logs, JSON APIs, databases,
// HTTP clients). scripts/apicheck.sh checks the Go API itself. A failure
// here after v1.0.0 means a breaking change: restore the old value instead
// of updating the test.

func TestStable_EventTypes(t *testing.T) {
	for got, want := range map[wardn.EventType]string{
		wardn.EventAssigned:    "assignment.created",
		wardn.EventRevoked:     "assignment.revoked",
		wardn.EventExpired:     "assignment.expired",
		wardn.EventRoleCreated: "role.created",
		wardn.EventRoleUpdated: "role.updated",
		wardn.EventRoleDeleted: "role.deleted",
		wardn.EventLinked:      "scope.linked",
		wardn.EventMoved:       "scope.moved",
	} {
		if string(got) != want {
			t.Errorf("event type %q, want %q", got, want)
		}
	}
}

func TestStable_BuiltInPermissions(t *testing.T) {
	if wardn.PermRolesAssign != "wardn:roles.assign" || wardn.PermRolesManage != "wardn:roles.manage" {
		t.Errorf("built-in permissions: %q, %q", wardn.PermRolesAssign, wardn.PermRolesManage)
	}
}

func TestStable_JSON(t *testing.T) {
	t0 := time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)
	branch := wardn.NewScope("branch", "b1")
	org := wardn.NewScope("organisation", "o1")
	for _, c := range []struct {
		name string
		v    any
		want string
	}{
		{"Scope", branch, `{"type":"branch","id":"b1"}`},
		{"Assignment", wardn.Assignment{User: "u", Role: "teller", Scope: branch, StartsAt: t0, ExpiresAt: t0.Add(time.Hour)},
			`{"user":"u","role":"teller","scope":{"type":"branch","id":"b1"},"starts_at":"2026-11-09T09:00:00Z","expires_at":"2026-11-09T10:00:00Z"}`},
		{"Assignment, permanent", wardn.Assignment{User: "u", Role: "teller", Scope: branch},
			`{"user":"u","role":"teller","scope":{"type":"branch","id":"b1"}}`},
		{"Decision", wardn.Decision{Allowed: true, User: "u", Permission: "loan:view", Scope: branch, Role: "teller", At: branch, Rule: "loan:*", Reason: "r"},
			`{"allowed":true,"user":"u","permission":"loan:view","scope":{"type":"branch","id":"b1"},"role":"teller","at":{"type":"branch","id":"b1"},"rule":"loan:*","reason":"r"}`},
		{"Permission", wardn.Permission{Name: "loan:view", Description: "View loans"},
			`{"name":"loan:view","description":"View loans"}`},
		{"RoleSpec", wardn.RoleSpec{Name: "Desk", Description: "d", Allow: []string{"loan:view"}, AssignableAt: []string{"branch"}},
			`{"name":"Desk","description":"d","allow":["loan:view"],"assignable_at":["branch"]}`},
		{"CustomRole", wardn.CustomRole{ID: "cr-1", Owner: org, Name: "Desk", NameKey: "desk", Description: "d", Allow: []string{"loan:view"},
			AssignableAt: []string{"branch"}, Version: 2, CreatedAt: t0, UpdatedAt: t0},
			`{"id":"cr-1","owner":{"type":"organisation","id":"o1"},"name":"Desk","name_key":"desk","description":"d","allow":["loan:view"],` +
				`"assignable_at":["branch"],"version":2,"created_at":"2026-11-09T09:00:00Z","updated_at":"2026-11-09T09:00:00Z"}`},
		{"RoleInfo", wardn.RoleInfo{ID: "cr-1", Name: "Desk", Description: "d", Allow: []string{"loan:view"}, AssignableAt: []string{"branch"},
			Custom: true, Owner: org, Version: 2},
			`{"id":"cr-1","name":"Desk","description":"d","allow":["loan:view"],"assignable_at":["branch"],"custom":true,"owner":{"type":"organisation","id":"o1"},"version":2}`},
		{"Event", wardn.Event{Type: wardn.EventAssigned, Actor: "mgr", At: t0, User: "u", Role: "teller", Scope: branch, ExpiresAt: t0.Add(time.Hour)},
			`{"type":"assignment.created","actor":"mgr","system":false,"at":"2026-11-09T09:00:00Z","user":"u","role":"teller",` +
				`"scope":{"type":"branch","id":"b1"},"expires_at":"2026-11-09T10:00:00Z"}`},
	} {
		got, err := json.Marshal(c.v)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != c.want {
			t.Errorf("%s JSON:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
}

func TestStable_HTTPStatus(t *testing.T) {
	for err, want := range map[error]int{
		nil:                             http.StatusOK,
		wardn.ErrUnauthenticated:        http.StatusUnauthorized,
		wardn.ErrDenied:                 http.StatusForbidden,
		wardn.ErrEscalation:             http.StatusForbidden,
		wardn.ErrInvalidInput:           http.StatusBadRequest,
		wardn.ErrNotAssignable:          http.StatusBadRequest,
		wardn.ErrRoleNotFound:           http.StatusNotFound,
		wardn.ErrConflict:               http.StatusConflict,
		wardn.ErrRoleNameTaken:          http.StatusConflict,
		wardn.ErrRoleInUse:              http.StatusConflict,
		wardn.ErrAlreadyLinked:          http.StatusConflict,
		wardn.ErrInvalidLink:            http.StatusInternalServerError,
		wardn.ErrLinksExternal:          http.StatusInternalServerError,
		wardn.ErrAuditRejected:          http.StatusInternalServerError,
		wardn.ErrCacheInvalidation:      http.StatusInternalServerError,
		errors.New("store unavailable"): http.StatusInternalServerError,
	} {
		// Wrapped, as wardn returns them.
		wrapped := err
		if err != nil {
			wrapped = fmt.Errorf("context: %w", err)
		}
		if got := wardn.HTTPStatus(wrapped); got != want {
			t.Errorf("HTTPStatus(%v) = %d, want %d", err, got, want)
		}
	}
}

// The default responses of the HTTP middleware, which API clients may parse.
func TestStable_DefaultErrorResponses(t *testing.T) {
	policy, err := wardn.ParsePolicy([]byte("permissions:\n  doc:read: Read documents\nroles:\n  reader: [doc:read]\n"), "stable.yaml")
	if err != nil {
		t.Fatal(err)
	}
	w := wardntest.NewFromPolicy(t, policy)
	h := w.Require("doc:read")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, c := range []struct {
		user   string
		status int
		body   string
	}{
		{"", http.StatusUnauthorized, `{"error":"unauthenticated"}` + "\n"},
		{"nobody", http.StatusForbidden, `{"error":"forbidden"}` + "\n"},
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		if c.user != "" {
			req = req.WithContext(wardn.WithUser(req.Context(), c.user))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.status || rec.Body.String() != c.body || rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
			t.Errorf("user %q: %d %q (%s)", c.user, rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
		}
	}
}
