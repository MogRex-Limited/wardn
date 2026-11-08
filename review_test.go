package wardn

// Regression tests for the M7 internal security review
// (docs/SECURITY_REVIEW.md). Each test is named after the finding it
// proves fixed.

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// F1: revoking a role with deny rules lifts restrictions; it must need the
// power to grant what the role denies.
func TestReview_F1_RevokingDenyRoleNeedsTheDeniedPower(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "aud", "auditor", org1)
	assign(t, w, "aud", "suspended", branch1)
	assign(t, w, "bm", "branch_manager", branch1)
	wantCan(t, w, "aud", "report:export", branch1, false)

	wantEscalation(t, w.Revoke(as("bm"), "aud", "suspended", branch1))
	wantCan(t, w, "aud", "report:export", branch1, false)

	// Someone holding everything the role denies can lift it.
	assign(t, w, "boss", "org_admin", org1)
	if err := w.Revoke(as("boss"), "aud", "suspended", branch1); err != nil {
		t.Fatalf("org admin lifting a suspension: %v", err)
	}
	wantCan(t, w, "aud", "report:export", branch1, true)
}

// F1b: assigning a deny role restricts; a lower admin must not be able to
// lock out a higher one (T04).
func TestReview_F1b_AssigningDenyRoleNeedsTheDeniedPower(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "oa", "org_admin", org1)
	assign(t, w, "bm", "branch_manager", branch1)
	wantEscalation(t, w.Assign(as("bm"), "oa", "suspended", branch1))
	wantCan(t, w, "oa", PermRolesAssign, branch1, true)

	// AssignableRoles no longer offers it to the branch manager.
	roles, err := w.AssignableRoles(as("bm"), branch1)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		if r.ID == "suspended" || r.ID == "ops_admin" {
			t.Errorf("AssignableRoles offers %s to a branch manager", r.ID)
		}
	}
}

// casFailStore fails RevokeRole, after running a reader just before
// DeleteRole.
type cascadeFailStore struct {
	Store
	reader func()
}

func (s *cascadeFailStore) DeleteRole(ctx context.Context, id string) error {
	if s.reader != nil {
		s.reader()
	}
	return s.Store.DeleteRole(ctx, id)
}

func (s *cascadeFailStore) RevokeRole(context.Context, string) error {
	return errors.New("timeout")
}

// F2: a write that fails part-way must still invalidate the cache.
func TestReview_F2_PartialWriteStillInvalidatesCache(t *testing.T) {
	store := &cascadeFailStore{Store: NewMemoryStore()}
	w, _ := newBank(t, func(c *Config) { c.Store = store; c.Cache = NewMemoryCache(); c.CacheTTL = 5 * time.Minute })
	ctx := context.Background()
	r := mustCreate(t, w, org1, RoleSpec{Name: "Approvers", Allow: []string{"loan:approve"}, AssignableAt: []string{"branch"}})
	assign(t, w, "x", r.ID, branch1)
	store.reader = func() { w.Can(ctx, "x", "loan:approve", branch1) }

	if err := w.System().DeleteRole(ctx, r.ID, Cascade()); err == nil {
		t.Fatal("expected the cascade to fail")
	}
	wantCan(t, w, "x", "loan:approve", branch1, false) // the role is gone; no cached copy may grant
}

// F3: the audit log must never show a change that was not written.
func TestReview_F3_AuditNeverRecordsUnwrittenChange(t *testing.T) {
	var events []Event
	fc := &failingCache{Cache: NewMemoryCache()}
	w, _ := newBank(t, func(c *Config) {
		c.Cache = fc
		c.OnChange = func(_ context.Context, e Event) error { events = append(events, e); return nil }
	})
	events = nil
	fc.failIncr = true
	if err := w.System().Assign(context.Background(), "u", "teller", branch1); err == nil {
		t.Fatal("assign succeeded although the cache could not be invalidated")
	}
	for _, e := range events {
		if e.Type == EventAssigned && e.Err == nil {
			t.Fatalf("audit recorded an assignment that was never written: %+v", e)
		}
	}
}

// F4: the sweeper must not delete an assignment re-granted after it read
// the expired one.
func TestReview_F4_SweepKeepsRegrantedAssignment(t *testing.T) {
	var w *Warden
	regranted := false
	w, clock := newBank(t, func(c *Config) {
		c.OnChange = func(ctx context.Context, e Event) error {
			if e.Type == EventExpired && !regranted {
				regranted = true
				// An admin grants a fresh window while the sweep is running.
				return w.System().Assign(ctx, e.User, e.Role, e.Scope, Until(e.At.Add(30*24*time.Hour)))
			}
			return nil
		}
	})
	assign(t, w, "tess", "teller", branch1, Until(t0.Add(time.Hour)))
	clock.Advance(time.Hour)
	if _, err := w.SweepExpired(context.Background(), RemoveExpired()); err != nil {
		t.Fatal(err)
	}
	wantCan(t, w, "tess", "customer:view", branch1, true)
}

// F5: an actor without the management permission learns nothing about a
// role from UpdateRole or DeleteRole.
func TestReview_F5_NoRoleExistenceOracle(t *testing.T) {
	w, _ := newBank(t)
	r := mustCreate(t, w, org1, spec("Hidden Fraud Team", "loan:view"))
	nobody := as("nobody")
	missing := "cr-aaaaaaaaaaaaaaaaaaaaaaaa"

	answers := map[string]string{}
	_, err := w.UpdateRole(nobody, missing, spec("X", "loan:view"), 1)
	answers["update missing"] = err.Error()
	_, err = w.UpdateRole(nobody, r.ID, spec("X", "loan:view"), 1)
	answers["update existing"] = err.Error()
	_, err = w.UpdateRole(nobody, r.ID, spec("X", "loan:view"), 99)
	answers["update existing, wrong version"] = err.Error()
	answers["delete missing"] = errString(w.DeleteRole(nobody, missing))
	answers["delete existing"] = errString(w.DeleteRole(nobody, r.ID))

	want := answers["update missing"]
	for k, v := range answers {
		got := strings.ReplaceAll(v, r.ID, missing)
		if got != want {
			t.Errorf("%s answers %q, but a missing role answers %q: the difference reveals the role", k, v, want)
		}
	}
	if !strings.Contains(want, "role not found") {
		t.Errorf("answer = %q", want)
	}
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// F6: times outside years 1–9999 are rejected; stores cannot represent
// them and could wrap them into the past.
func TestReview_F6_TimesOutOfRangeRejected(t *testing.T) {
	w, _ := newBank(t)
	far := time.Date(300000, 1, 1, 0, 0, 0, 0, time.UTC)
	ancient := time.Date(-5, 1, 1, 0, 0, 0, 0, time.UTC)
	for name, opt := range map[string]AssignOption{"From far future": From(far), "Until far future": Until(far), "From before year 1": From(ancient)} {
		if err := w.System().Assign(context.Background(), "u", "teller", branch1, opt); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := w.System().Assign(context.Background(), "u", "teller", branch1, Until(time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC))); err != nil {
		t.Errorf("year 9999: %v", err)
	}
}

// F7: names that read like system role names are refused.
func TestReview_F7_LookAlikeRoleNames(t *testing.T) {
	w, _ := newBank(t)
	for _, name := range []string{"Super Admin.", "0rg Admin", "Super Admın", "Ｓuper Ａdmin", "ORG-ADMIN!", "Org_Admin"} {
		if _, err := w.System().CreateRole(context.Background(), org1, spec(name, "loan:view")); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
	// Ordinary names that merely contain a system role's words are fine.
	if _, err := w.System().CreateRole(context.Background(), org1, spec("Org Admin Assistant", "loan:view")); err != nil {
		t.Errorf("Org Admin Assistant: %v", err)
	}
}

// F8: audit events tell System() calls apart from a user whose ID is
// "system".
func TestReview_F8_SystemActorIsUnambiguous(t *testing.T) {
	var events []Event
	w, _ := newBank(t, func(c *Config) {
		c.OnChange = func(_ context.Context, e Event) error { events = append(events, e); return nil }
	})
	assign(t, w, "system", "super_admin", Global) // a real user called "system"
	events = nil
	if err := w.Assign(as("system"), "a", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	if err := w.System().Assign(context.Background(), "b", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].System || events[0].Actor != "system" || !events[1].System || events[1].Actor != "" {
		t.Fatalf("events = %+v; the user and System() must be distinguishable", events)
	}
}

// F9: the number of custom roles per owner is bounded.
func TestReview_F9_CustomRolesPerOwnerBounded(t *testing.T) {
	w, _ := newBank(t)
	ctx := context.Background()
	for i := range maxRolesPerOwner {
		if _, err := w.System().CreateRole(ctx, branch1, spec("Role "+itoa(i), "loan:view")); err != nil {
			t.Fatalf("role %d: %v", i, err)
		}
	}
	if _, err := w.System().CreateRole(ctx, branch1, spec("One Too Many", "loan:view")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("role %d: %v", maxRolesPerOwner+1, err)
	}
}

func itoa(i int) string {
	// No letters that fold together as look-alikes (i/l, o/0, s/5, ...).
	const letters = "acdfghjkmnpqruvwxyz"
	s := ""
	for {
		s = string(letters[i%len(letters)]) + s
		i /= len(letters)
		if i == 0 {
			return s
		}
	}
}

// Found by the M8 usability rehearsal: two tenants reusing a scope ID.
func TestThreat_T27_ReusedScopeIDCannotCrossTenants(t *testing.T) {
	w, _ := newBank(t)
	ctx := context.Background()
	lagosCardio := NewScope("branch", "cardiology")
	if err := w.Link(ctx, lagosCardio, region1); err != nil { // tenant o1's "cardiology"
		t.Fatal(err)
	}
	assign(t, w, "admin2", "org_admin", org2)

	// Tenant o2 also calls a branch "cardiology" and links it: refused, not
	// moved under o2's administrators.
	err := w.Link(ctx, lagosCardio, region2)
	if !errors.Is(err, ErrAlreadyLinked) || !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("Link of a reused ID: %v", err)
	}
	wantCan(t, w, "admin2", "loan:approve", lagosCardio, false)
}

func TestLinkIsIdempotentAndQuiet(t *testing.T) {
	var events int
	w, _ := newBank(t, func(c *Config) {
		c.OnChange = func(_ context.Context, e Event) error {
			if e.Type == EventLinked {
				events++
			}
			return nil
		}
	})
	events = 0 // newBank's own links
	ctx := context.Background()
	for range 3 {
		if err := w.Link(ctx, branch1, region1); err != nil {
			t.Fatal(err)
		}
	}
	if events != 0 {
		t.Fatalf("re-linking to the same parent produced %d audit events; want none", events)
	}
}

func TestNowFollowsTheConfiguredClock(t *testing.T) {
	w, clock := newBank(t)
	if !w.Now().Equal(clock.Now()) {
		t.Fatal("Now does not use Config.Clock")
	}
	clock.Advance(time.Hour)
	if !w.Now().Equal(t0.Add(time.Hour)) {
		t.Fatal("Now does not follow the clock")
	}
}

func TestAssignIsQuietWhenNothingChanges(t *testing.T) {
	var events []Event
	w, _ := newBank(t, func(c *Config) {
		c.OnChange = func(_ context.Context, e Event) error { events = append(events, e); return nil }
	})
	ctx := context.Background()
	for range 3 { // e.g. seeding the first admin on every start
		if err := w.System().Assign(ctx, "root", "super_admin", Global); err != nil {
			t.Fatal(err)
		}
	}
	// A different time window is a real change.
	if err := w.System().Assign(ctx, "root", "super_admin", Global, Until(t0.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	var assigned int
	for _, e := range events {
		if e.Type == EventAssigned {
			assigned++
		}
	}
	if assigned != 2 {
		t.Fatalf("%d assignment events, want 2 (the first assignment and the window change)", assigned)
	}
}

// Found in the M9 API review: a move was audited as a plain link, with no
// record of where the scope came from.
func TestMoveIsAuditedWithThePreviousParent(t *testing.T) {
	var events []Event
	w, _ := newBank(t, func(c *Config) {
		c.OnChange = func(_ context.Context, e Event) error { events = append(events, e); return nil }
	})
	ctx := WithUser(context.Background(), "ops")
	events = nil
	if err := w.Move(ctx, branch1, region2); err != nil {
		t.Fatal(err)
	}
	b9 := NewScope("branch", "b9")
	if err := w.Move(ctx, b9, region1); err != nil { // no parent yet: a link
		t.Fatal(err)
	}
	if err := w.Move(ctx, b9, region1); err != nil { // already there: nothing
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("%d events, want 2: %+v", len(events), events)
	}
	if e := events[0]; e.Type != EventMoved || e.Scope != branch1 || e.Parent != region2 || e.PreviousParent != region1 || e.Actor != "ops" {
		t.Errorf("move: %+v", e)
	}
	if e := events[1]; e.Type != EventLinked || e.Scope != b9 || e.Parent != region1 || !e.PreviousParent.IsGlobal() {
		t.Errorf("first move of an unlinked scope: %+v", e)
	}
}

// Found in the M9 API review: Event had no JSON names, unlike every other
// public type, and its error marshalled as {}. Audit trails are written as
// JSON, so these names are part of the stable API.
func TestEventJSONIsStable(t *testing.T) {
	e := Event{
		Type: EventMoved, Actor: "ops", At: t0, Scope: branch1, Parent: region2, PreviousParent: region1,
		Err: errors.New("store unavailable"),
	}
	got, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"type":"scope.moved","actor":"ops","system":false,"at":"2026-11-09T09:00:00Z",` +
		`"scope":{"type":"branch","id":"b1"},"parent":{"type":"region","id":"r2"},` +
		`"previous_parent":{"type":"region","id":"r1"},"error":"store unavailable"}`
	if string(got) != want {
		t.Fatalf("JSON:\n got %s\nwant %s", got, want)
	}
	var back Event
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatal(err)
	}
	if back.Err == nil || back.Err.Error() != e.Err.Error() {
		t.Fatalf("Err round trip: %v", back.Err)
	}
	back.Err, e.Err = nil, nil
	if !reflect.DeepEqual(back, e) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", back, e)
	}

	// A role event carries the role, and no fields of other event types.
	role := CustomRole{ID: "cr-1", Owner: org1, Name: "Desk", Allow: []string{"loan:view"}, Version: 1, CreatedAt: t0, UpdatedAt: t0}
	if got, err = json.Marshal(Event{Type: EventRoleCreated, System: true, Role: "cr-1", Scope: org1, After: &role}); err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{`"user"`, `"parent"`, `"starts_at"`, `"before"`, `"error"`, `"actor"`} {
		if strings.Contains(string(got), absent) {
			t.Errorf("role event has %s: %s", absent, got)
		}
	}
}
