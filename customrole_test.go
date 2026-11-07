package wardn

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// as returns a context acting as user, the way an HTTP handler's context
// carries the signed-in user.
func as(user string) context.Context {
	return WithUser(context.Background(), user)
}

func spec(name string, allow ...string) RoleSpec {
	return RoleSpec{Name: name, Allow: allow}
}

func mustCreate(t *testing.T, w *Warden, owner Scope, s RoleSpec) CustomRole {
	t.Helper()
	r, err := w.System().CreateRole(context.Background(), owner, s)
	if err != nil {
		t.Fatalf("CreateRole(%q): %v", s.Name, err)
	}
	return r
}

func TestValidateRoleName(t *testing.T) {
	valid := []string{"Senior Teller", "Loan Officer (Lagos)", "Ops/IT", "R&D", "Café Manager", "Ọya", "Менеджер", "2nd Line Support", "Bank's Auditor", strings.Repeat("a", maxRoleNameLen)}
	for _, n := range valid {
		if err := validateRoleName(n); err != nil {
			t.Errorf("%q rejected: %v", n, err)
		}
	}
	invalid := map[string]string{
		"":                                    "empty",
		" Teller":                             "leading",
		"Teller ":                             "trailing",
		"Senior  Teller":                      "repeated spaces",
		"Аdmin":                               "mixes", // Cyrillic А + Latin
		"Super\u200bAdmin":                    "not allowed",
		"Admin\u202e":                         "not allowed",
		"Cafe\u0301":                          "combining mark",
		"Tab\tName":                           "not allowed",
		"<script>":                            "not allowed",
		"123":                                 "must contain a letter",
		strings.Repeat("a", maxRoleNameLen+1): "longer than",
		"bad\xff":                             "UTF-8",
	}
	for n, want := range invalid {
		err := validateRoleName(n)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want error containing %q", n, err, want)
		}
	}
	if roleNameKey("Org  _Admin-") != roleNameKey("org admin") || roleNameKey("ORG-ADMIN") != roleNameKey("org_admin") || roleNameKey("Desk") == roleNameKey("Disk") {
		t.Error("roleNameKey does not normalise")
	}
}

func TestCreateRoleAndEvaluate(t *testing.T) {
	w, _ := newBank(t)
	senior := mustCreate(t, w, org1, RoleSpec{
		Name: "Senior Teller", Description: "Tellers who approve loans",
		Allow: []string{"customer:view", "loan:*"}, AssignableAt: []string{"branch"},
	})
	if !strings.HasPrefix(senior.ID, "cr-") || senior.Version != 1 || senior.Owner != org1 || senior.NameKey != roleNameKey("Senior Teller") || senior.CreatedAt.IsZero() {
		t.Fatalf("created role = %+v", senior)
	}

	assign(t, w, "sam", senior.ID, branch1)
	wantCan(t, w, "sam", "loan:approve", branch1, true)
	wantCan(t, w, "sam", "customer:edit", branch1, false)
	wantCan(t, w, "sam", "loan:approve", branch2, false) // other organisation

	d, _ := w.Check(context.Background(), "sam", "loan:approve", branch1)
	if d.Role != senior.ID || !strings.Contains(d.Reason, `"Senior Teller" (`+senior.ID+`)`) {
		t.Errorf("decision does not name the custom role: %+v", d)
	}

	// Default assignable_at: the owner's type.
	orgRole := mustCreate(t, w, org1, spec("Org Viewer", "customer:view"))
	if !slices.Equal(orgRole.AssignableAt, []string{"organisation"}) {
		t.Errorf("default AssignableAt = %v", orgRole.AssignableAt)
	}
	if err := w.System().Assign(context.Background(), "u", orgRole.ID, branch1); !errors.Is(err, ErrNotAssignable) {
		t.Errorf("assigning an org-level role at a branch: %v", err)
	}

	// A custom role can only be assigned inside its owner's subtree.
	if err := w.System().Assign(context.Background(), "u", senior.ID, branch2); !errors.Is(err, ErrNotAssignable) {
		t.Errorf("assigning outside the owner: %v", err)
	}
	if err := w.System().Assign(context.Background(), "u", "cr-doesnotexist", branch1); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("unknown custom role: %v", err)
	}

	// Global custom roles are visible everywhere.
	g := mustCreate(t, w, Global, RoleSpec{Name: "Report Reader", Allow: []string{"report:export"}, AssignableAt: []string{"branch", "global"}})
	assign(t, w, "rae", g.ID, branch2)
	wantCan(t, w, "rae", "report:export", branch2, true)
}

func TestCustomRoleOutsideOwnerSubtreeIgnored(t *testing.T) {
	// An assignment that somehow sits outside the owner's subtree (written
	// directly to the store, or left behind after a branch moved) grants
	// nothing.
	w, _ := newBank(t)
	r := mustCreate(t, w, org1, RoleSpec{Name: "X", Allow: []string{"loan:view"}, AssignableAt: []string{"branch"}})
	assign(t, w, "u", r.ID, branch1)
	wantCan(t, w, "u", "loan:view", branch1, true)
	if err := w.Link(context.Background(), region1, org2); err != nil { // move the region to another organisation
		t.Fatal(err)
	}
	wantCan(t, w, "u", "loan:view", branch1, false)
}

func TestCreateRoleValidation(t *testing.T) {
	w, _ := newBank(t)
	sys := w.System()
	ctx := context.Background()
	var ue *UndefinedError
	cases := []struct {
		name  string
		owner Scope
		spec  RoleSpec
		check func(error) bool
	}{
		{"deny", org1, RoleSpec{Name: "X", Allow: []string{"loan:view"}, Deny: []string{"loan:approve"}}, func(e error) bool {
			return errors.Is(e, ErrInvalidInput) && strings.Contains(e.Error(), "cannot contain deny")
		}},
		{"empty", org1, spec("X"), func(e error) bool { return errors.Is(e, ErrInvalidInput) }},
		{"bad pattern", org1, spec("X", "loan approve"), func(e error) bool { return errors.Is(e, ErrInvalidInput) }},
		{"typo", org1, spec("X", "loan:aprove"), func(e error) bool { return errors.As(e, &ue) && ue.Suggestion == "loan:approve" }},
		{"wildcard matches nothing", org1, spec("X", "audit:*"), func(e error) bool { return strings.Contains(e.Error(), "matches no permission") }},
		{"duplicate", org1, spec("X", "loan:view", "loan:view"), func(e error) bool { return strings.Contains(e.Error(), "more than once") }},
		{"too many", org1, RoleSpec{Name: "X", Allow: slices.Repeat([]string{"loan:view"}, maxRolePatterns+1)}, func(e error) bool { return strings.Contains(e.Error(), "more than") }},
		{"bad name", org1, spec("Аdmin", "loan:view"), func(e error) bool { return errors.Is(e, ErrInvalidInput) }},
		{"bad description", org1, RoleSpec{Name: "X", Description: "a\x00b", Allow: []string{"loan:view"}}, func(e error) bool { return errors.Is(e, ErrInvalidInput) }},
		{"assignable above owner", branch1, RoleSpec{Name: "X", Allow: []string{"loan:view"}, AssignableAt: []string{"organisation"}}, func(e error) bool { return errors.Is(e, ErrNotAssignable) }},
		{"assignable at global from org", org1, RoleSpec{Name: "X", Allow: []string{"loan:view"}, AssignableAt: []string{"global"}}, func(e error) bool { return errors.Is(e, ErrNotAssignable) }},
		{"assignable undeclared type", Global, RoleSpec{Name: "X", Allow: []string{"loan:view"}, AssignableAt: []string{"brnch"}}, func(e error) bool { return errors.Is(e, ErrNotAssignable) }},
		{"same as system role", org1, spec("Org-Admin", "loan:view"), func(e error) bool {
			return errors.Is(e, ErrRoleNameTaken) && strings.Contains(e.Error(), `system role "org_admin"`)
		}},
		{"undefined owner type", NewScope("nope", "x"), spec("X", "loan:view"), func(e error) bool { return errors.As(e, &ue) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := sys.CreateRole(ctx, c.owner, c.spec); err == nil || !c.check(err) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestRoleNameUniqueness(t *testing.T) {
	w, _ := newBank(t)
	sys := w.System()
	ctx := context.Background()
	mustCreate(t, w, org1, spec("Loan Desk", "loan:view"))
	for name, owner := range map[string]Scope{
		"loan desk":  org1,    // same owner, different case
		"Loan_Desk":  region1, // descendant of the owner: both visible there
		"LOAN-DESK ": org1,
	} {
		if _, err := sys.CreateRole(ctx, owner, spec(strings.TrimSpace(name), "loan:view")); !errors.Is(err, ErrRoleNameTaken) {
			t.Errorf("%q at %s: %v, want ErrRoleNameTaken", name, owner, err)
		}
	}
	// Another tenant may use the same name.
	mustCreate(t, w, org2, spec("Loan Desk", "loan:view"))
}

func TestUpdateRole(t *testing.T) {
	w, _ := newBank(t)
	ctx := context.Background()
	r := mustCreate(t, w, org1, RoleSpec{Name: "Desk", Allow: []string{"loan:view"}, AssignableAt: []string{"branch"}})
	assign(t, w, "u", r.ID, branch1)
	wantCan(t, w, "u", "loan:create", branch1, false)

	updated, err := w.System().UpdateRole(ctx, r.ID, RoleSpec{Name: "Loan Desk", Allow: []string{"loan:view", "loan:create"}, AssignableAt: []string{"branch"}}, r.Version)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version != 2 || updated.Name != "Loan Desk" || updated.ID != r.ID || !updated.CreatedAt.Equal(r.CreatedAt) {
		t.Fatalf("updated = %+v", updated)
	}
	wantCan(t, w, "u", "loan:create", branch1, true) // every holder changes at once

	got, err := w.CustomRole(ctx, r.ID)
	if err != nil || got.Version != 2 || got.Name != "Loan Desk" {
		t.Fatalf("CustomRole = %+v, %v", got, err)
	}
	if _, err := w.CustomRole(ctx, "teller"); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("CustomRole on a system role: %v", err)
	}
	if _, err := w.System().UpdateRole(ctx, "cr-missing", spec("X", "loan:view"), 1); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("update missing role: %v", err)
	}
}

func TestDeleteRole(t *testing.T) {
	w, _ := newBank(t)
	ctx := context.Background()
	r := mustCreate(t, w, org1, RoleSpec{Name: "Desk", Allow: []string{"loan:view"}, AssignableAt: []string{"branch"}})
	assign(t, w, "u", r.ID, branch1)

	if err := w.System().DeleteRole(ctx, r.ID); !errors.Is(err, ErrRoleInUse) {
		t.Fatalf("delete in-use role: %v", err)
	}
	wantCan(t, w, "u", "loan:view", branch1, true)
	if err := w.System().DeleteRole(ctx, r.ID, Cascade()); err != nil {
		t.Fatal(err)
	}
	wantCan(t, w, "u", "loan:view", branch1, false)
	if inUse, _ := w.store.RoleInUse(ctx, r.ID); inUse {
		t.Error("cascade left assignments behind")
	}
	if err := w.System().DeleteRole(ctx, r.ID); err != nil {
		t.Errorf("deleting twice: %v", err)
	}
	// An unused role needs no cascade.
	r2 := mustCreate(t, w, org1, spec("Idle", "loan:view"))
	if err := w.System().DeleteRole(ctx, r2.ID); err != nil {
		t.Errorf("delete unused: %v", err)
	}
}

func TestCustomRoleLosesRemovedPermissions(t *testing.T) {
	store := NewMemoryStore()
	w1, _ := newBank(t, func(c *Config) { c.Store = store })
	r := mustCreate(t, w1, Global, RoleSpec{Name: "Exporter", Allow: []string{"report:export", "loan:view"}, AssignableAt: []string{"global"}})
	assign(t, w1, "u", r.ID, Global)

	// Redeploy without report:export in the catalog.
	p := mustParse(t, bankYAML)
	delete(p.Permissions, "report:export")
	r2 := p.Roles["auditor"]
	r2.Allow = []string{"customer:view", "loan:view"}
	p.Roles["auditor"] = r2
	w2, err := New(Config{Policy: p, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if !w2.Can(context.Background(), "u", "loan:view", Global) {
		t.Error("remaining permission lost")
	}
}

func TestGuardedCallsNeedAnActor(t *testing.T) {
	w, _ := newBank(t)
	ctx := context.Background() // no WithUser
	checks := map[string]error{}
	checks["Assign"] = w.Assign(ctx, "u", "teller", branch1)
	checks["Revoke"] = w.Revoke(ctx, "u", "teller", branch1)
	_, checks["CreateRole"] = w.CreateRole(ctx, org1, spec("X", "loan:view"))
	_, checks["UpdateRole"] = w.UpdateRole(ctx, "cr-x", spec("X", "loan:view"), 1)
	checks["DeleteRole"] = w.DeleteRole(ctx, "cr-x")
	_, checks["AssignableRoles"] = w.AssignableRoles(ctx, branch1)
	for name, err := range checks {
		if !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s without an actor: %v", name, err)
		}
	}
	if err := w.Assign(WithUser(ctx, "bad\x00"), "u", "teller", branch1); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("invalid actor: %v", err)
	}
}

func TestRoles(t *testing.T) {
	w, _ := newBank(t)
	mustCreate(t, w, org1, RoleSpec{Name: "Zeta Desk", Allow: []string{"loan:view"}, AssignableAt: []string{"branch"}})
	mustCreate(t, w, org1, RoleSpec{Name: "Alpha Desk", Allow: []string{"loan:view"}, AssignableAt: []string{"branch"}})
	mustCreate(t, w, org1, spec("Org Only", "loan:view"))                                                               // not assignable at branches
	mustCreate(t, w, org2, RoleSpec{Name: "Elsewhere", Allow: []string{"loan:view"}, AssignableAt: []string{"branch"}}) // other tenant

	roles, err := w.Roles(context.Background(), branch1)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range roles {
		names = append(names, r.Name)
	}
	want := []string{"auditor", "branch_manager", "loan_officer", "ops_admin", "suspended", "teller", "Alpha Desk", "Zeta Desk"}
	if !slices.Equal(names, want) {
		t.Fatalf("Roles(branch1) = %v\nwant %v", names, want)
	}
	if !roles[6].Custom || roles[6].Owner != org1 || roles[6].Version != 1 || roles[0].Custom {
		t.Errorf("role info = %+v / %+v", roles[6], roles[0])
	}
	if _, err := w.Roles(context.Background(), NewScope("nope", "x")); err == nil {
		t.Error("invalid scope accepted")
	}
}

func TestAssignableRoles(t *testing.T) {
	w, _ := newBank(t)
	assign(t, w, "boss", "branch_manager", branch1)
	mustCreate(t, w, org1, RoleSpec{Name: "Viewer", Allow: []string{"loan:view"}, AssignableAt: []string{"branch"}})
	mustCreate(t, w, org1, RoleSpec{Name: "Exporter", Allow: []string{"report:export"}, AssignableAt: []string{"branch"}})

	roles, err := w.AssignableRoles(as("boss"), branch1)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range roles {
		names = append(names, r.Name)
	}
	// branch_manager can grant what it holds. Not "suspended": it denies
	// everything, and the manager does not hold everything (review F1b).
	want := []string{"branch_manager", "loan_officer", "teller", "Viewer"}
	if !slices.Equal(names, want) {
		t.Fatalf("AssignableRoles = %v, want %v", names, want)
	}
	if roles, err := w.AssignableRoles(as("nobody"), branch1); err != nil || len(roles) != 0 {
		t.Fatalf("user without wardn:roles.assign: %v, %v", roles, err)
	}
}

func TestMembers(t *testing.T) {
	w, _ := newBank(t)
	for _, u := range []string{"carol", "alice", "bob", "dave", "erin"} {
		assign(t, w, u, "teller", branch1)
	}
	assign(t, w, "alice", "auditor", branch1)
	assign(t, w, "zed", "teller", NewScope("branch", "b9")) // other scope
	assign(t, w, "olga", "org_admin", org1)                 // inherited, not listed

	var got []string
	cursor := ""
	for pages := 0; ; pages++ {
		page, next, err := w.Members(context.Background(), branch1, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range page {
			got = append(got, a.User+"/"+a.Role)
		}
		if next == "" {
			break
		}
		if pages > 10 {
			t.Fatal("pagination does not end")
		}
		cursor = next
	}
	want := []string{"alice/auditor", "alice/teller", "bob/teller", "carol/teller", "dave/teller", "erin/teller"}
	if !slices.Equal(got, want) {
		t.Fatalf("Members = %v, want %v", got, want)
	}
	if _, _, err := w.Members(context.Background(), branch1, "%%%", 2); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("bad cursor: %v", err)
	}
	if _, _, err := w.Members(context.Background(), NewScope("nope", "x"), "", 2); err == nil {
		t.Error("invalid scope accepted")
	}
}

func TestOnChange(t *testing.T) {
	var events []Event
	var veto error
	w, clock := newBank(t, func(c *Config) {
		c.OnChange = func(_ context.Context, e Event) error {
			events = append(events, e)
			return veto
		}
	})
	events = nil // ignore links made by newBank
	assign(t, w, "root", "super_admin", Global)
	ctx := as("root")

	if err := w.Assign(ctx, "u", "teller", branch1, Until(t0.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	r, err := w.CreateRole(ctx, org1, spec("Desk", "loan:view"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.UpdateRole(ctx, r.ID, spec("Desk 2", "loan:view"), 1); err != nil {
		t.Fatal(err)
	}
	if err := w.DeleteRole(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.Revoke(ctx, "u", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	if err := w.Link(ctx, NewScope("branch", "b5"), region1); err != nil {
		t.Fatal(err)
	}
	types := make([]EventType, len(events))
	for i, e := range events {
		types[i] = e.Type
	}
	want := []EventType{EventAssigned, EventAssigned, EventRoleCreated, EventRoleUpdated, EventRoleDeleted, EventRevoked, EventLinked}
	if !slices.Equal(types, want) {
		t.Fatalf("events = %v\nwant %v", types, want)
	}
	if e := events[0]; !e.System || e.Actor != "" || e.User != "root" {
		t.Errorf("System() event = %+v", e)
	}
	if e := events[1]; e.Actor != "root" || e.User != "u" || e.Role != "teller" || e.Scope != branch1 || !e.ExpiresAt.Equal(t0.Add(time.Hour)) || !e.At.Equal(clock.Now()) {
		t.Errorf("assign event = %+v", e)
	}
	if e := events[3]; e.Before == nil || e.After == nil || e.Before.Name != "Desk" || e.After.Name != "Desk 2" {
		t.Errorf("update event = %+v", e)
	}
	if e := events[6]; e.Scope != NewScope("branch", "b5") || e.Parent != region1 || e.Actor != "root" {
		t.Errorf("link event = %+v", e)
	}
}

func TestThreat_T21_AuditVetoBlocksChange(t *testing.T) {
	auditDown := errors.New("audit log unavailable")
	var down bool
	w, _ := newBank(t, func(c *Config) {
		c.OnChange = func(context.Context, Event) error {
			if down {
				return auditDown
			}
			return nil
		}
	})
	down = true // after setup: links are audited too
	err := w.System().Assign(context.Background(), "u", "teller", branch1)
	if !errors.Is(err, ErrAuditRejected) || !errors.Is(err, auditDown) {
		t.Fatalf("err = %v", err)
	}
	wantCan(t, w, "u", "loan:create", branch1, false) // nothing changed
	if _, err := w.System().CreateRole(context.Background(), org1, spec("X", "loan:view")); !errors.Is(err, ErrAuditRejected) {
		t.Fatalf("CreateRole: %v", err)
	}
	if roles, _ := w.store.RolesOwnedBy(context.Background(), []Scope{org1}); len(roles) != 0 {
		t.Fatal("role created despite audit veto")
	}
}

func TestThreat_T21_FailedChangeIsReported(t *testing.T) {
	var events []Event
	fs := &faultyStore{Store: NewMemoryStore()}
	w, _ := newBank(t, func(c *Config) {
		c.Store = fs
		c.OnChange = func(_ context.Context, e Event) error { events = append(events, e); return nil }
	})
	events = nil
	fs.failAssign = true
	if err := w.System().Assign(context.Background(), "u", "teller", branch1); !errors.Is(err, errStore) {
		t.Fatalf("err = %v", err)
	}
	if len(events) != 2 || events[0].Err != nil || !errors.Is(events[1].Err, errStore) {
		t.Fatalf("events = %+v; want the change, then the same change with Err set", events)
	}
}

func TestSweepExpired(t *testing.T) {
	var expired []Event
	w, clock := newBank(t, func(c *Config) {
		c.OnChange = func(_ context.Context, e Event) error {
			if e.Type == EventExpired {
				expired = append(expired, e)
			}
			return nil
		}
	})
	ctx := context.Background()
	assign(t, w, "a", "teller", branch1, Until(t0.Add(time.Hour)))
	assign(t, w, "b", "teller", branch1, Until(t0.Add(2*time.Hour)))
	assign(t, w, "c", "teller", branch1) // permanent

	if n, err := w.SweepExpired(ctx); err != nil || n != 0 {
		t.Fatalf("before expiry: %d, %v", n, err)
	}
	clock.Advance(time.Hour)
	if n, err := w.SweepExpired(ctx); err != nil || n != 1 || len(expired) != 1 || expired[0].User != "a" || !expired[0].System {
		t.Fatalf("first sweep: %d, %v, %+v", n, err, expired)
	}
	if n, _ := w.SweepExpired(ctx); n != 0 {
		t.Fatalf("reported twice: %d", n)
	}

	// Assigning again starts a new window, which is reported again when it ends.
	assign(t, w, "a", "teller", branch1, Until(clock.Now().Add(time.Hour)))
	clock.Advance(2 * time.Hour)
	if n, _ := w.SweepExpired(ctx, RemoveExpired()); n != 2 {
		t.Fatalf("second sweep reported %d, want 2 (a again, and b)", n)
	}
	if as, _ := w.store.Assignments(ctx, "b", []Scope{branch1}); len(as) != 0 {
		t.Error("RemoveExpired left the assignment")
	}
	if as, _ := w.store.Assignments(ctx, "c", []Scope{branch1}); len(as) != 1 {
		t.Error("permanent assignment removed")
	}
}

func TestSweepStopsWhenAuditFails(t *testing.T) {
	fail := true
	w, clock := newBank(t, func(c *Config) {
		c.OnChange = func(_ context.Context, e Event) error {
			if e.Type == EventExpired && fail {
				return errors.New("audit down")
			}
			return nil
		}
	})
	assign(t, w, "a", "teller", branch1, Until(t0.Add(time.Hour)))
	clock.Advance(time.Hour)
	if _, err := w.SweepExpired(context.Background()); !errors.Is(err, ErrAuditRejected) {
		t.Fatalf("err = %v", err)
	}
	fail = false
	if n, err := w.SweepExpired(context.Background()); err != nil || n != 1 {
		t.Fatalf("retry: %d, %v (the expiry must be reported once audit recovers)", n, err)
	}
}

func TestRunExpiry(t *testing.T) {
	reported := make(chan Event, 1)
	w, clock := newBank(t, func(c *Config) {
		c.OnChange = func(_ context.Context, e Event) error {
			if e.Type == EventExpired {
				reported <- e
			}
			return nil
		}
	})
	assign(t, w, "a", "teller", branch1, Until(t0.Add(time.Hour)))
	clock.Advance(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.RunExpiry(ctx, time.Millisecond, nil); close(done) }()
	select {
	case e := <-reported:
		if e.User != "a" {
			t.Errorf("event = %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunExpiry did not sweep")
	}
	cancel()
	<-done
}

func TestHoldsAndCovers(t *testing.T) {
	g := func(allow, deny []string) []grant {
		return []grant{{role: &compiledRole{name: "r", allow: allow, deny: deny}}}
	}
	cases := []struct {
		allow, deny []string
		pattern     string
		want        bool
	}{
		{[]string{"*"}, nil, "loan:*", true},
		{[]string{"*"}, nil, "*", true},
		{[]string{"loan:*"}, nil, "loan:*", true},
		{[]string{"loan:*"}, nil, "loan:approve", true},
		{[]string{"loan:*"}, nil, "*", false},
		{[]string{"loan:approve", "loan:create", "loan:view"}, nil, "loan:*", false}, // T06: future loan:... permissions
		{[]string{"*"}, []string{"loan:approve"}, "loan:*", false},                   // a deny inside the wildcard
		{[]string{"*"}, []string{"loan:approve"}, "*", false},
		{[]string{"*"}, []string{"loan:approve"}, "customer:*", true},
		{[]string{"*"}, []string{"loan:*"}, "loan:approve", false},
		{[]string{"loan:approve:*"}, nil, "loan:*", false},
		{[]string{"loan:*"}, nil, "loans:*", false},
	}
	for _, c := range cases {
		if got := holds(g(c.allow, c.deny), c.pattern); got != c.want {
			t.Errorf("allow %v deny %v holds %q = %v, want %v", c.allow, c.deny, c.pattern, got, c.want)
		}
	}
}

// leakyMembersStore returns members of other scopes too.
type leakyMembersStore struct{ *MemoryStore }

func (l leakyMembersStore) Members(ctx context.Context, scope Scope, cursor string, limit int) ([]Assignment, string, error) {
	page, next, err := l.MemoryStore.Members(ctx, scope, cursor, limit)
	return append(page, Assignment{User: "intruder", Role: "super_admin", Scope: branch2}), next, err
}

func TestMembersIgnoresOtherScopesFromStore(t *testing.T) {
	w, _ := newBank(t, func(c *Config) { c.Store = leakyMembersStore{NewMemoryStore()} })
	assign(t, w, "tia", "teller", branch1)
	page, _, err := w.Members(context.Background(), branch1, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].User != "tia" {
		t.Fatalf("Members = %+v; another scope's member leaked through", page)
	}
}
