package wardn

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// The escalation guard (DESIGN.md §6.2): nobody can create, edit, assign or
// revoke a role containing permissions they do not hold.
//
// branch_manager (assignable at branches) holds customer:view,
// customer:edit, loan:*, wardn:roles.assign and wardn:roles.manage.

func wantDenied(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied (missing management permission)", err)
	}
}

func wantEscalation(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrEscalation) {
		t.Fatalf("err = %v, want ErrEscalation", err)
	}
}

func managerBank(t *testing.T) *Warden {
	t.Helper()
	w, _ := newBank(t)
	assign(t, w, "mgr", "branch_manager", branch1)
	return w
}

func TestThreat_T03_CannotGrantMoreThanYouHold(t *testing.T) {
	w := managerBank(t)
	ctx := as("mgr")

	// Allowed: roles within the manager's own power, in the manager's branch.
	if err := w.Assign(ctx, "tia", "teller", branch1); err != nil {
		t.Fatalf("assign teller: %v", err)
	}
	if _, err := w.CreateRole(ctx, branch1, spec("Loan Desk", "loan:*", "customer:view")); err != nil {
		t.Fatalf("create role within power: %v", err)
	}

	// Escalation: ops_admin includes report:export, which the manager lacks.
	wantEscalation(t, w.Assign(ctx, "tia", "ops_admin", branch1))
	wantEscalation(t, w.Assign(ctx, "mgr", "auditor", branch1)) // not even to themselves
	_, err := w.CreateRole(ctx, branch1, spec("Exporter", "report:export"))
	wantEscalation(t, err)
	_, err = w.CreateRole(ctx, branch1, spec("Everything", "*"))
	wantEscalation(t, err)
	wantCan(t, w, "tia", "report:export", branch1, false)

	// No management permission elsewhere: another branch, the parent org.
	wantDenied(t, w.Assign(ctx, "tia", "teller", branch2))
	_, err = w.CreateRole(ctx, org1, spec("Org Thing", "loan:view"))
	wantDenied(t, err)

	// A user without wardn:roles.assign cannot assign anything.
	assign(t, w, "tia", "loan_officer", branch1)
	wantDenied(t, w.Assign(as("tia"), "x", "teller", branch1))
}

func TestThreat_T03_DenialRevealsNothingAboutRoles(t *testing.T) {
	w, _ := newBank(t)
	// Without wardn:roles.assign, an existing and a non-existent role give
	// the same answer.
	r := mustCreate(t, w, org1, RoleSpec{Name: "Real", Allow: []string{"loan:view"}, AssignableAt: []string{"branch"}})
	wantDenied(t, w.Assign(as("nobody"), "u", r.ID, branch1))
	wantDenied(t, w.Assign(as("nobody"), "u", "cr-doesnotexist", branch1))
}

func TestThreat_T04_CannotRevokeHigherAdmin(t *testing.T) {
	w := managerBank(t)
	ctx := as("mgr")
	assign(t, w, "boss", "org_admin", org1)
	assign(t, w, "ops", "ops_admin", branch1)
	assign(t, w, "tia", "teller", branch1)

	wantDenied(t, w.Revoke(ctx, "boss", "org_admin", org1)) // no assign permission at org1
	wantEscalation(t, w.Revoke(ctx, "ops", "ops_admin", branch1))
	wantCan(t, w, "ops", "report:export", branch1, true)

	if err := w.Revoke(ctx, "tia", "teller", branch1); err != nil {
		t.Fatalf("revoke teller: %v", err)
	}
	// A leftover assignment of a role that no longer exists grants nothing,
	// so it can be cleaned up with wardn:roles.assign alone.
	if err := w.store.Assign(context.Background(), Assignment{User: "old", Role: "retired_role", Scope: branch1}); err != nil {
		t.Fatal(err)
	}
	if err := w.Revoke(ctx, "old", "retired_role", branch1); err != nil {
		t.Fatalf("revoke dangling: %v", err)
	}

	// Editing or deleting a role the manager could not have granted is
	// refused too (the mirror of T04 for roles).
	strong := mustCreate(t, w, branch1, spec("Strong", "report:export", "loan:view"))
	_, err := w.UpdateRole(ctx, strong.ID, spec("Strong", "loan:view"), strong.Version)
	wantEscalation(t, err)
	wantEscalation(t, w.DeleteRole(ctx, strong.ID))
}

func TestThreat_T05_CannotEscalateThroughOwnRole(t *testing.T) {
	w := managerBank(t)
	ctx := as("mgr")
	mine, err := w.CreateRole(ctx, branch1, spec("Mine", "loan:view"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Assign(ctx, "mgr", mine.ID, branch1); err != nil {
		t.Fatal(err)
	}
	// Editing a role you hold cannot add what you lack.
	_, err = w.UpdateRole(ctx, mine.ID, spec("Mine", "loan:view", "report:export"), mine.Version)
	wantEscalation(t, err)
	wantCan(t, w, "mgr", "report:export", branch1, false)
	// Adding what you already hold is fine.
	if _, err := w.UpdateRole(ctx, mine.ID, spec("Mine", "loan:view", "customer:edit"), mine.Version); err != nil {
		t.Fatalf("update within power: %v", err)
	}
}

func TestThreat_T06_WildcardsNeedTheWholeWildcard(t *testing.T) {
	w, _ := newBank(t)
	// An actor holding every current loan permission, one by one.
	lead := mustCreate(t, w, branch1, RoleSpec{Name: "Loan Lead", AssignableAt: []string{"branch"},
		Allow: []string{"loan:create", "loan:view", "loan:approve", PermRolesManage, PermRolesAssign}})
	assign(t, w, "lead", lead.ID, branch1)
	ctx := as("lead")

	_, err := w.CreateRole(ctx, branch1, spec("All Loans", "loan:*"))
	wantEscalation(t, err) // loan:* would also grant future loan permissions
	if _, err := w.CreateRole(ctx, branch1, spec("Loans", "loan:create", "loan:view", "loan:approve")); err != nil {
		t.Fatalf("explicit permissions: %v", err)
	}

	// An actor with "*" but a deny inside the wildcard.
	assign(t, w, "ops", "ops_admin", org1) // * except loan:approve
	ctx = as("ops")
	_, err = w.CreateRole(ctx, org1, spec("All Loans", "loan:*"))
	wantEscalation(t, err)
	_, err = w.CreateRole(ctx, org1, spec("Everything", "*"))
	wantEscalation(t, err)
	if _, err := w.CreateRole(ctx, org1, spec("Customers", "customer:*")); err != nil {
		t.Fatalf("wildcard clear of the deny: %v", err)
	}
	wantEscalation(t, w.Assign(ctx, "x", "loan_officer", branch1)) // loan_officer is loan:*
}

func TestThreat_T15_RoleNameSpoofingRejected(t *testing.T) {
	w, _ := newBank(t)
	for _, name := range []string{
		"Super Admin",       // looks like the system role super_admin
		"SUPER_ADMIN",       //
		"Ѕuper Admin",       // Cyrillic Ѕ
		"Super\u200bAdmin",  // zero-width space
		"Super Admin\u202e", // right-to-left override
		"Supe\u0301r Admin", // combining mark
		"Super  Admin",      // double space
	} {
		if _, err := w.System().CreateRole(context.Background(), org1, spec(name, "loan:view")); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
}

func TestThreat_T22_ConcurrentEditsDetected(t *testing.T) {
	w, _ := newBank(t)
	r := mustCreate(t, w, org1, spec("Desk", "loan:view"))
	ctx := context.Background()

	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := range 8 {
		wg.Go(func() {
			_, err := w.System().UpdateRole(ctx, r.ID, spec("Desk", "loan:view", []string{"loan:create", "customer:view"}[i%2]), r.Version)
			results <- err
		})
	}
	wg.Wait()
	close(results)
	ok, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 || conflicts != 7 {
		t.Fatalf("%d updates succeeded and %d conflicted; want exactly 1 and 7", ok, conflicts)
	}
	if _, err := w.System().UpdateRole(ctx, r.ID, spec("Desk", "loan:view"), r.Version); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale version: %v", err)
	}
}
