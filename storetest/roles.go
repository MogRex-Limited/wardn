package storetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/MogRex-Limited/wardn"
)

var created = time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)

func customRole(id string, owner wardn.Scope, name string) wardn.CustomRole {
	return wardn.CustomRole{
		ID: id, Owner: owner, Name: name, NameKey: name, Description: "desc of " + name,
		Allow: []string{"loan:view", "customer:*"}, AssignableAt: []string{"branch", "organisation"},
		Version: 1, CreatedAt: created, UpdatedAt: created,
	}
}

func getRole(t *testing.T, s wardn.Store, id string) (wardn.CustomRole, bool) {
	t.Helper()
	rs, err := s.Roles(context.Background(), []string{id})
	if err != nil {
		t.Fatalf("Roles(%s): %v", id, err)
	}
	if len(rs) == 0 {
		return wardn.CustomRole{}, false
	}
	return rs[0], true
}

func sameRole(a, b wardn.CustomRole) bool {
	return a.ID == b.ID && a.Owner == b.Owner && a.Name == b.Name && a.NameKey == b.NameKey &&
		a.Description == b.Description && slices.Equal(a.Allow, b.Allow) &&
		slices.Equal(a.AssignableAt, b.AssignableAt) && a.Version == b.Version &&
		!a.CreatedAt.Before(b.CreatedAt.Add(-time.Millisecond)) && !a.CreatedAt.After(b.CreatedAt.Add(time.Millisecond))
}

func testRoleRoundTrip(t *testing.T, s wardn.Store) {
	ctx := context.Background()
	r := customRole("cr-one", org, "Senior Teller")
	r.Name, r.NameKey = "Ọya Café — Lagos/Abuja", "ọya café — lagos/abuja"
	r.Allow = []string{"z:last", "a:first", "loan:*"} // order is preserved
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, ok := getRole(t, s, "cr-one")
	if !ok || !sameRole(got, r) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, r)
	}
	// Missing IDs are omitted; only requested IDs are returned.
	if err := s.CreateRole(ctx, customRole("cr-two", org, "Two")); err != nil {
		t.Fatal(err)
	}
	rs, err := s.Roles(ctx, []string{"cr-missing", "cr-two"})
	if err != nil || len(rs) != 1 || rs[0].ID != "cr-two" {
		t.Fatalf("Roles(missing, two) = %+v, %v", rs, err)
	}
	if rs, err := s.Roles(ctx, nil); err != nil || len(rs) != 0 {
		t.Fatalf("Roles(nil) = %+v, %v", rs, err)
	}
	// Global owner round-trips.
	if err := s.CreateRole(ctx, customRole("cr-global", wardn.Global, "Global")); err != nil {
		t.Fatal(err)
	}
	if got, _ := getRole(t, s, "cr-global"); !got.Owner.IsGlobal() {
		t.Fatalf("global owner = %v", got.Owner)
	}
}

func testRoleNameUnique(t *testing.T, s wardn.Store) {
	ctx := context.Background()
	if err := s.CreateRole(ctx, customRole("cr-a", org, "desk")); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRole(ctx, customRole("cr-b", org, "desk")); !errors.Is(err, wardn.ErrRoleNameTaken) {
		t.Fatalf("same owner and name key: %v, want ErrRoleNameTaken", err)
	}
	// Other owners, including one with the same ID in another type, may reuse it.
	for i, owner := range []wardn.Scope{wardn.NewScope("organisation", "o2"), wardn.NewScope("branch", "o1"), wardn.Global} {
		if err := s.CreateRole(ctx, customRole(fmt.Sprintf("cr-c%d", i), owner, "desk")); err != nil {
			t.Fatalf("owner %s: %v", owner, err)
		}
	}
	// Uniqueness is exact on the key wardn supplies (it normalises; stores must not).
	if err := s.CreateRole(ctx, customRole("cr-d", org, "Desk")); err != nil {
		t.Fatalf("different key: %v", err)
	}
}

// testRoleNameUniqueConcurrent: the uniqueness check must be atomic.
func testRoleNameUniqueConcurrent(t *testing.T, s wardn.Store) {
	ctx := context.Background()
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.CreateRole(ctx, customRole(fmt.Sprintf("cr-race%d", i), org, "contested"))
		}()
	}
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, wardn.ErrRoleNameTaken):
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d concurrent creations of the same name succeeded, want exactly 1", ok)
	}
}

func testRoleUpdate(t *testing.T, s wardn.Store) {
	ctx := context.Background()
	r := customRole("cr-u", org, "before")
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRole(ctx, customRole("cr-other", org, "taken")); err != nil {
		t.Fatal(err)
	}
	next := r
	next.Name, next.NameKey, next.Description = "after", "after", "new"
	next.Allow = []string{"loan:create"}
	next.AssignableAt = []string{"branch"}
	next.Version = 2
	next.UpdatedAt = created.Add(time.Hour)
	next.Owner = wardn.Global // owner and creation time are immutable
	next.CreatedAt = created.Add(time.Hour)

	if err := s.UpdateRole(ctx, next, 5); !errors.Is(err, wardn.ErrConflict) {
		t.Fatalf("wrong expected version: %v, want ErrConflict", err)
	}
	if err := s.UpdateRole(ctx, next, 1); err != nil {
		t.Fatal(err)
	}
	got, _ := getRole(t, s, "cr-u")
	want := next
	want.Owner, want.CreatedAt = org, created
	if !sameRole(got, want) {
		t.Fatalf("after update:\n got %+v\nwant %+v", got, want)
	}
	// The old name is free again; names of other roles are not.
	if err := s.CreateRole(ctx, customRole("cr-reuse", org, "before")); err != nil {
		t.Fatalf("old name not released: %v", err)
	}
	clash := got
	clash.Name, clash.NameKey, clash.Version = "taken", "taken", 3
	if err := s.UpdateRole(ctx, clash, 2); !errors.Is(err, wardn.ErrRoleNameTaken) {
		t.Fatalf("rename onto another role's name: %v, want ErrRoleNameTaken", err)
	}
	missing := customRole("cr-nope", org, "nope")
	if err := s.UpdateRole(ctx, missing, 1); !errors.Is(err, wardn.ErrRoleNotFound) {
		t.Fatalf("update missing: %v, want ErrRoleNotFound", err)
	}
}

// testRoleUpdateConcurrent: optimistic concurrency must be atomic
// (threat model T22).
func testRoleUpdateConcurrent(t *testing.T, s wardn.Store) {
	ctx := context.Background()
	if err := s.CreateRole(ctx, customRole("cr-cas", org, "cas")); err != nil {
		t.Fatal(err)
	}
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := customRole("cr-cas", org, "cas")
			r.Description, r.Version = fmt.Sprintf("writer %d", i), 2
			errs <- s.UpdateRole(ctx, r, 1)
		}()
	}
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, wardn.ErrConflict):
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d concurrent updates from version 1 succeeded, want exactly 1", ok)
	}
}

func testRoleDeleteAndOwners(t *testing.T, s wardn.Store) {
	ctx := context.Background()
	o2 := wardn.NewScope("organisation", "o2")
	for _, r := range []wardn.CustomRole{
		customRole("cr-1", org, "one"), customRole("cr-2", org, "two"),
		customRole("cr-3", o2, "three"), customRole("cr-4", wardn.NewScope("region", "o1"), "four"),
	} {
		if err := s.CreateRole(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	owned := func(owners ...wardn.Scope) []string {
		rs, err := s.RolesOwnedBy(ctx, owners)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, len(rs))
		for i, r := range rs {
			ids[i] = r.ID
		}
		slices.Sort(ids)
		return ids
	}
	if got := owned(org); !slices.Equal(got, []string{"cr-1", "cr-2"}) {
		t.Fatalf("RolesOwnedBy(o1) = %v", got)
	}
	if got := owned(org, o2); !slices.Equal(got, []string{"cr-1", "cr-2", "cr-3"}) {
		t.Fatalf("RolesOwnedBy(o1, o2) = %v", got)
	}
	if got := owned(); len(got) != 0 {
		t.Fatalf("RolesOwnedBy() = %v", got)
	}
	if err := s.DeleteRole(ctx, "cr-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRole(ctx, "cr-1"); err != nil {
		t.Fatalf("deleting twice: %v", err)
	}
	if got := owned(org); !slices.Equal(got, []string{"cr-2"}) {
		t.Fatalf("after delete: %v", got)
	}
	// The deleted role's name is free again.
	if err := s.CreateRole(ctx, customRole("cr-5", org, "one")); err != nil {
		t.Fatalf("name not released by delete: %v", err)
	}
}

func testRoleInUseAndRevokeRole(t *testing.T, s wardn.Store) {
	ctx := context.Background()
	inUse := func(role string) bool {
		t.Helper()
		ok, err := s.RoleInUse(ctx, role)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if inUse("cr-x") {
		t.Fatal("unused role reported in use")
	}
	mustAssign(t, s, wardn.Assignment{User: "u1", Role: "cr-x", Scope: branch})
	mustAssign(t, s, wardn.Assignment{User: "u2", Role: "cr-x", Scope: org})
	mustAssign(t, s, wardn.Assignment{User: "u1", Role: "cr-xy", Scope: branch})
	if !inUse("cr-x") {
		t.Fatal("assigned role not in use")
	}
	if err := s.RevokeRole(ctx, "cr-x"); err != nil {
		t.Fatal(err)
	}
	if inUse("cr-x") {
		t.Fatal("RevokeRole left assignments")
	}
	wantRoles(t, read(t, s, "u1", branch), "cr-xy@branch:b1") // exact match only
}

func testMembers(t *testing.T, s wardn.Store) {
	ctx := context.Background()
	users := []string{"carol", "alice", "bob", "Bob", "dave"}
	for _, u := range users {
		mustAssign(t, s, wardn.Assignment{User: u, Role: "teller", Scope: branch})
	}
	mustAssign(t, s, wardn.Assignment{User: "alice", Role: "auditor", Scope: branch})
	mustAssign(t, s, wardn.Assignment{User: "zed", Role: "teller", Scope: other})
	mustAssign(t, s, wardn.Assignment{User: "yan", Role: "teller", Scope: wardn.NewScope("region", "b1")})

	for _, limit := range []int{1, 2, 3, 100} {
		var got []string
		cursor := ""
		for pages := 0; ; pages++ {
			page, next, err := s.Members(ctx, branch, cursor, limit)
			if err != nil {
				t.Fatal(err)
			}
			if len(page) > limit {
				t.Fatalf("limit %d: page of %d", limit, len(page))
			}
			for _, a := range page {
				if a.Scope != branch {
					t.Fatalf("Members returned another scope: %+v", a)
				}
				got = append(got, a.User+"/"+a.Role)
			}
			if next == "" {
				break
			}
			if pages > 20 {
				t.Fatalf("limit %d: pagination does not end", limit)
			}
			cursor = next
		}
		// Byte order: uppercase sorts before lowercase.
		want := []string{"Bob/teller", "alice/auditor", "alice/teller", "bob/teller", "carol/teller", "dave/teller"}
		if !slices.Equal(got, want) {
			t.Fatalf("limit %d: Members = %v\nwant %v", limit, got, want)
		}
	}
	if page, next, err := s.Members(ctx, wardn.NewScope("branch", "empty"), "", 10); err != nil || len(page) != 0 || next != "" {
		t.Fatalf("empty scope: %v %q %v", page, next, err)
	}
}

func testExpiry(t *testing.T, s wardn.Store) {
	ctx := context.Background()
	t0 := time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)
	mustAssign(t, s, wardn.Assignment{User: "a", Role: "r", Scope: branch, ExpiresAt: t0})
	mustAssign(t, s, wardn.Assignment{User: "b", Role: "r", Scope: branch, ExpiresAt: t0.Add(time.Hour)})
	mustAssign(t, s, wardn.Assignment{User: "c", Role: "r", Scope: branch}) // permanent
	mustAssign(t, s, wardn.Assignment{User: "d", Role: "r", Scope: branch, ExpiresAt: t0.Add(-time.Hour)})

	expired := func(at time.Time, limit int) []string {
		t.Helper()
		as, err := s.ExpiredUnreported(ctx, at, limit)
		if err != nil {
			t.Fatal(err)
		}
		users := make([]string, len(as))
		for i, a := range as {
			users[i] = a.User
		}
		slices.Sort(users)
		return users
	}
	if got := expired(t0, 10); !slices.Equal(got, []string{"a", "d"}) { // ExpiresAt <= t: inclusive
		t.Fatalf("expired at t0 = %v", got)
	}
	if got := expired(t0, 1); len(got) != 1 {
		t.Fatalf("limit 1 returned %v", got)
	}
	as, _ := s.ExpiredUnreported(ctx, t0, 10)
	if err := s.MarkExpiryReported(ctx, as); err != nil {
		t.Fatal(err)
	}
	if got := expired(t0, 10); len(got) != 0 {
		t.Fatalf("reported assignments returned again: %v", got)
	}
	// Assigning again gives a new window, to be reported again when it ends.
	mustAssign(t, s, wardn.Assignment{User: "a", Role: "r", Scope: branch, ExpiresAt: t0.Add(time.Minute)})
	if got := expired(t0.Add(2*time.Hour), 10); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("after re-assign = %v", got)
	}
	// A mark made with a stale window must not hide the new window.
	stale := wardn.Assignment{User: "b", Role: "r", Scope: branch, ExpiresAt: t0.Add(time.Hour)}
	mustAssign(t, s, wardn.Assignment{User: "b", Role: "r", Scope: branch, ExpiresAt: t0.Add(90 * time.Minute)})
	if err := s.MarkExpiryReported(ctx, []wardn.Assignment{stale}); err != nil {
		t.Fatal(err)
	}
	if got := expired(t0.Add(2*time.Hour), 10); !slices.Contains(got, "b") {
		t.Fatalf("stale mark hid a newer window: %v", got)
	}
	if err := s.MarkExpiryReported(ctx, nil); err != nil {
		t.Fatalf("marking nothing: %v", err)
	}

	// RevokeExpired removes only the window it was given.
	mustAssign(t, s, wardn.Assignment{User: "e", Role: "r", Scope: branch, ExpiresAt: t0})
	if err := s.RevokeExpired(ctx, wardn.Assignment{User: "e", Role: "r", Scope: branch, ExpiresAt: t0.Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, s, "e", branch); len(got) != 1 {
		t.Fatalf("RevokeExpired with another window removed the assignment: %+v", got)
	}
	if err := s.RevokeExpired(ctx, wardn.Assignment{User: "e", Role: "r", Scope: branch, ExpiresAt: t0}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, s, "e", branch); len(got) != 0 {
		t.Fatalf("RevokeExpired with the same window left it: %+v", got)
	}
	if err := s.RevokeExpired(ctx, wardn.Assignment{User: "nobody", Role: "r", Scope: branch, ExpiresAt: t0}); err != nil {
		t.Fatalf("RevokeExpired of a missing assignment: %v", err)
	}
}

func testRoleCanceledContext(t *testing.T, s wardn.Store) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := customRole("cr-c", org, "c")
	checks := map[string]error{
		"CreateRole":         s.CreateRole(ctx, r),
		"UpdateRole":         s.UpdateRole(ctx, r, 1),
		"DeleteRole":         s.DeleteRole(ctx, "cr-c"),
		"RevokeRole":         s.RevokeRole(ctx, "cr-c"),
		"MarkExpiryReported": s.MarkExpiryReported(ctx, []wardn.Assignment{{User: "u", Role: "r", Scope: branch}}),
		"RevokeExpired":      s.RevokeExpired(ctx, wardn.Assignment{User: "u", Role: "r", Scope: branch}),
	}
	_, checks["Roles"] = s.Roles(ctx, []string{"cr-c"})
	_, checks["RolesOwnedBy"] = s.RolesOwnedBy(ctx, []wardn.Scope{org})
	_, checks["RoleInUse"] = s.RoleInUse(ctx, "cr-c")
	_, _, checks["Members"] = s.Members(ctx, branch, "", 10)
	_, checks["ExpiredUnreported"] = s.ExpiredUnreported(ctx, time.Now(), 10)
	for name, err := range checks {
		if err == nil {
			t.Errorf("%s ignored a canceled context", name)
		}
	}
	if _, ok := getRole(t, s, "cr-c"); ok {
		t.Error("role created despite canceled context")
	}
}
