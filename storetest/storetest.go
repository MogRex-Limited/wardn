// Package storetest is the conformance suite for wardn.Store
// implementations, and their benchmark suite (Bench). A store that passes
// the conformance suite behaves correctly and securely with wardn:
//
//	func TestMyStore(t *testing.T) {
//		storetest.Run(t, func(t *testing.T) wardn.Store {
//			return mystore.New(...) // a new, empty store
//		})
//	}
package storetest

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MogRex-Limited/wardn"
)

// Run runs the conformance suite. newStore must return a new, empty store
// each time it is called; it may use t for cleanup.
func Run(t *testing.T, newStore func(t *testing.T) wardn.Store) {
	t.Helper()
	tests := []struct {
		name string
		fn   func(t *testing.T, s wardn.Store)
	}{
		{"AssignAndRead", testAssignAndRead},
		{"AssignReplacesTimeWindow", testAssignReplaces},
		{"Revoke", testRevoke},
		{"FiltersByUser", testFiltersByUser},
		{"FiltersByScope", testFiltersByScope},
		{"GlobalScope", testGlobalScope},
		{"NoScopesReturnsNothing", testNoScopes},
		{"ExactIdentity", testExactIdentity},
		{"HostileAndLongIDs", testHostileIDs},
		{"TimeRoundTrip", testTimeRoundTrip},
		{"Links", testLinks},
		{"ReturnedDataIsACopy", testReturnedCopy},
		{"CanceledContext", testCanceledContext},
		{"Concurrency", testConcurrency},
		{"Members", testMembers},
		{"Expiry", testExpiry},
		{"RoleRoundTrip", testRoleRoundTrip},
		{"RoleNameUnique", testRoleNameUnique},
		{"RoleNameUniqueConcurrent", testRoleNameUniqueConcurrent},
		{"RoleUpdate", testRoleUpdate},
		{"RoleUpdateConcurrent", testRoleUpdateConcurrent},
		{"RoleDeleteAndOwners", testRoleDeleteAndOwners},
		{"RoleInUseAndRevokeRole", testRoleInUseAndRevokeRole},
		{"RoleCanceledContext", testRoleCanceledContext},
		{"WithWarden", testWithWarden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fn(t, newStore(t))
		})
	}
}

var (
	org    = wardn.NewScope("organisation", "o1")
	branch = wardn.NewScope("branch", "b1")
	other  = wardn.NewScope("branch", "b2")
)

func mustAssign(t *testing.T, s wardn.Store, a wardn.Assignment) {
	t.Helper()
	if err := s.Assign(context.Background(), a); err != nil {
		t.Fatalf("Assign(%+v): %v", a, err)
	}
}

func read(t *testing.T, s wardn.Store, user string, scopes ...wardn.Scope) []wardn.Assignment {
	t.Helper()
	as, err := s.Assignments(context.Background(), user, scopes)
	if err != nil {
		t.Fatalf("Assignments(%q, %v): %v", user, scopes, err)
	}
	slices.SortFunc(as, func(a, b wardn.Assignment) int {
		return strings.Compare(a.Role+"\x00"+a.Scope.Type+"\x00"+a.Scope.ID, b.Role+"\x00"+b.Scope.Type+"\x00"+b.Scope.ID)
	})
	return as
}

func roles(as []wardn.Assignment) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.Role + "@" + a.Scope.String()
	}
	return out
}

func wantRoles(t *testing.T, got []wardn.Assignment, want ...string) {
	t.Helper()
	slices.Sort(want)
	g := roles(got)
	slices.Sort(g)
	if !slices.Equal(g, want) {
		t.Fatalf("assignments = %v, want %v", g, want)
	}
}

func testAssignAndRead(t *testing.T, s wardn.Store) {
	mustAssign(t, s, wardn.Assignment{User: "u1", Role: "teller", Scope: branch})
	mustAssign(t, s, wardn.Assignment{User: "u1", Role: "auditor", Scope: branch})
	mustAssign(t, s, wardn.Assignment{User: "u1", Role: "admin", Scope: org})
	got := read(t, s, "u1", branch, org)
	wantRoles(t, got, "admin@organisation:o1", "auditor@branch:b1", "teller@branch:b1")
	for _, a := range got {
		if a.User != "u1" {
			t.Errorf("assignment has User %q, want u1", a.User)
		}
		if !a.StartsAt.IsZero() || !a.ExpiresAt.IsZero() {
			t.Errorf("permanent assignment came back with a time window: %+v", a)
		}
	}
}

func testAssignReplaces(t *testing.T, s wardn.Store) {
	until := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	mustAssign(t, s, wardn.Assignment{User: "u1", Role: "teller", Scope: branch, ExpiresAt: until})
	mustAssign(t, s, wardn.Assignment{User: "u1", Role: "teller", Scope: branch}) // now permanent
	got := read(t, s, "u1", branch)
	if len(got) != 1 {
		t.Fatalf("assigning twice stored %d assignments, want 1", len(got))
	}
	if !got[0].ExpiresAt.IsZero() {
		t.Fatalf("time window not replaced: %+v", got[0])
	}
	mustAssign(t, s, wardn.Assignment{User: "u1", Role: "teller", Scope: branch, ExpiresAt: until})
	if got := read(t, s, "u1", branch); len(got) != 1 || !got[0].ExpiresAt.Equal(until) {
		t.Fatalf("time window not set again: %+v", got)
	}
}

func testRevoke(t *testing.T, s wardn.Store) {
	ctx := context.Background()
	mustAssign(t, s, wardn.Assignment{User: "u1", Role: "teller", Scope: branch})
	mustAssign(t, s, wardn.Assignment{User: "u1", Role: "auditor", Scope: branch})
	if err := s.Revoke(ctx, "u1", "teller", branch); err != nil {
		t.Fatal(err)
	}
	wantRoles(t, read(t, s, "u1", branch), "auditor@branch:b1")
	if err := s.Revoke(ctx, "u1", "teller", branch); err != nil {
		t.Fatalf("revoking a missing assignment: %v", err)
	}
	if err := s.Revoke(ctx, "nobody", "nothing", wardn.Global); err != nil {
		t.Fatalf("revoking for an unknown user: %v", err)
	}
	// Revoke matches all four key fields exactly.
	if err := s.Revoke(ctx, "u1", "auditor", other); err != nil {
		t.Fatal(err)
	}
	wantRoles(t, read(t, s, "u1", branch), "auditor@branch:b1")
}

// testFiltersByUser: a store must never return another user's assignments
// (threat model T01).
func testFiltersByUser(t *testing.T, s wardn.Store) {
	mustAssign(t, s, wardn.Assignment{User: "alice", Role: "admin", Scope: branch})
	mustAssign(t, s, wardn.Assignment{User: "alicia", Role: "admin", Scope: branch})
	mustAssign(t, s, wardn.Assignment{User: "bob", Role: "teller", Scope: branch})
	wantRoles(t, read(t, s, "bob", branch), "teller@branch:b1")
	wantRoles(t, read(t, s, "alic", branch))
	wantRoles(t, read(t, s, "alice%", branch)) // no pattern matching
	wantRoles(t, read(t, s, "eve", branch))
}

// testFiltersByScope: only assignments at the requested scopes are returned,
// even when another scope shares the type or the ID (threat model T01).
func testFiltersByScope(t *testing.T, s wardn.Store) {
	for _, sc := range []wardn.Scope{
		branch, other, org, wardn.Global,
		wardn.NewScope("region", "b1"),       // same ID, other type
		wardn.NewScope("branch", "b1-extra"), // ID with b1 as prefix
	} {
		mustAssign(t, s, wardn.Assignment{User: "u1", Role: "r", Scope: sc})
	}
	wantRoles(t, read(t, s, "u1", branch), "r@branch:b1")
	wantRoles(t, read(t, s, "u1", branch, org), "r@branch:b1", "r@organisation:o1")
	wantRoles(t, read(t, s, "u1", wardn.NewScope("branch", "b")))
}

func testGlobalScope(t *testing.T, s wardn.Store) {
	mustAssign(t, s, wardn.Assignment{User: "u1", Role: "super_admin", Scope: wardn.Global})
	got := read(t, s, "u1", wardn.Global)
	if len(got) != 1 || !got[0].Scope.IsGlobal() {
		t.Fatalf("global assignment did not round-trip: %+v", got)
	}
	wantRoles(t, read(t, s, "u1", branch))
}

func testNoScopes(t *testing.T, s wardn.Store) {
	mustAssign(t, s, wardn.Assignment{User: "u1", Role: "r", Scope: wardn.Global})
	wantRoles(t, read(t, s, "u1"))
}

// testExactIdentity: IDs are compared byte for byte; a store must not fold
// case, accents, Unicode normalisation forms or widths (threat model T13).
// Database defaults often do (MySQL's default collation is case- and
// accent-insensitive).
func testExactIdentity(t *testing.T, s wardn.Store) {
	ctx := context.Background()
	groups := [][]string{
		{"o1", "O1"},
		{"café", "cafe\u0301", "CAFÉ", "cafe"}, // NFC, NFD, upper, unaccented
		{"o1", "ｏ1"},                           // fullwidth
		{"strasse", "straße"},
		{"user", "user "}, // stores must not trim (wardn validates, stores must not alter)
	}
	for gi, ids := range groups {
		for i, id := range ids {
			user := fmt.Sprintf("u%d-%s", gi, id)
			mustAssign(t, s, wardn.Assignment{User: user, Role: fmt.Sprintf("role%d", i), Scope: wardn.NewScope("branch", id)})
			if err := s.Link(ctx, wardn.NewScope("branch", id), wardn.NewScope("region", fmt.Sprintf("r%d", i))); err != nil {
				t.Fatalf("Link(%q): %v", id, err)
			}
		}
		for i, id := range ids {
			user := fmt.Sprintf("u%d-%s", gi, id)
			got := read(t, s, user, wardn.NewScope("branch", id))
			if len(got) != 1 || got[0].Role != fmt.Sprintf("role%d", i) || got[0].Scope.ID != id || got[0].User != user {
				t.Errorf("ID %q (%x) is not distinct from its look-alikes: %+v", id, id, got)
			}
			p, ok, err := s.Parent(ctx, wardn.NewScope("branch", id))
			if err != nil || !ok || p.ID != fmt.Sprintf("r%d", i) {
				t.Errorf("link for %q (%x) is not distinct: %v, %v, %v", id, id, p, ok, err)
			}
		}
	}
}

// testHostileIDs: valid IDs may contain quotes, SQL syntax, separators and
// multibyte characters, up to 256 bytes.
func testHostileIDs(t *testing.T, s wardn.Store) {
	ids := []string{
		`o1'; DROP TABLE wardn_assignments; --`,
		`"quoted"`,
		`back\slash`,
		`50%_off`,
		"a:b/c|d",
		"Ọ̀yọ\u0301 branch",
		"emoji 🔐",
		strings.Repeat("x", 256),
		strings.Repeat("é", 128), // 256 bytes, 128 characters
	}
	// Each ID is used as user, role and scope ID at once; all are at most
	// 256 bytes, the limit wardn enforces.
	for i, id := range ids {
		scope := wardn.NewScope("branch", id)
		mustAssign(t, s, wardn.Assignment{User: id, Role: id, Scope: scope})
		got := read(t, s, id, scope)
		if len(got) != 1 || got[0].User != id || got[0].Role != id || got[0].Scope != scope {
			t.Fatalf("ID %d (%q) did not round-trip: %+v", i, id, got)
		}
	}
	// The table-dropping ID above must have been harmless.
	mustAssign(t, s, wardn.Assignment{User: "after", Role: "r", Scope: branch})
	wantRoles(t, read(t, s, "after", branch), "r@branch:b1")
}

// testTimeRoundTrip: times come back as the same instant, possibly rounded,
// but a time window must never become wider than requested.
func testTimeRoundTrip(t *testing.T, s wardn.Store) {
	lagos := time.FixedZone("WAT", 3600)
	cases := []struct{ start, end time.Time }{
		{time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC), time.Date(2026, 11, 13, 17, 0, 0, 0, time.UTC)},
		{time.Date(2026, 11, 9, 9, 0, 0, 123456789, lagos), time.Date(2026, 11, 9, 9, 0, 1, 987654321, lagos)},
		{time.Time{}, time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)},
		{time.Date(1971, 1, 1, 0, 0, 0, 1, time.UTC), time.Time{}},
	}
	const tolerance = time.Millisecond
	for i, c := range cases {
		role := fmt.Sprintf("r%d", i)
		mustAssign(t, s, wardn.Assignment{User: "u1", Role: role, Scope: branch, StartsAt: c.start, ExpiresAt: c.end})
		var got wardn.Assignment
		for _, a := range read(t, s, "u1", branch) {
			if a.Role == role {
				got = a
			}
		}
		if got.Role == "" {
			t.Fatalf("case %d: assignment missing", i)
		}
		if c.start.IsZero() != got.StartsAt.IsZero() || c.end.IsZero() != got.ExpiresAt.IsZero() {
			t.Fatalf("case %d: zero (unbounded) times not preserved: sent %v–%v, got %v–%v", i, c.start, c.end, got.StartsAt, got.ExpiresAt)
		}
		if !c.start.IsZero() && (got.StartsAt.Before(c.start) || got.StartsAt.Sub(c.start) > tolerance) {
			t.Errorf("case %d: StartsAt %v widens or drifts from %v", i, got.StartsAt, c.start)
		}
		if !c.end.IsZero() && (got.ExpiresAt.After(c.end) || c.end.Sub(got.ExpiresAt) > tolerance) {
			t.Errorf("case %d: ExpiresAt %v widens or drifts from %v", i, got.ExpiresAt, c.end)
		}
	}
}

func testLinks(t *testing.T, s wardn.Store) {
	ctx := context.Background()
	region := wardn.NewScope("region", "r1")
	if _, ok, err := s.Parent(ctx, branch); err != nil || ok {
		t.Fatalf("unlinked scope: ok=%v err=%v", ok, err)
	}
	if err := s.Link(ctx, branch, region); err != nil {
		t.Fatal(err)
	}
	if p, ok, err := s.Parent(ctx, branch); err != nil || !ok || p != region {
		t.Fatalf("Parent = %v, %v, %v; want %v", p, ok, err, region)
	}
	moved := wardn.NewScope("region", "r2")
	if err := s.Link(ctx, branch, moved); err != nil {
		t.Fatal(err)
	}
	if p, _, _ := s.Parent(ctx, branch); p != moved {
		t.Fatalf("relink: Parent = %v, want %v", p, moved)
	}
	// Same ID, different type: a separate scope.
	if _, ok, _ := s.Parent(ctx, wardn.NewScope("team", "b1")); ok {
		t.Fatal("link leaked to a scope of another type with the same ID")
	}
}

func testReturnedCopy(t *testing.T, s wardn.Store) {
	mustAssign(t, s, wardn.Assignment{User: "u1", Role: "teller", Scope: branch})
	got := read(t, s, "u1", branch)
	got[0].Role = "super_admin"
	got[0].Scope = wardn.Global
	wantRoles(t, read(t, s, "u1", branch), "teller@branch:b1")
}

func testCanceledContext(t *testing.T, s wardn.Store) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := wardn.Assignment{User: "u1", Role: "teller", Scope: branch}
	if err := s.Assign(ctx, a); err == nil {
		t.Error("Assign ignored a canceled context")
	}
	if err := s.Revoke(ctx, "u1", "teller", branch); err == nil {
		t.Error("Revoke ignored a canceled context")
	}
	if _, err := s.Assignments(ctx, "u1", []wardn.Scope{branch}); err == nil {
		t.Error("Assignments ignored a canceled context")
	}
	if err := s.Link(ctx, branch, org); err == nil {
		t.Error("Link ignored a canceled context")
	}
	if _, _, err := s.Parent(ctx, branch); err == nil {
		t.Error("Parent ignored a canceled context")
	}
	wantRoles(t, read(t, s, "u1", branch)) // nothing was written
}

func testConcurrency(t *testing.T, s wardn.Store) {
	ctx := context.Background()
	const workers, perWorker = 8, 25
	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker*3)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWorker {
				role := fmt.Sprintf("w%d-r%d", w, i)
				if err := s.Assign(ctx, wardn.Assignment{User: "shared", Role: role, Scope: branch}); err != nil {
					errs <- err
				}
				// Contended key: every worker writes the same assignment.
				if err := s.Assign(ctx, wardn.Assignment{User: "shared", Role: "contended", Scope: branch}); err != nil {
					errs <- err
				}
				if _, err := s.Assignments(ctx, "shared", []wardn.Scope{branch}); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent operation failed: %v", err)
	}
	if got := read(t, s, "shared", branch); len(got) != workers*perWorker+1 {
		t.Fatalf("after concurrent writes: %d assignments, want %d", len(got), workers*perWorker+1)
	}
}

const conformancePolicy = `
scopes:
  organisation: {}
  branch: { parent: organisation }
permissions:
  loan:create: Create loans
  loan:approve: Approve loans
roles:
  org_admin:
    assignable_at: [organisation]
    allow: ["*"]
  teller:
    assignable_at: [branch]
    allow: [loan:create]
`

// testWithWarden runs a short end-to-end scenario through a Warden.
func testWithWarden(t *testing.T, s wardn.Store) {
	ctx := context.Background()
	p, err := wardn.ParsePolicy([]byte(conformancePolicy), "conformance.yaml")
	if err != nil {
		t.Fatal(err)
	}
	clock := &fixedClock{t: time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)}
	w, err := wardn.New(wardn.Config{Policy: p, Store: s, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Link(ctx, branch, org); err != nil {
		t.Fatal(err)
	}
	sys := w.System()
	if err := sys.Assign(ctx, "ada", "org_admin", org); err != nil {
		t.Fatal(err)
	}
	if err := sys.Assign(ctx, "bayo", "teller", branch, wardn.Until(clock.t.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	check := func(user, perm string, scope wardn.Scope, want bool) {
		t.Helper()
		d, err := w.Check(ctx, user, perm, scope)
		if err != nil || d.Allowed != want {
			t.Fatalf("Check(%s, %s, %s) = %v (%s), %v; want %v", user, perm, scope, d.Allowed, d.Reason, err, want)
		}
	}
	check("ada", "loan:approve", branch, true) // inherited through the stored link
	check("ada", "loan:approve", other, false) // other branch, not linked
	check("bayo", "loan:create", branch, true) // within its time window
	check("bayo", "loan:approve", branch, false)
	clock.t = clock.t.Add(time.Hour)
	check("bayo", "loan:create", branch, false) // expired
	if err := sys.Revoke(ctx, "ada", "org_admin", org); err != nil {
		t.Fatal(err)
	}
	check("ada", "loan:approve", branch, false) // revoked
}

type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }
