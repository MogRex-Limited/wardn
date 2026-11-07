package wardn

import (
	"context"
	"testing"
)

// FuzzCheck feeds arbitrary users, permissions and scopes to Check. It must
// never panic, never allow on error, and never allow an input that fails
// validation.
func FuzzCheck(f *testing.F) {
	f.Add("u", "loan:approve", "branch", "b1")
	f.Add("", "loan:*", "", "")
	f.Add("u\x00", "*", "global", "x")
	f.Add("root", "wardn:roles.manage", "organisation", "o1:x")
	f.Add("root", "loan:approve ", "branch", " b1")

	w, _ := newBank(f)
	ctx := context.Background()
	for _, u := range []string{"u", "root"} {
		assign(f, w, u, "super_admin", Global)
	}
	assign(f, w, "u", "org_admin", org1)

	f.Fuzz(func(t *testing.T, user, perm, scopeType, scopeID string) {
		scope := NewScope(scopeType, scopeID)
		d, err := w.Check(ctx, user, perm, scope)
		if err != nil {
			if d.Allowed {
				t.Fatalf("allowed with error %v", err)
			}
			return
		}
		if validateID("user", user) != nil {
			t.Fatalf("accepted invalid user %q", user)
		}
		if _, ok := w.policy.permissions[perm]; !ok {
			t.Fatalf("accepted undefined permission %q", perm)
		}
		if !scope.IsGlobal() && (w.policy.scopeTypes[scopeType] == nil || validateID("scope", scopeID) != nil) {
			t.Fatalf("accepted invalid scope %+v", scope)
		}
		if d.Allowed != w.Can(ctx, user, perm, scope) {
			t.Fatal("Check and Can disagree")
		}
		// Only the users given roles may ever be allowed.
		if d.Allowed && user != "u" && user != "root" {
			t.Fatalf("user %q with no roles was allowed: %+v", user, d)
		}
	})
}
