package wardn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"
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

// FuzzRoleName: role-name validation never panics, and accepted names are
// safe to show and compare.
func FuzzRoleName(f *testing.F) {
	for _, s := range []string{"Senior Teller", "Аdmin", "a\u200bb", "Café", "Cafe\u0301", "  x", "Ọya", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if validateRoleName(name) != nil {
			return
		}
		key := roleNameKey(name)
		if key == "" || roleNameKey(key) != key {
			t.Fatalf("accepted %q has key %q (empty or not stable)", name, key)
		}
		for _, r := range name {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Mn, r) {
				t.Fatalf("accepted %q contains %U", name, r)
			}
		}
	})
}

// FuzzMemberCursor: cursors from clients never panic, and real cursors
// round-trip.
func FuzzMemberCursor(f *testing.F) {
	f.Add("", "alice", "teller")
	f.Add("YWxpY2UAdGVsbGVy", "bob", "cr-x")
	f.Add("%%%", "", "")
	f.Fuzz(func(t *testing.T, cursor, user, role string) {
		_, _, _ = DecodeMemberCursor(cursor)
		if strings.Contains(user, "\x00") {
			return
		}
		u, r, err := DecodeMemberCursor(EncodeMemberCursor(user, role))
		if err != nil || u != user || r != role {
			t.Fatalf("round trip (%q, %q) = (%q, %q, %v)", user, role, u, r, err)
		}
	})
}

// FuzzCacheContents: whatever bytes the cache returns, wardn never panics
// and never grants anything to a user with no roles.
func FuzzCacheContents(f *testing.F) {
	f.Add([]byte(`[{"user":"nobody","role":"super_admin","scope":{"type":"","id":""}}]`))
	f.Add([]byte(`{"ok":true,"parent":{"type":"region","id":"r1"}}`))
	f.Add([]byte("null"))
	f.Add([]byte{0xff, 0x00})
	cache := NewMemoryCache()
	w, _ := newBank(f, func(c *Config) { c.Cache = cache })
	assign(f, w, "tia", "teller", branch1)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		w.Can(ctx, "tia", "loan:create", branch1) // fill the cache
		cache.mu.Lock()
		for k, e := range cache.entries {
			e.value = data
			cache.entries[k] = e
		}
		cache.mu.Unlock()
		for _, s := range []Scope{branch1, org1, Global} {
			if d, err := w.Check(ctx, "nobody", "loan:approve", s); err == nil && d.Allowed {
				t.Fatalf("cache contents %q granted access to a user with no roles: %+v", data, d)
			}
		}
	})
}

// FuzzRoleSpec: arbitrary admin-form input to CreateRole never panics, and
// anything accepted is a valid, evaluable role.
func FuzzRoleSpec(f *testing.F) {
	f.Add("Desk", "Front desk", "loan:view,customer:view", "branch")
	f.Add("Аdmin", "", "*", "")
	f.Add("X", "a\x00", "loan:*,loan:*", "organisation,global")
	f.Add("Y", "", "wardn:roles.manage", "brnch")
	w, _ := newBank(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, name, desc, allow, assignable string) {
		spec := RoleSpec{Name: name, Description: desc, Allow: strings.Split(allow, ",")}
		if assignable != "" {
			spec.AssignableAt = strings.Split(assignable, ",")
		}
		r, err := w.System().CreateRole(ctx, org1, spec)
		if err != nil {
			return
		}
		if validateRoleName(r.Name) != nil || len(r.Allow) == 0 {
			t.Fatalf("accepted an invalid role: %+v", r)
		}
		for _, p := range r.Allow {
			if !validPattern(p) {
				t.Fatalf("accepted pattern %q", p)
			}
		}
		_ = w.System().DeleteRole(ctx, r.ID) // keep names free for later inputs
	})
}

// FuzzHTTPPath: any URL path through ScopeFrom and Require never panics and
// never lets a user with no roles through.
func FuzzHTTPPath(f *testing.F) {
	for _, p := range []string{"b1", "%20b1", "b1%00", "..%2f..", strings.Repeat("x", 300), "%E2%80%AE"} {
		f.Add(p)
	}
	w, _ := newBank(f)
	mux := http.NewServeMux()
	mux.Handle("GET /branches/{branchID}/loans", w.ScopeFrom("branch", PathValue("branchID"))(w.Require("loan:view")(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))))
	h := authAs("nobody")(mux)
	f.Fuzz(func(t *testing.T, segment string) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/branches/"+segment+"/loans", nil)
		if err != nil {
			return
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Fatalf("path segment %q let a user with no roles through", segment)
		}
	})
}
