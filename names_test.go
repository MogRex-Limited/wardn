package wardn

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestValidName(t *testing.T) {
	valid := []string{"a", "teller", "org_admin", "branch2", strings.Repeat("a", maxNameLen)}
	invalid := []string{"", "Teller", "2fa", "_x", "org-admin", "org admin", "café", "a:b", strings.Repeat("a", maxNameLen+1)}
	for _, s := range valid {
		if !validName(s) {
			t.Errorf("validName(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if validName(s) {
			t.Errorf("validName(%q) = true, want false", s)
		}
	}
}

func TestValidPermissionAndPattern(t *testing.T) {
	tests := []struct {
		s                 string
		permission, patrn bool
	}{
		{"loan:approve", true, true},
		{"wardn:roles.manage", true, true},
		{"loan:approve:own", true, true},
		{"report2:export_csv", true, true},
		{"*", false, true},
		{"loan:*", false, true},
		{"loan:approve:*", false, true},
		{"loan", false, false},
		{"loan:", false, false},
		{":approve", false, false},
		{"Loan:approve", false, false},
		{"loan:approve ", false, false},
		{" loan:approve", false, false},
		{"loan::approve", false, false},
		{"loan:roles..manage", false, false},
		{"loan:.x", false, false},
		{"loan:*:x", false, false},
		{"*:approve", false, false},
		{":*", false, false},
		{"**", false, false},
		{"loan:appr*", false, false},
		{"lоan:approve", false, false}, // Cyrillic 'о' (T14)
		{"loan:approve\x00", false, false},
		{"loan:" + strings.Repeat("a", maxPermissionLen), false, false},
		{"loan:" + strings.Repeat("a", maxPermissionLen) + ":*", false, false},
	}
	for _, tt := range tests {
		if got := validPermission(tt.s); got != tt.permission {
			t.Errorf("validPermission(%q) = %v, want %v", tt.s, got, tt.permission)
		}
		if got := validPattern(tt.s); got != tt.patrn {
			t.Errorf("validPattern(%q) = %v, want %v", tt.s, got, tt.patrn)
		}
	}
}

func TestMatches(t *testing.T) {
	tests := []struct {
		pattern, perm string
		want          bool
	}{
		{"*", "loan:approve", true},
		{"loan:*", "loan:approve", true},
		{"loan:*", "loan:approve:own", true},
		{"loan:*", "loans:approve", false},
		{"loan:*", "customer:view", false},
		{"loan:approve:*", "loan:approve:own", true},
		{"loan:approve:*", "loan:approve", false},
		{"loan:approve", "loan:approve", true},
		{"loan:approve", "loan:approve:own", false},
		{"loan:approve", "loan:approv", false},
	}
	for _, tt := range tests {
		if got := matches(tt.pattern, tt.perm); got != tt.want {
			t.Errorf("matches(%q, %q) = %v, want %v", tt.pattern, tt.perm, got, tt.want)
		}
	}
}

func TestValidateID(t *testing.T) {
	valid := []string{"o1", "O1", "user@example.com", "a:b", "550e8400-e29b-41d4-a716-446655440000", "Ọ̀yọ́ branch", strings.Repeat("x", maxIDLen)}
	invalid := []string{
		"",
		strings.Repeat("x", maxIDLen+1),
		"bad\xffutf8",
		"tab\there",
		"new\nline",
		"nul\x00",
		"zero\u200bwidth",    // zero-width space
		"bidi\u202eoverride", // right-to-left override
		" leading",
		"trailing ",
		"trailing\u00a0", // no-break space
	}
	for _, s := range valid {
		if err := validateID("test", s); err != nil {
			t.Errorf("validateID(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range invalid {
		if err := validateID("test", s); err == nil {
			t.Errorf("validateID(%q) = nil, want error", s)
		}
	}
}

func TestSuggest(t *testing.T) {
	perms := []string{"customer:view", "loan:approve", "loan:create", "loan:view"}
	tests := []struct{ name, want string }{
		{"loan:aprove", "loan:approve"},
		{"loan:approv", "loan:approve"},
		{"custmer:view", "customer:view"},
		{"loan:veiw", "loan:view"}, // transposition
		{"report:export", ""},      // nothing close
		{"x", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := suggest(tt.name, perms); got != tt.want {
			t.Errorf("suggest(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
	if got := suggest("brnach", []string{"branch", "organisation", "region"}); got != "branch" {
		t.Errorf("suggest(brnach) = %q, want branch", got)
	}
}

func TestScopeString(t *testing.T) {
	if Global.String() != "global" || !Global.IsGlobal() {
		t.Errorf("Global = %q, IsGlobal %v", Global.String(), Global.IsGlobal())
	}
	if s := NewScope("branch", "b7"); s.String() != "branch:b7" || s.IsGlobal() {
		t.Errorf("NewScope = %q, IsGlobal %v", s.String(), s.IsGlobal())
	}
}

func FuzzNames(f *testing.F) {
	for _, s := range []string{"loan:approve", "loan:*", "*", "wardn:roles.manage", "a:b:c", "x", "", "lоan:approve"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if validPermission(s) {
			if !validPattern(s) || isWildcard(s) || !matches(s, s) || !matches("*", s) {
				t.Fatalf("inconsistent classification of permission %q", s)
			}
			if !utf8.ValidString(s) || strings.TrimSpace(s) != s {
				t.Fatalf("validPermission accepted unsafe %q", s)
			}
		}
		if validPattern(s) && !isWildcard(s) && !validPermission(s) {
			t.Fatalf("non-wildcard pattern %q is not a valid permission", s)
		}
		// A wildcard pattern matches exactly the permissions that extend its prefix.
		if validPattern(s) && strings.HasSuffix(s, ":*") {
			prefix := strings.TrimSuffix(s, "*")
			if !matches(s, prefix+"x") || matches(s, strings.TrimSuffix(prefix, ":")) {
				t.Fatalf("wildcard %q matches incorrectly", s)
			}
		}
		_ = validateID("fuzz", s)
		_ = suggest(s, []string{"loan:approve", "customer:view"})
	})
}
