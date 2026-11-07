package wardn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// policyIssues parses and validates src, returning its issues.
func policyIssues(t *testing.T, src string) []PolicyIssue {
	t.Helper()
	p, err := ParsePolicy([]byte(src), "test.yaml")
	if err == nil {
		err = p.Validate()
	}
	if err == nil {
		return nil
	}
	var pe *PolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("error is %T, want *PolicyError: %v", err, err)
	}
	return pe.Issues
}

func TestPolicyValid(t *testing.T) {
	p := mustParse(t, bankYAML)
	if err := p.Validate(); err != nil {
		t.Fatalf("bank policy invalid: %v", err)
	}
	if got := p.Scopes["branch"].Parent; got != "region" {
		t.Errorf("branch parent = %q", got)
	}
	if got := p.Roles["loan_officer"].Allow; !slices.Equal(got, []string{"loan:*"}) {
		t.Errorf("shorthand allow = %v", got)
	}
	if got := p.Roles["ops_admin"]; got.Description == "" || !slices.Equal(got.Deny, []string{"loan:approve"}) {
		t.Errorf("ops_admin = %+v", got)
	}
}

func TestPolicyMinimal(t *testing.T) {
	// No scopes, null scope body, no version: all fine.
	for _, src := range []string{
		"permissions:\n  doc:read: Read documents\nroles:\n  reader: [doc:read]\n",
		"scopes:\n  workspace:\npermissions:\n  doc:read: Read\nroles:\n  reader: [doc:read]\n",
	} {
		if is := policyIssues(t, src); is != nil {
			t.Errorf("unexpected issues for %q: %+v", src, is)
		}
	}
}

func TestPolicyErrors(t *testing.T) {
	const base = "permissions:\n  customer:view: View\n  loan:approve: Approve\n" // lines 1-3
	tests := []struct {
		name string
		src  string
		line int
		want string // substring of the message
	}{
		{"unknown top-level key", base + "role:\n  a: [loan:approve]\n", 4, `unknown key; did you mean "roles"?`},
		{"typo in role permission", base + "roles:\n  teller:\n    - customer:view\n    - custmer:view\n", 7, `permission "custmer:view" is not in permissions; did you mean "customer:view"?`},
		{"typo in scope parent", "scopes:\n  branch: { parent: regin }\n  region: {}\n" + base + "roles:\n  a: [loan:approve]\n", 2, `parent "regin" is not a declared scope type; did you mean "region"?`},
		{"scope cycle", "scopes:\n  a: { parent: b }\n  b: { parent: a }\n" + base + "roles:\n  x: [loan:approve]\n", 2, "cycle"},
		{"reserved scope name", "scopes:\n  global: {}\n" + base + "roles:\n  x: [loan:approve]\n", 2, "reserved"},
		{"parent global", "scopes:\n  org: { parent: global }\n" + base + "roles:\n  x: [loan:approve]\n", 2, "omit parent"},
		{"builtin declared", base + "  wardn:roles.manage: Manage\nroles:\n  x: [loan:approve]\n", 4, "built in"},
		{"reserved prefix", base + "  wardn:other: X\nroles:\n  x: [loan:approve]\n", 4, "reserved for built-in"},
		{"missing description", base + "  loan:view:\nroles:\n  x: [loan:approve]\n", 4, "add a description"},
		{"wildcard in catalog", base + "  loan:*: All\nroles:\n  x: [loan:approve]\n", 4, "wildcards are only allowed in roles"},
		{"bad permission name", base + "  Loan:View: X\nroles:\n  x: [loan:approve]\n", 4, "invalid permission"},
		{"wildcard matches nothing", base + "roles:\n  x: [\"report:*\"]\n", 5, `"report:*" matches no permission`},
		{"duplicate pattern", base + "roles:\n  x: [loan:approve, loan:approve]\n", 5, "listed more than once"},
		{"allow and deny same", base + "roles:\n  x:\n    allow: [loan:approve]\n    deny: [loan:approve]\n", 6, "both allowed and denied"},
		{"empty role", base + "roles:\n  x: []\n", 5, "grants and denies nothing"},
		{"no roles", base, 0, "define at least one role"},
		{"assignable_at undeclared", "scopes:\n  branch: {}\n" + base + "roles:\n  x:\n    allow: [loan:approve]\n    assignable_at: [brnch]\n", 9, `scope type "brnch" is not declared; did you mean "branch"?`},
		{"invalid role name", base + "roles:\n  Teller: [loan:approve]\n", 5, "invalid role name"},
		{"unknown role key", base + "roles:\n  x:\n    alow: [loan:approve]\n", 6, `did you mean "allow"?`},
		{"role is a scalar", base + "roles:\n  x: loan:approve\n", 5, "must be a list"},
		{"allow is a scalar", base + "roles:\n  x:\n    allow: \"*\"\n", 6, "must be a list"},
		{"duplicate key", base + "roles:\n  x: [loan:approve]\n  x: [customer:view]\n", 6, "defined more than once"},
		{"alias", base + "roles:\n  x: &a [loan:approve]\n  y: *a\n", 5, "anchors, aliases"},
		{"merge key", base + "roles:\n  x: { allow: [loan:approve] }\n  y:\n    <<: { allow: [loan:approve] }\n", 7, "anchors, aliases"},
		{"version 2", "version: 2\n" + base + "roles:\n  x: [loan:approve]\n", 1, "unsupported version"},
		{"two documents", base + "roles:\n  x: [loan:approve]\n---\nroles: {}\n", 0, "exactly one YAML document"},
		{"empty file", "", 0, "file is empty"},
		{"comment only", "# nothing\n", 0, "file is empty"},
		{"invalid yaml", "roles: [unclosed\n", 0, "invalid YAML"},
		{"top level list", "- a\n- b\n", 1, "top level must be a mapping"},
		{"unknown scope key", "scopes:\n  org: { parnt: x }\n" + base + "roles:\n  x: [loan:approve]\n", 2, "scope types only have parent"},
		{"control char in description", base + "  loan:view: \"bad\\u0007\"\nroles:\n  x: [loan:approve]\n", 4, "control or invisible"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := policyIssues(t, tt.src)
			for _, is := range issues {
				if strings.Contains(is.Message, tt.want) {
					if is.Line != tt.line {
						t.Errorf("line = %d, want %d (issue %+v)", is.Line, tt.line, is)
					}
					return
				}
			}
			t.Fatalf("no issue containing %q; got %+v", tt.want, issues)
		})
	}
}

func TestPolicyErrorReportsAllProblems(t *testing.T) {
	src := "permissions:\n  loan:view: View\n  loan:approve:\nroles:\n  a: [loan:veiw]\n  b: [report:x]\n"
	p, err := ParsePolicy([]byte(src), "wardn.yaml")
	if err != nil {
		t.Fatal(err)
	}
	err = p.Validate()
	var pe *PolicyError
	if !errors.As(err, &pe) || len(pe.Issues) != 3 {
		t.Fatalf("want 3 issues, got %v", err)
	}
	for i := 1; i < len(pe.Issues); i++ {
		if pe.Issues[i-1].Line > pe.Issues[i].Line {
			t.Errorf("issues not sorted by line: %+v", pe.Issues)
		}
	}
	msg := err.Error()
	for _, want := range []string{"wardn.yaml has 3 problems", "wardn.yaml:3: permissions.loan:approve: add a description", `wardn.yaml:5: roles.a.allow[0]: permission "loan:veiw" is not in permissions; did you mean "loan:view"?`} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
}

func TestPolicySingleIssueMessage(t *testing.T) {
	p := &Policy{Permissions: map[string]string{"a:b": "x"}}
	err := p.Validate()
	if err == nil || err.Error() != "wardn: policy: roles: define at least one role" {
		t.Fatalf("got %v", err)
	}
	if err := (*Policy)(nil).Validate(); err == nil {
		t.Fatal("nil policy validated")
	}
}

func TestPolicyDefinedInGo(t *testing.T) {
	p := &Policy{
		Scopes:      map[string]ScopeType{"workspace": {}},
		Permissions: map[string]string{"doc:read": "Read documents", "doc:write": "Write documents"},
		Roles: map[string]Role{
			"editor": {Allow: []string{"doc:*"}, AssignableAt: []string{"workspace"}},
			"viewer": {Allow: []string{"doc:read"}},
		},
	}
	w, err := New(Config{Policy: p})
	if err != nil {
		t.Fatal(err)
	}
	if got := w.SystemRoles(); !slices.Equal(got, []string{"editor", "viewer"}) {
		t.Errorf("SystemRoles = %v", got)
	}
	cat := w.Catalog()
	names := make([]string, len(cat))
	for i, c := range cat {
		names[i] = c.Name
		if c.Description == "" {
			t.Errorf("%s has no description", c.Name)
		}
	}
	if want := []string{"doc:read", "doc:write", PermRolesAssign, PermRolesManage}; !slices.Equal(names, want) {
		t.Errorf("Catalog = %v, want %v", names, want)
	}
}

func TestLoadPolicyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wardn.yaml")
	if err := os.WriteFile(path, []byte(bankYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{File: path}); err != nil {
		t.Fatalf("New from file: %v", err)
	}
	if _, err := LoadPolicyFile(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("missing file: no error")
	}

	// T23: oversized files are rejected without being fully read.
	big := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(big, []byte("# "+strings.Repeat("x", maxPolicySize)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicyFile(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized file: got %v", err)
	}

	// Errors name the file.
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("roles: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{File: bad}); err == nil || !strings.Contains(err.Error(), bad) {
		t.Errorf("error does not name file: %v", err)
	}
}

func TestNewConfigErrors(t *testing.T) {
	if _, err := New(Config{File: "x.yaml", Policy: &Policy{}}); err == nil {
		t.Error("File and Policy both set: no error")
	}
	t.Chdir(t.TempDir())
	if _, err := New(Config{}); err == nil || !strings.Contains(err.Error(), DefaultPolicyFile) {
		t.Errorf("default file missing: got %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Error("MustNew did not panic")
		}
	}()
	MustNew(Config{})
}

func TestMustNewSuccess(t *testing.T) {
	if MustNew(Config{Policy: mustParse(t, bankYAML)}) == nil {
		t.Fatal("MustNew returned nil")
	}
}

func FuzzParsePolicy(f *testing.F) {
	f.Add([]byte(bankYAML))
	f.Add([]byte("roles:\n  a: [x:y]\n"))
	f.Add([]byte("scopes:\n  a: { parent: b }\n  b: { parent: a }\n"))
	f.Add([]byte("roles: &a\n  x: *a\n"))
	f.Add([]byte("- 1\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParsePolicy(data, "fuzz.yaml")
		if err != nil {
			var pe *PolicyError
			if !errors.As(err, &pe) || len(pe.Issues) == 0 {
				t.Fatalf("parse error is not a non-empty *PolicyError: %v", err)
			}
			return
		}
		verr := p.Validate()
		w, nerr := New(Config{Policy: p})
		if (verr == nil) != (nerr == nil) {
			t.Fatalf("Validate (%v) and New (%v) disagree", verr, nerr)
		}
		if w != nil {
			// Every catalog permission must be checkable without error.
			for _, perm := range w.Catalog() {
				if _, err := w.Check(t.Context(), "u", perm.Name, Global); err != nil {
					t.Fatalf("Check(%s): %v", perm.Name, err)
				}
			}
		}
	})
}

func TestPolicyStructureErrors(t *testing.T) {
	const roles = "roles:\n  x: [a:b]\n"
	const perms = "permissions:\n  a:b: X\n"
	tests := []struct{ name, src, want string }{
		{"scopes is a list", "scopes: [org]\n" + perms + roles, "scopes: must be a mapping"},
		{"scope body is a list", "scopes:\n  org: [x]\n" + perms + roles, "scopes.org: must be a mapping"},
		{"parent is a list", "scopes:\n  org: { parent: [x] }\n" + perms + roles, "scopes.org.parent: must be a single value"},
		{"permissions is a list", "permissions: [a:b]\n" + roles, "permissions: must be a mapping"},
		{"description is a mapping", "permissions:\n  a:b: { x: y }\n" + roles, "permissions.a:b: must be a single value"},
		{"roles is a list", perms + "roles: [x]\n", "roles: must be a mapping"},
		{"role description is a list", perms + "roles:\n  x:\n    description: [a]\n    allow: [a:b]\n", "roles.x.description: must be a single value"},
		{"list item is a mapping", perms + "roles:\n  x: [{ a: b }]\n", "roles.x.allow[0]: must be a single value"},
		{"list item is null", perms + "roles:\n  x: [~]\n", "roles.x.allow[0]: must be a single value"},
		{"non-scalar key", perms + "roles:\n  [x]: [a:b]\n", "keys must be plain names"},
		{"version not a number", "version: one\n" + perms + roles, "unsupported version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePolicy([]byte(tt.src), "t.yaml")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %q", err, tt.want)
			}
		})
	}
	// Null sections are allowed and mean "empty".
	p := mustParse(t, "scopes:\npermissions:\nroles:\n")
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "define at least one role") {
		t.Errorf("null sections: %v", err)
	}
	if _, err := ParsePolicy([]byte("roles: {}\n"), ""); err != nil {
		t.Errorf("empty source name: %v", err)
	}
}

func TestPolicyGoValidation(t *testing.T) {
	long := strings.Repeat("x", maxDescLen+1)
	p := &Policy{
		Scopes:      map[string]ScopeType{"Org": {}, "team": {Parent: "Org"}},
		Permissions: map[string]string{"a:b": "ok", "a:c": long, "a:d": "bad\xff"},
		Roles: map[string]Role{
			"x": {Description: "tab\there", Allow: []string{"a:b"}, AssignableAt: []string{"team", "team"}},
			"y": {Allow: []string{"bad pattern"}},
		},
	}
	err := p.Validate()
	for _, want := range []string{
		`scopes.Org: invalid scope type name`,
		`scopes.team.parent: parent "Org" is not a declared scope type`,
		"permissions.a:c: description is longer than",
		"permissions.a:d: description is not valid UTF-8",
		"roles.x.description: description contains a control",
		`roles.x.assignable_at[1]: "team" is listed more than once`,
		`roles.y.allow[0]: invalid permission pattern "bad pattern"`,
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
	var pe *PolicyError
	if errors.As(err, &pe) {
		for _, is := range pe.Issues {
			if is.Line != 0 {
				t.Errorf("Go policy issue has a line number: %+v", is)
			}
		}
	}
}

// badParentStore returns a parent with an invalid ID.
type badParentStore struct{ *MemoryStore }

func (badParentStore) Parent(context.Context, Scope) (Scope, bool, error) {
	return NewScope("region", "r1\x00"), true, nil
}

func TestChainRejectsInvalidStoredParentID(t *testing.T) {
	w, err := New(Config{Policy: mustParse(t, bankYAML), Store: badParentStore{NewMemoryStore()}})
	if err != nil {
		t.Fatal(err)
	}
	if d, err := w.Check(context.Background(), "u", "loan:view", branch1); !errors.Is(err, ErrInvalidLink) || d.Allowed {
		t.Fatalf("got %+v, %v", d, err)
	}
}
