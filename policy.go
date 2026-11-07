package wardn

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Built-in permissions. Every policy's catalog includes them automatically;
// grant them to roles like any other permission.
const (
	// PermRolesManage allows creating, editing and deleting custom roles.
	PermRolesManage = "wardn:roles.manage"
	// PermRolesAssign allows assigning and revoking roles.
	PermRolesAssign = "wardn:roles.assign"
)

var builtinPermissions = map[string]string{
	PermRolesManage: "Create, edit and delete custom roles",
	PermRolesAssign: "Assign and revoke roles",
}

// Policy is a product's authorization model: its scope types, the catalog of
// permissions its code checks, and its system roles. It is usually loaded
// from a YAML file with LoadPolicyFile, but can be built in Go.
type Policy struct {
	// Scopes declares the scope types and how they nest. Leave it empty for
	// a product without tenancy, which uses only the Global scope.
	Scopes map[string]ScopeType

	// Permissions is the catalog: every permission the code checks, mapped
	// to a human-readable description. The built-in wardn:... permissions
	// are added automatically and must not be declared.
	Permissions map[string]string

	// Roles are the system roles, keyed by name.
	Roles map[string]Role

	source string         // file name, for error messages
	lines  map[string]int // policy path -> line, for error messages
}

// ScopeType declares one kind of scope.
type ScopeType struct {
	// Parent is the scope type this one sits inside, or "" for a top-level
	// type. Roles assigned at a parent scope apply in its children.
	Parent string
}

// Role is a system role: a named set of permission patterns.
type Role struct {
	Description string

	// Allow lists the permissions this role grants. Entries may be concrete
	// permissions ("loan:create"), resource wildcards ("loan:*"), or "*".
	Allow []string

	// Deny lists permissions this role takes away. A deny from any role
	// overrides an allow from every role.
	Deny []string

	// AssignableAt lists the scope types (or "global") at which this role
	// may be assigned. Empty means anywhere.
	AssignableAt []string
}

// Validate checks the policy and reports every problem it finds as a
// *PolicyError. New calls it automatically.
func (p *Policy) Validate() error {
	_, err := compilePolicy(p)
	return err
}

// compiledPolicy is an immutable, validated copy of a Policy, optimised for
// evaluation. It shares no memory with the Policy it came from, so later
// changes to that Policy cannot affect a running Warden.
type compiledPolicy struct {
	scopeTypes  map[string]*compiledScopeType
	maxDepth    int               // longest chain of parents among scope types
	permissions map[string]string // catalog, including built-ins
	permList    []string          // sorted catalog
	roles       map[string]*compiledRole
	roleNames   []string // sorted
}

type compiledScopeType struct {
	name   string
	parent string // "" for top-level types
}

type compiledRole struct {
	name         string
	description  string
	allow        []string
	deny         []string
	assignableAt map[string]bool // nil means anywhere; "global" for Global
}

// assignableAt reports whether the role may be assigned at scope s.
func (r *compiledRole) assignableAtScope(s Scope) bool {
	if r.assignableAt == nil {
		return true
	}
	if s.IsGlobal() {
		return r.assignableAt[globalName]
	}
	return r.assignableAt[s.Type]
}

// assignableList returns the role's assignable_at list for error messages.
func (r *compiledRole) assignableList() []string {
	return slices.Sorted(maps.Keys(r.assignableAt))
}

// firstMatch returns the first pattern in patterns that matches perm.
func firstMatch(patterns []string, perm string) (string, bool) {
	for _, p := range patterns {
		if matches(p, perm) {
			return p, true
		}
	}
	return "", false
}

// issues collects problems found while validating a policy.
type issues struct {
	p    *Policy
	list []PolicyIssue
}

func (is *issues) add(path, format string, args ...any) {
	is.list = append(is.list, PolicyIssue{
		Line:    is.p.lineOf(path),
		Path:    path,
		Message: fmt.Sprintf(format, args...),
	})
}

func (is *issues) err() error {
	if len(is.list) == 0 {
		return nil
	}
	slices.SortStableFunc(is.list, func(a, b PolicyIssue) int {
		if a.Line != b.Line {
			if a.Line == 0 {
				return 1
			}
			if b.Line == 0 {
				return -1
			}
			return cmp.Compare(a.Line, b.Line)
		}
		return cmp.Compare(a.Path, b.Path)
	})
	return &PolicyError{Source: is.p.sourceName(), Issues: is.list}
}

func (p *Policy) sourceName() string {
	if p.source != "" {
		return p.source
	}
	return "policy"
}

// lineOf returns the source line for a policy path, falling back to the
// nearest enclosing path that has one.
func (p *Policy) lineOf(path string) int {
	for path != "" {
		if line, ok := p.lines[path]; ok {
			return line
		}
		i := strings.LastIndexAny(path, ".[")
		if i < 0 {
			break
		}
		path = path[:i]
	}
	return 0
}

func compilePolicy(p *Policy) (*compiledPolicy, error) {
	if p == nil {
		return nil, &PolicyError{Source: "policy", Issues: []PolicyIssue{{Message: "policy is nil"}}}
	}
	is := &issues{p: p}
	cp := &compiledPolicy{
		scopeTypes:  map[string]*compiledScopeType{},
		permissions: map[string]string{},
		roles:       map[string]*compiledRole{},
	}
	compileScopes(p, cp, is)
	compilePermissions(p, cp, is)
	compileRoles(p, cp, is)
	if err := is.err(); err != nil {
		return nil, err
	}
	return cp, nil
}

func compileScopes(p *Policy, cp *compiledPolicy, is *issues) {
	names := slices.Sorted(maps.Keys(p.Scopes))
	for _, name := range names {
		path := "scopes." + name
		switch {
		case name == globalName:
			is.add(path, "%q is reserved for the implicit top-level scope; choose another name", name)
			continue
		case !validName(name):
			is.add(path, "invalid scope type name %q: use lowercase letters, digits and '_', starting with a letter (max %d)", name, maxNameLen)
			continue
		}
		cp.scopeTypes[name] = &compiledScopeType{name: name, parent: p.Scopes[name].Parent}
	}

	for _, name := range names {
		st, ok := cp.scopeTypes[name]
		if !ok || st.parent == "" {
			continue
		}
		path := "scopes." + name + ".parent"
		switch {
		case st.parent == globalName:
			is.add(path, "omit parent for a top-level scope type; every scope is already inside global")
			st.parent = ""
		case cp.scopeTypes[st.parent] == nil:
			is.add(path, "parent %q is not a declared scope type%s", st.parent, didYouMean(st.parent, names))
			st.parent = ""
		}
	}

	// Reject cycles and compute the deepest chain. With n types, any chain
	// longer than n must revisit a type.
	for _, name := range names {
		st := cp.scopeTypes[name]
		if st == nil {
			continue
		}
		depth, cur := 0, st
		for cur.parent != "" {
			depth++
			if depth > len(cp.scopeTypes) {
				is.add("scopes."+name+".parent", "scope types form a cycle through %q", name)
				break
			}
			cur = cp.scopeTypes[cur.parent]
		}
		cp.maxDepth = max(cp.maxDepth, depth)
	}
}

func compilePermissions(p *Policy, cp *compiledPolicy, is *issues) {
	for _, name := range slices.Sorted(maps.Keys(p.Permissions)) {
		path := "permissions." + name
		desc := p.Permissions[name]
		switch {
		case builtinPermissions[name] != "":
			is.add(path, "%q is built in; remove it from permissions (it is always available)", name)
			continue
		case strings.HasPrefix(name, "wardn:"):
			is.add(path, "the wardn: prefix is reserved for built-in permissions")
			continue
		case isWildcard(name):
			is.add(path, "wildcards are only allowed in roles; declare concrete permissions here")
			continue
		case !validPermission(name):
			is.add(path, "invalid permission %q: use resource:action, e.g. loan:approve (lowercase letters, digits, '_' and '.', max %d)", name, maxPermissionLen)
			continue
		case strings.TrimSpace(desc) == "":
			is.add(path, "add a description; admin screens show it to people choosing permissions")
			continue
		}
		if err := validDescription(desc); err != nil {
			is.add(path, "%v", err)
			continue
		}
		cp.permissions[name] = desc
	}
	for name, desc := range builtinPermissions {
		cp.permissions[name] = desc
	}
	cp.permList = slices.Sorted(maps.Keys(cp.permissions))
}

func compileRoles(p *Policy, cp *compiledPolicy, is *issues) {
	if len(p.Roles) == 0 {
		is.add("roles", "define at least one role")
		return
	}
	for _, name := range slices.Sorted(maps.Keys(p.Roles)) {
		path := "roles." + name
		if !validName(name) {
			is.add(path, "invalid role name %q: use lowercase letters, digits and '_', starting with a letter (max %d)", name, maxNameLen)
			continue
		}
		def := p.Roles[name]
		before := len(is.list)
		if err := validDescription(def.Description); err != nil {
			is.add(path+".description", "%v", err)
		}
		r := &compiledRole{
			name:        name,
			description: def.Description,
			allow:       compilePatterns(cp, is, path+".allow", def.Allow),
			deny:        compilePatterns(cp, is, path+".deny", def.Deny),
		}
		if len(def.Allow) == 0 && len(def.Deny) == 0 {
			is.add(path, "role grants and denies nothing; add allow or deny entries")
		}
		denied := map[string]bool{}
		for _, d := range r.deny {
			denied[d] = true
		}
		for i, a := range def.Allow {
			if denied[a] {
				is.add(fmt.Sprintf("%s.allow[%d]", path, i), "%q is both allowed and denied; deny always wins, so remove it from allow", a)
			}
		}
		r.assignableAt = compileAssignableAt(cp, is, path+".assignable_at", def.AssignableAt)
		if len(is.list) == before {
			cp.roles[name] = r
		}
	}
	cp.roleNames = slices.Sorted(maps.Keys(cp.roles))
}

func compilePatterns(cp *compiledPolicy, is *issues, path string, patterns []string) []string {
	out := make([]string, 0, len(patterns))
	seen := map[string]bool{}
	for i, pat := range patterns {
		ipath := fmt.Sprintf("%s[%d]", path, i)
		switch {
		case seen[pat]:
			is.add(ipath, "%q is listed more than once", pat)
			continue
		case !validPattern(pat):
			is.add(ipath, "invalid permission pattern %q: use a permission (loan:approve), a wildcard (loan:*), or *", pat)
			continue
		}
		seen[pat] = true
		if isWildcard(pat) {
			if !slices.ContainsFunc(cp.permList, func(perm string) bool { return matches(pat, perm) }) {
				is.add(ipath, "%q matches no permission in the catalog", pat)
				continue
			}
		} else if _, ok := cp.permissions[pat]; !ok {
			is.add(ipath, "permission %q is not in permissions%s", pat, didYouMean(pat, cp.permList))
			continue
		}
		out = append(out, pat)
	}
	return out
}

func compileAssignableAt(cp *compiledPolicy, is *issues, path string, types []string) map[string]bool {
	if len(types) == 0 {
		return nil
	}
	declared := slices.Sorted(maps.Keys(cp.scopeTypes))
	out := map[string]bool{}
	for i, t := range types {
		ipath := fmt.Sprintf("%s[%d]", path, i)
		switch {
		case out[t]:
			is.add(ipath, "%q is listed more than once", t)
		case t != globalName && cp.scopeTypes[t] == nil:
			is.add(ipath, "scope type %q is not declared%s", t, didYouMean(t, append(declared, globalName)))
		default:
			out[t] = true
		}
	}
	return out
}

func didYouMean(name string, candidates []string) string {
	if s := suggest(name, candidates); s != "" {
		return fmt.Sprintf("; did you mean %q?", s)
	}
	return ""
}
