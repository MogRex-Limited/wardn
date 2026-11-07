package wardn

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"go.yaml.in/yaml/v3"
)

// maxPolicySize bounds policy files (threat model T23).
const maxPolicySize = 1 << 20 // 1 MiB

// policyVersion is the only policy file format version this release reads.
const policyVersion = 1

// LoadPolicyFile reads and parses a YAML policy file. It checks the file's
// structure; New (or Policy.Validate) checks its meaning.
func LoadPolicyFile(path string) (*Policy, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("wardn: reading policy: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only file; a close error cannot lose data
	data, err := io.ReadAll(io.LimitReader(f, maxPolicySize+1))
	if err != nil {
		return nil, fmt.Errorf("wardn: reading policy %s: %w", path, err)
	}
	return ParsePolicy(data, path)
}

// ParsePolicy parses a YAML policy. source names it in error messages,
// usually the file name.
func ParsePolicy(data []byte, source string) (*Policy, error) {
	if source == "" {
		source = "policy"
	}
	p := &Policy{source: source, lines: map[string]int{}}
	is := &issues{p: p}
	if len(data) > maxPolicySize {
		is.add("", "file is larger than %d bytes", maxPolicySize)
		return nil, is.err()
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			is.add("", "file is empty")
		} else {
			is.add("", "invalid YAML: %v", err)
		}
		return nil, is.err()
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		is.add("", "file must contain exactly one YAML document")
		return nil, is.err()
	}
	if len(doc.Content) != 1 {
		is.add("", "file is empty")
		return nil, is.err()
	}
	root := doc.Content[0]

	// Anchors, aliases and merge keys make files harder to review and are a
	// classic resource-exhaustion vector; policies don't need them.
	if n := findAlias(root); n != nil {
		p.lines["yaml"] = n.Line
		is.add("yaml", "anchors, aliases and merge keys (&, *, <<) are not supported in policy files")
		return nil, is.err()
	}

	pp := &policyParser{p: p, is: is}
	pp.parseRoot(root)
	if err := is.err(); err != nil {
		return nil, err
	}
	return p, nil
}

func findAlias(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.AliasNode || n.Anchor != "" || (n.Kind == yaml.ScalarNode && n.Tag == "!!merge") {
		return n
	}
	for _, c := range n.Content {
		if found := findAlias(c); found != nil {
			return found
		}
	}
	return nil
}

type policyParser struct {
	p  *Policy
	is *issues
}

func (pp *policyParser) mark(path string, n *yaml.Node) {
	pp.p.lines[path] = n.Line
}

// entries returns a mapping node's key/value pairs, reporting non-string
// and duplicate keys.
func (pp *policyParser) entries(path string, n *yaml.Node) (keys []string, values []*yaml.Node) {
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			pp.p.lines[path] = k.Line
			pp.is.add(path, "keys must be plain names")
			continue
		}
		kpath := join(path, k.Value)
		pp.mark(kpath, k)
		if seen[k.Value] {
			pp.is.add(kpath, "%q is defined more than once", k.Value)
			continue
		}
		seen[k.Value] = true
		keys = append(keys, k.Value)
		values = append(values, v)
	}
	return keys, values
}

func (pp *policyParser) parseRoot(root *yaml.Node) {
	if root.Kind != yaml.MappingNode {
		pp.p.lines["policy"] = root.Line
		pp.is.add("policy", "the top level must be a mapping with scopes, permissions and roles")
		return
	}
	known := []string{"version", "scopes", "permissions", "roles"}
	keys, values := pp.entries("", root)
	for i, key := range keys {
		v := values[i]
		switch key {
		case "version":
			pp.parseVersion(v)
		case "scopes":
			pp.parseScopes(v)
		case "permissions":
			pp.parsePermissions(v)
		case "roles":
			pp.parseRoles(v)
		default:
			pp.is.add(key, "unknown key%s; allowed keys are version, scopes, permissions, roles", didYouMean(key, known))
		}
	}
}

func (pp *policyParser) parseVersion(v *yaml.Node) {
	n, err := strconv.Atoi(v.Value)
	if v.Kind != yaml.ScalarNode || err != nil || n != policyVersion {
		pp.is.add("version", "unsupported version %q; this release of wardn reads version %d", v.Value, policyVersion)
	}
}

func (pp *policyParser) parseScopes(v *yaml.Node) {
	if isNull(v) {
		return
	}
	if v.Kind != yaml.MappingNode {
		pp.is.add("scopes", "must be a mapping of scope types, e.g. `organisation: {}`")
		return
	}
	pp.p.Scopes = map[string]ScopeType{}
	keys, values := pp.entries("scopes", v)
	for i, name := range keys {
		path := "scopes." + name
		var st ScopeType
		switch body := values[i]; {
		case isNull(body):
		case body.Kind == yaml.MappingNode:
			fields, fvalues := pp.entries(path, body)
			for j, f := range fields {
				if f != "parent" {
					pp.is.add(path+"."+f, "unknown key; scope types only have parent")
					continue
				}
				if s, ok := pp.scalar(path+".parent", fvalues[j]); ok {
					st.Parent = s
				}
			}
		default:
			pp.is.add(path, "must be a mapping, e.g. `{}` or `{ parent: organisation }`")
		}
		pp.p.Scopes[name] = st
	}
}

func (pp *policyParser) parsePermissions(v *yaml.Node) {
	if isNull(v) {
		return
	}
	if v.Kind != yaml.MappingNode {
		pp.is.add("permissions", "must be a mapping of permission to description, e.g. `loan:approve: Approve loans`")
		return
	}
	pp.p.Permissions = map[string]string{}
	keys, values := pp.entries("permissions", v)
	for i, name := range keys {
		if isNull(values[i]) {
			pp.p.Permissions[name] = ""
			continue
		}
		if s, ok := pp.scalar("permissions."+name, values[i]); ok {
			pp.p.Permissions[name] = s
		}
	}
}

func (pp *policyParser) parseRoles(v *yaml.Node) {
	if isNull(v) {
		return
	}
	if v.Kind != yaml.MappingNode {
		pp.is.add("roles", "must be a mapping of role names to permissions")
		return
	}
	pp.p.Roles = map[string]Role{}
	keys, values := pp.entries("roles", v)
	for i, name := range keys {
		path := "roles." + name
		var r Role
		switch body := values[i]; body.Kind {
		case yaml.SequenceNode: // shorthand: a list is an allow list
			r.Allow = pp.list(path+".allow", body)
		case yaml.MappingNode:
			fields, fvalues := pp.entries(path, body)
			for j, f := range fields {
				fpath := path + "." + f
				switch f {
				case "description":
					r.Description, _ = pp.scalar(fpath, fvalues[j])
				case "allow":
					r.Allow = pp.list(fpath, fvalues[j])
				case "deny":
					r.Deny = pp.list(fpath, fvalues[j])
				case "assignable_at":
					r.AssignableAt = pp.list(fpath, fvalues[j])
				default:
					pp.is.add(fpath, "unknown key%s; roles have description, allow, deny, assignable_at",
						didYouMean(f, []string{"description", "allow", "deny", "assignable_at"}))
				}
			}
		case yaml.DocumentNode, yaml.ScalarNode, yaml.AliasNode:
			pp.is.add(path, "must be a list of permissions, or a mapping with allow, deny, description, assignable_at")
		}
		pp.p.Roles[name] = r
	}
}

func (pp *policyParser) list(path string, n *yaml.Node) []string {
	if n.Kind != yaml.SequenceNode {
		pp.is.add(path, "must be a list, e.g. [customer:view, loan:create]")
		return nil
	}
	out := make([]string, 0, len(n.Content))
	for i, item := range n.Content {
		ipath := fmt.Sprintf("%s[%d]", path, i)
		pp.mark(ipath, item)
		if s, ok := pp.scalar(ipath, item); ok {
			out = append(out, s)
		}
	}
	return out
}

func (pp *policyParser) scalar(path string, n *yaml.Node) (string, bool) {
	if n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		pp.p.lines[path] = n.Line
		pp.is.add(path, "must be a single value")
		return "", false
	}
	return n.Value, true
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
