package wardn

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits on the size of names and identifiers (threat model T13, T23).
const (
	maxNameLen       = 64  // scope types and system role names
	maxPermissionLen = 128 // permission names and patterns
	maxIDLen         = 256 // user IDs and scope IDs
	maxDescLen       = 512 // human-readable descriptions
)

// globalName is the reserved name of the implicit scope above all others.
const globalName = "global"

// validName reports whether s is a valid scope type or system role name:
// a lowercase ASCII letter followed by lowercase letters, digits or '_'.
func validName(s string) bool {
	if s == "" || len(s) > maxNameLen || !isLower(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; !isLower(c) && !isDigit(c) && c != '_' {
			return false
		}
	}
	return true
}

// validPermission reports whether s is a concrete (non-wildcard) permission:
// two or more segments separated by ':'. A segment is one or more words
// separated by '.', and a word is a lowercase letter followed by lowercase
// letters, digits or '_'. Examples: "loan:approve", "wardn:roles.manage".
func validPermission(s string) bool {
	if s == "" || len(s) > maxPermissionLen {
		return false
	}
	segments := strings.Split(s, ":")
	if len(segments) < 2 {
		return false
	}
	for _, seg := range segments {
		if !validSegment(seg) {
			return false
		}
	}
	return true
}

// permissionProblem explains why name is not a valid permission, in words
// a developer can act on, with a corrected name when there is an obvious
// one. It returns "" for a valid permission.
func permissionProblem(name string) string {
	suggest := func(problem, fixed string) string {
		if fixed != name && validPermission(fixed) {
			return fmt.Sprintf("%s; did you mean %q?", problem, fixed)
		}
		return problem
	}
	switch {
	case validPermission(name):
		return ""
	case len(name) > maxPermissionLen:
		return fmt.Sprintf("it is longer than %d characters", maxPermissionLen)
	case !strings.Contains(name, ":"):
		fixed := name
		if i := strings.LastIndexByte(name, '.'); i >= 0 {
			fixed = name[:i] + ":" + name[i+1:]
		}
		return suggest("it has no ':' between the resource and the action", fixed)
	case strings.ToLower(name) != name:
		return suggest("it has capital letters", strings.ToLower(name))
	case strings.ContainsAny(name, "- "):
		return suggest("it has '-' or a space", strings.NewReplacer("-", "_", " ", "_").Replace(name))
	}
	for _, seg := range strings.Split(name, ":") {
		if seg == "" {
			return "it has an empty part: two ':' in a row, or one at the start or end"
		}
		if !validSegment(seg) {
			return fmt.Sprintf("in %q, use lowercase letters, digits, '_' and '.', with each word starting with a letter", seg)
		}
	}
	return "it is not of the form resource:action"
}

// validPattern reports whether s is a valid permission pattern for use in a
// role: a concrete permission, "*" (everything), or a prefix of one or more
// segments followed by ":*" (for example "loan:*").
func validPattern(s string) bool {
	if s == "*" {
		return true
	}
	if prefix, ok := strings.CutSuffix(s, ":*"); ok {
		if prefix == "" || len(s) > maxPermissionLen {
			return false
		}
		for _, seg := range strings.Split(prefix, ":") {
			if !validSegment(seg) {
				return false
			}
		}
		return true
	}
	return validPermission(s)
}

func isWildcard(pattern string) bool {
	return pattern == "*" || strings.HasSuffix(pattern, ":*")
}

func validSegment(seg string) bool {
	if seg == "" {
		return false
	}
	for _, word := range strings.Split(seg, ".") {
		if word == "" || !isLower(word[0]) {
			return false
		}
		for i := 1; i < len(word); i++ {
			if c := word[i]; !isLower(c) && !isDigit(c) && c != '_' {
				return false
			}
		}
	}
	return true
}

// matches reports whether a role's permission pattern grants or denies perm.
// perm must be a concrete permission.
func matches(pattern, perm string) bool {
	if pattern == "*" {
		return true
	}
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(perm, prefix) // prefix ends with ':'
	}
	return pattern == perm
}

// validateID checks a user ID or scope ID supplied by the application. IDs
// are compared byte-for-byte and never normalised, so anything that could
// make two IDs look identical while differing (or hide content in logs and
// admin screens) is rejected: invalid UTF-8, control and invisible format
// characters, and leading or trailing whitespace (threat model T13).
func validateID(kind, id string) error {
	switch {
	case id == "":
		return fmt.Errorf("%s ID is empty", kind)
	case len(id) > maxIDLen:
		return fmt.Errorf("%s ID is longer than %d bytes", kind, maxIDLen)
	case !utf8.ValidString(id):
		return fmt.Errorf("%s ID is not valid UTF-8", kind)
	}
	for _, r := range id {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("%s ID contains a control or invisible character (%U)", kind, r)
		}
	}
	first, _ := utf8.DecodeRuneInString(id)
	last, _ := utf8.DecodeLastRuneInString(id)
	if unicode.IsSpace(first) || unicode.IsSpace(last) {
		return fmt.Errorf("%s ID has leading or trailing whitespace", kind)
	}
	return nil
}

// validDescription checks human-readable text from a policy.
func validDescription(s string) error {
	switch {
	case len(s) > maxDescLen:
		return fmt.Errorf("description is longer than %d bytes", maxDescLen)
	case !utf8.ValidString(s):
		return fmt.Errorf("description is not valid UTF-8")
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("description contains a control or invisible character (%U)", r)
		}
	}
	return nil
}

func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
