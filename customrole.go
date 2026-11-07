package wardn

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// CustomRole is a role created at runtime, usually by an administrator. It
// belongs to an owner scope and applies only within that scope's subtree.
// Custom roles only grant; they cannot deny (design decision D2).
type CustomRole struct {
	ID          string `json:"id"`          // generated; starts with "cr-", so it never clashes with a system role name
	Owner       Scope  `json:"owner"`       // where the role was created
	Name        string `json:"name"`        // display name, unique within the owner scope and its ancestors
	NameKey     string `json:"name_key"`    // normalised name used for uniqueness; set by wardn
	Description string `json:"description"` //

	// Allow lists the permissions the role grants: concrete permissions or
	// wildcards from the catalog.
	Allow []string `json:"allow"`

	// AssignableAt lists the scope types where the role may be assigned:
	// the owner's type and types below it. Default: the owner's type.
	AssignableAt []string `json:"assignable_at"`

	Version   int       `json:"version"` // incremented on every update; used to detect conflicting edits
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RoleSpec describes a custom role to create or the new content of one to
// update.
type RoleSpec struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Allow        []string `json:"allow"`
	AssignableAt []string `json:"assignable_at,omitempty"` // default: the owner scope's type
	// Deny is not supported for custom roles in this release: a RoleSpec
	// with Deny entries is rejected (design decision D2).
	Deny []string `json:"deny,omitempty"`
}

const customRolePrefix = "cr-"

// Limits on custom roles (threat model T23).
const (
	maxRoleNameLen  = 64  // characters
	maxRolePatterns = 256 // entries in Allow
)

// isCustomRoleID reports whether role is a custom role ID rather than a
// system role name. System role names cannot contain '-'.
func isCustomRoleID(role string) bool {
	return strings.HasPrefix(role, customRolePrefix)
}

var roleIDEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// newCustomRoleID returns an unpredictable ID: 120 random bits.
func newCustomRoleID() (string, error) {
	var b [15]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("wardn: generating role ID: %w", err)
	}
	return customRolePrefix + roleIDEncoding.EncodeToString(b[:]), nil
}

// roleNameKey normalises a role name for uniqueness checks, so names that
// read the same to a person collide: case, underscores, hyphens and spacing
// are ignored. "Org Admin", "org_admin" and "ORG-ADMIN" share a key.
func roleNameKey(name string) string {
	fields := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return unicode.IsSpace(r) || r == '_' || r == '-'
	})
	return strings.Join(fields, " ")
}

// validateRoleName checks a custom role's display name. Names are shown to
// administrators choosing roles, so anything that could make one name look
// like another is rejected (threat model T15): control and invisible
// characters, combining marks (which allow two encodings of the same
// visible text), letters from more than one script (homoglyphs such as a
// Cyrillic "а" in "Аdmin"), and leading, trailing or repeated spaces.
func validateRoleName(name string) error {
	switch {
	case name == "":
		return invalidf("role name is empty")
	case !utf8.ValidString(name):
		return invalidf("role name is not valid UTF-8")
	case utf8.RuneCountInString(name) > maxRoleNameLen:
		return invalidf("role name is longer than %d characters", maxRoleNameLen)
	case strings.TrimSpace(name) != name:
		return invalidf("role name has leading or trailing spaces")
	case strings.Contains(name, "  "):
		return invalidf("role name has repeated spaces")
	}
	var script *unicode.RangeTable
	var scriptName string
	for _, r := range name {
		switch {
		case unicode.IsLetter(r):
			s, sName := scriptOf(r)
			if script == nil {
				script, scriptName = s, sName
			} else if s != script {
				return invalidf("role name mixes %s and %s letters; use one script", scriptName, sName)
			}
		case unicode.IsDigit(r), r == ' ':
		case strings.ContainsRune("-_'.,&()/+", r):
		case unicode.Is(unicode.Mn, r), unicode.Is(unicode.Me, r):
			return invalidf("role name contains a combining mark (%U); use precomposed characters", r)
		default:
			return invalidf("role name contains a character that is not allowed (%U); use letters, digits, spaces and - _ ' . , & ( ) / +", r)
		}
	}
	if script == nil {
		return invalidf("role name must contain a letter")
	}
	if roleNameKey(name) == "" {
		return invalidf("role name is empty")
	}
	return nil
}

// scriptOf returns the Unicode script of a letter.
func scriptOf(r rune) (*unicode.RangeTable, string) {
	for name, table := range unicode.Scripts {
		if unicode.Is(table, r) {
			return table, name
		}
	}
	return nil, "unknown"
}
