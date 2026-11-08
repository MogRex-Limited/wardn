package wardn

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors. Errors returned by wardn wrap these, so test for them
// with errors.Is.
var (
	// ErrInvalidInput reports a malformed user ID, scope, role name,
	// permission or time window.
	ErrInvalidInput = errors.New("wardn: invalid input")

	// ErrNotAssignable reports an attempt to assign a role at a scope type
	// its assignable_at list does not include.
	ErrNotAssignable = errors.New("wardn: role is not assignable at this scope")

	// ErrInvalidLink reports a scope link that contradicts the policy's
	// scope hierarchy, or a stored link that does.
	ErrInvalidLink = errors.New("wardn: invalid scope link")

	// ErrEscalation reports an attempt to create, edit, assign or revoke a
	// role containing permissions the acting user does not hold (the
	// escalation guard, design §6.2).
	ErrEscalation = errors.New("wardn: you cannot grant permissions you do not hold")

	// ErrRoleInUse reports an attempt to delete a custom role that is still
	// assigned, without wardn.Cascade.
	ErrRoleInUse = errors.New("wardn: role is still assigned")

	// ErrAlreadyLinked reports a Link to a different parent than the scope
	// already has. It usually means two tenants reuse an ID. Use Move to
	// change a parent on purpose. It also matches ErrInvalidLink.
	ErrAlreadyLinked = errors.New("wardn: scope already has a different parent")

	// ErrLinksExternal reports a call to Link when scope parents are
	// resolved by Config.ParentOf instead of stored by wardn.
	ErrLinksExternal = errors.New("wardn: scope parents are resolved by Config.ParentOf; Link is disabled")
)

// UndefinedError reports a reference to a permission, role or scope type
// that the policy does not define. It carries a suggestion when the name
// looks like a typo of one that is defined.
type UndefinedError struct {
	Kind       string // "permission", "role" or "scope type"
	Name       string // the undefined name
	Suggestion string // the closest defined name, or ""
}

func (e *UndefinedError) Error() string {
	msg := fmt.Sprintf("wardn: %s %q is not defined", e.Kind, e.Name)
	if e.Suggestion != "" {
		msg += fmt.Sprintf("; did you mean %q?", e.Suggestion)
	}
	return msg
}

// PolicyError reports every problem found in a policy, so they can all be
// fixed at once.
type PolicyError struct {
	Source string        // the file name, or "policy" for a Go-defined policy
	Issues []PolicyIssue // sorted by line, then path
}

// PolicyIssue is one problem in a policy.
type PolicyIssue struct {
	Line    int    // line in the source file; 0 if unknown
	Path    string // location in the policy, e.g. "roles.teller.allow[1]"
	Message string
}

func (e *PolicyError) Error() string {
	var b strings.Builder
	if len(e.Issues) == 1 {
		b.WriteString("wardn: ")
		e.writeIssue(&b, e.Issues[0])
		return b.String()
	}
	fmt.Fprintf(&b, "wardn: %s has %d problems:", e.Source, len(e.Issues))
	for _, is := range e.Issues {
		b.WriteString("\n  ")
		e.writeIssue(&b, is)
	}
	return b.String()
}

func (e *PolicyError) writeIssue(b *strings.Builder, is PolicyIssue) {
	b.WriteString(e.Source)
	if is.Line > 0 {
		fmt.Fprintf(b, ":%d", is.Line)
	}
	b.WriteString(": ")
	if is.Path != "" {
		b.WriteString(is.Path)
		b.WriteString(": ")
	}
	b.WriteString(is.Message)
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidInput}, args...)...)
}
