package wardn

// Scope is where a role applies: an instance of one of the scope types the
// policy declares, such as an organisation or a branch. The zero value is
// Global, the implicit scope above all others.
//
// Scopes are compared exactly, field by field: "o1" and "O1" are different
// scopes. wardn never normalises IDs.
type Scope struct {
	Type string // a scope type declared in the policy, e.g. "branch"
	ID   string // the application's identifier for this instance, e.g. "b7"
}

// Global is the implicit scope above every other scope. A role assigned at
// Global applies everywhere.
var Global = Scope{}

// NewScope returns the scope of the given type and ID.
func NewScope(scopeType, id string) Scope {
	return Scope{Type: scopeType, ID: id}
}

// IsGlobal reports whether s is the Global scope.
func (s Scope) IsGlobal() bool {
	return s == Global
}

// String returns "global" or "type:id", for display and logs only. Never
// use it as a key: IDs may themselves contain ':'.
func (s Scope) String() string {
	if s.IsGlobal() {
		return globalName
	}
	return s.Type + ":" + s.ID
}
