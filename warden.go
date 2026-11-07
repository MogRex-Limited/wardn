package wardn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"
)

// migrationTimeout bounds how long New waits for store migrations.
const migrationTimeout = 2 * time.Minute

// DefaultPolicyFile is the policy file New reads when Config sets neither
// File nor Policy.
const DefaultPolicyFile = "wardn.yaml"

// Config configures a Warden. Every field is optional.
type Config struct {
	// File is the path of a YAML policy file. Default: "wardn.yaml".
	File string

	// Policy is a policy defined in Go, used instead of File.
	Policy *Policy

	// Store persists assignments and scope links. Default: a new
	// MemoryStore, which is lost on exit. Use a database store in
	// production.
	Store Store

	// ParentOf, if set, resolves a scope's parent from the application's own
	// data instead of links stored with Link. It must return the true parent
	// from authoritative data; returning ok=false means "no parent".
	ParentOf func(ctx context.Context, child Scope) (parent Scope, ok bool, err error)

	// ManualMigrations stops New from migrating the Store's database
	// schema. Set it if your deploy pipeline runs migrations itself.
	ManualMigrations bool

	// Clock supplies the current time for time-limited assignments.
	// Default: the system clock. Tests can inject a fake clock.
	Clock Clock

	// UserFrom, if set, returns the authenticated user's ID for a request.
	// By default wardn's HTTP middleware reads it from the request context,
	// where the application's authentication middleware put it with
	// WithUser.
	UserFrom func(r *http.Request) (userID string, ok bool)

	// OnError, if set, writes the response when wardn's HTTP middleware
	// rejects a request. Use HTTPStatus(err) for the status code. By default
	// wardn writes a generic JSON error that does not reveal which
	// permission was missing.
	OnError func(w http.ResponseWriter, r *http.Request, err error)

	// OnChange, if set, is called before every change to assignments,
	// custom roles and scope links, with the acting user, for the audit
	// trail. If it returns an error, the change is not made (fail closed).
	// If the change then fails, it is called again with Event.Err set.
	OnChange func(ctx context.Context, e Event) error

	// OnDecision, if set, is called with every authorization decision and
	// any error, for audit logging and debugging. It must be fast and must
	// not panic.
	OnDecision func(ctx context.Context, d Decision, err error)
}

// Clock supplies the current time.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Warden answers authorization questions for one policy. It is safe for
// concurrent use; create one at startup and share it.
type Warden struct {
	policy       *compiledPolicy
	store        Store
	parentOf     func(context.Context, Scope) (Scope, bool, error)
	clock        Clock
	onDecision   func(context.Context, Decision, error)
	userFrom     func(*http.Request) (string, bool)
	onChange     func(context.Context, Event) error
	errorHandler func(http.ResponseWriter, *http.Request, error)
}

// New validates the policy and returns a Warden. Any problem in the policy
// is reported here, so a misconfigured application fails at startup rather
// than when a user is first denied.
func New(cfg Config) (*Warden, error) {
	policy := cfg.Policy
	switch {
	case cfg.Policy != nil && cfg.File != "":
		return nil, errors.New("wardn: set Config.File or Config.Policy, not both")
	case policy == nil:
		file := cfg.File
		if file == "" {
			file = DefaultPolicyFile
		}
		p, err := LoadPolicyFile(file)
		if err != nil {
			return nil, err
		}
		policy = p
	}
	cp, err := compilePolicy(policy)
	if err != nil {
		return nil, err
	}
	w := &Warden{
		policy:       cp,
		store:        cfg.Store,
		parentOf:     cfg.ParentOf,
		clock:        cfg.Clock,
		onDecision:   cfg.OnDecision,
		userFrom:     cfg.UserFrom,
		onChange:     cfg.OnChange,
		errorHandler: cfg.OnError,
	}
	if w.store == nil {
		w.store = NewMemoryStore()
	}
	if w.clock == nil {
		w.clock = systemClock{}
	}
	if m, ok := w.store.(Migrator); ok && !cfg.ManualMigrations {
		ctx, cancel := context.WithTimeout(context.Background(), migrationTimeout)
		defer cancel()
		if err := m.Migrate(ctx); err != nil {
			return nil, fmt.Errorf("wardn: migrating store schema: %w", err)
		}
	}
	return w, nil
}

// MustNew is like New but panics on error. It is meant for main(), where a
// misconfigured policy should stop the application.
func MustNew(cfg Config) *Warden {
	w, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return w
}

// Permission is an entry in the permission catalog.
type Permission struct {
	Name        string
	Description string
}

// Catalog returns every permission in the policy, including the built-in
// ones, sorted by name. Admin screens use it to let people pick permissions.
func (w *Warden) Catalog() []Permission {
	out := make([]Permission, 0, len(w.policy.permList))
	for _, name := range w.policy.permList {
		out = append(out, Permission{Name: name, Description: w.policy.permissions[name]})
	}
	return out
}

// SystemRoles returns the names of the policy's system roles, sorted.
func (w *Warden) SystemRoles() []string {
	return slices.Clone(w.policy.roleNames)
}
