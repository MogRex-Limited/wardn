package wardn

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
)

// MaxCheckEach is the most scopes one CheckEach or CanEach call accepts.
// Page longer lists.
const MaxCheckEach = 1000

// assignmentsBatch is how many scopes CheckEach reads assignments for in
// one store call. Stores bound the scopes in one query (wardnsql: 64).
const assignmentsBatch = 32

// CanEach reports, for each scope, whether user holds permission there.
// The result has one entry per scope, in order. Use it to filter a list,
// such as the projects a user may see, without one round trip per item.
// Every entry is false on any error; use CheckEach to see why.
func (w *Warden) CanEach(ctx context.Context, user, permission string, scopes []Scope) []bool {
	out := make([]bool, len(scopes))
	ds, err := w.CheckEach(ctx, user, permission, scopes)
	if err != nil {
		return out
	}
	for i, d := range ds {
		out[i] = d.Allowed
	}
	return out
}

// CheckEach decides, for each scope, whether user holds permission there,
// with the same rules and reasons as Check. It reads the user's
// assignments for all the scopes together, so it costs a few store reads
// rather than a few per scope.
//
// The whole call fails, denying every scope, if the permission or user is
// invalid, any scope is invalid, there are more than MaxCheckEach scopes,
// or a read fails.
func (w *Warden) CheckEach(ctx context.Context, user, permission string, scopes []Scope) ([]Decision, error) {
	ds, err := w.checkEach(ctx, user, permission, scopes)
	if err != nil {
		ds = make([]Decision, len(scopes))
		for i, s := range scopes {
			ds[i] = Decision{User: user, Permission: permission, Scope: s, Reason: "error: " + err.Error()}
		}
	}
	if w.onDecision != nil {
		for _, d := range ds {
			w.onDecision(ctx, d, err)
		}
	}
	return ds, err
}

func (w *Warden) checkEach(ctx context.Context, user, permission string, scopes []Scope) ([]Decision, error) {
	if len(scopes) > MaxCheckEach {
		return nil, invalidf("%d scopes in one CheckEach; the maximum is %d", len(scopes), MaxCheckEach)
	}
	if err := w.checkPermission(permission); err != nil {
		return nil, err
	}
	if err := validateID("user", user); err != nil {
		return nil, invalidf("%v", err)
	}
	for _, s := range scopes {
		if err := w.validateScope(s); err != nil {
			return nil, err
		}
	}
	if len(scopes) == 0 {
		return []Decision{}, ctx.Err()
	}
	// Scopes in a list usually share ancestors: remember parents and roles
	// for the length of this call, unless the caller already does.
	ctx = w.WithMemo(ctx)

	chains := make(map[Scope][]Scope, len(scopes))
	for _, s := range scopes {
		if _, done := chains[s]; done {
			continue
		}
		chain, err := w.chain(ctx, s)
		if err != nil {
			return nil, err
		}
		chains[s] = chain
	}
	// One set of cache counters per tenant.
	versions := map[Scope]*cacheVersions{}
	cvFor := func(chain []Scope) *cacheVersions {
		root := tenantRoot(chain)
		cv, seen := versions[root]
		if !seen {
			cv = w.versionsFor(ctx, chain)
			versions[root] = cv
		}
		return cv
	}

	found, err := w.assignmentsEach(ctx, user, chains, cvFor)
	if err != nil {
		return nil, err
	}

	ds := make([]Decision, len(scopes))
	for i, s := range scopes {
		gs, err := w.grantsFrom(ctx, user, chains[s], found[s], cvFor(chains[s]))
		if err != nil {
			return nil, err
		}
		ds[i] = evaluate(gs, Decision{User: user, Permission: permission, Scope: s})
	}
	return ds, nil
}

// assignmentsEach returns the user's assignments along each scope's chain.
// Scopes found in the request memo or the cache are not read again; the
// rest are read together, a batch of scopes per store call.
func (w *Warden) assignmentsEach(ctx context.Context, user string, chains map[Scope][]Scope,
	cvFor func([]Scope) *cacheVersions) (map[Scope][]Assignment, error) {
	out := make(map[Scope][]Assignment, len(chains))
	m := w.readMemo(ctx)
	var missing []Scope
	for s, chain := range chains {
		if m != nil {
			m.mu.Lock()
			as, hit := m.assignments[assignmentsKey{user: user, scope: s}]
			m.mu.Unlock()
			if hit {
				out[s] = as
				continue
			}
		}
		if cv := cvFor(chain); cv != nil {
			if b, ok := w.cacheGet(ctx, assignmentsCacheKey(user, s, cv)); ok {
				var as []Assignment
				if json.Unmarshal(b, &as) == nil {
					out[s] = as
					continue
				}
			}
		}
		missing = append(missing, s)
	}
	if len(missing) == 0 {
		return out, nil
	}
	slices.SortFunc(missing, func(a, b Scope) int { // deterministic queries
		return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.ID, b.ID))
	})

	var union []Scope
	seen := map[Scope]bool{}
	for _, s := range missing {
		for _, c := range chains[s] {
			if !seen[c] {
				seen[c] = true
				union = append(union, c)
			}
		}
	}
	byScope := map[Scope][]Assignment{}
	for batch := range slices.Chunk(union, assignmentsBatch) {
		as, err := w.store.Assignments(ctx, user, slices.Clone(batch))
		if err != nil {
			return nil, fmt.Errorf("wardn: loading assignments: %w", err)
		}
		for _, a := range as {
			if seen[a.Scope] { // never trust a store to filter correctly (T01)
				byScope[a.Scope] = append(byScope[a.Scope], a)
			}
		}
	}
	for _, s := range missing {
		var as []Assignment
		for _, c := range chains[s] {
			as = append(as, byScope[c]...)
		}
		out[s] = as
		if m != nil {
			m.mu.Lock()
			m.assignments[assignmentsKey{user: user, scope: s}] = as
			m.mu.Unlock()
		}
		if cv := cvFor(chains[s]); cv != nil {
			if b, err := json.Marshal(as); err == nil {
				w.cacheSet(ctx, assignmentsCacheKey(user, s, cv), b)
			}
		}
	}
	return out, nil
}
