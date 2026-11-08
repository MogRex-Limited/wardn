package wardn

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
)

// TxStore is a Store that can work inside the application's own database
// transaction, so a change to access commits or rolls back together with
// the application's other writes. The SQL store implements it
// (wardnsql.Store.WithTx).
type TxStore interface {
	Store
	// InTx reports whether ctx carries an application transaction that
	// this store will use instead of starting its own. A wrapper around a
	// TxStore must implement it too, by calling the wrapped store.
	InTx(ctx context.Context) bool
}

// ErrNoTransaction reports a change made with a context that carries an
// application transaction, but did not come from Warden.Transaction. wardn
// refuses it, because it could not keep its cache in step with the commit.
var ErrNoTransaction = errors.New("wardn: a change inside an application transaction needs a context from Warden.Transaction")

// txKey identifies one Warden's pending transaction in a context.
type txKey struct{ w *Warden }

// pendingTx collects the cache counters that changes made inside an
// application transaction invalidate, until the transaction ends.
type pendingTx struct {
	mu       sync.Mutex
	counters []string
	done     bool
}

// Transaction prepares ctx for wardn changes made inside the application's
// own database transaction. The context passed to those changes must also
// carry the transaction for the store (for the SQL store, Store.WithTx),
// added before or after Transaction. Call the returned function once the
// transaction has ended, whether it committed or rolled back, never
// before the commit:
//
//	tx, err := db.BeginTx(ctx, nil)
//	...
//	defer tx.Rollback()
//	ctx, ended := w.Transaction(store.WithTx(ctx, tx))
//	if err := w.Assign(ctx, "bayo", "teller", branch); err != nil { ... }
//	// ... the application's own writes, using tx ...
//	err = tx.Commit()
//	if endErr := ended(ctx); endErr != nil { ... log it ... }
//
// Inside the transaction, wardn reads through it, so it sees the
// transaction's own uncommitted writes, and it neither reads nor fills
// the cache or the request memo: uncommitted data must never reach other
// requests. The cache is invalidated before each change and again when
// ended is called, so no instance serves the old state once the
// transaction has committed. If ended fails, other instances may serve
// the old state for up to the cache TTL (ErrCacheInvalidation).
//
// A change made with a transaction context that did not come from
// Transaction fails with ErrNoTransaction, so a forgotten call cannot
// silently leave the cache stale.
func (w *Warden) Transaction(ctx context.Context) (context.Context, func(context.Context) error) {
	p := &pendingTx{}
	ctx = context.WithValue(ctx, txKey{w}, p)
	return ctx, func(ctx context.Context) error { return w.endTx(ctx, p) }
}

func (w *Warden) pendingFrom(ctx context.Context) *pendingTx {
	p, _ := ctx.Value(txKey{w}).(*pendingTx)
	return p
}

// inAppTx reports whether ctx carries an application transaction for the
// store.
func (w *Warden) inAppTx(ctx context.Context) bool {
	ts, ok := w.store.(TxStore)
	return ok && ts.InTx(ctx)
}

// uncommitted reports whether reads with ctx may see data that is not yet
// committed: the store says ctx carries a transaction, or ctx came from
// Transaction. The second covers a store wrapper that hides InTx.
func (w *Warden) uncommitted(ctx context.Context) bool {
	return w.inAppTx(ctx) || w.pendingFrom(ctx) != nil
}

// readsCache reports whether reads with ctx may use the shared cache.
func (w *Warden) readsCache(ctx context.Context) bool {
	return w.cache != nil && !w.uncommitted(ctx)
}

// readMemo returns the request memo that reads with ctx may use: none
// inside an application transaction, whose data is not yet committed.
func (w *Warden) readMemo(ctx context.Context) *memo {
	if w.uncommitted(ctx) {
		return nil
	}
	return w.memoFrom(ctx)
}

// add records counters to invalidate when the transaction ends. It
// reports false if the transaction has already ended.
func (p *pendingTx) add(counters []string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return false
	}
	p.counters = append(p.counters, counters...)
	return true
}

func (w *Warden) endTx(ctx context.Context, p *pendingTx) error {
	p.mu.Lock()
	counters := slices.Compact(slices.Sorted(slices.Values(p.counters)))
	p.counters, p.done = nil, true
	p.mu.Unlock()
	// The transaction may have changed what this request remembers.
	w.memoFrom(ctx).forget()
	if w.cache == nil || len(counters) == 0 {
		return nil
	}
	if err := w.cache.Incr(ctx, counters); err != nil {
		return fmt.Errorf("%w (transaction): %w", ErrCacheInvalidation, err)
	}
	return nil
}
