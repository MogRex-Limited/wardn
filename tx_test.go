package wardn

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"
)

// txStore is a TxStore over a MemoryStore. A transaction stages assigns and
// revokes; reads in the transaction see them, other reads see only what
// was committed. It is enough to test what wardn does around commits.
type txStore struct {
	*MemoryStore
}

type stagedTx struct {
	mu  sync.Mutex
	ops []Assignment // an op with Role prefixed by "-" is a revoke
}

type stagedTxKey struct{}

func (s *txStore) begin(ctx context.Context) (context.Context, *stagedTx) {
	tx := &stagedTx{}
	return context.WithValue(ctx, stagedTxKey{}, tx), tx
}

func txOf(ctx context.Context) *stagedTx {
	tx, _ := ctx.Value(stagedTxKey{}).(*stagedTx)
	return tx
}

func (s *txStore) InTx(ctx context.Context) bool { return txOf(ctx) != nil }

func (s *txStore) commit(tx *stagedTx) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	ctx := context.Background()
	for _, op := range tx.ops {
		var err error
		if role, revoke := revokeRole(op.Role); revoke {
			err = s.MemoryStore.Revoke(ctx, op.User, role, op.Scope)
		} else {
			err = s.MemoryStore.Assign(ctx, op)
		}
		if err != nil {
			return err
		}
	}
	tx.ops = nil
	return nil
}

func revokeRole(r string) (string, bool) {
	if len(r) > 0 && r[0] == '-' {
		return r[1:], true
	}
	return r, false
}

func (s *txStore) Assign(ctx context.Context, a Assignment) error {
	if tx := txOf(ctx); tx != nil {
		tx.mu.Lock()
		tx.ops = append(tx.ops, a)
		tx.mu.Unlock()
		return nil
	}
	return s.MemoryStore.Assign(ctx, a)
}

func (s *txStore) Revoke(ctx context.Context, user, role string, scope Scope) error {
	if tx := txOf(ctx); tx != nil {
		tx.mu.Lock()
		tx.ops = append(tx.ops, Assignment{User: user, Role: "-" + role, Scope: scope})
		tx.mu.Unlock()
		return nil
	}
	return s.MemoryStore.Revoke(ctx, user, role, scope)
}

func (s *txStore) Assignments(ctx context.Context, user string, scopes []Scope) ([]Assignment, error) {
	as, err := s.MemoryStore.Assignments(ctx, user, scopes)
	tx := txOf(ctx)
	if err != nil || tx == nil {
		return as, err
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()
	for _, op := range tx.ops {
		if op.User != user || !slices.Contains(scopes, op.Scope) {
			continue
		}
		role, revoke := revokeRole(op.Role)
		as = slices.DeleteFunc(as, func(a Assignment) bool { return a.Role == role && a.Scope == op.Scope })
		if !revoke {
			as = append(as, op)
		}
	}
	return as, nil
}

var _ TxStore = (*txStore)(nil)

// countingCache counts reads and writes of cache entries.
type countingCache struct {
	*MemoryCache
	mu               sync.Mutex
	gets, sets, incr int
}

func (c *countingCache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	c.mu.Lock()
	c.gets++
	c.mu.Unlock()
	return c.MemoryCache.Get(ctx, key)
}

func (c *countingCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	c.mu.Lock()
	c.sets++
	c.mu.Unlock()
	return c.MemoryCache.Set(ctx, key, value, ttl)
}

func (c *countingCache) Incr(ctx context.Context, keys []string) error {
	c.mu.Lock()
	c.incr++
	c.mu.Unlock()
	return c.MemoryCache.Incr(ctx, keys)
}

func (c *countingCache) counts() (gets, sets, incr int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gets, c.sets, c.incr
}

func newTxBank(t *testing.T, mod ...func(*Config)) (*Warden, *txStore) {
	t.Helper()
	s := &txStore{MemoryStore: NewMemoryStore()}
	w, _ := newBank(t, append([]func(*Config){func(c *Config) { c.Store = s }}, mod...)...)
	return w, s
}

func TestTransactionCommitsWithTheApplication(t *testing.T) {
	w, s := newTxBank(t)
	bg := context.Background()
	txCtx, tx := s.begin(bg)
	ctx, ended := w.Transaction(txCtx)
	if err := w.System().Assign(ctx, "bayo", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	if !w.Can(ctx, "bayo", "loan:create", branch1) {
		t.Error("the transaction does not see its own change")
	}
	wantCan(t, w, "bayo", "loan:create", branch1, false) // not committed yet
	if err := s.commit(tx); err != nil {
		t.Fatal(err)
	}
	if err := ended(ctx); err != nil {
		t.Fatal(err)
	}
	wantCan(t, w, "bayo", "loan:create", branch1, true)
}

func TestTransactionRollbackLeavesNothing(t *testing.T) {
	w, s := newTxBank(t)
	txCtx, _ := s.begin(context.Background())
	ctx, ended := w.Transaction(txCtx)
	if err := w.System().Assign(ctx, "bayo", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	// Roll back: drop the transaction without committing.
	if err := ended(ctx); err != nil {
		t.Fatal(err)
	}
	wantCan(t, w, "bayo", "loan:create", branch1, false)
}

func TestTransactionIsRequiredForChangesInAnAppTransaction(t *testing.T) {
	var audited int
	w, s := newTxBank(t, func(c *Config) {
		c.OnChange = func(context.Context, Event) error { audited++; return nil }
	})
	audited = 0 // the setup links were audited
	txCtx, tx := s.begin(context.Background())
	sys := w.System()
	for name, change := range map[string]func() error{
		"assign": func() error { return sys.Assign(txCtx, "bayo", "teller", branch1) },
		"revoke": func() error { return sys.Revoke(txCtx, "bayo", "teller", branch1) },
	} {
		if err := change(); !errors.Is(err, ErrNoTransaction) {
			t.Errorf("%s without Warden.Transaction: %v, want ErrNoTransaction", name, err)
		}
	}
	if audited != 0 || len(tx.ops) != 0 {
		t.Errorf("refused changes still reached the audit hook (%d) or the store (%d)", audited, len(tx.ops))
	}

	// The other way round: a Transaction context without the store's
	// transaction would write outside it, silently.
	ctx, _ := w.Transaction(context.Background())
	if err := sys.Assign(ctx, "bayo", "teller", branch1); !errors.Is(err, ErrNoTransaction) {
		t.Errorf("Transaction without a store transaction: %v, want ErrNoTransaction", err)
	}
	wantCan(t, w, "bayo", "loan:create", branch1, false)
}

// TestThreat_T28_UncommittedAccessNeverCached: reads inside an application
// transaction see uncommitted data. If they filled the shared cache or the
// request memo, other requests could use access that is later rolled back,
// or keep old access after the commit.
func TestThreat_T28_UncommittedAccessNeverCached(t *testing.T) {
	cache := &countingCache{MemoryCache: NewMemoryCache()}
	w, s := newTxBank(t, func(c *Config) { c.Cache = cache })
	bg := w.WithMemo(context.Background())

	// Another request has cached "no access".
	wantCan(t, w, "bayo", "loan:create", branch1, false)

	txCtx, _ := s.begin(bg) // rolled back: never committed
	ctx, ended := w.Transaction(txCtx)
	if err := w.System().Assign(ctx, "bayo", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	gets, sets, _ := cache.counts()
	for range 3 {
		if !w.Can(ctx, "bayo", "loan:create", branch1) {
			t.Fatal("the transaction does not see its own change")
		}
	}
	if g, st, _ := cache.counts(); g != gets || st != sets {
		t.Errorf("checks inside the transaction used the cache: %d gets, %d sets", g-gets, st-sets)
	}
	// The same request, outside the transaction, before it ends.
	if w.Can(bg, "bayo", "loan:create", branch1) {
		t.Fatal("uncommitted access leaked into the request memo")
	}

	// Rolled back: nobody may see the access, from the cache or the memo.
	if err := ended(ctx); err != nil {
		t.Fatal(err)
	}
	if w.Can(bg, "bayo", "loan:create", branch1) {
		t.Fatal("access from a rolled-back transaction leaked through the memo or cache")
	}
	wantCan(t, w, "bayo", "loan:create", branch1, false)

	// Committed: the old "no access" in the cache must not survive.
	txCtx, tx := s.begin(bg)
	ctx, ended = w.Transaction(txCtx)
	if err := w.System().Assign(ctx, "bayo", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	wantCan(t, w, "bayo", "loan:create", branch1, false) // re-caches the committed state
	if w.Can(bg, "bayo", "loan:create", branch1) {       // and re-memoises it
		t.Fatal("uncommitted access leaked into the request memo")
	}
	if err := s.commit(tx); err != nil {
		t.Fatal(err)
	}
	if err := ended(ctx); err != nil {
		t.Fatal(err)
	}
	wantCan(t, w, "bayo", "loan:create", branch1, true)
	if !w.Can(bg, "bayo", "loan:create", branch1) {
		t.Error("the request memo kept the state from before the transaction")
	}
}

func TestTransactionEndedTwiceAndLateChanges(t *testing.T) {
	cache := &countingCache{MemoryCache: NewMemoryCache()}
	w, s := newTxBank(t, func(c *Config) { c.Cache = cache })
	txCtx, tx := s.begin(context.Background())
	ctx, ended := w.Transaction(txCtx)
	if err := ended(ctx); err != nil {
		t.Fatal(err)
	}
	// A change after ended can no longer wait for the end: it is
	// invalidated straight away.
	_, _, before := cache.counts()
	if err := w.System().Assign(ctx, "bayo", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	if _, _, after := cache.counts(); after-before != 2 {
		t.Errorf("late change invalidated %d times, want before and after the write", after-before)
	}
	if err := s.commit(tx); err != nil {
		t.Fatal(err)
	}
	if err := ended(ctx); err != nil {
		t.Errorf("second ended: %v", err)
	}
}

func TestSweepRefusesAnAppTransaction(t *testing.T) {
	w, s := newTxBank(t)
	txCtx, _ := s.begin(context.Background())
	ctx, _ := w.Transaction(txCtx)
	if _, err := w.SweepExpired(ctx); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("SweepExpired in a transaction: %v, want ErrInvalidInput", err)
	}
}

func TestTransactionEndReportsCacheFailure(t *testing.T) {
	cache := &failingIncrCache{MemoryCache: NewMemoryCache()}
	w, s := newTxBank(t, func(c *Config) { c.Cache = cache })
	txCtx, tx := s.begin(context.Background())
	ctx, ended := w.Transaction(txCtx)
	if err := w.System().Assign(ctx, "bayo", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	if err := s.commit(tx); err != nil {
		t.Fatal(err)
	}
	cache.fail = true
	if err := ended(ctx); !errors.Is(err, ErrCacheInvalidation) {
		t.Errorf("ended with a failing cache: %v, want ErrCacheInvalidation", err)
	}
}

type failingIncrCache struct {
	*MemoryCache
	fail bool
}

func (c *failingIncrCache) Incr(ctx context.Context, keys []string) error {
	if c.fail {
		return errStore
	}
	return c.MemoryCache.Incr(ctx, keys)
}

// hidingStore wraps a TxStore without passing InTx on, as an application's
// metrics wrapper that embeds wardn.Store would.
type hidingStore struct{ Store }

// TestThreat_T28_WrapperHidingInTx: even when a store wrapper hides InTx,
// reads with a context from Transaction never touch the cache, and changes
// fail instead of writing outside wardn's knowledge.
func TestThreat_T28_WrapperHidingInTx(t *testing.T) {
	inner := &txStore{MemoryStore: NewMemoryStore()}
	cache := &countingCache{MemoryCache: NewMemoryCache()}
	w, _ := newBank(t, func(c *Config) { c.Store, c.Cache = hidingStore{inner}, cache })
	txCtx, tx := inner.begin(context.Background())
	ctx, _ := w.Transaction(txCtx)
	tx.ops = append(tx.ops, Assignment{User: "bayo", Role: "teller", Scope: branch1}) // written by the app
	gets, sets, _ := cache.counts()
	if !w.Can(ctx, "bayo", "loan:create", branch1) {
		t.Fatal("the transaction does not see its own change")
	}
	if g, st, _ := cache.counts(); g != gets || st != sets {
		t.Errorf("transaction reads used the cache through a wrapper: %d gets, %d sets", g-gets, st-sets)
	}
	wantCan(t, w, "bayo", "loan:create", branch1, false)
	if err := w.System().Assign(ctx, "kemi", "teller", branch1); !errors.Is(err, ErrNoTransaction) {
		t.Errorf("change through a wrapper hiding InTx: %v, want ErrNoTransaction", err)
	}
}
