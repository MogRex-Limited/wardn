package wardn

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Cache is an optional cache shared across requests, and across instances
// of the application when the implementation is shared (Redis, for
// example). It is off by default (design decision D1).
//
// wardn caches what it reads from the store (assignments, scope parents,
// custom roles), never decisions: every check is still evaluated, against
// the clock, so time-limited access starts and ends on time however long
// an entry is cached. Entries are invalidated by version counters: every
// cache key includes the current counters of the tenant it belongs to, and
// every change increments them before and after writing, so stale entries
// become unreachable everywhere at once. The TTL is only a safety net, for
// changes made directly in the database, bypassing wardn.
//
// Implementations must be safe for concurrent use and must keep Incr
// atomic. Keys are opaque, fixed-length hashes; wardn validates everything
// it reads back. A shared cache must be private to the application
// (threat model T24).
type Cache interface {
	// Get returns the value stored under key, and false if there is none
	// or it has expired.
	Get(ctx context.Context, key string) ([]byte, bool, error)
	// Set stores value under key for ttl.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// Counters returns the current values of counters; a counter that has
	// never been incremented is 0. Counters never expire.
	Counters(ctx context.Context, keys []string) ([]uint64, error)
	// Incr atomically increments each counter by one.
	Incr(ctx context.Context, keys []string) error
}

// DefaultCacheTTL is how long cache entries live when Config.CacheTTL is 0.
const DefaultCacheTTL = 5 * time.Second

// maxCacheTTL bounds Config.CacheTTL: the TTL is the longest a change made
// behind wardn's back can go unnoticed.
const maxCacheTTL = 5 * time.Minute

// ErrCacheInvalidation reports that a change was saved, but invalidating
// the cache afterwards failed: other instances may serve the old state for
// up to the cache TTL. Retrying the (idempotent) change is safe.
var ErrCacheInvalidation = errors.New("wardn: change saved, but invalidating the cache failed")

// Counter keys.
const (
	counterLinks  = "v:links"  // any scope link
	counterGlobal = "v:global" // anything at the Global scope
)

// counterTenant is the counter of everything under one top-level scope.
func counterTenant(root Scope) string {
	if root.IsGlobal() {
		return counterGlobal
	}
	return "v:t:" + cacheKey("tenant", root)
}

// cacheKey derives a fixed-length key from structured parts. Hashing keeps
// IDs out of the cache (they may be personal data) and makes keys immune to
// separator injection (threat model T13, T24).
func cacheKey(kind string, parts ...any) string {
	b, err := json.Marshal(append([]any{kind}, parts...))
	if err != nil {
		panic(err) // parts are strings, scopes and integers
	}
	sum := sha256.Sum256(b)
	return kind + ":" + hex.EncodeToString(sum[:20])
}

// tenantRoot returns the top-level scope of a chain (Global for Global).
func tenantRoot(chain []Scope) Scope {
	if len(chain) < 2 {
		return Global
	}
	return chain[len(chain)-2] // the last element is Global
}

// cacheVersions are the counters a request's cache keys depend on.
type cacheVersions struct {
	tenant, global uint64
	root           Scope
}

// versionsFor reads the counters for a chain, or nil when there is no cache
// or reading them failed (then the store is used directly).
func (w *Warden) versionsFor(ctx context.Context, chain []Scope) *cacheVersions {
	if w.cache == nil {
		return nil
	}
	root := tenantRoot(chain)
	vs, err := w.cache.Counters(ctx, []string{counterTenant(root), counterGlobal})
	if err != nil || len(vs) != 2 {
		return nil
	}
	return &cacheVersions{tenant: vs[0], global: vs[1], root: root}
}

// minCacheSecret is the minimum length of Config.CacheSecret.
const minCacheSecret = 32

// Every cached value is sealed with an HMAC over its key and its content,
// so whoever can write to a shared cache still cannot forge an entry or
// move one to another key (threat model T24). Values that fail
// verification are misses.

func (w *Warden) seal(key string, value []byte) []byte {
	mac := hmac.New(sha256.New, w.cacheSecret)
	mac.Write([]byte(key))
	mac.Write([]byte{0})
	mac.Write(value)
	return append(mac.Sum(nil), value...)
}

func (w *Warden) unseal(key string, sealed []byte) ([]byte, bool) {
	if len(sealed) < sha256.Size {
		return nil, false
	}
	tag, value := sealed[:sha256.Size], sealed[sha256.Size:]
	mac := hmac.New(sha256.New, w.cacheSecret)
	mac.Write([]byte(key))
	mac.Write([]byte{0})
	mac.Write(value)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return nil, false
	}
	return value, true
}

// cacheGet returns the verified value under key.
func (w *Warden) cacheGet(ctx context.Context, key string) ([]byte, bool) {
	b, ok, err := w.cache.Get(ctx, key)
	if err != nil || !ok {
		return nil, false
	}
	return w.unseal(key, b)
}

func (w *Warden) cacheSet(ctx context.Context, key string, value []byte) {
	_ = w.cache.Set(ctx, key, w.seal(key, value), w.cacheTTL)
}

// cached returns the value under key, or loads, stores and returns it. Any
// cache failure, or a value that fails verification or does not decode,
// falls back to load: the cache can make wardn faster, never wrong.
func cached[T any](ctx context.Context, w *Warden, key string, load func() (T, error)) (T, error) {
	if b, ok := w.cacheGet(ctx, key); ok {
		var v T
		if json.Unmarshal(b, &v) == nil {
			return v, nil
		}
	}
	v, err := load()
	if err != nil {
		return v, err
	}
	if b, err := json.Marshal(v); err == nil {
		w.cacheSet(ctx, key, b)
	}
	return v, nil
}

// cachedParent is a parent lookup result in cacheable form.
type cachedParent struct {
	Parent Scope `json:"parent"`
	OK     bool  `json:"ok"`
}

// countersFor returns the counters a change invalidates.
func (w *Warden) countersFor(ctx context.Context, ev Event) ([]string, error) {
	if w.cache == nil {
		return nil, nil
	}
	rootOf := func(s Scope) (string, error) {
		chain, err := w.chain(ctx, s)
		if err != nil {
			return "", err
		}
		return counterTenant(tenantRoot(chain)), nil
	}
	switch ev.Type {
	case EventLinked:
		// The child moves from its old tenant to the parent's: both change,
		// and so does every cached parent lookup.
		oldRoot, err := rootOf(ev.Scope)
		if err != nil {
			return nil, err
		}
		newRoot, err := rootOf(ev.Parent)
		if err != nil {
			return nil, err
		}
		return []string{counterLinks, oldRoot, newRoot}, nil
	case EventAssigned, EventRevoked, EventExpired, EventRoleCreated, EventRoleUpdated, EventRoleDeleted:
		root, err := rootOf(ev.Scope)
		if err != nil {
			return nil, err
		}
		return []string{root}, nil
	}
	return nil, nil
}

// InvalidateCache makes cached data for the tenants of the given scopes
// stale on every instance. wardn invalidates automatically after its own
// changes; call this after changing scope parents behind its back (when
// Config.ParentOf reads them from your data) or editing wardn's tables
// directly.
func (w *Warden) InvalidateCache(ctx context.Context, scopes ...Scope) error {
	if w.cache == nil {
		return nil
	}
	keys := []string{counterLinks}
	for _, s := range scopes {
		if err := w.validateScope(s); err != nil {
			return err
		}
		chain, err := w.chain(ctx, s)
		if err != nil {
			return err
		}
		keys = append(keys, counterTenant(tenantRoot(chain)))
	}
	if err := w.cache.Incr(ctx, keys); err != nil {
		return fmt.Errorf("wardn: invalidating cache: %w", err)
	}
	return nil
}

// cacheSecretFor returns the secret that seals cache values.
func cacheSecretFor(cache Cache, secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		if _, private := cache.(*MemoryCache); private {
			// Nobody outside this process can write to it: a random secret
			// is enough.
			b := make([]byte, minCacheSecret)
			if _, err := rand.Read(b); err != nil {
				return nil, fmt.Errorf("wardn: generating cache secret: %w", err)
			}
			return b, nil
		}
		return nil, errors.New("wardn: a shared Cache needs Config.CacheSecret: at least 32 random bytes, the same on every instance, so cache entries cannot be forged")
	}
	if len(secret) < minCacheSecret {
		return nil, fmt.Errorf("wardn: Config.CacheSecret must be at least %d bytes", minCacheSecret)
	}
	return append([]byte(nil), secret...), nil
}

// MemoryCache is a Cache held in this process. It is correct only when a
// single instance of the application runs: other instances would not see
// its invalidations. Use a shared cache (wardn/cache/redis) when you run
// more than one.
type MemoryCache struct {
	mu         sync.Mutex
	entries    map[string]memEntry
	counters   map[string]uint64
	maxEntries int
	now        func() time.Time
}

type memEntry struct {
	value   []byte
	expires time.Time
}

// MemoryCacheOption configures a MemoryCache.
type MemoryCacheOption func(*MemoryCache)

// WithMaxEntries bounds the number of cached entries (default 100 000).
func WithMaxEntries(n int) MemoryCacheOption {
	return func(c *MemoryCache) { c.maxEntries = n }
}

// WithCacheClock sets the clock used for entry expiry, for tests.
func WithCacheClock(now func() time.Time) MemoryCacheOption {
	return func(c *MemoryCache) { c.now = now }
}

// NewMemoryCache returns an empty MemoryCache.
func NewMemoryCache(opts ...MemoryCacheOption) *MemoryCache {
	c := &MemoryCache{entries: map[string]memEntry{}, counters: map[string]uint64{}, maxEntries: 100_000, now: time.Now}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Get implements Cache.
func (c *MemoryCache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !c.now().Before(e.expires) {
		delete(c.entries, key)
		return nil, false, nil
	}
	return append([]byte(nil), e.value...), true, nil
}

// Set implements Cache.
func (c *MemoryCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.entries) >= c.maxEntries {
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.maxEntries {
			clear(c.entries) // simple and always safe: the cache is only an optimisation
		}
	}
	c.entries[key] = memEntry{value: append([]byte(nil), value...), expires: now.Add(ttl)}
	return nil
}

// Counters implements Cache.
func (c *MemoryCache) Counters(ctx context.Context, keys []string) ([]uint64, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]uint64, len(keys))
	for i, k := range keys {
		out[i] = c.counters[k]
	}
	return out, nil
}

// Incr implements Cache.
func (c *MemoryCache) Incr(ctx context.Context, keys []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range keys {
		c.counters[k]++
	}
	return nil
}
