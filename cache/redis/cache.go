// Package wardnredis is a wardn.Cache backed by Redis (or Valkey), shared by
// every instance of the application, so a change made on one instance is
// seen by all of them on the next request.
//
//	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379", Password: ...})
//	w := wardn.MustNew(wardn.Config{
//		File:  "wardn.yaml",
//		Store: wardnsql.MustNew(db),
//		Cache: wardnredis.MustNew(rdb, "lending-app"),
//	})
//
// The Redis server must be private to the application, with authentication
// and TLS: anyone who can write to it can change what wardn reads (threat
// model T24). The namespace keeps applications that share a server apart.
package wardnredis

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/MogRex-Limited/wardn"
)

// Cache is a wardn.Cache stored in Redis.
type Cache struct {
	rdb       redis.UniversalClient
	entries   string // key prefix for cached entries
	counters  string // key prefix for version counters
	namespace string
}

// New returns a Cache using rdb. namespace identifies the application; two
// applications sharing a Redis server must use different namespaces. It is
// 1–64 characters: lowercase letters, digits, '-' and '_'.
func New(rdb redis.UniversalClient, namespace string) (*Cache, error) {
	if rdb == nil {
		return nil, errors.New("wardnredis: client is nil")
	}
	if !validNamespace(namespace) {
		return nil, fmt.Errorf("wardnredis: invalid namespace %q: use 1-64 lowercase letters, digits, '-' and '_'", namespace)
	}
	p := "wardn:" + namespace + ":"
	return &Cache{rdb: rdb, entries: p + "e:", counters: p + "c:", namespace: namespace}, nil
}

// MustNew is like New but panics on error, for use in main().
func MustNew(rdb redis.UniversalClient, namespace string) *Cache {
	c, err := New(rdb, namespace)
	if err != nil {
		panic(err)
	}
	return c
}

func validNamespace(ns string) bool {
	if ns == "" || len(ns) > 64 {
		return false
	}
	for i := 0; i < len(ns); i++ {
		c := ns[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// Get implements wardn.Cache.
func (c *Cache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	v, err := c.rdb.Get(ctx, c.entries+key).Bytes()
	switch {
	case errors.Is(err, redis.Nil):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("wardnredis: get: %w", err)
	}
	return v, true, nil
}

// Set implements wardn.Cache.
func (c *Cache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ttl = max(ttl, time.Millisecond) // Redis needs a positive expiry; never store forever
	if err := c.rdb.Set(ctx, c.entries+key, value, ttl).Err(); err != nil {
		return fmt.Errorf("wardnredis: set: %w", err)
	}
	return nil
}

// Counters implements wardn.Cache.
func (c *Cache) Counters(ctx context.Context, keys []string) ([]uint64, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return []uint64{}, nil
	}
	full := make([]string, len(keys))
	for i, k := range keys {
		full[i] = c.counters + k
	}
	vals, err := c.rdb.MGet(ctx, full...).Result()
	if err != nil {
		return nil, fmt.Errorf("wardnredis: counters: %w", err)
	}
	// Treat the reply as untrusted: a malformed one is an error, never a panic.
	if len(vals) != len(keys) {
		return nil, fmt.Errorf("wardnredis: counters: asked for %d values, got %d", len(keys), len(vals))
	}
	out := make([]uint64, len(keys))
	for i, key := range keys {
		v := vals[i]
		if v == nil {
			continue
		}
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("wardnredis: counter %s has an unexpected type", key)
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("wardnredis: counter %s is not a number", key)
		}
		out[i] = n
	}
	return out, nil
}

// Incr implements wardn.Cache. Each INCR is atomic in Redis; the keys are
// sent in one transaction so either all are incremented or none.
func (c *Cache) Incr(ctx context.Context, keys []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}
	_, err := c.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		for _, k := range keys {
			p.Incr(ctx, c.counters+k)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("wardnredis: incr: %w", err)
	}
	return nil
}

var _ wardn.Cache = (*Cache)(nil)
