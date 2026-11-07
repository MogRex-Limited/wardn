package wardnredis

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/cachetest"
)

// client connects to the Redis named by WARDN_TEST_REDIS_ADDR, or skips.
func client(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("WARDN_TEST_REDIS_ADDR")
	if addr == "" {
		if os.Getenv("WARDN_TEST_REQUIRE_ALL") != "" {
			t.Fatal("WARDN_TEST_REDIS_ADDR is not set, but WARDN_TEST_REQUIRE_ALL is")
		}
		t.Skip("set WARDN_TEST_REDIS_ADDR to run (make integration starts Redis)")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Fatalf("redis: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

var (
	runID = fmt.Sprintf("t%d", time.Now().UnixNano()%1_000_000_000)
	nsSeq atomic.Int64
)

// freshNamespace isolates each test on a shared server.
func freshNamespace() string { return fmt.Sprintf("%s-%d", runID, nsSeq.Add(1)) }

func TestConformance(t *testing.T) {
	rdb := client(t)
	cachetest.Run(t, func(*testing.T) wardn.Cache { return MustNew(rdb, freshNamespace()) })
}

func TestNew(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer rdb.Close() //nolint:errcheck // test client
	if _, err := New(nil, "app"); err == nil {
		t.Error("nil client accepted")
	}
	for _, ns := range []string{"", "App", "a b", "a:b", "a*", string(make([]byte, 65))} {
		if _, err := New(rdb, ns); err == nil {
			t.Errorf("namespace %q accepted", ns)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("MustNew did not panic")
		}
	}()
	MustNew(rdb, "")
}

func TestNamespacesAreIsolated(t *testing.T) {
	rdb := client(t)
	ctx := context.Background()
	a, b := MustNew(rdb, freshNamespace()), MustNew(rdb, freshNamespace())
	if err := a.Set(ctx, "k", []byte("a"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := a.Incr(ctx, []string{"c"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := b.Get(ctx, "k"); ok {
		t.Error("entry visible in another namespace")
	}
	if vs, _ := b.Counters(ctx, []string{"c"}); vs[0] != 0 {
		t.Error("counter visible in another namespace")
	}
}

func TestRedisDown(t *testing.T) {
	c := MustNew(redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 100 * time.Millisecond}), "down")
	ctx := context.Background()
	if _, _, err := c.Get(ctx, "k"); err == nil {
		t.Error("Get: no error")
	}
	if err := c.Set(ctx, "k", nil, time.Second); err == nil {
		t.Error("Set: no error")
	}
	if _, err := c.Counters(ctx, []string{"k"}); err == nil {
		t.Error("Counters: no error")
	}
	if err := c.Incr(ctx, []string{"k"}); err == nil {
		t.Error("Incr: no error")
	}
}

const policy = `
scopes:
  organisation: {}
  branch: { parent: organisation }
permissions:
  loan:create: Create loans
roles:
  teller:
    assignable_at: [branch]
    allow: [loan:create]
`

// TestTwoInstances: a revocation on one instance is seen at once by another
// instance sharing the Redis cache.
func TestTwoInstances(t *testing.T) {
	rdb := client(t)
	p, err := wardn.ParsePolicy([]byte(policy), "wardn.yaml")
	if err != nil {
		t.Fatal(err)
	}
	store, ns := wardn.NewMemoryStore(), freshNamespace()
	a := wardn.MustNew(wardn.Config{Policy: p, Store: store, Cache: MustNew(rdb, ns)})
	b := wardn.MustNew(wardn.Config{Policy: p, Store: store, Cache: MustNew(rdb, ns)})
	ctx := context.Background()
	branch := wardn.NewScope("branch", "b1")
	if err := a.Link(ctx, branch, wardn.NewScope("organisation", "o1")); err != nil {
		t.Fatal(err)
	}
	if err := a.System().Assign(ctx, "u", "teller", branch); err != nil {
		t.Fatal(err)
	}
	if !b.Can(ctx, "u", "loan:create", branch) {
		t.Fatal("instance B denied after A assigned")
	}
	if err := a.System().Revoke(ctx, "u", "teller", branch); err != nil {
		t.Fatal(err)
	}
	if b.Can(ctx, "u", "loan:create", branch) {
		t.Fatal("instance B still allowed after A revoked: stale cache")
	}
}
