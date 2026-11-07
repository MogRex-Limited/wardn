// Package cachetest is the conformance suite for wardn.Cache
// implementations:
//
//	func TestMyCache(t *testing.T) {
//		cachetest.Run(t, func(t *testing.T) wardn.Cache { return mycache.New(...) })
//	}
package cachetest

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/MogRex-Limited/wardn"
)

// Run runs the suite. newCache must return a new, empty cache each time.
// Some tests wait for entries to expire, so the suite takes about a second.
func Run(t *testing.T, newCache func(t *testing.T) wardn.Cache) {
	t.Helper()
	for _, tt := range []struct {
		name string
		fn   func(*testing.T, wardn.Cache)
	}{
		{"GetSet", testGetSet},
		{"BinaryValues", testBinary},
		{"Expiry", testExpiry},
		{"Counters", testCounters},
		{"CountersAreAtomic", testCountersAtomic},
		{"CanceledContext", testCanceled},
	} {
		t.Run(tt.name, func(t *testing.T) { tt.fn(t, newCache(t)) })
	}
}

func testGetSet(t *testing.T, c wardn.Cache) {
	ctx := context.Background()
	if _, ok, err := c.Get(ctx, "k1"); err != nil || ok {
		t.Fatalf("missing key: ok=%v err=%v", ok, err)
	}
	if err := c.Set(ctx, "k1", []byte("one"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := c.Set(ctx, "k2", []byte("two"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := c.Get(ctx, "k1"); err != nil || !ok || string(v) != "one" {
		t.Fatalf("Get(k1) = %q, %v, %v", v, ok, err)
	}
	if err := c.Set(ctx, "k1", []byte("uno"), time.Minute); err != nil {
		t.Fatal(err)
	}
	v, _, _ := c.Get(ctx, "k1")
	if string(v) != "uno" {
		t.Fatalf("overwrite: %q", v)
	}
	v[0] = 'X' // the returned slice must be the caller's own
	if v2, _, _ := c.Get(ctx, "k1"); string(v2) != "uno" {
		t.Fatalf("returned value aliases the cache: %q", v2)
	}
	if v, _, _ := c.Get(ctx, "k2"); string(v) != "two" {
		t.Fatalf("keys interfere: %q", v)
	}
}

func testBinary(t *testing.T, c wardn.Cache) {
	ctx := context.Background()
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	if err := c.Set(ctx, "bin", all, time.Minute); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := c.Get(ctx, "bin"); err != nil || !ok || !bytes.Equal(v, all) {
		t.Fatalf("binary value did not round-trip: %v %v", ok, err)
	}
	if err := c.Set(ctx, "empty", []byte{}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := c.Get(ctx, "empty"); err != nil || !ok || len(v) != 0 {
		t.Fatalf("empty value: %q %v %v", v, ok, err)
	}
}

func testExpiry(t *testing.T, c wardn.Cache) {
	ctx := context.Background()
	if err := c.Set(ctx, "short", []byte("x"), 150*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := c.Incr(ctx, []string{"counter"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if _, ok, err := c.Get(ctx, "short"); err != nil || ok {
		t.Fatalf("entry outlived its TTL: ok=%v err=%v", ok, err)
	}
	if vs, err := c.Counters(ctx, []string{"counter"}); err != nil || vs[0] != 1 {
		t.Fatalf("counters must not expire: %v %v", vs, err)
	}
}

func testCounters(t *testing.T, c wardn.Cache) {
	ctx := context.Background()
	vs, err := c.Counters(ctx, []string{"a", "b"})
	if err != nil || len(vs) != 2 || vs[0] != 0 || vs[1] != 0 {
		t.Fatalf("new counters = %v, %v", vs, err)
	}
	if err := c.Incr(ctx, []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Incr(ctx, []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if vs, _ := c.Counters(ctx, []string{"b", "a", "c"}); vs[0] != 1 || vs[1] != 2 || vs[2] != 0 {
		t.Fatalf("counters = %v, want [1 2 0]", vs)
	}
	if err := c.Incr(ctx, nil); err != nil {
		t.Fatalf("Incr(nil): %v", err)
	}
	if vs, err := c.Counters(ctx, nil); err != nil || len(vs) != 0 {
		t.Fatalf("Counters(nil) = %v, %v", vs, err)
	}
	// Counters and entries are separate: setting an entry with a counter's
	// name must not reset the counter.
	if err := c.Set(ctx, "entry", []byte("1"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if vs, _ := c.Counters(ctx, []string{"entry"}); vs[0] != 0 {
		t.Fatalf("entry and counter share storage: %v", vs)
	}
}

func testCountersAtomic(t *testing.T, c wardn.Cache) {
	ctx := context.Background()
	const workers, each = 16, 50
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				if err := c.Incr(ctx, []string{"hot"}); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if vs, _ := c.Counters(ctx, []string{"hot"}); vs[0] != workers*each {
		t.Fatalf("counter = %d after %d concurrent increments; increments were lost", vs[0], workers*each)
	}
}

func testCanceled(t *testing.T, c wardn.Cache) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, getErr := c.Get(ctx, "k")
	_, countersErr := c.Counters(ctx, []string{"k"})
	for name, err := range map[string]error{
		"Get":      getErr,
		"Set":      c.Set(ctx, "k", []byte("v"), time.Minute),
		"Counters": countersErr,
		"Incr":     c.Incr(ctx, []string{"k"}),
	} {
		if err == nil {
			t.Errorf("%s ignored a canceled context", name)
		}
	}
	if vs, _ := c.Counters(context.Background(), []string{"k"}); vs[0] != 0 {
		t.Errorf("Incr with a canceled context still incremented: %v", vs)
	}
}
