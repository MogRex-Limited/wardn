package wardn_test

import (
	"testing"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/cachetest"
	"github.com/MogRex-Limited/wardn/storetest"
)

func TestMemoryStoreConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) wardn.Store { return wardn.NewMemoryStore() })
}

func TestMemoryCacheConformance(t *testing.T) {
	cachetest.Run(t, func(*testing.T) wardn.Cache { return wardn.NewMemoryCache() })
}

// BenchmarkMemoryStore measures checks on a bank-sized dataset; see
// storetest.Bench. Run with: go test -run '^$' -bench . (or make bench).
func BenchmarkMemoryStore(b *testing.B) {
	storetest.Bench(b, func(*testing.B) wardn.Store { return wardn.NewMemoryStore() })
}
