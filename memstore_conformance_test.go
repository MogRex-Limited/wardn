package wardn_test

import (
	"testing"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/storetest"
)

func TestMemoryStoreConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) wardn.Store { return wardn.NewMemoryStore() })
}
