package integration

import (
	"testing"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/storetest"
)

// BenchmarkSQL measures checks on a bank-sized dataset in every configured
// database (SQLite always; the servers when their settings are set, as
// make bench-all does). See storetest.Bench.
func BenchmarkSQL(b *testing.B) {
	for _, d := range databases(b) {
		b.Run(d.name, func(b *testing.B) {
			storetest.Bench(b, func(b *testing.B) wardn.Store {
				db := d.open(b)
				// As a production service should: database/sql keeps only 2
				// idle connections by default, so parallel checks would keep
				// opening new ones (costly on PostgreSQL).
				db.SetMaxIdleConns(32)
				return newStore(b, db)
			})
		})
	}
}
