package main

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MogRex-Limited/wardn/examples/internal/demo"
)

// BenchmarkRequest measures whole HTTP requests through the bank's router,
// and the same handler routed without wardn, so the difference is what
// authorization costs a request (with wardn's in-memory store; see
// storetest.Bench for databases).
func BenchmarkRequest(b *testing.B) {
	bk := newBank(b)
	for range 3 {
		bk.newLoan("bayo")
	}
	loan := bk.newLoan("bayo")

	// The same handler, authentication and data, with no authorization.
	plain := chi.NewRouter()
	plain.Use(demo.Auth)
	plain.Get("/branches/{branchID}/loans", bk.app.listLoans)
	unprotected := &bank{t: b, h: plain, w: bk.w}

	run := func(c *bank, user, method, path string, status int) func(b *testing.B) {
		return func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if got, _ := c.do(user, method, path, ""); got != status {
					b.Fatalf("status %d, want %d", got, status)
				}
			}
		}
	}
	b.Run("list-loans/no-authorization", run(unprotected, "bayo", "GET", "/branches/lagos/loans", http.StatusOK))
	b.Run("list-loans/teller", run(bk, "bayo", "GET", "/branches/lagos/loans", http.StatusOK))
	b.Run("approve/inherited-from-head-office", run(bk, "ada", "POST", "/branches/lagos/loans/"+loan+"/approve", http.StatusOK))
	b.Run("approve/denied", run(bk, "bayo", "POST", "/branches/lagos/loans/"+loan+"/approve", http.StatusForbidden))
}
