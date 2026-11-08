// Command bank is the multi-branch bank reference application: a lending
// platform serving several banks, each with regions and branches.
//
//	go run ./bank           # from the examples directory; listens on :8080
//
// It stores wardn's data in SQLite (BANK_DB, default bank.db) and makes the
// user "root" (BANK_PLATFORM_ADMIN) a platform administrator on start.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/examples/bank/perm"
	"github.com/MogRex-Limited/wardn/examples/internal/demo"
	wardnsql "github.com/MogRex-Limited/wardn/store/sql"
)

func main() {
	if err := run(); err != nil {
		slog.Error("bank", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	db, err := demo.OpenSQLite(demo.Env("BANK_DB", "bank.db"))
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck // closing on exit

	policy, err := Policy()
	if err != nil {
		return err
	}
	w, err := wardn.New(wardn.Config{
		Policy:   policy,
		Store:    wardnsql.MustNew(db),
		OnChange: demo.AuditLog(slog.Default()),
	})
	if err != nil {
		return err
	}

	// Seed the first administrator. System() is for code with no user acting.
	if err := w.System().Assign(ctx, demo.Env("BANK_PLATFORM_ADMIN", "root"), perm.RolePlatformAdmin, wardn.Global); err != nil {
		return err
	}
	go w.RunExpiry(ctx, time.Minute, func(err error) { slog.Error("expiry sweep", "err", err) })

	return demo.Serve(ctx, "bank", demo.Env("ADDR", ":8080"), (&App{w: w, bank: NewBank()}).Router())
}
