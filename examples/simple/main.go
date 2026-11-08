// Command simple is the reference application without tenancy: an internal
// publishing tool with admins, editors and viewers.
//
//	go run ./simple         # from the examples directory; listens on :8080
//
// It stores wardn's data in SQLite (SIMPLE_DB, default simple.db) and makes
// the user "root" (SIMPLE_ADMIN) an admin on start.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/examples/internal/demo"
	"github.com/MogRex-Limited/wardn/examples/simple/perm"
	wardnsql "github.com/MogRex-Limited/wardn/store/sql"
)

func main() {
	if err := run(); err != nil {
		slog.Error("simple", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	db, err := demo.OpenSQLite(demo.Env("SIMPLE_DB", "simple.db"))
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck // closing on exit

	policy, err := Policy()
	if err != nil {
		return err
	}
	w, err := wardn.New(wardn.Config{Policy: policy, Store: wardnsql.MustNew(db), OnChange: demo.AuditLog(slog.Default())})
	if err != nil {
		return err
	}
	if err := w.System().Assign(ctx, demo.Env("SIMPLE_ADMIN", "root"), perm.RoleAdmin, wardn.Global); err != nil {
		return err
	}
	return demo.Serve(ctx, "simple", demo.Env("ADDR", ":8080"), NewApp(w).Router())
}
