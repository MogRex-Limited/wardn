// Command saas is the multi-tenant SaaS reference application: customer
// workspaces with projects and customer-defined roles.
//
//	go run ./saas           # from the examples directory; listens on :8080
//
// It stores wardn's data in SQLite (SAAS_DB, default saas.db). Anyone signed
// in can create a workspace with POST /signup and becomes its owner.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/examples/internal/demo"
	wardnsql "github.com/MogRex-Limited/wardn/store/sql"
)

func main() {
	if err := run(); err != nil {
		slog.Error("saas", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	db, err := demo.OpenSQLite(demo.Env("SAAS_DB", "saas.db"))
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
	return demo.Serve(ctx, "saas", demo.Env("ADDR", ":8080"), (&App{w: w, data: NewData()}).Router())
}
