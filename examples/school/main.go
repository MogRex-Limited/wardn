// Command school is the school-system reference application. Schools contain
// classes; the school a class belongs to lives in the application's own
// data, and wardn reads it through Config.ParentOf instead of storing it.
//
//	go run ./school         # from the examples directory; listens on :8080
//
// It stores wardn's data in SQLite (SCHOOL_DB, default school.db) and makes
// the user "head" (SCHOOL_PRINCIPAL) principal of school "s1" on start.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/examples/internal/demo"
	"github.com/MogRex-Limited/wardn/examples/school/perm"
	wardnsql "github.com/MogRex-Limited/wardn/store/sql"
)

func main() {
	if err := run(); err != nil {
		slog.Error("school", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	db, err := demo.OpenSQLite(demo.Env("SCHOOL_DB", "school.db"))
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck // closing on exit

	policy, err := Policy()
	if err != nil {
		return err
	}
	data := NewData()
	w, err := wardn.New(wardn.Config{
		Policy:   policy,
		Store:    wardnsql.MustNew(db),
		ParentOf: data.ParentOf,
		OnChange: demo.AuditLog(slog.Default()),
	})
	if err != nil {
		return err
	}
	if err := w.System().Assign(ctx, demo.Env("SCHOOL_PRINCIPAL", "head"), perm.RolePrincipal, perm.ScopeSchool("s1")); err != nil {
		return err
	}
	return demo.Serve(ctx, "school", demo.Env("ADDR", ":8080"), (&App{w: w, data: data}).Router())
}
