package demo

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	_ "modernc.org/sqlite" // the demos store wardn's data in SQLite
)

// Env returns the environment variable key, or fallback if it is unset.
func Env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// OpenSQLite opens (creating if needed) a SQLite database file. The busy
// timeout lets concurrent writers wait instead of failing.
func OpenSQLite(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
}

// Serve runs h on addr until ctx is done, then shuts down gracefully.
func Serve(ctx context.Context, name, addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	slog.Info(name+" listening", "addr", addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
