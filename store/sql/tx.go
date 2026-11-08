package wardnsql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// txKey identifies one Store's application transaction in a context, so a
// transaction on one database is never used by a store for another.
type txKey struct{ s *Store }

// WithTx returns a copy of ctx in which the store reads and writes through
// tx, the application's own transaction, instead of starting its own. A
// change to access then commits or rolls back with the application's other
// writes. tx must be a transaction on the store's database.
//
// Pass the result to wardn.Warden.Transaction before making changes with
// it; wardn refuses changes otherwise (wardn.ErrNoTransaction). The store
// wraps each of its writes in a savepoint, so a write that fails, such as
// a custom role whose name is taken, leaves the transaction usable.
//
// Keep row-level security, locks and isolation in mind: wardn's queries
// run with whatever the transaction has set.
func (s *Store) WithTx(ctx context.Context, tx *sql.Tx) context.Context {
	if tx == nil {
		return ctx
	}
	return context.WithValue(ctx, txKey{s}, tx)
}

// InTx implements wardn.TxStore: it reports whether ctx carries an
// application transaction for this store.
func (s *Store) InTx(ctx context.Context) bool {
	_, ok := s.txFrom(ctx)
	return ok
}

func (s *Store) txFrom(ctx context.Context) (*sql.Tx, bool) {
	tx, ok := ctx.Value(txKey{s}).(*sql.Tx)
	return tx, ok && tx != nil
}

// querier is what *sql.DB and *sql.Tx have in common.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// conn returns what reads with ctx go through: the application's
// transaction, or the database.
func (s *Store) conn(ctx context.Context) querier {
	if tx, ok := s.txFrom(ctx); ok {
		return tx
	}
	return s.db
}

// exec runs one write statement. Inside an application transaction it runs
// in a savepoint, so a failure leaves the transaction usable.
func (s *Store) exec(ctx context.Context, query string, args ...any) error {
	if tx, ok := s.txFrom(ctx); ok {
		return savepoint(ctx, tx, func(q querier) error {
			_, err := q.ExecContext(ctx, query, args...)
			return err
		})
	}
	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

// inTx runs fn atomically: in a savepoint of the application's transaction
// when ctx carries one, otherwise in a transaction of its own, committed if
// fn succeeds.
func (s *Store) inTx(ctx context.Context, fn func(querier) error) error {
	if tx, ok := s.txFrom(ctx); ok {
		return savepoint(ctx, tx, fn)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// savepointName is fixed: wardn never nests its own savepoints, and a
// savepoint the application set with the same name is shadowed, not
// replaced, until this one is released.
const savepointName = "wardn_write"

// savepoint runs fn inside a savepoint of tx, rolling back to it if fn
// fails. PostgreSQL, MySQL, MariaDB and SQLite share this syntax.
func savepoint(ctx context.Context, tx *sql.Tx, fn func(querier) error) error {
	if _, err := tx.ExecContext(ctx, "SAVEPOINT "+savepointName); err != nil {
		return fmt.Errorf("wardnsql: starting savepoint: %w", err)
	}
	if err := fn(tx); err != nil {
		// Undo even if ctx was cancelled, so the transaction stays usable.
		undo := context.WithoutCancel(ctx)
		if _, rbErr := tx.ExecContext(undo, "ROLLBACK TO SAVEPOINT "+savepointName); rbErr != nil {
			return errors.Join(err, fmt.Errorf("wardnsql: rolling back to savepoint: %w", rbErr))
		}
		if _, relErr := tx.ExecContext(undo, "RELEASE SAVEPOINT "+savepointName); relErr != nil {
			return errors.Join(err, fmt.Errorf("wardnsql: releasing savepoint: %w", relErr))
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, "RELEASE SAVEPOINT "+savepointName); err != nil {
		return fmt.Errorf("wardnsql: releasing savepoint: %w", err)
	}
	return nil
}
