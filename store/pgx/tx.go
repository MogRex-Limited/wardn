package wardnpgx

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// txKey identifies one Store's application transaction in a context, so a
// transaction on one database is never used by a store for another.
type txKey struct{ s *Store }

// WithTx returns a copy of ctx in which the store reads and writes through
// tx, the application's own transaction, instead of the pool. A change to
// access then commits or rolls back with the application's other writes:
//
//	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
//		ctx, ended := w.Transaction(store.WithTx(ctx, tx))
//		defer ... // call ended(ctx) after BeginFunc returns, not here
//		...
//	})
//
// Pass the result to wardn.Warden.Transaction before making changes with
// it; wardn refuses changes otherwise (wardn.ErrNoTransaction). Each of the
// store's writes runs in a savepoint (pgx's nested transaction), so a
// write that fails, such as a custom role whose name is taken, leaves tx
// usable.
//
// wardn's queries run with whatever the transaction has set: role,
// row-level security settings, isolation level.
func (s *Store) WithTx(ctx context.Context, tx pgx.Tx) context.Context {
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

func (s *Store) txFrom(ctx context.Context) (pgx.Tx, bool) {
	tx, ok := ctx.Value(txKey{s}).(pgx.Tx)
	return tx, ok && tx != nil
}

// conn returns what reads with ctx go through: the application's
// transaction, or the database.
func (s *Store) conn(ctx context.Context) DB {
	if tx, ok := s.txFrom(ctx); ok {
		return tx
	}
	return s.db
}

// exec runs one write statement. Inside an application transaction it runs
// in a savepoint, so a failure leaves the transaction usable.
func (s *Store) exec(ctx context.Context, query string, args ...any) error {
	if s.InTx(ctx) {
		return s.inTx(ctx, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, query, args...)
			return err
		})
	}
	_, err := s.db.Exec(ctx, query, args...)
	return err
}

// inTx runs fn atomically. Begin on the application's transaction makes a
// savepoint; on the database it starts a transaction of its own.
func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.conn(ctx).Begin(ctx)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		// Undo even if ctx was cancelled, so an application transaction
		// stays usable.
		if rbErr := tx.Rollback(context.WithoutCancel(ctx)); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
			return errors.Join(err, rbErr)
		}
		return err
	}
	return tx.Commit(ctx)
}
