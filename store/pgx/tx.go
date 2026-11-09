package wardnpgx

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/MogRex-Limited/wardn"
)

// txKey identifies one Store's application transaction in a context, so a
// transaction on one database is never used by a store for another.
type txKey struct{ s *Store }

// WithTx returns a copy of ctx in which the store reads and writes through
// tx, the application's own transaction, instead of the pool. A change to
// access then commits or rolls back with the application's other writes.
// RunInTx does this for a new transaction; use WithTx when the
// application already has one:
//
//	wctx, ended := w.Transaction(ctx)
//	err := pgx.BeginFunc(wctx, pool, func(tx pgx.Tx) error {
//		ctx := store.WithTx(wctx, tx)
//		...
//	})
//	endErr := ended(ctx) // after BeginFunc has committed or rolled back
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

// RunInTx runs fn in a new transaction on the store's database, and commits
// it if fn returns nil. If fn fails or panics, it rolls back. The ctx
// passed to fn is ready for wardn changes in that transaction (WithTx and
// w.Transaction), so access commits or rolls back with the application's
// own writes through tx, including sqlc's Queries.WithTx(tx):
//
//	err := store.RunInTx(ctx, w, pgx.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
//		if _, err := tx.Exec(ctx, insertMember, orgID, userID); err != nil {
//			return err
//		}
//		return w.Assign(ctx, userID, "agent", product)
//	})
//
// RunInTx ends wardn's transaction after the commit or rollback, which is
// easy to get wrong by hand. It returns fn's error, or else the commit's.
// If the transaction committed but invalidating the cache then failed, it
// returns an error matching wardn.ErrCacheInvalidation: the changes are
// saved, and other instances may serve the old state for up to the cache
// TTL.
//
// opts sets the isolation level and access mode; the zero value uses the
// database's defaults. Options other than the zero value need a DB with a
// BeginTx method, as *pgxpool.Pool and *pgx.Conn have.
func (s *Store) RunInTx(ctx context.Context, w *wardn.Warden, opts pgx.TxOptions, fn func(ctx context.Context, tx pgx.Tx) error) (err error) {
	if w == nil || fn == nil {
		return errors.New("wardnpgx: RunInTx needs a Warden and a function")
	}
	tx, err := s.begin(ctx, opts)
	if err != nil {
		return fmt.Errorf("wardnpgx: starting transaction: %w", err)
	}
	txCtx, ended := w.Transaction(s.WithTx(ctx, tx))
	defer func() {
		// A no-op after Commit; after a failure or panic, undo even if ctx
		// was cancelled. Its error adds nothing to fn's, or to the panic.
		_ = tx.Rollback(context.WithoutCancel(ctx))
		// After the commit or rollback, also when fn panics.
		if endErr := ended(ctx); endErr != nil && err == nil {
			err = endErr
		}
	}()
	if err := fn(txCtx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// begin starts a transaction on the store's database with opts.
func (s *Store) begin(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	if opts == (pgx.TxOptions{}) {
		return s.db.Begin(ctx)
	}
	b, ok := s.db.(interface {
		BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
	})
	if !ok {
		return nil, fmt.Errorf("%T cannot start a transaction with options", s.db)
	}
	return b.BeginTx(ctx, opts)
}
