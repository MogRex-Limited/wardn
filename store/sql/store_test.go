package wardnsql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MogRex-Limited/wardn"
)

// fakeDriver lets tests open a *sql.DB without a real database. Its package
// path is not a known driver, so detection must fail.
type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("fake driver: no connections")
}

func init() { //nolint:gochecknoinits // test-only driver registration
	sql.Register("wardnsql-fake", fakeDriver{})
}

func fakeDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("wardnsql-fake", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestNewErrors(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("nil db accepted")
	}
	db := fakeDB(t)
	if _, err := New(db); err == nil || !strings.Contains(err.Error(), "WithDialect") {
		t.Errorf("unknown driver: %v", err)
	}
	if _, err := New(db, WithDialect(Dialect(42))); err == nil {
		t.Error("invalid dialect accepted")
	}
	for _, p := range []string{"", "Wardn_", "1x_", "wardn-", "wardn_; DROP TABLE x; --", "w.x_", strings.Repeat("a", 33)} {
		if _, err := New(db, WithDialect(Postgres), WithTablePrefix(p)); err == nil {
			t.Errorf("table prefix %q accepted", p)
		}
	}
	for _, p := range []string{"w", "wardn_", "app2_wardn_", strings.Repeat("a", 32)} {
		if _, err := New(db, WithDialect(Postgres), WithTablePrefix(p)); err != nil {
			t.Errorf("table prefix %q rejected: %v", p, err)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("MustNew did not panic")
		}
	}()
	MustNew(db)
}

func TestDetect(t *testing.T) {
	if _, err := detect(nil); err == nil {
		t.Error("nil driver detected")
	}
	if _, err := detect(fakeDriver{}); err == nil {
		t.Error("unknown driver detected")
	}
	if d := MustNew(fakeDB(t), WithDialect(MySQL)).Dialect(); d != MySQL {
		t.Errorf("Dialect() = %v", d)
	}
}

func TestDialectString(t *testing.T) {
	for d, want := range map[Dialect]string{DetectDialect: "detect", Postgres: "postgres", MySQL: "mysql", SQLite: "sqlite", Dialect(9): "Dialect(9)"} {
		if d.String() != want {
			t.Errorf("%d.String() = %q, want %q", int(d), d.String(), want)
		}
	}
}

func TestQueries(t *testing.T) {
	pg := MustNew(fakeDB(t), WithDialect(Postgres), WithTablePrefix("app_"))
	if want := "DELETE FROM app_assignments WHERE user_id = $1 AND role = $2 AND scope_type = $3 AND scope_id = $4"; pg.q.revoke != want {
		t.Errorf("postgres revoke:\n got %s\nwant %s", pg.q.revoke, want)
	}
	if !strings.Contains(pg.q.assign, "ON CONFLICT (user_id, scope_type, scope_id, role) DO UPDATE SET starts_at = excluded.starts_at") {
		t.Errorf("postgres upsert: %s", pg.q.assign)
	}
	my := MustNew(fakeDB(t), WithDialect(MySQL))
	if !strings.Contains(my.q.assign, "ON DUPLICATE KEY UPDATE starts_at = VALUES(starts_at)") || strings.Contains(my.q.assign, "$") {
		t.Errorf("mysql upsert: %s", my.q.assign)
	}
	// MySQL columns are binary so IDs compare exactly (threat model T13).
	ddl := stepsSQL(my.migrations())
	if !strings.Contains(ddl, "user_id    VARBINARY(256)") || strings.Contains(ddl, "VARCHAR") {
		t.Errorf("mysql columns are not binary:\n%s", ddl)
	}
	lite := MustNew(fakeDB(t), WithDialect(SQLite))
	if strings.Contains(lite.q.parent, "$") || !strings.Contains(stepsSQL(lite.migrations()), "CREATE INDEX IF NOT EXISTS") {
		t.Errorf("sqlite queries: %s", lite.q.parent)
	}
}

func TestAssignmentsLimits(t *testing.T) {
	s := MustNew(fakeDB(t), WithDialect(Postgres))
	ctx := context.Background()
	if as, err := s.Assignments(ctx, "u", nil); err != nil || as != nil {
		t.Errorf("no scopes: %v, %v", as, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Assignments(canceled, "u", nil); err == nil {
		t.Error("no scopes with canceled context: no error")
	}
	if _, err := s.Assignments(ctx, "u", make([]wardn.Scope, maxScopes+1)); err == nil {
		t.Error("too many scopes accepted")
	}
}

func TestTimeRounding(t *testing.T) {
	base := time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)
	exact := base.Add(5 * time.Microsecond)
	between := exact.Add(500 * time.Nanosecond)

	if v := startMicros(exact); !v.Valid || v.Int64 != exact.UnixMicro() {
		t.Errorf("exact start changed: %v", v)
	}
	// A start between microseconds is rounded up, an end down: the window
	// only ever shrinks.
	if v := startMicros(between); v.Int64 != exact.UnixMicro()+1 {
		t.Errorf("start not rounded up: %v", v)
	}
	if v := endMicros(between); v.Int64 != exact.UnixMicro() {
		t.Errorf("end not rounded down: %v", v)
	}
	if startMicros(time.Time{}).Valid || endMicros(time.Time{}).Valid || !fromMicros(sql.NullInt64{}).IsZero() {
		t.Error("zero time is not NULL")
	}
	if got := fromMicros(startMicros(exact)); !got.Equal(exact) || got.Location() != time.UTC {
		t.Errorf("round trip = %v", got)
	}
}

func TestLatestSchemaVersion(t *testing.T) {
	for _, d := range []Dialect{Postgres, MySQL, SQLite} {
		if n := len(MustNew(fakeDB(t), WithDialect(d)).migrations()); n != LatestSchemaVersion {
			t.Errorf("%v: %d migrations, LatestSchemaVersion is %d", d, n, LatestSchemaVersion)
		}
	}
}

func stepsSQL(migrations [][]step) string {
	var b strings.Builder
	for _, m := range migrations {
		for _, st := range m {
			b.WriteString(st.sql + "\n")
		}
	}
	return b.String()
}
