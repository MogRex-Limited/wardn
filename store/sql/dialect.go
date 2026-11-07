package wardnsql

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Dialect selects the SQL flavour a Store speaks.
type Dialect int

// Supported dialects.
const (
	// DetectDialect detects the dialect from the database driver. It is the
	// default.
	DetectDialect Dialect = iota
	// Postgres is PostgreSQL 13 or newer.
	Postgres
	// MySQL is MySQL 8.0 or newer, or MariaDB 10.6 or newer.
	MySQL
	// SQLite is SQLite 3.24 or newer.
	SQLite
)

func (d Dialect) String() string {
	switch d {
	case DetectDialect:
		return "detect"
	case Postgres:
		return "postgres"
	case MySQL:
		return "mysql"
	case SQLite:
		return "sqlite"
	}
	return "Dialect(" + strconv.Itoa(int(d)) + ")"
}

// knownDrivers maps driver package paths to dialects.
var knownDrivers = map[string]Dialect{
	"github.com/jackc/pgx/v5/stdlib":       Postgres,
	"github.com/jackc/pgx/v4/stdlib":       Postgres,
	"github.com/lib/pq":                    Postgres,
	"github.com/go-sql-driver/mysql":       MySQL,
	"modernc.org/sqlite":                   SQLite,
	"github.com/mattn/go-sqlite3":          SQLite,
	"github.com/ncruces/go-sqlite3/driver": SQLite,
}

// detect identifies the dialect from the driver's package path.
func detect(driver any) (Dialect, error) {
	t := reflect.TypeOf(driver)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil {
		return DetectDialect, fmt.Errorf("wardnsql: database has no driver")
	}
	if d, ok := knownDrivers[t.PkgPath()]; ok {
		return d, nil
	}
	return DetectDialect, fmt.Errorf("wardnsql: cannot detect the SQL dialect of driver %s; pass wardnsql.WithDialect", t.PkgPath())
}

// dialect holds the SQL that differs between databases.
type dialect struct {
	kind Dialect
	// Column types. MySQL uses VARBINARY so IDs compare byte for byte:
	// its default collations are case-, accent- and trailing-space-
	// insensitive (threat model T13).
	id, name, integer string
	perm, text        string // permission names (128 bytes); descriptions (512 bytes)
	// byteOrder makes comparisons and ORDER BY use byte order, so pages of
	// Members are stable and identical on every database.
	byteOrder      string
	tableSuffix    string
	inlineIndexes  bool // MySQL cannot CREATE INDEX IF NOT EXISTS
	numbered       bool // $1, $2 placeholders instead of ?
	upsertTemplate string
}

func dialectFor(d Dialect) (dialect, error) {
	switch d {
	case Postgres:
		return dialect{kind: d, id: "VARCHAR(256)", name: "VARCHAR(64)", integer: "BIGINT",
			perm: "VARCHAR(128)", text: "VARCHAR(512)", byteOrder: ` COLLATE "C"`,
			numbered: true, upsertTemplate: "ON CONFLICT (%s) DO UPDATE SET %s"}, nil
	case SQLite:
		return dialect{kind: d, id: "TEXT", name: "TEXT", integer: "INTEGER", perm: "TEXT", text: "TEXT",
			upsertTemplate: "ON CONFLICT (%s) DO UPDATE SET %s"}, nil
	case MySQL:
		return dialect{kind: d, id: "VARBINARY(256)", name: "VARBINARY(64)", integer: "BIGINT",
			perm: "VARBINARY(128)", text: "VARBINARY(512)",
			tableSuffix: " ENGINE=InnoDB", inlineIndexes: true, upsertTemplate: "ON DUPLICATE KEY UPDATE %[2]s"}, nil
	case DetectDialect:
	}
	return dialect{}, fmt.Errorf("wardnsql: unsupported dialect %v", d)
}

// upsert returns the clause that turns an INSERT into an insert-or-update.
func (d dialect) upsert(key []string, update []string) string {
	sets := make([]string, len(update))
	for i, col := range update {
		if d.kind == MySQL {
			sets[i] = col + " = VALUES(" + col + ")" // VALUES() also works on MariaDB
		} else {
			sets[i] = col + " = excluded." + col
		}
	}
	return fmt.Sprintf(d.upsertTemplate, strings.Join(key, ", "), strings.Join(sets, ", "))
}

// bind rewrites '?' placeholders for dialects that number them. wardn's
// queries never contain '?' in literals.
func (d dialect) bind(query string) string {
	if !d.numbered {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
