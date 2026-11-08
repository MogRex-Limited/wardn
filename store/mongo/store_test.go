package wardnmongo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/storetest"
)

func connect(t testing.TB) *mongo.Client {
	t.Helper()
	uri := os.Getenv("WARDN_TEST_MONGO_URI")
	if uri == "" {
		if os.Getenv("WARDN_TEST_REQUIRE_ALL") != "" {
			t.Fatal("WARDN_TEST_MONGO_URI is not set, but WARDN_TEST_REQUIRE_ALL is")
		}
		t.Skip("set WARDN_TEST_MONGO_URI to run (make integration starts MongoDB)")
	}
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetTimeout(30 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	if err := client.Ping(context.Background(), nil); err != nil {
		t.Fatalf("mongo: %v", err)
	}
	return client
}

var (
	runID = fmt.Sprintf("t%d", time.Now().UnixNano()%1_000_000_000)
	dbSeq atomic.Int64
)

// freshDB returns a database no other test uses; it is dropped afterwards.
func freshDB(t testing.TB, client *mongo.Client) *mongo.Database {
	t.Helper()
	db := client.Database(fmt.Sprintf("wardn_%s_%d", runID, dbSeq.Add(1)))
	t.Cleanup(func() { _ = db.Drop(context.Background()) })
	return db
}

func migrated(t testing.TB, db *mongo.Database) *Store {
	t.Helper()
	s := MustNew(db)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestConformance(t *testing.T) {
	client := connect(t)
	storetest.Run(t, func(t *testing.T) wardn.Store { return migrated(t, freshDB(t, client)) })
}

func TestMigrate(t *testing.T) {
	client := connect(t)
	ctx := context.Background()
	s := MustNew(freshDB(t, client))
	if v, err := s.SchemaVersion(ctx); err != nil || v != 0 {
		t.Fatalf("before: %d, %v", v, err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- s.Migrate(ctx) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Migrate: %v", err)
		}
	}
	if v, _ := s.SchemaVersion(ctx); v != LatestSchemaVersion {
		t.Fatalf("after: version %d", v)
	}

	// A database set up by a newer wardn is refused.
	if _, err := s.meta.UpdateOne(ctx, bson.D{{Key: "_id", Value: "version"}}, bson.D{{Key: "$set", Value: bson.D{{Key: "v", Value: 99}}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("newer schema: %v", err)
	}
	if v, _ := s.SchemaVersion(ctx); v != 99 {
		t.Fatalf("Migrate lowered the version to %d", v)
	}
}

func TestNewMigratesAutomatically(t *testing.T) {
	client := connect(t)
	p, err := wardn.ParsePolicy([]byte("permissions:\n  doc:read: Read\nroles:\n  reader: [doc:read]\n"), "t.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := MustNew(freshDB(t, client))
	if _, err := wardn.New(wardn.Config{Policy: p, Store: s}); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.SchemaVersion(context.Background()); v != LatestSchemaVersion {
		t.Fatalf("version %d after wardn.New", v)
	}
}

// TestOperatorInjection: IDs that look like query operators are plain
// strings, never interpreted.
func TestOperatorInjection(t *testing.T) {
	client := connect(t)
	s := migrated(t, freshDB(t, client))
	ctx := context.Background()
	branch := wardn.NewScope("branch", "b1")
	if err := s.Assign(ctx, wardn.Assignment{User: "victim", Role: "admin", Scope: branch}); err != nil {
		t.Fatal(err)
	}
	for _, evil := range []string{`{"$ne": ""}`, `$ne`, `$where`, `{"$gt": ""}`, `a.b`, `$`} {
		as, err := s.Assignments(ctx, evil, []wardn.Scope{branch, {Type: "$ne", ID: "$ne"}})
		if err != nil || len(as) != 0 {
			t.Errorf("user %q matched %v (%v)", evil, as, err)
		}
		if err := s.Assign(ctx, wardn.Assignment{User: evil, Role: evil, Scope: wardn.NewScope("branch", evil)}); err != nil {
			t.Errorf("storing %q: %v", evil, err)
		}
	}
}

func TestNew(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("nil database accepted")
	}
	db := (&mongo.Client{}).Database("x")
	for _, p := range []string{"", "Wardn_", "1x", "a.b", "a$b", string(make([]byte, 33))} {
		if _, err := New(db, WithCollectionPrefix(p)); err == nil {
			t.Errorf("prefix %q accepted", p)
		}
	}
	if s := MustNew(db, WithCollectionPrefix("app_")); s.CollectionPrefix() != "app_" {
		t.Error("prefix not applied")
	}
	defer func() {
		if recover() == nil {
			t.Error("MustNew did not panic")
		}
	}()
	MustNew(nil)
}

func TestTimeRounding(t *testing.T) {
	base := time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC).Add(5 * time.Microsecond)
	between := base.Add(500 * time.Nanosecond)
	if *startMicros(between) != base.UnixMicro()+1 || *endMicros(between) != base.UnixMicro() {
		t.Error("rounding widens the window")
	}
	if startMicros(time.Time{}) != nil || endMicros(time.Time{}) != nil || !fromMicros(nil).IsZero() {
		t.Error("zero time is not null")
	}
}

// BenchmarkMongo measures checks on a bank-sized dataset; see
// storetest.Bench. Needs WARDN_TEST_MONGO_URI (make bench-all).
func BenchmarkMongo(b *testing.B) {
	client := connect(b)
	storetest.Bench(b, func(b *testing.B) wardn.Store { return migrated(b, freshDB(b, client)) })
}
