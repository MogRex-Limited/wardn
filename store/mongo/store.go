// Package wardnmongo is a wardn.Store for MongoDB 6.0 or newer.
//
//	client, _ := mongo.Connect(options.Client().ApplyURI(uri))
//	w := wardn.MustNew(wardn.Config{
//		File:  "wardn.yaml",
//		Store: wardnmongo.MustNew(client.Database("myapp")),
//	})
//
// It needs no transactions, so it works on a standalone server as well as a
// replica set: every write touches a single document, and a custom role
// (with its permissions) is one document. wardn.New creates the indexes
// (see Store.Migrate).
//
// Values from users are only ever used as typed string values in filters,
// never as query documents or field names, so they cannot inject query
// operators.
package wardnmongo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/MogRex-Limited/wardn"
)

// DefaultCollectionPrefix is prepended to the names of wardn's collections.
const DefaultCollectionPrefix = "wardn_"

// LatestSchemaVersion is the schema (index set) version this release
// migrates to.
const LatestSchemaVersion = 1

// ErrSchemaTooNew reports a database set up by a newer release of wardn.
var ErrSchemaTooNew = errors.New("wardnmongo: database schema is newer than this release of wardn supports")

// maxIDs bounds the IDs or scopes in one query.
const maxIDs = 256

// Store is a wardn.Store backed by MongoDB. It is safe for concurrent use.
type Store struct {
	assignments, links, roles, meta *mongo.Collection
	prefix                          string
}

// Option configures a Store.
type Option func(*storeOptions)

type storeOptions struct{ prefix string }

// WithCollectionPrefix sets the prefix of wardn's collection names
// (default "wardn_"): 1–32 lowercase letters, digits and '_', starting with
// a letter.
func WithCollectionPrefix(prefix string) Option {
	return func(o *storeOptions) { o.prefix = prefix }
}

// New returns a Store using db. Call Migrate (wardn.New does) to create the
// indexes, which enforce uniqueness.
func New(db *mongo.Database, opts ...Option) (*Store, error) {
	if db == nil {
		return nil, errors.New("wardnmongo: database is nil")
	}
	o := storeOptions{prefix: DefaultCollectionPrefix}
	for _, opt := range opts {
		opt(&o)
	}
	if !validPrefix(o.prefix) {
		return nil, fmt.Errorf("wardnmongo: invalid collection prefix %q: use 1-32 lowercase letters, digits and '_', starting with a letter", o.prefix)
	}
	return &Store{
		assignments: db.Collection(o.prefix + "assignments"),
		links:       db.Collection(o.prefix + "scope_links"),
		roles:       db.Collection(o.prefix + "roles"),
		meta:        db.Collection(o.prefix + "schema"),
		prefix:      o.prefix,
	}, nil
}

// MustNew is like New but panics on error, for use in main().
func MustNew(db *mongo.Database, opts ...Option) *Store {
	s, err := New(db, opts...)
	if err != nil {
		panic(err)
	}
	return s
}

func validPrefix(p string) bool {
	if p == "" || len(p) > 32 || p[0] < 'a' || p[0] > 'z' {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// Migrate creates the indexes wardn needs and records the schema version.
// It is idempotent and safe to run concurrently. It refuses a database set
// up by a newer release (ErrSchemaTooNew).
func (s *Store) Migrate(ctx context.Context) error {
	current, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if current > LatestSchemaVersion {
		return fmt.Errorf("%w (database is at version %d, this release supports up to %d)", ErrSchemaTooNew, current, LatestSchemaVersion)
	}
	indexes := map[*mongo.Collection][]mongo.IndexModel{
		s.assignments: {
			{Keys: bson.D{{Key: "u", Value: 1}, {Key: "t", Value: 1}, {Key: "i", Value: 1}}},
			{Keys: bson.D{{Key: "t", Value: 1}, {Key: "i", Value: 1}, {Key: "u", Value: 1}, {Key: "r", Value: 1}}},
			{Keys: bson.D{{Key: "e", Value: 1}}},
			{Keys: bson.D{{Key: "r", Value: 1}}},
		},
		s.roles: {
			{Keys: bson.D{{Key: "ot", Value: 1}, {Key: "oi", Value: 1}, {Key: "nk", Value: 1}}, Options: options.Index().SetUnique(true).SetName("owner_name_unique")},
		},
	}
	for coll, models := range indexes {
		if _, err := coll.Indexes().CreateMany(ctx, models); err != nil {
			return fmt.Errorf("wardnmongo: creating indexes on %s: %w", coll.Name(), err)
		}
	}
	// $max never lowers the version, so concurrent migrations are safe.
	return retryDuplicate(func() error {
		_, err := s.meta.UpdateOne(ctx, bson.D{{Key: "_id", Value: "version"}},
			bson.D{{Key: "$max", Value: bson.D{{Key: "v", Value: LatestSchemaVersion}}}}, options.UpdateOne().SetUpsert(true))
		return err
	})
}

// SchemaVersion returns the recorded schema version, or 0 if never migrated.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var doc struct {
		V int `bson:"v"`
	}
	err := s.meta.FindOne(ctx, bson.D{{Key: "_id", Value: "version"}}).Decode(&doc)
	switch {
	case errors.Is(err, mongo.ErrNoDocuments):
		return 0, nil
	case err != nil:
		return 0, fmt.Errorf("wardnmongo: reading schema version: %w", err)
	}
	return doc.V, nil
}

// CollectionPrefix returns the prefix of the store's collection names.
func (s *Store) CollectionPrefix() string { return s.prefix }

// retryDuplicate retries an upsert that lost a race to insert the same _id,
// which MongoDB reports as a duplicate key error.
func retryDuplicate(fn func() error) error {
	var err error
	for range 3 {
		if err = fn(); !mongo.IsDuplicateKeyError(err) {
			return err
		}
	}
	return err
}

// --- documents --------------------------------------------------------------

// Every key field is written in a fixed order: MongoDB compares embedded
// documents field by field, in order.

func assignmentID(user, role string, s wardn.Scope) bson.D {
	return bson.D{{Key: "u", Value: user}, {Key: "r", Value: role}, {Key: "t", Value: s.Type}, {Key: "i", Value: s.ID}}
}

func scopeID(s wardn.Scope) bson.D {
	return bson.D{{Key: "t", Value: s.Type}, {Key: "i", Value: s.ID}}
}

type assignmentDoc struct {
	User     string `bson:"u"`
	Role     string `bson:"r"`
	Type     string `bson:"t"`
	ID       string `bson:"i"`
	Starts   *int64 `bson:"s"`
	Expires  *int64 `bson:"e"`
	Reported *int64 `bson:"rep"`
}

func (d assignmentDoc) assignment() wardn.Assignment {
	return wardn.Assignment{User: d.User, Role: d.Role, Scope: wardn.Scope{Type: d.Type, ID: d.ID},
		StartsAt: fromMicros(d.Starts), ExpiresAt: fromMicros(d.Expires)}
}

// Times are stored as Unix microseconds, as in the SQL store; rounding
// never widens a window: starts round up, ends round down.

func startMicros(t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	us := t.UnixMicro()
	if time.UnixMicro(us).Before(t) {
		us++
	}
	return &us
}

func endMicros(t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	us := t.UnixMicro()
	return &us
}

func fromMicros(v *int64) time.Time {
	if v == nil {
		return time.Time{}
	}
	return time.UnixMicro(*v).UTC()
}

// --- assignments -----------------------------------------------------------

// Assign implements wardn.Store.
func (s *Store) Assign(ctx context.Context, a wardn.Assignment) error {
	now := time.Now().UnixMicro()
	err := retryDuplicate(func() error {
		_, err := s.assignments.UpdateOne(ctx, bson.D{{Key: "_id", Value: assignmentID(a.User, a.Role, a.Scope)}},
			bson.D{
				{Key: "$set", Value: bson.D{{Key: "s", Value: startMicros(a.StartsAt)}, {Key: "e", Value: endMicros(a.ExpiresAt)}, {Key: "rep", Value: nil}, {Key: "up", Value: now}}},
				{Key: "$setOnInsert", Value: bson.D{{Key: "u", Value: a.User}, {Key: "r", Value: a.Role}, {Key: "t", Value: a.Scope.Type}, {Key: "i", Value: a.Scope.ID}, {Key: "c", Value: now}}},
			}, options.UpdateOne().SetUpsert(true))
		return err
	})
	if err != nil {
		return fmt.Errorf("wardnmongo: assign: %w", err)
	}
	return nil
}

// Revoke implements wardn.Store.
func (s *Store) Revoke(ctx context.Context, user, role string, scope wardn.Scope) error {
	if _, err := s.assignments.DeleteOne(ctx, bson.D{{Key: "_id", Value: assignmentID(user, role, scope)}}); err != nil {
		return fmt.Errorf("wardnmongo: revoke: %w", err)
	}
	return nil
}

func scopesFilter(scopes []wardn.Scope) bson.A {
	or := make(bson.A, len(scopes))
	for i, sc := range scopes {
		or[i] = bson.D{{Key: "t", Value: sc.Type}, {Key: "i", Value: sc.ID}}
	}
	return or
}

// Assignments implements wardn.Store.
func (s *Store) Assignments(ctx context.Context, user string, scopes []wardn.Scope) ([]wardn.Assignment, error) {
	if len(scopes) == 0 {
		return nil, ctx.Err()
	}
	if len(scopes) > maxIDs {
		return nil, fmt.Errorf("wardnmongo: %d scopes in one query; the maximum is %d", len(scopes), maxIDs)
	}
	return s.findAssignments(ctx, bson.D{{Key: "u", Value: user}, {Key: "$or", Value: scopesFilter(scopes)}}, nil)
}

func (s *Store) findAssignments(ctx context.Context, filter bson.D, opts *options.FindOptionsBuilder) ([]wardn.Assignment, error) {
	cur, err := s.assignments.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("wardnmongo: reading assignments: %w", err)
	}
	var docs []assignmentDoc
	if err := cur.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("wardnmongo: reading assignments: %w", err)
	}
	out := make([]wardn.Assignment, len(docs))
	for i, d := range docs {
		out[i] = d.assignment()
	}
	return out, nil
}

// Members implements wardn.Store. MongoDB compares strings by their UTF-8
// bytes by default, so pages are in byte order, as on every other store.
func (s *Store) Members(ctx context.Context, scope wardn.Scope, cursor string, limit int) ([]wardn.Assignment, string, error) {
	afterUser, afterRole, err := wardn.DecodeMemberCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	if limit <= 0 {
		limit = 1
	}
	filter := bson.D{{Key: "t", Value: scope.Type}, {Key: "i", Value: scope.ID}}
	if cursor != "" {
		filter = append(filter, bson.E{Key: "$or", Value: bson.A{
			bson.D{{Key: "u", Value: bson.D{{Key: "$gt", Value: afterUser}}}},
			bson.D{{Key: "u", Value: afterUser}, {Key: "r", Value: bson.D{{Key: "$gt", Value: afterRole}}}},
		}})
	}
	page, err := s.findAssignments(ctx, filter, options.Find().
		SetSort(bson.D{{Key: "u", Value: 1}, {Key: "r", Value: 1}}).SetLimit(int64(limit)+1))
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(page) > limit {
		page = page[:limit]
		last := page[len(page)-1]
		next = wardn.EncodeMemberCursor(last.User, last.Role)
	}
	return page, next, nil
}

// RoleInUse implements wardn.Store.
func (s *Store) RoleInUse(ctx context.Context, role string) (bool, error) {
	err := s.assignments.FindOne(ctx, bson.D{{Key: "r", Value: role}}, options.FindOne().SetProjection(bson.D{{Key: "_id", Value: 1}})).Err()
	switch {
	case errors.Is(err, mongo.ErrNoDocuments):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("wardnmongo: checking role use: %w", err)
	}
	return true, nil
}

// RevokeRole implements wardn.Store.
func (s *Store) RevokeRole(ctx context.Context, role string) error {
	if _, err := s.assignments.DeleteMany(ctx, bson.D{{Key: "r", Value: role}}); err != nil {
		return fmt.Errorf("wardnmongo: revoking role: %w", err)
	}
	return nil
}

// ExpiredUnreported implements wardn.Store.
func (s *Store) ExpiredUnreported(ctx context.Context, t time.Time, limit int) ([]wardn.Assignment, error) {
	if limit <= 0 {
		limit = 1
	}
	filter := bson.D{
		{Key: "e", Value: bson.D{{Key: "$ne", Value: nil}, {Key: "$lte", Value: t.UnixMicro()}}},
		{Key: "rep", Value: nil},
	}
	return s.findAssignments(ctx, filter, options.Find().SetSort(bson.D{{Key: "e", Value: 1}}).SetLimit(int64(limit)))
}

// MarkExpiryReported implements wardn.Store. Matching on the expiry leaves
// an assignment unmarked if it was assigned again with a new window.
func (s *Store) MarkExpiryReported(ctx context.Context, as []wardn.Assignment) error {
	if len(as) == 0 {
		return ctx.Err()
	}
	now := time.Now().UnixMicro()
	models := make([]mongo.WriteModel, len(as))
	for i, a := range as {
		models[i] = mongo.NewUpdateOneModel().
			SetFilter(bson.D{{Key: "_id", Value: assignmentID(a.User, a.Role, a.Scope)}, {Key: "e", Value: endMicros(a.ExpiresAt)}}).
			SetUpdate(bson.D{{Key: "$set", Value: bson.D{{Key: "rep", Value: now}}}})
	}
	if _, err := s.assignments.BulkWrite(ctx, models); err != nil {
		return fmt.Errorf("wardnmongo: marking expiry: %w", err)
	}
	return nil
}

// --- scope links -----------------------------------------------------------

// Link implements wardn.Store.
func (s *Store) Link(ctx context.Context, child, parent wardn.Scope) error {
	err := retryDuplicate(func() error {
		_, err := s.links.UpdateOne(ctx, bson.D{{Key: "_id", Value: scopeID(child)}},
			bson.D{{Key: "$set", Value: bson.D{{Key: "pt", Value: parent.Type}, {Key: "pi", Value: parent.ID}, {Key: "up", Value: time.Now().UnixMicro()}}}},
			options.UpdateOne().SetUpsert(true))
		return err
	})
	if err != nil {
		return fmt.Errorf("wardnmongo: link: %w", err)
	}
	return nil
}

// Parent implements wardn.Store.
func (s *Store) Parent(ctx context.Context, child wardn.Scope) (wardn.Scope, bool, error) {
	var doc struct {
		Type string `bson:"pt"`
		ID   string `bson:"pi"`
	}
	err := s.links.FindOne(ctx, bson.D{{Key: "_id", Value: scopeID(child)}}).Decode(&doc)
	switch {
	case errors.Is(err, mongo.ErrNoDocuments):
		return wardn.Scope{}, false, nil
	case err != nil:
		return wardn.Scope{}, false, fmt.Errorf("wardnmongo: reading parent: %w", err)
	}
	return wardn.Scope{Type: doc.Type, ID: doc.ID}, true, nil
}

// --- custom roles ----------------------------------------------------------

type roleDoc struct {
	ID          string   `bson:"_id"`
	OwnerType   string   `bson:"ot"`
	OwnerID     string   `bson:"oi"`
	Name        string   `bson:"name"`
	NameKey     string   `bson:"nk"`
	Description string   `bson:"desc"`
	Allow       []string `bson:"allow"` // custom roles only grant (design decision D2)
	Assignable  []string `bson:"assignable"`
	Version     int      `bson:"v"`
	Created     int64    `bson:"c"`
	Updated     int64    `bson:"up"`
}

func toRoleDoc(r wardn.CustomRole) roleDoc {
	return roleDoc{ID: r.ID, OwnerType: r.Owner.Type, OwnerID: r.Owner.ID, Name: r.Name, NameKey: r.NameKey,
		Description: r.Description, Allow: r.Allow, Assignable: r.AssignableAt, Version: r.Version,
		Created: r.CreatedAt.UnixMicro(), Updated: r.UpdatedAt.UnixMicro()}
}

func (d roleDoc) role() wardn.CustomRole {
	return wardn.CustomRole{ID: d.ID, Owner: wardn.Scope{Type: d.OwnerType, ID: d.OwnerID}, Name: d.Name, NameKey: d.NameKey,
		Description: d.Description, Allow: d.Allow, AssignableAt: d.Assignable, Version: d.Version,
		CreatedAt: time.UnixMicro(d.Created).UTC(), UpdatedAt: time.UnixMicro(d.Updated).UTC()}
}

// CreateRole implements wardn.Store. The unique index on (owner, name key)
// makes the name check atomic.
func (s *Store) CreateRole(ctx context.Context, r wardn.CustomRole) error {
	if _, err := s.roles.InsertOne(ctx, toRoleDoc(r)); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return wardn.ErrRoleNameTaken
		}
		return fmt.Errorf("wardnmongo: creating role: %w", err)
	}
	return nil
}

// UpdateRole implements wardn.Store: a single conditional update on the
// role's version, so concurrent edits cannot both succeed.
func (s *Store) UpdateRole(ctx context.Context, r wardn.CustomRole, expectedVersion int) error {
	res, err := s.roles.UpdateOne(ctx,
		bson.D{{Key: "_id", Value: r.ID}, {Key: "v", Value: expectedVersion}},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "name", Value: r.Name}, {Key: "nk", Value: r.NameKey}, {Key: "desc", Value: r.Description},
			{Key: "allow", Value: r.Allow}, {Key: "assignable", Value: r.AssignableAt},
			{Key: "v", Value: r.Version}, {Key: "up", Value: r.UpdatedAt.UnixMicro()},
		}}})
	switch {
	case mongo.IsDuplicateKeyError(err):
		return wardn.ErrRoleNameTaken
	case err != nil:
		return fmt.Errorf("wardnmongo: updating role: %w", err)
	case res.MatchedCount == 1:
		return nil
	}
	n, err := s.roles.CountDocuments(ctx, bson.D{{Key: "_id", Value: r.ID}})
	if err != nil {
		return fmt.Errorf("wardnmongo: updating role: %w", err)
	}
	if n == 0 {
		return wardn.ErrRoleNotFound
	}
	return wardn.ErrConflict
}

// DeleteRole implements wardn.Store.
func (s *Store) DeleteRole(ctx context.Context, id string) error {
	if _, err := s.roles.DeleteOne(ctx, bson.D{{Key: "_id", Value: id}}); err != nil {
		return fmt.Errorf("wardnmongo: deleting role: %w", err)
	}
	return nil
}

// Roles implements wardn.Store.
func (s *Store) Roles(ctx context.Context, ids []string) ([]wardn.CustomRole, error) {
	if len(ids) == 0 {
		return nil, ctx.Err()
	}
	if len(ids) > maxIDs {
		return nil, fmt.Errorf("wardnmongo: %d role IDs in one query; the maximum is %d", len(ids), maxIDs)
	}
	return s.findRoles(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: ids}}}})
}

// RolesOwnedBy implements wardn.Store.
func (s *Store) RolesOwnedBy(ctx context.Context, owners []wardn.Scope) ([]wardn.CustomRole, error) {
	if len(owners) == 0 {
		return nil, ctx.Err()
	}
	if len(owners) > maxIDs {
		return nil, fmt.Errorf("wardnmongo: %d owners in one query; the maximum is %d", len(owners), maxIDs)
	}
	or := make(bson.A, len(owners))
	for i, o := range owners {
		or[i] = bson.D{{Key: "ot", Value: o.Type}, {Key: "oi", Value: o.ID}}
	}
	return s.findRoles(ctx, bson.D{{Key: "$or", Value: or}})
}

func (s *Store) findRoles(ctx context.Context, filter bson.D) ([]wardn.CustomRole, error) {
	cur, err := s.roles.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("wardnmongo: reading roles: %w", err)
	}
	var docs []roleDoc
	if err := cur.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("wardnmongo: reading roles: %w", err)
	}
	out := make([]wardn.CustomRole, len(docs))
	for i, d := range docs {
		out[i] = d.role()
	}
	return out, nil
}

var (
	_ wardn.Store    = (*Store)(nil)
	_ wardn.Migrator = (*Store)(nil)
)
