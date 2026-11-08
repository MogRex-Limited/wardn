# Changelog

All notable changes to wardn are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and wardn uses
[semantic versioning](https://semver.org/). Security fixes are always called out.

## [Unreleased]

## [1.1.0] - 2026-11-08

Released together with `store/mongo` v1.1.0 and `cache/redis` v1.1.0. Every
change is an addition: nothing in v1.0.0 changes.

### Added

- **Changes inside your own transaction.** `wardnsql.Store.WithTx(ctx, tx)`
  and `Warden.Transaction(ctx)` let `Assign`, `Revoke`, `Link`, `Move` and
  custom-role changes commit or roll back with the application's own writes,
  such as a membership row, an audit record or an outbox message. The SQL
  store writes in savepoints, so a failed write (for example a taken role
  name) leaves the transaction usable, including on PostgreSQL. New:
  `wardn.TxStore`, `wardn.ErrNoTransaction`. Guide: *Changes in your own
  transaction*, including sharing a transaction with pgx.
- **`CheckEach` and `CanEach`:** one permission at many scopes, for filtering
  lists, in a few store reads instead of a few per item. Decisions are the
  same as `Check`'s, with the same reasons. `wardn.MaxCheckEach` bounds a
  call at 1,000 scopes.
- **Guide: Row-level security**, for PostgreSQL applications that use RLS
  and a restricted database role: grants, migrations, tenant transactions,
  and making `ParentOf` see parents.

### Security

- New threat **T28**: uncommitted access escaping an application's
  transaction through the cache or the request memo. Inside a transaction,
  wardn bypasses both and invalidates again after the commit; a change with
  only half of the transaction setup fails with `ErrNoTransaction`. Tested in
  the core with every safeguard mutated, and against every SQL database.

## [1.0.0] - 2026-11-08

Released together with `store/mongo` v1.0.0 and `cache/redis` v1.0.0.

**wardn v1.0.0, the first release.** wardn is authorization for Go services. You
define your permissions, roles and scope hierarchy (organisations, regions,
branches, workspaces…) in one policy file. wardn stores who has which role
where, checks every request, protects HTTP routes, stops admins from granting
more than they hold, and records every change for your audit trail. It runs
inside your service, on the database you already run.

From this release, the API is stable: nothing in v1 will break code, data or
decisions that rely on v1.0.0 ([STABILITY.md](docs/STABILITY.md)).

### Highlights

- **Your model, not ours.** Permissions, roles and any depth of scope
  hierarchy, defined in YAML (or Go) and validated with file, line and "did
  you mean". `wardn gen` turns the policy into Go constants, so typos fail to
  compile. `wardn check` validates it in CI.
- **Checks you can trust.** Default deny, inheritance down the hierarchy, deny
  wins, fail closed on any error, and time-limited access that starts and ends
  on time with no cleanup job. Every decision explains itself.
- **HTTP in one line.** `Require` and `RequireAny` middleware for net/http and
  chi. Undefined permissions fail at startup. `wardntest.AuditRoutes` fails a
  test for any route you forgot to protect.
- **Custom roles for admin screens**, with the escalation guard on by default:
  nobody can create, edit, assign or revoke a role with permissions they don't
  hold. APIs for role lists, assignable roles and paginated members.
- **An audit trail that can't be skipped.** `OnChange` runs before every
  change and can veto it, and runs again if the change fails. Events marshal
  to stable JSON. Expiries are reported exactly once.
- **Your database.** PostgreSQL 13+, MySQL 8.0+, MariaDB 10.6+, SQLite 3.24+
  and MongoDB 6.0+, with automatic, lock-protected migrations. Any store you
  write is proven by the same conformance suite (`storetest`).
- **Fast when you need it.** About 0.7–1 ms per check against a database
  server (measured with the server on the same machine).
  Several checks in one request cost about the same as one. An opt-in cache
  (in memory, or shared through Redis or Valkey with signed entries) brings
  checks down to tens of microseconds and never serves a stale grant.
  Measurements are on the Performance page.
- **Testing built in.** `wardntest` runs your real policy in memory, with a
  controllable clock and one-line test users.

### Evidence

- 218 tests, fuzz targets and examples across five modules, run with the
  race detector on Go 1.26 and 1.27, and against real PostgreSQL, MySQL,
  MariaDB, MongoDB and Redis on every change.
- A threat model of 27 threats, each with a `TestThreat_` test. A property
  test checks the engine against an independent reference implementation,
  and another attacks the escalation guard in random worlds.
- An internal security review (docs/SECURITY_REVIEW.md) and an API review
  before the freeze. Every finding is fixed and has a regression test. Fault
  injection covers every write path on every change. 8 fuzz targets and 50
  security mutants run every week.
- Four reference applications (a multi-branch bank, a multi-tenant SaaS, a
  school system and a simple app) built only on the public API.
- Signed releases. The `wardn` CLI binaries are reproducible, with checksums
  and Sigstore build provenance.

### Requirements

Go 1.26 or newer. The core module depends only on the standard library and
YAML. The SQL store works through `database/sql` with the driver you already
use. MongoDB and Redis support are separate modules, so a service pulls in
only what it uses.

### If you used a pre-release commit

These changed during the final review. Each one is described in full below.

- **`AssignOption` is no longer `func(*Assignment)`** (security fix). Only
  `wardn.From` and `wardn.Until` exist. Code that wrote its own options must
  use those.
- **`Link` never moves a scope** that already has a parent. It returns
  `ErrAlreadyLinked` (409). Use `Move` to move one on purpose, which is
  audited as `scope.moved`.
- **`Event` has JSON field names.** Audit records written with
  `json.Marshal` change from `"Type"` to `"type"` and so on.
- **The cache key format changed.** Entries cached by earlier commits are
  ignored; nothing to do.

### Not included

- **No external security audit.** v1.0 rests on the internal review and the
  evidence above (DESIGN.md D16).
- **SQL Server**, until a product needs it (D12).
- **Not yet built:** maker-checker approval, attribute conditions (such as
  amount limits), Gin and Echo helpers, and a server mode for non-Go
  services. Each will be added when a product needs it.

### Added (full history, by milestone)

- Design document, threat model, and security policy.
- Secure development foundation (M1): CI with tests under the race detector,
  security linting, govulncheck, module verification, and a direct
  dependency allowlist; SHA-pinned actions; Dependabot with cooldown;
  contribution rules and maintainer release process.
- Pre-push hook (`make hooks`) that runs every CI gate locally before a push.

- Core engine (M2):
  - Policy loading from YAML (`LoadPolicyFile`, `ParsePolicy`) or Go (`Policy`), with
    validation that reports every problem at once, each with file, line and a
    "did you mean" suggestion. YAML anchors and aliases, oversized files, and
    multiple documents are rejected.
  - Evaluation engine (`Check`, `Can`, `CanAny`, `CanAll`) implementing all seven
    evaluation rules: default deny, downward inheritance through product-defined
    scope hierarchies, accumulating allows, deny wins, fail closed, dangling
    roles ignored, and time windows. Every `Decision` explains itself.
  - `PermissionsOf`, `RolesOf`, `Catalog`, `SystemRoles`.
  - Scope hierarchy through stored links (`Link`) or `Config.ParentOf`.
  - `System()` for unguarded management: `Assign` (with `From` / `Until` time
    windows and `assignable_at` enforcement) and `Revoke`.
  - Per-request memoisation (`WithMemo`); `OnDecision` audit hook; injectable `Clock`.
  - `MemoryStore` and the `Store` interface.
  - `wardntest` package: `New`, `NewFromPolicy`, `AllowAll`, `AsRole`, `AsRoleIn`,
    `NewUser`, and a fake `Clock`.
  - Tests: one per evaluation rule; `TestThreat_` tests for 13 threats; a
    property test against an independent reference implementation; fuzz targets.

- Storage (M3):
  - `store/sql` (package `wardnsql`): a `Store` for PostgreSQL, MySQL, MariaDB
    and SQLite over `database/sql`, with no driver dependency. The dialect is
    detected from the driver. IDs compare exactly on every database (binary
    columns on MySQL/MariaDB), times are stored as microseconds without ever
    widening a window, and table names come only from a validated prefix.
  - Versioned, idempotent migrations, safe under concurrent startup, that
    refuse a schema written by a newer wardn (`ErrSchemaTooNew`). `wardn.New`
    runs them through the new `Migrator` interface unless
    `Config.ManualMigrations` is set.
  - `storetest`: the conformance suite every `Store` must pass, covering
    isolation, exact identity, hostile IDs, time handling, cancellation and
    concurrency.
  - `MemoryStore` now honours context cancellation.
  - Integration test module (`tests/integration`) running the suite against
    real PostgreSQL, MySQL and MariaDB (Docker locally with `make integration`,
    service containers in CI), with its own dependency allowlist.

- HTTP and tooling (M4):
  - `Require(perms...)` (all needed) and `RequireAny(perms...)` middleware for
    net/http and chi, with no router dependency. Undefined permissions panic at
    route registration. No user → 401, denied → 403, bad scope → 400, store
    error → 500; the handler never runs on any of them.
  - `ScopeFrom(scopeType, id)` with `PathValue(name)`, which works with chi
    through Go's standard `r.PathValue`, so no chi adapter is needed.
  - `Config.UserFrom` and `Config.OnError`; `DeniedError`, `ErrDenied`,
    `ErrUnauthenticated`, `HTTPStatus`. Default error bodies are generic JSON
    and reveal nothing.
  - `wardntest.AuditRoutes`: fails a test for any route that doesn't answer 403
    to a signed-in user with no roles (catches routes that forgot `Require`).
  - `wardn` CLI: `check` validates a policy for CI; `gen` writes Go constants
    for permissions, roles and scope constructors, and `gen -check` fails if
    they are stale. Output failures make the command fail.
  - Release workflow: signed-tag check, reproducible cross-platform CLI builds,
    checksums and Sigstore build provenance.

- Custom roles and the escalation guard (M5):
  - `CreateRole`, `UpdateRole` (optimistic concurrency), `DeleteRole` (with
    `Cascade()`), and guarded `Assign` and `Revoke`, acting as the user in the
    context. Custom roles are grants-only, belong to a scope, and apply only
    within its subtree. Names resist spoofing (one script, no invisible
    characters or combining marks, unique ignoring case and spacing).
  - The escalation guard: nobody can create, edit, assign or revoke a role
    containing a permission they don't hold. Holding a wildcard means holding
    all of it, with no deny inside. `ErrEscalation`, `ErrRoleInUse`,
    `ErrRoleNameTaken`, `ErrRoleNotFound`, `ErrConflict`.
  - `System()` gains the same management methods, unguarded.
  - Admin-screen APIs: `Roles`, `AssignableRoles`, `Members` (paginated) and
    `CustomRole`.
  - Audit: `Config.OnChange` is called before every change (and can veto it),
    and again if the change fails. `Link` is audited too.
  - Expiry sweeper: `SweepExpired` (with `RemoveExpired()`) and `RunExpiry`
    report expired assignments exactly once.
  - `Store` now includes `RoleStore` and the new `AssignmentStore` methods.
    SQL schema v2 adds role tables (with an `effect` column for future
    denies), expiry reporting and indexes. Steps that can't use
    `IF NOT EXISTS` check before running, so interrupted migrations re-run
    safely. `wardnsql.LatestSchemaVersion`, `Store.TablePrefix`.
  - The conformance suite grows to 25 checks, including atomic name
    uniqueness and atomic versioned updates under concurrent writers.

- Completeness (M6):
  - Opt-in cross-request cache: `Config.Cache`, `Config.CacheTTL`,
    `wardn.NewMemoryCache()` for a single instance, and the `cache/redis`
    module (package `wardnredis`) for shared caching. It caches store data,
    never decisions, so time windows stay exact. Version counters are bumped
    before and after every change, so no instance serves stale data after a
    change made through wardn. Keys are hashes. Cache failures fall back to
    the store. `InvalidateCache` handles changes made behind wardn's back.
    `ErrCacheInvalidation`.
  - `cachetest`: the conformance suite for caches, including atomic counters.
  - `store/mongo` module (package `wardnmongo`): a MongoDB store passing all
    25 store checks, with no transactions needed and safe against operator
    injection.
  - Public types (`Scope`, `Assignment`, `CustomRole`, `RoleSpec`, `RoleInfo`,
    `Decision`, `Permission`) have stable snake_case JSON field names.
  - Build: every gate runs on every module, CI lints each module separately,
    and the integration job adds MongoDB and Redis.
  - SQL Server is not supported until a product needs it; products use
    PostgreSQL and MySQL (DESIGN.md D12).

- Hardening (M7):
  - Internal security review (docs/SECURITY_REVIEW.md): one high, four medium
    and six low findings, all fixed with regression tests. **Security fixes:**
    - Assigning or revoking a role now requires holding what it denies as well
      as what it grants (F1, F1b: high).
    - Cache entries are sealed with HMAC-SHA256. Shared caches require
      `Config.CacheSecret` (FZ1, found by fuzzing).
    - Cache invalidation after partial writes (F2). Audit never records an
      abandoned change (F3). The sweeper no longer removes re-granted
      assignments, using the new `Store.RevokeExpired` (F4).
    - Management answers no longer reveal role existence (F5). Times outside
      years 1–9999 are rejected (F6).
    - Look-alike role names are folded together (F7). `Event.System`
      replaces `SystemActor` (F8). At most 500 custom roles per scope (F9).
    - Redis keys share a hash slot, for Redis Cluster.
  - `HTTPStatus` maps management errors: 404 unknown role, 409 conflict,
    taken name or role in use, 400 not assignable, 403 escalation.
  - Fault injection on every store, cache and SQL write path; mutation
    testing (`make mutation`, 46 security mutants); five new fuzz targets
    and `make fuzz`; a weekly "Deep checks" CI workflow running both.

- Documentation site (M8, `website/`): a landing page and 37 documentation
  pages built with Astro Starlight: getting started, concepts, guides,
  recipes, reference, security and project. It has full-text search, link
  validation on every build, `make docs` and `make docs-build`, a hardened
  container for internal hosting, and a CI job.

- Reference applications (M8, `examples/`, its own module): `bank`
  (organisations, regions and branches; custom approver role for a week;
  suspension; maker-checker), `saas` (workspaces, customer-defined roles,
  per-project access), `simple` (no tenancy) and `school` (hierarchy through
  `ParentOf`; students see only their own grades). They use only the public
  API with chi, SQLite and generated names. Each app's tests check its recipe
  page request by request, audit every route, and check generated code is
  current. Their route audit caught an ID-enumeration mistake in an early
  SaaS draft, and the multi-tenancy guide now teaches "authorize first, then
  look up".

- Usability rehearsal (M8): a developer agent with only the documentation
  built a clinic service and kept a friction log. Fixes from it:
  - **Security:** `Link` no longer re-parents an already-linked scope; it
    fails with the new `ErrAlreadyLinked` (409), so two tenants reusing an ID
    can't move each other's scopes (threat model T27). The new `Move` changes a
    parent on purpose.
  - Repeating a change that changes nothing (same assignment and window, or
    the same parent) is no longer written or audited.
  - New `w.Now()`, so application code computing time windows uses wardn's
    (test-controllable) clock.
  - Docs: the Quick Start's authentication middleware no longer erases the
    test user (its own test failed before); scope IDs must be unique per type,
    with the composite-ID pattern; the confused-deputy section is clearer;
    `go get -tool` for the CLI; `wardntest` options, `AssignOption`, the
    `ScopeFrom` ID function, event fields and check order are documented.

- Benchmarks (M8): `storetest.Bench` measures any store on a bank-sized
  dataset (1,000 branches, about 20,000 assignments): single checks, custom
  roles, denials, ten checks in one request, parallel checks, with and
  without the cache, and assignments. It runs on the memory store, every SQL
  database and MongoDB, plus whole HTTP requests in the bank app (`make
  bench`, `make bench-all`). Results and advice are on the new Performance
  page. A finding: the default `database/sql` pool more than halves parallel
  throughput on PostgreSQL, so the stores guide now says to size it.
- API review before v1.0 (M9):
  - **Security:** `AssignOption` was `func(*Assignment)`, so an option written
    by the application could change the role, scope or user after the
    escalation guard had checked them, and the audit event recorded the
    original request. Options now set only the time window (`From`, `Until`).
    Breaking only for code that wrote its own options.
  - `Move` is audited as the new `scope.moved` event, with `PreviousParent`.
    A move of a scope with no parent yet is still `scope.linked`.
  - `Event` marshals to JSON with stable snake_case names, like every other
    public type, and writes `Err` as its message under `error`.
- Stability promise for v1 (M9, `docs/STABILITY.md`, and a page on the site):
  what stays compatible across every v1 release (Go API, decisions, policy
  files, JSON and event names, HTTP statuses, database schemas, the `Store`
  and `Cache` interfaces, the CLI), what may change, and the security
  exception. `make api` (in `make check` and a new CI job) compares every
  change with each module's latest v1 tag using `apidiff`;
  `stability_test.go` pins the names other systems keep. Cache keys now carry
  a format number, so releases sharing a cache never read each other's
  entries.
- No external security audit for v1.0 (DESIGN.md D16). The internal security
  review's brief now addresses any later reviewer.
- The confused-deputy tests in the bank and SaaS apps are now
  `TestThreat_T02_ConfusedDeputy`, so T02 is traced like every other threat.
- Clock skew (threat model T19) is tested and documented: two instances
  sharing a store and cache, one with a slow clock, are wrong by exactly the
  skew and no longer. The time-limited access guide explains what skew does.
  The route-audit and MongoDB operator-injection tests are renamed
  `TestThreat_T17_...` and `TestThreat_T26_...`, so every threat now has a
  `TestThreat_` test.

### Removed

- CodeQL workflow, until the repository is public or GitHub Advanced
  Security is enabled (see docs/MAINTAINING.md).
