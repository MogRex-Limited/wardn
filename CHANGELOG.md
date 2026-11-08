# Changelog

All notable changes to wardn are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and wardn uses
[semantic versioning](https://semver.org/). Security fixes are always called out.

## [Unreleased]

### Added

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
- The confused-deputy tests in the bank and SaaS apps are now
  `TestThreat_T02_ConfusedDeputy`, so T02 is traced like every other threat.

### Removed

- CodeQL workflow, until the repository is public or GitHub Advanced
  Security is enabled (see docs/MAINTAINING.md).
