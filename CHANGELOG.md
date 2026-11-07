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

### Removed

- CodeQL workflow, until the repository is public or GitHub Advanced
  Security is enabled (see docs/MAINTAINING.md).
