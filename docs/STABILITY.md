# wardn — Stability Promise

| | |
|---|---|
| **Applies from** | v1.0.0 |
| **Applies to** | Every v1.x.y release of `github.com/MogRex-Limited/wardn`, `.../store/mongo`, `.../store/pgx` (from v1.2.0) and `.../cache/redis` |
| **Enforced by** | `make api` (`scripts/apicheck.sh`) and `stability_test.go`, in `make check` and CI |

An authorization library sits under every route of every product that uses it. Upgrading within v1 must be safe and boring: run `go get -u`, run your tests, and deploy. A change that would break code, data or behaviour that relies on v1.0.0 waits for v2. We expect never to need v2.

---

## 1. What stays compatible

| Area | Promise | Checked by |
|---|---|---|
| **Go API** | Code that compiles against v1.0.0 compiles against every later v1 release. This covers the packages `wardn`, `wardntest`, `storetest`, `cachetest`, `store/sql` (`wardnsql`), `store/mongo` (`wardnmongo`), `store/pgx` (`wardnpgx`) and `cache/redis` (`wardnredis`). | `make api`: every pull request is compared with the latest v1 tag of each module, using `apidiff` |
| **Decisions** | The evaluation rules (DESIGN.md §5) do not change. A check that a v1.0.0 policy and set of assignments allows stays allowed, and a denied one stays denied. | The rule tests, the property test against the reference implementation, and the mutation suite |
| **Policy files** | A `version: 1` policy file that loads in a v1 release loads, and means the same, in every later v1 release. New optional keys may be added. A file that uses them won't load in older releases. | Policy tests and fuzzing |
| **Names other systems keep** | JSON field names of public types (`Event`, `Decision`, `Assignment`, `CustomRole`, `RoleInfo`, `RoleSpec`, `Permission`, `Scope`); audit event types (`assignment.created`…); built-in permission names (`wardn:roles.assign`, `wardn:roles.manage`); the sentinel errors and their `HTTPStatus` codes; the generic default error responses. | `stability_test.go` |
| **Databases** | `New` upgrades wardn's tables and collections automatically. Within v1, migrations only **add** (tables, columns, indexes). They never rename or drop anything, so instances still running an older v1 keep working while a newer one rolls out. Table and collection prefixes and their defaults don't change. | `make integration`, on every supported database |
| **Store and Cache interfaces** | No method is added to `Store`, its parts, or `Cache` within v1, so a store or cache written for v1.0.0 keeps compiling. New capabilities come as **optional interfaces** that wardn detects, as `Migrator` already does. Implementations that lack them keep working. | `make api` |
| **CLI** | The `wardn` commands, flags and exit codes, and the identifiers `wardn gen` produces for a given policy. | CLI tests |

## 2. What may change in a minor or patch release

- **Wording:** error messages, `Decision.Reason`, the CLI's human-readable output, and log text. Match errors with `errors.Is` and `errors.As`, not on their text.
- **The cache's contents and key format.** Cache keys carry a format number (`cacheFormat` in `cache.go`). When what is cached changes, the number changes, so two releases sharing a cache during a rolling deploy never read each other's entries.
- **Performance**, the number and shape of store queries, and the conformance suite. `storetest` may gain checks. A store that fails a new check was already wrong in a way that the check now catches.
- **Unexported identifiers**, anything under `internal/`, the `tests/integration` and `examples` modules, and the CLI's Go code.
- **Supported Go versions.** wardn supports the two Go releases that receive security fixes (DESIGN.md D8). Requiring a newer Go once an old one loses support is not a breaking change.

## 3. Exceptions

- **Security.** If keeping something compatible would keep users exposed, it changes in a minor or patch release. Go itself follows the same rule. The CHANGELOG lists every such change under **Security**, with what users must do. A guard that becomes stricter is the typical case: an escalation that used to succeed starts failing with `ErrEscalation`.
- **Bugs.** Behaviour that contradicts the documentation is a bug, and fixing it is not a breaking change. If code may reasonably depend on the wrong behaviour, the CHANGELOG says so.

## 4. Rolling deploys and rollbacks

- **Rolling forward:** instances on different v1 releases can run side by side against the same database and cache.
- **Rolling back:** an older release **refuses to start** against a database that a newer release has upgraded (`ErrSchemaTooNew`), so it can't misread data it doesn't understand. Instances already running are unaffected. To roll back across a schema change, restore the database as well, or roll forward with a fix instead. The CHANGELOG says which releases change the schema.

## 5. Deprecation

Nothing public is removed in v1. Anything that should no longer be used gets a `// Deprecated:` comment naming its replacement. It keeps working until v2, and the CHANGELOG lists it under **Deprecated**. `staticcheck`, `gopls` and `pkg.go.dev` then point existing users to the replacement.

## 6. For maintainers

- `make api` runs in `make check` and CI. Before the first v1 tag of a module it has nothing to compare with and passes. `API_BASE=main make api` previews what a branch would break.
- `apidiff` reports a break even when it describes it oddly, for example "field removed" when a type it points to changed. Every line it prints is a break.
- When `stability_test.go` fails, restore the old value. Changing the expected value in the test is a breaking change.
- When something cached changes shape, increase `cacheFormat` in the same pull request.
- Migrations within v1 only add. A migration that renames or drops waits for v2. If the old structure must go, add the new one alongside it and keep reading both.
- Sub-modules share the core's major version: `store/mongo/v1.x.y`, `store/pgx/v1.x.y` and `cache/redis/v1.x.y` require a v1 core.
