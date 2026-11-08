<div align="center">

<img src="website/src/assets/logo.svg" alt="wardn" width="96" height="96">

# wardn

**Simple, opinionated authorization for Go.**

Define your roles, permissions and tenancy in one file. wardn stores them, checks every request,<br>
stops privilege escalation and keeps an audit trail, inside your app, on the database you already run.

[![CI](https://github.com/MogRex-Limited/wardn/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MogRex-Limited/wardn/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/release-v1.0.0-0f766e)](CHANGELOG.md)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![Stability](https://img.shields.io/badge/API-stable%20v1-115e59)](docs/STABILITY.md)
[![Threats tested](https://img.shields.io/badge/threats%20tested-27%2F27-115e59)](docs/THREAT_MODEL.md)

[Documentation](#documentation) · [Quick start](#quick-start) · [Examples](#examples) · [Security](#security) · [Changelog](CHANGELOG.md)

</div>

---

Every product needs to answer the same question: *is this user allowed to do this, here?* Most teams answer it with a hand-built role system that grows a little more fragile with every feature. wardn replaces it with one small library:

- **Your model, not ours.** wardn knows nothing about banks, schools or SaaS. Your product declares its own permissions, roles and scope tree: flat, one level, or as deep as it needs.
- **No new infrastructure.** wardn is a library, not a server. It runs in your process and keeps its data in your PostgreSQL, MySQL, MariaDB, SQLite or MongoDB database.
- **Safe by default.** Default deny. Deny always wins. Any error means "no". Error responses reveal nothing. None of this can be switched off.

```text
organisation:acme                     ada  → org_admin      (everything in Acme)
 └── region:south
      └── branch:lagos                bayo → teller         (this branch only)
                                      tolu → loan_officer   (until Friday)
```

## Contents

- [Quick start](#quick-start)
- [Features](#features)
- [Choosing the right tool](#choosing-the-right-tool)
- [Supported platforms](#supported-platforms)
- [Examples](#examples)
- [Performance](#performance)
- [Security](#security)
- [Stability](#stability)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Author](#author)
- [License](#license)

## Quick start

**1. Install** (Go 1.26 or newer):

```bash
go get github.com/MogRex-Limited/wardn@v1.0.0
```

> [!NOTE]
> The repository is private for now. Run `go env -w GOPRIVATE=github.com/MogRex-Limited/*` once, with Git access to the organisation. The [installation guide](website/src/content/docs/getting-started/installation.mdx) has the details.

**2. Describe your product** in `wardn.yaml`:

```yaml
scopes:
  organisation: {}
  branch: { parent: organisation }

permissions:
  customer:view: View customers
  loan:create:   Create loan applications
  loan:approve:  Approve loans

roles:
  org_admin:
    assignable_at: [organisation]
    allow: ["*"]
  teller:
    assignable_at: [branch]
    allow: [customer:view, loan:create]
```

**3. Start wardn** in `main`. It validates the policy and creates its tables:

```go
w := wardn.MustNew(wardn.Config{
	File:  "wardn.yaml",
	Store: wardnsql.MustNew(db), // your existing *sql.DB
})
```

**4. Protect your routes** (net/http or chi):

```go
r.Route("/branches/{branchID}", func(r chi.Router) {
	r.Use(w.ScopeFrom("branch", wardn.PathValue("branchID")))
	r.With(w.Require("loan:create")).Post("/loans", createLoan)
	r.With(w.Require("loan:approve")).Post("/loans/{id}/approve", approveLoan)
})
```

No user gets `401`, no permission gets `403`, and your handler never runs for either. A typo in a permission name stops the app at startup, with a "did you mean …?".

**5. Prove it with a test.** `wardntest` runs your real policy in memory:

```go
func TestTellersCannotApproveLoans(t *testing.T) {
	w := wardntest.New(t, "wardn.yaml")
	req := httptest.NewRequest("POST", "/branches/lagos/loans/7/approve", nil)
	req = wardntest.AsRoleIn(t, w, req, wardn.NewScope("branch", "lagos"), "teller")

	rec := httptest.NewRecorder()
	newRouter(w).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
}
```

The [full quick start](website/src/content/docs/getting-started/quick-start.mdx) also seeds the first administrator and covers authentication.

## Features

| | |
|---|---|
| **Policy as one file** | Permissions, roles and scope hierarchy in YAML (or Go), validated with file, line and suggestions. `wardn gen` generates Go constants, so typos fail to compile. `wardn check` validates the file in CI. |
| **Hierarchy and tenancy** | Roles assigned at a scope apply to everything below it. Parents are stored with `Link` or resolved from your own data with `ParentOf`. Tenants stay isolated. |
| **Checks** | `Require` / `RequireAny` middleware, plus `Can`, `CanAny`, `CanAll` and `Check` in code. Every `Decision` says which role and rule decided it. |
| **Custom roles** | Admins create roles at runtime for their own scope. The **escalation guard** stops anyone from creating, editing, assigning or revoking a role with permissions they don't hold. |
| **Admin screen APIs** | Role lists, assignable roles, paginated members and permissions-of-user, ready for a "Manage access" page. |
| **Time-limited access** | `From` and `Until` on any assignment. Access starts and stops on time with no cleanup job, and each expiry is recorded once. |
| **Audit trail** | `OnChange` runs before every change and can veto it. Events marshal to stable JSON. `OnDecision` sees every check. |
| **Caching** | Off by default. An opt-in cache, in memory or shared through Redis or Valkey, caches data, never decisions, with signed entries and instant invalidation on every instance. |
| **Testing** | `wardntest` for your tests, `AuditRoutes` to catch unprotected routes, and conformance suites (`storetest`, `cachetest`) for your own store or cache. |

## Choosing the right tool

| | **wardn** | Casbin | OpenFGA / SpiceDB | Home-grown |
|---|---|---|---|---|
| **Built for** | Roles and tenancy inside a Go product | General policy models, in many languages | Sharing individual objects across millions of them (Zanzibar-style) | A product's first few checks |
| **Runs** | Inside your app, on your database | Inside your app | As a separate service | Inside your app |
| **Your team learns** | One YAML file | Casbin's model language | A modelling language and relationship tuples | Nothing new, at first |
| **Tenancy and hierarchy** | Built in | Domains built in; scope trees are yours to build | Built in, as relationships | Yours to build |
| **Admin-created roles that can't escalate** | Built in | Yours to build | Yours to build | Rarely done |
| **Time-limited access** | Built in | Yours to build | Supported | Rarely done |
| **Audit of every change** | Built in, and can block a change | Yours to build | Change history API | Rarely done |

Different tools for different jobs. wardn is built for roles and tenancy inside a Go product: no extra service, no new language, and the safety rules built in. OpenFGA and SpiceDB are built for sharing individual objects between people and groups at very large scale. They work well together: many products use wardn for who runs what in the organisation, and a relationship service for who can see which document. The [Learn](website/src/content/docs/learn/models.mdx) pages explain the models in depth.

## Supported platforms

| | Supported | Module |
|---|---|---|
| **Go** | 1.26, 1.27 (the two releases with security support) | |
| **PostgreSQL** | 13+ | `github.com/MogRex-Limited/wardn/store/sql` |
| **MySQL** | 8.0+ | `github.com/MogRex-Limited/wardn/store/sql` |
| **MariaDB** | 10.6+ | `github.com/MogRex-Limited/wardn/store/sql` |
| **SQLite** | 3.24+ | `github.com/MogRex-Limited/wardn/store/sql` |
| **MongoDB** | 6.0+ | `github.com/MogRex-Limited/wardn/store/mongo` |
| **Redis / Valkey** | shared cache (optional) | `github.com/MogRex-Limited/wardn/cache/redis` |
| **Routers** | net/http, chi, and anything built on `http.Handler` | core |

The core module depends only on the standard library and YAML. The SQL store uses `database/sql` with the driver you already have, and MongoDB and Redis support live in their own modules, so your service pulls in only what it uses.

## Examples

Four complete applications in [`examples/`](examples), built only on the public API, each with tests that walk through its recipe request by request:

| App | Shows |
|---|---|
| [`bank`](examples/bank) | Organisations › regions › branches; tellers, managers and auditors; a custom approver role for one week; suspensions; maker-checker |
| [`saas`](examples/saas) | Workspaces as tenants, customer-defined roles, per-project access |
| [`school`](examples/school) | Hierarchy from your own data with `ParentOf`; students see only their own grades |
| [`simple`](examples/simple) | No tenancy at all: roles and permissions for one app |

```bash
cd examples && go run ./bank    # then follow examples/bank/README.md
```

## Performance

A check costs a few database reads. Measured on a bank with 1,000 branches and about 20,000 assignments:

| Store | One check | 10 checks in one request | With the cache |
|---|---|---|---|
| In memory | 2–5 µs | 26 µs | — |
| SQLite | ~0.1 ms | 0.14 ms | 25–40 µs |
| PostgreSQL, MySQL, MariaDB, MongoDB | 0.7–1.1 ms | 0.7–1.2 ms | 25–45 µs |

Database servers ran on the same machine. Run `make bench` or `make bench-all` to measure your own setup, and see the [performance guide](website/src/content/docs/guides/performance.mdx) for tuning.

## Security

A flaw in an authorization library is a flaw in every product that uses it, so wardn is tested the way an attacker thinks:

- A [threat model](docs/THREAT_MODEL.md) of 28 threats, **each with its own `TestThreat_` test**.
- A property test that checks about 130,000 decisions per run against an independent reference implementation, and another that attacks the escalation guard in random worlds.
- Fault injection on every store, cache and SQL write path. Any failure must deny, never allow.
- 58 deliberately broken security rules, every one caught by the test suite (`make mutation`), plus 8 fuzz targets. Both run every week.
- An [internal security review](docs/SECURITY_REVIEW.md) and an API review before v1.0. Every finding is fixed and has a regression test. There has been no external audit ([decision D16](docs/DESIGN.md)).
- Signed releases. The CLI binaries are reproducible, with checksums and Sigstore build provenance.

**Found a vulnerability?** Please don't open an issue. Follow the [security policy](SECURITY.md) to report it privately.

## Stability

wardn follows semantic versioning. From v1.0.0, **nothing in v1 will break your code, your data or the decisions wardn makes**: Go API, policy files, JSON and audit event names, HTTP statuses and database schemas all stay compatible. Every change is checked automatically against the latest release (`make api`). Read the [stability promise](docs/STABILITY.md).

## Documentation

The documentation site lives in [`website/`](website): getting started, concepts, guides, recipes, reference and security. Run it locally:

```bash
make docs    # http://localhost:4321
```

| Start here | |
|---|---|
| [Quick start](website/src/content/docs/getting-started/quick-start.mdx) | Your first protected route in about ten minutes |
| [Concepts](website/src/content/docs/concepts/overview.mdx) | Permissions, roles, scopes, assignments, and how a decision is made |
| [Multi-tenancy](website/src/content/docs/guides/multi-tenancy.mdx) | Tenants, hierarchy, and "authorize first, then look up" |
| [Custom roles](website/src/content/docs/guides/custom-roles.mdx) | A safe "Create role" screen for your admins |
| [Design](docs/DESIGN.md) | How wardn works and why, with every design decision |

## Contributing

Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md). Everything CI checks runs locally:

```bash
make hooks   # once: run every check before each push
make check   # tests, race detector, linters, vulnerabilities, dependency allowlist, API compatibility
make integration   # everything against real PostgreSQL, MySQL, MariaDB, MongoDB and Redis (Docker)
```

Maintainers: releases and repository settings are in [docs/MAINTAINING.md](docs/MAINTAINING.md).

## Author

wardn was designed and built by **Abakpa Dominic** ([@DT-GAMER](https://github.com/DT-GAMER)), who maintains it with the code owners listed in [`.github/CODEOWNERS`](.github/CODEOWNERS).

## License

wardn is internal to MogRex Limited.
