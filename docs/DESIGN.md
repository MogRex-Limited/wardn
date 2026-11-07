# wardn — Design Document

| | |
|---|---|
| **Status** | Draft for review |
| **Date** | 2026-11-07 |
| **Audience** | Engineering leadership, product teams, future contributors |
| **Language** | Go |

---

## 1. Summary

**wardn** is an authorization library for Go. Every product in the organisation needs to answer the same question — *"is this user allowed to do this, here?"* — and today every product answers it with its own hand-built role system.

wardn replaces those with one shared, embedded library:

- **Each product defines its own world.** Permissions, roles, and the shape of its tenancy (organisations, branches, workspaces, schools…) are declared by the product. wardn knows nothing about banking, loans, or any specific business.
- **Simple by default, deep when needed.** A developer gets working, database-backed access control in about ten lines and ten minutes. Hierarchies, admin-created custom roles, privilege-escalation protection, and audit are built in and appear only when a product needs them.
- **No extra infrastructure.** wardn is a library, not a server. It runs inside the product and stores its data in the product's existing database — SQL or NoSQL.

```yaml
# wardn.yaml
scopes:
  organisation: {}
permissions:
  customer:view: View customer profiles
  loan:create:   Create loan applications
roles:
  admin: ["*"]
  staff: [customer:view, loan:create]
```

```go
w := wardn.MustNew(wardn.Config{File: "wardn.yaml", Store: wardnsql.New(db)})

r.With(w.Require("loan:create")).Post("/loans", createLoan)
```

That is the whole first experience: permissions and roles defined, tables created, routes protected.

---

## 2. Problem

### 2.1 What happens today

Every new product rebuilds role-based access control from scratch:

- **Repeated effort.** Each team spends days to weeks designing tables, writing middleware, and building role management screens — work that has nothing to do with the product itself.
- **Inconsistent behaviour.** "Admin" means something different in every product. Rules like "deny overrides allow" or "an organisation admin can act inside every branch" are implemented differently, or not at all.
- **Security risk.** Access control is easy to get subtly wrong. Common bugs in home-grown systems: missing tenant isolation (Org A's admin sees Org B's data), privilege escalation (an admin with "manage roles" grants themselves super-admin), failing open on database errors, and no audit trail of who granted what.
- **No shared knowledge.** A developer moving between products must relearn access control each time.

### 2.2 Why not use an existing tool?

| Tool | Strength | Why it doesn't fit as our default |
|---|---|---|
| **Casbin** | Very flexible; many languages | Developers must learn a policy model language (`.conf` matchers). Flexibility means every team still designs its own model — the inconsistency problem remains. |
| **OpenFGA / SpiceDB** (Zanzibar-style) | Relationship-based access at very large scale | Requires running and operating a separate service, and a different way of thinking (relation tuples, schemas). Heavy for typical product teams. |
| **OPA / Cedar** | General-purpose policy engines | Policies in a separate language; designed for policy-as-code across infrastructure, not for "roles and permissions inside a product with an admin screen". |
| **Home-grown** | Fits exactly | The problem described above. |

The gap: **an embedded, opinionated, product-agnostic RBAC library for Go that a normal product team can adopt in an afternoon and trust in production.** That is wardn.

---

## 3. Goals and non-goals

### 3.1 Goals

1. **Product-agnostic.** Any product can express its own permissions, roles, and tenancy shape without changing wardn.
2. **Ten minutes to first protected route.** One YAML file, one constructor, one middleware.
3. **Correct and secure by default.** Default deny, deny wins, fail closed, tenant isolation, escalation guard, audit hooks — all on without configuration.
4. **Any database.** SQL and NoSQL through a small storage interface, with official adapters and a conformance test suite for custom ones.
5. **Admin-created custom roles.** Products can let their administrators create and edit roles at runtime.
6. **Arbitrary scope hierarchies.** Flat, one level, or deep trees, defined by the product.
7. **Mistakes fail early and loudly.** Invalid configuration stops the application at startup with a helpful message; typos are caught at boot or compile time, not in production.
8. **Easy to test.** Product tests never need a database to exercise authorization.
9. **Open-source ready.** No company-specific code in the core.

### 3.2 Non-goals

These are deliberate. Each is a real need, but each would double the surface area of the core. They may become optional sub-packages later (see §14).

| Non-goal | Reason / alternative |
|---|---|
| **Authentication** (login, passwords, JWT, sessions) | wardn receives an already-authenticated user ID from the product's existing auth. |
| **Attribute-based conditions** ("approve loans under ₦5M", "only during business hours") | Product code handles these after `Can` succeeds. A future `wardn/conditions` module may cover common cases. |
| **Relationship-based access at Zanzibar scale** (arbitrary object graphs, "editor of a folder inherits to all documents") | Use OpenFGA/SpiceDB if this is the core need. wardn does support object-level grants when the object is modelled as a scope (§4.3). |
| **A policy server / non-Go clients** | wardn is embedded. A server mode can be built on top later if non-Go services need it. |
| **A user interface** | wardn provides every API an admin UI needs (§7.3); products build their own screens. A reference UI kit may follow. |
| **Multiple parents for a scope** (DAGs) | Scopes form a tree. Trees are predictable and cover almost every real tenancy model. |

---

## 4. Concepts

wardn has exactly four concepts. A developer must learn these and nothing else.

### 4.1 Permission

An action the code checks. Written as `resource:action`.

```
customer:view
loan:create
loan:approve
report:export
```

- Lowercase letters, digits, and `_`; segments separated by `:`. At least two segments.
- **Permissions are code.** They are declared by developers (in YAML or Go) because the code checks them. Administrators cannot invent permissions; they can only combine existing ones into roles.
- Every permission has a human-readable description, so admin screens can show "Approve loans" instead of `loan:approve`.
- The `wardn:` prefix is reserved for wardn's own built-in permissions (§6).

**Wildcards** may be used in role definitions, never in checks:

| Pattern | Matches |
|---|---|
| `*` | every permission |
| `loan:*` | every permission whose resource is `loan` |

### 4.2 Role

A named set of permissions, with optional denies.

```yaml
roles:
  teller:
    description: Front-desk staff
    allow: [customer:view, loan:create]
  ops_admin:
    description: Everything except approving loans
    allow: ["*"]
    deny:  [loan:approve]
```

There are two kinds of role. They behave identically during checks; they differ only in who defines them.

| | **System roles** | **Custom roles** |
|---|---|---|
| Defined by | Developers, in YAML or Go | Administrators, at runtime |
| Stored in | The config file / code (version-controlled) | The database |
| Editable from an admin UI | No | Yes |
| Visible in | Every scope | The scope that owns it and everything below it |
| Identified by | Name (`teller`) | Stable generated ID (`cr_8f2k…`) plus an editable display name |
| May contain denies | Yes | No (v1). See §6.1 |
| `assignable_at` default | Any scope type | The scope type where the role was created |

The guiding principle: **permissions are code; roles are data.**

Every role, system or custom, has an **`assignable_at`** list: the scope types at which it may be assigned. `Assign` rejects anything else with a clear error. For example, `teller` can be assignable only at `branch`. System and custom roles follow the same rule, so there is one behaviour to learn.

### 4.3 Scope

*Where* a role applies. A scope has a **type** and an **ID**: `organisation:o1`, `branch:b7`, `workspace:w42`.

The product declares its scope types and how they nest. wardn has no built-in hierarchy.

```yaml
# A bank
scopes:
  organisation: {}
  region: { parent: organisation }
  branch: { parent: region }
```

```yaml
# A flat SaaS
scopes:
  workspace: {}
```

```yaml
# Object-level grants: a project is a scope inside a workspace
scopes:
  workspace: {}
  project: { parent: workspace }
```

There is always one implicit scope above everything: **global**. A role assigned globally applies everywhere. Products that have no tenancy at all can declare no scopes and use only global.

### 4.4 Assignment

A fact stored in the database: *user U has role R in scope S*, optionally only *between time T1 and T2*.

```
u42  →  org_admin    in  organisation:o1
u77  →  teller       in  branch:b7
u90  →  loan_approver in branch:b7   from 2026-11-09 until 2026-11-13   (covering leave)
u01  →  super_admin  globally
```

- **Time windows are optional.** `starts_at` and `expires_at` are both nullable. An assignment with neither is permanent.
- There is at most one assignment per (user, role, scope). Assigning again replaces the time window.
- wardn never stores users themselves, only their IDs, as provided by the product's authentication.

---

## 5. Evaluation rules

These rules are fixed. They are not configurable, so they mean the same thing in every product.

1. **Default deny.** If no role grants a permission, the answer is no.
2. **Roles inherit downward.** A role assigned at a scope applies in that scope and every scope beneath it. An `org_admin` of `organisation:o1` acts as `org_admin` in every region and branch of `o1`.
3. **Allows accumulate.** A user's effective permissions are the union of all their applicable roles.
4. **Deny wins.** If any applicable role denies a permission, the answer is no, regardless of any allow.
5. **Fail closed.** If the store returns an error, the answer is no and the error is reported.
6. **Unknown references are ignored safely.** An assignment that points to a role that no longer exists grants nothing.
7. **Time windows are enforced at check time.** An assignment applies only when `starts_at ≤ now < expires_at`, with null bounds meaning "no limit". Correctness never depends on a cleanup job: an expired assignment stops working at the exact moment it expires, even if nothing has deleted it.

### 5.1 Algorithm

```
Check(user, permission, scope):
  1. permission must exist in the catalog          → otherwise error (with suggestion)
  2. scope type must be declared                    → otherwise error (with suggestion)
  3. chain := [scope, parent(scope), …, root, global]
  4. assignments := store.Assignments(user, chain)
     drop assignments outside their time window (using the configured clock)
  5. roles := resolve each assignment to a role definition (system or custom);
              drop assignments whose role no longer exists
  6. if any role's deny matches permission  → DENY  (reason: "denied by role X at scope Y")
  7. if any role's allow matches permission → ALLOW (reason: "granted by role X at scope Y")
  8. DENY (reason: "no role grants permission")
```

Every check produces a `Decision` that records the outcome and the reason, for logging and debugging (§7.2). When the answer is a deny caused by an explicit `deny` rule, the `Decision` always names the role and scope responsible. "Why am I locked out?" must always have an answer.

### 5.2 Hierarchy edge cases

- **Unlinked scope.** If wardn doesn't know a scope's parent, the chain is just `[scope, global]`. Nothing is inherited. This fails closed.
- **Moving a scope.** Re-linking a branch to a different region immediately changes which roles apply.
- **Depth is bounded** by the number of declared scope types (the YAML tree is acyclic), so a corrupted link can never cause an infinite loop.
- **Parent type is enforced.** Linking a `branch` to an `organisation` when the YAML says branches belong to regions is rejected.

---

## 6. Custom roles and the escalation guard

### 6.1 Custom roles

Administrators can create, edit and delete roles at runtime:

```go
role, err := w.CreateRole(ctx, orgScope, wardn.RoleSpec{
    Name:        "Senior Teller",
    Description: "Tellers who can also approve small loans",
    Allow:       []string{"customer:view", "loan:create", "loan:approve"},
})
```

Rules:

- A custom role **belongs to a scope**. It is visible and assignable only in that scope and the scopes beneath it. Org A's custom roles never appear in Org B.
- A custom role may only use permissions from the catalog. Unknown permissions are rejected.
- **Custom roles are grants-only in v1.** A `RoleSpec` with `Deny` entries is rejected. Only developer-defined system roles may contain denies. Admins rarely reason well about deny-wins interactions, and a mistaken deny locks people out in ways that are hard to diagnose. The data model already stores an effect (allow/deny) for every rule, so custom-role denies can later be enabled with a configuration flag without a schema change or breaking change.
- `AssignableAt` defaults to the type of the owning scope, and may list only that type and the types beneath it. A role created in `organisation:o1` with `AssignableAt: [branch]` can be handed out only at branches inside `o1`.
- Display names must be unique within the owning scope and cannot reuse a system role name.
- Editing a custom role affects every holder immediately; there are no copies.
- Deleting a role that is still assigned returns `ErrRoleInUse` unless the caller asks for cascade deletion. Because evaluation ignores dangling assignments (rule 6), cascade deletion is safe even on databases without multi-document transactions.
- Edits use optimistic concurrency (a version number), so two admins editing the same role cannot silently overwrite each other.

### 6.2 The escalation guard

The most common serious bug in home-grown RBAC is this: any user who can manage roles can grant themselves everything. wardn prevents it by default.

wardn defines two built-in permissions, which every catalog includes automatically:

| Permission | Allows |
|---|---|
| `wardn:roles.manage` | Create, edit, delete custom roles |
| `wardn:roles.assign` | Assign and revoke roles |

Products grant these to whichever roles should have them, like any other permission.

**Guard rules** — enforced on every management call, in the scope where it happens:

1. **Create / edit a role:** the actor needs `wardn:roles.manage`, *and* must hold every permission they put into the role.
2. **Assign a role:** the actor needs `wardn:roles.assign`, *and* must hold every permission the role grants.
3. **Revoke a role:** same as assign. (This stops a branch manager from stripping an organisation admin.)
4. **System roles cannot be edited or deleted** at runtime.

A super-admin holding `*` passes these checks naturally. Nobody else can create or hand out more power than they have.

The actor is the user in the request context (§7.6). If there is no user, management calls fail with `ErrUnauthenticated`.

### 6.3 System operations

Seeding the first super-admin, data migrations, and background jobs have no human actor. They use an explicitly named unguarded handle:

```go
w.System().Assign(ctx, "u01", "super_admin", wardn.Global)
```

`System()` is deliberately visible in code review. Its calls are still audited, with the actor recorded as `system`.

---

## 7. Go API

The core API is small. Most developers will only ever use `New`, `Require`, `Can`, `Assign` and `Revoke`.

### 7.1 Setup

```go
w, err := wardn.New(wardn.Config{
    File:  "wardn.yaml",          // or Policy: &wardn.Policy{...} to define in Go
    Store: wardnsql.New(db),      // omitted → in-memory store (tests and demos only)
})
// wardn.MustNew panics instead of returning an error — convenient in main().
```

`Config` fields — all optional except the policy:

| Field | Purpose | Default |
|---|---|---|
| `File` / `Policy` | Policy from YAML or Go | `File: "wardn.yaml"` |
| `Store` | Storage adapter | in-memory |
| `ParentOf` | Resolve scope parents from the product's own data (§8) | stored links |
| `UserFrom` | Extract the user ID from a request | read from context |
| `OnDecision` | Called on every check (audit/logging) | none |
| `OnChange` | Called on every management change (audit trail) | none |
| `OnError` | Custom HTTP error responses | JSON `401` / `403` / `500` |
| `Clock` | Source of "now" for time windows; tests inject a fake clock | system clock |
| `Cache` | Cross-request cache (§12) | none (per-request memoisation only) |

`New` validates the entire policy and runs storage migrations. If anything is wrong, the application does not start.

### 7.2 Checking access

```go
ok := w.Can(ctx, userID, "loan:approve", branch)            // bool; false on any error

d, err := w.Check(ctx, userID, "loan:approve", branch)      // full Decision
// d.Allowed, d.Reason, d.Role, d.GrantedAt (scope), d.Permission

w.CanAny(ctx, userID, branch, "loan:approve", "loan:view")
w.CanAll(ctx, userID, branch, "loan:approve", "loan:view")
```

`Can` is for normal code. `Check` is for logging, debugging and explaining a denial ("why can't I see this button?").

### 7.3 Introspection (for frontends and admin screens)

```go
w.PermissionsOf(ctx, userID, scope)   // concrete permissions, wildcards expanded — drive show/hide in the UI
w.RolesOf(ctx, userID, scope)         // roles in effect here, including inherited ones
w.Catalog()                           // every permission with its description, grouped by resource
w.Roles(ctx, scope)                   // system roles + custom roles visible in this scope
w.AssignableRoles(ctx, scope)         // only the roles the current actor may grant (escalation guard applied)
w.Members(ctx, scope, page)           // who has which role here — paginated
```

### 7.4 Managing access (guarded)

```go
w.Assign(ctx, userID, "teller", branch)
w.Assign(ctx, userID, "loan_approver", branch,
    wardn.From(monday), wardn.Until(friday))          // time-limited access
w.Revoke(ctx, userID, "teller", branch)

w.CreateRole(ctx, scope, wardn.RoleSpec{...})
w.UpdateRole(ctx, roleID, wardn.RoleSpec{...}, version)
w.DeleteRole(ctx, roleID, wardn.Cascade)

w.System().Assign(...)                // unguarded, for seeding and jobs (§6.3)
```

Assign and Revoke are idempotent. Assign also checks that the role may be used in that scope: the scope's type must be in the role's `assignable_at`, and a custom role may only be assigned within its owning scope's subtree.

### 7.5 Expiry

Expired assignments stop working on their own (rule 7). Separately, regulators expect a record of when access ended. An optional sweeper emits an `AssignmentExpired` event through `OnChange` for each assignment that has expired since its last run:

```go
go w.RunExpiry(ctx, time.Minute)     // or call w.SweepExpired(ctx) from the product's own scheduler
```

The sweeper exists for auditing and housekeeping only. If it never runs, access is still correct. It can optionally delete expired rows once they have been reported.

### 7.6 HTTP

`Require` returns standard `func(http.Handler) http.Handler` middleware. This is chi's native middleware type, so no adapter is needed.

```go
r := chi.NewRouter()
r.Use(authMiddleware)                             // the product's auth; puts the user in context

r.With(w.Require("customer:view")).Get("/customers", listCustomers)

r.Route("/orgs/{orgID}", func(r chi.Router) {
    r.Use(w.ScopeFrom(wardnchi.Param("organisation", "orgID")))
    r.With(w.Require("loan:approve")).Post("/loans/{id}/approve", approveLoan)
})
```

- No user → `401`. Denied → `403`. Store error → `500` (fail closed).
- `Require` with an undefined permission **panics when the route is registered**, so a typo stops the application at boot, not when a customer hits the route.
- The default `403` body does not reveal which permission was missing; the full `Decision` goes to `OnDecision`.
- `RequireAny(perms...)` and `RequireAll(perms...)` are also available.

Context helpers, for code outside HTTP handlers:

```go
ctx = wardn.WithUser(ctx, userID)
ctx = wardn.WithScope(ctx, wardn.NewScope("branch", "b7"))
id, ok := wardn.UserOf(ctx)
```

### 7.7 Errors

Errors are written to be read by the developer who caused them:

```
wardn: permission "loan:aprove" is not defined; did you mean "loan:approve"?
wardn: wardn.yaml:14: role "teller" allows "custmer:view", which is not in permissions; did you mean "customer:view"?
wardn: scope type "brnach" is not declared; declared types are: organisation, region, branch
wardn: cannot link branch:b7 to organisation:o1 — branch's parent type is region
wardn: role "teller" cannot be assigned at organisation:o1; it is assignable at: branch
wardn: custom roles cannot contain deny rules (role "Night Shift"); remove Deny or use a system role
```

Sentinel errors for programmatic handling: `ErrUnauthenticated`, `ErrDenied`, `ErrEscalation`, `ErrRoleInUse`, `ErrConflict`, `ErrNotAssignable`. Undefined names return `*wardn.UndefinedError`, which carries the kind, the name, and a suggestion.

---

## 8. Scope hierarchy data

The YAML says *a branch belongs to a region*. At runtime wardn must also know *branch b7 belongs to region r2*. Two options, chosen per product:

**A. wardn stores the links (default).** The product calls `Link` when it creates or moves an entity:

```go
w.Link(ctx, wardn.NewScope("branch", "b7"), wardn.NewScope("region", "r2"))
```

This is simple. The cost is that the relationship also lives in the product's own tables. `Link` is plumbing called by backend code, not an end-user action, and must not be exposed directly through an API.

**B. The product resolves parents on demand.** The product supplies a function, and nothing is duplicated:

```go
wardn.Config{
    ParentOf: func(ctx context.Context, s wardn.Scope) (wardn.Scope, bool, error) {
        if s.Type == "branch" {
            regionID, err := branches.RegionOf(ctx, s.ID)
            return wardn.NewScope("region", regionID), err == nil, err
        }
        ...
    },
}
```

The parent type returned is validated against the YAML in both cases.

---

## 9. Configuration file reference

```yaml
version: 1

scopes:                          # optional; omit for global-only products
  organisation: {}
  region: { parent: organisation }
  branch: { parent: region }

permissions:                     # the catalog — every permission the code checks
  customer:view:   View customer profiles
  customer:edit:   Edit customer details
  loan:create:     Create loan applications
  loan:approve:    Approve loans
  report:export:   Export reports

roles:                           # system roles
  super_admin:
    description: Full access everywhere
    allow: ["*"]

  org_admin:
    description: Administers one organisation
    assignable_at: [organisation]   # may only be assigned at organisation scopes (default: any)
    allow: ["*"]

  ops_admin:
    allow: ["*"]
    deny:  [loan:approve]

  teller: [customer:view, loan:create]     # shorthand: a list is an allow list
```

Validation at startup rejects: unknown keys, undefined permissions or scope types referenced by roles, wildcards that match nothing, cycles in the scope tree, invalid names, and duplicate definitions. Every error includes the file, the line, and a suggestion where one exists.

The same structure can be built in Go (`wardn.Policy{...}`) for teams that prefer code. YAML is the recommended default.

---

## 10. Storage

### 10.1 Interface

The core contains all the logic: inheritance, wildcards, deny-wins, the escalation guard. Stores only save and load records, which is what makes any database practical.

```go
type Store interface {
    AssignmentStore
    RoleStore
    ScopeStore
    Migrate(ctx context.Context) error
}

type AssignmentStore interface {
    Assign(ctx context.Context, a Assignment) error                         // idempotent upsert (replaces time window)
    Revoke(ctx context.Context, a Assignment) error                         // idempotent
    Assignments(ctx context.Context, user string, in []Scope) ([]Assignment, error)
    Members(ctx context.Context, scope Scope, page Page) ([]Assignment, string, error)
    ExpiredUnreported(ctx context.Context, before time.Time, limit int) ([]Assignment, error)
    MarkExpiryReported(ctx context.Context, a []Assignment) error
}

type Assignment struct {
    User      string
    RoleID    string
    Scope     Scope
    StartsAt  *time.Time   // nil = no lower bound
    ExpiresAt *time.Time   // nil = never expires
}

type RoleStore interface {
    CreateRole(ctx context.Context, r CustomRole) error
    UpdateRole(ctx context.Context, r CustomRole, expectedVersion int) error   // ErrConflict on mismatch
    DeleteRole(ctx context.Context, id string) error
    Roles(ctx context.Context, ids []string) ([]CustomRole, error)
    RolesOwnedBy(ctx context.Context, scopes []Scope) ([]CustomRole, error)
}

type ScopeStore interface {
    Link(ctx context.Context, child, parent Scope) error
    Parent(ctx context.Context, child Scope) (Scope, bool, error)
}
```

Design choices that keep adapters simple:

- **No transactions required.** Every operation is a single-record write or a read. Dangling references are harmless (rule 6), so multi-step operations can safely be done in sequence.
- **Idempotent writes.** Retrying is always safe.
- **No query language.** Every read is a lookup by key or a small set of keys.
- **No time logic.** Stores return assignments as saved. The core applies time windows using its clock, so every adapter gets expiry right automatically.

### 10.2 Official adapters

| Package | Databases | Go module |
|---|---|---|
| `wardn/store/memory` | In-process (tests, demos) | core |
| `wardn/store/sql` | PostgreSQL, MySQL/MariaDB, SQLite, SQL Server — through `database/sql`; the product brings its own driver | core (no driver dependency) |
| `wardn/store/mongo` | MongoDB | separate module |

Separate Go modules mean a SQL user never downloads the MongoDB driver and vice versa. The core module depends only on the standard library and a YAML parser.

### 10.3 Custom adapters and the conformance suite

Anyone can write an adapter for another database (Redis, DynamoDB, Firestore, Cassandra…). To make that trustworthy, wardn ships a conformance suite:

```go
func TestMyStore(t *testing.T) {
    storetest.Run(t, func() wardn.Store { return mystore.New(...) })
}
```

It runs the same behavioural tests that the official adapters pass: idempotency, tenant isolation, pagination, concurrency conflicts, and edge cases. An adapter that passes is correct.

### 10.4 SQL schema (illustrative)

```
wardn_assignments     (user_id, scope_type, scope_id, role_id,
                       starts_at NULL, expires_at NULL, expiry_reported_at NULL,
                       created_at, updated_at)                              PK (user_id, scope_type, scope_id, role_id)
                                                                             IX (scope_type, scope_id)
                                                                             IX (expires_at)
wardn_roles           (id, owner_scope_type, owner_scope_id, name, description, version, created_at, updated_at)
wardn_role_rules      (role_id, effect, permission)                         effect ∈ {allow, deny}; v1 writes only allow for custom roles
wardn_role_assignable (role_id, scope_type)
wardn_scope_links     (child_type, child_id, parent_type, parent_id)         PK (child_type, child_id)
wardn_schema_version  (version)
```

Migrations are automatic and versioned. Products can disable automatic migration and run them through their own tooling.

---

## 11. Security

wardn is security-critical infrastructure in a regulated (fintech) environment. A flaw in wardn would be a flaw in every product that uses it, so security covers both what wardn does (its logic) and what wardn is (its code, dependencies and releases).

The full analysis, including attackers, trust boundaries, assumptions, and every threat with its mitigation and test, is in **[THREAT_MODEL.md](THREAT_MODEL.md)**. That document is authoritative; the table below summarises the logic threats:

| Threat | Mitigation |
|---|---|
| Forgotten check on a route | `Require` at the router; a future `wardn check` lint flags handlers without it |
| Typo silently denies or allows | Unknown permissions are errors; `Require` panics at boot; optional generated constants |
| Cross-tenant access | Evaluation only considers assignments in the requested scope's own ancestor chain; custom roles are invisible outside their subtree; conformance tests cover isolation |
| Privilege escalation via role management | Escalation guard (§6.2), on by default |
| Database outage grants access | Fail closed (rule 5) |
| Deleted role still grants access | Dangling assignments grant nothing (rule 6) |
| Lost or concurrent role edits | Optimistic concurrency (`ErrConflict`) |
| Revoked access still works (stale cache) | No cross-request cache by default; when enabled, every change invalidates it (§12) |
| Temporary access outlives its window | Time windows enforced on every check (rule 7); no dependence on a cleanup job; cache entries never outlive the nearest expiry |
| Admin locks users out with a confusing deny | Custom roles are grants-only in v1; every deny `Decision` names the role and scope responsible |
| No record of who granted what | `OnChange` receives every management event with actor, target, role, scope, and time; `OnDecision` receives every check |
| Injection through IDs | All storage access is parameterised; IDs are length- and character-validated |
| Information leakage in errors | Default HTTP responses do not reveal permission names or roles |

### 11.1 Supply-chain security

wardn itself must not become the way in. Since the first commit:

- **Minimal dependencies.** The core uses only the standard library and one YAML parser. Every direct dependency is on an explicit allowlist that CI enforces; adding one requires a written justification and maintainer approval.
- **Security gates on every change.** `govulncheck`, `gosec` (via golangci-lint), `staticcheck`, the race detector, and module verification all block merging, and also run locally before every push through a pre-push hook. CodeQL is added when the repository goes public (M10); on a private repository it requires paid GitHub Advanced Security.
- **Pinned CI.** Every GitHub Action is pinned to a full commit SHA, workflows run with read-only tokens, and Dependabot proposes updates for review.
- **Protected main branch.** Changes land only through reviewed pull requests with passing checks and signed commits.
- **Verifiable releases.** Releases are signed tags. The Go checksum database (`sum.golang.org`) guarantees every user downloads byte-identical source for a version. Binaries (the CLI) ship with build-provenance attestations.
- **No hidden behaviour.** No network calls, telemetry, `init()` side effects, `unsafe`, or reflection-based magic in the core.
- **Responsible disclosure.** [SECURITY.md](../SECURITY.md) defines private reporting and response times.

### 11.2 Assurance before v1.0

- A test for every evaluation rule, and an **adversarial suite** written from the attacker's side
- **Fuzzing** of the evaluator, the YAML parser and every input-validation path
- **Property-based tests** for invariants (for example, "deny always wins" and "no assignment outside the ancestor chain ever applies")
- **Mutation testing** to prove the tests catch broken logic
- Race-detector runs on all concurrent code paths
- **Internal security review**, then an **independent external audit** before the announcement

---

## 12. Performance

A check costs:

- one parent lookup per level of hierarchy (usually 0–3), unless parents come from `ParentOf`,
- one query for the user's assignments across the scope chain,
- one query for any custom roles referenced (system roles are in memory).

### 12.1 Caching

In banking, a stale permission is a security bug: a revocation must take effect on the user's very next request. The caching design follows from that.

**Default: per-request memoisation only.** Within a single request, repeated checks and lookups reuse their results. A request is short-lived and sees one consistent view, so this is always safe. It is on by default and needs no configuration.

**Opt-in: cross-request cache.** Products that need more throughput can turn it on deliberately:

```go
wardn.Config{
    Cache: wardncache.Redis(rdb, wardncache.TTL(5*time.Second)),   // or wardncache.Memory(...)
}
```

- It sits behind a `Cache` interface. Official implementations are in-memory (single instance) and Redis (multi-instance).
- **Version counters for invalidation.** Each root scope (tenant) and the global scope has a version counter in the cache backend. Every change (assign, revoke, role edit, link) bumps the counter of the affected tenant, or of global for global changes. Cache keys include the current counters, so one increment invalidates everything for that tenant across every instance, without a "delete by pattern".
- **TTL is short** by default and acts as a safety net if an invalidation is ever missed. An example is a change made directly in the database, bypassing wardn.
- **Expiry-aware.** An entry never lives past the earliest `starts_at` or `expires_at` among the assignments it was computed from, so time-limited access begins and ends on time even when cached.

Benchmarks ship with the library. Performance targets will be set by measuring the reference applications (M8) against realistic data sizes, not guessed.

---

## 13. Developer experience

### 13.1 The first ten minutes

1. Copy the starter `wardn.yaml` and edit permissions and roles.
2. `wardn.MustNew(...)` in `main`.
3. `w.Require("...")` on routes.
4. `w.System().Assign(...)` to seed the first admin.

The quick-start README covers only these steps. Everything else lives in separate concept and recipe docs.

### 13.2 Tooling: `cmd/wardn`

```
wardn check                 # validate wardn.yaml (for CI)
wardn gen -o internal/perm  # generate Go constants from the YAML
```

Generated code turns typos into compile errors:

```go
r.With(w.Require(perm.LoanApprove)).Post(...)
w.Assign(ctx, userID, perm.RoleTeller, scope.Branch("b7"))
```

### 13.3 Testing helpers: `wardntest`

```go
w := wardntest.New(t, "../wardn.yaml")              // real policy, in-memory store
req = wardntest.AsRole(t, w, req, "teller")         // request from a user holding "teller"
req = wardntest.AsRoleIn(t, w, req, branch, "teller")

w := wardntest.AllowAll(t)                          // when authorization isn't what's being tested

clock := wardntest.NewClock(t0)                     // fake clock for time-limited access
w := wardntest.New(t, "../wardn.yaml", wardntest.WithClock(clock))
clock.Advance(48 * time.Hour)                       // "fast-forward" past an expiry
```

### 13.4 Documentation set

- **Quick start:** one page.
- **Concepts:** the four concepts and the evaluation rules.
- **Recipes:** multi-tenant SaaS; bank with organisation, region and branch; admin "Create role" screen; object-level grants; seeding and migrations; writing a store adapter.
- **API reference:** godoc.
- **A runnable example** product using chi and PostgreSQL.

### 13.5 The bar

If a new developer has to ask the wardn maintainers a question to get started, the API or the documentation isn't simple enough yet, and it gets fixed.

This is tested formally before the announcement (M8): a developer who has never seen wardn integrates it into a sample application using only the documentation, and every question they ask is treated as a defect.

---

## 14. Package layout

```
github.com/MogRex-Limited/wardn            core: policy, evaluation, HTTP middleware, context
├── store/memory                           in-memory store
├── store/sql                              database/sql store
├── storetest                              store conformance suite
├── wardntest                              testing helpers
├── cmd/wardn                              CLI: check, gen
└── examples/                              runnable example products

Separate modules (own go.mod):
├── chi            (package wardnchi)      chi URL-param scope helpers
├── store/mongo                            MongoDB store
└── cache          (package wardncache)    opt-in cross-request cache: in-memory, Redis
```

Future optional modules, each added only after a real product needs it:

- `wardn/makerchecker`: four-eyes approval for sensitive actions (common in banking).
- `wardn/conditions`: simple attribute conditions on permissions.
- Router helpers for Gin and Echo.
- `wardn/server`: an HTTP/gRPC service for non-Go consumers.

**Rule:** nothing company-specific ever goes in this repository. Integrations with internal services live in internal repositories that import wardn.

---

## 15. Delivery plan

wardn is built **complete and proven before any product adopts it**. It will become the team standard on announcement, and a flaw in a standard library is a flaw in every product, so it must not be hardened while products depend on it. It is also built for no particular product: it is validated against several very different product shapes, which proves it is truly generic.

The security pipeline is built **before any feature code**, so every line of wardn passes through it from the first commit.

| Milestone | Contents | Exit criteria |
|---|---|---|
| **M0: Design** | This document; [threat model](THREAT_MODEL.md) | Approved by engineering leadership |
| **M1: Secure foundation** | Go module, CI security gates (tests with race detector, golangci-lint with gosec, govulncheck, module verification, dependency allowlist), pre-push hook running the same gates locally, SHA-pinned actions, Dependabot, `SECURITY.md`, contribution rules, branch-protection and release process | Every gate runs and blocks on failure; repository settings applied |
| **M2: Core engine** | Policy loading and validation, scopes and hierarchy, evaluation engine (all seven rules), `assignable_at`, time-limited assignments with injectable clock, per-request memoisation, memory store, `wardntest` | Every rule tested; property tests and fuzzing in place |
| **M3: Storage** | SQL store (Postgres, MySQL, SQLite) with the full v1 schema, conformance suite, versioned migrations | All adapters pass `storetest` in CI against real databases |
| **M4: HTTP and tooling** | `Require` / `RequireAny` / `RequireAll`, chi helpers, error handling, `cmd/wardn check` and `gen` | Every HTTP path tested, including fail-closed behaviour |
| **M5: Custom roles** | Runtime roles (grants-only), escalation guard, introspection APIs, audit hooks, expiry sweeper | Escalation and isolation test suites pass |
| **M6: Completeness** | MongoDB store, opt-in cross-request cache (memory, Redis) | Mongo passes `storetest`; cache invalidation and expiry tests pass |
| **M7: Hardening** | Adversarial suite, extended fuzzing campaign, mutation testing, internal security review, **independent external audit** | No open high or critical findings |
| **M8: Proof and documentation** | Reference applications (multi-branch bank, multi-tenant SaaS, flat app, school system), quick start, concepts, recipes, API reference; fresh-developer usability test; benchmarks | All four reference apps built cleanly on the public API; usability test passes unaided |
| **M9: v1.0 announcement** | Stability guarantee, release, internal announcement | Becomes the standard for new products |
| **M10: Open source** | Licence, public repository, CodeQL code scanning (free for public repositories), launch post and talk | Leadership and legal approval |

Versioning: semantic versioning. The API may change during `v0.x`. From `v1.0`, breaking changes require a new major version. The YAML format carries its own `version` field.

---

## 16. How we'll measure success

**Before the announcement (quality bar):**

- Every evaluation rule and every threat in the threat model has a test that names it.
- Zero open high- or critical-severity findings from the internal review and the external audit.
- All four reference applications are built using only the public API, with no workarounds.
- A developer new to wardn protects a route in **under 10 minutes**, using only the documentation.

**After the announcement (adoption):**

- **Time to first protected route** for each adopting team.
- **Lines of access-control code** removed from or never written in each product.
- **Access-control bugs** in adopting products, compared with before.
- **Adoption:** products using wardn, and how many use custom roles and hierarchy.
- **Support load:** questions asked of maintainers per new adopter, which should trend toward zero.

These numbers form the basis of the internal case and, later, the public story.

---

## 17. Decisions log

| # | Question | Decision | Rationale |
|---|---|---|---|
| D1 | Default caching | Per-request memoisation only. Cross-request cache is opt-in, with short TTL, per-tenant version-counter invalidation, and expiry awareness (§12.1). | A stale permission is a security bug; revocation must apply on the next request. |
| D2 | Denies in custom roles | The schema supports them (an `effect` column on every rule). v1 rejects them for custom roles; system roles may deny. A config flag may enable them later, non-breaking. | Admins rarely reason well about deny-wins; a mistaken deny causes confusing lockouts. Every deny `Decision` names its source role. |
| D3 | Scope restrictions on custom roles | Yes. `assignable_at` on every role; custom roles default to their creation scope type; invalid assignments are rejected at `Assign`. | One rule for all roles means less to document and fewer surprises. |
| D4 | Expiring assignments | Yes, in v1.0: nullable `starts_at` and `expires_at`; enforced at check time; audit event on expiry; injectable clock; cache never outlives the nearest expiry. | Costs almost nothing now; adding it later would force a migration in every product. Regulators expect an expiry trail. |
| D5 | Hierarchy data source | wardn stores links by default; products may supply `ParentOf` instead (§8). | Simple by default, one source of truth when wanted. |
| D6 | Runtime custom roles | In scope for v1.0, with the escalation guard on by default (§6). | Every serious product admin panel needs a "Create role" screen. |
| D7 | Delivery approach | Built complete, hardened and externally audited before any product adopts it; validated against four reference applications rather than a pilot product (§15). | It becomes the team standard on announcement; a library must not be hardened while products depend on it. |
| D8 | Supported Go versions | The two most recent Go releases, matching Go's own security-support policy (currently 1.26 and 1.27). | Older Go releases no longer receive security fixes. |

## 18. Open questions

1. **Name.** Check for trademark and package-name conflicts before open-sourcing.
