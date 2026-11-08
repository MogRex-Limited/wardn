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
w := wardn.MustNew(wardn.Config{File: "wardn.yaml", Store: wardnsql.MustNew(db)})

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
| `loan:*` | every permission whose resource is `loan` (`loan:create`, `loan:approve:own`), but not `loans:…` |
| `loan:approve:*` | any deeper prefix works the same way |

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
6. **Unknown references are ignored safely.** An assignment that points to a role that no longer exists grants nothing. Likewise, if the policy is changed so a role is no longer assignable at a scope type, existing assignments of it there stop applying.
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
- **Names are checked against spoofing** (threat model T15): letters from one script only (no Cyrillic "а" in "Аdmin"), no control or invisible characters, no combining marks (two encodings of the same visible text), no leading, trailing or repeated spaces. Uniqueness ignores case, spaces, `_` and `-`. A name must be unique within its owner scope and the owner's ancestors (where both roles are visible together), and must not look like a system role name: "Org Admin" is refused when `org_admin` exists.
- Roles are always identified by a generated ID (`cr-` plus 24 random characters) that can never clash with a system role name. Names are only for display.
- Editing a custom role affects every holder immediately; there are no copies.
- Deleting a role that is still assigned returns `ErrRoleInUse` unless the caller asks for cascade deletion. Because evaluation ignores dangling assignments (rule 6), cascade deletion is safe even on databases without multi-document transactions.
- Edits use optimistic concurrency (a version number), so two admins editing the same role cannot silently overwrite each other.
- If a permission is removed from the catalog, custom roles that list it simply stop granting it, the same way a deleted role stops granting (rule 6).

### 6.2 The escalation guard

The most common serious bug in home-grown RBAC is this: any user who can manage roles can grant themselves everything. wardn prevents it by default.

wardn defines two built-in permissions, which every catalog includes automatically:

| Permission | Allows |
|---|---|
| `wardn:roles.manage` | Create, edit, delete custom roles |
| `wardn:roles.assign` | Assign and revoke roles |

Products grant these to whichever roles should have them, like any other permission.

**Guard rules** — enforced on every management call, in the scope where it happens:

1. **Create a role:** the actor needs `wardn:roles.manage` at the owner scope, *and* must hold every permission they put into the role.
2. **Edit or delete a role:** the same, and the actor must also hold every permission the role *already* has, so nobody can strip a role they could not have granted.
3. **Assign a role:** the actor needs `wardn:roles.assign`, *and* must hold every permission the role grants **and every permission it denies**. A deny role restricts its holder, so assigning one is as powerful as granting what it denies: only someone who holds everything `suspended` denies (`*`) can suspend, and a branch manager cannot lock out an organisation admin (security review F1b).
4. **Revoke a role:** same as assign, denies included: lifting a suspension restores what it denied, which the actor must hold (security review F1). (This also stops a branch manager from stripping an organisation admin.) A leftover assignment of a role that no longer exists grants nothing, so revoking it needs only `wardn:roles.assign`.
5. **System roles cannot be edited or deleted** at runtime.

**Holding a wildcard** means holding *all* of it: an allow covering the whole wildcard, and no deny anywhere inside it. An actor who holds `loan:create`, `loan:view` and `loan:approve` one by one cannot create a `loan:*` role, because it would also grant every `loan:` permission added later (threat model T06). An actor with `*` minus a deny on `loan:approve` cannot grant `*` or `loan:*`.

**Order of checks:** the management permission is checked first, before the target role is even looked up, so a user without it learns nothing (not even whether a role ID exists).

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
    Store: wardnsql.MustNew(db),  // omitted → in-memory store (tests and demos only)
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
| `OnDecision` | Called with every decision and any error, `func(ctx, Decision, error)` (audit/logging) | none |
| `OnChange` | Called on every management change (audit trail) | none |
| `OnError` | Custom HTTP error responses | JSON `401` / `403` / `500` |
| `Clock` | Source of "now" for time windows; tests inject a fake clock | system clock |
| `Cache` | Cross-request cache (§12) | none (per-request memoisation only) |

`New` validates the entire policy and runs storage migrations. If anything is wrong, the application does not start.

### 7.2 Checking access

```go
ok := w.Can(ctx, userID, "loan:approve", branch)            // bool; false on any error

d, err := w.Check(ctx, userID, "loan:approve", branch)      // full Decision
// d.Allowed, d.Reason, d.Role, d.At (scope where the role is assigned), d.Rule, d.Permission

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
w.Members(ctx, scope, cursor, limit)  // who has which role here: paginated, byte-ordered by user then role
w.CustomRole(ctx, id)                 // one custom role, with its Version, for an edit form
```

### 7.4 Managing access (guarded)

```go
w.Assign(ctx, userID, "teller", branch)
w.Assign(ctx, userID, "loan_approver", branch,
    wardn.From(monday), wardn.Until(friday))          // time-limited access
w.Revoke(ctx, userID, "teller", branch)

w.CreateRole(ctx, scope, wardn.RoleSpec{...})
w.UpdateRole(ctx, roleID, wardn.RoleSpec{...}, version)
w.DeleteRole(ctx, roleID, wardn.Cascade())

w.System().Assign(...)                // unguarded, for seeding and jobs (§6.3)
```

The acting user comes from the context (`wardn.WithUser`, which the product's authentication middleware sets). Without one, every guarded call fails with `ErrUnauthenticated`. Guard failures are `ErrDenied` (missing the management permission) or `ErrEscalation` (missing a permission being granted); `HTTPStatus` maps both to 403. `w.System()` offers the same methods without the guard.

Assign and Revoke are idempotent. Assign also checks that the role may be used in that scope: the scope's type must be in the role's `assignable_at`, and a custom role may only be assigned within its owning scope's subtree.

### 7.5 Expiry

Expired assignments stop working on their own (rule 7). Separately, regulators expect a record of when access ended. An optional sweeper emits an `AssignmentExpired` event through `OnChange` for each assignment that has expired since its last run:

```go
go w.RunExpiry(ctx, time.Minute, logError)  // or call w.SweepExpired(ctx) from the product's own scheduler
```

The sweeper exists for auditing and housekeeping only. If it never runs, access is still correct. It can optionally delete expired rows once they have been reported.

### 7.6 HTTP

`Require` returns standard `func(http.Handler) http.Handler` middleware. This is chi's native middleware type, so no adapter is needed.

```go
r := chi.NewRouter()
r.Use(authMiddleware)                             // the product's auth; puts the user in context

r.With(w.Require("customer:view")).Get("/customers", listCustomers)

r.Route("/orgs/{orgID}", func(r chi.Router) {
    r.Use(w.ScopeFrom("organisation", wardn.PathValue("orgID")))
    r.With(w.Require("loan:approve")).Post("/loans/{id}/approve", approveLoan)

    r.Route("/branches/{branchID}", func(r chi.Router) {
        r.Use(w.ScopeFrom("branch", wardn.PathValue("branchID"))) // the innermost scope wins
        r.With(w.Require("loan:create")).Post("/loans", createLoan)
    })
})
```

- `Require(perms...)` needs **all** of the permissions; `RequireAny(perms...)` needs one.
- No user → `401`. Denied → `403`. Missing or invalid scope ID → `400`. Store error → `500` (fail closed). The handler never runs on any of these.
- `Require` with an undefined permission, and `ScopeFrom` with an undeclared scope type, **panic when the route is registered**, so a typo stops the application at boot, not when a customer hits the route.
- Default error bodies are generic JSON (`{"error":"forbidden"}`), with `nosniff` and `no-store` headers. They don't reveal which permission was missing; the full `Decision` goes to `OnDecision`, and a custom `OnError` receives a `*DeniedError` carrying the decisions. `HTTPStatus(err)` maps any wardn error to its status code.
- `wardn.PathValue(name)` reads a path parameter through Go's standard `r.PathValue`, which both net/http's `ServeMux` and chi (v5.1+) fill in. **wardn needs no chi adapter and no chi dependency.** `ScopeFrom` must sit where the parameter exists: with chi, inside `r.Route` or `r.With`, after routing. If it's placed too early, the ID is empty and every request gets `400`, never a silent fallback to Global.
- Without `ScopeFrom`, a route checks at **Global**, where only global assignments apply (threat model T18). That is safe, but usually not what a tenant route wants.
- Each request gets a per-request memo automatically, so several `Require` layers plus in-handler `Can` calls share one store read.

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

This is simple. The cost is that the relationship also lives in the product's own tables.

`Link` never changes an existing parent: linking to the same parent is a quiet no-op, and linking to a different one fails with `ErrAlreadyLinked` (409). A scope is identified by type and ID across all tenants, so two tenants that reuse an ID (a `cardiology` department in two hospitals) would otherwise move one tenant's scope under the other's administrators (threat model T27, found by the M8 usability rehearsal). Deliberate moves use `w.Move`. Scope IDs must be unique per type: primary keys, UUIDs, or composite IDs. `Link` is plumbing called by backend code, not an end-user action, and must not be exposed directly through an API.

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

Validation at startup rejects: unknown keys, undefined permissions or scope types referenced by roles, permissions without a description, wildcards that match nothing, a permission both allowed and denied by one role, cycles in the scope tree, invalid names, and duplicate definitions. It also rejects YAML anchors, aliases and merge keys (they make files hard to review and enable resource-exhaustion attacks), files over 1 MiB, and more than one document. `version` is optional and defaults to 1. **Every problem is reported at once**, each with the file, the line, and a suggestion where one exists.

A role may contain only denies, which is useful for a `suspended` role that blocks everything wherever it is assigned.

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
}

type AssignmentStore interface {
    Assign(ctx context.Context, a Assignment) error                   // upsert; replaces the window, clears any expiry report
    Revoke(ctx context.Context, user, role string, scope Scope) error // idempotent
    Assignments(ctx context.Context, user string, scopes []Scope) ([]Assignment, error)
    Members(ctx context.Context, scope Scope, cursor string, limit int) ([]Assignment, string, error)
    RoleInUse(ctx context.Context, role string) (bool, error)
    RevokeRole(ctx context.Context, role string) error                // every assignment of a role
    ExpiredUnreported(ctx context.Context, t time.Time, limit int) ([]Assignment, error)
    MarkExpiryReported(ctx context.Context, as []Assignment) error    // never marks a newer window
    RevokeExpired(ctx context.Context, a Assignment) error            // atomic: only if ExpiresAt is unchanged
}

type Assignment struct {
    User      string
    Role      string       // system role name or custom role ID
    Scope     Scope
    StartsAt  time.Time    // zero = no lower bound
    ExpiresAt time.Time    // zero = never expires; the window is [StartsAt, ExpiresAt)
}

type RoleStore interface {
    CreateRole(ctx context.Context, r CustomRole) error                       // ErrRoleNameTaken, atomically
    UpdateRole(ctx context.Context, r CustomRole, expectedVersion int) error  // ErrConflict / ErrRoleNotFound / ErrRoleNameTaken
    DeleteRole(ctx context.Context, id string) error                          // idempotent
    Roles(ctx context.Context, ids []string) ([]CustomRole, error)
    RolesOwnedBy(ctx context.Context, owners []Scope) ([]CustomRole, error)
}

type ScopeStore interface {
    Link(ctx context.Context, child, parent Scope) error
    Parent(ctx context.Context, child Scope) (Scope, bool, error)
}

// Optional: stores that manage a schema. wardn.New calls it.
type Migrator interface {
    Migrate(ctx context.Context) error
}
```

Design choices that keep adapters simple:

- **Few atomicity requirements, all explicit.** Role-name uniqueness and versioned role updates must be atomic, and the conformance suite tests both with concurrent writers. Everything else is a single write or a read. Dangling references are harmless (rule 6), so multi-step operations such as cascade deletion can safely be done in sequence.
- **Idempotent writes.** Retrying is always safe.
- **No query language.** Every read is a lookup by key or a small set of keys.
- **No time logic.** Stores return assignments as saved. The core applies time windows using its clock, so every adapter gets expiry right automatically.

### 10.2 Official adapters

| Package | Databases | Go module |
|---|---|---|
| `wardn.NewMemoryStore()` | In-process (tests, demos); the default when no store is configured | core package (it is the default, so it cannot live in a sub-package that imports the core) |
| `wardn/store/sql` (package `wardnsql`) | PostgreSQL 13+, MySQL 8.0+, MariaDB 10.6+, SQLite 3.24+, through `database/sql`; the product brings its own driver, and the dialect is detected from it | core (no driver dependency) |
| SQL Server | **Not supported** (D12): no product uses it. If one ever does, it needs SQL Server 2019+ (UTF-8 binary collations, for exact ID comparison with index use) and a key design within the 900-byte key limit. | core |
| `wardn/store/mongo` (package `wardnmongo`) | MongoDB 6.0+, standalone or replica set; needs no transactions (every write is one document) | separate module |

Separate Go modules mean a SQL user never downloads the MongoDB driver and vice versa. The core module depends only on the standard library and a YAML parser.

### 10.3 Custom adapters and the conformance suite

Anyone can write an adapter for another database (Redis, DynamoDB, Firestore, Cassandra…). To make that trustworthy, wardn ships a conformance suite:

```go
func TestMyStore(t *testing.T) {
    storetest.Run(t, func() wardn.Store { return mystore.New(...) })
}
```

It runs the same behavioural tests that the official adapters pass: idempotency, tenant isolation, pagination, concurrency conflicts, and edge cases. An adapter that passes is correct.

### 10.4 SQL schema

Schema version 1 (M3):

```
v1 (M3)
wardn_assignments        (user_id, role, scope_type, scope_id,
                          starts_at NULL, expires_at NULL, created_at, updated_at)
                          PK (user_id, scope_type, scope_id, role)   IX (scope_type, scope_id)
wardn_scope_links        (child_type, child_id, parent_type, parent_id, updated_at)
                          PK (child_type, child_id)
wardn_schema_migrations  (version, applied_at)

v2 (M5)
wardn_roles              (id PK, owner_type, owner_id, name, name_key, description,
                          version, created_at, updated_at)
                          UNIQUE (owner_type, owner_id, name_key)
wardn_role_rules         (role_id, position, effect, permission)    PK (role_id, position)
                          effect ∈ {allow, deny}; only allow is written in this release (D2)
wardn_role_assignable    (role_id, position, scope_type)            PK (role_id, position)
wardn_assignments        + expiry_reported_at NULL                  IX (expires_at), IX (role)
```

Decisions:

- **Exact comparison on every database.** On MySQL and MariaDB, IDs are stored as `VARBINARY`, because their default collations treat `o1` and `O1` (and often accented and trailing-space variants) as equal. That would let one scope match another's assignments (threat model T13). Postgres and SQLite compare text exactly by default.
- **Times are Unix microseconds (`BIGINT`).** This is exact on every database, with no time-zone or driver-configuration pitfalls, and works past 2038. Rounding to microseconds never widens a window: starts round up, ends round down.
- **Global is stored as an empty type and ID**, so all rows use the same key shape.
- **Table names come only from a validated prefix** (`WithTablePrefix`, default `wardn_`); every value is a query parameter.

Tables are added only when the code that uses them ships, each as a new migration version, so no table exists without tests exercising it.

- **Uniqueness is enforced by the database** (`UNIQUE (owner_type, owner_id, name_key)`). wardn computes the normalised `name_key`; the store never normalises.
- **Versioned updates** are a single `UPDATE … WHERE id = ? AND version = ?`; zero rows changed means a conflict, or a missing role.
- **Admin listings** compare and sort in byte order (`COLLATE "C"` on Postgres, whose default sorts by locale), so pagination is identical on every database.

**Migration rules:** released migrations are never edited, only appended; every step is safe to run twice, either through `IF NOT EXISTS` or through an existence check before steps that have no such form (adding a column, or creating an index on MySQL), because MySQL cannot run DDL inside a transaction and a migration interrupted halfway must simply run again (tested on every database); concurrent startups are safe (a Postgres advisory lock or MySQL `GET_LOCK`, released even if the caller's context is cancelled, with the connection discarded if release fails); and a database migrated by a *newer* wardn is refused (`ErrSchemaTooNew`) rather than used by an older one.

Migrations are automatic and versioned: `wardn.New` runs them through the optional `wardn.Migrator` interface. Products can set `Config.ManualMigrations` and run `Store.Migrate` from their own deploy pipeline instead.

---

## 11. Security

wardn is security-critical infrastructure in a regulated (fintech) environment. A flaw in wardn would be a flaw in every product that uses it, so security covers both what wardn does (its logic) and what wardn is (its code, dependencies and releases).

The full analysis, including attackers, trust boundaries, assumptions, and every threat with its mitigation and test, is in **[THREAT_MODEL.md](THREAT_MODEL.md)**. That document is authoritative; the table below summarises the logic threats:

| Threat | Mitigation |
|---|---|
| Forgotten check on a route | `Require` at the router; `wardntest.AuditRoutes` requests every route as a user with no roles and fails for any route that doesn't answer 403 |
| Typo silently denies or allows | Unknown permissions are errors; `Require` panics at boot; optional generated constants |
| Cross-tenant access | Evaluation only considers assignments in the requested scope's own ancestor chain; custom roles are invisible outside their subtree; conformance tests cover isolation |
| Privilege escalation via role management | Escalation guard (§6.2), on by default |
| Database outage grants access | Fail closed (rule 5) |
| Deleted role still grants access | Dangling assignments grant nothing (rule 6) |
| Lost or concurrent role edits | Optimistic concurrency (`ErrConflict`) |
| Revoked access still works (stale cache) | No cross-request cache by default; when enabled, every change invalidates it (§12) |
| Temporary access outlives its window | Time windows enforced on every check (rule 7); no dependence on a cleanup job; cache entries never outlive the nearest expiry |
| Admin locks users out with a confusing deny | Custom roles are grants-only in v1; every deny `Decision` names the role and scope responsible |
| No record of who granted what | `OnChange` is called *before* every change, after the cache is invalidated (so it never records an abandoned change) (assignments, roles, links, expiries) with actor, target, role, scope and time, and can veto it; if the change then fails, it is told. `OnDecision` receives every check |
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
- **Internal security review** (M7) and an **API review** before the freeze (M9). No external audit is commissioned (decision D16).

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
    Cache:    wardnredis.MustNew(rdb, "lending-app"), // shared by every instance; or wardn.NewMemoryCache() for one instance
    CacheSecret: secretFromVault,                   // 32+ random bytes, the same on every instance; required for shared caches
    CacheTTL: 5 * time.Second,                      // the default; at most 5 minutes
}
```

- **It caches data, never decisions.** wardn caches what it reads from the store (a user's assignments for a scope, scope parents, custom roles) and still evaluates every check, against the clock. A cached time-limited assignment therefore starts and ends at exactly the right moment, however long it stays in the cache. This is simpler and stronger than limiting entry lifetimes to the nearest expiry, which was the original plan.
- **Version counters for invalidation.** There is one counter per tenant (top-level scope), one for Global, and one for scope links. Cache keys include the counters they depend on, so one increment makes every entry for that tenant unreachable on every instance, with no "delete by pattern".
- **Invalidation before and after every change.** Assign, revoke, role edits and deletions, links, and removal of expired assignments increment the affected counters *before* writing, and abort if that fails, so nothing changes without invalidation. They increment again *after* writing, so an entry that a concurrent reader cached from the old data in between is never reachable. If only the second increment fails, the change is saved and `ErrCacheInvalidation` is returned (retrying is safe). Moving a scope invalidates both its old and its new tenant.
- **A failing cache never makes wardn wrong.** Cache read errors, and values that don't decode, fall back to the store. Everything read from the cache is validated exactly like store data.
- **Keys are hashes** (SHA-256 of structured parts), so IDs, which may be personal data, never appear in the cache, and separators can't be injected.
- **Entries are sealed** with HMAC-SHA256 over their key and value (`Config.CacheSecret`, required for any shared cache). Whoever can write to the cache server still can't forge an entry or move one to another key; entries that fail verification are misses. This closed a fuzzing finding: a forged entry used to grant super-admin (docs/SECURITY_REVIEW.md, FZ1). Version counters are not sealed; a lost counter can at worst revive old genuine entries for one TTL, which is why Redis must not evict them.
- **The TTL is only a safety net**, for changes wardn can't see: edits made directly in the database, or scope moves when `Config.ParentOf` reads parents from the product's own data. After such changes, call `w.InvalidateCache(ctx, scopes...)`.
- **`wardn.NewMemoryCache()` is correct only for a single instance**, because other instances can't see its counters. With more than one instance, use the shared Redis cache (`wardn/cache/redis`, which works with Redis and Valkey). It needs a namespace per application and a private server (threat model T24).
- Any cache implementation must pass the `cachetest` conformance suite, which includes atomic counters under concurrent increments.

Benchmarks ship with the library (M8). `storetest.Bench` runs on a bank-shaped dataset of 4 organisations, 40 regions, 1,000 branches and about 20,000 assignments. It runs against any store, so every official store and any third-party store are measured the same way. `make bench` and `make bench-all` run it, together with whole HTTP requests through the bank reference application. The first measurements were taken on a 12-thread laptop with each database in Docker on the same machine. A check costs a few store round trips. The cost of evaluation itself is negligible:

| | One check | 10 checks, one request | Parallel |
|---|---|---|---|
| Memory store | 2–5 µs | 26 µs | 0.8 µs |
| SQLite | 0.1 ms | 0.14 ms | 0.05 ms |
| PostgreSQL / MySQL / MariaDB / MongoDB | 0.7–1.1 ms | 0.7–1.2 ms | 0.2–0.3 ms |
| Any database + memory cache | 25–45 µs | 90–135 µs | 10–12 µs |

These confirm the design. The per-request memo makes extra checks in a request nearly free. The opt-in cache makes database-backed checks 20–30× faster. Authorization adds 4–7 µs to a request in the bank application. The cache is slower than the in-memory store, because hashing and sealing cost more than a map lookup, so it is only for database-backed stores. A finding for products: `database/sql`'s default of 2 idle connections more than halved parallel throughput on PostgreSQL. The stores guide tells products to size the pool. The full table is on the site's Performance page. No performance targets are set yet. They will come from the first product's real traffic.

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
w.System().Assign(ctx, userID, perm.RoleTeller, perm.ScopeBranch("b7"))
```

`wardn gen` writes one package (default `perm`) holding the permissions (`perm.LoanApprove`), the built-in permissions (`perm.WardnRolesAssign`), the system roles (`perm.RoleTeller`) and a constructor per scope type (`perm.ScopeBranch(id)`). Two names that would become the same Go identifier are reported as an error. `wardn gen -check` fails in CI if the generated file is stale. Nothing in a policy file can inject code into the output: identifiers are built only from the characters policy names allow, values are quoted, and descriptions can't contain line breaks.

```
```

### 13.3 Testing helpers: `wardntest`

```go
w := wardntest.New(t, "../wardn.yaml")              // real policy, in-memory store
req = wardntest.AsRole(t, w, req, "teller")         // request from a user holding "teller"
req = wardntest.AsRoleIn(t, w, req, branch, "teller")

uid := wardntest.NewUser(t, w, branch, "teller")    // a user ID for non-HTTP tests

w := wardntest.AllowAll(t, "../wardn.yaml")         // everyone may do everything; typos still fail

// Catch routes that forgot Require (threat model T17): every route must
// answer 403 to a signed-in user with no roles.
wardntest.AuditRoutes(t, router, authenticateAs, routes, publicRoutes...)

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
github.com/MogRex-Limited/wardn            core: policy, evaluation, memory store, HTTP middleware, context
├── store/sql      (package wardnsql)      database/sql store
├── storetest                              store conformance suite and benchmarks
├── cachetest                              cache conformance suite
├── wardntest                              testing helpers
├── cmd/wardn                              CLI: check, gen
└── examples/                              runnable example products

Separate modules (own go.mod):
├── store/mongo    (package wardnmongo)    MongoDB store
└── cache/redis    (package wardnredis)    shared cross-request cache (Redis, Valkey)

The in-memory cache (`wardn.NewMemoryCache`) lives in the core, like the memory store.
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
| **M3: Storage** | SQL store (Postgres, MySQL, MariaDB, SQLite), conformance suite, versioned migrations, real-database CI | All adapters pass `storetest` in CI against real databases |
| **M4: HTTP and tooling** | `Require` / `RequireAny`, `ScopeFrom` with `PathValue` (works with chi, no adapter), error handling, `wardntest.AuditRoutes`, `cmd/wardn check` and `gen`, signed release workflow | Every HTTP path tested, including fail-closed behaviour |
| **M5: Custom roles** | Runtime roles (grants-only) with spoof-resistant names, escalation guard, guarded `Assign`/`Revoke`, introspection APIs (`Roles`, `AssignableRoles`, `Members`, `CustomRole`), audit events (`OnChange`), expiry sweeper, schema v2 | Escalation and isolation test suites pass |
| **M6: Completeness** | MongoDB store, opt-in cross-request cache (memory, Redis) with version-counter invalidation, cache conformance suite, stable JSON for public types; SQL Server deferred until a product needs it (D12) | Mongo passes `storetest`; Redis passes `cachetest`; no stale answer after random changes across instances |
| **M7: Hardening** | Adversarial suite, extended fuzzing campaign, mutation testing, internal security review | No open high or critical findings |
| **M8: Proof and documentation** | Reference applications (multi-branch bank, multi-tenant SaaS, flat app, school system), quick start, concepts, recipes, API reference; fresh-developer usability test; benchmarks | All four reference apps built cleanly on the public API; usability test passes unaided |
| **M9: v1.0 announcement** | API review, stability promise ([STABILITY.md](STABILITY.md)) with an automatic API-compatibility check, release, internal announcement | Becomes the standard for new products |
| **M10: Open source** | Licence, public repository, CodeQL code scanning (free for public repositories), launch post and talk | Leadership and legal approval |

Versioning: semantic versioning. The API may change during `v0.x`. From `v1.0`, breaking changes require a new major version. The YAML format carries its own `version` field. What exactly stays compatible, and how it is checked, is in [STABILITY.md](STABILITY.md).

---

## 16. How we'll measure success

**Before the announcement (quality bar):**

- Every evaluation rule and every threat in the threat model has a test that names it.
- Zero open high- or critical-severity findings from the internal security review and every review since.
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
| D9 | Custom role names | One script, no invisible characters or combining marks, uniqueness ignoring case, spacing, `_` and `-`, checked against system roles and ancestors' roles. | Role names are chosen by admins and read by other admins; anything that lets two names look alike enables T15. Combining marks are refused because the standard library cannot normalise Unicode; precomposed letters (é, Ọ) work. Adopting `golang.org/x/text` normalisation later would relax this. |
| D10 | Audit timing | `OnChange` runs *before* the write and can veto it; if the write then fails, it is called again with `Event.Err` set. | Fail closed: nothing changes without a record. The follow-up call keeps the trail accurate when a store write fails. |
| D11 | What the cache holds | Store data (assignments, parents, custom roles), never decisions; version counters bumped before and after every change. | Decisions depend on the clock; data doesn't. Caching data keeps time windows exact without any expiry arithmetic, and keeps one evaluation path, cached or not. |
| D12 | SQL Server | Not supported until a product needs it. The organisation's products use PostgreSQL and MySQL, which are fully supported and tested (with MariaDB and SQLite). | Untested database support is a liability in a security library. Doing SQL Server correctly needs 2019+ binary UTF-8 collations and a new key design; that work is justified only by a real user. |
| D13 | Guard scope | The escalation guard is evaluated at the scope where the change happens. An actor's denies at *child* scopes do not limit what they may grant at the parent (security review F10). | Checking every descendant is unbounded. A deny constrains its holder, not what that holder may delegate above it. To restrict someone, put the deny on the roles of the people being restricted. |
| D14 | Management errors reveal nothing | Without `wardn:roles.manage` at a role's owner, `UpdateRole` and `DeleteRole` answer exactly as for a missing role (`ErrRoleNotFound`, 404). Guarded deletes of missing roles are therefore not silent; `System()` deletes stay idempotent. | Existence, versions and nearby names are information an attacker can use (security review F5). |
| D15 | Quiet no-op changes; `Link` vs `Move` | Repeating a change that changes nothing (same assignment and window, same parent) is not written or audited. `Link` refuses to re-parent; `Move` re-parents on purpose. | Found by the usability rehearsal: seeding on every start filled the audit trail, and a reused ID could silently move one tenant's scope into another. |
| D16 | External audit | No external security audit for v1.0: the maintainers decided against one (2026-11-08). | v1.0 rests on the internal security review (docs/SECURITY_REVIEW.md), the API review before the freeze, a `TestThreat_` test for every threat, property tests against a reference implementation, fault injection, fuzzing and mutation testing. The review brief stays in SECURITY_REVIEW.md §5 for any later reviewer. |
| D17 | Changes inside the application's transaction (v1.1) | The transaction travels in the context (`wardnsql.Store.WithTx`), keyed per store; `Warden.Transaction` returns a function to call after the commit. Stores opt in through `TxStore`. The SQL store writes in savepoints. Inside the transaction the cache and memo are bypassed. A change with only one of the two fails with `ErrNoTransaction`. | Found by the first product adoption: membership changes there commit together with audit and outbox rows, and the access change must too. Passing the transaction in the context keeps every method signature unchanged (v1 compatibility). The cache can't know when a transaction commits, so the application tells it; refusing a half-configured change turns a silent stale cache into an error in development. |
| D18 | Checking many scopes (v1.1) | `CheckEach` / `CanEach`: one permission at up to 1,000 scopes, reading the union of their chains in batches of 32 scopes. The whole call fails closed on any error. Decisions are identical to `Check` (property-tested). | Filtering a list one `Can` at a time costs a few queries per item. One permission at many scopes covers list filtering; many permissions at one scope is already `PermissionsOf`. |

## 18. Open questions

1. **Name.** Check for trademark and package-name conflicts before open-sourcing.
