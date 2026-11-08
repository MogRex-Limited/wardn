# wardn — Threat Model

| | |
|---|---|
| **Status** | Current for v1.0.0; re-reviewed for every minor release |
| **Date** | 2026-11-07 |
| **Companion to** | [DESIGN.md](DESIGN.md) |

This document lists what wardn protects, who might attack it, where the trust boundaries are, and every known threat with its mitigation and the test that proves it.

**Traceability rule:** every threat `Txx` must have at least one test named `TestThreat_Txx_<Description>` before v1.0. A threat without a test counts as unmitigated.

---

## 1. What wardn protects (assets)

| Asset | Why it matters |
|---|---|
| **Authorization decisions** | A wrong "yes" is a breach; a wrong "no" is an outage. |
| **Assignments** (who has which role where) | Tampering grants or removes access. |
| **Custom role definitions** | Tampering silently changes what every holder can do. |
| **Scope links** (hierarchy) | A wrong link moves a tenant's data under someone else's admin. |
| **Audit events** | Regulators and incident responders depend on them. |
| **The wardn code and releases** | A compromised wardn compromises every product using it. |

---

## 2. Who might attack

| Actor | Has | Wants |
|---|---|---|
| **A1: Anonymous outsider** | Network access to a product's API | Any access at all |
| **A2: Low-privilege user** | A valid account (for example, a teller) | Permissions they weren't given |
| **A3: Malicious tenant admin** | Admin rights in one tenant | Access to another tenant, or more power in their own (for example, super-admin) |
| **A4: Former or temporary user** | An assignment that was revoked or expired | Continued access |
| **A5: Malicious insider or contributor** | Ability to propose changes to wardn | Insert a backdoor into wardn |
| **A6: Supply-chain attacker** | Control of a dependency, CI action, or release path | Ship malicious code inside wardn |
| **A7: Well-meaning developer** *(not an attacker, but the most common cause of real incidents)* | Writes the product's YAML and routes | Gets something wrong by accident |

---

## 3. Trust boundaries and assumptions

### 3.1 Trusted

wardn trusts these, and its guarantees depend on them:

- **The product's authentication.** The user ID that reaches wardn (from the request context or `UserFrom`) is authentic. wardn doesn't authenticate.
- **The policy file and Go policy.** These are code, reviewed and deployed like code.
- **The product's database,** against tampering from outside wardn's API. An attacker with write access to the database can grant themselves anything; database security is the product's responsibility.
- **`ParentOf`, when supplied,** returns the true parent from the product's authoritative data.
- **The server clock,** within a reasonable skew (see T19).

### 3.2 Untrusted

wardn validates all of these:

- **Every value derived from a request:** scope IDs from URL parameters, query strings, headers and bodies.
- **Every argument to management APIs:** role names and specs, user IDs, scope IDs, time windows. These usually originate from admin forms.
- **Store contents read back:** treated as data, never as code or patterns. A stored permission string is matched literally against the catalog.
- **Contributors and dependencies,** until reviewed.

---

## 4. Threats — authorization logic

| ID | Threat | Actor | Mitigation |
|---|---|---|---|
| **T01** | **Cross-tenant access:** an admin of Org A acts in Org B. | A3 | Only assignments in the requested scope's own ancestor chain are considered. Custom roles are visible only in their owner's subtree. The conformance suite checks that stores never return assignments outside the requested scopes. |
| **T02** | **Confused deputy (IDOR):** a request to `/orgs/A/loans/{id}` passes the check for Org A, but loan `id` belongs to Org B. | A2, A3 | wardn can't know which tenant a loan belongs to, so this must be handled in the product; wardn makes the safe way easy. Documentation and recipes require checking against **the resource's own scope** (`w.Can(ctx, u, perm, loan.Scope())`) whenever a route acts on a specific resource, and reference apps demonstrate this. This threat gets its own section in the quick start. |
| **T03** | **Privilege escalation through role management:** an admin creates or edits a role containing permissions they don't hold, or assigns such a role. | A3 | Escalation guard (DESIGN §6.2) on every create, edit, assign and revoke, in the target scope. |
| **T04** | **Lockout attack:** a lower admin revokes a higher admin's role. | A3 | Revoking requires the same guard as assigning. |
| **T05** | **Self-escalation through a custom role you already hold:** an admin with `wardn:roles.manage` edits a role assigned to them to add permissions. | A3 | The guard applies to edits: every permission added must already be held by the actor, so editing can never increase the editor's own power. |
| **T06** | **Wildcard abuse:** an admin creates a custom role with `*` or `loan:*` and thereby gains permissions added to the catalog later. | A3 | Actors may use a wildcard in a custom role only if they hold that same wildcard. Holding every current `loan:` permission is not enough. Planned wildcard expansion is explicit in the docs. |
| **T07** | **Deny bypass:** a combination of roles or scopes makes an allow beat a deny. | A2 | Deny-wins is evaluated after collecting all applicable roles, and the property test "for any set of roles, a matching deny always yields DENY" runs on every change. |
| **T08** | **Fail-open on error:** a store timeout or error is treated as allow. | A1, A2 | Every error path returns DENY. `Can` returns false on error; middleware returns 500, never calls the handler. Errors are injected into a fake store to test every path. |
| **T09** | **Revoked or expired access still works.** | A4 | Time windows and revocations are evaluated on every check. No cross-request caching by default. When caching is opt-in, it uses version-counter invalidation and expiry-bounded entries. |
| **T10** | **Deleted role still grants access.** | A4 | Assignments referencing a missing role grant nothing. |
| **T11** | **Hierarchy manipulation:** a scope is linked under an attacker-controlled parent, so the attacker's admin role is inherited into it. | A3 | `Link` is backend plumbing and is never exposed as an end-user API; the docs say so explicitly. Parent types are validated against the YAML. Re-linking emits an audit event. |
| **T12** | **Hierarchy loops or deep chains** cause unbounded lookups (denial of service). | A3, A7 | Chain depth is bounded by the number of declared scope types, and cycles in the YAML are rejected at startup. |
| **T13** | **Scope identity confusion:** IDs that differ only in case, Unicode form, or embedded separators (`"o1"` vs `"O1"`, `"a:b"` as an ID) collide or split incorrectly. | A2, A3 | Scope IDs are compared byte-exactly; wardn never normalises them. Type names are restricted to `[a-z0-9_]`. IDs reject control characters and are length-limited. All composite keys (cache keys, store keys) use length-prefixed or structured encoding, never string concatenation. |
| **T14** | **Permission spoofing:** a stored or supplied permission string such as `loan:approve ` (trailing space) or a look-alike Unicode character is treated as valid. | A3 | Permissions are restricted to `[a-z0-9_:.]` plus wildcards, and are matched exactly against the catalog. Unknown permissions are rejected on write and ignored on read. |
| **T15** | **Role-name spoofing in admin UIs:** a custom role called "Super Admin" (or with homoglyphs) misleads other admins into assigning it. | A3 | Custom role names cannot match or case-fold-collide with system role names. Mixed-script and invisible characters are rejected. Roles are always identified by ID, never by name, in APIs. |
| **T16** | **Typo silently changes behaviour:** a misspelled permission in a route or YAML file grants nothing or everything. | A7 | Unknown names are errors; `Require` panics at registration; YAML is fully validated at startup; generated constants turn typos into compile errors. |
| **T17** | **Missing check on a route.** | A7 | Out of wardn's full control, since a route that never calls wardn can't be stopped by wardn. Mitigated by recipes using router-group-level `Require`, by reference apps, and by `wardntest.AuditRoutes`: a test helper that requests every route (collected with `chi.Walk`, for example) as a signed-in user with no roles, and fails for any route that doesn't answer 403. It also fails if its probe user was never really authenticated, so a misconfigured audit can't pass by accident. |
| **T18** | **Default-deny bypass through the global scope:** a request with no derivable scope accidentally becomes a check at global scope, where more roles apply. | A2 | Checking at global only considers *global* assignments, which are strictly fewer than or equal to those at any tenant scope. If a route requires a scope and none is found, middleware fails with an error, never with a silent fallback; the fallback is configurable only in the strict direction. |
| **T19** | **Clock skew** makes access start early or end late on one instance. | A4 | The clock is injectable, and the docs require NTP-synced servers. Time windows are evaluated against the checking instance's clock. Neither the store nor the cache carries a time or a decision between instances, so a skewed instance is wrong by at most its own skew, and only on that instance (tested with two instances sharing a store and cache). Stores may provide database time in a later version. |
| **T20** | **Information leakage:** error responses reveal which permission or role is missing, helping an attacker map the system. | A1, A2 | Default HTTP responses are generic (`401` / `403`). Detailed `Decision`s go only to `OnDecision`. |
| **T21** | **Audit gaps:** a change happens without an audit event, or an audit failure is silently ignored. | A3, A5 | Every management call emits an event, including calls through `System()`, with the actor recorded as `system`. Products choose whether an `OnChange` error aborts the change; fail-closed is recommended for regulated products and is the documented default. |
| **T22** | **Concurrent edits** cause lost updates to a role, re-adding a permission someone just removed. | A3 | Optimistic concurrency on role updates (`ErrConflict`). |
| **T23** | **Resource exhaustion through huge inputs:** a giant policy file, millions of roles in a spec, or an unbounded `Members` page. | A3, A7 | Size limits on policy files, role specs and IDs; `Members` is paginated with a maximum page size. The YAML parser is fuzzed, and its alias-expansion limits are tested. |
| **T24** | **Cache poisoning or key collision** (cache opt-in only). | A2, A3 | Hashed, structured cache keys (T13). Every value is sealed with HMAC-SHA256 over key and value (`Config.CacheSecret`, required for shared caches), so a writable cache can't forge or move entries. Unverifiable values are misses. Version counters aren't sealed: Redis must not evict them (`noeviction` or `volatile-*`), and a lost counter revives old genuine entries for at most one TTL. The server must still be private, with authentication and TLS. |
| **T26** | **Query-operator injection (MongoDB):** an ID such as `{"$ne": ""}` matches every document. | A1, A2 | The MongoDB store only ever uses user-supplied values as typed string values in filters, never as query documents or field names; tested with operator-like IDs. |
| **T27** | **Reused scope IDs across tenants:** two tenants name a scope the same (`department:cardiology`); linking the second moves the first under the other tenant's administrators. | A3, A7 | `Link` never changes an existing parent: a different parent fails with `ErrAlreadyLinked`; moves require the explicit `Move`. Docs require IDs unique per type (primary keys or composite IDs) and show the composite-ID pattern. Found by the M8 usability rehearsal. |
| **T28** | **Uncommitted access escapes the application's transaction** (v1.1): wardn reads inside an application transaction, sees an uncommitted grant, and caches it, so other requests use access that is later rolled back; or the cache keeps the old state after the commit. | A2, A4 | Inside an application transaction wardn neither reads nor fills the shared cache or the request memo. Counters are bumped before the write and again when the application calls the function `Warden.Transaction` returned, after the commit. A change with only one of `Store.WithTx` and `Warden.Transaction` fails with `ErrNoTransaction`, so a forgotten call can't silently leave the cache stale. The SQL store writes in savepoints, so a failed write never aborts the application's transaction. |
| **T25** | **Race conditions** in concurrent checks and changes produce inconsistent decisions. | A2 | Immutable compiled policy; per-request memo scoped to one request; every package tested with `-race`. |

---

## 5. Threats — wardn's own supply chain

| ID | Threat | Actor | Mitigation |
|---|---|---|---|
| **S01** | **Malicious or vulnerable dependency.** | A6 | Minimal dependencies. A CI-enforced allowlist of direct dependencies. `govulncheck` on every change and on a weekly schedule. Dependabot updates are reviewed, never auto-merged. |
| **S02** | **Compromised CI action** (a tag moved to malicious code). | A6 | Every action is pinned to a full commit SHA. Workflows have read-only default permissions. Checkout doesn't persist credentials. |
| **S03** | **Backdoor in a contribution.** | A5 | Protected `main`, required review by a code owner, all checks green, signed commits. Security-sensitive paths (evaluation, guard, stores) require two approvals. |
| **S04** | **Tampered release.** | A6 | Signed tags; the release workflow refuses a tag that is lightweight or not verified by GitHub. The Go checksum database guarantees immutable module content per version. CLI binaries are built reproducibly (`-trimpath`, no build ID) in CI and published with SHA-256 checksums and Sigstore-signed build-provenance attestations (`gh attestation verify`). |
| **S05** | **Leaked maintainer credentials.** | A6 | Two-factor authentication required in the GitHub organisation. No long-lived secrets in CI. Releases are made from CI, not laptops. |
| **S06** | **Hidden behaviour in the library:** network calls, telemetry, `unsafe`, code run at import time. | A5 | Forbidden by the contribution rules and enforced by lint on every change. `depguard` bans `unsafe`, `os/exec`, `plugin`, `math/rand` and global `log`. `forbidigo` bans outbound connections (`http.Get`, `http.Client`, `net.Dial`, …), writing to stdout, and process-state changes (`os.Exit`, `os.Setenv`). wardn uses `net/http` only to *serve* middleware, never to make requests. |
| **S07** | **Unreported vulnerabilities.** | — | `SECURITY.md` with private reporting, response-time commitments, and coordinated advisories. |

---

## 5a. Test status

Threats with a `TestThreat_` test, by milestone:

| Status | Threats |
|---|---|
| **Tested (M2)** | T01, T07, T08, T09, T10, T11, T12, T13, T14, T16, T18, T23, T25 |
| **Tested at the store level (M3)** | T01 (`FiltersByUser`, `FiltersByScope`), T13 (`ExactIdentity`: case, Unicode normalisation, width and trailing space on every database), T08 (`TestFailClosedWhenDatabaseDown`), T25 (`Concurrency`), SQL injection through IDs (`HostileAndLongIDs`). These run in the `storetest` conformance suite against SQLite, PostgreSQL, MySQL and MariaDB on every change. |
| **Tested (M4)** | T08 over HTTP (store error → 500, handler not run), T16 at route registration, T17 (`AuditRoutes`, proven against a deliberately unprotected chi route), T18 over HTTP, T20 (error bodies and headers reveal nothing) |
| **Tested (M5)** | T03, T04, T05, T06 (guard tests, plus a property test that attacks the guard in 300 random worlds against the reference implementation), T15 (role-name spoofing), T21 (audit veto and failure reporting), T22 (concurrent edits, in the core and atomically in every store) |
| **Tested (M8)** | T02 (confused deputy: a resource named through another scope's URL is not found, in the bank and SaaS reference applications), T19 (clock skew is bounded by the skew, with two instances sharing a store and cache; documented in the time-limited access guide), T27 (reused scope IDs, in the core and in the bank reference application). T17 and T26, tested since M4 and M6, now also carry `TestThreat_` names, so every threat T01–T27 has one. |
| **Tested (v1.1)** | T28 (`TestThreat_T28_UncommittedAccessNeverCached`: rollback and commit with a warm cache and memo; each of its five safeguards removed in turn is caught, including a store wrapper that hides `InTx`). Application transactions, savepoints and `CheckEach` run against SQLite, PostgreSQL, MySQL and MariaDB, including PostgreSQL with forced row-level security and a restricted role. |
| **Tested (M7)** | Internal security review (docs/SECURITY_REVIEW.md): F1/F1b (deny roles and the guard, extending T03/T04), FZ1 (cache forgery, T24), F2/F3 (T21, T09), F4, F5 (T03), F6 (T09), F7 (T15), F8 (T21), F9 (T23); fault injection on every store, cache and SQL write path; 46 mutants, all caught |
| **Tested (M6)** | T24 (cache values validated, keys hashed, invalidation proven by a property test across two instances and by a real two-instance Redis test), T26 (MongoDB operator injection) |
| Supply chain (process, not unit tests) | S01–S07: enforced by CI gates, repository settings and review (docs/MAINTAINING.md) |

Beyond the named threat tests, M2 adds a property test that checks the engine against an independent reference implementation of the evaluation rules: over 400 random worlds and about 130,000 checks per run. It also adds fuzz targets for policy parsing, permission and ID validation, and `Check` inputs.

## 6. Out of scope

wardn doesn't defend against these; the product and its infrastructure must.

- Compromised authentication (stolen sessions or tokens, forged JWTs)
- Direct write access to the product's database
- A compromised host running the product
- Business-logic rules beyond permissions, such as transaction limits or maker-checker. These are future optional modules.

---

## 7. Review schedule

- Updated whenever a milestone adds or changes an attack surface.
- Fully re-reviewed in M7 (Hardening), and again in the M9 API review. There is no external audit (DESIGN.md D16).
- Re-reviewed for every minor release after v1.0.
