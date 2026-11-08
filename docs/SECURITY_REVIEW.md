# wardn — Internal Security Review (M7)

| | |
|---|---|
| **Date** | 2026-11-08 |
| **Scope** | The core library, `store/sql` (PostgreSQL, MySQL, MariaDB, SQLite), `store/mongo`, `cache/redis`, the HTTP middleware, the `wardn` CLI |
| **Result** | 1 high, 4 medium and 6 low findings, plus 1 found by fuzzing. All are fixed and protected by regression tests, except two low-severity items accepted as design decisions (§4). |
| **For** | Engineering leadership, and any later reviewer as their starting point (§5) |

---

## 1. Methods

| Method | What it does | Where |
|---|---|---|
| **Independent adversarial review** | A reviewer with no access to the author's reasoning, given only the code, DESIGN.md and THREAT_MODEL.md, tried to break wardn and confirmed each finding with a runnable proof of concept. | §2 |
| **Fault injection: store** | Every management operation runs once per store call it makes, with that one call failing. A failed change must report an error and must never leave access that neither the old state nor the intended new state grants. | `fault_test.go` |
| **Fault injection: cache** | The same, with each cache call failing. Afterwards, cached answers must match the store exactly. | `fault_test.go` |
| **Fault injection: SQL transactions** | A `database/sql` driver wrapper fails each statement, begin and commit in turn. A custom role must always be entirely old or entirely new. | `tests/integration/fault_test.go` |
| **Mutation testing** | 58 deliberate breaks of specific security rules. The test suite must fail for every one. | `scripts/mutate.py`, `make mutation` |
| **Fuzzing** | 8 targets, covering policy parsing, names, `Check` inputs, role names, role specs, pagination cursors, cache contents and HTTP paths. Each ran for 90 seconds (about 14 million executions in total), plus a weekly CI campaign of 5 minutes per target. | `scripts/fuzz.sh`, `make fuzz` |
| **Property tests** | The engine against an independent reference implementation (about 130,000 checks per run). The escalation guard attacked in 300 random worlds. Two instances sharing a cache, checked for staleness after random changes. | `property_test.go`, `guard_property_test.go`, `cache_test.go` |

The fault-injection and mutation harnesses were themselves tested by planting bugs, and each planted bug was caught.

---

## 2. Findings

Every finding was first reproduced by a failing test, then fixed. The test now passes and stays in the suite.

| ID | Severity | Finding | Fix | Regression test |
|---|---|---|---|---|
| **F1** | **High** | **The escalation guard ignored a role's denies.** Revoking a deny role (for example `suspended`) lifted restrictions the actor could never have granted: a branch manager could restore an auditor's `report:export`. | Assigning *or* revoking a role requires holding everything it denies as well as everything it grants. Holding a wildcard still means holding all of it. | `TestReview_F1_RevokingDenyRoleNeedsTheDeniedPower` |
| **F1b** | **High** | Same root cause: a branch manager could assign `suspended` to an organisation admin, locking them out with no way back (breaking T04). `AssignableRoles` offered deny roles to every assigner. | Same rule; `AssignableRoles` applies it. | `TestReview_F1b_AssigningDenyRoleNeedsTheDeniedPower` |
| **FZ1** | **Medium** (found by fuzzing) | **Anyone able to write to a shared cache could grant themselves anything.** A forged entry such as `[{"user":"nobody","role":"super_admin"}]` was accepted. The threat model had listed a private cache as an *assumption*. | Cache entries are sealed with HMAC-SHA256 over key and value. A shared cache requires `Config.CacheSecret` (32+ bytes); entries that fail verification are misses. | `FuzzCacheContents` (crashing input kept in `testdata/fuzz`), `TestCacheForgeryRejected`, `TestCacheEntriesAreSigned` |
| **F2** | Medium | A write that failed part-way (a cascade delete that deleted the role but not its assignments) skipped the second cache invalidation. A cached copy of the deleted role kept granting for up to the TTL. | The post-write invalidation always runs, whether or not the write failed. `Event.Err` now means "failed, may be partly applied". | `TestReview_F2_PartialWriteStillInvalidatesCache` |
| **F3** | Medium | The audit hook could record a change that was then abandoned, because the pre-write cache invalidation failed after the hook approved it. | The pre-write invalidation now runs *before* the audit hook. | `TestReview_F3_AuditNeverRecordsUnwrittenChange` |
| **F4** | Medium | `SweepExpired(RemoveExpired())` could delete an assignment re-granted (with a new window) while the sweep was running, silently removing access an admin had just given. | New store method `RevokeExpired`, an atomic delete only if the expiry is unchanged, in every store and in the conformance suite. | `TestReview_F4_SweepKeepsRegrantedAssignment`, `storetest/Expiry` |
| **F5** | Low | A user with no permissions could learn whether a role ID exists (and its version, and nearby role names) from `UpdateRole` and `DeleteRole` answers. | The management permission is checked first. A denied actor gets exactly the answer for a missing role (`ErrRoleNotFound`, HTTP 404). | `TestReview_F5_NoRoleExistenceOracle` |
| **F6** | Low | A start time beyond year 294,246 overflowed in the SQL and Mongo stores and wrapped into the past, so access meant to start in the far future started *now*. | Times outside years 1–9999 are rejected. | `TestReview_F6_TimesOutOfRangeRejected` |
| **F7** | Low | Role names that look like system roles passed validation: "0rg Admin", dotless-ı, full-width letters, trailing punctuation. | Uniqueness compares a "skeleton": case, punctuation and spacing ignored, full-width folded, common confusables (0/o, 1/l/i/ı, 5/s, …) folded. Full-width characters are refused in names. | `TestReview_F7_LookAlikeRoleNames` |
| **F8** | Low | A user whose ID is `system` was indistinguishable from `System()` calls in the audit trail. | `Event.System` is true for unguarded changes and sweeps, and `Actor` is then empty. The `SystemActor` constant is removed. | `TestReview_F8_SystemActorIsUnambiguous` |
| **F9** | Low | Unbounded custom roles per scope: one tenant could create enough to break role listings (SQLite's limit on query variables). | At most 500 custom roles per owner scope. | `TestReview_F9_CustomRolesPerOwnerBounded` |
| **R1** | Low | Redis Cluster: multi-key commands across hash slots would fail, so the cache would be bypassed and atomic increments wouldn't hold. | All of a namespace's keys share one hash slot (`{namespace}` hash tag). | Redis conformance suite |

The harnesses also found gaps in wardn's *own tests*, which are now closed:
- No test exercised the read/write race that the second cache invalidation exists for. `TestCacheReaderBetweenInvalidationAndWrite` forces it.
- `ScopeFrom` was only ever tested together with `Require`. A handler reading `ScopeOf` directly would have received unvalidated IDs if that check broke (`TestScopeFromAloneValidates`).
- `Members` was never tested against a store returning other scopes' rows.
- Moving a scope within one tenant was never tested.

---

## 3. Sound areas

The review found no bypass in these areas (details in each section of DESIGN.md):

- **Evaluation:** tenant isolation, inheritance, deny-wins, wildcards and their boundaries, half-open time windows, dangling roles, `assignable_at` at check time, custom roles confined to their owner's subtree.
- **The hierarchy:** bounded, with type-checked links.
- **The escalation guard's wildcard semantics.**
- **Optimistic concurrency in every store.**
- **Injection:** SQL fully parameterised with a validated table prefix; MongoDB values only ever typed, never operators; code generation that can't be injected.
- **YAML parsing:** no aliases, size cap.
- **HTTP failure modes and error bodies.**

---

## 4. Accepted risks and design decisions

| Item | Decision | Mitigation |
|---|---|---|
| **F10: the guard is evaluated at the target scope.** An actor who is denied a permission at a *child* scope can still grant it at the parent, from where it reaches the child. | Accepted (DESIGN.md D13). Checking every descendant is unbounded and the result would be surprising. A deny constrains its holder, not what that holder may delegate above it. | Documented. Put restrictive denies on the roles of the people being restricted. |
| **Custom role names are unique within the owner and its ancestors, not its descendants.** A role created at an organisation may share a name with an existing branch role. | Accepted. Scopes have no child index, so checking descendants means scanning every branch. | Admin pickers must show the owner (`RoleInfo.Owner`). |
| **Guard-then-write is not atomic** (TOCTOU). If an actor's own rights are revoked during their request, the request can still complete. | Accepted. The window is one request long, and the action is fully audited. | Audit trail. |
| **Cache version counters are not signed**, and a counter that is lost (evicted, or rolled back by Redis failover) can make old, validly signed entries reachable again until their TTL ends. | Accepted with requirements. | Default TTL 5 s, maximum 5 min. Redis must use `noeviction` or a `volatile-*` policy (documented in `wardnredis`). The server must be private. |
| **`CustomRole`, `Members`, `Roles` and `PermissionsOf` do not check who is asking.** | By design: they are reads, like `Can`. | Products protect routes exposing them with `Require` (documented). |
| **GO-2026-5932** (`x/crypto/openpgp`) is reported in `store/mongo`'s dependency graph. | Not reachable: no package in the graph imports `openpgp`. | Upgrade when a tagged fix exists (docs/MAINTAINING.md). |

---

## 4a. Findings after the review

Found later, fixed the same way: a failing test first, then the fix, and a mutant where a rule can be broken in one line.

| ID | Severity | Finding | Fix | Regression test |
|---|---|---|---|---|
| **T27** (M8 usability rehearsal) | Medium | Two tenants reusing a scope ID: linking the second moved the first tenant's scope under the other tenant's administrators. | `Link` never changes an existing parent (`ErrAlreadyLinked`); `Move` does it on purpose. | `TestThreat_T27_ReusedScopeIDCannotCrossTenants` |
| **A1** (M9 API review) | Medium | `AssignOption` was `func(*Assignment)`, so an option written by the application could change the role, scope or user **after** the escalation guard had checked them: a branch manager's guarded `Assign` of `teller` wrote `super_admin` globally, and the audit event recorded `teller`. Exploiting it needs application code that builds such an option; end users cannot reach it directly. | Options now reach only a private time window, so only `From` and `Until` can exist. | `TestThreat_T03_AssignOptionsCannotChangeWhatIsGuarded` |
| **A2** (M9 API review) | Low | A `Move` was audited as `scope.linked`, without the old parent. `Event` had no JSON names, and its error marshalled as `{}`. | `EventMoved` with `PreviousParent`; stable snake_case JSON for `Event`, with `Err` as `error`. | `TestMoveIsAuditedWithThePreviousParent`, `TestEventJSONIsStable` |

## 5. Brief for later reviewers

wardn has no external audit (DESIGN.md D16). This brief is for anyone who reviews it later: a new maintainer, a security team adopting it, or an auditor if one is ever engaged.

- **Start here:** docs/DESIGN.md §5 (evaluation rules) and §6 (custom roles and the guard); docs/THREAT_MODEL.md; this document.
- **Highest-value targets:**
  1. `manage.go` (the escalation guard: `guard`, `holds`, `covers`, and every management path);
  2. `check.go` (`grants`, `evaluate`, `chain`);
  3. `cache.go`, `events.go` and `tx.go` (invalidation ordering, sealing, and changes inside an application's transaction);
  4. `store/sql/roles.go`, `store/sql/tx.go` and `store/mongo/store.go` (atomicity, savepoints).
- **Running everything:** `make check` runs all gates on all modules. `make integration` runs everything against real PostgreSQL, MySQL, MariaDB, MongoDB and Redis in Docker. `make mutation` and `make fuzz FUZZTIME=5m` run the slower checks.
- **Questions we would most like answered:**
  - Is there any sequence of guarded calls after which someone holds a permission no actor in that sequence held?
  - Is there any interleaving of concurrent operations after which a cache serves a grant the store no longer contains?
