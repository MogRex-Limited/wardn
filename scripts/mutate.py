#!/usr/bin/env python3
"""Mutation testing for wardn's security rules.

Each mutant deliberately breaks one security rule. The test suite must fail
for every mutant; a mutant that survives is a security rule no test
protects. Run with `make mutation`.

A mutant that does not compile is reported as invalid (a mistake in this
list), never counted as caught.

Adding a mutant: copy an exact snippet from the source (it must occur exactly
once) and a replacement that compiles but breaks the rule.
"""
import os
import shutil
import subprocess
import sys
import tempfile

# (file, description, original, mutated)
MUTANTS = [
    # Names and matching
    ("names.go", "wildcard matches across the ':' boundary (loan:* matches loans:x)",
     "return strings.HasPrefix(perm, prefix) // prefix ends with ':'",
     "return strings.HasPrefix(perm, strings.TrimSuffix(prefix, \":\"))"),
    ("names.go", "IDs may contain control and invisible characters",
     "if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {\n\t\t\treturn fmt.Errorf(\"%s ID contains",
     "if false && unicode.IsControl(r) {\n\t\t\treturn fmt.Errorf(\"%s ID contains"),
    ("names.go", "single-segment permissions are valid",
     "if len(segments) < 2 {", "if len(segments) < 1 {"),
    # Evaluation
    ("check.go", "store results are trusted: other users' assignments count",
     "case a.User != user, !inChain:", "case !inChain:"),
    ("check.go", "time windows ignored",
     "case !a.activeAt(now):", "case now.IsZero():"),
    ("check.go", "deny rules ignored",
     "if rule, ok := firstMatch(g.role.deny, d.Permission); ok {",
     "if rule, ok := firstMatch(nil, d.Permission); ok {"),
    ("check.go", "assignable_at not enforced at check time",
     "if !role.assignableAtScope(a.Scope) {\n\t\t\tcontinue // the policy no longer allows this role here",
     "if false {\n\t\t\tcontinue // the policy no longer allows this role here"),
    ("check.go", "custom roles apply outside their owner's subtree",
     "if ownerDepth, ok := depthOf[cr.Owner]; !ok || ownerDepth < depth {",
     "if _, ok := depthOf[cr.Owner]; !ok && false {"),
    ("check.go", "stored links of the wrong type are followed",
     "if parent.Type != want {\n\t\t\treturn nil, fmt.Errorf(\"%w: parent of %s is %s",
     "if false {\n\t\t\treturn nil, fmt.Errorf(\"%w: parent of %s is %s"),
    ("check.go", "inheritance stops one level early",
     "for range w.policy.maxDepth {", "for range w.policy.maxDepth - 1 {"),
    ("check.go", "undefined permissions are checkable",
     "if _, ok := w.policy.permissions[perm]; ok {\n\t\treturn nil\n\t}",
     "if _, ok := w.policy.permissions[perm]; ok || true {\n\t\treturn nil\n\t}"),
    # Not listed: skipping the "only requested IDs" filter on custom roles
    # loaded from the store (check.go) is an equivalent mutant. Only
    # requested IDs are ever looked up, so extra roles are never used.
    ("store.go", "access lasts until the end of the expiry instant (inclusive)",
     "if !a.ExpiresAt.IsZero() && !t.Before(a.ExpiresAt) {",
     "if !a.ExpiresAt.IsZero() && t.After(a.ExpiresAt) {"),
    # Escalation guard
    ("manage.go", "guard does not check held permissions",
     "\t\t\tif !holds(gs, p) {", "\t\t\tif !holds(gs, p) && p == \"\" {"),
    ("manage.go", "guard does not check the management permission",
     "if d := evaluate(gs, Decision{User: a.id, Permission: mgmtPerm, Scope: scope}); !d.Allowed {",
     "if d := evaluate(gs, Decision{User: a.id, Permission: mgmtPerm, Scope: scope}); !d.Allowed && false {"),
    ("manage.go", "a deny inside a wildcard does not stop holding it",
     "if covers(d, pattern) || covers(pattern, d) {", "if covers(d, pattern) {"),
    ("manage.go", "wildcard coverage ignores the ':' boundary",
     "return strings.HasPrefix(p, strings.TrimSuffix(q, \"*\"))",
     "return strings.HasPrefix(p, strings.TrimSuffix(q, \":*\"))"),
    ("manage.go", "editing a role does not require holding its current permissions",
     "if err := w.guard(ctx, a, old.Owner, PermRolesManage, old.Allow, r.Allow); err != nil {",
     "if err := w.guard(ctx, a, old.Owner, PermRolesManage, r.Allow); err != nil {"),
    ("manage.go", "revoking does not require holding the role's permissions",
     "\tcase err == nil:\n\t\tallow, deny = r.compiled.allow, r.compiled.deny", "\tcase err == nil:\n\t\tallow, deny = r.compiled.allow[:0], r.compiled.deny"),
    ("manage.go", "custom roles assignable outside their owner",
     "if !slices.Contains(chain, r.custom.Owner) {", "if !slices.Contains(chain, r.custom.Owner) && false {"),
    ("manage.go", "custom roles assignable at scope types above their owner",
     "\tfor cur := t; cur != \"\"; {\n\t\tif cur == owner.Type {",
     "\tfor cur := t; cur != \"\" || true; {\n\t\tif true {"),
    ("manage.go", "custom roles may contain denies",
     "if len(spec.Deny) > 0 {", "if len(spec.Deny) > 1000 {"),
    ("manage.go", "role names may look like system role names",
     "\t\tif roleNameKey(name) == key {", "\t\tif name == key {"),
    ("manage.go", "an assigned role can be deleted without Cascade",
     "if inUse && !o.cascade {", "if inUse && !o.cascade && false {"),
    ("customrole.go", "role names may mix scripts (homoglyphs)",
     "} else if s != script {", "} else if s != script && false {"),
    ("customrole.go", "role name uniqueness is case-sensitive",
     "for _, r := range strings.ToLower(name) {", "for _, r := range name {"),
    # Audit
    ("events.go", "an audit hook failure does not stop the change",
     "\t\tif err := w.onChange(ctx, ev); err != nil {\n\t\t\treturn fmt.Errorf(\"%w: %w\", ErrAuditRejected, err)",
     "\t\tif err := w.onChange(ctx, ev); err != nil && false {\n\t\t\treturn fmt.Errorf(\"%w: %w\", ErrAuditRejected, err)"),
    # Cache
    ("cache.go", "moving a scope does not invalidate tenants",
     "return []string{counterLinks, oldRoot, newRoot}, nil", "return []string{counterLinks, oldRoot[:0], newRoot[:0]}, nil"),
    ("cache.go", "a move does not invalidate like a link (M9 API review)",
     "case EventLinked, EventMoved:", "case EventLinked:"),
    ("manage.go", "a move is audited as a link, losing the old parent (M9 API review)",
     "ev.Type, ev.PreviousParent = EventMoved, current", "ev.Type, ev.PreviousParent = EventLinked, Scope{}"),
    ("events.go", "an audit event's error is left out of its JSON (M9 API review)",
     "out.Error = e.Err.Error()", "_ = e.Err.Error()"),
    ("events.go", "no cache invalidation after the write",
     "if err := w.cache.Incr(ctx, counters); err != nil {\n\t\t\tcacheErr = ",
     "if err := error(nil); err != nil {\n\t\t\tcacheErr = "),
    ("events.go", "no cache invalidation after a failed (possibly partial) write (review F2)",
     "\tif len(counters) > 0 {\n\t\tif err := w.cache.Incr(ctx, counters); err != nil {\n\t\t\tcacheErr = ",
     "\tif len(counters) > 0 && writeErr == nil {\n\t\tif err := w.cache.Incr(ctx, counters); err != nil {\n\t\t\tcacheErr = "),
    ("cache.go", "cache keys ignore the Global counter",
     "return &cacheVersions{tenant: vs[0], global: vs[1], root: root}",
     "return &cacheVersions{tenant: vs[0], global: 0, root: root}"),
    # HTTP
    ("http.go", "RequireAny/Require logic: a request is allowed by default",
     "\t\t\tallowed := !needAny", "\t\t\tallowed := true"),
    ("http.go", "invalid scope IDs from the URL reach Require",
     "\t\t\tif err := w.validateScope(scope); err != nil {\n\t\t\t\tw.onError(rw, r, err)",
     "\t\t\tif err := w.validateScope(scope); err != nil && false {\n\t\t\t\tw.onError(rw, r, err)"),
    ("http.go", "error responses reveal the reason",
     "_, _ = fmt.Fprintf(w, \"{\\\"error\\\":%q}\\n\", body)",
     "_, _ = fmt.Fprintf(w, \"{\\\"error\\\":%q}\\n\", err.Error())"),
    ("http.go", "Require registration accepts undefined permissions",
     "\t\tif err := w.checkPermission(p); err != nil {\n\t\t\tpanic(",
     "\t\tif err := w.checkPermission(p); err != nil && false {\n\t\t\tpanic("),
    # Admin screens
    ("introspect.go", "AssignableRoles offers roles the actor cannot grant",
     "return slices.ContainsFunc(r.Allow, lacks) || slices.ContainsFunc(r.Deny, lacks)",
     "return slices.ContainsFunc(r.Allow[:0], lacks)"),
    ("introspect.go", "AssignableRoles ignores what a role denies (review F1b)",
     "return slices.ContainsFunc(r.Allow, lacks) || slices.ContainsFunc(r.Deny, lacks)",
     "return slices.ContainsFunc(r.Allow, lacks)"),
    ("introspect.go", "the sweeper removes re-granted assignments (review F4)",
     "if err := w.store.RevokeExpired(ctx, a); err != nil {",
     "if err := w.store.Revoke(ctx, a.User, a.Role, a.Scope); err != nil {"),
    # Security review fixes
    ("manage.go", "assigning a role ignores what it denies (review F1b)",
     "if err := w.guard(ctx, a, scope, PermRolesAssign, r.compiled.allow, r.compiled.deny); err != nil {",
     "if err := w.guard(ctx, a, scope, PermRolesAssign, r.compiled.allow); err != nil {"),
    ("manage.go", "revoking a role ignores what it denies (review F1)",
     "if err := w.guard(ctx, a, scope, PermRolesAssign, allow, deny); err != nil {",
     "if err := w.guard(ctx, a, scope, PermRolesAssign, allow, deny[:0]); err != nil {"),
    ("manage.go", "a denied actor learns that a role exists (review F5)",
     "if errors.As(err, &denied) {", "if errors.As(err, &denied) && false {"),
    ("manage.go", "times outside years 1-9999 accepted (review F6)",
     "if !tm.IsZero() && (tm.Year() < 1 || tm.Year() > 9999) {", "if false && !tm.IsZero() {"),
    ("manage.go", "Link silently moves a scope to another parent (rehearsal, T27)",
     "\tcase linked && !move:", "\tcase linked && !move && false:"),
    ("manage.go", "no limit on custom roles per owner (review F9)",
     "if len(own) >= maxRolesPerOwner {", "if len(own) >= maxRolesPerOwner*1000 {"),
    ("customrole.go", "look-alike characters are not folded in role names (review F7)",
     "if folded, ok := confusables[r]; ok {", "if folded, ok := confusables[r]; ok && false {"),
    ("cache.go", "cache entries are not verified (fuzzing finding)",
     "if !hmac.Equal(tag, mac.Sum(nil)) {", "if !hmac.Equal(tag, mac.Sum(nil)) && false {"),
    ("store.go", "the memory store's RevokeExpired ignores the window (review F4)",
     "if ma := m.byUser[a.User][key]; ma != nil && ma.a.ExpiresAt.Equal(a.ExpiresAt) {",
     "if ma := m.byUser[a.User][key]; ma != nil {"),
    ("introspect.go", "Members trusts the store's scope filtering",
     "return slices.DeleteFunc(page, func(a Assignment) bool { return a.Scope != scope }), next, nil",
     "return page, next, nil"),
]


def run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    work = tempfile.mkdtemp(prefix="wardn-mutation-")
    try:
        shutil.copytree(root, work, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git"))
        survived, invalid = [], []
        for i, (path, desc, old, new) in enumerate(MUTANTS, 1):
            full = os.path.join(work, path)
            with open(full, encoding="utf-8") as f:
                original = f.read()
            if original.count(old) != 1:
                invalid.append((path, desc, f"snippet occurs {original.count(old)} times"))
                print(f"[{i:2}/{len(MUTANTS)}] INVALID  {path}: {desc}")
                continue
            with open(full, "w", encoding="utf-8") as f:
                f.write(original.replace(old, new))
            try:
                build = run(["go", "vet", "./..."], work)
                if build.returncode != 0 and ("cannot" in build.stderr or "undefined" in build.stderr or "declared and not used" in build.stderr or "syntax error" in build.stderr):
                    invalid.append((path, desc, build.stderr.strip().splitlines()[0]))
                    print(f"[{i:2}/{len(MUTANTS)}] INVALID  {path}: {desc}")
                    continue
                test = run(["go", "test", "-short", "-count=1", "-vet=off", "./..."], work)
                if test.returncode == 0:
                    survived.append((path, desc))
                    print(f"[{i:2}/{len(MUTANTS)}] SURVIVED {path}: {desc}")
                else:
                    print(f"[{i:2}/{len(MUTANTS)}] caught   {path}: {desc}")
            finally:
                with open(full, "w", encoding="utf-8") as f:
                    f.write(original)
        print()
        caught = len(MUTANTS) - len(survived) - len(invalid)
        print(f"{caught}/{len(MUTANTS)} mutants caught, {len(survived)} survived, {len(invalid)} invalid")
        for path, desc, why in invalid:
            print(f"  invalid: {path}: {desc}: {why}")
        for path, desc in survived:
            print(f"  SURVIVED (no test protects this rule): {path}: {desc}")
        return 1 if survived or invalid else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
