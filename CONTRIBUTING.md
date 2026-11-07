# Contributing to wardn

wardn decides who can do what in every product that uses it. A bug here is a security incident everywhere, so the bar for changes is deliberately high. These rules exist to protect every team that depends on wardn.

Read [docs/DESIGN.md](docs/DESIGN.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before your first change.

## Before you open a pull request

Run the same checks CI runs:

```bash
make check
```

This runs formatting and lint (including security linters), tests with the race detector, the dependency allowlist check, module verification and `govulncheck`. A pull request cannot merge unless all of them pass.

Requirements: Go 1.26 or newer, plus `make`. The pinned linter and vulnerability scanner are fetched automatically.

## Rules for every change

1. **Tests come with the code.** No behaviour change merges without tests that prove it. Security-relevant behaviour needs a test that would fail if the protection were removed.
2. **Threats are traceable.** If a change mitigates a threat in the threat model, its test is named `TestThreat_<ID>_<Description>` (for example, `TestThreat_T01_CrossTenantAssignmentsIgnored`). If a change adds new attack surface, update the threat model in the same pull request.
3. **Fail closed.** Every error path must result in "deny". If you are unsure what an error path should do, it should deny.
4. **No silent suppression.** `//nolint` needs a specific linter and an explanation: `//nolint:gosec // G115: value is bounded by len(x) above`. Reviewers will question every one.
5. **No hidden behaviour.** No network calls, telemetry, global logging, writing to stdout, `init()` side effects, `unsafe`, `os/exec` or runtime code loading. Lint enforces most of this.
6. **Public API changes need design agreement first.** Open an issue describing the change and update `docs/DESIGN.md` before writing code.
7. **Small, focused pull requests.** One concern per pull request. Large changes are split.

## Dependencies

Every dependency is code we trust to run inside every product, so the core module stays as close to the standard library as possible.

- A new **direct** dependency must be added to [`.github/allowed-dependencies.txt`](.github/allowed-dependencies.txt) with a justification, and approved by a maintainer. CI rejects anything not on the list.
- Before proposing one, answer in the pull request: Can the standard library do this? Is it actively maintained? How large is its own dependency tree? Has it had security issues?
- Dependency updates (including Dependabot's) are reviewed like code: read the changelog and the diff for anything unexpected. Nothing is auto-merged.

## Commits and review

- Commits must be **signed** (GPG, SSH or Sigstore `gitsign`) and are verified by branch protection.
- Every pull request needs approval from a code owner. Changes to the evaluation engine, the escalation guard, stores, or anything in the threat model need **two** approvals.
- Reviewers check the security checklist in the pull request template, not just the code.

## Reporting security problems

Never in public. See [SECURITY.md](SECURITY.md).
