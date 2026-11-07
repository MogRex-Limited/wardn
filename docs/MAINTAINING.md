# Maintaining wardn

This document is for wardn maintainers. It covers the GitHub settings the security model depends on, and how releases are made.

Some protections in the [threat model](THREAT_MODEL.md) (S02–S05) cannot be enforced by files in the repository; they depend on these settings. **Check them at every milestone and before every release.**

## 1. Maintainers

- wardn needs **at least two maintainers**. With one, required reviews either block every change or have to be bypassed, and bypassing defeats the purpose.
- Maintainers are listed in [`.github/CODEOWNERS`](../.github/CODEOWNERS).
- Every maintainer uses two-factor authentication and signs commits.

## 2. Repository settings checklist

### Branch protection for `main` (Settings → Rules → Rulesets)

- [ ] Require a pull request before merging
  - [ ] Required approvals: **1** (2 by convention for sensitive paths; see CONTRIBUTING.md)
  - [ ] Dismiss stale approvals when new commits are pushed
  - [ ] Require review from code owners
  - [ ] Require approval of the most recent push (no self-approving after a reviewer's approval)
  - [ ] Require conversation resolution before merging
- [ ] Require status checks to pass, with branches up to date:
  - `Test (Go 1.26.x)`, `Test (Go 1.27.x)`, `Lint`, `Supply chain`, `Analyze (Go)`
- [ ] Require signed commits
- [ ] Require linear history
- [ ] Block force pushes
- [ ] Restrict deletions
- [ ] **No bypass list**: the rules apply to administrators too

### Tag protection (Settings → Rules → Rulesets, target: tags)

- [ ] Ruleset on `v*` tags: only maintainers may create them; block updates and deletions. A published version tag must never move.

### Code security (Settings → Code security)

- [ ] Private vulnerability reporting: **enabled** (required by SECURITY.md)
- [ ] Dependabot alerts: enabled
- [ ] Dependabot security updates: enabled
- [ ] Secret scanning and push protection: enabled
- [ ] CodeQL: results visible in the Security tab. Code scanning on private repositories requires GitHub Advanced Security (Code Security); if it is unavailable, the CodeQL workflow will fail and must be enabled before M9.

### Actions (Settings → Actions → General)

- [ ] Allow only actions from GitHub and these verified creators: `actions/*`, `github/codeql-action/*`, `golangci/golangci-lint-action`
- [ ] Require actions to be pinned to a full-length commit SHA
- [ ] Workflow permissions: **read repository contents** (default token is read-only)
- [ ] Do **not** allow GitHub Actions to create or approve pull requests
- [ ] Require approval to run workflows for all outside contributors

### Organisation

- [ ] Two-factor authentication required for all members

## 3. Reviewing dependency updates

Dependabot opens pull requests weekly, after a 7-day cooldown. For each one:

1. Read the release notes and the source diff of the dependency for anything unexpected: new network access, new dependencies, obfuscated code, changed ownership.
2. Check that CI passes, including `govulncheck`.
3. Never auto-merge.

## 4. Releases

wardn is a Go module: users download source through the Go module proxy, and the Go checksum database (`sum.golang.org`) guarantees every user gets byte-identical content for a version. A released version can therefore never be changed, only superseded. Releases need care.

### Steps

1. Make sure `main` is green on every check, and the [threat model](THREAT_MODEL.md) is up to date.
2. Update [CHANGELOG.md](../CHANGELOG.md): move "Unreleased" entries under the new version, and call out security fixes and breaking changes.
3. Create a **signed, annotated** tag on the merge commit:
   ```bash
   git tag -s v0.1.0 -m "wardn v0.1.0"
   git tag -v v0.1.0     # verify the signature before pushing
   git push origin v0.1.0
   ```
4. Create the GitHub release from the tag, with the changelog section as notes.
5. Check that the new version appears on `pkg.go.dev` and that `go get github.com/MogRex-Limited/wardn@v0.1.0` works.

From M4, when the `wardn` CLI exists, a release workflow will build the CLI binaries in CI and publish them with build-provenance attestations, so users can verify that a binary was built from the tagged source.

### Versioning

- Semantic versioning. `v0.x` may change the API; from `v1.0.0`, breaking changes need a new major version.
- A security fix is released as a patch version as soon as it is ready, following [SECURITY.md](../SECURITY.md).
- If a released version is found to be dangerous, add a `retract` directive to `go.mod` in the next release so `go get` warns users away from it.
