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
  - `Test (Go 1.26.x)`, `Test (Go 1.27.x)`, `Lint (.)`, `Lint (store/mongo)`, `Lint (store/pgx)`, `Lint (cache/redis)`, `Lint (tests/integration)`, `Supply chain`, `Integration (real databases)`
  - add `Analyze (Go)` when CodeQL is restored (see "CodeQL" below)
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
- [ ] CodeQL: see below.

### CodeQL (currently disabled)

CodeQL code scanning on a private repository requires paid GitHub Advanced Security (Code Security), so the CodeQL workflow has been removed for now. `gosec`, `staticcheck` and `govulncheck` still run on every change.

Restore it when the repository goes public (M10, where it is free), or earlier if the organisation enables Code Security. The removed workflow is in git history at commit `3fa1d16`:

```bash
git show 3fa1d16:.github/workflows/codeql.yml > .github/workflows/codeql.yml
```

Update the pinned action SHAs before re-enabling it.

### Database images

The integration servers (PostgreSQL, MySQL, MariaDB, MongoDB, Redis) are pinned by digest in two places that must match: `tests/integration/compose.yaml` and the `integration` job in `.github/workflows/ci.yml`. Dependabot does not update them. Refresh them deliberately, at least once per milestone:

```bash
docker pull postgres:17-alpine && docker image inspect --format '{{index .RepoDigests 0}}' postgres:17-alpine
```

### Billing

GitHub Actions on a private repository uses the organisation's included minutes (2,000 a month on the Free plan). If the organisation's billing is in a failed-payment state, **no workflows run at all**, including the security gates. An organisation owner must keep billing in good standing, even with a $0 spending limit. Until it is, the pre-push hook (`make hooks`) is the only enforcement, and it can be bypassed.

### Actions (Settings → Actions → General)

- [ ] Allow only actions from GitHub and these verified creators: `actions/*` (including `actions/attest-build-provenance`), `golangci/golangci-lint-action` (add `github/codeql-action/*` when CodeQL is restored)
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
2. Update [CHANGELOG.md](../CHANGELOG.md): move "Unreleased" entries under the new version, and call out security fixes, deprecations and database schema changes. From v1.0.0 there are no breaking changes ([STABILITY.md](STABILITY.md)).
3. Create a **signed, annotated** tag on the merge commit:
   ```bash
   git tag -s v1.2.0 -m "wardn v1.2.0"
   git tag -v v1.2.0     # verify the signature before pushing
   git push origin v1.2.0
   ```
   Then tag the sub-modules on the same commit (see [Sub-modules](#sub-modules)).
4. Create the GitHub release from the tag, with the changelog section as notes.
5. Check that the new version appears on `pkg.go.dev` and that `go get github.com/MogRex-Limited/wardn@v1.2.0` works.

Pushing the tag starts `.github/workflows/release.yml`. It:

1. refuses the release unless the tag is an annotated tag whose signature GitHub verifies;
2. runs the tests;
3. builds the `wardn` CLI for Linux, macOS and Windows (amd64 and arm64) reproducibly;
4. publishes the binaries with a `SHA256SUMS` file and Sigstore-signed build provenance;
5. creates the GitHub release.

Anyone can verify a downloaded binary with `gh attestation verify <file> --repo MogRex-Limited/wardn`. Developers who install with `go install` are protected by the Go checksum database instead.

### Documentation site

The site in `website/` is built with Astro Starlight. CI builds it on every change and fails on any broken internal link or vulnerable dependency (`npm audit`). Dependabot proposes npm and container-image updates weekly.

Until the open-source milestone, host it **internally only**: build the container (`docker build -t wardn-docs website/`) and run it on an internal host or behind company sign-in. It serves static files only, as a non-root user, with strict security headers.

### Deep checks

`.github/workflows/deep.yml` runs a 5-minute-per-target fuzzing campaign and mutation testing every week. Treat a failure as a security issue: a fuzz crash uploads its input as an artifact. Commit that input under `testdata/fuzz/` with the fix, so it becomes a permanent regression test.

### Sub-modules

`store/mongo`, `store/pgx` and `cache/redis` are separate Go modules, so their drivers reach only the teams that use them. They are released **in lockstep with the core**: every release tags all four, at the same version, on the same commit. (`store/pgx` joined in v1.2.0: its first tag is `store/pgx/v1.2.0`.)

Each sub-module's `go.mod` keeps a `replace` line pointing at the core in this repository, so CI always tests the sub-modules against the current core. Go ignores `replace` for downstream users, who get the core version in the `require` line instead. That line is therefore what users actually build against, and it must name the version being released. In the release pull request:

1. In `store/mongo/go.mod`, `store/pgx/go.mod` and `cache/redis/go.mod`, set `require github.com/MogRex-Limited/wardn` to the new version, and run `go mod tidy` in each. This works before the tag exists, because of the `replace` line.
2. After merging, tag the core (`v1.2.0`, step 3 above), then each sub-module with its path, on the same commit:
   ```bash
   git tag -s store/mongo/v1.2.0 -m "wardn store/mongo v1.2.0"
   git tag -s store/pgx/v1.2.0 -m "wardn store/pgx v1.2.0"
   git tag -s cache/redis/v1.2.0 -m "wardn cache/redis v1.2.0"
   git push origin store/mongo/v1.2.0 store/pgx/v1.2.0 cache/redis/v1.2.0
   ```
3. Check that `go get github.com/MogRex-Limited/wardn/store/mongo@v1.2.0` works in a fresh module.

Only core tags (`v*`) start the release workflow. Sub-module tags only publish their source. `make api` fails if a sub-module's `require` is older than the latest core tag, so a forgotten step 1 is caught on the next change.

### Known advisories

- **GO-2026-5932** (`golang.org/x/crypto/openpgp`, deprecated and unsafe by design) is reported for `store/mongo`'s dependency graph. No package in the graph imports `openpgp` (`go list -deps ./... | grep openpgp` is empty), and its fix exists only as an untagged snapshot. Move `golang.org/x/crypto` to the first tagged release that contains the fix, then remove this note.

### Versioning

- Semantic versioning. From `v1.0.0`, breaking changes need a new major version. [STABILITY.md](STABILITY.md) defines what that covers. `make api` (in `make check` and CI) compares every change with each module's latest v1 tag.
- A security fix is released as a patch version as soon as it is ready, following [SECURITY.md](../SECURITY.md).
- If a released version is found to be dangerous, add a `retract` directive to `go.mod` in the next release so `go get` warns users away from it.
