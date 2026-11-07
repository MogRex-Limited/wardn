# Contributing to wardn

wardn decides who can do what in every product that uses it. A bug here is a security incident everywhere, so the bar for changes is deliberately high. These rules exist to protect every team that depends on wardn.

Read [docs/DESIGN.md](docs/DESIGN.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before your first change.

## Before you open a pull request

Once per clone, install the pre-push hook. It runs every check automatically before each push and blocks the push if any fail:

```bash
make hooks
```

You can also run the same checks CI runs at any time:

```bash
make check
```

Don't bypass the hook with `git push --no-verify`.

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

- Commits must be **signed** (GPG, SSH or Sigstore `gitsign`) and are verified by branch protection. See [Setting up commit signing](#setting-up-commit-signing) below.
- Every pull request needs approval from a code owner. Changes to the evaluation engine, the escalation guard, stores, or anything in the threat model need **two** approvals.
- Reviewers check the security checklist in the pull request template, not just the code.

## Setting up commit signing

A signed commit proves it came from you and wasn't altered. GitHub shows a **Verified** badge on it, and branch protection rejects unsigned commits. The simplest method uses an SSH key. Do this once per machine.

### 1. Get an SSH key

Check whether you already have one:

```bash
ls ~/.ssh/id_ed25519.pub
```

If the file doesn't exist, create a key using the email on your GitHub account:

```bash
ssh-keygen -t ed25519 -C "you@example.com"
```

### 2. Tell git to sign with it

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true    # sign every commit automatically
git config --global tag.gpgsign true       # sign tags too (needed for releases)
```

### 3. Let git verify signatures locally

Without this step, `git log --show-signature` reports "No signature" even when the commit is signed:

```bash
echo "$(git config user.email) $(cat ~/.ssh/id_ed25519.pub)" >> ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

### 4. Add the key to GitHub as a signing key

This is separate from the SSH key you use to push, even if it's the same key file.

With the GitHub CLI:

```bash
gh auth refresh -h github.com -s admin:ssh_signing_key
gh ssh-key add ~/.ssh/id_ed25519.pub --type signing --title "commit signing"
```

Or in the browser: GitHub → **Settings → SSH and GPG keys → New SSH key**, set **Key type** to **Signing Key**, and paste the contents of `~/.ssh/id_ed25519.pub`.

### 5. Make sure your commit email is verified on GitHub

GitHub only shows **Verified** if the commit's email is a verified email on your account:

```bash
git config --global user.email    # this address...
```

…must be listed and verified under GitHub → **Settings → Emails**.

### 6. Commit and check

```bash
git commit -m "Your message"       # signed automatically (commit.gpgsign is on)
git log --show-signature -1        # expect: Good "git" signature for you@example.com
```

### Troubleshooting

| Problem | Cause and fix |
|---|---|
| `error: pathspec '...' did not match any file(s)` | The message is missing `-m`: use `git commit -m "message"`, not `git commit "message"`. |
| `No signature` with `gpg.ssh.allowedSignersFile needs to be configured` | The commit is signed, but git can't verify it locally. Do step 3. |
| GitHub shows **Unverified** | The key isn't added as a *signing* key (step 4), or the commit email isn't verified on your account (step 5). |
| `error: Load key ... : invalid format` | `user.signingkey` must point to the **public** key file (`.pub`). |
| Need to fix an unsigned last commit | `git commit --amend --no-edit -S`, then push. Use `--force-with-lease` only if it was already pushed to your own branch. |

## Reporting security problems

Never in public. See [SECURITY.md](SECURITY.md).
