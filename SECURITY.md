# Security policy

wardn is authorization infrastructure: a vulnerability in wardn is a vulnerability in every product that uses it. We treat every report as urgent.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a security problem.**

Report it privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**.

Please include:

- the affected version or commit,
- a description of the issue and its impact (for example, "an admin of tenant A can read tenant B"),
- steps or code to reproduce it,
- any suggested fix.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | within 2 business days |
| Initial assessment and severity rating | within 5 business days |
| Fix for critical or high severity | within 14 days of confirmation |
| Fix for medium or low severity | in the next scheduled release |

We will keep you informed throughout, credit you in the advisory unless you prefer otherwise, and coordinate the disclosure date with you. Fixes are published as a GitHub Security Advisory and to the Go vulnerability database, so `govulncheck` warns every affected user.

## Supported versions

| Version | Supported |
|---|---|
| `v1.x` | Latest minor, plus security fixes for the previous minor for 6 months |
| `v0.x` | Never released; not supported |

## Scope

In scope: any way wardn can produce a wrong authorization decision, leak information, be made to fail open, or be used to escalate privileges, plus wardn's build, dependencies and release process.

The assumptions wardn makes, and what is out of scope, are listed in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). If you find that one of those assumptions is unsafe in practice, please report that too.
