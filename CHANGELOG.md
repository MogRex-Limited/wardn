# Changelog

All notable changes to wardn are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and wardn uses
[semantic versioning](https://semver.org/). Security fixes are always called out.

## [Unreleased]

### Added

- Design document, threat model, and security policy.
- Secure development foundation (M1): CI with tests under the race detector,
  security linting, govulncheck, module verification, and a direct
  dependency allowlist; SHA-pinned actions; Dependabot with cooldown;
  contribution rules and maintainer release process.
- Pre-push hook (`make hooks`) that runs every CI gate locally before a push.

### Removed

- CodeQL workflow, until the repository is public or GitHub Advanced
  Security is enabled (see docs/MAINTAINING.md).
