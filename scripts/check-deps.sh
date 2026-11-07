#!/usr/bin/env bash
# Fails if a module requires a direct dependency that is not on its
# allowlist. Part of wardn's supply-chain policy.
#
# Usage: scripts/check-deps.sh [module-dir] [allowlist]
#   defaults: the root module and .github/allowed-dependencies.txt
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
module="${1:-$root}"
allowlist="${2:-$root/.github/allowed-dependencies.txt}"

if [ ! -f "$allowlist" ]; then
	echo "allowlist not found: $allowlist" >&2
	exit 1
fi
allowlist="$(cd "$(dirname "$allowlist")" && pwd)/$(basename "$allowlist")"

cd "$module"
allowed="$(grep -v '^[[:space:]]*#' "$allowlist" | awk 'NF { print $1 }' || true)"
direct="$(go list -m -f '{{if and (not .Main) (not .Indirect)}}{{.Path}}{{end}}' all)"

status=0
while IFS= read -r mod; do
	[ -z "$mod" ] && continue
	if ! grep -qxF -- "$mod" <<<"$allowed"; then
		echo "dependency not allowlisted in $(basename "$allowlist"): $mod" >&2
		echo "  add it with a justification, and get maintainer approval" >&2
		status=1
	fi
done <<<"$direct"

if [ "$status" -eq 0 ]; then
	echo "dependencies OK ($(basename "$allowlist"))"
fi
exit "$status"
