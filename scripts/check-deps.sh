#!/usr/bin/env bash
# Fails if go.mod requires a direct dependency that is not on the allowlist
# in .github/allowed-dependencies.txt. Part of wardn's supply-chain policy.
set -euo pipefail

cd "$(dirname "$0")/.."
allowlist=".github/allowed-dependencies.txt"

allowed="$(grep -v '^[[:space:]]*#' "$allowlist" | awk 'NF { print $1 }' || true)"
direct="$(go list -m -f '{{if and (not .Main) (not .Indirect)}}{{.Path}}{{end}}' all)"

status=0
while IFS= read -r mod; do
	[ -z "$mod" ] && continue
	if ! grep -qxF -- "$mod" <<<"$allowed"; then
		echo "dependency not allowlisted: $mod" >&2
		echo "  add it to $allowlist with a justification, and get maintainer approval" >&2
		status=1
	fi
done <<<"$direct"

if [ "$status" -eq 0 ]; then
	echo "dependencies OK"
fi
exit "$status"
