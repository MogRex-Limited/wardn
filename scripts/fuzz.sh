#!/usr/bin/env bash
# Runs every fuzz target in the library for FUZZTIME each (default 60s).
# Usage: scripts/fuzz.sh [fuzztime]   e.g. scripts/fuzz.sh 5m
# A failure leaves the crashing input in testdata/fuzz/<Target>/, where it
# becomes a permanent regression test once committed.
set -euo pipefail
cd "$(dirname "$0")/.."
fuzztime="${1:-${FUZZTIME:-60s}}"
status=0
for pkg in $(go list ./...); do
	for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
		echo "== $pkg $target ($fuzztime)"
		if ! go test -run '^$' -fuzz "^${target}\$" -fuzztime "$fuzztime" "$pkg" 2>&1 | tail -n 3; then
			status=1
		fi
	done
done
exit "$status"
