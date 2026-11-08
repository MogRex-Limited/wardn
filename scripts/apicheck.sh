#!/usr/bin/env bash
# apicheck: fail if the public Go API of any published module has a change
# that is incompatible with its latest v1 release (docs/STABILITY.md).
#
# Each module is compared with its own latest release tag: v1.x.y for the
# core, store/mongo/v1.x.y and cache/redis/v1.x.y for the sub-modules.
# Before a module's first v1 release there is nothing to compare, and it
# is skipped. API_BASE=<git ref> compares every module with that ref
# instead (for example API_BASE=main, to preview what a branch breaks).
#
# Usage: scripts/apicheck.sh            (run from the repository root)
set -euo pipefail

APIDIFF_VERSION="v0.0.0-20261011100332-faecfb24eb49" # golang.org/x/exp
APIDIFF="go run golang.org/x/exp/cmd/apidiff@${APIDIFF_VERSION}"

# Published modules. tests/integration and examples are not published.
MODULES=(. store/mongo cache/redis)

root=$(pwd)
work=$(mktemp -d)
trap 'git -C "$root" worktree remove --force "$work/base" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

# public_packages lists a module's importable, non-internal, non-main packages.
public_packages() {
	go list -f '{{if ne .Name "main"}}{{.ImportPath}}{{end}}' ./... | grep -v '/internal\(/\|$\)' || true
}

failed=0
checked_out=""
for m in "${MODULES[@]}"; do
	prefix=""
	[ "$m" != "." ] && prefix="$m/"
	base="${API_BASE:-}"
	if [ -z "$base" ]; then
		base=$(git tag --list "${prefix}v1.*" --sort=-v:refname | head -n 1)
		if [ -z "$base" ]; then
			echo "== $m: no v1 release yet (no ${prefix}v1.* tag); nothing to compare"
			continue
		fi
	fi
	echo "== $m: compared with $base"

	if [ "$checked_out" != "$base" ]; then
		git -C "$root" worktree remove --force "$work/base" >/dev/null 2>&1 || true
		git -C "$root" worktree add --quiet --detach "$work/base" "$base"
		checked_out="$base"
	fi
	if [ ! -f "$work/base/$m/go.mod" ]; then
		echo "   $m did not exist in $base; nothing to compare"
		continue
	fi

	old_pkgs=$(cd "$work/base/$m" && public_packages)
	new_pkgs=$(cd "$root/$m" && public_packages)
	for pkg in $old_pkgs; do
		if ! grep -qxF "$pkg" <<<"$new_pkgs"; then
			echo "   $pkg: package removed"
			failed=1
			continue
		fi
		name=${pkg//\//_}
		(cd "$work/base/$m" && $APIDIFF -w "$work/$name.old" "$pkg")
		(cd "$root/$m" && $APIDIFF -w "$work/$name.new" "$pkg")
		# apidiff exits 0 either way: any output from -incompatible is a break.
		out=$($APIDIFF -incompatible "$work/$name.old" "$work/$name.new")
		if [ -n "$out" ]; then
			echo "   $pkg: incompatible changes"
			sed 's/^/     /' <<<"$out"
			failed=1
		fi
	done
done

# Sub-modules are released in lockstep with the core (docs/MAINTAINING.md):
# the core version they require is what users build against, so it must not
# fall behind the latest core release.
latest_core=$(git tag --list "v1.*" --sort=-v:refname | head -n 1)
if [ -n "$latest_core" ]; then
	for m in store/mongo cache/redis; do
		required=$(cd "$root/$m" && go list -m -f '{{.Version}}' github.com/MogRex-Limited/wardn)
		lowest=$(printf '%s\n%s\n' "$required" "$latest_core" | sort -V | head -n 1)
		if [ "$required" != "$latest_core" ] && [ "$lowest" = "$required" ]; then
			echo "== $m requires wardn $required, older than the latest release $latest_core; set it to the version being released"
			failed=1
		fi
	done
fi

if [ "$failed" -ne 0 ]; then
	cat <<'EOF'

See above. An incompatible API change needs a new major version
(docs/STABILITY.md): make the change compatible instead, adding rather than
changing and deprecating rather than removing. A stale sub-module require is
fixed in the release pull request (docs/MAINTAINING.md, Sub-modules).
EOF
	exit 1
fi
echo "No incompatible API changes."
