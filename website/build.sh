#!/usr/bin/env sh
# Builds the documentation site into website/dist/, on hosts whose Node.js is
# older than Astro needs and can't be changed (they ignore .nvmrc and
# package.json "engines"). If the host's Node is new enough it is used;
# otherwise a pinned official Node.js release is downloaded from nodejs.org,
# checked against the SHA-256 below, and used for this build only.
#
# Usage, as the host's build command:  sh website/build.sh
# To update Node: change NODE_VERSION and both checksums, copied from
# https://nodejs.org/dist/vX.Y.Z/SHASUMS256.txt (the linux-*.tar.gz lines).
set -eu

NODE_VERSION="24.22.2"
SHA256_LINUX_X64="361718c444e49af2ca5a110c83ba6a8901143f23ab285ebbef0341f391f482a9"
SHA256_LINUX_ARM64="95c264150aceb7f3437a29fd6984924f5f8d1511ea3cbd6c508b83f6c555dae2"
MIN_NODE="22.23.4" # what Astro requires (package.json "engines")

cd "$(dirname "$0")"

# version_ok VERSION: true if VERSION (x.y.z) is at least MIN_NODE.
version_ok() {
	[ "$(printf '%s\n%s\n' "$MIN_NODE" "$1" | sort -t. -k1,1n -k2,2n -k3,3n | head -n 1)" = "$MIN_NODE" ]
}

current=$(node --version 2>/dev/null | sed 's/^v//' || true)
if [ -n "$current" ] && version_ok "$current"; then
	echo "Using the host's Node.js v$current"
else
	echo "Host Node.js is ${current:+v}${current:-missing}; Astro needs v$MIN_NODE or newer. Fetching Node.js v$NODE_VERSION."
	case "$(uname -m)" in
		x86_64 | amd64) arch=x64 sum=$SHA256_LINUX_X64 ;;
		aarch64 | arm64) arch=arm64 sum=$SHA256_LINUX_ARM64 ;;
		*) echo "Unsupported CPU: $(uname -m). Use the Dockerfile build instead." >&2; exit 1 ;;
	esac
	name="node-v$NODE_VERSION-linux-$arch"
	dir="${TMPDIR:-/tmp}/wardn-$name"
	if [ ! -x "$dir/bin/node" ]; then
		url="https://nodejs.org/dist/v$NODE_VERSION/$name.tar.gz"
		tarball="$dir.tar.gz"
		if command -v curl >/dev/null 2>&1; then
			curl -fsSL "$url" -o "$tarball"
		else
			wget -q "$url" -O "$tarball"
		fi
		if command -v sha256sum >/dev/null 2>&1; then
			echo "$sum  $tarball" | sha256sum -c - >/dev/null
		else
			echo "$sum  $tarball" | shasum -a 256 -c - >/dev/null
		fi || { echo "Checksum mismatch for $name.tar.gz; refusing to use it." >&2; rm -f "$tarball"; exit 1; }
		mkdir -p "$dir"
		tar -xzf "$tarball" -C "$dir" --strip-components=1
		rm -f "$tarball"
	fi
	PATH="$dir/bin:$PATH"
	export PATH
	echo "Using Node.js $(node --version)"
fi

npm ci --no-audit --no-fund
npm run build
