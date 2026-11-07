#!/usr/bin/env bash
# The one definition of the macserve release build.
#
# release.yml builds the published binaries with this script, the CI
# reproducibility jobs rebuild with it on a second host and path, and an
# off-host verifier rebuilds a tag with it to compare against the release
# asset. Run it from a clean git checkout of the commit to build. For a
# release, the tag must be present in that checkout: Go stamps the main
# module version from it, so the same commit without the tag yields
# different bytes.
#
# Usage: checks/release-build.sh OUT_DIR
# Writes OUT_DIR/macserve-darwin-arm64 (./cmd/macserve) and
# OUT_DIR/macserve-controller-darwin-arm64 (./cmd/macserve-controller), and
# prints "<sha256>  <path>" for each, in that order. An off-host verifier
# compares both lines against the release's SHA256SUMS.
set -euo pipefail

out=${1:?usage: checks/release-build.sh OUT_DIR}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$root"

die() {
	echo "release-build: $*" >&2
	exit 1
}

mkdir -p "$out"
out=$(cd "$out" && pwd -P)
case "$out/" in
"$root"/*) die "OUT_DIR must be outside the checkout; an untracked binary marks later builds vcs.modified" ;;
esac

# Release settings. Everything that changes the output bytes is pinned here
# rather than inherited, so a stray GOFLAGS, GOEXPERIMENT or go env file
# cannot alter a release or a rebuild.
export GOENV=off GOFLAGS='' GOEXPERIMENT='' GOTOOLCHAIN=local
export CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 GOARM64=v8.0

want=$(awk '$1 == "toolchain" { t = $2 } $1 == "go" { g = "go" $2 } END { print (t != "" ? t : g) }' go.mod)
have=$(go env GOVERSION)
[[ $have == "$want" ]] || die "go.mod pins $want but the local toolchain is $have"

revision=$(git rev-parse HEAD)

# build PACKAGE BINARY builds one release binary and checks that it carries
# the stamps an off-host rebuild relies on. Go finds the repository only
# through a .git directory, so a git worktree or an exported tree builds
# without vcs stamps even under -buildvcs=true.
build() {
	local pkg=$1 bin=$out/$2 info setting
	rm -f "$bin"
	nice -n 10 go build -p 2 -trimpath -buildvcs=true -o "$bin" "$pkg"
	info=$(go version -m "$bin")
	has() { grep -qxF "$(printf '\tbuild\t%s' "$1")" <<<"$info"; }
	has vcs=git || die "$2 has no git stamps; build from a git clone, not a worktree or exported tree"
	has "vcs.revision=$revision" || die "$2 is not stamped with HEAD $revision"
	has vcs.modified=false || die "checkout has modified or untracked files"
	for setting in -trimpath=true CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 GOARM64=v8.0; do
		has "$setting" || die "$2 lacks build setting $setting"
	done
	grep -E $'^\t(path|mod|build\tvcs)' <<<"$info" >&2
}

build ./cmd/macserve macserve-darwin-arm64
build ./cmd/macserve-controller macserve-controller-darwin-arm64

for bin in "$out/macserve-darwin-arm64" "$out/macserve-controller-darwin-arm64"; do
	if command -v sha256sum >/dev/null; then
		sha256sum "$bin"
	else
		shasum -a 256 "$bin"
	fi
done
