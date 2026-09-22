#!/usr/bin/env bash
# Every crate must package for crates.io AND BUILD FROM THAT PACKAGE,
# including a new crate that still carries `publish = false` before its
# first release.
#
# Why this exists: the path dependencies between these crates once had no
# version, which cargo refuses to package, and nothing said so. It was
# found by hand, and would otherwise have surfaced at the first release.
#
# ⛔ WHY IT BUILDS. A package is not the tree: `macula-mldsa` leaves its
# 28 MB of NIST vectors out with `exclude`. Source that reads an excluded
# file compiles here and fails for every consumer, and only a build of
# the package itself can see that.
#
# ⚠ WHY A COPY. cargo leaves `publish = false` crates out of the local
# registry it packages their dependents against, so `cargo package
# --workspace` cannot pass in a tree where any crate carries the flag, by
# design. This packages a copy with the flag removed, offline. The real
# tree is never touched. The builds keep their own target directory, so
# after the first run they take about a second.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tar --exclude=./target --exclude=./.git -cf - . | (cd "$tmp" && tar xf -)
for manifest in "$tmp"/*/Cargo.toml; do
  grep -vx 'publish = false' "$manifest" > "$manifest.stripped"
  mv "$manifest.stripped" "$manifest"
done

CARGO_TARGET_DIR="$PWD/target/packaging" cargo package --workspace --offline --quiet \
  --manifest-path "$tmp/Cargo.toml"
echo "packaging: every crate packages for crates.io and builds from its package"
