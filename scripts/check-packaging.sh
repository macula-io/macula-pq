#!/usr/bin/env bash
# Every crate must be packageable for crates.io, including a new crate
# that still carries `publish = false` before its first release.
#
# Why this exists: the path dependencies between these crates once had no
# version, which cargo refuses to package, and nothing said so. It was
# found by hand, and would otherwise have surfaced at the first release.
#
# ⚠ WHY A COPY. cargo leaves `publish = false` crates out of the local
# registry it packages their dependents against, so `cargo package
# --workspace` cannot pass in a tree where any crate carries the flag, by
# design. This packages a copy with the flag removed: offline, no build,
# under a second. The real tree is never touched, and the release
# workflow's dry run still does the full verification.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tar --exclude=./target --exclude=./.git -cf - . | (cd "$tmp" && tar xf -)
for manifest in "$tmp"/*/Cargo.toml; do
  grep -vx 'publish = false' "$manifest" > "$manifest.stripped"
  mv "$manifest.stripped" "$manifest"
done

CARGO_TARGET_DIR="$tmp/target" cargo package --workspace --no-verify --offline --quiet \
  --manifest-path "$tmp/Cargo.toml"
echo "packaging: every crate packages for crates.io"
