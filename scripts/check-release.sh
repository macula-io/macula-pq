#!/usr/bin/env bash
# The release guard: what a vX.Y.Z tag publishes, what it withholds and
# why, and whether it may run at all. release-core.yml runs this before
# anything is built or uploaded; so can you.
#
#   scripts/check-release.sh vX.Y.Z
#
# Refuses, exit 1, when:
#
# - ⛔ NOTHING IS PUBLISHABLE. `cargo publish --workspace` exits 0 when
#   every crate carries `publish = false`: it warns "nothing to publish"
#   and reports success, so a stray tag would give a green release run
#   that released nothing. This is the one refusal the guard exists for.
# - any crate's version differs from the tag's.
# - a crate is withheld without saying why. `publish = false` must come
#   with `[package.metadata.withheld] reason = "..."`, and the reason
#   with the flag: one without the other is stale.
#
# A withheld crate does NOT refuse the tag. The crates share a version
# and a tag, but a crate still being built, and depended on by nothing
# published, releases nothing half-made by staying behind. `publish =
# false` keeps it off crates.io, and cargo itself refuses to publish a
# crate whose dependency is not on the registry, which the dry run in
# verify exercises before anything is uploaded.
#
# The table of published and withheld crates, with each reason, goes to
# stdout and, in Actions, to the run summary, so "0.1.1 published" never
# reads as "every crate published".
set -euo pipefail
cd "$(dirname "$0")/.."

tag="${1:?usage: scripts/check-release.sh vX.Y.Z}"

cargo metadata --no-deps --format-version 1 --offline | python3 -c '
import json, os, sys

tag = sys.argv[1]
want = tag[1:] if tag.startswith("v") else tag
packages = sorted(json.load(sys.stdin)["packages"], key=lambda p: p["name"])

errors, rows, published = [], [], 0
for p in packages:
    name, version = p["name"], p["version"]
    withheld = p["publish"] == []
    reason = ((p.get("metadata") or {}).get("withheld") or {}).get("reason")
    if version != want:
        errors.append(f"{name} is {version}, the tag says {want}")
    if withheld and not reason:
        errors.append(f"{name} carries publish = false with no [package.metadata.withheld] reason")
    if reason and not withheld:
        errors.append(f"{name} states a withheld reason but is publishable: one of the two is stale")
    if withheld:
        shown = reason or "no reason given"
        rows.append(f"| `{name}` | {version} | **withheld**: {shown} |")
    else:
        published += 1
        rows.append(f"| `{name}` | {version} | published |")

if published == 0:
    errors.append("no crate is publishable: cargo would report success and release nothing")

table = "\n".join([f"### Release {tag}", "", "| Crate | Version | |", "|---|---|---|", *rows, ""])
print(table)
summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    with open(summary, "a") as f:
        f.write(table + "\n")
for e in errors:
    print(f"::error::{e}")
sys.exit(1 if errors else 0)
' "$tag"
