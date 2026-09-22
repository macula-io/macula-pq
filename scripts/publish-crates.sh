#!/usr/bin/env bash
# Publishes this workspace's crates to crates.io, each with the credential
# crates.io accepts for it. Run by release-core.yml's publish job.
#
#   scripts/publish-crates.sh           publish
#   scripts/publish-crates.sh --plan    print what it would do, publish nothing
#
# ⛔ TWO CREDENTIALS, BECAUSE CRATES.IO REQUIRES BOTH.
#
# - A crate already on crates.io publishes with TRUSTPUB_TOKEN, the
#   short-lived token rust-lang/crates-io-auth-action gets by OIDC. Every
#   such crate here is set to trusted-publishing-only, and crates.io
#   refuses anything else: "New versions of this crate can only be
#   published using Trusted Publishing". The v0.1.2 release failed on
#   exactly that, with the API token.
# - A crate crates.io has never seen publishes with FIRST_PUBLISH_TOKEN,
#   the plain API token, because crates.io cannot create a crate through
#   Trusted Publishing: "Trusted Publishing tokens do not support creating
#   new crates. Publish the crate manually, first." After its first
#   release, give it a Trusted Publisher and set it trusted-publishing-only
#   like the others; from then on it takes the first route.
#
# Existing crates go first, in cargo's dependency order, then each new
# one. A new crate that an existing one depends on cannot be ordered that
# way, and is refused before anything is published.
#
# Whether a crate exists is asked of crates.io itself: 200 is published,
# 404 is new, and anything else stops the run, since guessing wrong spends
# a credential crates.io will refuse.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-publish}"
agent="macula-pqc release (github.com/macula-io/macula-pqc)"

# Publishable crates, and for each the workspace crates it depends on.
graph=$(cargo metadata --no-deps --format-version 1 --offline | python3 -c '
import json, sys
packages = json.load(sys.stdin)["packages"]
names = {p["name"] for p in packages if p["publish"] != []}
for p in packages:
    if p["name"] in names:
        deps = sorted({d["name"] for d in p["dependencies"]
                       if d["name"] in names and d["kind"] in (None, "build")})
        print(p["name"], *deps)
')

existing=()
new=()
while read -r name _; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -A "$agent" "https://crates.io/api/v1/crates/$name")
  case "$code" in
    200) existing+=("$name") ;;
    404) new+=("$name") ;;
    *) echo "::error::crates.io answered $code for $name: cannot tell whether it exists"; exit 1 ;;
  esac
done <<< "$graph"

for n in "${new[@]}"; do
  while read -r name deps; do
    for d in $deps; do
      if [ "$d" = "$n" ] && [[ " ${existing[*]} " == *" $name "* ]]; then
        echo "::error::$name is on crates.io and depends on $n, which is not: publish $n alone first"
        exit 1
      fi
    done
  done <<< "$graph"
done

echo "Trusted Publishing, in dependency order: ${existing[*]:-none}"
echo "First publish, with the API token:       ${new[*]:-none}"
[ "$mode" = "--plan" ] && exit 0

excludes=()
for n in "${new[@]}"; do excludes+=(--exclude "$n"); done
if [ "${#existing[@]}" -gt 0 ]; then
  : "${TRUSTPUB_TOKEN:?the OIDC token from crates-io-auth-action}"
  CARGO_REGISTRY_TOKEN="$TRUSTPUB_TOKEN" cargo publish --workspace "${excludes[@]}"
fi
for n in "${new[@]}"; do
  : "${FIRST_PUBLISH_TOKEN:?the API token, for the first publish of a crate}"
  CARGO_REGISTRY_TOKEN="$FIRST_PUBLISH_TOKEN" cargo publish -p "$n"
done
