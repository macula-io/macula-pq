#!/usr/bin/env bash
# Proves scripts/check-release.sh refuses what it exists to refuse, and
# names what it withholds, on every commit rather than once by hand. A
# guard nobody has seen go red may check nothing.
#
# Each case copies the tree without targets, history or vectors, plants
# one fault in the copy and runs the copy's own guard. The real tree is
# never touched.
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(cargo metadata --no-deps --format-version 1 --offline \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["packages"][0]["version"])')
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

fresh_copy() {
  rm -rf "$tmp/tree" && mkdir "$tmp/tree"
  tar --exclude=./target --exclude=./.git --exclude='./*/vectors' -cf - . | (cd "$tmp/tree" && tar xf -)
}

# plant <what> [crate]: edits manifests in the copy, prints the crate it
# touched.
#   withhold  one crate: publish = false and a reason, both planted
#   all       every crate withheld, each with a reason
#   no-reason one withheld crate loses its reason, keeping the flag
#   no-flag   one withheld crate loses its flag, keeping the reason
plant() {
  python3 - "$tmp/tree" "$@" <<'PY'
import glob, re, sys
root, what = sys.argv[1], sys.argv[2]
FLAG, TABLE = "publish = false\n", "[package.metadata.withheld]\n"
REASON = TABLE + 'reason = "planted by test-check-release.sh"\n'

def withhold(s):
    if FLAG not in s:
        s = s.replace("[package]\n", "[package]\n" + FLAG, 1)
    if TABLE not in s:
        s += "\n" + REASON
    return s

manifests = sorted(glob.glob(f"{root}/*/Cargo.toml"))
crate = lambda m: m.split("/")[-2]
# Read before writing: open(m, "w") truncates the file, and in
# open(m, "w").write(f(open(m).read())) it is opened first.
def rewrite(m, f):
    s = open(m).read()
    with open(m, "w") as out:
        out.write(f(s))

if what == "withhold":
    m = next(m for m in manifests if FLAG not in open(m).read())
    rewrite(m, withhold)
    print(crate(m))
elif what == "all":
    for m in manifests:
        rewrite(m, withhold)
else:
    m = next(m for m in manifests if FLAG in open(m).read())
    s = open(m).read()
    s = re.sub(r'\[package\.metadata\.withheld\]\nreason = "[^"]*"\n', "", s) if what == "no-reason" else s.replace(FLAG, "", 1)
    open(m, "w").write(s)
    print(crate(m))
PY
}

# expect <exit code> <text the output must contain> <case> <tag>
expect() {
  local want_code="$1" want_text="$2" case="$3" tag="$4" out code
  set +e
  out=$(cd "$tmp/tree" && ./scripts/check-release.sh "$tag" 2>&1)
  code=$?
  set -e
  if [ "$code" != "$want_code" ] || ! grep -qF -- "$want_text" <<<"$out"; then
    echo "release guard: FAILED case \"$case\": exit $code (wanted $want_code), output:"
    sed 's/^/    /' <<<"$out"
    fail=1
  else
    echo "release guard: $case"
  fi
}

fresh_copy
expect 0 "| published |" "the tree as it is passes at v$version" "v$version"

fresh_copy
crate=$(plant withhold)
expect 0 "| \`$crate\` | $version | **withheld**: planted by test-check-release.sh |" \
  "a withheld crate is named in the summary, with its reason" "v$version"

fresh_copy
expect 1 "the tag says" "a tag that disagrees with the version is refused" "v0.0.0"

fresh_copy
plant all
expect 1 "no crate is publishable" "every crate withheld is refused: the exit-0 trap" "v$version"

fresh_copy
plant all
crate=$(plant no-reason)
expect 1 "$crate carries publish = false with no [package.metadata.withheld] reason" \
  "a withheld crate with no reason is refused" "v$version"

fresh_copy
plant all
crate=$(plant no-flag)
expect 1 "$crate states a withheld reason but is publishable" \
  "a reason on a publishable crate is refused" "v$version"

exit "$fail"
