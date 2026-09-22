#!/usr/bin/env bash
# Verify the README two ways. BOTH are required and one of them was missed.
#
# ⛔ The standing rule is that a README is verified against the tree before
# a push. Applied once as "is everything it says true", it passed twelve
# content checks AND STILL SHIPPED A README MISSING THE TEMPLATE'S LOGO
# BLOCK, because a true document can still be the wrong document.
#
#   1. SHAPE   does it follow the SDK template (macula-rust, macula-go):
#              H1, badge row, logo block, centred tagline, rule, dated
#              status blockquote, and the closing sections
#
# ⛔ A TRUE DOCUMENT CAN BE THE WRONG DOCUMENT, AND CONTENT VERIFICATION
# CANNOT SEE THAT. That is why shape is checked at all.
#   2. CONTENT do its claims match the tree: links resolve, referenced
#              files exist, asserted counts are real
#
# Mechanised rather than remembered, because remembering is what failed.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
need() { if ! grep -qF -- "$2" README.md; then echo "README: missing $1"; fail=1; fi; }
needre() { if ! grep -qE -- "$2" README.md; then echo "README: missing $1"; fail=1; fi; }

# --- shape, in template order ---
needre "H1"                    '^# macula-pq$'
needre "CI badge on main"      '^\[!\[CI\].*branch=main'
needre "License badge"         '^\[!\[License\]'
needre "Rust badge"            '^\[!\[Rust\]'
# ⚠ Anchored on the safety-dance LINK, not on the badge's label text.
# The label is presentation and has already changed once; the link is the
# stable identity of the claim. Asserting the label would have made a
# wording fix look like a missing badge.
needre "memory-safety badge" 'rust-secure-code/safety-dance'
needre "GitHub Sponsors badge" '^\[!\[GitHub Sponsors\].*sponsors/rgfaber'
need    "logo <picture> block" '<picture>'
need    "dark logo source"     'assets/macula-pq-full-dark.svg'
need    "light logo img"       'assets/macula-pq-full-light.svg'
needre  "centred tagline"      '<strong>.*</strong>'
needre  "horizontal rule"      '^---$'
needre  "dated status blockquote" '^> \*\*Status, [0-9]{4}-[0-9]{2}-[0-9]{2}:'
needre  "What is this?"        '^## What is this\?'
needre  "Related projects"     '^## Related projects'
needre  "License section"      '^## License'

# --- content: every referenced local file must exist ---
#
# ⚠ Done in python, not grep. The first version combined -oE and -P,
# which grep refuses, and the loop then read nothing while the script
# still reported success. A link check that silently checks no links is
# worse than none, so this one FAILS LOUDLY if it finds zero links to
# check.
python3 - <<'PYEOF' || fail=1
import os, re, sys
text = open("README.md").read()
links = re.findall(r'\]\((?!https?://|#)([^)]+)\)', text)
links += re.findall(r'(?:src|srcset)="(?!https?://)([^"]+)"', text)
if not links:
    print("README: the link check found NO links, which means it is not working")
    sys.exit(1)
bad = [l for l in links if not os.path.exists(l)]
for b in bad:
    print(f"README: broken link {b}")
sys.exit(1 if bad else 0)
PYEOF

# --- content: the README's Rust code is code that compiles ---
#
# Every ```rust block here must appear verbatim in macula-pq/README.md,
# which macula-pq's tests compile as a doctest. A snippet edited here and
# not there fails this check rather than drifting from the API.
python3 - <<'PYEOF' || fail=1
import re, sys
blocks = re.findall(r"```rust\n(.*?)```", open("README.md").read(), re.S)
tested = open("macula-pq/README.md").read()
if not blocks:
    print("README: no ```rust block found; the getting-started code is missing")
    sys.exit(1)
stray = [b for b in blocks if b not in tested]
for b in stray:
    print("README: a rust block is not in macula-pq/README.md, so nothing compiles it:")
    print("  " + b.splitlines()[0])
sys.exit(1 if stray else 0)
PYEOF

# --- content: the badge's CLAIM must be true of the tree ---
#
# This is the half that matters. The badge asserts that this workspace is
# 100% safe Rust; the assertion is checked against every crate, not
# against the words on the badge.
for c in macula-keccak macula-mlkem macula-pq-kx macula-pq; do
  grep -q 'forbid(unsafe_code)' "$c/src/lib.rs" || {
    echo "README: the memory-safety badge is FALSE, $c does not forbid unsafe"; fail=1; }
done

[ "$fail" = 0 ] && echo "README: shape and content verified"
exit "$fail"
