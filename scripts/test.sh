#!/usr/bin/env bash
# Run the whole workspace in BOTH build profiles. Both must be green.
#
# ⛔ NEITHER PROFILE IS REDUNDANT. Removing one hides a whole class of
# defect, and the two classes are disjoint:
#
#   debug    Panics on arithmetic overflow. This is not hypothetical: the
#            first Barrett `reduce` in macula-mlkem overflowed i32,
#            because `V * a` with `a` near q^2 (exactly what a coefficient
#            product is) exceeds i32 by two orders of magnitude. Debug
#            panicked and that is how it was found. IN RELEASE IT WOULD
#            HAVE WRAPPED SILENTLY, and the vectors would have reported a
#            wrong implementation with no indication where.
#
#   release  Is the binary we actually ship, and the only place the
#            optimiser's output exists. A bounds check or a debug_assert
#            the optimiser removes changes the shape of the code whose
#            timing behaviour we claim things about. Testing only in debug
#            means never testing what runs.
#
# So a constant-time claim tested only in debug is untested, and an
# overflow caught only in debug is uncaught in production. Keep both.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== debug ==="
cargo test --workspace
echo
echo "=== release ==="
cargo test --workspace --release
echo
echo "=== clippy ==="
cargo clippy --workspace --all-targets -- -D warnings
echo
echo "=== libraries as a consumer builds them ==="
# ⚠ `--all-targets` above compiles each library with its dev-dependencies'
# features, and macula-mlkem's own tests switch on `internal`. Without
# this step the gate never compiles the library a consumer actually gets,
# the one where the seeded functions are private.
cargo clippy --workspace --lib -- -D warnings
echo
echo "=== packaging ==="
./scripts/check-packaging.sh
echo
echo "=== readme ==="
./scripts/check-readme.sh
echo
echo "=== fmt ==="
cargo fmt --all --check
