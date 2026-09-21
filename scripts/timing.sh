#!/usr/bin/env bash
# Timing measurement for macula-mlkem. RELEASE build only: the optimiser's
# output is the binary that ships, and it can turn arithmetic back into a
# branch, so timing a debug build measures the wrong thing.
#
# Not part of scripts/test.sh: it takes minutes, and timing on a shared CI
# runner is too noisy to gate a commit on. Run it on a quiet machine.
#
#   TIMING_N   measurements per test (default 200000)
#
# Times ML-KEM-768 and ML-KEM-1024, each with its own controls. The exit
# code is the worst of the two: 2 a control was NOT detected, so that
# instrument is broken; 3 identical data WAS flagged, so it is biased; 1 a
# leak detected; 0 both controls detected and no leak detected.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo run --release --quiet -p macula-mlkem --example timing
