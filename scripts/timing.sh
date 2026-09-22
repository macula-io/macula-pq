#!/usr/bin/env bash
# Timing measurement for macula-mlkem and macula-mldsa. RELEASE build only:
# the optimiser's output is the binary that ships, and it can turn
# arithmetic back into a branch, so timing a debug build measures the wrong
# thing.
#
# Not part of scripts/test.sh: it takes minutes, and timing on a shared CI
# runner is too noisy to gate a commit on. Run it on a quiet machine.
#
#   TIMING_N   measurements per test (defaults: 200000 for ML-KEM, 40000
#              for ML-DSA signing, whose every measurement is a signature)
#
# ML-KEM: decapsulation and encapsulation at ML-KEM-768 and -1024.
# ML-DSA: signing at ML-DSA-87 and -65, each input signing in one attempt.
# Every parameter set carries its own controls. The exit code is the worst
# of all of them: 2 a control was NOT detected, so that instrument is
# broken; 3 identical data WAS flagged, so it is biased; 1 a leak detected;
# 0 every control detected and no leak detected.
set -uo pipefail
cd "$(dirname "$0")/.."

# Severity of an exit code: a broken instrument outranks a biased one,
# which outranks a leak, which outranks a clean run.
rank() {
  case "$1" in 2) echo 3 ;; 3) echo 2 ;; 1) echo 1 ;; 0) echo 0 ;; *) echo 4 ;; esac
}

# Package and example, one pair per harness. The examples have distinct
# names: two examples called `timing` in one workspace collide in target/.
worst=0
for harness in macula-mlkem:timing macula-mldsa:signing_timing; do
  cargo run --release --quiet -p "${harness%%:*}" --example "${harness##*:}"
  code=$?
  if [ "$(rank "$code")" -gt "$(rank "$worst")" ]; then
    worst=$code
  fi
done
exit "$worst"
