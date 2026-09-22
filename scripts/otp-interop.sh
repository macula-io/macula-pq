#!/usr/bin/env bash
# Interop with OTP's own implementations, the independent ones the fleet
# already runs:
#
# - macula-pqc's TLS configurations against OTP's ssl, the one independent
#   implementation of SecP384r1MLKEM1024 there is
#   (macula-pqc/examples/otp_interop.rs);
# - macula-mldsa against OTP's crypto: public keys derived from one private
#   key, and each side's signatures verified by the other, with keys
#   expanded and as seeds (macula-mldsa/examples/otp_signature_interop.rs).
#
# Not part of scripts/test.sh: it needs OTP 28.4 or later, which CI does
# not have.
#
#   OTP_BIN   directory holding OTP's erl and escript (default: from PATH)
#
# Exit codes, the worst of both checks: 0 every case as expected; 1 an
# interop case failed; 2 a negative control failed; 3 this OTP cannot run
# the check.
set -uo pipefail
cd "$(dirname "$0")/.."
OTP_BIN="${OTP_BIN:-$(dirname "$(command -v escript)")}"
export OTP_BIN

# Severity of an exit code: an unusable OTP outranks a failed control,
# which outranks a failed case, which outranks a clean run.
rank() {
  case "$1" in 3) echo 3 ;; 2) echo 2 ;; 1) echo 1 ;; 0) echo 0 ;; *) echo 4 ;; esac
}

worst=0
for check in macula-pqc:otp_interop macula-mldsa:otp_signature_interop; do
  cargo run --release --quiet -p "${check%%:*}" --example "${check##*:}"
  code=$?
  if [ "$(rank "$code")" -gt "$(rank "$worst")" ]; then
    worst=$code
  fi
  echo
done
exit "$worst"
