#!/usr/bin/env bash
# Interop between macula-pq's provider() and OTP's own ssl, the one
# independent implementation of SecP384r1MLKEM1024 there is. See
# macula-pq/examples/otp_interop.rs for what each case checks.
#
# Not part of scripts/test.sh: it needs OTP 28.4 or later, which CI does
# not have.
#
#   OTP_BIN   directory holding OTP's erl and escript (default: from PATH)
#
# Exit codes: 0 every case as expected; 1 an interop case failed; 2 the
# negative control failed (a classical-only OTP peer agreed); 3 this OTP
# cannot run the check.
set -euo pipefail
cd "$(dirname "$0")/.."
OTP_BIN="${OTP_BIN:-$(dirname "$(command -v escript)")}"
export OTP_BIN
cargo run --release --quiet -p macula-pq --example otp_interop
