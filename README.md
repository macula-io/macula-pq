# macula-pq

**Post-quantum cryptography that macula owns, rather than depends on.**

This workspace exists so that the post-quantum parts of macula are ours:
implemented here, verified against the standards bodies' own test vectors,
and swappable underneath the protocol code without rewriting it.

| Crate | What it is | State |
|---|---|---|
| `macula-keccak` | Keccak-f[1600], SHA3-256/512, SHAKE128/256 | implemented, NIST ACVP vectors passing |
| `macula-mlkem` | ML-KEM (FIPS 203) | not yet implemented |
| `macula-pq-kx` | Hybrid TLS key exchange groups, including `SecP384r1MLKEM1024` | implemented |
| `macula-pq` | The facade: `provider()` | stubbed |

## Why these boundaries

**rustls and quinn are the envelope.** They are TLS and QUIC protocol
engineering: record layers, handshake state machines, key schedules. There
is no reason to own that, and owning it would add risk without serving the
thesis.

**The post-quantum maths is what we own.** Everything a quantum adversary
threatens, and nothing else. Writing our own AES-GCM would buy nothing and
cost real safety.

Each crate is generic over the layer beneath it, so replacing a component
is a component change rather than a rewrite. `macula-pq-kx` reaches its
ML-KEM through a trait object precisely so `macula-mlkem` can take that
slot when it is ready.

## `SecP384r1MLKEM1024`, and why it had to be written

It is the key exchange group macula's `pq_hybrid` profile declares, and
**no provider supplies it**: not `ring`, not `aws-lc-rs`, not rustls. BSI
TR-02102-2 states it *intends to recommend* the group once the
corresponding RFC is adopted. Until this crate, the profile's declaration
was aspirational.

## How these crates are verified

**Against the standards bodies' own vectors, byte-exact, vendored with
provenance and checksums.** Not against each other, and not by round trip:
two matching wrong implementations agree perfectly.

Where no vectors exist, the claim is stated as what it is.
`macula-pq-kx`'s hybrid composition has none published, so it is verified
*differentially* against rustls's independently written implementation of
the same draft, and its documentation says so rather than implying more.

## ⚠ What is not claimed

**Nothing here is claimed to be constant-time.** `macula-keccak` argues
from the algorithm's shape that there is no secret-dependent branch or
table index to write, and says plainly that this is an argument and not a
measurement. No timing analysis has been performed on any crate here.

A timing harness is a **gate** on the ML-KEM work rather than a follow-up
to it: shipping our own ML-KEM with an unverified timing claim would be
worse than the dependency it replaces, because that one has had the
analysis and ours would merely look finished.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

Vendored NIST test vectors are US Government works; see each `vectors/`
directory's README for provenance, checksums and the licence position.
