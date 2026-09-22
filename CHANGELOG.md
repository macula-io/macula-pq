# Changelog

All notable changes to the crates of this workspace, `macula-pqc`,
`macula-pqc-kx`, `macula-mlkem`, `macula-mldsa` and `macula-keccak`, are
documented here. The 0.1.0 entry below uses the names it shipped under.
They share one version and are released together from one `vX.Y.Z` tag,
so there is one section per release. A crate still being built is
withheld from a release, and its section says so. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Pre-1.0: a minor
version may include a breaking change where that was the right call.

## [Unreleased]

### The old names are gone

- `macula-pq` and `macula-pq-kx` 0.1.0 are deleted from crates.io, after
  both consumers, `macula_quic` and `macula-rust`, moved to `macula-pqc`
  0.1 on their default branches.

### `macula-mldsa` (still withheld)

- Key generation: `key_gen` draws its seed from the OS, and FIPS 204
  Algorithm 6 (`internal::key_gen`, testing only) passes all 75 of NIST's
  keyGen vectors, byte-exact, at ML-DSA-44, -65 and -87. Every secret
  intermediate is wiped. No signing or verification yet.

### `macula-keccak`

- `Shake256` absorbs its input in pieces and `finalize_xof` returns a
  `Shake256Reader` that squeezes in pieces, both wiped on drop. ML-DSA
  needs both. Every byte-aligned NIST SHAKE256 vector is run again
  absorbed and squeezed in chunk sizes around the 136-byte rate.
- One absorbing and one squeezing sponge, generic over the rate, now
  serve every function, the one-shot hashes included, so the padding
  rule exists once.

## [0.1.1] - 2026-09-22

The first release under the new names. No API changes.

### Renamed: `macula-pq` is now `macula-pqc`

- The facade `macula-pq` is now `macula-pqc`, and `macula-pq-kx` is now
  `macula-pqc-kx`; the repository is `macula-io/macula-pqc`. PQC is the
  established term (NIST's programme, ETSI, BSI), where "PQ" alone is
  ambiguous. In code: `use macula_pqc::`, not `use macula_pq::`.
- ⚠ Under the new names the first version is 0.1.1, not 0.1.0: 0.1.0 was
  released as `macula-pq` and `macula-pq-kx`, and the workspace shares
  one version with `macula-keccak` and `macula-mlkem`, whose 0.1.0 is
  already on crates.io. No `macula-pqc` 0.1.0 exists.
- `macula-keccak`, `macula-mlkem` and `macula-mldsa` keep their names:
  they are named for their algorithm.

### `macula-mldsa`

- New crate, **withheld from this release** (`publish = false`): ML-DSA
  (FIPS 204) is being built. So far the three parameter sets with their
  key and signature sizes, and NIST's ACVP vectors vendored, excluded from
  the published crate, with a harness asserting their shape.

### Releasing

- A tag no longer refuses to run while a crate is withheld. It releases
  the others, and refuses only when nothing is publishable, when a
  version differs from the tag's, or when `publish = false` and a reason
  in `[package.metadata.withheld]` do not come together. Both release jobs name every
  withheld crate and its reason in the run summary. The gate proves each
  refusal on every commit (`scripts/test-check-release.sh`).
- The gate builds every crate from its package, not only packages it:
  source reading a file `exclude` leaves out would fail every consumer.

## [0.1.0] - 2026-09-22

The first release.

### `macula-pq`

- `client_builder()` and `server_builder()`: rustls configuration builders
  with the crypto provider and TLS 1.3 fixed. They offer
  `SecP384r1MLKEM1024`, then `SecP256r1MLKEM768`, and nothing classical.
  No function returns the provider itself.
- Tested with real TLS 1.3 handshakes, including a negative control: a
  classical-only peer cannot connect, in either role.

### `macula-pq-kx`

- `SecP384r1MLKEM1024` (code point `0x11ED`) and `SecP256r1MLKEM768` as
  rustls key exchange groups, per draft-ietf-tls-ecdhe-mlkem-05: ML-KEM
  from `macula-mlkem`, ECDH from `aws-lc-rs`.
- Verified differentially against rustls's `SECP256R1MLKEM768`,
  `aws-lc-rs`'s ML-KEM-768 and -1024, and OTP 28.4.2's `ssl` (outside the
  gate: `scripts/otp-interop.sh`).

### `macula-mlkem`

- ML-KEM-512, -768 and -1024 (FIPS 203): key generation, encapsulation,
  decapsulation with implicit rejection, and both key checks.
- Seeds drawn from the OS; `Error::RandomnessUnavailable` when it cannot
  supply them. The seeded forms are behind the testing-only `internal`
  feature.
- Every secret wiped when dropped, measured on the heap.
- 240 NIST ACVP cases, byte-exact. Timing measured at ML-KEM-768 and -1024
  with a calibrated harness (`scripts/timing.sh`): no leak detected.

### `macula-keccak`

- SHA3-256, SHA3-512, SHAKE128 and SHAKE256, with an incremental SHAKE128
  reader. Sponge state wiped after use.
- NIST ACVP vectors, including the Monte Carlo chains, and FIPS 202 known
  answers.

[0.1.1]: https://github.com/macula-io/macula-pqc/releases/tag/v0.1.1
[0.1.0]: https://github.com/macula-io/macula-pq/releases/tag/v0.1.0
