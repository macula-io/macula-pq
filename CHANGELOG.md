# Changelog

All notable changes to the four crates of this workspace, `macula-pq`,
`macula-pq-kx`, `macula-mlkem` and `macula-keccak`, are documented here.
They share one version and are released together from one `vX.Y.Z` tag,
so there is one section per release. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Pre-1.0: a minor
version may include a breaking change where that was the right call.

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

[0.1.0]: https://github.com/macula-io/macula-pq/releases/tag/v0.1.0
