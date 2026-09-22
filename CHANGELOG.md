# Changelog

All notable changes to the crates of this workspace, `macula-pqc`,
`macula-pqc-kx`, `macula-mlkem`, `macula-mldsa` and `macula-keccak`, are
documented here. The 0.1.0 entry below uses the names it shipped under.
They share one version and are released together from one `vX.Y.Z` tag,
so there is one section per release. A crate still being built is
withheld from a release, and its section says so. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Pre-1.0: a minor
version may include a breaking change where that was the right call.

## [0.2.0] - 2026-09-22

`macula-pqc`'s TLS signatures are post-quantum: ML-DSA-87 alone, on
`macula-mldsa`. Breaking for anyone presenting or accepting a classical
certificate through `macula-pqc`, hence 0.2. The other crates are
unchanged and move to 0.2.0 with it, as one version for the workspace.

### `macula-pqc`: ML-DSA-87 signatures

- The provider inside `client_builder()` and `server_builder()` verifies
  ML-DSA-87 and nothing else, for certificates and for TLS 1.3
  CertificateVerify (code point `0x0906`), through `macula-mldsa`. A
  classical certificate or handshake signature is refused, and no
  signature is verified by `aws-lc-rs` any more.
- Its key loader takes an ML-DSA-87 PKCS#8 key in any of RFC 9881's three
  forms, seed, expanded key or both, and nothing else. A key holding both
  is refused when they disagree. A server built here signs its handshakes
  with ML-DSA-87, hedged from the OS.
- `self_signed_certificate(seed, subject_alt_names)`: a self-signed
  ML-DSA-87 certificate and its PKCS#8 key from a 32-byte seed, the form a
  macula node keeps its TLS key in. `rcgen` builds the X.509 structure;
  the signature is `macula-mldsa`'s.
- `KeyPossessionVerifier`: a rustls server certificate verifier for a
  self-signed ML-DSA-87 certificate, the one a macula client dials a
  station with. It accepts exactly one certificate whose key is ML-DSA-87,
  then the server's TLS 1.3 handshake signature under that key, and
  refuses TLS 1.2. It proves possession of the key, not identity: the
  caller binds the key to one. Tested with no roots against a server
  holding the key, and refusing a chain, an ECDSA certificate and a server
  signing with another ML-DSA-87 key; each of its three checks, disabled
  in turn, fails its test.
- Tests: real TLS 1.3 handshakes between two peers on the builders
  complete with ML-DSA-87 on both sides; a peer with classical signatures,
  in either role, cannot agree with us (the negative control), while two
  such classical peers agree with each other, so the harness can complete
  a handshake with them at all.
- `scripts/otp-interop.sh` now runs the TLS cases with ML-DSA-87 on both
  sides against OTP 28.4.2's `ssl`: both hybrids agree in both roles, our
  client with no roots agrees with OTP's server by `KeyPossessionVerifier`
  alone, OTP verifies our certificate's own signature, and classical key exchange,
  classical signatures and a classical certificate are refused. A context
  byte planted in our handshake signer, our verifier or our certificate
  signer fails exactly the cases that depend on it.

## [0.1.2] - 2026-09-22

The first release of `macula-mldsa`, ML-DSA (FIPS 204), which macula's
plan now uses for every ML-DSA signature in the stack. It is the crate to
depend on for signatures; `macula-pqc` stays the one for TLS key exchange.

### The old names are gone

- `macula-pq` and `macula-pq-kx` 0.1.0 are deleted from crates.io, after
  both consumers, `macula_quic` and `macula-rust`, moved to `macula-pqc`
  0.1 on their default branches.

### `macula-mldsa`, released

- Key generation, signing and verification, FIPS 204 Algorithms 1 to 3,
  at ML-DSA-44, -65 and -87: NIST's keyGen (75), sigGen and sigGen-tr1
  (810) and sigVer (135) vectors pass byte-exact, HashML-DSA excluded by
  count with its reason. Signing is hedged from the OS; a private key is
  used expanded or as its 32-byte seed. Signing is timed, the heap is
  scanned for secrets, and it agrees with OTP's `crypto`.

- `key_gen_seed` generates a key kept as its 32-byte seed, drawn from the
  OS, the form RFC 9964's `AKP` key stores and macula's amended D6 keeps.
- `public_key` derives a private key's public key from either form. An
  expanded key is checked against itself on the way, and refused with
  `InconsistentPrivateKey` when its stored `t0` or `tr` disagree with
  what its `rho`, `s1` and `s2` determine: the load check macula's D6
  asks for.
- `scripts/otp-interop.sh` now also checks macula-mldsa against OTP's
  `crypto` at all three sets: public keys derived from one private key
  match, and each side's signatures verify on the other, with keys
  expanded and as seeds.

- Key generation: `key_gen` draws its seed from the OS, and FIPS 204
  Algorithm 6 (`internal::key_gen`, testing only) passes all 75 of NIST's
  keyGen vectors, byte-exact, at ML-DSA-44, -65 and -87. Every secret
  intermediate is wiped.
- Verification: `verify` (FIPS 204 Algorithm 3) agrees with NIST on all
  135 pure sigVer cases, each counted under NIST's reason label. It
  returns an error for a context over 255 bytes and `false` for a key or
  signature of the wrong length.
- Signing: `sign` (FIPS 204 Algorithm 2) is hedged from the OS and takes
  a `PrivateKey`, expanded or its 32-byte seed. All 810 pure sigGen and
  sigGen-tr1 cases pass byte-exact. Deterministic signing is testing-only.
- Signing timed (`examples/signing_timing.rs`, run by `scripts/timing.sh`) at
  ML-DSA-87 and -65, fixed against random secret polynomials among inputs
  signing in one attempt: no difference detected, both controls behaving.
  The harness found one difference first: `HintBitPack` branched on each
  hint bit, flagged at |t| 9.73 and 15.15; it is now branch-free.
- `tests/heap_residue.rs` scans every heap block freed during key
  generation and signing, with both key formats, for that run's secrets,
  and finds none. `tests/os_randomness.rs` and unit tests show `key_gen`
  and `sign` draw from the OS, the drawn bytes becoming the seed and the
  hedge.

### Releasing

- Crates already on crates.io publish by Trusted Publishing, with a
  short-lived token for the release job's OIDC identity, since each is
  trusted-publishing-only. The API token is used only for a crate
  crates.io has never seen, which Trusted Publishing cannot create
  (`scripts/publish-crates.sh`). The first v0.1.2 tag published nothing:
  crates.io refused the API token for `macula-keccak`, as it must.

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
