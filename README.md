# macula-pq

[![CI](https://img.shields.io/github/actions/workflow/status/macula-io/macula-pq/ci.yml?branch=main&label=CI)](https://github.com/macula-io/macula-pq/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-stable-orange?logo=rust)](https://www.rust-lang.org)
[![memory safety](https://img.shields.io/badge/memory%20safety-100%25%20safe%20Rust-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub%20Sponsors-support-ea4aaa.svg?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/rgfaber)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/macula-pq-full-dark.svg">
    <img src="assets/macula-pq-full-light.svg" alt="Macula" width="320">
  </picture>
</p>

<p align="center">
  <strong>Post-quantum cryptography library with hybrid TLS key exchange</strong>
</p>

---

> **Status, 2026-09-22:** early. `macula-pq-kx` is complete and supplies
> **`SecP384r1MLKEM1024`, which no rustls provider offers**: not `ring`,
> not `aws-lc-rs`, not rustls itself. `macula-keccak` is complete and
> passes NIST's own ACVP vectors for SHA3-256/512 and SHAKE128/256,
> including the Monte Carlo chains. **`macula-mlkem` passes every NIST
> ACVP vector for ML-KEM-512, -768 and -1024**, implicit rejection and key
> checks included, draws its seeds from the OS, and has been timed at
> ML-KEM-768 and -1024: no leak detected (see [What is not
> claimed](#what-is-not-claimed) for exactly what that means). It wipes
> its secrets when they are dropped, measured on the heap, and both of
> `macula-pq-kx`'s hybrids run on it.
> **`macula-pq` hands out TLS configuration builders locked to
> `SecP384r1MLKEM1024` then `SecP256r1MLKEM768`, both on our ML-KEM, and
> nothing classical**; nothing uses them yet. Every crate carries `publish =
> false` and nothing has been released. See [Status](#status) for what is
> done and what is not.

## What is this?

**Post-quantum cryptography library with hybrid TLS key exchange.**
ML-KEM (FIPS 203), the Keccak primitives it is built on, and the hybrid
key exchange groups that combine it with elliptic-curve Diffie-Hellman
for rustls.

The genuinely distinctive part is **`SecP384r1MLKEM1024`**, which **no
rustls provider ships**: not `ring`, not `aws-lc-rs`, not rustls itself.

⚠ **The ML-KEM here is not special and this README will not pretend it
is.** FIPS 203 is a NIST standard with several good implementations,
`aws-lc-rs` and RustCrypto's `ml-kem` among them. Ours is written from
scratch and verified byte-exact against NIST's own ACVP vectors, which is
a claim about **independence and assurance**, not about being first or
better.

**Why it exists.** Macula's `pq_hybrid` profile declares
`SecP384r1MLKEM1024`, and no rustls provider implements it. OTP's own
`ssl` does, from OTP 28.4, but **macula's transport is QUIC through a
Rust NIF, and OTP's `ssl` does not do QUIC**: the TLS inside it is
rustls, so the group has to exist as a rustls provider. Building the
primitives here
rather than depending on them also means the post-quantum parts of
[Macula](https://github.com/macula-io/macula) are not supplied by an
external library, which is the reason for the boundary described below.

**Depend on `macula-pq`.** The other three are implementation crates. They
are published only because cargo refuses to publish a crate whose path
dependencies are not themselves on the registry, and they are not
advertised as entry points: nothing in this stack needs SHA-3 outside
ML-KEM, since TLS uses SHA-2.

| Crate | What it is | State |
|---|---|---|
| **`macula-pq`** | **The facade. This is what you depend on.** | `client_builder()` / `server_builder()`: locked to our two hybrids, nothing classical; no consumer uses them yet |
| `macula-keccak` | Keccak-f[1600], SHA3-256/512, SHAKE128/256 | complete, NIST ACVP vectors passing |
| `macula-mlkem` | ML-KEM (FIPS 203) | complete: NIST ACVP vectors passing, seeds from the OS, secrets wiped, timed |
| `macula-pq-kx` | Hybrid TLS key exchange groups, including `SecP384r1MLKEM1024` | complete |

⛔ **It is four crates rather than one with modules because the layering is
load-bearing:**

    macula-keccak   zeroize only
    macula-mlkem    keccak + OS randomness + zeroize    no rustls
    macula-pq-kx    mlkem + rustls + aws-lc-rs
    macula-pq       facade

Collapse that and anyone wanting ML-KEM is forced to take rustls and
`aws-lc-rs` with it. **If `macula-mlkem` ever gains a rustls dependency
that separation is gone**, and it will not be visible from inside the
crate.

### `SecP384r1MLKEM1024`, and why it had to be written

It is the key exchange group macula's `pq_hybrid` profile declares, and
**no rustls provider supplies it**. BSI TR-02102-2 states it *intends to
recommend* the group once the corresponding RFC is adopted. OTP's `ssl`
implements it, but macula's QUIC runs on rustls, so until this workspace
the profile's declaration could not be true on macula's transport.

## Features

- **`SecP384r1MLKEM1024` as a rustls `SupportedKxGroup`**, composed per
  [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem-05),
  code point `0x11ED`.
- **SHA3-256, SHA3-512, SHAKE128 and SHAKE256**, with an incremental
  SHAKE128 reader for multi-block squeezing.
- **Byte-exact verification against the standards bodies' own test
  vectors**, vendored with provenance and per-file checksums.
- **No `unsafe` in any crate**: every crate carries `#![forbid(unsafe_code)]`.
  The one file with `unsafe` in it is a test, `macula-mlkem/tests/heap_residue.rs`,
  because the allocator it needs cannot be written without it.
- **No copied constants.** Lengths are measured from live components and
  the NTT's zeta table is computed at compile time from its definition,
  because one mistyped digit in a transcribed table gives a coherent
  implementation that fails everything with no hint where.

## The boundary, precisely

| | |
|---|---|
| **Ours** | Keccak (**inside ML-KEM only**), ML-KEM, the hybrid composition |
| **The platform** | The OS CSPRNG |
| **`aws-lc-rs`** | AES-GCM, ChaCha20-Poly1305, SHA-2, HKDF, P-256 and P-384 ECDH, ECDSA/RSA/Ed25519 verification |

**The rule is that `aws-lc-rs` supplies no post-quantum primitive.**
Everything left to it is either quantum-safe already or paired with ML-KEM
in a hybrid, so none of it is ours to write. Writing our own AES-GCM would
buy nothing and cost real safety.

⚠ **Keccak does not appear in the `CryptoProvider` at all.** TLS 1.3's key
schedule uses SHA-256 and SHA-384, not SHA-3, so `macula-keccak` is used
**only inside ML-KEM**. "We own the hashing" is false at the TLS layer and
true inside the post-quantum primitive.

**rustls and quinn are the envelope**: TLS and QUIC protocol engineering.
There is no reason to own that.

### Randomness comes from the operating system, deliberately

ML-KEM key generation and encapsulation take randomness from the **OS
CSPRNG**, trusted as part of the platform. Not `aws-lc-rs`, and
**emphatically not ours**.

**A hand-written CSPRNG is the one piece of this where rolling your own
would be unambiguously wrong.** Every other crate here is verifiable
against published vectors; randomness has none, because you cannot test
that output is unpredictable. It is the one place a bug would be invisible
to the method everything else depends on.

## How this is consumed

    macula_quic   ->  macula-pq        (+ rustls, quinn: the envelope)
    macula-rust   ->  macula-pq
    macula-pq     ->  aws-lc-rs        internal, invisible to consumers
                  ->  macula-keccak, macula-mlkem, macula-pq-kx

**`aws-lc-rs` sits behind the facade, not beside it.** A consumer depends
on `macula-pq` and nothing else for crypto: no provider selection, no
`ring` or `aws-lc-rs` feature flags in its manifest.

1. **The `kx_groups` list exists in exactly one place, with its negative
   control beside it.** A second copy could regain a classical group while
   the control guarding the first one kept passing.
2. **Replacing `aws-lc-rs` changes this workspace and no consumer**: the
   facade's default-provider line and the two ECDH halves in
   `macula-pq-kx`.

⚠ **THE DIAGRAM ABOVE IS THE INTENDED SHAPE, NOT THE CURRENT STATE.**
Neither `macula_quic` nor `macula-rust` has been migrated. Both still
select a provider themselves, and `macula-rust` still selects `ring`.
Those are follow-ups in those repositories and neither is done.

## Testing

```sh
./scripts/test.sh
```

Seven gates: `cargo test`, `cargo test --release`, `cargo clippy -D
warnings` twice, `scripts/check-packaging.sh`, `scripts/check-readme.sh`,
`cargo fmt --check`. CI runs this same script rather than restating the
gates, so the two cannot drift.

**Packaging is checked on every commit, not at the first release.**
[`check-packaging.sh`](scripts/check-packaging.sh) packages all four
crates for crates.io, offline and without building, from a copy of the
tree with `publish = false` removed: cargo will not package a crate
against a dependency marked unpublishable, so the check cannot run in the
tree itself while that flag is on.

**Clippy runs twice because tests and consumers build different
libraries.** `macula-mlkem`'s own tests switch on its `internal` feature,
and a build that includes them compiles the library with it. The second
run builds the libraries alone, which is what a consumer gets.

**Both build profiles are required and neither is redundant.** Debug panics
on arithmetic overflow, which is how a real i32 overflow in this
workspace's Barrett reduction was caught; in release it would have wrapped
silently. Release is the binary that ships and the only place the
optimiser's output exists, so **a constant-time claim tested only in debug
is untested**.

### The pre-commit gate

`.githooks/pre-commit` runs the same script and **refuses any commit that
fails**. Enable it after cloning:

```sh
git config core.hooksPath .githooks
```

⚠ If a commit genuinely must bypass it, use `--no-verify` **and say so in
the commit message with the reason**. An undocumented bypass that everyone
uses silently is worse than a documented one used twice.

### Timing

```sh
./scripts/timing.sh
```

**Not part of the gate**: it takes minutes, and a shared CI runner is too
noisy to time on. It times decapsulation and encapsulation at ML-KEM-768
and ML-KEM-1024 in a release build, dudect-style, and each run checks
itself before its results mean anything:

- **Positive control**: a real decapsulation with an early-exit `==`
  planted after it. Not flagged, and the run exits 2.
- **Negative control**: byte-identical ciphertexts reached by two
  different preparation paths. Flagged, and the run exits 3.

The positive control is sized to the leak it stands for. With `decaps`'s
constant-time compare replaced by `==` and a branch, the valid-against-
invalid test flags it; with the real code it does not.
[`examples/timing.rs`](macula-mlkem/examples/timing.rs) documents the
method and the confounds the negative control exposed.

### Interop with OTP

```sh
OTP_BIN=/path/to/otp/bin ./scripts/otp-interop.sh
```

OTP's own `ssl` implements `SecP384r1MLKEM1024` and `SecP256r1MLKEM768`
independently: its hybrid composition is Erlang, its ML-KEM and ECDH come
from its `crypto` library. No Rust implementation of `SecP384r1MLKEM1024`
exists to exchange with, so **this is the only independent check of that
composition**.

It runs real TLS 1.3 handshakes over TCP between `macula-pq` and OTP, in
both roles, with OTP offering one group at a time and a `ping`/`pong`
crossing each connection. A classical-only OTP peer must be refused in
both roles: the negative control. **Not part of the gate**, because it
needs OTP 28.4 or later and CI has none.
[`examples/otp_interop.rs`](macula-pq/examples/otp_interop.rs) documents
it; exit codes are in [`scripts/otp-interop.sh`](scripts/otp-interop.sh).

Result on OTP 28.4.2, whose `crypto` is OpenSSL 3.6.4: both hybrids agree
in both roles, and the classical-only peer is refused in both. With
`SecP384r1MLKEM1024`'s share order reversed in `macula-pq-kx`, both of
its cases fail and the 768 cases still pass.

### How these crates are verified

**Against the standards bodies' own vectors, byte-exact, vendored with
provenance and checksums**: not against each other, and not by round
trip, because two matching wrong implementations agree perfectly.

`macula-keccak` runs NIST's ACVP vectors for SHA3-256, SHA3-512, SHAKE128
and SHAKE256, including the Monte Carlo chains, plus FIPS 202 known
answers. See [`macula-keccak/vectors/README.md`](macula-keccak/vectors/README.md)
for provenance, checksums, and why two vector revisions are used rather
than the one named after the standard.

`macula-mlkem` runs NIST's ACVP vectors for key generation,
encapsulation, decapsulation and both key checks, at all three parameter
sets. The fifteen implicit-rejection cases are each identified by NIST's
own label, so none can pass for the wrong reason unnoticed. See
[`macula-mlkem/vectors/README.md`](macula-mlkem/vectors/README.md) for
provenance and checksums.

**Wiping is measured on the heap.**
[`heap_residue.rs`](macula-mlkem/tests/heap_residue.rs) replaces the
global allocator and scans every block freed during key generation,
encapsulation and both kinds of decapsulation, at all three parameter
sets, for that run's secrets: seeds, PRF outputs, noise polynomials, the
secret key, shared secrets. It finds none, and it does catch the two
mistakes most likely to creep back: a key grown into its buffer instead
of allocated at its final size, and a secret temporary left unwrapped.

Where no vectors exist, the claim is stated as what it is.
`macula-pq-kx`'s hybrid composition has none published, so it is verified
**differentially** against rustls's independently written implementation of
the same draft, and its documentation says so rather than implying more.
That exchange runs `SecP256r1MLKEM768` on our ML-KEM against rustls's on
`aws-lc-rs`'s, so it checks our ML-KEM-768 on the wire as well as the
composition. It passed before the ML-KEM half was moved onto
`macula-mlkem` and after. `SecP384r1MLKEM1024`'s composition has no Rust
counterpart; it is checked against OTP's `ssl`, outside the gate (see
[Interop with OTP](#interop-with-otp)).

## Status

**Done**

- `macula-keccak`: SHA3-256/512, SHAKE128/256, incremental SHAKE128
  reader; ACVP AFT, VOT and MCT vectors, plus FIPS 202 known answers.
- `macula-pq-kx`: `SecP384r1MLKEM1024` and `SecP256r1MLKEM768`, both on
  `macula-mlkem`, verified differentially against rustls's
  `SECP256R1MLKEM768` and against `aws-lc-rs`'s ML-KEM-768 and -1024.
- `macula-mlkem`: key generation, encapsulation, decapsulation with
  implicit rejection, and both key checks, at ML-KEM-512, -768 and -1024.
  Every ACVP vector passes byte-exact. Key generation and encapsulation
  draw their seeds from the OS and return an error if it cannot supply
  them; the seeded forms are behind the testing-only `internal` feature,
  as FIPS 203 sections 3.3 and 6 require. Secrets are wiped when dropped,
  and none survives on the heap.
- The timing harness, with a positive and a negative control.
  ML-KEM-768 and -1024 measured: no leak detected.
- `macula-pq`: `client_builder()` and `server_builder()`, rustls builders
  with the provider and TLS 1.3 already fixed, so no caller can change the
  groups: `SecP384r1MLKEM1024` then `SecP256r1MLKEM768`, from
  `macula-pq-kx`, and nothing classical. No function returns the provider
  itself. Tested with real TLS 1.3 handshakes: two peers on it agree on
  `SecP384r1MLKEM1024`; a peer on `macula_quic`'s current list agrees on
  `SecP256r1MLKEM768`, our ML-KEM against `aws-lc-rs`'s, in both roles;
  and a classical-only peer cannot agree with it in either role.
- Interop with OTP 28.4.2's `ssl`, outside the gate: both hybrids agree in
  both roles; a classical-only peer is refused in both.
- The gate: seven checks, two build profiles, one script, run by the
  pre-commit hook and by CI.

**Not done**

- Migrating `macula_quic` and `macula-rust` onto the facade.
- Nothing is published; every crate carries `publish = false`.
  Releasing is a `vX.Y.Z` tag:
  [`release-core.yml`](.github/workflows/release-core.yml)'s `verify` job
  checks all four are publishable at the tag's version, runs the gate and
  a dry-run publish, then `publish` waits for approval in the `crates-io`
  environment. The crates.io token belongs in that environment's secrets,
  not the repository's, so nothing holding it runs before the approval.

## What is not claimed

**Nothing here is claimed to be constant-time.**

`macula-mlkem` has been **measured**, which is a different thing. On one
AMD Ryzen 9 5950X, rustc 1.98.1, release build, 200,000 measurements per
test, the harness detected no timing difference at ML-KEM-768 or
ML-KEM-1024 in decapsulation (valid against invalid ciphertexts; one fixed
ciphertext against random valid ones) or encapsulation (fixed against
random messages), with both controls behaving at both. **That is "no leak
detected at that n, on that machine, with that compiler"**, not a proof.
ML-KEM-512 has not been timed: nothing negotiates it.

`macula-keccak` is measured only inside ML-KEM, where it hashes secret
data. On its own it rests on an argument from the algorithm's shape: there
is no secret-dependent branch or table index to write, since the round
count is fixed, the rotation offsets are compile-time constants and the
round constants are indexed by round number. **That is an argument, not a
measurement.**

`macula-pq-kx`'s composition has not been timed. Its ML-KEM half is
`macula-mlkem`, timed as above; its ECDH half is `aws-lc-rs`'s.

**Wiping is measured on the heap only.** Values on the stack are wiped by
construction, which safe code cannot observe, and copies the compiler
makes when it moves or spills a value, or leaves in registers, are beyond
any of it, as `zeroize` itself states.

**MSRV is not established.** The gate runs on stable; no minimum has been
determined or tested.

## Related projects

| Project | Description |
|---|---|
| [macula](https://github.com/macula-io/macula) | The reference SDK (Erlang/OTP) whose `pq_hybrid` profile declares `SecP384r1MLKEM1024` |
| [macula-rust](https://github.com/macula-io/macula-rust) | Rust SDK, an intended consumer of this facade |
| [macula-station](https://github.com/macula-io/macula-station) | The station: DHT, SWIM, routing, peering |
| [macula-realm](https://github.com/macula-io/macula-realm) | Managed-realm identity + certificate authority |

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE) or
<http://www.apache.org/licenses/LICENSE-2.0>).

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this workspace by you shall be licensed as
above, without any additional terms or conditions.
