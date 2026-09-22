# macula-mldsa

ML-DSA (FIPS 204), the post-quantum signature standard, written from
scratch on `macula-keccak`.

**Depend on this crate for ML-DSA signatures.** It brings no TLS. At
ML-DSA-44, -65 and -87:

- **Key generation**: `key_gen` draws its seed from the OS and returns the
  expanded private key; `key_gen_seed` returns the 32-byte seed instead,
  the form RFC 9964 stores. FIPS 204's key generation passes all 75 of
  NIST's keyGen vectors byte-exact, with every secret intermediate wiped.
  `public_key` derives a public key from either form, refusing an expanded
  key whose parts disagree.
- **Verification**: `verify` agrees with NIST on all 135 pure sigVer
  cases, counted by NIST's reason: 27 valid, and 27 each of a modified
  message, commitment, `z` and hint. The refusals no vector reaches are
  tested directly: two hint rules on NIST's own signatures with the fault
  planted, and the norm bound and a third hint rule on signatures this
  crate makes.
- **Signing**: `sign` is hedged, drawing fresh randomness from the OS for
  every signature, and takes the private key expanded or as its 32-byte
  seed. All 810 pure signing cases in NIST's sigGen and sigGen-tr1 vectors
  pass byte-exact: deterministic and hedged, both key formats, every
  interface. Deterministic signing exists only behind the testing-only
  `internal` feature.
- **Secrets**: every secret and every rejected attempt is wiped. The heap
  is scanned after key generation and signing, with both key formats, for
  the seed, `rho'`, `K`, the private key's secret bytes, `rnd` and `rho''`,
  and none survives. The working secrets live in wiped stack arrays, which
  that scan cannot see.
- **Randomness**: `key_gen`, `key_gen_seed` and `sign` draw from the OS.
  Tests show no two keys and no two signatures on one message are the
  same, and that the drawn bytes are the seed and the hedge.
- **Interop with OTP's `crypto`**, the ML-DSA macula's existing node keys
  were made with: public keys derived from one private key match on both
  sides, and each side's signatures verify on the other, with keys
  expanded and as seeds (`scripts/otp-interop.sh`).
- **Timing**: signing is measured at ML-DSA-87 and -65 with a calibrated
  harness, against what FIPS 204 lets it vary with: no difference
  detected between secret keys, among inputs signing in one attempt. That
  is not a proof; see the
  [project README](https://github.com/macula-io/macula-pqc#what-is-not-claimed).

ML-DSA is not special here. FIPS 204 has several good implementations,
OTP's `crypto` and `aws-lc-rs` among them. This one exists so the
workspace owns its maths end to end on one Keccak, verified byte-exact
against NIST's own vectors, and so it takes a context string and a seed,
which OTP's cannot.

**Pure ML-DSA only.** HashML-DSA (FIPS 204 section 5.4) signs a
pre-computed hash and would bring SHA-2, which this workspace does not
own. When the tests run NIST's vectors, the HashML-DSA ones are
excluded by count, beside that reason.

For TLS key exchange, depend on
[`macula-pqc`](https://crates.io/crates/macula-pqc) instead.

## License

Apache-2.0. See [LICENSE](LICENSE).
