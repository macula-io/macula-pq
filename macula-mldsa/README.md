# macula-mldsa

ML-DSA (FIPS 204), the post-quantum signature standard, being written
from scratch on `macula-keccak`.

⚠ **In progress. Not released, and nothing uses it.** Today it
generates keys at ML-DSA-44, -65 and -87: `key_gen` draws its seed from
the OS, and FIPS 204's key generation passes all 75 of NIST's ACVP keyGen
vectors byte-exact, with every secret intermediate wiped. The harness
already asserts the shape of the signing and verification vectors: what
will run, what is excluded and why, and every sigVer negative by its
reason. There is no signing or verification yet.

ML-DSA is not special here. FIPS 204 has several good implementations,
OTP's `crypto` and `aws-lc-rs` among them. This one exists so the
workspace owns its maths end to end on one Keccak, and it will be
verified byte-exact against NIST's vectors before it is called done.

**Pure ML-DSA only.** HashML-DSA (FIPS 204 section 5.4) signs a
pre-computed hash and would bring SHA-2, which this workspace does not
own. When the tests run NIST's vectors, the HashML-DSA ones are
excluded by count, beside that reason.

**Depend on [`macula-pqc`](https://crates.io/crates/macula-pqc), not on
this crate.**

## License

Apache-2.0. See [LICENSE](LICENSE).
