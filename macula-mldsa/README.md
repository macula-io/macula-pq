# macula-mldsa

ML-DSA (FIPS 204), the post-quantum signature standard, being written
from scratch on `macula-keccak`.

⚠ **In progress. Not released, and nothing uses it.** Today it holds the
three parameter sets, ML-DSA-44, -65 and -87, with their key and
signature sizes checked against FIPS 204's tables, and NIST's ACVP
vectors. There is no key generation, signing or verification yet.

ML-DSA is not special here. FIPS 204 has several good implementations,
OTP's `crypto` and `aws-lc-rs` among them. This one exists so the
workspace owns its maths end to end on one Keccak, and it will be
verified byte-exact against NIST's vectors before it is called done.

**Pure ML-DSA only.** HashML-DSA (FIPS 204 section 5.4) signs a
pre-computed hash and would bring SHA-2, which this workspace does not
own. When the tests run NIST's vectors, the HashML-DSA ones are
excluded by count, beside that reason.

**Depend on [`macula-pq`](https://crates.io/crates/macula-pq), not on
this crate.**

## License

Apache-2.0. See [LICENSE](LICENSE).
