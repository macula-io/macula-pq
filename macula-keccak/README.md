# macula-keccak

Keccak-f[1600], SHA3-256, SHA3-512, SHAKE128 and SHAKE256, with
incremental SHAKE128 squeezing and SHAKE256 absorbing and squeezing: the
hashing ML-KEM and ML-DSA are built on.

**Depend on [`macula-pqc`](https://crates.io/crates/macula-pqc) instead.**
This crate is published because `macula-mlkem` needs it on crates.io; it
is not a supported entry point, and not a general-purpose Keccak.

Verified byte-exact against NIST's ACVP vectors for all four functions,
including the Monte Carlo chains, plus FIPS 202 known answers, and every
SHAKE256 vector again absorbed and squeezed in pieces. The sponge state is
wiped after use. See the [project README](https://github.com/macula-io/macula-pqc).

## License

Apache-2.0. See [LICENSE](LICENSE).
