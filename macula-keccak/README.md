# macula-keccak

Keccak-f[1600], SHA3-256, SHA3-512, SHAKE128 and SHAKE256, with an
incremental SHAKE128 reader: the hashing ML-KEM is built on.

**Depend on [`macula-pq`](https://crates.io/crates/macula-pq) instead.**
This crate is published because `macula-mlkem` needs it on crates.io; it
is not a supported entry point, and not a general-purpose Keccak.

Verified byte-exact against NIST's ACVP vectors for all four functions,
including the Monte Carlo chains, plus FIPS 202 known answers. The sponge
state is wiped after use. See the [project README](https://github.com/macula-io/macula-pq).

## License

Apache-2.0. See [LICENSE](LICENSE).
