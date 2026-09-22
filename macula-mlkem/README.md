# macula-mlkem

ML-KEM (FIPS 203) at ML-KEM-512, -768 and -1024, written from scratch on
`macula-keccak`.

**Depend on [`macula-pq`](https://crates.io/crates/macula-pq) instead.**
This crate is published because `macula-pq` needs it on crates.io; it is
not a supported entry point.

- **Verified byte-exact** against NIST's ACVP vectors: 240 cases across key
  generation, encapsulation, decapsulation and both key checks, including
  the fifteen implicit-rejection cases, each identified by NIST's label.
- **Seeds come from the OS.** The seeded forms (FIPS 203 Algorithms 16 and
  17) are behind the testing-only `internal` feature, as FIPS 203 sections
  3.3 and 6 require.
- **Secrets are wiped when dropped**, measured on the heap.
- **Timing is measured, not claimed**: no leak detected at ML-KEM-768 and
  -1024 on one machine, with a calibrated harness. That is not a proof;
  see the [project README](https://github.com/macula-io/macula-pq#what-is-not-claimed).

## License

Apache-2.0. See [LICENSE](LICENSE).
