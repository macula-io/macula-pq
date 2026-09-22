# macula-pqc-kx

`SecP384r1MLKEM1024` and `SecP256r1MLKEM768` as rustls key exchange
groups, composed per
[draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem-05),
with ML-KEM from `macula-mlkem` and ECDH from `aws-lc-rs`.

**Depend on [`macula-pqc`](https://crates.io/crates/macula-pqc) instead.**
This crate is published because `macula-pqc` needs it on crates.io; it is
not a supported entry point.

Verified differentially, since the draft publishes no test vectors:
against rustls's `SECP256R1MLKEM768` in both directions, against
`aws-lc-rs`'s ML-KEM, and against OTP's `ssl`, the one independent
implementation of `SecP384r1MLKEM1024`. See the
[project README](https://github.com/macula-io/macula-pqc) for how each check works and what it does not
cover.

## License

Apache-2.0. See [LICENSE](LICENSE).
