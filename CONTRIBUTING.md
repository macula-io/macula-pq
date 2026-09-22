# Contributing to macula-pqc

Thank you for considering a contribution. This is cryptography, so the bar
is evidence: every claim here is backed by a test that has been seen to
fail, and a change is expected to keep it that way.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting a vulnerability

**Do not open a public issue.** Report it privately through GitHub's
[private vulnerability reporting](https://github.com/macula-io/macula-pqc/security/advisories/new)
on the Security tab.

## Getting started

```sh
git clone https://github.com/macula-io/macula-pqc.git
cd macula-pqc
git config core.hooksPath .githooks
./scripts/test.sh
```

The last line is the whole gate: both build profiles, clippy twice, the
docs, packaging, the README checks and formatting. The pre-commit hook
runs the same script and refuses a commit that fails it, and CI runs it
again. If a commit genuinely must bypass the hook, use `--no-verify` and
say why in the commit message.

## How changes are made here

- **Test first, and see it fail.** A test that has never been red may
  assert nothing. For code that already exists, plant the fault the test
  guards against and watch it go red.
- **Verify against the standards bodies, not against ourselves.** NIST's
  vectors are vendored verbatim with their provenance and checksums, never
  edited or trimmed. Where no vectors exist, verify against an independent
  implementation and say so.
- **No `unsafe` in any crate.** Every crate carries
  `#![forbid(unsafe_code)]`.
- **Secrets are wiped.** Anything secret is wrapped in `Zeroizing` where it
  is made, in a buffer allocated at its final size.
  `macula-mlkem/tests/heap_residue.rs` checks the heap.
- **Timing is measured, not asserted.** A change to ML-KEM's arithmetic
  reruns `./scripts/timing.sh`; its positive control must be detected and
  its negative control must not be.
- **Documentation states what was measured, not what the code avoids.**

## Submitting changes

1. Fork, branch, and make the change with its tests.
2. `./scripts/test.sh` passes.
3. Update `CHANGELOG.md` under an `[Unreleased]` section.
4. Open a pull request saying what changed, why, and how it was verified.

## Releases

A `vX.Y.Z` tag publishes every crate to crates.io. The release
workflow checks every crate is publishable at the tag's version, runs the
gate and a dry-run publish, then publishes.

## License

By contributing, you agree that your contributions will be licensed under
the Apache-2.0 License.
