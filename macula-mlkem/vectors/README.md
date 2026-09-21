# NIST ACVP test vectors for FIPS 203 (ML-KEM)

**These files are verbatim copies. Nothing here has been edited, reformatted
or trimmed**, so the checksums below can be checked against the source.

## Provenance

| | |
|---|---|
| Source | <https://github.com/usnistgov/ACVP-Server>, `gen-val/json-files/` |
| Commit | `975de31eb83d87039ec88934fdc47d8c312b892d` |
| Commit date | 2026-08-12 |
| Retrieved | 2026-09-21 |

**Licence.** The ACVP-Server repository declares no licence and carries no
`LICENSE` file. These are works of the US Government, which are not subject
to copyright protection in the United States under 17 U.S.C. section 105.

## What they cover

Every function at ML-KEM-512, ML-KEM-768 and ML-KEM-1024:

| Set | Function | Cases per parameter set |
|---|---|---:|
| `ML-KEM-keyGen-FIPS203` | key generation from `d` and `z` | 25 |
| `ML-KEM-encapDecap-FIPS203` | encapsulation | 25 |
| | decapsulation | 10, of which 5 are modified ciphertexts |
| | encapsulation key check | 10 |
| | decapsulation key check | 10 |

`tests/acvp.rs` asserts every one of these counts before it runs anything,
so a revised file that covers less fails loudly instead of passing quietly.

## ⚠ Why encapDecap's `internalProjection.json` is here

The `reason` field that marks a decapsulation case as a **modified
ciphertext** exists only in `internalProjection.json`, not in `prompt.json`
or `expectedResults.json`. Without it the implicit-rejection cases still
run, but nothing can say which they are, so an implementation that passed
them for the wrong reason would go unnoticed. The harness asserts all
fifteen by that label.

keyGen's `internalProjection.json` carries no such field and is not read,
so it is not vendored.

## Checksums

Verify with `sha256sum`, or regenerate from the commit above.

| File | Bytes | SHA-256 |
|---|---:|---|
| `ML-KEM-encapDecap-FIPS203/expectedResults.json` | 190,940 | `9089ec6ff2424da9f2782b89b2f831a329a3e28d6e5e24b802b78ff36ac61cdf` |
| `ML-KEM-encapDecap-FIPS203/internalProjection.json` | 1,465,634 | `a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f` |
| `ML-KEM-encapDecap-FIPS203/prompt.json` | 624,189 | `998e22dfb12efb14ce9fdff911ca634b13612819a1806f25da69adba7e16db91` |
| `ML-KEM-keyGen-FIPS203/expectedResults.json` | 544,032 | `a253d0ad91c95ebea5b409673defef0aa49d65d4ed72286399e2e798ddf073a4` |
| `ML-KEM-keyGen-FIPS203/prompt.json` | 16,066 | `3f9ce34f6c836c77958bad2729e837c3b213f44ac36c3065976e7acca6389523` |
