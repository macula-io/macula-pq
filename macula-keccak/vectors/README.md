# NIST ACVP test vectors for FIPS 202 (SHA-3 and SHAKE)

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
The absence of a declaration is recorded here rather than glossed, because
it is a fact about the source and not an oversight in this directory.

## ⛔ Why both `-1.0` AND `-FIPS202` are here

⚠ **An earlier version of this file generalised from SHAKE-128 to both
SHAKE functions and was wrong about SHAKE-256.** The corrected per-function
facts, each measured from the vendored files:

| Set | rate | byte-aligned `outLen` | exceeding the rate |
|---|---:|---|---:|
| `SHAKE-128-FIPS202` | 168 B | 32 to 64 B | **0** |
| `SHAKE-128-1.0` | 168 B | up to 512 B | 37 |
| `SHAKE-256-FIPS202` | 136 B | 16 to 512 B | 25 |
| `SHAKE-256-1.0` | 136 B | up to 512 B | 50 |

**`SHAKE-128-FIPS202` cannot test a multi-block squeeze at all.** Every one
of its cases fits inside the first squeezed block of a 168-byte rate. For
SHAKE128, that coverage exists only in `SHAKE-128-1.0`. `SHAKE-256-FIPS202`
does carry multi-block cases, so the original claim held for one function
and not the other.

Multi-block squeezing is where the sponge state has to be carried across
calls: where an XOF goes wrong, and what ML-KEM leans on hardest when it
expands its matrix. The counts in that table are asserted by
`multi_block_coverage_exists_for_both_functions`, including the zero, so
this README cannot drift from the data.

## ⚠ Deliberate exclusion: bit-oriented cases

**Most of the `-1.0` and `-2.0` vectors are bit-oriented**, with message
lengths and SHAKE output lengths that are not multiples of 8. This crate
hashes BYTES, because ML-KEM only ever hashes whole bytes.

Runnable, byte-aligned counts, asserted exactly in the test suite so the
skip stays bounded and visible:

| Set | runnable | of its AFT/VOT total |
|---|---:|---:|
| `SHA3-256-2.0` | 151 | 1194 |
| `SHA3-512-2.0` | 86 | 682 |
| `SHAKE-128-1.0` | 236 | 1904 |
| `SHAKE-256-1.0` | 210 | 1660 |
| `SHAKE-128-FIPS202` | 269 | 269 |
| `SHAKE-256-FIPS202` | 41 | 237 |

**The `-FIPS202` message sets are 100% byte-aligned.** So they are the
byte-oriented sets, and the `-1.0` sets are not simply "more coverage":
they are a different ORIENTATION, of which only the byte-aligned subset is
runnable here.

Bit-oriented support is not planned. If it is ever wanted it is its own
job, and these files already contain the vectors for it.

## ⚠ Deliberate exclusion: LDT

`SHA3-256-2.0` and `SHA3-512-2.0` each contain an **LDT** (large data test)
group of 4 tests. Each has a `fullLength` of 68,719,476,736 bits, which is
**8 GiB per test**, produced by a repeating expansion.

**These are not run.** Four 8 GiB hashes is not a unit test. This is a
scope line, recorded here so a later reader sees a decision rather than an
accidental gap. If large-input coverage is wanted it is its own job.

The files are vendored unmodified, LDT groups included, so nothing is lost
and the exclusion lives in the test harness rather than in the data.

## Checksums

Verify with `sha256sum`, or regenerate from the commit above.

| File | Bytes | SHA-256 |
|---|---:|---|
| `SHA3-256-2.0/expectedResults.json` | 164,189 | `f3d600d1cd031bb339f8d32ff94e19a6ab5f4e82d3f6115e564ebbf521d22e70` |
| `SHA3-256-2.0/prompt.json` | 1,102,048 | `1dd47c747b93dfdef583d62074a2097f207753d94969766a84ce3e917a1e1446` |
| `SHA3-512-2.0/expectedResults.json` | 149,269 | `a6bd247f6d0b45b0c41c11d6284fe8ac833c2bcfc8c9375361ee8493c2b56d82` |
| `SHA3-512-2.0/prompt.json` | 1,025,895 | `670801995987d9f80ec2a124477020242bbfee51d02d799b60fd05fc9147c2df` |
| `SHAKE-128-1.0/expectedResults.json` | 545,119 | `bf62e319f056a9c543fdd09994e4469d6a388c1738a7681fc6ea3f4622d6620e` |
| `SHAKE-128-1.0/prompt.json` | 868,193 | `086819330ec02ce5ab0b39e90c26426b6ed0c95e4108377d8c3e017eeee8402a` |
| `SHAKE-128-FIPS202/expectedResults.json` | 42,855 | `aa71446ad7a6f700b1f47a585d49b49ffbdca476c18a0f9a2dd37dbceeae1e9d` |
| `SHAKE-128-FIPS202/prompt.json` | 840,204 | `afebc2a6b0366ff77d87d6824af64c5ff44a7dc50300af3e0fed417d85eedaa1` |
| `SHAKE-256-1.0/expectedResults.json` | 551,074 | `811f412df1c834a9d0e4eaf537ba2aafc177e0756cb7661081cbee698a682915` |
| `SHAKE-256-1.0/prompt.json` | 881,990 | `77bb830ac3583616af1cb099aecd3ea173ad850b41370811aa2822623e43c218` |
| `SHAKE-256-FIPS202/expectedResults.json` | 94,813 | `7a346ad391c2e945d099eb8ad8fbb3d9d7f9526a3a2d094927c0055df8c0e068` |
| `SHAKE-256-FIPS202/prompt.json` | 868,965 | `b9d6e0e74cbfe485e7f3c0ccec98d21f3e68216678b1486d0ac49e821310d662` |
