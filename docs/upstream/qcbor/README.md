# QCBOR: upstream bug reports from the run-5 review

These are the reports, reproducers and patches for the QCBOR bugs confirmed while re-assessing
QCBOR run-5. The assessment itself is in
[`../../bugs/2026-11-09-qcbor-run5-assessment.md`](../../bugs/2026-11-09-qcbor-run5-assessment.md).

- **Upstream:** https://github.com/laurencelundblade/QCBOR (maintainer: Laurence Lundblade).
- **Analyzed:** `dev` at `9bd08456d46ac5fbaa7822420fd3e25e0e9c486f`. The run's `src/` and `inc/` are
  identical to it.
- **Also checked:** v2.0-alpha-6 (`2a482af`), 1.x `master` at `1d060574db3d58aac439bc3b8a60167951c7e959`, and v1.6.1.
- **Nothing has been filed yet.**

## Disclosure plan

QCBOR's [`SECURITY.md`](https://github.com/laurencelundblade/QCBOR/blob/dev/SECURITY.md) asks for
vulnerabilities to be emailed to lgl@island-resort.com, with "QCBOR SECURITY" in the subject,
rather than filed as issues. GitHub private vulnerability reporting is also enabled on the
repository. The maintainer verifies each fix privately with the reporter, and makes it public
after the reporter has integrated it, or after 30 days.

| # | Bug | Affected | Severity | Channel | Report | Patch |
| :-- | :--- | :--- | :---: | :--- | :--- | :--- |
| 08 | `GetArray()`/`GetMap()` return an uninitialized length for `[]` / `{}` | `dev` only (since 33cf49e, 2026-11-02) | High | **Private** | [08](08-getarray-empty-container-length.md) | [private/0002](patches/private/0002-Fix-GetArray-GetMap-length-for-empty-definite-length.patch) |
| 01 | Encoding an all-zero big number reads 1 byte past the buffer | `dev`, v2.0-alpha-6 | Medium | **Private** | [01](01-bignum-all-zero-overread.md) | [private/0001](patches/private/0001-Fix-1-byte-over-read-encoding-an-all-zero-big-number.patch) |
| 02 | Positive big number with `ENCODE_AS_BORROWED` encodes as negative | `dev`, v2.0-alpha-6 | Medium | Public issue | [02](02-bignum-positive-borrowed-sign.md) | [public/0001](patches/public/0001-Fix-encoding-of-positive-big-numbers-that-are-not-ty.patch) |
| 03 | Negative zero big number encodes as −1, −256 or −2^64 | `dev`, v2.0-alpha-6 | Low | Public issue | [03](03-bignum-negative-zero.md) | [public/0002](patches/public/0002-Encode-a-negative-zero-big-number-as-zero.patch) |
| 04 | Out-of-range shifts in `IEEE754_SingleToHalf()` / `DoubleToSingle()` | `dev`, v2.0-alpha-6, 1.x incl. v1.6.1 | Low | Public issue | [04](04-ieee754-out-of-range-shift.md) | [public/0003](patches/public/0003-Don-t-shift-by-an-out-of-range-amount-in-float-conve.patch), [v1/0001](patches/v1/0001-Don-t-shift-by-an-out-of-range-amount-in-float-conve.patch) |
| 05 | `UsefulOutBuf_Compare()` reads outside the buffer for wrapping offsets | `dev`, v2.0-alpha-6 | Low | Public issue | [05](05-usefuloutbuf-compare-offsets.md) | [public/0004](patches/public/0004-Make-UsefulOutBuf_Compare-safe-for-any-offset-and-le.patch) |
| 06 | Epoch date/days getters write an indeterminate value on error | `dev`, v2.0-alpha-6 | Low | Public issue | [06](06-epoch-date-output-on-error.md) | [public/0005](patches/public/0005-Don-t-write-an-indeterminate-epoch-date-or-days-on-d.patch) |
| 07 | `QCBOREncode_EncodeHead()` with `uMinLen` > 8 writes before its buffer | `dev`, v2.0-alpha-6, 1.x incl. v1.6.1 | Low | Public issue | [07](07-encodehead-uminlen.md) | [public/0006](patches/public/0006-Reject-uMinLen-8-in-QCBOREncode_EncodeHead.patch), [v1/0002](patches/v1/0002-Reject-uMinLen-8-in-QCBOREncode_EncodeHead.patch) |
| 09 | Signed overflow negating `INT64_MIN` in `ProcessBigNumber()` | `dev`, v2.0-alpha-6 | Low | Public issue | [09](09-processbignumber-int64-min.md) | [public/0007](patches/public/0007-Don-t-negate-INT64_MIN-in-QCBORDecode_ProcessBigNumb.patch) |

**Why 08 and 01 are private.** Both are out-of-bounds reads that data can trigger.
- **08** is triggered by a single byte of untrusted input (`80`) through the decoder, QCBOR's main
  attack surface. It hands the caller a valid pointer with a garbage length, and a caller that
  hashes or copies the result reads far past the input. It is not in any release, but `dev` is
  what v2.0 will ship.
- **01** is in a published pre-release. It copies one byte of adjacent memory into the encoded
  output. The trigger is an all-zero value, which an application may well take from outside, for
  example a zero-padded fixed-width number.

Both are cheap to keep private, and both fixes are small.

**Why the others are public.** Each fails one of the two tests above: either the problem is in
the value, not in memory, or data cannot reach it.
- **02 and 03** produce wrong values, not memory errors, and the attacker does not choose the
  encoder's input.
- **04 and 09** are undefined behavior that compilers have not been seen to exploit. QCBOR's own
  test suite triggers both, and 04 and 09 are already public in this repository (`QCBOR-01..03`
  in [`docs/bugs-found/qcbor/README.md`](../../bugs-found/qcbor/README.md), on `origin/main`).
- **05 and 07** need an out-of-range argument from the application, never data.
- **06** only affects callers that ignore the latched error, which the API tells them not to do.

**Borderline: 07.** It is an out-of-bounds *write* in a stable release (v1.6.1). Only a constant
the application passes triggers it, so public is the normal call for API hardening. If in doubt,
mention 05 and 07 in the private email, say you plan to file them publicly, and let the
maintainer object.

### What not to publish yet

This repository is public (`Harvester57/Frama-C-agentic-pipeline`). Until the private fixes are
public upstream, do not push the following. They describe or reproduce bugs 01 and 08:
- `01-bignum-all-zero-overread.md` and `08-getarray-empty-container-length.md`;
- `patches/private/`;
- `repro/bignum_zero.c`, `repro/getarray_empty.c`, and `repro/run_all.sh`, which runs them;
- `logs/dev-*.log` (all four `dev` logs run the private reproducers);
- `../../bugs/2026-11-09-qcbor-run5-findings-review.md` (the run-5 dossier, which describes the
  over-read) and `../../bugs/2026-11-09-qcbor-run5-assessment.md`.

Everything else in this folder can go public with the public issues.

### Suggested private email

> **To:** lgl@island-resort.com
> **Subject:** QCBOR SECURITY: out-of-bounds reads in GetArray()/GetMap() (dev) and in big-number encoding (dev, v2.0-alpha-6)
>
> Two out-of-bounds read bugs, each with a reproducer, a patch with tests, and sanitizer
> validation. Details for each are attached (the two report files, the two patches, and the two
> reproducers).
>
> 1. `QCBORDecode_GetArray()`/`GetMap()` on an empty definite-length array or map (`80`, `a0`)
>    return `pEncodedCBOR` with a valid pointer and a length taken from uninitialized stack
>    memory. This is on `dev` only, since 33cf49e.
> 2. `QCBOREncode_AddTBigNumber()`/`AddTBigNumberNoPreferred()` read and encode the byte after an
>    all-zero big number. This is on `dev` and v2.0-alpha-6.
>
> I also have seven lower-severity bugs (wrong big-number encodings, undefined behavior in the
> float conversion and INT64_MIN negation, API hardening) that I plan to file as public issues
> with patches, unless you would rather see any of them privately first.

## Applying the patches

| Series | Applies to | Contents |
| :--- | :--- | :--- |
| `patches/public/` (7) | `origin/dev` | Fixes 02, 03, 04, 05, 06, 07, 09 |
| `patches/private/` (2) | `origin/dev` | Fixes 01, 08 |
| `patches/v1/` (2) | `origin/master`, v1.6.1 | Fixes 04 and 07 for 1.x |

```bash
git am patches/public/*.patch
```

The public and private series both apply to `origin/dev` on their own. Applied one on top of the
other, they conflict in one place: both add tests at the end of `BigNumEncodeTests()` in
`test/qcbor_encode_tests.c`. Keep both blocks; their return codes (-3/-4 and -5/-6) don't collide.
With both series applied, the tree is identical to the combined series that was validated.

Each patch fixes one bug and carries its own test, except 04 and 09, which existing tests already
cover. Every new test was checked to fail on the sources before its fix.

## Reproducers

`repro/` has one standalone C file per bug, plus `run_all.sh`. The script builds the library from a
QCBOR checkout under ASan+UBSan, ASan, UBSan, MSan and with no sanitizer, runs every reproducer,
and with `tests` also runs the test suite:

```bash
bash repro/run_all.sh /path/to/QCBOR /tmp/qcbor-build tests
```

The runs here used clang 19.1.7 on Linux x86_64, inside the `framac-analysis` container
(`docker run --security-opt seccomp=unconfined …` for MSan).

## Validation

| Tree | Reproducers | Test suite |
| :--- | :--- | :--- |
| `dev` 9bd0845 | All 9 bugs reproduce ([log](logs/dev-9bd0845.log)) | 89/89 pass; recoverable UBSan reports `ieee754.c:466`, `:625` and `qcbor_number_decode.c:1964`, `:2008` |
| `dev` + public + private | All clean ([log](logs/dev-patched.log)) | 89/89 pass in plain, ASan + recoverable UBSan, and MSan builds; no UBSan reports left from these bugs |
| `dev` + public only | Public bugs clean, 01 and 08 still reproduce ([log](logs/dev-public.log)) | 89/89 pass |
| `dev` + private only | 01 and 08 clean, public bugs still reproduce ([log](logs/dev-private.log)) | 89/89 pass |
| 1.x `master` 1d06057 | 04 and 07 reproduce ([log](logs/v1-master.log)) | 76/76 pass; UBSan reports `ieee754.c:510` and `:666` |
| 1.x + `patches/v1` | Clean ([log](logs/v1-master.log)) | 76/76 pass under ASan + recoverable UBSan |

**UBSan reports left after the patches.** These are on every tree, not caused by these bugs, and
not reported: `memcpy`/`memcmp` passed a NULL pointer with length 0, at `UsefulBuf.h:2195`
(`:2196` once patch 0004 shifts the header by a line, `:1859` on 1.x) and `UsefulBuf.c:102`, `:122` and `:506`. This is formally undefined in C17 and
harmless in practice. C2y makes it defined (N3322).

**One consequence for UBSan users.** A no-recover ASan+UBSan build of the test suite now stops at
the first of these NULL-pointer reports, `UsefulBuf.h:2196`, instead of at `ieee754.c:625`.

## Not reported

- **`uOffset` in `QCBORDecode_Private_GetItemInMap()`** is uninitialized when an error is already
  latched, but it is never read on that path. See the note at the end of
  [06](06-epoch-date-output-on-error.md).
- **The three harness-induced rejections** of run-5 are on `*_Private_*` helpers that no public
  API can drive into the reported state. The exception is `QCBOREncode_EncodeHead()`, which is
  public and is report 07.
- **The 13 "toolchain artifact" rejections** come from an E-ACSL bug, not a QCBOR one. That bug
  is reported to Frama-C in
  [`../frama-c-eacsl-formal-params-initialized.md`](../frama-c-eacsl-formal-params-initialized.md).
