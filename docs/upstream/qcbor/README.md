# QCBOR: upstream bug reports from the run-5 and run-6 reviews

These are the reports, reproducers and patches for the QCBOR bugs confirmed while re-assessing
QCBOR run-5 and run-6. The assessments are in
[`../../runs/2026-11-09-qcbor-run5-assessment.md`](../../runs/2026-11-09-qcbor-run5-assessment.md) and
[`../../runs/2026-11-15-qcbor-run6-findings-assessment.md`](../../runs/2026-11-15-qcbor-run6-findings-assessment.md).

- **Upstream:** https://github.com/laurencelundblade/QCBOR (maintainer: Laurence Lundblade).
- **Analyzed:** `dev` at `9bd08456d46ac5fbaa7822420fd3e25e0e9c486f`. The run's `src/` and `inc/` are
  identical to it.
- **Patches and filing texts target:** `dev` at `19c3367c0bf7db3ffcc8bc5626d7740dc5b8a76e` and
  1.x `master` at `1d060574db3d58aac439bc3b8a60167951c7e959`. Both were still the upstream heads on 2026-11-15.
- **Also checked:** v2.0-alpha-6 (`2a482af`), v1.6.1 and v1.5.3.

## Status (2026-11-15)

- **04 and 09 were reported privately** by email to the maintainer on 2026-11-04, with patches.
- **04 is public.** A third party filed it as laurencelundblade/QCBOR#434, and the maintainer's fix is
  laurencelundblade/QCBOR#438 (`dev` only). #438 was checked against
  [`repro/float_shift.c`](./repro/float_shift.c) on `19c3367`: all four modes are clean under UBSan,
  the UBSan test-suite run no longer reports `ieee754.c`, and `make warn` is clean with gcc and
  clang. 1.x `master` still has both shifts.
- **09 is still open on `19c3367`.** Do not file it publicly: it belongs to the private report.
  Follow up by email with the rebased patch ([`private-followup-email.md`](./private-followup-email.md)).
- **01 and 08 are not reported yet.**
- **02, 03, 05, 06, 07 and 10 were filed publicly on 2026-11-15.** Each PR comes from a one-commit
  branch on the fork [`Harvester57/QCBOR`](https://github.com/Harvester57/QCBOR), with the GitHub
  noreply address as author:

  | # | Issue | PR (`dev`) | PR (`master`, 1.x) |
  | :-- | :--- | :--- | :--- |
  | 02 | [#439](https://github.com/laurencelundblade/QCBOR/issues/439) | [#445](https://github.com/laurencelundblade/QCBOR/pull/445) | - |
  | 03 | [#440](https://github.com/laurencelundblade/QCBOR/issues/440) | [#446](https://github.com/laurencelundblade/QCBOR/pull/446) | - |
  | 05 | [#441](https://github.com/laurencelundblade/QCBOR/issues/441) | [#447](https://github.com/laurencelundblade/QCBOR/pull/447) | - |
  | 06 | [#442](https://github.com/laurencelundblade/QCBOR/issues/442) | [#448](https://github.com/laurencelundblade/QCBOR/pull/448) | - |
  | 07 | [#443](https://github.com/laurencelundblade/QCBOR/issues/443) | [#449](https://github.com/laurencelundblade/QCBOR/pull/449) | [#451](https://github.com/laurencelundblade/QCBOR/pull/451) |
  | 10 | [#444](https://github.com/laurencelundblade/QCBOR/issues/444) | [#450](https://github.com/laurencelundblade/QCBOR/pull/450) | [#452](https://github.com/laurencelundblade/QCBOR/pull/452) |

  The private follow-up email has not been sent yet. It now points to these references.

**Exposure in this repository.** `origin` (`Harvester57/Frama-C-agentic-pipeline`) is a public
GitHub repository:
- [`../../bugs-found/qcbor/README.md`](../../bugs-found/qcbor/README.md) has described 04 and 09
  (`QCBOR-01..03`) on `origin/main` since `5da9f46` (2026-11-04).
- This folder, including the 01 and 08 reports, `patches/private/` and their reproducers, has been
  on `origin/main` since `ac30fb8` (2026-11-09).

So 01 and 08 are already publicly readable. Whether to remove them from `main` (the history keeps
them) is the owner's decision. Either way, the maintainer should hear about 01 and 08 from the
private follow-up email. The public issues went out first, on the owner's decision.

## Bugs

| # | Bug | Affected | Severity | Channel | Issue text | PR text | Patch |
| :-- | :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| 08 | `GetArray()`/`GetMap()` return an uninitialized length for `[]` / `{}` | `dev` only (since 33cf49e, 2026-11-02) | High | **Private** | [08](./08-getarray-empty-container-length.md) | - | [private/0002](./patches/private/0002-Fix-GetArray-GetMap-length-for-empty-definite-length.patch) |
| 01 | Encoding an all-zero big number reads 1 byte past the buffer | `dev`, v2.0-alpha-6 | Medium | **Private** | [01](./01-bignum-all-zero-overread.md) | - | [private/0001](./patches/private/0001-Fix-1-byte-over-read-encoding-an-all-zero-big-number.patch) |
| 02 | Positive big number with `ENCODE_AS_BORROWED` encodes as negative | `dev`, v2.0-alpha-6 | Medium | Public: issue #439, PR #445 | [issue](./02-bignum-positive-borrowed-sign-issue.md) | [PR](./02-bignum-positive-borrowed-sign-pr.md) | [public/0001](./patches/public/0001-Fix-encoding-of-positive-big-numbers-that-are-not-ty.patch) |
| 03 | Negative zero big number encodes as −1 or −2^64 | `dev`, v2.0-alpha-6 | Low | Public: issue #440, PR #446 | [issue](./03-bignum-negative-zero-issue.md) | [PR](./03-bignum-negative-zero-pr.md) | [public/0002](./patches/public/0002-Encode-a-negative-zero-big-number-as-zero.patch) |
| 04 | Out-of-range shifts in `IEEE754_SingleToHalf()` / `DoubleToSingle()` | `dev`, v2.0-alpha-6, 1.x incl. v1.6.1 | Low | Reported privately 2026-11-04; public as #434, fix in #438 | [04](./04-ieee754-out-of-range-shift.md) | - | [v1/0001](./patches/v1/0001-Don-t-shift-by-an-out-of-range-amount-in-float-conve.patch) (1.x only) |
| 05 | `UsefulOutBuf_Compare()` reads outside the buffer for wrapping offsets | `dev`, v2.0-alpha-6 | Low | Public: issue #441, PR #447 | [issue](./05-usefuloutbuf-compare-offsets-issue.md) | [PR](./05-usefuloutbuf-compare-offsets-pr.md) | [public/0004](./patches/public/0004-Make-UsefulOutBuf_Compare-safe-for-any-offset-and-le.patch) |
| 06 | Epoch date/days getters write an indeterminate value on error | `dev`, v2.0-alpha-6 | Low | Public: issue #442, PR #448 | [issue](./06-epoch-date-output-on-error-issue.md) | [PR](./06-epoch-date-output-on-error-pr.md) | [public/0005](./patches/public/0005-Don-t-write-an-indeterminate-epoch-date-or-days-on-d.patch) |
| 07 | `QCBOREncode_EncodeHead()` with `uMinLen` > 8 writes before its buffer | `dev`, v2.0-alpha-6, 1.x incl. v1.6.1 | Low | Public: issue #443, PRs #449 (`dev`), #451 (`master`) | [issue](./07-encodehead-uminlen-issue.md) | [PRs](./07-encodehead-uminlen-pr.md) | [public/0006](./patches/public/0006-Reject-uMinLen-8-in-QCBOREncode_EncodeHead.patch), [v1/0002](./patches/v1/0002-Reject-uMinLen-8-in-QCBOREncode_EncodeHead.patch) |
| 09 | Signed overflow negating `INT64_MIN` in `ProcessBigNumber()` | `dev`, v2.0-alpha-6 | Low | Reported privately 2026-11-04; follow up by email | [09](./09-processbignumber-int64-min.md) | - | [public/0007](./patches/public/0007-Don-t-negate-INT64_MIN-in-QCBORDecode_ProcessBigNumb.patch) |
| 10 | `VGetNextConsume()` on a truncated array or map leaves an uninitialized `uNextNestLevel` | `dev` (not v2.0-alpha-6), 1.x `master`, v1.6.1, v1.5.3 | Low | Public: issue #444, PRs #450 (`dev`), #452 (`master`) | [issue](./10-consumeitem-nest-level-issue.md) | [PRs](./10-consumeitem-nest-level-pr.md) | [public/0008](./patches/public/0008-Don-t-set-uNextNestLevel-when-consuming-an-array-or-.patch), [v1/0003](./patches/v1/0003-Don-t-set-uNextNestLevel-when-consuming-an-array-or-.patch) |

The `NN-*-issue.md` and `NN-*-pr.md` files are paste-ready bodies. Their titles:

| # | Issue title | PR title |
| :-- | :--- | :--- |
| 02 | A positive big number encoded with `QCBOR_ENCODE_AS_BORROWED` comes out negative | Fix encoding of positive big numbers that are not type 0 |
| 03 | A negative big number of value zero encodes as −1 or −2^64 | Encode a negative zero big number as zero |
| 05 | `UsefulOutBuf_Compare()` reads outside the buffer for large offsets or lengths | Make UsefulOutBuf_Compare() safe for any offset and length |
| 06 | `GetTEpochDate()` / `GetTEpochDays()` overwrite the caller's output with an uninitialized value on error | Don't write an indeterminate epoch date or days on decode error |
| 07 | `QCBOREncode_EncodeHead()` with `uMinLen` > 8 writes before the start of its buffer | Reject uMinLen > 8 in QCBOREncode_EncodeHead() (and "(1.x)" for `master`) |
| 10 | `QCBORDecode_VGetNextConsume()` on a truncated array or map leaves `uNextNestLevel` uninitialized | Don't set uNextNestLevel when consuming an array or map stops early (and "(1.x)" for `master`) |

The longer `NN-<slug>.md` drafts (02 to 09) are the original analysis against `9bd0845`, kept as
background. Their line numbers and test counts (89) are from `9bd0845`; the filing texts use `19c3367`
(90 tests).

**Why 08 and 01 are private.** Both are out-of-bounds reads that data can trigger.
- **08** is triggered by a single byte of untrusted input (`80`) through the decoder, QCBOR's main
  attack surface. It hands the caller a valid pointer with a garbage length, and a caller that
  hashes or copies the result reads far past the input. It is not in any release, but `dev` is
  what v2.0 will ship.
- **01** is in a published pre-release. It copies one byte of adjacent memory into the encoded
  output. The trigger is an all-zero value, which an application may well take from outside, for
  example a zero-padded fixed-width number.

**Why the others can be public.** Each fails one of the two tests above: either the problem is in
the value, not in memory, or data cannot reach it.
- **02 and 03** produce wrong values, not memory errors, and the attacker does not choose the
  encoder's input.
- **05 and 07** need an out-of-range argument from the application, never data.
- **06 and 10** only affect callers that ignore the latched error, which the API tells them not to
  do. Both leave an uninitialized value in an output, nothing more.
- **04 and 09** are undefined behavior that compilers have not been seen to exploit, but they were
  reported privately, so they follow that channel.

**Borderline: 07.** It is an out-of-bounds *write* in a stable release (v1.6.1). Only a constant
the application passes triggers it, so public is the normal call for API hardening. It was filed
publicly with the others (#443).

**03 and private bug 01.** Both are in `QCBOREncode_Private_AddTBigNumberMain()`. The 03 texts and
reproducer use only the empty big number, which never reaches 01's over-read, and the 03 patch
decides "is zero" from the caller's buffer, not from the result of `SkipLeadingZeros()`. So the 03 fix
is right whether or not 01 is fixed. The test-table rows for `"\x00"` still pass because a string
literal has a zero byte after it.

## Filing

1. Done 2026-11-15: each public issue (02, 03, 05, 06, 07, 10) was filed, then its PR was opened
   from a branch with that one patch, with `#<issue>` (and `#<dev PR>` for the `master` PRs)
   replaced in the PR text. The `NN-*-pr.md` files keep the placeholders. Each `dev` PR applies on
   its own to `dev` `19c3367`. The Claude Code attribution line was appended to each PR body. It is
   left out of these files because `docs/` allows no emojis.
2. To do: send [`private-followup-email.md`](./private-followup-email.md) (09 follow-up, 04
   status, 01 and 08, and the references of the public filings). Check its **[check]** point first.

## Applying the patches

| Series | Applies to | Contents |
| :--- | :--- | :--- |
| `patches/public/` (7) | `dev` `19c3367`, each patch on its own | One patch per PR: 0001 = 02, 0002 = 03, 0004 = 05, 0005 = 06, 0006 = 07, 0007 = 09, 0008 = 10 |
| `patches/private/` (2) | `dev` `19c3367`, each patch on its own | Fixes 01 and 08. Rebased 2026-11-15; both applied cleanly. |
| `patches/v1/` (3) | `master` `1d06057`, each patch on its own | 0001 = 04, 0002 = 07, 0003 = 10 for 1.x |

To open one PR, apply its single patch on a branch cut from `dev`:

```bash
git switch -c fix-bignum-borrowed origin/dev
git am /path/to/patches/public/0001-Fix-encoding-of-positive-big-numbers-that-are-not-ty.patch
```

Merged with the public series, `private/0001` conflicts with `public/0001` in one place: both add
tests at the end of `BigNumEncodeTests()` in `test/qcbor_encode_tests.c`. Keep both blocks. Their
return codes (-5/-6 and -3/-4) don't collide.

The old `public/0003` (04 on `dev`) was dropped, because #438 replaces it. The patch numbers keep
their old values so that links from the background drafts still resolve. All seven `dev` patches
also merge together without conflict.

Each patch fixes one bug and carries its own test, except 0007 (09), which the existing tests
already cover under UBSan. Every new test was checked to fail on the sources before its fix.

## Reproducers

- [`repro/min/`](./repro/min/) has one minimal, self-checking program per public bug (02, 03,
  05, 06, 07, 09, 10). Each prints `BUG: ...` and exits 1 on unfixed code, and prints `OK` with the
  fix. The 09 program shows the bug only under UBSan, and 06 and 10 read a stack value, so
  MSan is the reliable check for those two. These are the programs pasted in the issue texts. Build each from a
  QCBOR checkout with `cc -Iinc -Isrc <file> src/*.c -lm`.
- `repro/` has the original analysis reproducers, plus `run_all.sh`. The script builds the library from a
  QCBOR checkout under ASan+UBSan, ASan, UBSan, MSan and with no sanitizer, runs every reproducer,
  and with `tests` also runs the test suite:

  ```bash
  bash repro/run_all.sh /path/to/QCBOR /tmp/qcbor-build tests
  ```

- The run-6 assessment added three MSan reproducers, which `run_all.sh` does not run yet:
  [`repro/consume_item.c`](./repro/consume_item.c) (bug 10, with [`repro/consume_indef.c`](./repro/consume_indef.c) for the loop
  condition), [`repro/epoch_days_sz.c`](./repro/epoch_days_sz.c) (the sixth getter of 06), and
  [`repro/getiteminmap.c`](./repro/getiteminmap.c) (the `uOffset` case under "Not reported").

The runs used gcc and clang 19.1.7 on Linux x86_64, inside the `framac-analysis` container
(`docker run --security-opt seccomp=unconfined …` for MSan).

## Validation on `dev` `19c3367` and `master` `1d06057` (2026-11-15)

For each `dev` patch on its own, and for all seven merged together:

| Check | Result |
| :--- | :--- |
| `make warn` with gcc and clang, 12 CI configurations, then `qcbortest` | 24 jobs per tree. Every job builds and passes 90/90, with no warning except the 10 that `QCBOR_DISABLE_DECODE_CONFORMANCE` already gives on unpatched `dev` |
| New tests on unpatched `src/` | 0001 `BigNumEncodeTests` -5; 0002 `BigNumEncodeTests` 7003000; 0004 `UOBExtraTests` "Comparison with wrapping offset"; 0005 `SpiffyDateDecodeTest` 1081; 0006 segfault (the write before the buffer); 0008 `EnterMapTest` 3002 |
| Minimal reproducers | `BUG` on unpatched `dev`, `OK` with the fix, plain and under the relevant sanitizer |
| Test suite, ASan + recoverable UBSan | 90/90; only the reports listed below |
| Test suite, MSan with `-fno-sanitize-memory-param-retval` | 90/90 and clean, on unpatched `dev`, with 0005, with 0008, and with all seven |

For the private patches on `19c3367`, each alone and both merged with the seven public ones: all 72 CI
jobs build with no new warning and pass 90/90. The new tests fail on unpatched `src/`
(`BigNumEncodeTests` -3; `GetMapAndArrayTest` 110). [`repro/bignum_zero.c`](./repro/bignum_zero.c) goes from `c2 41 a5` / `18 a5`
and an ASan heap-buffer-overflow to `c2 41 00` / `00`, clean. [`repro/getarray_empty.c`](./repro/getarray_empty.c) goes from a garbage
or 0 length and an MSan report in all four modes to `len=1`, clean. The test suite reports nothing new under ASan + UBSan, and
is clean under MSan.

For `master` `1d06057`: with `v1/0002` alone and with `v1/0003` alone, all 10 CI configurations build with
gcc and clang with no warning, 76/76 pass, the new tests fail without the fix (0002: segfault;
0003: `EnterMapTest` 3002), the reproducer prints `OK`, and the ASan + UBSan suite reports
nothing new. With `v1/0003`, the suite is also clean under MSan.

**MSan with eager parameter checks** (the clang 16+ default) stops the test suite at
`qcbor_spiffy_decode.c:517` on every tree, and flags the latched-error case of 06 at
`qcbor_tag_decode.c:886`. Both are an uninitialized `uOffset` passed by value and never read on
that path (see "Not reported"). Lazy MSan (`-fno-sanitize-memory-param-retval`) checks the actual uses.

**UBSan reports left after the patches.** These are on every tree, not caused by these bugs, and
not reported: `memcpy`/`memcmp` passed a NULL pointer with length 0, at `UsefulBuf.h:2195`
(`:2196` once patch 0004 shifts the header by a line, `:1859` on 1.x) and `UsefulBuf.c:102`, `:122` and `:506`. This is formally undefined in C17 and
harmless in practice. C2y makes it defined (N3322). `ieee754.c:466` and `:625` remain until #438 is
merged, and `qcbor_number_decode.c:1964` and `:2008` until 09 is fixed.

The earlier validation against `9bd0845` is in [`logs/`](./logs/): `dev-*.log` and `v1-master.log`. All
nine bugs still reproduce on `19c3367`
([log](./logs/run6-assessment-9bd0845-and-19c3367.log), [probes](./logs/run6-assessment-probes.log)).

## Not reported

- **`uOffset` in `QCBORDecode_Private_GetItemInMap()`** and in the six epoch getters is
  uninitialized when an error is already latched, but it is never read on that path. See the note
  at the end of [06](./06-epoch-date-output-on-error.md).
- **The three harness-induced rejections** of run-5 are on `*_Private_*` helpers that no public
  API can drive into the reported state. The exception is `QCBOREncode_EncodeHead()`, which is
  public and is report 07.
- **The 13 "toolchain artifact" rejections** come from an E-ACSL bug, not a QCBOR one. That bug
  is reported to Frama-C in
  [`../frama-c/frama-c-eacsl-formal-params-initialized.md`](../frama-c/frama-c-eacsl-formal-params-initialized.md).

## What not to publish yet

Until the private fixes are public upstream, do not push the following. They describe or
reproduce bugs 01 and 08. Some of them are already on `origin/main` (see "Exposure" above), so
this list only stops further copies.
- `01-bignum-all-zero-overread.md` and `08-getarray-empty-container-length.md`;
- `patches/private/`;
- `repro/bignum_zero.c`, `repro/getarray_empty.c`, and `repro/run_all.sh`, which runs them;
- `logs/dev-*.log` (all four `dev` logs run the private reproducers);
- `private-followup-email.md`, and this README, which name both private bugs;
- `../../runs/2026-11-09-qcbor-run5-findings-review.md` (the run-5 dossier, which describes the
  over-read) and `../../runs/2026-11-09-qcbor-run5-assessment.md`;
- `../../runs/2026-11-14-qcbor-run6-supervision.md` and
  `../../runs/2026-11-15-qcbor-run6-findings-assessment.md`, which describe both bugs;
- `logs/run6-assessment-9bd0845-and-19c3367.log`, which runs the private reproducers.

Everything else in this folder can go public with the public issues.
