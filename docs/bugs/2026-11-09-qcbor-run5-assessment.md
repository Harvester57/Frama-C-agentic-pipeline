# QCBOR run-5: assessment of the 30 verdicts

**Answers:** [`2026-11-09-qcbor-run5-findings-review.md`](2026-11-09-qcbor-run5-findings-review.md) (the dossier), §7.
**Date:** 2026-11-09.
**Upstream reports and patches:** [`../upstream/qcbor/`](../upstream/qcbor/README.md).
**Do not publish yet:** this file describes two bugs that are being reported privately. See
[the disclosure plan](../upstream/qcbor/README.md#disclosure-plan).

## Method

Every verdict was re-judged from the source and from a reproduction, not from the record's
wording.

- **Code checked against.** Upstream `dev` at 9bd0845. The run's `workspace/work/src` and `inc` are
  byte-identical to it, so the dirty target worktree (dossier §6.6) did not affect the analyzed
  code. Upstream has not moved since: `dev` is still 9bd0845 and `master` 1d06057 as of
  2026-11-09.
- **Releases checked.** v2.0-alpha-6 and 1.x (`master` 1d06057, v1.6.1), to see which releases
  each bug is in.
- **Reproductions.** Each bug got a standalone reproducer. They ran under ASan, UBSan, MSan with
  origin tracking, and with no sanitizer (clang 19.1.7, analysis container). MSan answers the
  questions that E-ACSL could not.
- **Fixes.** Each bug got a fix with a regression test. Every test was checked to fail on the
  sources before its fix, and QCBOR's suite passes with all fixes: 89/89 on `dev` and 76/76 on
  1.x, in plain, ASan+UBSan and MSan builds.

## 1. Bottom line

- **Nine distinct upstream bugs.** Two should be reported privately: GetArray/GetMap (High, `dev`
  only) and the all-zero big-number over-read (Medium).
- **What the run got right.** It found 4 of the 9 (C1–C4), and it rightly rejected 13 toolchain
  artifacts, 2 harness-induced records and 2 duplicates.
- **Verdicts changed.** 6 of 30:
  - one confirmed record is not a bug (`GetItemInMap` `uOffset`);
  - one harness-induced rejection is a real public-API bug (`EncodeHead`);
  - the 4 needs-validation records are confirmed.
- **What the run missed.** 4 bugs: the most severe one (GetArray/GetMap), two wrong big-number
  encodings, and `INT64_MIN`, which run-3 had found. One rejection, `ProcessBigNumber`, sits
  directly on top of the `INT64_MIN` bug and hid it.

## 2. The 30 records

Agree = the run's verdict stands. Where the verdict stands but the class, severity or
reachability changes, the change is in the "Corrected" column.

### Confirmed (8)

| # | Record | Verdict | Corrected | Evidence |
| :-- | :--- | :--- | :--- | :--- |
| 1 | `UsefulOutBuf_AppendUsefulBuf::mem_access::a1f5da65a9` | **Agree** | Medium. Reachability: public encode API with application data, not `untrusted_surface`. Same root cause as #2 and #30: count it once (upstream bug 01). | ASan heap-buffer-overflow, 0 bytes after a 1-byte region. Without a sanitizer, `00 00 00 00` followed by `a5` encodes as `c2 41 a5`. QCBOR's tests miss it because their literals' NUL terminator is the byte that gets read. |
| 2 | `QCBOREncode_Private_BigNumberToUInt::mem_access::a1f5da65a9` | **Agree** | As #1, the same finding. | Preferred path: the same input encodes as `18 a5` (165). |
| 3 | `IEEE754_DoubleToSingle::shift::5614f2d044` | **Agree** | Low. Affects 1.x too (`ieee754.c:666`, v1.6.1). One upstream bug with #4 (bug 04). | UBSan: `shift exponent -93` for `AddDouble(0.1)` and for decoding `fb 3f b9 99 99 99 99 99 9a` in PREFERRED mode. |
| 4 | `IEEE754_SingleToHalf::shift::5614f2d044` | **Agree** | As #3 (1.x: `ieee754.c:510`). | UBSan: `shift exponent -1` for `AddFloat(1.1f)` and for decoding `fa 3f 8c cc cd`. |
| 5 | `UsefulOutBuf_Compare::mem_access::b939358da2` | **Agree** | Low. Class: public-API hardening plus a documentation bug. Reachability: public `UsefulBuf` API only. The in-tree caller (map sorting) cannot produce such offsets. `dev` and alpha-6 only, since 534112f. | ASan: read 1 byte before the buffer for `Compare(SIZE_MAX,2,0,2)`. The header promises safety "regardless of the provided offsets". It also says the function "returns zero" for an offset past the end, which is wrong: it returns 1, and the existing tests expect 1. |
| 6 | `QCBORDecode_Private_GetItemInMap::initialization::c132f24cbe` | **Disagree → rejected (not a defect)** | At most a hardening note: initialize `uOffset`. | `QCBORDecode_Private_GetItemChecks()` reads `uOffset` only when the error passed in is `QCBOR_SUCCESS` (`qcbor_main_decode.c:2291-2298`). `GetItemInMap` passes the latched error, so the value is never used. Not UB either: `&uOffset` is taken (`qcbor_spiffy_decode.c:514`), so it is an unspecified value, not a trap. |
| 7 | `QCBORDecode_GetTEpochDate::initialization::745871f887` | **Agree** | Low. Class: indeterminate value written to the caller's output on error. Not UB, since `Item`'s address is taken. It is a regression from 1.x, which assigns only on success. One upstream bug with #8–#12 (bug 06). | MSan: store at `qcbor_tag_decode.c:893`, origin `Item` at `:882`. The caller's pre-set value is overwritten. |
| 8 | `QCBORDecode_GetTEpochDays::initialization::f982f8f015` | **Agree** | As #7. | MSan: store `:966`, origin `Item` `:955`. |

### Needs validation (4)

| # | Record | Verdict | Corrected | Evidence |
| :-- | :--- | :--- | :--- | :--- |
| 9 | `GetTEpochDateInMapN::initialization::745871f887` | **→ confirmed** | Low, bug 06. | MSan: store `:919`, via `memcpy` at `qcbor_spiffy_decode.c:497`, origin `OneItemSearch` at `:566`. |
| 10 | `GetTEpochDateInMapSZ::initialization::745871f887` | **→ confirmed** | Low, bug 06. | MSan: store `:945`, origin `OneItemSearch` `qcbor_spiffy_decode.c:624`. |
| 11 | `GetTEpochDaysInMapN::initialization::f982f8f015` | **→ confirmed** | Low, bug 06. | MSan: store `:992`, origin `OneItemSearch` `:566`. |
| 12 | `GetTEpochDaysInMapSZ::initialization::f982f8f015` | **→ confirmed** | Low, bug 06. | Code identical to #10. The fix's test 1082 exercises it. It was not run separately under MSan (see §6). |

### Rejected: toolchain artifact (13), all agree

In every record, the failing predicate names a field of a **by-value struct formal**. That is the
E-ACSL bug described in dossier §5.1: the formal is registered with
`__e_acsl_store_block` but never marked initialized.
- **It is a real Frama-C bug.** It reproduces in a standalone program, it is a regression of
  Frama-C issue #177, it is reported in
  [`../upstream/frama-c-eacsl-formal-params-initialized.md`](../upstream/frama-c-eacsl-formal-params-initialized.md),
  and it is worked around in the pipeline at 14ff32a.
- **Callers do initialize these arguments, as far as the tests show.** An MSan build of the full
  test suite is clean. MSan would report a partially initialized argument once the callee branches
  on it, as all these functions do on `len` or `uDataType`.

| # | Function | Line | By-value formal in the predicate |
| :-- | :--- | :--- | :--- |
| 13 | `UsefulBuf_Compare` | 116 | `UB2` (`UsefulBufC`) |
| 14 | `UsefulBuf_CopyOffset` | 98 | `Dest` (`UsefulBuf`) |
| 15 | `UsefulBuf_FindBytes` | 155 | `BytesToFind` (`UsefulBufC`) |
| 16 | `UsefulBuf_IsValue` | 136 | `UB` (`UsefulBufC`) |
| 17 | `UsefulBuf_SkipLeading` | 179 | `String` (`UsefulBufC`) |
| 18 | `UsefulOutBuf_AppendUsefulBuf` | 489 | `NewData` (`UsefulBufC`) |
| 19 | `UsefulOutBuf_InsertUsefulBuf` | 302 | `NewData` (`UsefulBufC`) |
| 20 | `QCBORDecode_SetMemPool` | 2764 | `Pool` (`UsefulBuf`) |
| 21 | `QCBORItem_IsMapOrArray` | 97 | `Item` (`const QCBORItem`) |
| 22 | `QCBOREncode_EncodeHead` | 423 | `Buffer` (`UsefulBuf`) |
| 23 | `QCBOREncode_Private_AddBuffer` | 753 | `Bytes` (`UsefulBufC`) |
| 24 | `QCBORDecode_ProcessBigNumber` | 1895 | `Item` (`const QCBORItem`). **Note:** this abort at the function's first statement hid the real signed overflow 70 lines below (bug 09). Case 108 is masked in the E-ACSL build. |
| 25 | `QCBOR_Private_BigNumConformance` | 1457 | `BigNum` (`UsefulBufC`) |

### Rejected: harness-induced (3)

| # | Record | Verdict | Corrected | Evidence |
| :-- | :--- | :--- | :--- | :--- |
| 26 | `QCBOREncode_EncodeHead::index_bound::02209a353f` | **Disagree → confirmed** | Low. Class: public-API hardening, an out-of-bounds read and write. Reachability: public encode API. Also in 1.x (`qcbor_encode.c:468`, v1.6.1). Upstream bug 07. | `EncodeHead` is declared in the public header, and its `uMinLen` was documented without an upper bound. With `uMinLen` 9: UBSan `index 4 out of bounds`; ASan global-buffer-overflow; the loop then writes before the caller's buffer. On 1.x the UBSan build crashed with `pc 0x0` after the stack writes. "Every in-tree caller passes ≤ 8" describes usage, not the contract. Harness repair 1 then narrowed the input and hid it. Repair 2 (`QCBOREncode_Private_AppendCBORHead`) was right: that helper is private. |
| 27 | `DecodeNesting_LevelUpCurrent::mem_access::6a88caa10e` | **Agree** | — | The public exits check `DecodeNesting_IsBoundedType()` before calling `ExitBoundedLevel`: `ExitArray`/`ExitMap` through `QCBORDecode_Private_ExitBoundedMapOrArray`, and `ExitBstrWrapped`. Mismatched or extra exits return `QCBOR_ERR_EXIT_MISMATCH`. Only the private helper, called directly, reaches `NULL - 1`. |
| 28 | `QCBORDecode_Private_ProcessTagItem::mem_access::5b85e2af5a` | **Agree** | — | `pfCB` is always a static callback from QCBOR's own getters. Tag decoders installed with `QCBORDecode_InstallTagDecoders()` are dispatched elsewhere (`qcbor_main_decode.c:2010`, `pTagDecoder->pfContentDecoder`), never as `pfCB` at `qcbor_tag_decode.c:485`. No public path passes NULL here. |

### Rejected: duplicate (2)

| # | Record | Verdict | Evidence |
| :-- | :--- | :--- | :--- |
| 29 | `IEEE754_SingleToHalf::shift::31f1bd25a5` | **Agree** | Same statement and fix as #4: the shift is 32 or more for exponents below −32. |
| 30 | `QCBOREncode_Private_AddTNegativeBigNumber::mem_access::a1f5da65a9` | **Agree** | Same root cause as #1, in a third consumer of the bad `NLZ`. |

## 3. Distinct upstream bugs

| Upstream # | Bug | Run-5 records | Severity | Channel |
| :-- | :--- | :--- | :---: | :--- |
| 08 | `GetArray()`/`GetMap()`: uninitialized `pEncodedCBOR->len` for an empty definite-length array or map | none: missed | High (`dev` only) | Private |
| 01 | Encoding an all-zero big number reads and encodes 1 byte past the buffer | #1, #2, #30 | Medium | Private |
| 02 | `AddTBigNumberRaw()` arguments swapped: positive + `BORROWED` → negative; refused under `ONLY_PREFERRED` | none: missed | Medium | Public |
| 03 | Negative zero big number encodes as −1, −256 or −2^64 | none (the verifier's side note in dossier §3 C1 Q6) | Low | Public |
| 04 | Out-of-range shifts in `IEEE754_SingleToHalf()` / `DoubleToSingle()`, `dev` and 1.x | #3, #4, #29 | Low | Public |
| 05 | `UsefulOutBuf_Compare()` with wrapping offsets, plus documentation | #5 | Low | Public |
| 06 | Epoch date/days getters write an indeterminate value on error | #7–#12 | Low | Public |
| 07 | `QCBOREncode_EncodeHead()` with `uMinLen` > 8, `dev` and 1.x | #26 | Low | Public |
| 09 | `-INT64_MIN` in `QCBORDecode_ProcessBigNumber()` | none in run-5 (run-3's `QCBOR-01`) | Low | Public |

The answers to the dossier's specific questions are in each upstream report. In short:
- **C1.** `ptr` is one past the end for an all-zero input. An all-zero big number is valid input.
  Medium is right. It is one finding, not two, and it is not fixed upstream.
- **C2.** It is UB on all four paths: `nShiftAmount` is a signed `int` and the shifted operand is
  unsigned. No miscompilation was seen. Low is right. `DoubleToSingle` now has a fix, as does 1.x.
- **C3.** The header does promise safety for *any* offset. The class is API hardening, through the
  public `UsefulOutBuf_Compare`.
- **C4.** QCBOR's contract makes the outputs unspecified after an error, so these are not memory
  errors. They are still a regression from 1.x and inconsistent with the other getters, which is
  why they are reported, as Low. `uOffset` is not a bug.

## 4. Hardening notes, not bugs

- **`uOffset` in `QCBORDecode_Private_GetItemInMap()`** (#6). Initializing it would silence tools.
  It has no behavioral effect.
- **`memcpy`/`memcmp` with a NULL pointer and length 0** in `UsefulBuf.h` and `UsefulBuf.c`. Every
  sanitized test run shows these: `UsefulBuf.h:2195` (`:1859` on 1.x), and `UsefulBuf.c:102`, `:122`
  and `:506`. Formally UB in C17 and harmless in practice; C2y makes it defined (N3322). A no-recover
  UBSan build of the test suite stops on them once the shift bug is fixed.
- **`GetArray()`/`GetMap()` defense in depth.** Initialize `End.uEndOffset` to an invalid value and
  fail if it is still unset. This is suggested in report 08, on top of the fix.
- **Private helpers.** `QCBORDecode_Private_ExitBoundedLevel()` (NULL `pCurrentBounded`) and
  `QCBORDecode_Private_ProcessTagItem()` (NULL `pfCB`, unterminated arrays) could assert their
  preconditions. Neither is reachable from the public API (#27, #28).
- **`QCBOREncode_Private_AppendCBORHead()` with `uMinLen` > 8** (harness repair 2). It is private,
  and the bug 07 fix makes it safe anyway, since it goes through `EncodeHead`.

## 5. What the run got wrong, and why

| Error | Records | Cause |
| :--- | :--- | :--- |
| A non-bug confirmed | #6 | **Verifier reasoning.** The verifier treated passing an indeterminate value as a defect without reading how the callee uses it. E-ACSL flags the argument evaluation, not a use. |
| A public-API bug rejected as harness-induced | #26 | **Trust model plus verifier reasoning.** The verifier took the in-tree callers' usage as the contract of a function that the header exports. The harness repair then removed the input that triggered it. The rule "Private helpers have caller-defined contracts" was right for #27 and #28, and wrongly applied here. |
| Four true positives left unvalidated | #9–#12 | **Toolchain.** E-ACSL marks a whole-struct copy as initialized (§5.2). One MSan build confirms all four. |
| Severity and reachability defaults | #1, #2, #5 | **Trust model.** `untrusted_surface` by default for encoder-side bugs. The application chooses the encoder's input, so it can be attacker-influenced but is not attacker input. |
| A real bug hidden by a correct rejection | #24, bug 09 | **Toolchain.** The by-value-formal abort is at `ProcessBigNumber`'s first statement, so E-ACSL never checked the rest of the function, and case 108 is masked in the E-ACSL build. The sanitizer engine did not report the overflow either; why is not established. Run-3 had found it. |
| Missed: GetArray/GetMap (bug 08) | none | **No oracle saw it.** The sanitizer engine has no uninitialized-read detection (no MSan). The harness never uses the returned `pEncodedCBOR`, so ASan never sees the over-read that the garbage length implies. E-ACSL did not mask cases 30 and 134 (`GetArrayOrMap`) but raised nothing there. That is not established either. A plausible reason is the by-value abort in `QCBORItem_IsMapOrArray()` (#21), which every item decoded through `GetNextMapOrArray` hits first. |
| Missed: bugs 02 and 03 | none | **Out of scope for RTE oracles.** These are wrong values, not memory errors. A verifier noticed the symptom of 03 in passing. |
| 1.x not covered | #3, #4, #26 | **Scope.** Run-5 analyzed `dev` only; bugs 04 and 07 are also in the stable releases. |

**Lessons for the pipeline.**
- **Harnesses should consume what they get back.** For example, read every byte of each returned
  `UsefulBufC`, so that a bad length becomes an ASan report.
- **The sanitizer engine needs an MSan variant.** E-ACSL masked 41 dispatch cases in the current
  build (55 during fuzzing). Uninitialized reads in those cases were not searched.
- **Verifiers judging "harness-induced" should check whether the function is in a public
  header,** not only how in-tree callers use it.
- **A record whose failure is at a function's first statement should not be closed** until the
  rest of the function has been checked by another engine.

**Corrections for [`../bugs-found/qcbor/README.md`](../bugs-found/qcbor/README.md).** It is
public on `origin/main`. Nothing was changed here; these are left for when the reports are filed.
- **QCBOR-01** (`INT64_MIN`): severity Medium → Low. No miscompilation, and 1.x is unaffected.
- **QCBOR-02/03** (shifts): reachability `internal_api` → untrusted decode input on `dev`, and the
  encode API on both branches.
- Add the new bugs once the private ones are public.

## 6. Checks not done, and what they could change

- **MSan fuzzing of the harness.** It would cover the E-ACSL-masked cases. Not done; more
  uninitialized-read bugs may exist there.
- **Re-running the E-ACSL engine** with the formal-parameter fix (14ff32a). Not done. It would
  show whether E-ACSL now finds bugs 08 and 09, and what else the artifact was hiding.
- **An exhaustive audit of every caller** of the 13 by-value-formal functions, for partially
  initialized struct arguments. Not done; the evidence is the clean MSan run of the test suite.
  A path the tests do not cover could still pass a partially initialized struct, which would turn
  one of those rejections into a real bug.
- **`GetTEpochDaysInMapSZ` under MSan on its own** (#12). It is covered by code identity and by
  the patched test.
- **Compiler exploitation of the shift and `INT64_MIN` UB.** Only clang 19 at `-O0`/`-O1` was
  tried. GCC, `-O2`/`-O3` and LTO were not. A miscompile there would raise bugs 04 and 09 above
  Low.
- **Other targets.** No 32-bit or big-endian builds. `size_t` wrapping in bug 05 and the garbage
  length in bug 08 behave the same way, but this was not run.
