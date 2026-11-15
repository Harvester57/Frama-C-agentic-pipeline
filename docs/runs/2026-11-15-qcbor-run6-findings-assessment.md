# QCBOR `run-6`: Assessment of the Target Findings (2026-11-15)

This assessment re-checks the 28 records in `run-6`'s `findings.json` against the QCBOR source and runs reproducers under ASan, UBSan and MSan. For each record it settles whether the finding is real, whether it was already known from the run-5 review ([`./2026-11-09-qcbor-run5-assessment.md`](./2026-11-09-qcbor-run5-assessment.md), [`../upstream/qcbor/README.md`](../upstream/qcbor/README.md)), and whether it is still present upstream. The run itself is described in [`./2026-11-14-qcbor-run6-supervision.md`](./2026-11-14-qcbor-run6-supervision.md).

**Do not publish this file** while upstream drafts 01 and 08 are private: it describes both bugs. It is on the list in [`../upstream/qcbor/README.md`](../upstream/qcbor/README.md#what-not-to-publish-yet).

## 1. Summary

- **15 of the 16 `confirmed` records are real**, and they come down to 7 defects. 6 of the 7 were already known from the run-5 review: upstream drafts 01, 04, 05, 06, 07 and 08. The 16th record, `GetItemInMap`, is not a bug (§3.2).
- **One new bug:** `QCBORDecode_Private_ConsumeItem` (`b5ec324eae`). Low severity. It reproduces under MSan on `9bd0845` and on the current `dev` (`19c3367`). It is in the same class as draft 06: an indeterminate value written to the caller's output on an error path.
- **`GetItemInMap` (`c132f24cbe`) is not a bug,** and run-5's "Not reported" verdict stands. The value is passed but never used. MSan reports it only through its eager parameter check at `-O0`, never as a use.
- **The 4 `needs_validation` records are real:** they are the in-map variants of draft 06. MSan confirms all four on both trees. `GetTEpochDaysInMapSZ` had not been run before.
- **7 of the 8 rejections are correct.** The exception is `EncodeHead` `02209a353f`: it repeats the run-5 mistake of reading the in-tree callers' usage as the contract of a public function. Draft 07 stays a real, low-severity bug.
- **Upstream status:**
  - Every known bug still reproduces on `dev` `19c3367`.
  - Draft 04 (float shifts) is now upstream as issue laurencelundblade/QCBOR#434, filed by a third party.
  - The maintainer (`laurencelundblade`) opened a fix on the day of this assessment: [laurencelundblade/QCBOR#438](https://github.com/laurencelundblade/QCBOR/pull/438), open, against `dev`. In both `IEEE754_SingleToHalf()` and `IEEE754_DoubleToSingle()` it moves the shift inside the exponent-range check, as draft 04 proposed.
  - A keyword search of upstream issues and PRs (`uNextNestLevel`, `EncodeHead`, `UsefulOutBuf_Compare`, `GetTEpoch`, `big number`, `GetArray`, `uninitialized`, `MemorySanitizer`) found no public report of the other bugs. Private security advisories are not visible to this search.
- **Severity labels in the run are off in three places.**
  - `UsefulOutBuf_Compare` (draft 05) and `EncodeHead` (draft 07) are rated `medium` and `attacker_input`, but only an application argument triggers them. They are low.
  - `GetArrayOrMap` (draft 08) is rated `medium`, but one byte of input makes the caller read past its buffer. It is high.
  - The `ConsumeItem` and `GetItemInMap` records call the indeterminate read "undefined behaviour". It is not, because both objects have their address taken (C11 6.3.2.1p2).

## 2. Method

- **Trees.**
  - `dev` at `9bd0845`: the run's checkout, `targets/QCBOR`, mounted read-only.
  - Upstream `dev` at `19c3367`: a fresh clone. Since `9bd0845` its source changed in `qcbor_main_decode.c`, `qcbor_spiffy_decode.c`, `qcbor_tag_decode.c` and `qcbor_main_encode.c`, and the error codes were renumbered (`8243246`).
- **Toolchain.** `framac-analysis:latest`, clang 19.1.7, `docker run --security-opt seccomp=unconfined --network none`, with a 25-minute timeout.
- **Reproducers.**
  - The existing set in [`../upstream/qcbor/repro/`](../upstream/qcbor/repro/run_all.sh), run on both trees.
  - Three new reproducers: [`consume_item.c`](../upstream/qcbor/repro/consume_item.c), [`getiteminmap.c`](../upstream/qcbor/repro/getiteminmap.c) and [`epoch_days_sz.c`](../upstream/qcbor/repro/epoch_days_sz.c).
  - Each new reproducer was built under MSan with eager parameter checks (the clang 19 default), and again with `-fno-sanitize-memory-param-retval`, which reports only real uses. Each build was made at `-O0` and at `-O1`.
- **Upstream state.** Read with `gh issue list` and `gh pr list` on `laurencelundblade/QCBOR`, open and closed, on 2026-11-15.

## 3. Findings

### 3.1 Confirmed Records

| # | Fingerprint(s) | Location | Real? | Known as | Upstream `dev` `19c3367` | Run-6 severity | Assessed severity |
| :-- | :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| 0, 13-16 | `26e4dafbc6`, `9fce4ec630`, `e4ea36ae74` | `UsefulBuf.c:523`; readers `qcbor_number_encode.c:214`, `:290`; root `:331` | Yes. ASan heap-buffer-overflow (READ of 1) on both trees. | Draft 01 (**private**). It names all three readers. | Present | medium | Medium (agrees) |
| 1-3 | `0e34c586b3`, `b939358da2`, `22aa038aa3` | `UsefulBuf.c:744-753` | Yes. UBSan pointer overflow at `:744`; ASan heap-buffer-overflow at `:753`. | Draft 05. `22aa038aa3` is the `uLen1` variant of the same missing bounds check, and the draft 05 patch covers it. | Present | medium, `attacker_input` | **Low.** The only caller in QCBOR, map sorting at `qcbor_main_encode.c:1289`, passes offsets from its own output. Only an application argument reaches it. |
| 6, 8 | `cd899614e4`, `31f1bd25a5` (plus `5614f2d044`, `d355106f76`, `ceaaa12428` as evidence) | `ieee754.c:625`, `:466` | Yes. UBSan `shift exponent -93` / `-1 is negative` on both trees. | Draft 04 / `QCBOR-02`, `QCBOR-03`. Filed by a third party as laurencelundblade/QCBOR#434. **Fix pending:** laurencelundblade/QCBOR#438. | Present; the fix is open | low | Low (agrees) |
| 9 | `b5ec324eae` | `qcbor_main_decode.c:2089` (`dev`: `:2116`) | **Yes. New.** See §3.3. | Not known | Present (reproduced) | low | Low |
| 10 | `b1b1b1fe2a` | `qcbor_main_decode.c:2549` | Yes. MSan on all four shapes (`top`, `nested`, `map`, `indef`) on both trees; the plain build returns `len=4702111234474983745`. | Draft 08 (**private**) | Present (`dev` `:2578`) | medium | **High** (draft 08). One input byte (`80`) gives the caller a garbage length, and the out-of-bounds read happens in the caller's use of it. The anchors in `crash_verifier_brief.md` only see the library-side initialization read. |
| 12 | `ce76fb1dc0` (sibling `02209a353f` rejected) | `qcbor_main_encode.c:470` | Yes. UBSan `index 4 out of bounds`; ASan global-buffer-overflow on both trees. | Draft 07 | Present | medium, `attacker_input` | **Low.** Public-API hardening: only an out-of-range `uMinLen` constant from the application triggers it. |
| 17 | `c132f24cbe` | `qcbor_spiffy_decode.c:516` | **No.** See §3.2. | Run-5 "Not reported" (end of draft 06) | Unchanged (`:517`) | low | Not a bug |
| 18, 21 | `745871f887`, `f982f8f015` | `qcbor_tag_decode.c:893`, `:966` | Yes. MSan, `latched` and `days-latched` modes, both trees. | Draft 06 | Present | low | Low (agrees) |

### 3.2 `GetItemInMap` `uOffset` (`c132f24cbe`): Not a Bug

- `QCBORDecode_Private_GetItemInMap()` passes its never-written `uOffset` to `QCBORDecode_Private_GetItemChecks()` when an error is already latched.
- `GetItemChecks()` reads `uOffset` only inside `if(uErr == QCBOR_SUCCESS && ...)` (`qcbor_main_decode.c:2291-2296`). On this path `uErr` is the latched error, so the value is never compared, indexed or stored. The run-6 record's own severity rationale says the same thing.
- The record calls this "a read of the indeterminate value" because E-ACSL counts passing a value by value as a read. That does not contradict run-5, which said the value is never *used*.
- It is not undefined behaviour either, because `&uOffset` is taken.
- MSan, input empty, `EnterMap` failing, then `GetItemInMapSZ("x")`:

| Build | `9bd0845` | `19c3367` |
| :--- | :--- | :--- |
| `-O0`, eager parameter checks (default) | Report at `qcbor_spiffy_decode.c:516:11`, origin `uOffset` | Report at `:517:11` |
| `-O0`, `-fno-sanitize-memory-param-retval` | Clean | Clean |
| `-O1`, either mode | Clean | Clean |

The only effect is that a `-O0` MSan build of an application flags QCBOR when the application calls `GetItemInMap*` after an error. Initializing `uOffset` to 0 silences it. At most this is a one-line note in the draft 06 issue, not a report of its own.

### 3.3 New: `ConsumeItem` Copies an Indeterminate `uNextNestLevel` to the Caller (`b5ec324eae`)

**The defect.**
- `QCBORDecode_Private_ConsumeItem()` walks a non-empty array or map with a local `QCBORItem Item`.
- When the input ends before the first member, `QCBORDecode_Private_GetNextMapOrArray()` returns `QCBOR_ERR_NO_MORE_ITEMS` from its first check. It never writes `Item`.
- `ConsumeItem()` then executes `*puNextNestLevel = Item.uNextNestLevel` unconditionally, although its own comment says the output is "Not set when traversal stops early".
- `QCBORDecode_VGetNextConsume()` passes `&pDecodedItem->uNextNestLevel`. The valid value `VGetNext()` had just written (1) is therefore replaced with a stack byte.

**Reproducer.** [`consume_item.c`](../upstream/qcbor/repro/consume_item.c), inputs `81` and `b7`, with `81 01` as the control:

| Build | `9bd0845` | `19c3367` |
| :--- | :--- | :--- |
| MSan `-O0`, eager or lazy | `use-of-uninitialized-value` at the caller's first use. Stored at `qcbor_main_decode.c:2089:21`, origin `Item` at `:2073` | The same; stored at `:2116:21`, origin `:2090` |
| MSan `-O1`, eager | The same, origin `Item.i` | The same |
| MSan `-O1`, lazy | Clean; the cause is not diagnosed (§5) | Clean |
| Control `81 01` | Clean | Clean |

The error code is `QCBOR_ERR_NO_MORE_ITEMS` on both trees: 67 on `9bd0845` and 147 after the renumbering.

**On upstream `dev`.**
- `19c3367` changed the loop: it now `break`s on a halting error or on `QCBOR_ERR_NO_MORE_ITEMS`, and its condition reads `Item.uNextNestLevel` without testing `uReturn`.
- No probe reached that condition with an unwritten `Item`.
  - The early returns of `GetNextMapOrArray()` that skip the `uNextNestLevel` assignment are `NO_MORE_ITEMS` (147), unrecoverable errors (40..99), a descend error (`DECODE_NESTING_TOO_DEEP`, 61), and whatever the ascend path's break peek (`QCBOR_Private_NextIsBreak()`) returns from `QCBOR_Private_DecodeAtomicDataItem()`.
  - That peek can return non-halting errors. To test them, [`consume_indef.c`](../upstream/qcbor/repro/consume_indef.c) puts a second member after `01` in an indefinite-length array, chosen to fail: a NaN payload (error 172) in a default build, and a float in `-DUSEFULBUF_DISABLE_ALL_FLOAT` (157) and `-DQCBOR_DISABLE_PREFERRED_FLOAT` (154) builds.
  - MSan `-O0` reported nothing on any of these inputs. The error surfaces when the member itself is decoded, after `uNextNestLevel` is written, not in the peek ([log](../upstream/qcbor/logs/run6-assessment-probes.log)).
  - This lowers the risk; it does not prove it unreachable.
- The copy after the loop is unchanged, so `dev` keeps the defect, as the reproducer shows.

**Who sees the value.**
- The other callers check the error before they use the level: `GetLabelAndConsume` (`CheckDups` and `CheckMap` break on error), `GetArrayOrMap`, and `MapSearch`.
- Only `VGetNextConsume()` hands the value to the application.

**Severity: low.**
- It is not undefined behaviour: `&Item` is taken and `uint8_t` has no trap representation.
- It needs a caller that reads `uNextNestLevel` after an error the API tells it to check.
- The arguments of draft 06 apply as they are: it contradicts the documented behaviour, it destroys a value the caller already held, and it makes MSan report inside QCBOR.

**Fix.** Write `*puNextNestLevel` only when the last `GetNextMapOrArray()` call completed, which leaves the output untouched on `NO_MORE_ITEMS` and halting errors, as the comment promises.

**Disclosure.** It can be filed publicly. It is drafted as report 10 ([`../upstream/qcbor/10-consumeitem-nest-level-issue.md`](../upstream/qcbor/10-consumeitem-nest-level-issue.md)), with patches for `dev` and 1.x. 1.x `master`, v1.6.1 and v1.5.3 have the same bug (checked 2026-11-15); v2.0-alpha-6 does not.

### 3.4 The Four `needs_validation` Records: Real, Draft 06

| # | Function | Line (`9bd0845`) | MSan evidence |
| :-- | :--- | :--- | :--- |
| 19 | `GetTEpochDateInMapN` | `qcbor_tag_decode.c:919` | `epoch_uninit notfound-n`, both trees |
| 20 | `GetTEpochDateInMapSZ` | `:945` | `epoch_uninit notfound-sz`, both trees |
| 22 | `GetTEpochDaysInMapN` | `:992` | `epoch_uninit days-notfound`, both trees |
| 23 | `GetTEpochDaysInMapSZ` | `:1018` | **New:** [`epoch_days_sz.c`](../upstream/qcbor/repro/epoch_days_sz.c) `notfound`, both trees. Stored at `:1018:12`, origin `OneItemSearch` in `GetItemInMapNoCheckSZ`. |

The verifiers could not confirm these four because of two pipeline gaps, and both are already recorded:
- The `*InMap*` dispatch cases never enter a map: [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md).
- E-ACSL marks the destination of a whole-struct copy initialized: [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md).

The second entry also says MSan cannot run in the container. That holds for the sandbox's seccomp profile only: MSan runs with `--security-opt seccomp=unconfined`, which is how every MSan result here was produced. The entry now says so.

### 3.5 Rejections

| # | Fingerprint | Reason in run-6 | Assessment |
| :-- | :--- | :--- | :--- |
| 4, 5 | `DecodeNesting_LevelUpCurrent` `6a88caa10e`, `133dcfec59` | `harness_induced`: case 129 calls `QCBORDecode_Private_ExitBoundedLevel` on a fresh context | **Correct.** The helper is private. Its precondition is stated in its body (`qcbor_spiffy_decode.c:946-947`), and both callers guard it with `DecodeNesting_IsBoundedType()`. |
| 7 | `IEEE754_SingleToDouble` `7977cf3cc9` | `contract_overconstraint` | **Correct.** At `ieee754.c:282`, a `uint64_t` subtraction is converted to `int`. That is modular, then implementation-defined (C11 6.3.1.3p3), not UB. The goal exists only because `run_wp_function.py` forces `-warn-signed-downcast`. |
| 11 | `EncodeHead` `02209a353f` | `harness_induced`: `uMinLen` > 8 is "outside the documented domain" | **Wrong; it is draft 07.** `QCBOREncode_EncodeHead()` is in the public header, and `uMinLen` was documented without an upper bound. "Every in-tree caller passes ≤ 8" describes usage, not the contract. This is the mistake the run-5 assessment found in run-5's #26. The sibling `ce76fb1dc0` stayed confirmed, so the run's report is right overall. The split is the open "opposite verdicts on one decision point" gap in [`../troubleshooting/ledger-and-verifier.md`](../troubleshooting/ledger-and-verifier.md). |
| 24-26 | `CheckItemType` `5963747e94`, `c8bb6202f9`; `ProcessTagItem` `5b85e2af5a` | `harness_induced`: case 166 passes unterminated arrays and a NULL `pfCB` | **Correct.** These are private helpers, and every caller terminates the arrays and passes a real callback; the call at `qcbor_tag_decode.c:485` is unconditional. This is run-5 #27/#28 again; the open generator gap is in [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md). |
| 27 | `UsefulBuf_Compare` `357c824f07` | E-ACSL artifact | **Correct.** An overlapping `memcmp` is defined behaviour. The abort comes from `eacsl_builtin_memcmp` (Issue 17, [`../upstream/frama-c/frama-c-eacsl-memcmp-overlapping-buffers.md`](../upstream/frama-c/frama-c-eacsl-memcmp-overlapping-buffers.md)). |

### 3.6 Not Found Again by Run-6

Drafts 02, 03 and 09 (big-number sign, negative zero, `INT64_MIN` negation in `ProcessBigNumber`) have no run-6 record. All three still reproduce on `dev` `19c3367` under `run_all.sh`:
- **02:** `NoPreferred(BORROWED, +258)` still encodes `c3 42 01 02`; the expected output is `42 01 02`.
- **03:** a negative zero still encodes as `3b ff ff ff ff ff ff ff ff`.
- **09:** UBSan still reports `negation of -9223372036854775808` at `qcbor_number_decode.c:1964:65`.

Why run-6 missed them:
- **02 and 03** produce wrong values, not runtime errors, so neither E-ACSL nor the sanitizers can see them.
- **09:**
  - The fuzzer executed the line: `QCBORDecode_ProcessBigNumber` ran 94 times, and lines 1964 and 2008 are not in its uncovered ranges in `workspace/reports/coverage/libqcbor_a.json`. No input carried `INT64_MIN`.
  - Eva left the six `signed_overflow` obligations at those two lines `Unknown`.
  - Their Phase 3 task, `prove:src/qcbor_number_decode.c#QCBORDecode_ProcessBigNumber` (13 Eva unknowns), was still `pending` with 0 dispatches when the run stopped Phase 3.
  - A complete run would have reached it. This is the cost of the `incomplete` stop, not a new pipeline bug.

## 4. Pipeline Gaps Found

- **Verifier severity and control labels** (recorded in [`../troubleshooting/ledger-and-verifier.md`](../troubleshooting/ledger-and-verifier.md)):
  - `crash_verifier_brief.md` defines `attacker_input` as "bytes of the fuzz input". In an `--api` harness those bytes also choose API arguments, so application-argument bugs are rated as attacker-driven (`UsefulOutBuf_Compare`, `EncodeHead`).
  - The severity anchors do not cover a library returning a corrupt length that its caller then reads, so draft 08 was rated `medium`.
  - Nothing tells verifiers that reading an indeterminate object whose address is taken is not undefined behaviour.
- **MSan as a second oracle:** the existing E-ACSL struct-copy entry in [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md) now records that MSan works in the analysis image when seccomp is relaxed.

## 5. Not Verified

- Whether `ConsumeItem`'s indeterminate byte ever differs from 0 in an unsanitized build: the plain `-O0` build printed 0 on both trees. MSan's report is the evidence, not the value.
- Why the `-O1` build without eager parameter checks misses the `ConsumeItem` use that the other three MSan builds report.
- That `dev`'s new `ConsumeItem` loop condition can never read an unwritten `Item` (§3.3): only probed, not proven.
- PR #438 was read in full, not built; it is not yet merged into `dev`.

## 6. How to Rerun

The scripts live in the session scratchpad. They are reproduced here so the run can be repeated:
- Run `bash repro/run_all.sh <tree> <out>` on each tree.
- For each of `consume_item.c`, `getiteminmap.c` and `epoch_days_sz.c`, build against the tree's `src/*.c` with `clang -g -O0 -fno-omit-frame-pointer -fsanitize=memory -fsanitize-memory-track-origins=2 -I<tree>/inc -I<tree>/src`, once as is and once with `-fno-sanitize-memory-param-retval`. Repeat at `-O1`.
- Run everything in `framac-analysis:latest` with `--security-opt seccomp=unconfined --network none`.

The output is in [`../upstream/qcbor/logs/run6-assessment-9bd0845-and-19c3367.log`](../upstream/qcbor/logs/run6-assessment-9bd0845-and-19c3367.log) and [`../upstream/qcbor/logs/run6-assessment-probes.log`](../upstream/qcbor/logs/run6-assessment-probes.log). The first log runs the private reproducers and is on the do-not-publish list. The probe log runs only `consume_item.c`, `getiteminmap.c` and `consume_indef.c`.
