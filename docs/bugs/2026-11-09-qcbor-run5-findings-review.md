# QCBOR run-5: findings dossier for independent re-assessment

**Audience:** a reviewing model with read access to the paths below and, ideally, the analysis container.
**Goal:** re-judge every verdict of this run from the evidence, not from the verdicts' own wording. Say where each verdict holds, where it is wrong, and where the severity, the reachability or the "duplicate", "harness-induced" or "toolchain artifact" label should change.

This document only summarizes. The authoritative records are:
- `findings.json`: all 30 verdict records, with full descriptions, evidence, harness notes and fix patches.
- `candidates.json`: the tool hits and their reproducers.
- `REPORT.md`, `FINDINGS-DETAIL.md` and `NEEDS-VALIDATION.md`: the pipeline's own reports.
- `agents/<agent-id>/scratch/`: each verifier's working files (replays, seeds, notes).

All of these are in `C:\Users\Florian\framac-pipeline\QCBOR\run-5`. Paths below are relative to it unless they start with `src/` or `inc/`; those are target paths, readable at `workspace/work/src/...` or in the read-only target `C:\Users\Florian\OneDrive\Documents\Dev\targets\QCBOR`.

---

## 1. What was analyzed, and how

| Item | Value |
| :--- | :--- |
| Target | QCBOR, git `9bd08456d46ac5fbaa7822420fd3e25e0e9c486f`. **The worktree was dirty**, so check `git -C <target> status` / `diff` before attributing a finding to upstream. |
| Build | `cmake -S . -B build -DBUILD_QCBOR_TEST=APP && cmake --build build`; tests: `build/test/qcbortest` |
| Analyzed unit | one link unit, `build/libqcbor.a` (module `libqcbor_a`). 755 functions, 171 treated as untrusted API entry points. |
| Trust model | **No `THREAT_MODEL.md`.** Every exported function counts as attacker-reachable by default, *including `*_Private_*` helpers that QCBOR exports only for its inline wrappers*. This is the most important bias to correct; see §6. |
| Profile | `standard` |
| Toolchain | Frama-C 35.0~dev, E-ACSL, clang 19.1.7 (libFuzzer, ASan, UBSan), Alt-Ergo 2.4.3, Z3 4.13.3, CVC5 1.1.2 |
| Pipeline | frama-c checkout, branch `phase1-remediation`, up to `5dc6769` |

**Harness.** `workspace/harnesses/harness_libqcbor_a.c` and its sidecar `harness_libqcbor_a.json` (`api_cases`).
- It is an API dispatch harness: `fuzz_buf[0] % 179` selects a case, and the remaining bytes fill that case's arguments.
- Most cases call `*_Init` first; the sidecar lists them.
- Case 170 is a call sequence recorded from QCBOR's own test suite.
- The same file holds the Eva driver (`eva_main`) and the fuzz dispatch (`LLVMFuzzerTestOneInput`), as two copies of each case.

**Phases actually run.**
1. **Phase 0:** build capture, call graph, harness, reach gates. Passed.
2. **Phase 1:** fuzzing with two engines, E-ACSL and ASan/UBSan. It runs in keep-going mode: a case that crashes is masked through `FRAMAC_FUZZ_SKIP_CASES_<k>` and fuzzing continues.
   - E-ACSL masked 55 of 179 cases, most of them because of the toolchain artifact in §5.1. E-ACSL coverage is therefore shallow.
   - The sanitizers masked 32 cases.
3. **Phase 2:** Eva over the whole module, about 2 h. Tuning was skipped because the base run was over the per-rung cap. 56 RTE units were discharged by Eva.
4. **Crash gate:** 31 Crash Verifier subagents, one fresh LLM agent per candidate. Each replayed the reproducer in the sandbox, read the source and the in-tree callers, and judged whether the harness respected the callee's contract.
5. **Phase 3 (WP proofs) was not run, by the user's decision.** Nothing is formally proven. The reason is §5.1: the dual-oracle guardrail fails on unmodified code.
6. **Phase 4:** reports only. Run status `incomplete`.

**Harness repairs** (2 of 2 allowed), both made because verifiers rejected crashes as harness-induced. Backups are in `state/harness_libqcbor_a.c.pre-repair1` and `state/harness_libqcbor_a.c.pre-repair2`.
- **Repair 1:**
  - case 48: `QCBOREncode_EncodeHead` `uMinLen` limited to {0,1,2,4,8};
  - case 129: `QCBORDecode_Private_ExitBoundedLevel` replaced by public `EnterArray`/`ExitArray`;
  - case 166: `QCBORDecode_Private_ProcessTagItem` given `QCBORDecode_StringsTagCB` and terminated type and tag arrays instead of a NULL callback.
- **Repair 2:** `uMinLen` limited the same way in case 57 and twice in case 170, for `QCBOREncode_Private_AppendCBORHead`.

Reproduce any crash inside the container with:
`python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py replay --module libqcbor_a --inputs <crash file> --binary workspace/harnesses/fuzz_libqcbor_a` for ASan/UBSan, or `... fuzz_libqcbor_a.e-acsl` for E-ACSL.

**Caveat:** the current binaries were rebuilt with the skip masks. A case that crashed during fuzzing may now be masked and replay as "not reproduced". One verifier hit exactly this and rebuilt without masks in its scratch dir.

---

## 2. Verdict summary (30 records)

| Verdict | Count | Notes |
| :--- | ---: | :--- |
| confirmed | 8 | **2 "medium" are one root cause.** There are 6 distinct root causes, and for 3 of them, the uninitialized-output pattern, it is unclear whether QCBOR's API makes them bugs at all. |
| needs_validation | 4 | Same uninitialized-output pattern, in the `*InMapN/SZ` variants. E-ACSL cannot witness them. |
| rejected: toolchain_artifact | 13 | E-ACSL by-value formals never marked initialized (§5.1) |
| rejected: harness_induced | 3 | Repaired as above |
| rejected: duplicate | 2 | Both are additional sinks or reproducers of confirmed root causes |

---

## 3. Confirmed findings, with the questions to re-assess

### C1 (medium ×2, one root cause): 1-byte heap over-read for an all-zero big number

- **Records:**
  - `src/UsefulBuf.c#UsefulOutBuf_AppendUsefulBuf::mem_access::a1f5da65a9`, sink `UsefulBuf.c:523`, case 112;
  - `src/qcbor_number_encode.c#QCBOREncode_Private_BigNumberToUInt::mem_access::a1f5da65a9`, sink `qcbor_number_encode.c:214`, case 113;
  - duplicate: `...AddTNegativeBigNumber::mem_access::a1f5da65a9`, sink `qcbor_number_encode.c:290`, case 112.
- **Claim:** `QCBOREncode_Private_SkipLeadingZeros` (`src/qcbor_number_encode.c:325-332`) handles an all-zero input by setting `NLZ.len = 1` while `NLZ.ptr` is left one past the end by `UsefulBuf_SkipLeading`. Every consumer then reads `BigNumber.ptr[BigNumber.len]`.
  - On the raw path the byte is copied into the encoded output, so 1 byte of adjacent memory is disclosed to whoever receives the encoding.
  - On the preferred path it is folded into an integer.
- **Evidence:** ASan heap-buffer-overflow READ of size 1, "0 bytes after" the input region.
  - Reproducers: `workspace/crashes/libqcbor_a/crash-6c71ec2d...` (41 B) and `crash-072c6cd5...` (19 B), plus `crash-a839711c...` for the negative path.
  - A verifier says it reproduced through the public API alone (`QCBOREncode_AddTBigNumber` / `AddTBigNumberNoPreferred`).
- **Proposed fix:** return `UsefulBuf_Tail(BigNumber, BigNumber.len - 1)`. Patches: `agents/verify-usefuloutbuf_appendusefulbuf_a1f5da65a9/artifacts/a1f5da65a9.fix.patch` and `agents/verify-qcborencode_private_bignumbe_a1f5da65a9/artifacts/`.
- **Re-assess:**
  1. Read `SkipLeadingZeros` and `UsefulBuf_SkipLeading` yourself. Is `ptr` really one past the end for all-zero input?
  2. Is an all-zero big number valid input for the public API? The verifiers cite the doc comment saying it is "handled".
  3. Is "medium" right? It is a deterministic read of 1 byte just past a caller-supplied buffer, copied into output that may cross a trust boundary. Note that the *encoder's* input usually comes from the application, not from an attacker.
  4. Should it be reported as **one** finding? The report counts it twice.
  5. Is it already fixed upstream after `9bd0845`?
  6. A side note from the verifier: with the fix, a *negative* zero encodes magnitude `0xff` because `uByte--` wraps. Is that a separate semantic bug?

### C2 (low): out-of-range shifts in `ieee754.c`

- **Records:**
  - `src/ieee754.c#IEEE754_DoubleToSingle::shift::5614f2d044` (line 625);
  - `src/ieee754.c#IEEE754_SingleToHalf::shift::5614f2d044` (line 466);
  - duplicate `...SingleToHalf::shift::31f1bd25a5` (shift ≥ 32 instead of negative).
- **Claim:** the subnormal-conversion shift runs before the exponent-range guard (lines 627-628 and 470-471), so out-of-range exponents produce negative shifts or shifts ≥ the type width. The result is discarded by the guard.
- **Reached by:**
  - decoding untrusted CBOR with `QCBOR_DECODE_MODE_ONLY_SHORTEST_FLOAT` (part of PREFERRED / CDE / dCBOR), e.g. the 5 bytes `fa 00 fa 00 00`;
  - `QCBORDecode_GetNumberConvertPrecisely`;
  - encoding any float through `QCBOREncode_AddFloat` / `AddDouble` with preferred serialization.
- **Re-assess:**
  1. Is this really UB on every listed path? Check the operand types and that `nShiftAmount` is signed.
  2. Could any compiler exploit the UB to drop the guard? With the guard after the shift, a compiler may assume `nShiftAmount` is in range and simplify the later range test.
  3. Is "low" right, given that it is reachable from untrusted decode input?
  4. Is one fix per function sufficient? `DoubleToSingle` has no fix patch.

### C3 (low): pointer overflow in `UsefulOutBuf_Compare`

- **Record:** `src/UsefulBuf.c#UsefulOutBuf_Compare::mem_access::b939358da2` (line 745), case 10, reproducer `crash-2f117de1...`.
- **Claim:**
  - Offsets and lengths are added to `pBase` before being clamped to `data_len`.
  - `UsefulBuf.h` documents that any offset is safe.
  - The only in-tree caller (map sorting, `qcbor_main_encode.c:1289`) passes offsets derived from its own output.
- **Re-assess:**
  1. Check the header text. Does it promise safety for *any* `size_t` offset, or only for "off the end" offsets?
  2. Without an attacker path through the in-tree caller, is this a finding, or an API-hardening note?
  3. Is the case reaching it through a `*_Private_*` helper, or through a public function? It is the public `UsefulOutBuf_Compare`.

### C4 (low ×3, plus the 4 needs-validation): indeterminate value read or returned after a decode error

- **Confirmed:**
  - `QCBORDecode_Private_GetItemInMap::initialization::c132f24cbe`: local `uOffset`, read at `qcbor_spiffy_decode.c:516` when an error is already latched.
  - `QCBORDecode_GetTEpochDate::initialization::745871f887`: `qcbor_tag_decode.c:893`, `*pnTime = Item.val.epochDate.nSeconds`.
  - `QCBORDecode_GetTEpochDays::initialization::f982f8f015`: `qcbor_tag_decode.c:966`.
- **Needs validation:** `GetTEpochDateInMapN` (919), `GetTEpochDateInMapSZ` (945), `GetTEpochDaysInMapN` (992), `GetTEpochDaysInMapSZ` (1018).
  - The `Item` they read is copied from a partially initialized search template, `OneItemSearch[0]` in `qcbor_spiffy_decode.c:497`.
  - E-ACSL marks a whole-struct copy as initialized (§5.2), so it cannot witness them.
  - Each record's validation plan is an MSan build of the harness case plus a branch on the output.
- **Evidence for the confirmed three:** E-ACSL `\initialized` failures on 1-byte inputs (`crash-fe83f217...`, `crash-fa138ae3...`, `crash-13cba177...`).
- **This is the group most likely to be over-called. Re-assess:**
  1. QCBOR's decode-error design is error latching: callers check `QCBORDecode_GetError()` / `Finish()`. `inc/qcbor/qcbor_main_decode.h:137-138` tells callers not to reference decoded data until then. Under that contract, is an indeterminate `*pnTime` on error a defect, or documented "unspecified output"?
     - If documented, these become hardening notes, not findings.
     - Exception: `uOffset` in `GetItemInMap` is consumed *inside* the library (passed to `QCBORDecode_Private_GetItemChecks`). Check whether that use can matter: is it read on the error path, or only stored?
  2. Even when the output is "unspecified", reading an indeterminate automatic object is UB in C only in specific cases: an object whose address is never taken, or trap representations. Is it UB here, or only an indeterminate value?
  3. The E-ACSL witnesses: E-ACSL is the tool with the by-value artifact (§5.1). Check that these three are locals and not by-value formals, as the verifiers claim. Confirm with MSan if possible.

---

## 4. Rejected: harness-induced (3, repaired)

All three were judged out of contract for semi-private helpers. Re-assess whether a **public** API path can reach the same state; if one can, the rejection is wrong.

| Record | Harness violation claimed | Question for the reviewer |
| :--- | :--- | :--- |
| `QCBOREncode_EncodeHead::index_bound::02209a353f` (`qcbor_main_encode.c:470`) | `uMinLen` > 8; every in-tree caller passes 0, 2, 4 or 8 | Can any public function pass a caller-chosen `uMinLen`? Check the public inline wrappers around `QCBOREncode_Private_AddType7` and `QCBOREncode_AddSimple`-style functions. `EncodeHead` itself is public in the header. The verifier suggests a library-hardening guard `if(uMinLen > 8)`. |
| `DecodeNesting_LevelUpCurrent::mem_access::6a88caa10e` (`decode_nesting.h:385`) | `ExitBoundedLevel` called with no bounded level entered (NULL − 1) | Do all public Exit functions really check `DecodeNesting_IsBoundedType` first? Check `ExitArray`, `ExitMap` and `ExitBstrWrapped` when entered and exited in mismatched orders. |
| `QCBORDecode_Private_ProcessTagItem::mem_access::5b85e2af5a` (`qcbor_tag_decode.c:485`) | NULL `pfCB` and unterminated type and tag arrays | Can a user install tag decoders (`QCBORDecode_InstallTagDecoders`) whose table leads to a NULL callback here? |

---

## 5. Rejected: toolchain artifact (13), and the two E-ACSL issues

### 5.1 By-value formal parameters are never marked initialized

E-ACSL registers each by-value formal with `__e_acsl_store_block(&formal, size)` but emits no `__e_acsl_full_init`. The first `\initialized(&formal.field)` check therefore fails on every call.
- **Evidence:** the instrumented source `workspace/harnesses/fuzz_libqcbor_a.instrumented.c`, around line 1648, shows it for `UsefulBuf_Compare`. A verifier reproduced it in a 15-line standalone program.
- **The 13 rejected records:**
  - `UsefulBuf_Compare` (116)
  - `UsefulBuf_CopyOffset` (98)
  - `UsefulBuf_FindBytes` (155)
  - `UsefulBuf_IsValue` (136)
  - `UsefulBuf_SkipLeading` (179)
  - `UsefulOutBuf_AppendUsefulBuf` (489)
  - `UsefulOutBuf_InsertUsefulBuf` (302)
  - `QCBORDecode_SetMemPool` (2764)
  - `QCBORItem_IsMapOrArray` (97)
  - `QCBOREncode_EncodeHead` (423)
  - `QCBOREncode_Private_AddBuffer` (753)
  - `QCBORDecode_ProcessBigNumber` (1895)
  - `QCBOR_Private_BigNumConformance` (1457)
- **Re-assess:**
  1. For each one, check that the failing predicate names a **by-value formal**, not a local or a field reached through a pointer. The verifier titles of `SetMemPool`, `IsMapOrArray`, `ProcessBigNumber`, `BigNumConformance`, `EncodeHead` and `AddBuffer` do not say which object failed. Check `predicate` in `findings.json` against each function's signature.
  2. For each one, check that every real caller initializes the argument fully. A struct argument with an uninitialized field *would* be a real bug that this rejection hides.
  3. Is the artifact real? Look at the instrumented source, and check against Frama-C/E-ACSL behaviour and documentation (`docs/references/` in the frama-c checkout).

### 5.2 A whole-struct copy marks the destination fully initialized

E-ACSL instruments `*pItem = OneItemSearch[0]` as `__e_acsl_initialize(pItem, sizeof(QCBORItem))` (instrumented source around line 144910), whatever the source's state. Uninitialized data travelling through struct copies is invisible to it. That is why the four C4 variants are "needs validation", and it may hide more of the same pattern elsewhere.

### 5.3 Consequence for coverage

Because of §5.1, E-ACSL fuzzing masked 55 of 179 cases almost immediately. Only the sanitizer engine, which has no uninitialized-memory checks (no MSan), covered those cases. **Uninitialized-memory bugs in roughly 55 dispatch cases were effectively not searched.** A reviewer should treat "no uninit findings there" as "not looked at".

---

## 6. Systemic doubts about the whole run

1. **Trust boundary.** With no threat model, all 171 exported functions are "untrusted entry points", including `*_Private_*` helpers that exist only for inline wrappers. Every harness-induced rejection came from such helpers.
   - Which findings remain reachable from the **documented public API**? C1 has a public-API reproducer; C2 is reachable by decoding.
   - Should the Private helpers be excluded or given contracts?
2. **Reachability labels.** Every confirmed finding is labelled `untrusted_surface` by default. For encoder-side bugs (C1, C3), the inputs normally come from the application, not the network.
3. **Severity calibration.** The only "medium" is a 1-byte over-read. Is anything here above "low" for a typical QCBOR deployment?
4. **Verifier independence.** Each verifier was a fresh agent, but all used the same harness, the same instructions (`agents/HOST-HOWTO.md`) and the same "known artifact" note.
   - That note told them to reject by-value-formal `\initialized` failures once the caller initializes the argument. It may have biased borderline cases toward rejection.
   - Spot-check at least 3 toolchain-artifact rejections from scratch.
5. **No formal proof.** Phase 3 did not run. Eva's 56 discharged units hold under the harness's context assumptions and are not unconditional.
6. **Dirty target worktree.** Confirm that the analyzed code equals upstream `9bd0845` before reporting anything upstream.

---

## 7. What the reviewer should produce

For each of the 30 records: **agree** or **disagree** with the verdict, with the corrected verdict, class, severity and reachability where you disagree, and the evidence (file:line or a reproduction) behind it.

Then:
- the final list of distinct, upstream-reportable QCBOR bugs, with one root cause each;
- the hardening notes that are not bugs;
- the verdicts the run got wrong, and why (harness, toolchain, trust model or verifier reasoning);
- any check that would change a conclusion and was not possible here (e.g. MSan builds).
