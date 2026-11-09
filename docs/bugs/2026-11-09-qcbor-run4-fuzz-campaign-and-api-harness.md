# Bug report: unsound `--api` harness cases, a fuzz skip mask capped at 64 cases, and a reach gate that fails on partial coverage

- **Date:** 2026-11-09
- **Found by:** `/framac-verify` standard run on QCBOR (`~/framac-pipeline/QCBOR/run-4`, target `targets/QCBOR`). The target has one link unit, `libqcbor_a`, an `--api` harness with 179 dispatch cases, and 171 API entry points.
- **Pipeline state:** branch `phase1-remediation` at `5a5beca`
- **Run outcome:**
  - The dynamic reach gate fails: the corpus executed 95 of 171 entry points. As a result `wp-queue` refuses and Phase 3 cannot start.
  - All 29 crash candidates are fuzz crashes. The ones checked come from the harness (see A); all 29 are probably noise.

Each item below was checked against the pipeline source. **Unverified** marks what is still inference.

## Summary

| # | Problem | Severity | Status |
|---|---|---|---|
| A | `--api` cases break the API's contract: wild pointers in by-value structs, contexts never initialized, a C string paired with an enum as `(buf, len)`, seeds that carry the pointers of the recording process | **P0**: crash candidates are mostly noise, and fuzzing exercises very little | confirmed in source |
| B | Coverage replay stops for good after 16 failing inputs, and the dynamic reach gate treats that `partial` measurement as complete | **P0**: blocks Phase 3 on 11% of the corpus | confirmed in source |
| C | Keep-going fuzz rounds cannot skip dispatch cases ≥ 64, so the campaign ends early and says nothing | **P1** | confirmed in source |
| D | `--api` drops cases with no diagnostic; a failed `generate_harness.py` still writes a harness, and the reach gate passes it | **P2** | confirmed in source |
| E | The E-ACSL build fails on glibc `isnan` (`__builtin_isnan`) | **P2** | confirmed; fix untested |
| F | Smaller items: 64 MB Eva tuning artifact, a define pointing into scratch, wrapper quoting | P3 | observed |

A, B and C compound each other:
1. A makes most cases crash at once, on fuzz inputs and on seeds alike.
2. C ends the campaign once only cases ≥ 64 are still crashing: 70.9 s of a 100 s budget for the sanitizer engine, 20.7 s for E-ACSL.
3. B stops the coverage replay at the 16th crashing input and leaves 1,971 of 2,240 inputs unreplayed.
4. The dynamic gate then fails on that lower bound.

Each candidate would then cost a Crash Verifier subagent. The likely verdict is `harness_induced`, with up to two repair rounds each, and then `harness_repair_exhausted`. That is LLM spend on harness defects, not on target bugs.

---

## A. `--api` generates cases that violate the API's contract (P0)

**Where:** `scripts/api_harness.py`, `_bind_call` (lines 155-260), and `scripts/seed_harvest.py` (`classify_type`, `layout_seed`).

### A1. Structs passed by value are filled from input bytes, pointer fields included

`api_harness.py:255-258` (the "scalar, enum or struct by value" branch) declares the struct and fills it from the input with `memcpy`. QCBOR's `UsefulBuf` and `UsefulBufC` are `{ptr, len}` structs, so every such argument gets a pointer and a length taken from the input.
- Case 52: `QCBOREncode_Init(&ctx, c0a1)` with the output buffer read from the fuzz bytes.
- Case 13: `UsefulOutBuf_Init`.
- Case 0: `UsefulBuf_Compare(c0a0, c0a1)`, where both sides are wild pointers.

About 138 by-value `UsefulBufC` and 58 by-value `UsefulBuf` declarations per harness copy. The harness holds an Eva copy and a fuzz copy of every case.

### A2. Pointers to context objects get a zeroed object with no constructor

`api_harness.py:237-252`: a pointer to a struct gets one zeroed object, or an array when `param_sizes` gives a size (case 93: `static unsigned char c0a0[4024]` cast to `QCBORDecodeContext *`). No `QCBORDecode_Init`, `QCBOREncode_Init`, `UsefulOutBuf_Init` or `UsefulInputBuf_Init` runs first.
- Case 109: `QCBOREncode_AddInt64` on a zeroed context.
- About 96 decode and 30 encode context arguments per copy are built this way.

### A3. A `char *` C string followed by an enum is treated as a `(buf, len)` pair

`seed_harvest.py:208-209` maps every enum to `{"kind": "int", "ctype": "int"}`, and `int` is in `_LEN_SCALARS` (line 125). `_bind_call` (line 204) therefore pairs `const char *szLabel` with the next enum argument.

Case 93, `QCBORDecode_GetTDecimalFractionBigMantissaRawInMapSZ`, passes `(char *)(fuzz_buf + fuzz_off)`, which is not NUL-terminated, as the label, and `(enum QCBORDecodeTagReq)(fuzz_len - fuzz_off)` as the tag requirement.

The candidate checked (case 93, 4-byte reproducer) is an ASan heap-buffer-overflow in `strlen` inside `UsefulBuf_FromSZ`, which this case explains. 7 of the 29 candidates sit in `UsefulBuf_FromSZ`. **Unverified** that the other 6 come from the same pattern.

### A4. Seeds put the recording process's pointers into struct slots

The recorder (`seed_harvest.py:405-414`, `fc_struct`) stores a by-value struct's raw bytes (`'t'`) and separately records the memory of each `(ptr, len)` pair inside it. The seed writer only uses the raw bytes (`_LAYOUT_KINDS["struct"] = ("t",)`, line 1181).

A seed for any case taking a `UsefulBufC` therefore holds a pointer value from the test process. The recorded pair data is never used.
- This matches the coverage failures on seeds: `workspace/seeds/libqcbor_a/seed-00095a5195546067` SEGVs in `Nesting_GetMajorType`.
- The E-ACSL round 1 crash happened in `ReadAndExecuteSeedCorpora`, before any mutation.

### A5. The recorded call sequences do not help

The test suite runs in one process, so the whole run is a single trace of 4,397 calls (`seed_harvest.json`: `traces: 1`). The 8 sequence cases that come out of it run `Init` then `Add`/`Get` calls. That is the right shape, but `Init` gets its buffer through A1 and A4, so the sequences crash too.

### Consequences
- Every candidate checked is a harness defect: the `UsefulBuf_*`, `Nesting_*` and `DecodeNesting_*` crashes, and `UsefulBuf_FromSZ` (A3).
- **Unverified:** the Eva copy uses the same cases with `Frama_C_make_unknown` bytes, so Eva probably reports spurious alarms through the same wild pointers.
- This affects any library whose API passes slices by value or uses context objects. `--api` is the documented default for units with many entry points.

### Suggested fixes
1. **By-value structs with pointer fields.** Never fill them from input. Give each `(ptr, len)` field generator-owned storage of a known size, take the length from the input clamped to that storage, and let the bytes come from the input for `const` pairs. The model has the struct layout, or `fc_struct` already finds the pairs at run time.
2. **Context objects.** When the module has an initializer that takes a pointer to the same struct type (`*_Init`, or the first call in recorded traces), call it in each case before the call under test. Its own by-value arguments follow fix 1. Without a known initializer, skip the case and record the reason, so the reach gate shows a documented gap and not a crash.
3. **Pair detection.** Pair a pointer with the next argument only when that argument has a length type (`size_t` and other unsigned integers, not enums), or when the formal names say so (`*Len`, `*Size`, `n*`). A `char *` with no pair is a NUL-terminated string.
4. **Seeds.** For a struct slot, rebuild the struct from the recorded pair data under fix 1's layout, and never copy a recorded pointer value.

---

## B. Coverage replay stops for good after 16 failing inputs, and the gate treats the result as complete (P0)

**Where:**
- `scripts/run_eacsl_fuzz.py:131-133`: `COVERAGE_BATCH_SIZE = 256`, `COVERAGE_MAX_FAILED_INPUTS = 16`.
- `replay_for_coverage`, lines 3458-3527: `while pending and len(failed) < max_failed`.
- `scripts/harness_reach.py:516`: `_COVERAGE_OK = ("ok", "partial")`.

The replay splits a failing batch until the crashing input stands alone, and it stops completely at the 16th such input. Run-4 hit exactly 16: 253 inputs replayed and 1,971 never replayed. The corpus includes the seeds that crash because of A4.

The dynamic reach gate accepts a `partial` report as measured and fails the module on its gaps. Those 76 gaps are a lower bound taken from 11% of the corpus.

### Suggested fixes
- Keep replaying past failures, with a time limit and no failure count. Input known to crash (fingerprints in `candidates.json`, files under `workspace/crashes/`) can be left out of the replay or counted separately.
- In `harness_reach.py`, a gap measured on a `partial` report should be reported as `unmeasured` or `partial_gap`, not as a failed gate. Otherwise, rerun coverage until it is `ok`.

---

## C. Keep-going rounds cannot skip dispatch cases ≥ 64 (P1)

**Where:**
- `scripts/run_eacsl_fuzz.py:1363`: `new = [c for c in crashed if c not in skipped and c < 64]`.
- `scripts/generate_harness.py:864-865, 878-879`: the generated guard handles bits 0-63 only. The docstring states this limit.
- `run_eacsl_fuzz.py:4472`: `-DFRAMAC_FUZZ_SKIP_CASES=<mask>ULL`.

When every newly crashing case is ≥ 64, `new` is empty and the loop ends (`run_eacsl_fuzz.py:1364`). The round records no `stopped` reason. In this harness, 115 of the 179 cases can never be skipped.

Evidence (`engines.*.keep_going` in `workspace/reports/fuzz/libqcbor_a.json`):
- **Sanitizers:** 18 rounds, 70.9 s of a 100 s budget. The last three rounds crashed in `[44 59 93 104 110]`, `[43 67 80 113 166 175]` and `[70 83 86 113 114]`. Cases 104 and 113 crash in two rounds.
- **E-ACSL:** 3 rounds, 20.7 s, ending on case 175.

`MAX_CASES = 255` in `api_harness.py`, so generated harnesses routinely go past 64 cases.

### Suggested fix
Skip by case number for all cases: a `-D` list expanded into a `static const unsigned char skip[N]`, or an array of mask words. Until then, record `stopped: "unskippable_case"` and keep fuzzing the remaining cases in fork mode with crashes ignored, the same fallback the code uses for non-dispatch harnesses.

---

## D. Silent case drops, and a failed harness that passes the gate (P2)

- **Dropped without a reason.** `api_harness.py:598-604` drops every case clang rejects and records only "the case does not compile with the target's headers". Here 23 cases were dropped because `qcbor.h` does not include `qcbor_spiffy_decode.h`. I found that only by regenerating with the probe off and running clang by hand. Fix: store the first clang diagnostic for each dropped case in `api_skipped`.
- **Failed harness kept.** `generate_harness.py` writes the harness (line 1986) and the sidecar (line 2060) before raising on unresolved prelude identifiers (lines 2062-2073). The sidecar records `prelude_status: "unresolved"`, but no other script reads `prelude_status`. `harness_reach.py check` then passed on that harness. The E-ACSL build would have failed later. Fix: let the reach gate (or `phase0_gates`) refuse a sidecar whose `prelude_status` is `unresolved`, or write the harness only after the check succeeds.

---

## E. The E-ACSL build fails on glibc `isnan` (P2)

`build-check` fell back with `eacsl_compile_failed: cannot redeclare builtin function '__builtin_isnan'`. Under the E-ACSL frontend (host headers, `-no-frama-c-stdlib`), glibc's `math.h` (around line 978) expands `isnan` to `__builtin_isnan` when `__GNUC_PREREQ(4,4) && !defined __SUPPORT_SNAN__`. Frama-C does not know that builtin ("Calling undeclared function __builtin_isnan") and prints a K&R prototype for it, which clang then refuses. `isinf` (`__builtin_isinf_sign`), `isfinite` and `fpclassify` are guarded the same way. The pipeline has no handling for any of them.

**Workaround used in run-4:**
- a `workspace/harnesses/include/math.h` shim doing `#include_next <math.h>`, `#undef isnan`, `#define isnan(x) ((x) != (x))`;
- `-Iworkspace/harnesses/include` placed first in `--cppflags`;
- no `#ifndef __FRAMAC__` guard: the E-ACSL frontend defines `__FRAMAC__`, so a guard hides the shim.

**Suggested fix (untested):** add `-D__SUPPORT_SNAN__` to `EACSL_DEFINES` in `scripts/eacsl_toolchain.py:44`. That flag is frontend only, next to the existing `_Float128` and `__int128` workarounds. glibc then uses the library functions `__isnan`, `__isinf` and `__fpclassify`. `signbit` is not covered: it uses `__builtin_signbit` whenever `__GNUC_PREREQ(6,0)`. Add a regression harness that calls `isnan`, `isinf`, `fpclassify` and `signbit`.

---

## F. Smaller items (P3)

- **Eva tuning artifact too large:** `workspace/reports/eva-tuning/libqcbor_a/base.json` exceeds 64 MiB (67,108,864 bytes). The warning repeats on every `pipeline_make` call.
- **Config define pointing into scratch:** `gen` reports `dag_cppflags_missing: -DQCBOR_CONFIG_FILE="/framac-scratch/tree/build/generated/qcbor/qcbor_config.h"`. That path exists only while the scratch volume does. The harness falls back to the default `qcbor_config.h`. **Unverified** that the two configs match. All options were at their defaults.
- **Wrapper quoting:** commands containing `\"` fail in `framac-docker.ps1` (`Missing argument in parameter list`). The workaround is a shell script in the run directory run with `sh`.

---

## Recommended order

1. **A.** Without it every other fix measures noise. Fixes A1, A3 and A4 are mechanical. A2 needs a rule for finding initializers.
2. **B.** Then the gate decides on real coverage.
3. **C.** Then the campaign spends its whole budget.
4. **D, E**, then **F**.

**Run-4:** the run stays blocked until A and B are fixed or worked around. Then regenerate the harness, run `reach-gate` and `build-check`, and rerun Phases 1-2. Do not spend Crash Verifier subagents on the current 29 candidates.

## Reproduce

1. Run `/framac-verify` on QCBOR, profile `standard`, with recipe `cmake -S . -B build -DBUILD_QCBOR_TEST=APP && cmake --build build` and test command `build/test/qcbortest`.
2. Generate the harness: `generate_harness.py --module libqcbor_a --api --header workspace/work/inc/qcbor/qcbor.h --extra-include qcbor/qcbor_spiffy_decode.h`.
3. Add the `math.h` shim from E, then run `pipeline_make.py build-check`.
4. Run `pipeline_make.py run build fuzz eva coverage reach-dynamic`.
5. Read:
   - `engines.*.keep_going` in `workspace/reports/fuzz/libqcbor_a.json` (C);
   - `inputs` in `workspace/reports/coverage/libqcbor_a.json` (B);
   - `harness_reach_dynamic.json` (76 gaps);
   - cases 13, 52, 93 and 109 in `workspace/harnesses/harness_libqcbor_a.c` (A).
