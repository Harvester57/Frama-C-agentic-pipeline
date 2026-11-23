# CryptoLib Phase 0: Today's Pipeline Against the Stored Baselines (2026-11-23)

- **Runs index:** [`./README.md`](./README.md)
- **Benchmark guide:** [`../guides/benchmark.md`](../guides/benchmark.md)
- **Troubleshooting entries written for this run:** [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md) (`--api` undeclared functions; the seed, global-setup, zeroed-frame and exact-bounds entries are `main`'s own), [`../troubleshooting/resources-and-infra.md`](../troubleshooting/resources-and-infra.md) (`--phase0-only` comparison)

## What Was Run

This run checks what Phase 0 alone gives on CryptoLib today, to see where coverage could grow. It ran no Eva, fuzzing, WP or LLM step.

| | Run 1: pinned harness | Run 2: generated `--api` harness |
| :--- | :--- | :--- |
| Command | `benchmark.py run --target cryptolib --phase0-only --run-id cl-p0-20261123 --compare phase0-r1` | the same with `--manifest <scratch copy> --run-id cl-p0-api-20261123` |
| Harness | the manifest's 5 pinned recall harnesses (`core`, `crypto`, `key`, `mc`, `sa`) | one `{"generate": "api"}` harness for the `libcryptolib_so` link unit, with `--header include/crypto.h` and the `core` cppflags, and no exemptions |
| Result | Phase 0 `ok` (111 s wall, 15 s CPU) | reach gate failed with 29 gaps (64 s): a measurement, not a defect of the run |

- **Pipeline:** `main` at `9077b9b`, run from the worktree `.claude/worktrees/cryptolib-phase0` (branch `bench/cryptolib-phase0-20261123`). The containers mounted the worktree's `scripts/`, not the main checkout's.
- **Toolchain:** Frama-C 34.0~beta with the curated patch queue, against 35.0~~dev for `phase0-r1`.
- **Machine:** 30 CPUs and 36 GB, against 30 CPUs and 21.6 GB for `phase0-r1`. The QCBOR run-2 was running at the same time, so the wall times are not like for like.
- **Target:** CryptoLib `5b98c8b`, the same revision as every baseline.
- **Harness digest:** it changed (`e917b3bf...` -> `7654165c...`). A JSON diff of the CryptoLib entry against `c5ee34e`, the commit `phase0-r1` records (it was dirty then), shows the `modules` and `profile` unchanged. Only the `compile_commands` asset and key were removed, and `harness_digest()` hashes assets. The pinned harnesses are therefore the same.
- **What "Phase 0 ok" covers here:** the capture, the model, the seeds, the overlay, the DAG, the harness generation, the reach gate, the security properties, the ledger seed, validation and Make generation. `build-check`, the E-ACSL build gate, belongs to the benchmark's later `build` stage and ran in neither pass. The 177 generated cases passed only `api_harness`'s per-case clang probe.

## Phase 0 Numbers Across Runs

| Field | `default` (11-05) | `phase0-i0` (11-07) | `phase0-i5a` | `phase0-i5b` | `phase0-i9` / `i10` | `phase0-r1` (11-08) | **today** |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Compiles captured | - | - | 55 | 55 | 55 | 55 | **55** |
| API entry points (capture) | - | - | 193 | 193 | 193 | 193 | **193** |
| Test units | - | - | 16 | 16 | 16 | 16 | **16** |
| Model functions | - | - | 232 | 232 | 232 | 232 | **232** |
| Direct / indirect call edges | - | - | 273 / 142 | 273 / 142 | 273 / 142 | 273 / 142 | **273 / 142** |
| GCC fallback units | - | - | 0 | 0 | 0 | 0 | **0** |
| Trust (untrusted / trusted functions) | - | - | - | - | 193 / 39 | 193 / 39 | **193 / 39** |
| Seeds recorded from the tests | - | - | - | - | 0 (`not_relinked`) | 0 (`not_relinked`) | **0 (`not_relinked`)** |
| DAG modules | 5 lexer | 5 lexer | 5 lexer | 1 link unit | 1 link unit | 1 link unit | **1 link unit** |
| DAG files / functions / waves | 23 / 232 / 7 | 23 / 232 / 7 | 23 / 232 / 7 | 23 / 232 / 7 | 23 / 232 / 7 | 23 / 232 / 7 | **23 / 232 / 7** |
| Ledger `rte` units | 226 | 226 | 226 | 226 | 232 | 232 | **232** |
| Ledger `l2_termination` units | 66 | 66 | 65 | 65 | 64 | 64 | **72** |
| Ledger `l3_frame` units | - | - | - | - | - | 69 | **85** |
| Ledger `l5` / `l6` units | 9 / 6 | 9 / 6 | 9 / 6 | 9 / 6 | - | - | **-** (no threat model) |
| API entry points the harnesses call directly | - | - | - | - | - | not recorded | **9 / 193** (184 exempt) |

The `default` and `phase0-i0` columns predate the capture and the model, so their DAG came from the lexer. The baselines' unit counts are totals over every status. Today the 389 units are seeded `planned` (387) or `deferred` (2), with none decided, because no later phase ran.

Phase 0 stage times (wall seconds, today against `phase0-r1`):

| Stage | `phase0-r1` | today |
| :--- | :--- | :--- |
| capture | 13.3 | 18.3 (the build itself took 5.8 s) |
| model | 5.9 | 11.7 (parse 9.0 s against 3.5 s) |
| seeds | 2.7 | 3.0 |
| phase0 | 31.2 | 77.3 (overlay 17.1 s, 5 harnesses 25.6 s, reach gate 8.7 s, the rest 6 s) |

The times are slower on the same CPU count. With a concurrent run and different memory, the cause is not established, so read this only as an indication.

## What Changed Since the Baselines

1. **The capture counts, the model, the DAG and the trust split are unchanged since `phase0-i9`.** CryptoLib has one link unit, no GCC fallback, no name collisions and no recursion cycles. Only the header snapshot changed: 12 files before, 17 now, with a new digest (`eaf822c1...`). I did not compare which headers were added. Nothing else there has improved or regressed.
2. **More obligations are seeded:** `l2_termination` went from 64 to 72 and `l3_frame` from 69 to 85. The 85 `l3_frame` units match `security_props.json` (`functions_by_class.l3_frame: 85`; reasons such as "calls memset" and "writes through parameter(s) ..."). I did not trace which pipeline commits added the 8 + 16 units. This means more work for Phase 3, not more coverage.
3. **Risk tiers per function** (from the DAG): 155 Tier 1A, 37 Tier 1B, 18 Tier 2 and 22 Tier 3. The link unit is Tier 1A, `run_wp_full: true`.
4. **No MetAcsl security properties** (0): the benchmark gives CryptoLib no threat model. With one, Layers 4 to 6 would be generated. The baselines up to `phase0-i5b` show 9 `l5` and 6 `l6` units from the earlier default rules.

## Coverage: How Much of the API Phase 0 Puts Under Test

This is the main finding. The pinned recall harnesses call only **9 of the 193** API entry points directly. The other 184 are exempt with the manifest's reason "pinned recall harness ...". Through those 9 entry points, the harnesses reach 46 of `core`'s 168 functions and 10 of `sa`'s 34.

Today's generator does much better on the same unit (run 2):

| | Pinned (run 1) | Generated `--api` (run 2) |
| :--- | :--- | :--- |
| Dispatch cases | 5 harnesses with 9 roots (5 in `core`, 1 in each of the others) | 177 cases in one harness |
| Entry points called directly | 9 / 193 | **164 / 193** |
| Functions statically reached | 46 + 1 + 1 + 1 + 10 over 5 harnesses | **227 / 232** |
| Reach-gate gaps (no exemptions) | 0 (184 exempt) | 29 |

Of the 29 gaps:

- **26** are exported functions that no header declares (`sa_populate`, `update_sa_from_ptr`, `key_validation`, `Crypto_TM_Check_IV_ARSN`, `crypto_free_config_structs`, ...). Their case fails with `call to undeclared function`. **25 of the 29 gaps are still reached through another entry point**, so in practice only 4 entry points are untouched: `Crypto_Config_Cam`, `Crypto_Config_Kmc_Crypto_Service`, `Crypto_TM_Print_CLCW` and `key_validation`.
- **2** take a file-system path (`Crypto_Config_Cam`, `Crypto_Config_Kmc_Crypto_Service`). The generator never passes fuzz bytes as a path, as designed.
- **1** takes an anonymous struct by value (`Crytpo_TC_Validate_TC_Temp_Header`).

Run 2 did not continue past the reach gate, so its ledger seed and the Eva/fuzz reach (the dynamic gate) are not measured.

## Potential Improvements, in Order of Value

1. **Measure CryptoLib with the generated harness.** It calls about 18 times as many entry points as the pinned recall harness. It means a second harness entry next to the recall one, so `CRYPTOLIB-01`'s recall stays measured, plus exemptions or fixes for up to 29 gaps (item 3 removes 26 of them). The Eva and fuzz cost of a 193-case harness is unknown. A Phases 0-2 run would measure it (`phase0-r1` took 16 minutes with the pinned harnesses). Since `44ba2dd`, its configured case 166 is set up the way the pinned `core` harness is (see the fourth rerun), so that run would also show whether the generated harness finds `CRYPTOLIB-01` by fuzzing alone.
2. **Frames for the non-`const` frame parsers:** **fixed on `main`**. `a52178b` fed them the input instead of a zeroed buffer. `44ba2dd` then gave the three `ProcessSecurity` functions the exact-size input itself, instead of a 9216-byte copy in which a read past the frame stayed in bounds (see the third and fourth reruns). Two observations remain open in `main`'s entry: CryptoLib's `sa_save_file.bin`, which carries SA state from one case into the next (target-side), and 20 single cases that dereference the interface pointers `Crypto_Init` sets (`mc_if`, `sa_if`, ...) while they are still NULL.
3. **Declare the functions no header declares:** **fixed on `main` in `8ef9c98`** in [`../../scripts/api_harness.py`](../../scripts/api_harness.py) (reactive `extern` prototype synthesis recorded in `api_headers.synthesized_prototypes`; see [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md)). Takes the generated harness from 164 to about 190 direct entry points.
4. **Seeds from CryptoLib's tests:** **fixed on `main` in `4c88db5`** (see the first rerun below). The 16 unit tests were copied to `build/internal/bin/` and deleted by a CMake `POST_BUILD` step, so the seed recorder found none of them (`not_built`). Every baseline since `phase0-i9` had this.
5. **Keep the recorded global setup in trace-derived cases:** **fixed on `main` in `f7784ce`** for sequence cases (see the second rerun below). The 164 single cases still run without configuration.
6. **A threat model for CryptoLib** would bring back Layers 4 to 6 (0 security properties today) and replace the default trust split (193 untrusted / 39 trusted).
7. **`--phase0-only` comparisons:** **fixed on `main` in `8ef9c98`** in [`../../scripts/benchmark.py`](../../scripts/benchmark.py) and [`../../scripts/benchmark_compare.py`](../../scripts/benchmark_compare.py) (`selection.phase0_only: true`, post-Phase-0 stages reported as `not_compared`, per-stage `stage_time` rows; see [`../troubleshooting/resources-and-infra.md`](../troubleshooting/resources-and-infra.md)).

## Rerun After the Seed Fix (`4c88db5`)

Both passes were rerun from a detached worktree at `c4e7d94` (`main` with `4c88db5` and its troubleshooting entry), as `cl-p0-seeds-20261123` (pinned harness) and `cl-p0-api-seeds-20261123` (generated harness). Same target, toolchain and machine. The QCBOR run-2 was still running.

| Field | Before (`cl-p0-20261123`) | After (`cl-p0-seeds-20261123`) |
| :--- | :--- | :--- |
| Seed status | `not_relinked` | `ok`, `ctest` exit 0 |
| Test units relinked | 0 / 16 (`not_built`) | 16 / 16 |
| Calls recorded (unique) | 0 | 1,031 (222) |
| API functions with seeds | 0 | 36 |
| Trace segments | 0 | 43 |
| Units with `installed_as` | 0 | 17 (the library and 16 tests) |
| Outputs with unchecked architecture | 16 | 0 |
| Seeds stage wall time | 3.0 s | 22.4 s |

The functions with the most unique recorded calls are `Crypto_Config_Add_TC_Gvcid_Managed_Parameters` (33), `Crypto_AOS_ProcessSecurity` (24), `Crypto_TC_ApplySecurity` (22), `Crypto_TM_ProcessSecurity` (20), and `Crypto_Config_Add_AOS_Gvcid_Managed_Parameters` and `Crypto_TC_ProcessSecurity` (16 each). These match the counts in `4c88db5`'s own verification. The generated-harness run recorded 223 unique calls instead of 222; the tests are not quite deterministic. Everything else in Phase 0 is identical before and after: the capture counts, the snapshot, the model, the DAG, the ledger seed (389 units), and the reach of 9/193 pinned and 164/193 generated.

**What the seeds change in the generated harness:** 13 to 29 `sequence` cases (177 to 193 cases). The 29 reach-gate gaps are the same.

**What they do not change yet:** every new sequence case repeats one function, such as `Crypto_TC_ProcessSecurity` 2 to 8 times or `Crypto_TC_ApplySecurity` 2 to 5 times. None keeps the setup the traces recorded before it (`Crypto_Config_CryptoLib > Crypto_Config_TC > Crypto_Config_Add_TC_Gvcid_Managed_Parameters > Crypto_Init`). `api_harness.chains()` links calls only through shared pointers, and CryptoLib's configuration lives in globals. Without that setup, `Crypto_TC_Process_Sanity_Check` (`crypto_tc.c:1661`) returns `CRYPTO_LIB_ERR_NO_CONFIG` at once. A fuzz iteration gets past it only when an earlier input in the same process ran an init case, and Eva does not get past it. This was recorded in [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md) ("Trace-Derived `--api` Sequence Cases Drop the Library's Global Setup") and is fixed by `f7784ce` (next section).

The seed records themselves are written in Phase 0. The fuzz inputs built from them are written later, by the fuzz stage, which this run did not reach. So this run does not show whether the recorded TC frames become useful corpus entries for the pinned `core` harness either.

## Second Rerun After the Global-Setup Fix (`f7784ce`)

The generated-harness pass was rerun from a detached worktree at `a0b0124` (`main` with `f7784ce`, its entry `54b4e65`, and the unrelated fuzz and judge fixes `c83d101`, `ba385e7` and `a0b0124`), as `cl-p0-api-gs-20261123`. The pinned pass was not rerun: `f7784ce` changes only `api_harness.py`, which the pinned harnesses do not use.

**Unchanged:** the seeds (1,031 calls, 222 unique, 36 functions, 43 segments, 16/16 relinked), the capture, the model, the DAG, the 193 cases (164 single, 29 sequence), the reach of 164/193 with the same 29 gaps, and the Phase 0 exit (the reach gate, `rc=1`).

**What changed is the 16 trace-derived sequence cases** (selectors 164 to 179):

| | Before (`cl-p0-api-seeds-20261123`) | After (`cl-p0-api-gs-20261123`) |
| :--- | :--- | :--- |
| Cases that call `Crypto_Config_CryptoLib`, a `Crypto_Config_{TC,TM,AOS}` and a `Crypto_Config_Add_*_Gvcid_Managed_Parameters`, then `Crypto_Init` | 0 | **11** |
| Cases that end with `Crypto_Shutdown` | 0 | 13 |
| Frame entry points with a configured case | none | all six: `Crypto_{TC,TM,AOS}_{Process,Apply}Security` |
| Distinct functions called in sequences | 18 | 27 (adds `Crypto_Get_FSR`, `get_sa_interface_inmemory`, `Crypto_tmPrint`, `Crypto_aosPrint`, ...) |
| Fuzz slots used by the setup calls | - | 0: every setup argument is a recorded literal (scalars, and the packed GVCID structs as `static const` bytes) |

The other 5 are `Config_Add_*_Gvcid > Get_*_Managed_Parameters_For_Gvcid > Shutdown` (2), `Crypto_Init_TC_Unit_Test > Crypto_Calc_CRC16`, `clean_akref > clean_ekref` and `Crypto_saPrint` 6 times. The 13 synthesized lifecycle sequences (180 to 192, `Crypto_Check_Anti_Replay`) are unchanged. The 16-slot cap still binds: the multi-call `Crypto_TC_ApplySecurity` chains and 4 of the 6 `Crypto_TC_ProcessSecurity` repeats gave way to the configured cases.

**So the global-setup gap is closed for sequence cases.** It stays open for the single cases, for example selector 107, `Crypto_TC_ProcessSecurity` alone. Now that every sequence ends with `Crypto_Shutdown`, a single case no longer inherits a configuration from an earlier input either.

**The next gap is the frame itself.** Of the six frame entry points, only `Crypto_TC_ApplySecurity` (selector 167) reads its frame from the fuzz input, because its `p_in_frame` is `const`. The other five get a zeroed `static` 9216-byte buffer:

| Entry point | Frame argument in the generated C | First check after the configuration that a zeroed frame fails |
| :--- | :--- | :--- |
| `Crypto_TC_ProcessSecurity` (172, 179) | zeroed buffer; `int *len_ingest` zeroed too, nothing read from the input | `crypto_tc.c:1670`, `*len_ingest < TC_FRAME_HEADER_SIZE` |
| `Crypto_TM_ProcessSecurity` (164, 176) | zeroed buffer, length from the input | `crypto_tm.c:1225`, GVCID lookup: the frame gives scid 0, the configured GVCID has scid 44 |
| `Crypto_TM_ApplySecurity` (168) | zeroed buffer, length from the input | `crypto_tm.c:906`, same GVCID lookup |
| `Crypto_AOS_ProcessSecurity` (165, 175) | zeroed buffer, length from the input | `crypto_aos.c:1058`, GVCID lookup: the frame gives tfvn 0, the configured GVCIDs have tfvn 1 |
| `Crypto_AOS_ApplySecurity` (166) | zeroed buffer, length from the input | `crypto_aos.c:177`, same GVCID lookup |

These stop points come from reading the generated C and the CryptoLib sources; I did not build or run the harness. `api_harness._is_input` counts a pointer as input only when the model calls it `const_pointer`, and CryptoLib declares these frames `uint8_t *`. The tests do pass real frames there: the recorder kept a length-sized byte buffer of 8 to 1,786 non-zero bytes as argument 0 of every recorded `Crypto_TM_ProcessSecurity` (20 of 20), `Crypto_AOS_ProcessSecurity` (24 of 24) and `Crypto_TM_ApplySecurity` (11 of 12) call. The single cases of the same five functions (selectors 35, 36, 107, 118, 137) zero the frame in the same way, both before and after `f7784ce`, so this is older than the fix and was hidden behind `CRYPTO_LIB_ERR_NO_CONFIG`. The verification note of `54b4e65` reports "deep protocol execution" for the sequence cases; from the generated C, that can hold only for `Crypto_TC_ApplySecurity`. This was recorded as an open gap and is fixed by `a52178b` (next section); `main`'s entry `f28e6d7` corrects the verification note.

## Third Rerun After the Frame-Input Fix (`a52178b`)

The generated-harness pass was rerun from a detached worktree at `f28e6d7` (`main` with `a52178b` and its entry), as `cl-p0-api-nc-20261123`. Again, only the generated C changed. The seeds, the model, the 193 cases (164 single, 29 sequence; the same call lists, though some configured sequences changed selector, for example `Crypto_TC_ApplySecurity` 167 -> 168), the reach of 164/193 with the same 29 gaps, and the Phase 0 exit (`rc=1`, the reach gate) are as in the second rerun.

**All six frame entry points now get their frame from the input**, in their single cases and in the configured sequences:

| Entry point | Before `a52178b` | After |
| :--- | :--- | :--- |
| `Crypto_TC_ApplySecurity` (`const` frame) | `fuzz_buf + fuzz_off`, length `fuzz_len - fuzz_off` | unchanged |
| `Crypto_TC_ProcessSecurity` | zeroed frame, zeroed `int[4]` as `len_ingest` | input copied into a `static` 9216-byte buffer, `int len = rest_n` passed as `&len` |
| `Crypto_TM_ProcessSecurity`, `Crypto_AOS_ProcessSecurity` | zeroed frame, length from the input | input copied into a `static` 9216-byte buffer, length `rest_n` |
| `Crypto_TM_ApplySecurity`, `Crypto_AOS_ApplySecurity` | zeroed frame, length from the input | input copied into `calloc(1, 9216U)` (they call `malloc_usable_size`), length `rest_n` |

The case notes say `writable input buffer: copied from the rest of the input` (`with pointer-to-length` for TC). Those are the generated C's facts. The execution evidence is `main`'s own, in `f28e6d7`: a build under ASan/UBSan of the same harness shape, run on the 134 written seeds, parsed real headers past every stop point listed in the previous section. I did not build or run the harness.

**What is still missing: exact bounds for the `ProcessSecurity` frames.** In the `static` copies, the bytes after the frame, up to byte 9215, are valid zeroed memory. A read one byte past the frame therefore returns 0, and neither ASan nor E-ACSL reports it. That is the kind of defect the recall bug `CRYPTOLIB-01` is: a 5-byte TC frame (`0003000424`) makes `Crypto_TC_Set_Segment_Header` read `ingest[5]` (`crypto_tc.c:1949`). This is read from the generated C, not executed.
- The pinned `core` harness catches it, because it passes an exact-size `malloc` copy of the input.
- The generated harness builds the same exact-size, writable copy as `fuzz_buf` in `LLVMFuzzerTestOneInput`. Only `Crypto_TC_ApplySecurity` uses it directly.
- `fuzz_buf` points one byte into its block (past the selector), so it would not do for the two `ApplySecurity` functions. They pass their buffer to `malloc_usable_size`, and they need a buffer of the configured `max_frame_size` anyway (`crypto_tm.c:954`, `crypto_aos.c:453`).
- Exact bounds alone would not show that the generated harness recovers `CRYPTOLIB-01`. I did not check whether any generated TC case configures the GVCID that bug needs (scid 3, vcid 0, segment headers).
- A smaller limit: in a sequence that calls a frame function several times, only one call gets the frame. Selector 175's second and third `Crypto_AOS_ProcessSecurity` calls still get zeroed frames.

New open gap in [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md) ("`--api` Copies a Non-`const` Input Frame Into a 9216-Byte Buffer"), now fixed by `44ba2dd` (next section).

## Fourth Rerun After the Exact-Bounds Fix (`44ba2dd`)

The generated-harness pass was rerun from a detached worktree at `44ba2dd`, as `cl-p0-api-eb-20261123`. The seeds, the model, the 193 cases (164 single, 29 sequence), the reach of 164/193 with the same 29 gaps, and the Phase 0 exit (`rc=1`, the reach gate) are unchanged. 26 of the 29 sequences have the same call lists as before. The other three changed, as `44ba2dd` intends:
- the TC sequence now registers all four GVCIDs the test registered (vcid 0 to 3) before `Crypto_Init`, then calls `Crypto_TC_ProcessSecurity` seven times;
- `Crypto_Init_TC_Unit_Test` now opens a `Crypto_TC_ApplySecurity` case;
- `Crypto_Calc_CRC16` is now followed by a `Crypto_Shutdown`.

**How each frame entry point gets its frame now** (from the generated C):

| Entry point | Frame | Length |
| :--- | :--- | :--- |
| `Crypto_TC_ApplySecurity` | `fuzz_buf + fuzz_off` (unchanged) | `fuzz_len - fuzz_off` |
| `Crypto_{TC,TM,AOS}_ProcessSecurity` | `fuzz_buf + fuzz_off`, note `the rest of the input (exact bounds)` | the rest of the input (for TC, through `int *`) |
| `Crypto_{TM,AOS}_ApplySecurity` | `calloc(1, 9216U)` copy (unchanged), note `writable heap capacity input buffer` | the rest of the input |
| Later calls of a frame function in one sequence (selector 175 AOS, 179 TC) | an exact-size `malloc(n > 0 ? n : 1U)` copy of the input | that call's length slot |

`fuzz_buf` in `LLVMFuzzerTestOneInput` is an exact-size heap copy of the input, so a read one byte past a `ProcessSecurity` frame now lands outside its block. The two `ApplySecurity` functions keep a capacity buffer, which CryptoLib's own `malloc_usable_size` check requires.

**`CRYPTOLIB-01` from the generated harness.** Case 166 is `Crypto_Config_CryptoLib > Crypto_Config_TC > Crypto_Config_Add_TC_Gvcid_Managed_Parameters > Crypto_Init > Crypto_TC_ProcessSecurity > Crypto_Shutdown`. Its recorded GVCID decodes to:
- tfvn 0, scid 3, vcid 0;
- `has_fecf = TC_HAS_FECF`, `has_segmentation_hdr = TC_HAS_SEGMENT_HDRS`, `max_frame_size` 1024.

That is the configuration of the pinned `core` harness. The frame is the whole input after the selector byte, with `*len_ingest` set to its length. So the input `0xA6` (selector 166) followed by `0003000424` hands `Crypto_TC_ProcessSecurity` the bug's 5-byte frame at the end of its heap block. `44ba2dd`'s own verification ran exactly that and reports the read at `crypto_tc.c:1949` under ASan (`heap-buffer-overflow`, `READ of size 1`) and E-ACSL (`\valid_read(ingest + *byte_idx): 0`). I checked the configuration and the argument binding in the generated C, and did not build or run it myself. Whether fuzzing finds that input without being given it needs the fuzz stage.

## Not Measured

The run measured none of the following: Eva properties, alarms and dead code (in `phase0-r1`, Eva analysed 45 of 234 functions from `core` and 27 from `sa`, and the rest was dead after an `Invalid`), fuzz candidates, `CRYPTOLIB-01` recall, dynamic reach and prover tasks. They need the Phases 0-2 run.

## Artifacts

- Run files: `~/framac-pipeline/benchmark/results/cl-p0-20261123.json`, `~/framac-pipeline/benchmark/results/cl-p0-api-20261123.json`
- Run directories: `~/framac-pipeline/benchmark/runs/cl-p0-20261123/cryptolib/run-1`, `~/framac-pipeline/benchmark/runs/cl-p0-api-20261123/cryptolib/run-1`
- After the seed fix: `~/framac-pipeline/benchmark/results/cl-p0-seeds-20261123.json` and `cl-p0-api-seeds-20261123.json`, with the matching run directories
- After the global-setup fix: `~/framac-pipeline/benchmark/results/cl-p0-api-gs-20261123.json`, with the matching run directory. The generated harness is `workspace/harnesses/harness_libcryptolib_so.{c,json}`.
- After the frame-input fix: `~/framac-pipeline/benchmark/results/cl-p0-api-nc-20261123.json`, with the matching run directory.
- After the exact-bounds fix: `~/framac-pipeline/benchmark/results/cl-p0-api-eb-20261123.json`, with the matching run directory.
- The second validation run `r2v` of [`./2026-11-08-phase0-remediation.md`](./2026-11-08-phase0-remediation.md) is the only earlier CryptoLib run not in the table. It was not stored as a baseline, and its run file is no longer in `~/framac-pipeline/benchmark/results`. That report gives only `status ok -> partial` (`reach-dynamic-core` with no coverage) and 1028 s.
- The run directories hold no other earlier CryptoLib run. The two `framac-build:CryptoLib-*` images from 2026-11-22 have no matching run directory or result file under `~/framac-pipeline`.
