# Validation run V on `phase0-redesign` (2026-11-08)

Step V of `docs/phase0-remediation-plan.md`, per D1: today's tree (`c5ee34e`, with defects 1–8 and 15–20 fixed) before the merge.

## Verdict

**Ready to merge.**
- 0 regressions against `phase0-i10` on all 10 targets.
- Recall unchanged: 9 of 9 decided bugs retained.
- Seeded set: 8/8 bugs found, 0/4 decoys fired.
- Docker-backed suite green.
- Baseline `phase0-r1` recorded.

## What ran

- **Images:** `framac-analysis:latest` and `framac-build:latest`, rebuilt from the tree first, since the Dockerfile copies `scripts/` in.
- **`FRAMAC_DOCKER_TESTS=1 python -m pytest`:** 2125 passed, 41 skipped, 0 failed, in 4m22s.
- **Benchmark:** `benchmark.py run --target <t> --run-id r1v-<t>`, one target at a time. Run files are in `poc/phase0/out/checkouts/results/r1v-*.json`.
- **Seeded set:** `benchmark.py seeded --run-id seeded-r1v`, with 8/8 bugs found and 0/4 decoys fired.

| Target | Wall (s), I10 → r1v | Recall retained | Units by class, I10 → r1v | Compare |
| :--- | :--- | :--- | :--- | :--- |
| cryptolib | 958 → 975 | 1 → 1 | rte 232, l2 64 → + l3_frame 69 | 9 info |
| oscs-semver | 178 → 189 | – | rte 33, l2 6 → + l3_frame 8 | 3 info |
| minmea | 192 → 180 | 3 → 3 | rte 22, l2 4 → + l3_frame 8 | 5 info |
| qcbor-dev | 555 → 530 | 3 → 3 | rte 374, l2 43 → + l3_frame 167, l5_sanitized 1 | 28 info |
| qcbor-master | 182 → 177 | 2 → 2 | rte 12, l2 2 → same | 2 info |
| x509-parser | 238 → 219 | – | rte 210, l2 45 → + l3_frame 115 | 18 info |
| oscs-jsmn | 411 → 403 | – | rte 6, l2 3 → + l3_frame 6 | 4 info |
| oscs-stmr | 149 → 147 | – | rte 15, l2 3 → + l3_frame 2 | 1 warning (CPU), 3 info |
| oscs-qlz | 118 → 117 | – | rte 18, l2 6 → + l3_frame 9 | 7 info |
| oscs-tweetnacl | 144 → 153 | – | rte 61, l2 30 → + l3_frame 24 | 6 info |

The other figures match I10 on every target:
- RTE and L2 unit counts;
- proved units per wave;
- functions with an Unknown;
- the DAG's function count, flags and verifiability classes.

## Unit-count changes, explained

- **New `l3_frame` units on 9 targets, and one `l5_sanitized` on qcbor-dev (defect 5).**
  - In I10, `security-props` never ran before `seed`, so the ledger had no Layer 3–6 units. The I10 runs have no `security_props.json`.
  - Make now runs it first (`cf9c2cd`), so each function in the props' `frame` list gets an `l3_frame` unit. qcbor-dev's threat model adds one Layer 5 sanitization property.
  - **qcbor-master shows none.** Its 159 frame functions get ledger units, but all of them are `out_of_scope`, as 729 of its 747 ledger entries are. The benchmark leaves out-of-scope units out of its counts.
  - **Strict rates:**
    - minmea wave 0 drops from 60% to 50%, with 3 units proved before and after; the new units add to the count.
    - qcbor-dev wave 5 drops from 7.7% to 7.1% for the same reason.
- **More queued prover tasks:** cryptolib +7, qcbor-dev +34, jsmn +3, stmr +1, qlz +1. These are the new frame units' WP tasks.

## Other differences, explained

- **CryptoLib: 6 new `harness_core.c#unknown_function::unparsed_crash` candidates** (4 → 10 fuzz candidates).
  - **What they are:**
    - E-ACSL "deadly signal" crashes on 137- or 280-byte inputs;
    - none crashes again when replayed alone on the same binary (`not_reproduced`);
    - each stays a candidate for a verifier, not a finding.
  - **They come from fuzzing variance, not the fixes:**
    - `harness_core.c` is byte-identical to I10's;
    - both runs have empty seed records;
    - the E-ACSL campaign reached 412 coverage points against 314.
  - **A guess:** a crash that needs earlier inputs fits CryptoLib's global SA state.
- **Fuzz candidate churn:**
  - minmea loses one `minmea_getdatetime` signed-overflow candidate, but MINMEA-01..03 are all retained;
  - semver keeps 65 leak candidates with different fingerprints;
  - qcbor-dev goes from 43 to 47, and qcbor-master from 46 to 43; `IEEE754_SingleToHalf` shift fingerprints change on both;
  - qlz swaps one `fast_write` fingerprint for another.
- **oscs-stmr CPU 260 s → 417 s (the only warning).**
  - The fuzz stage takes 232 → 389 s of CPU with the same sizing: 7 workers, 7 jobs, 30 s.
  - Its wall time drops from 88 s to 79 s, and the target's wall time is unchanged (149 → 147 s).
  - This is fuzzing variance.
- **No `checkpoint` stage:** expected; `60107a9` removed the unconditional phase-2 checkpoint.

## The plan's expected changes

| Check | Result |
| :--- | :--- |
| `l3_frame` units (defect 5) | Present on 9 targets; see above. |
| `harness_module` in replay results (defect 8) | Present in the benchmark's replay results (`bench/replay*`). |
| QCBOR-02/03 on qcbor-dev | Both retained, 3 of 3 on qcbor-dev. |
| More `shell_unverifiable_wp` functions (defect 2) | Not exercised: classes are identical. The DAG computes the new `has_backward_goto` / `has_container_of` / `has_volatile_or_asm` facts, and none is true on any target. A source scan agrees: gotos are forward, CryptoLib's `volatile`s are globals, and there is no `asm` or `container_of`. |
| Fallback deferrals (defect 6) | Not exercised: no target has a GCC-fallback unit. |
| WP refused on stale harnesses (defect 16) | Not exercised: a clean run has no stale harness. Unit tests cover it (`test_wp_scheduler`, `test_phase0_gates`). |
| Embedded API on tweetnacl (defect 19) | No visible effect: tweetnacl's executable lists 26 embedded API functions, but it has no header functions to reach and no seed recording (no tests stage). Unit tests cover it (`test_dag_model_view`, `test_seed_harvest`). |
| Remapped-id warnings (defect 20) | None on any target: capture and model ids agree. |

Five of the eight checks have nothing to fire on in this benchmark. The fixes are pinned by the unit tests and the Docker-backed suite. A target that exercises them (a GCC-fallback unit, a backward goto) would be a useful benchmark addition.

## Left for you

- **The merge of `phase0-redesign` into `main`:** local only, nothing pushed.
