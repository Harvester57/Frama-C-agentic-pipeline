# Target Run Reports, Validation Logs & Pipeline Postmortems

- **Documentation Hub:** [`../README.md`](../README.md)
- **Confirmed Target Advisories:** [`../bugs-found/README.md`](../bugs-found/README.md)
- **Pipeline Troubleshooting Catalog:** [`../troubleshooting/README.md`](../troubleshooting/README.md)

This directory contains chronological engineering reports from running the pipeline on real-world C targets and benchmark validation suites:
- **Pipeline postmortems:** root-cause analyses when a target run exposed defects in harness generation, build capture, coverage replay, or E-ACSL instrumentation.
- **Validation & milestone logs:** benchmark comparison runs verifying major pipeline changes (`phase0-redesign`, `api-reach`, `R1`-`R10`).
- **Target run assessments:** full verdict reviews and triage dossiers from end-to-end target runs before upstream disclosure.

> [!NOTE]
> Verified vulnerabilities in target C repositories live in [`../bugs-found/`](../bugs-found/README.md), and reusable symptom/cause/fix entries for pipeline issues live in [`../troubleshooting/`](../troubleshooting/README.md). New files added here must use the `YYYY-MM-DD-<target-or-topic>.md` naming convention.

---

## Chronological Index

| Date | Target / Scope | Kind | Summary | Report |
| :--- | :--- | :--- | :--- | :--- |
| 2026-11-06 | `libssh2` (`run-1`) | Pipeline postmortem | Six Phase 1/2 build & E-ACSL blockers (`PB-1`..`PB-6`: function-pointer declarators, foreign `compile_commands` paths, link repair, `-include` libc re-registration, `alignof` on OpenSSL opaque handles, variadic fallback regexes) and their verified fixes. | [`./2026-11-06-libssh2-pipeline-blockers.md`](./2026-11-06-libssh2-pipeline-blockers.md) |
| 2026-11-08 | Phase 0 (`I5a`, `I5b`) | Milestone log | Cross-module Eva status placement by line range and link-unit DAG module transition across all 10 benchmark targets. | [`./2026-11-08-overnight-phase0-i5.md`](./2026-11-08-overnight-phase0-i5.md) |
| 2026-11-08 | `phase0-redesign` (`r1v`) | Validation run | Pre-merge validation run V across 10 benchmark targets and 8 seeded projects (`phase0-r1` baseline recorded, 0 regressions). | [`./2026-11-08-phase0-validation-r1.md`](./2026-11-08-phase0-validation-r1.md) |
| 2026-11-08 | `tweetnacl`, `qlz`, `x509-parser` | Milestone & run log | Generalizing `--api` dispatch harnesses, executable seed harvesting, `param_sizes`, and call-sequence synthesis (`api_reach` 1/25 -> 25/26 on TweetNaCl). | [`./2026-11-08-api-reach.md`](./2026-11-08-api-reach.md) |
| 2026-11-08 | Phase 0 (`R1`-`R10`, `r2v`) | Validation & remediation log | Post-redesign remediation steps `R1`-`R10` and second full validation run (`r2v` vs `r1v`). | [`./2026-11-08-phase0-remediation.md`](./2026-11-08-phase0-remediation.md) |
| 2026-11-08 | `libpng` (`run-2`) | Pipeline postmortem | Round 1 diagnosis of `generate_harness.py` pulling sibling executable `main` sources and skipping auto-prelude on CMake multi-tool targets. | [`./2026-11-08-libpng-harness-sources-bug.md`](./2026-11-08-libpng-harness-sources-bug.md) |
| 2026-11-09 | `libpng` (`run-3`) | Pipeline postmortem | Round 2 diagnosis of four remaining Phase 0 Step 4 harness generation defects on `libpng` (`libpng18_a` sub-modules + 9 CLI tools). | [`./2026-11-09-libpng-harness-generation-bugs.md`](./2026-11-09-libpng-harness-generation-bugs.md) |
| 2026-11-09 | `QCBOR` (`run-4`) | Pipeline postmortem | Root-cause analysis of unsound `--api` by-value struct/context bindings, 64-case fuzz skip-mask cap, and partial-coverage dynamic reach gate failure. | [`./2026-11-09-qcbor-run4-fuzz-campaign-and-api-harness.md`](./2026-11-09-qcbor-run4-fuzz-campaign-and-api-harness.md) |
| 2026-11-09 | `QCBOR` (`run-4` -> `run-5`) | Run progress log | Landing fixes `18bc5e9` for `run-4` defects `A`-`E` and progressing `QCBOR` `run-5` through Phases 0-2 and the 29-candidate Crash Verification Gate. | [`./2026-11-09-qcbor-run4-progress.md`](./2026-11-09-qcbor-run4-progress.md) |
| 2026-11-09 | `QCBOR` (`run-5`) | Target findings dossier | Full technical dossier reviewing all 30 candidate/verdict records produced by `QCBOR` `run-5`. | [`./2026-11-09-qcbor-run5-findings-review.md`](./2026-11-09-qcbor-run5-findings-review.md) |
| 2026-11-09 | `QCBOR` (`run-5`) | Target verdict assessment | Independent source + ASan/UBSan/MSan re-evaluation of the 30 `run-5` verdicts, identifying 9 distinct upstream QCBOR bugs staged in [`../upstream/qcbor/`](../upstream/qcbor/README.md). | [`./2026-11-09-qcbor-run5-assessment.md`](./2026-11-09-qcbor-run5-assessment.md) |
