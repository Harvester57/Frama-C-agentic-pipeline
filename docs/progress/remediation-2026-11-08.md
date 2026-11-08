# Phase 0 remediation R1–R10 and validation V (2026-11-08)

Plan: [`docs/phase0-remediation-plan.md`](../phase0-remediation-plan.md). Decisions D1′ (R1–R10, one V, then merge) and D8 (drop the pre-I9 classes).

## Steps landed (branch `phase0-redesign`, local, not pushed)

| Step | Commit(s) | What |
| :--- | :--- | :--- |
| R1 | `c689c1b` | Phase 0 checkpoint recorded by build-check; gated guidance mode; DAG digest in reach rows; exemption matcher |
| R2 | `ea9be7b` | `ledger.py seed --refresh`; fuzz ingest of renamed statics (defect 11); seed refusals; D8 in the ledger and schemas |
| R3 | `152970e` | Per-file trust (defect 9); one recorded threat model (path + sha256); invalid threat model stops `security_props` |
| R4 | `27f443d`, `f0cbf3c` | Model `schema_version` 2 and `model_features`; resumable `no_unit_parsed`; "Phase 0 parse" report section; unread DAG fields dropped, including `indirect_callees`, `cross_module_callees`, `entry_trust` (the skill now points at the fields that carry the same facts) |
| R5 | `630e09e`, `a2c0ca2` | Six new schemas; `validate_artifacts run-dir` checks every Phase 0 artifact; producers record schema problems as warnings; `scope_files`; `infer_unit` by DAG key |
| R6 | `b3298c1` | Fuzz side: snapshot headers out of coverage, replay fallback, campaign gate |
| R7 | `3c68074` | WP: sub-module gating (defect 13), header architects, D8 goal classes |
| R8 | `47d7c89`, `f0cbf3c` | Capture timeout retry, generated headers in the snapshot, scratch volume in the images, CI builds both images |
| R9 | `28101de` | Benchmark runs the skill's Phase 0 sequence; replays merge per run; seeded corpus in `tests/fixtures` |
| R10 | `9b67328` | Docs, skills and comments follow the code; D2–D5 and defect 14 recorded |

Also: `aa5cd53` (mypy-clean tests), `9eddc62` (API-reach rerun report).

Checks at `9b67328`: ruff, `ruff format --check`, `mypy scripts tests` clean; unit suite 2228 passed, 38 skipped (20 s with `-n auto`, pytest-xdist).

## Validation V (running)

Script: rebuild both images → `FRAMAC_DOCKER_TESTS=1 python -m pytest` → seeded set (`seeded-r2v`) → the ten benchmark targets (`r2v-<target>`), each compared with `r1v-<target>`. Baseline `phase0-r2` is recorded once V passes. The merge into `main` waits for the user's go-ahead.

Results so far (21:15, HEAD `9b67328`):

- Images: both built.
- Docker tests (`FRAMAC_DOCKER_TESTS=1`): 2290 passed, 41 skipped (236 s).
- Seeded set (`seeded-r2v`): bugs found 8/8, decoys fired 0/4.
- Targets, `r2v` against `r1v` (`benchmark_compare.py`):

| Target | rc | Wall | Compare |
| :--- | :--- | :--- | :--- |
| minmea | 0 | 191 s | MINMEA-01/02/03 still found; fingerprints changed (the harness changed) |
| oscs-jsmn | 0 | 407 s | no regression |
| oscs-semver | 0 | 180 s | no regression |
| oscs-stmr | 0 | 143 s | no regression |
| oscs-qlz | 0 | 118 s | status ok → partial: `reach-dynamic-quicklz` "no coverage (no_inputs)" |
| x509-parser | 0 | 200 s | status ok → partial: `x509-common` executed 7 of 51 API entry points (gate reopened); queue rc=1 |
| cryptolib | 0 | 1028 s | status ok → partial: `reach-dynamic-core` "no coverage (coverage_error)" |
| qcbor-master | 0 | 181 s | no regression |
| qcbor-dev | — | — | running |
| oscs-tweetnacl | — | — | pending |

Each "partial" comes from the `coverage` stage, which since R9 (`28101de`) also runs `reach-dynamic`. The `r1v` runs predate R9 and never ran that gate, so these are new checks failing, not lost results. Each still needs a diagnosis before the baseline:
- qlz: the campaign stops at its first crash, and there are no recorded seeds (`no_calls_recorded`), so the coverage binary has no inputs. The error row is also missing from `harness_reach_dynamic.json` (`modules: {}`).
- x509: a real reach gap. 44 entry points of `x509-common` were never executed.
- cryptolib: the coverage build or run of `core` failed.
