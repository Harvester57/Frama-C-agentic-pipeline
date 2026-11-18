# libmodbus run-1: the model that lost its CodeQL facts

Recorded from `libmodbus-d4227309de07 / run-1-f3ba5cce4b09` (2026-11-18), the run of the troubleshooting
entry "A Rebuilt Phase 0 Model Silently Drops the CodeQL Trust Facts and the Report Says `CodeQL: off`".
Used by `tests/test_codeql_trust_rebuild.py`.

| File | What it is |
|---|---|
| `codeql_trust.json` | The run's `workspace/reports/codeql_trust.json` as `codeql_trust.py run` wrote it: `status: ok`, 25 facts on 14 functions, of which 13 facts name 8 functions of the model (the others are `main` of test programs). |
| `phase0_model.json` | The run's `workspace/reports/phase0_model.json` as the rebuild at 02:41 left it: `trust.codeql` is `{"status": "off"}` and no function has a `codeql` source. Reduced: the sections `indirect_sites`, `external_decls`, `external_formals` and `global_variables` and the per-function fields `call_sites`, `formals`, `writes` and `param_sizes` are removed (trust reads none of them). Nothing else is changed. |
| `run-metadata.json` | The run's metadata (`codeql.enabled` and `open_source` true). `target` and `run_dir_host` are replaced by generic paths. |
| `THREAT_MODEL.md` | The structured `framac-threat-model` block of the threat model the run used (`/target/.security-reviews/20261118T003542Z-nogit/ThreatModel.md`), without its prose. Its sha256 therefore differs from the one the model recorded; the tests supply it as `workspace/THREAT_MODEL.md`. |

With this threat model, annotating the model without CodeQL gives back the recorded trust of all 120
functions; with the facts, 8 functions gain `codeql` in `sources` and no `value`, `source` or `boundary`
changes.
