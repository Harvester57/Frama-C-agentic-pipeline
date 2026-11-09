# Tier 6: Cross-Run Proof Carry-Forward

Self-contained implementation plan. Parent document: [`../formal-discovery-plan.md`](../formal-discovery-plan.md) (Section 3, Tier 6). Independent of the other tiers; it is the "publishing swept WP proofs" item of milestone M5 in [`../v2-design.md`](../v2-design.md) (Section 9) and [`../resources-and-caching.md`](../resources-and-caching.md) (Section 5, "WP results never reach the shared store today").

## Goal

The paper's wiki lets a new team start from the best verified solution. The pipeline re-derives every contract on every run. Publish each function's contract from the trusted end-of-run `wp-sweep` into the content-addressed cache, and on the next run re-apply and **re-prove** cached contracts on the current tree before any prover is dispatched. A cached proof never changes a verdict on its own: it only saves prover time.

New A/B switch: `FRAMAC_PROOF_CARRY` (`off` disables both publishing and replay; default on). The shared store is only written with the existing `FRAMAC_CACHE_MODE=rw`.

## Facts the implementer must know (verified 2026-11-09)

- `scripts/cache.py`: `enabled(cwd)`, `shared_mode()` (`off` / `ro` / `rw`), `lookup(ns, key, cwd, include_run=True) -> Entry | None` (run store first, then shared), `publish(ns, key, files: dict[name, Path], data: dict, key_material=None, cwd=None) -> bool` (run store, and shared when `rw`), `restore(entry, dest: dict[name, Path]) -> bool` (digest-checked), `make_key(ns, material) -> str` which **always folds in `toolchain_id()` and `scripts_digest()`** (a digest of `scripts/` and `templates/`), `normalized_source_digest(path, target_functions)` (digest of a C file with ACSL unrelated to the target functions stripped), `dependency_manifest(...)`, `file_digest(path)`. `Entry.data` is the published `data` dict; `Entry.path` the entry directory. Namespaces today: `eacsl-build`, `eva`, `facts`, `slice-index`, `guardrail`, `wp` (Frama-C's own `-wp-cache-dir`, counted only). LRU collection per store.
- `scripts/pipeline_make.py`: `sweep(run_dir, jobs, runner, plan, script_runner)` builds entries via `sweep_list(run_dir)` (`{"file", "function", "module", "coverage_ids", "eva_only"?}` for every `covered` unit with discharging WP evidence, plus Eva-covered callees of hypothesis-carrying callers), re-proves each with `run_wp_function.py --cache-dir off ... --out-json workspace/reports/wp-sweep/<slug>__<fn>.json`, then classifies rows into `results` (`status`), `regressions`, `missing`, `newly_wp_proven`, ingests regressions with `ledger.py ingest-wp --sweep`, runs `ledger.py audit-hypotheses`, writes `workspace/reports/wp-sweep/summary.json`. `plan.wp_cppflags_for(module)` and `plan.wp_extra_sources_for(module)` give the flags; `infer_prover_wp_flags(run_dir, c_file, function)` the extra WP flags. `WORK_DIR` is `workspace/work`.
- `scripts/acsl_ast.py`: `function_contract_text(source, function, is_header)` returns the contract text of a definition or prototype; `extract_top_level_acsl_declarations(source)` lists top-level `predicate` / `logic` / `lemma` / ... with `name`; `splice_prover_changes(base, agent, current, fn, is_header, path, contract_only)` is the function-scope splicer used by `merge-agent`.
- `scripts/workspace_overlay.py`: `init_agent_overlay(run_dir, agent_id, overlay)` copies `workspace/work/` to `agents/<id>/scratch/{work,base}`; `merge_agent_overlay(run_dir, agent_id, role, overlay_dir, c_file, function, header_file, module, sources, cppflags, ldflags, skip_reverify, allow_partial_wp, contract_only)` splices the agent's span and runs `_run_parent_reverify` (guardrail + WP on the merged tree, publishes the canonical `workspace/reports/wp/<fn>.json`); CLI `merge-agent`.
- `scripts/wp_scheduler.py`: prove tasks are created for `(file, function)` pairs whose ledger units are `planned` (around line 1009); units already `covered` get no task. `ledger.py ingest-wp <reports>` credits units from WP reports; evidence records carry `phase`, `result`, `discharging`.
- `scripts/c_definitions.py`: `extract_functions_from_code(raw_code)` lists definitions with their text spans (for a body-only digest if `normalized_source_digest` proves too coarse).
- Run layout: `run-metadata.json` marks a run directory; `agents/<id>/...`; the parent is the only writer of the ledger (`run_lock("ledger")`).

## Design decisions (fixed; do not re-open during implementation)

1. **Only `wp-sweep` publishes.** It is the trusted step with the final tree and no proof cache. Prover scratch results, merged-but-not-swept functions and `--allow-partial-wp` merges are never published.
2. **Key = what the proof depends on, not the whole file.** Material: `normalized_source_digest(work/<file>, [fn])`; for each direct callee resolved in the DAG, the digest of its `function_contract_text` (definition and, when present, header prototype); the digests of every top-level ACSL declaration whose `name` occurs in the function's contract or body annotations; the effective WP cppflags and extra WP flags; the machdep and WP model. `make_key` adds the toolchain and scripts digests on its own: accept that a pipeline change invalidates the proof store in this version (safe, and the store refills on the next sweep). Do not add an exemption.
3. **Replay re-proves on the current tree.** A hit is applied as a contract-only splice into a parent-owned scratch agent and goes through the normal `merge-agent` re-verification (guardrail + WP). Only an `all_proven` re-verification credits the units, with evidence `phase="wp"`, `result="carried_forward_reproven"`, `discharging=True`, and `tool_output` naming the cache entry. Anything else leaves the units `planned` and the prover runs as before.
4. **Replay happens before scheduler state is built** so that credited units never become prove tasks. It is a Make phase (`wp-replay`) between the Phase 3 gate and `wp_scheduler.py init`, static job class `wp`.

## Changes

### 1. Publishing (`scripts/pipeline_make.py`, new module `scripts/proof_carry.py`)

- `proof_carry.py` (stdlib only):
  - `proof_key_material(run_dir, overlay, file, function, module, cppflags, wp_extra_flags, dag) -> dict | None` (the material of decision 2; `None` when any input is missing, in which case nothing is published or looked up).
  - `publish_proof(run_dir, overlay, entry: dict, sweep_report: Path, cppflags, wp_extra_flags) -> bool`: builds the key, writes `contract.json` = `{"file", "function", "module", "contract_c": <definition contract text>, "contract_h": <prototype contract text or null>, "header_file", "top_level_decls": [{"name","kind","text"}], "wp_report_status": "all_proven", "swept_at", "run_id"}`, and calls `cache.publish("proofs", key, {"contract.json": path, "wp_report.json": sweep_report}, data={"function": ..., "file": ..., "module": ...}, key_material=material)`.
  - `lookup_proof(run_dir, overlay, file, function, module, cppflags, wp_extra_flags, dag) -> Entry | None`.
- `pipeline_make.sweep`: after the results loop, when `FRAMAC_PROOF_CARRY != off` and `cache.enabled()`, publish every row with `status == "all_proven"` and not `eva_only`; add `summary["published_proofs"] = N` and a per-row `published: bool`. Publishing failures are warnings, never a sweep failure.

### 2. Replay (`scripts/proof_carry.py`, `scripts/pipeline_make.py`)

- `proof_carry.replay(run_dir, overlay, plan, jobs) -> dict`: for each `(file, function, module)` with a `planned` unit in the ledger (reuse the scheduler's planned-pair selection; import or duplicate the small query), compute the key, `lookup_proof`; on a hit, `restore` the entry's files into `state/proof-carry/<slug>__<fn>/`, create agent `carry-<n>` via `init_agent_overlay`, splice `contract_c` over the function's current contract in the agent's `scratch/work/<file>` (build the "agent text" by replacing the current contract span with the cached one; use `locate_function_span` + `function_contract_text`), likewise `contract_h` for the prototype when `header_file` is set, and add missing `top_level_decls` to the header via the architect dedup path only if their names are absent (if a same-named declaration exists with different text, skip this hit: record `reason: "declaration conflict"`). Then run `merge_agent_overlay(..., role="prover", contract_only=True)`; on success, `ledger.py ingest-wp` is already done by the merge path with the canonical report; **replace** the evidence `result` on the credited units with `carried_forward_reproven` and append `tool_output` = the cache entry path. On failure (`ScopeViolationError`, guardrail, WP not `all_proven`), remove the agent and leave the units `planned`. Write `workspace/reports/proof-carry/summary.json` with `hits`, `reproven`, `rejected: [{file, function, reason}]`, `misses`.
- New Make phase `wp-replay` in `pipeline_make.py` (same registration pattern as `wp-sweep`: phase order number, summary path `workspace/reports/proof-carry/summary.json`, static job class `wp`, pool size from `resources.recommend()`), run before `wp_scheduler.py init`. With `FRAMAC_PROOF_CARRY=off`, the phase writes a summary with `skipped: true` and exits 0.

### 3. Scheduler and report

- `wp_scheduler.py`: no behaviour change. Add `carried_forward` to `status` output: count of covered units with `carried_forward_reproven` evidence (read-only).
- `generate_report.py`: in the coverage summary, one line `- Carried forward from earlier runs and re-proven: N function(s)`.

### 4. Flag plumbing and docs

- `FRAMAC_PROOF_CARRY` in `wrappers/framac-docker.ps1`, `wrappers/framac-docker.sh`, `docker-compose.yml`, `tests/test_remediation_p2_container.py` (`AB_SWITCHES`, `env.update`), and `docs/resources-and-caching.md` Section 4.
- `docs/resources-and-caching.md` Section 5: new `proofs` namespace row (what it stores, who writes it, what invalidates it); update the "WP results never reach the shared store" paragraph.
- `docs/v2-design.md` Section 9 and the M5 row of the milestone table: carry-forward of swept proofs implemented; per-unit ledger carry-forward still open.
- `docs/architecture.md` / Make phase list: add `wp-replay`.

## Tests (`-n auto`, no container)

- `tests/test_proof_carry.py` (new):
  - Key stability: same inputs → same key; a changed callee contract, a changed body, a changed cppflag, or a changed referenced predicate each change the key; an unrelated function's annotation in the same file does not (`normalized_source_digest` strips it).
  - Publish: with a fake run store (`tmp_path`, `FRAMAC_CACHE=on`), `publish_proof` writes `contract.json` and `wp_report.json`; nothing is published for a non-`all_proven` row or when `FRAMAC_PROOF_CARRY=off`.
  - Replay: a hit whose contract splices cleanly and whose injected `merge_agent_overlay` returns success → units credited with `carried_forward_reproven`; a hit whose merge fails → units stay `planned`, agent directory removed, `rejected` row with reason; a declaration conflict is skipped with its reason; a miss is counted.
  - Never writes outside the run directory (assert no files under the shared root when `FRAMAC_CACHE_MODE=ro`).
- `tests/test_pipeline_make.py` (existing module for Make phases): `wp-replay` is registered before the scheduler init step and after the Phase 3 gate; `sweep` summary carries `published_proofs`.
- `tests/test_remediation_p2_container.py`: switch forwarded.

## Verification

```powershell
$env:PYTHONIOENCODING="utf-8"
python -m pytest tests/test_proof_carry.py tests/test_pipeline_make.py tests/test_remediation_p2_container.py -n auto
python -m pytest tests -n auto
python -m ruff check scripts tests
python -m mypy scripts tests
```

Acceptance: run a target twice with `FRAMAC_CACHE_MODE=rw`. The second run's `workspace/reports/proof-carry/summary.json` shows `reproven > 0`; its `REPORT.md` coverage equals or exceeds the first run's; `wp-sweep` of the second run re-proves every carried function (`regressions` empty for them); `benchmark.py compare` between the two runs shows timing `improvement` or `info` rows and no `regression`. With `FRAMAC_PROOF_CARRY=off` the second run behaves exactly like the first.

## Out of scope

Carrying forward ledger verdicts or findings (M5 "per-unit ledger carry-forward"); sharing prover scratch candidates; publishing from anything other than `wp-sweep`; cross-target reuse (keys include the file digest, so identical vendored functions across targets may hit by construction; that is acceptable and needs no special handling).

## Implementation notes (2026-11-09): plan facts that turned out wrong, and what was done instead

- **The key could not use the plan's material as written.** `normalized_source_digest(work/<file>, [fn])` keeps the target function's own annotations, so the key published by run 1's sweep (annotated tree) would never be the key run 2 looks up before Phase 3 (fresh tree): nothing would ever hit. Likewise the referenced top-level declarations and the inferred extra WP flags (`infer_prover_wp_flags` reads the run's own earlier WP reports and ledger assumptions) are not known on a fresh tree. Implemented key: the C tokens of the file and of its header with every annotation and comment stripped (`proof_carry.c_tokens_digest`), the current contracts of the direct callees, the module's WP cppflags and extra sources, the machdep; `make_key` adds toolchain and scripts digests. The declarations are payload (conflict check on replay), and the extra WP flags are reproduced by seeding the agent's `scratch/wp_<fn>.json` with the swept report, which `infer_prover_wp_flags` reads first. Callee contracts work because replay runs callees first: a carried callee's contract is on the tree when its caller is looked up.
- **`merge_agent_overlay` does not ingest into the ledger.** The scheduler ingests `res["parent_wp_report"]` itself (`_on_merged`). `proof_carry.replay` does the same through `ledger.py ingest-wp`, then the new `ledger.py mark-carried`.
- **`contract_only=True` would drop loop invariants.** They live in the body, and a swept proof of any function with a loop depends on them. Replay splices the whole annotated definition span with `contract_only=False`; the ACSL-only and scope checks of the merge still forbid any C change.
- **Evidence `tool_output` must be a file inside the run directory** (`validate_artifacts._exists`), so it cannot name the cache entry. It stays the parent WP report of the re-proof (what justifies the credit); the restored entry (`state/proof-carry/<file>__<fn>/contract.json`) and its key go under `details.proof_carry`.
- **`wp-replay` is not a static job.** Its merge runs the parent guardrail, which executes target code. It is classed dynamic in `resources.py` (`_DYNAMIC_MAKE_TARGETS`), and so is `wp-queue`, which depends on it; `run ingest wp-queue` was removed from the read-write shared-cache allowlist, since that container would now run target code with a writable store. The Make recipe still leases one `wp` job.
- **"Between the Phase 3 gate and `wp_scheduler.py init`".** Both are in the `wp-queue` recipe. `wp-replay` is a prerequisite of `wp-queue` with its own gate check, and its recipe is prefixed with `-` so a replay problem never stops the queue.
- **Pool size from `resources.recommend()`** was not used: every replay goes through `merge_agent_overlay`, which holds the run-wide merge lock, so replays are sequential.
- **Report line** is printed only when at least one function was carried forward, so reports of runs without carry-forward are unchanged.
- **Benchmark acceptance** (two runs with `FRAMAC_CACHE_MODE=rw`, `benchmark_compare.py`) was not run: out of scope for the implementation change; listed in `docs/backlog.md`.
