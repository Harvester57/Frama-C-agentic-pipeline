# Address-Flow Unit Split: Correction Plan

- **Plans index:** [`./README.md`](../README.md)
- **Original design:** [`./unit-split-address-flow.md`](../unit-split-address-flow.md)
- **Review findings:** [`./unit-split-address-flow-review.md`](./unit-split-address-flow-review.md) (verdict: **Rework**, blocking issues `B1`–`B9`)
- **Base branch:** `claude/unit-split-indirect-edges` (`63cddeb`..`d1466bd`, on top of `origin/main` `7957660`)
- **Implementation branch:** `fix/unit-split-address-flow` (commits `3dc1bfd` [C1], `a921072` [C2], `bb81795` [C3], `9462e81` [C4], `7aa4b3d` [C5], `36ba45f` [C6], `9b4a184` [C7.1], `e10d660` & `1fbe43a` [C7.2 nginx build fixes], plus C7.3 docs; merged to `main` on 2026-11-20 in `f956747`).
- **Status:** Implemented (`C0`–`C7` complete); decisions settled as **D1(b)**, **D2(a)**, **D3(a)**, **D4(a)**. See [`./unit-split-address-flow.md`](../unit-split-address-flow.md) Section 2 and Section 6 for measured real nginx 1.31.9 dump-schema-6 and C7.2 validation numbers.

This plan turns the nine blocking issues (`B1`–`B9`) and non-blocking defects recorded in [`./unit-split-address-flow-review.md`](./unit-split-address-flow-review.md) into ordered, independently testable implementation steps (`C0`–`C7`) for future implementation.

---

## 1. Decisions to Settle Before Coding

| # | Question | Options | Recommendation |
| :--- | :--- | :--- | :--- |
| **D1** | How `flow_reach` closes **B2** (callbacks stored in locals or structs passed to external libraries) and **B3** (function-pointer casts across differing C signatures). | **(a)** Targeted AST rule: follow `cast_address_refs` (B3) plus `address_refs` of reached functions that make pointer-taking external calls (B2). **(b)** Follow all `address_refs` of reached function bodies unconditionally, keeping signature-pool filtering only for global initializers (`ngx_modules[]`, module tables). | **Measure (a) vs. (b) in C0** on real nginx dump-schema-6 data. Pick **(b)** if the within-limit nginx clusters stay within limits with comparable `build_sources` (simpler and structurally eliminates B2/B3 even across helper functions); otherwise pick **(a)**. |
| **D2** | How `api_harness` chooses cross-cluster struct initializers and destructors on an address-flow cluster (**B7**). | **(a)** Prefer candidates already inside `sub["functions"]`, or cross-cluster helpers whose combined `flow_reach` stays within `MAX_FUNCTIONS` and `MAX_LINES`; never auto-select an `over_limit` cross-cluster initializer (`ngx_init_cycle`, `ngx_http_upstream_init`) for a within-limit cluster. **(b)** Keep whole-unit selection and accept 58–124 file re-inflation. | **(a)** — otherwise `api_harness` re-inflates clusters on 125+ nginx entry points. |
| **D3** | Producer-consumer splits that drop unit-reachable runtime callbacks into `unclustered` (**B8**, e.g. `api_register` in C1 sets `g_cb = secret_cb`, `api_run` in C2 calls `g_cb()`). | **(a)** Add a within-limit rescue merge pass for producer/consumer pairs that uncover `cross_cluster_unclustered` callbacks, and record any remaining ones explicitly in `unit.split["cross_cluster_unclustered"]` with a DAG warning. **(b)** Record and warn only. | **(a)** — preserves library recall without breaking the size cap. |
| **D4** | Merge capping on pre-schema-6 models (on nginx run-5's old model, unconditional capping produces Option C's 108 clusters instead of Option A's 2). | **(a)** Keep capped merges in `call_graph` mode too, with a warning recommending re-running `phase0_model.py`. **(b)** Apply capped merges only in `address_flow` mode. | **(a)** — matches the split's Eva calibration; document the `phase0_model.py` rerun requirement. |

---

## 2. Dependency Order and Parallelism

```text
C0 (Step 0: real nginx dump-schema-6 measurement; settles D1)
  |
  v
C1 (AST & model: phase0_dump.ml, phase0_model.py, model schema)
  |
  +---> C2 (DAG & reach: build_callgraph_dag.py, unit_split.py, DAG schema)
  |       |
  |       +---> C3 (Harnesses: api_harness.py, generate_harness.py)
  |       +---> C6 (Eva gate: run_eva_slice.py)
  |
  +---> C4 (Stubs, .bss globals, single-pass E-ACSL, coverage: fuzz_build.py, fuzz_coverage.py)
  +---> C5 (Crash triage & ledger: failure_identity.py, crash_replay.py, run_eacsl_fuzz.py, ledger.py)
          |
          v
C7 (End-to-end Docker counterexample suite, real nginx validation, docs & skill mirrors)
```

Steps `C2`, `C4`, and `C5` own disjoint files and can execute in parallel once `C1` lands. Steps `C3` and `C6` can execute in parallel once `C2` lands.

---

## 3. Rules for Every Step

- **One branch/worktree per step** (or sequential commits on a rework branch cut from `claude/unit-split-indirect-edges` `d1466bd`).
- **Generated-text and doc guardrails:** edit files only with file-writing tools (no shell heredocs), keep LF line endings, no emojis, explicit `./` or `../` links in Markdown, and sync skill mirrors (`python tools/sync_skill_mirrors.py`) whenever [`../../skills/`](../../../skills/framac-slice/SKILL.md) changes.
- **Standard checks** after every step (Windows PowerShell with `$env:PYTHONIOENCODING="utf-8"`):

  ```text
  ruff check
  ruff format --check scripts tests
  mypy scripts tests tools
  python -m pytest tests -n auto
  python tools/check_generated_text.py
  python tools/sync_skill_mirrors.py --check
  python -m pytest tests/test_docs_structure.py tests/test_extract_references.py -n auto
  ```

---

## 4. Implementation Steps

### C0. Step 0 Measurement — Real Nginx Dump-Schema-6 Run (Settles D1, Prerequisite for B9)

- **Goal:** Replace the ELF-relocation approximation in [`./unit-split-address-flow.md`](../unit-split-address-flow.md) with real Frama-C AST schema-6 facts on nginx 1.31.9, and measure **D1(a)** vs. **D1(b)** before changing the reach algorithm.
- **Code changes:** None (read-only measurement in an isolated scratch run directory; never write to `run-5`).
- **Work:**
  1. Mount `run-5/workspace/work` and `run-5/workspace/snapshot` read-only into a scratch run directory and run [`../../scripts/phase0_model.py`](../../../scripts/phase0_model.py) (`phase0_dump.ml` schema 6) on `objs/nginx` inside `framac-analysis:latest` with explicit timeout and a dedicated `FRAMAC_RUN_TAG`.
  2. Diff the resulting AST `address_refs`, `global_refs`, `init_functions`, and `init_globals` against the ELF-derived counts in [`./unit-split-address-flow.md`](../unit-split-address-flow.md) Table 2.1.
  3. Run `unit_split.apply` on the real nginx schema-6 model under three variants: current branch reach, **D1(a)**, and **D1(b)**. Record cluster counts, `over_limit` count, function/line distributions, `build_sources` counts, and `link_stubs` counts.
- **Stop / Decision rule:** If **D1(b)** keeps the within-limit cluster set within thresholds and close to current `build_sources` counts, adopt **D1(b)** in `C1`/`C2`; otherwise adopt **D1(a)**.

---

### C1. AST & Model Completeness (`B1` cross-parse, `B2`/`B3` AST facts, `B5` global sizes, `B8` constructors & fallback globals)

- **Goal:** Record complete AST facts in dump schema 6 and resolve cross-parse function/global references soundly in `phase0_model.py`.
- **Owns:** [`../../scripts/phase0_dump.ml`](../../../scripts/phase0_dump.ml), [`../../scripts/phase0_model.py`](../../../scripts/phase0_model.py), [`../../schemas/phase0_model.schema.json`](../../../schemas/phase0_model.schema.json), [`../../tests/test_phase0_model.py`](../../../tests/test_phase0_model.py).
- **Changes:**
  1. **`scripts/phase0_dump.ml`:**
     - On each `GVar (vi, _, loc)` in `globals[]`, emit `"size"` (`I n` from `bytes_of vi.vtype` when known, else omit or `null`) so `fuzz_build.py` can emit accurately sized type-free `.bss` stubs in `C4`.
     - On each defined function, emit `"constructor": B (Cil.hasAttribute "constructor" vi.vattr)` so `unit_split.py` treats startup constructors in compiled files as reach roots (`ce7_ctor`).
     - If **D1(a)** is chosen in `C0`: in `note_expr`, track `CastE (t, e')` where `e'` (after stripping nested casts) is `AddrOf (Var v, NoOffset) | StartOf (Var v, NoOffset)` with `is_fun_var v` and `canon t <> canon (TPtr (v.vtype, []))`; emit `"cast_address_refs"` on functions and `"init_cast_functions"` on globals.
  2. **`scripts/phase0_model.py`:**
     - Pass each parse's `units` in `pending_refs`.
     - In `resolve_refs`: when a kernel name `k` in `fnames` (`address_refs`, `init_functions`, and `cast_address_refs` if present) is absent from `kmap`, resolve it across linked units via `self._lookup_global(u, k)` (matching `resolve()`'s linker lookup; fixes `ce4_xparse` / **B1**). Note: `phase0_dump.ml` emits `v.vname` (kernel name); for `extern` functions not defined in the parse, CIL preserves the C symbol name, matching `self.globals`.
     - In `resolve_refs`: when a global name `k` in `gnames` has `gmap.get(k) is None` and `len(cands) == 0`, check whether any unit in the parse's link closure (`self.closure[u]`) failed Frama-C parsing (`gcc_fallback` / `unparsed`); if so, add `k` to `unresolved_global_refs` (instead of silently dropping it like `errno`; fixes **B8**).
     - Carry `size` on `global_variables`, `constructor` on `functions`, and `cast_address_refs` / `init_cast_functions` if D1(a) is chosen.
     - Update `selftest()` to verify `size`, `constructor`, static-local tables, compound literals, and cast refs in `framac-analysis:latest`.
  3. **`schemas/phase0_model.schema.json`:**
     - Add optional `size` (`{"type": ["integer", "null"], "minimum": 1}`) to `global_variables` items (`additionalProperties: false` requires updating the schema).
     - Add optional `constructor` (`{"type": "boolean"}`) and (if D1(a)) `cast_address_refs` / `init_cast_functions`.
- **Acceptance:**
  - New unit tests in [`../../tests/test_phase0_model.py`](../../../tests/test_phase0_model.py): cross-parse `address_refs` (`prog` referencing `libcore.a`), `global_refs` naming a global when a linked unit is `gcc_fallback`, `size` propagation, `constructor` propagation, and schema validation against `phase0_model.schema.json`.
  - `phase0_model.selftest()` passes in `framac-analysis:latest`.

---

### C2. DAG & Address-Flow Reach Rework (`B1` linked libraries, `B2`/`B3` reach, `B6` `.inc` sources, `B8` constructors & producer-consumer)

- **Goal:** Make `unit_split.flow_reach` and `unit_split.build_plan` sound across linked libraries, external callbacks, function-pointer casts, `#include`d `.inc`/`.h` definitions, startup constructors, and producer-consumer splits.
- **Owns:** [`../../scripts/build_callgraph_dag.py`](../../../scripts/build_callgraph_dag.py), [`../../scripts/unit_split.py`](../../../scripts/unit_split.py), [`../../schemas/callgraph_dag.schema.json`](../../../schemas/callgraph_dag.schema.json), [`../../tests/test_dag_model_view.py`](../../../tests/test_dag_model_view.py), [`../../tests/test_unit_split.py`](../../../tests/test_unit_split.py).
- **Changes:**
  1. **`scripts/build_callgraph_dag.py` and `schemas/callgraph_dag.schema.json`:**
     - Declare `indirect_callees`, `address_refs`, `global_refs`, `constructor`, and (if D1(a)) `cast_address_refs` in `schemas/callgraph_dag.schema.json` under `definitions.function.properties`, plus `size` and `compiled_in` under `global_variables`, `linked_functions` (or `linked_modules`) under `definitions.module.properties`, and `cross_cluster_unclustered` under `split`.
     - Map any global variable or non-static header/included function whose `file` does not end in `.c` to the `.c` translation unit(s) compiling it (from `build_capture.json` `compiles[].headers` and `compiles[].defined_functions`), recorded as `compiled_in: list[str]` (fixes `ce4_inc` and `MPACK_INLINE`-style definitions; **B6**).
     - Record each link unit's linked project module names (`linked_modules`) on `modules[name]`, and carry `constructor` and `size` into DAG `functions` / `global_variables`.
     - When any unit in a module's link closure is `gcc_fallback` or `unparsed`, omit `address_refs` on that module's functions (or have `unit_split.has_flow_facts` check the full link closure) so the unit falls back cleanly to `call_graph`.
  2. **`scripts/unit_split.py`:**
     - **B1 (linked project libraries):** In `apply` and `cluster`, compute `within_all` = the unit's own functions plus all functions of its `linked_modules` (transitively). Run `flow_reach` over `within_all` so direct calls and callbacks into linked libraries are followed to a fixpoint. Keep `sub["functions"]`, `function_count`, `lines`, tiers, and reach-gate scope restricted to `reached & own_keys` (or decide whether linked-library size counts toward Eva limits — counting linked-library functions in `build_sources` ensures `generate_harness` and Eva always include the reached library `.c` files). In `build_plan`, collect defining `.c` files for **all** `reached` functions (unit + linked libraries) and `globs`, and exclude linked-library functions that were reached from `link_stubs`.
     - **B2 & B3 (casts & external callbacks):** Implement **D1** as settled by `C0`:
       - Under **D1(b)**: add `rec.get("address_refs")` directly to `work` (within `within_all`) when reached, keeping `indirect_callees & pool` filtering for global-initializer `init_functions`.
       - Under **D1(a)**: follow `cast_address_refs` (and `init_cast_functions`) whenever any indirect call is reached, and follow `rec.get("address_refs")` whenever `rec` has a pointer-taking external call (`external_callees` non-empty outside pure-value libc functions).
     - **B6 (`.inc` / `.h` definitions):** In `build_plan`, replace the `endswith(".c")` filter with a helper `_defining_c_files(rec)` returning `[file]` when `file.endswith(".c")`, else `rec.get("compiled_in") or []`. Never list a reached global or function in `link_stubs`.
     - **B8 (constructors):** In `build_plan` / `flow_reach`, if any compiled `.c` file in `build_sources` defines a function with `constructor: true`, add it to `starts` and re-run `flow_reach` to fixpoint so startup-registered callbacks join `build_sources` (`ce7_ctor`).
     - **B8 (producer-consumer `unclustered`, D3):** After Step 2 (overlap merging) and before Step 3 (packing), compute `unit_reached = flow_reach(all entries)` and `lost = unit_reached - union(c["functions"])`. While `lost` is non-empty, try merging a producer cluster (whose `address_refs` or `globals` contain a function `f in lost`) with a consumer cluster (whose `indirect_callees` contain `f`) if the merged reach fits `max_functions` and `max_lines`. Any function still in `unit_reached - covered` after clustering is recorded in `rec["split"]["cross_cluster_unclustered"]` with a warning in `dag["warnings"]`.
- **Acceptance:**
  - Unit tests in [`../../tests/test_unit_split.py`](../../../tests/test_unit_split.py) and [`../../tests/test_dag_model_view.py`](../../../tests/test_dag_model_view.py) covering every counterexample shape (`ce1`, `ce2`, `ce3`, `ce4_inc`, `ce4_prodcons`, `ce7_ctor`), schema validation via `validate_artifacts.validate_dag`, and verification that unsplit small libraries stay unchanged.

---

### C3. Harness Sources & `api_harness` Synchronization (`B1`, `B6` harness globals, `B7`)

- **Goal:** Prevent `api_harness` cross-cluster struct initializers from re-inflating narrowed clusters back to whole-program builds, include harness-referenced globals in `_flow_harness_sources`, and keep `harness_<mod>.json` synchronized with `fuzz_build`.
- **Owns:** [`../../scripts/api_harness.py`](../../../scripts/api_harness.py), [`../../scripts/generate_harness.py`](../../../scripts/generate_harness.py), [`../../tests/test_api_harness.py`](../../../tests/test_api_harness.py), [`../../tests/test_api_harness_unit_initializers.py`](../../../tests/test_api_harness_unit_initializers.py), [`../../tests/test_unit_split.py`](../../../tests/test_unit_split.py).
- **Changes:**
  1. **`scripts/api_harness.py` (B7 / D2):**
     - Pass the cluster record (when `module` is an `address_flow` entry in `dag["submodules"]`) and split limits (`dag["unit_split"]`) into `initializers()` and `struct_destructors()`.
     - For a within-limit `address_flow` cluster (`"over_limit" not in sub`):
       - Rank in-cluster candidates (`key in sub["functions"]`) ahead of cross-cluster candidates.
       - Reject any cross-cluster initializer/destructor whose combined `unit_split.flow_reach(anchors + [cand])` exceeds `max_functions` or `max_lines` (blocking `ngx_init_cycle`, `ngx_http_upstream_init`, etc.).
       - Record a case note (`"initializer <fn> skipped: cross-cluster reach exceeds cluster limit"`) whenever a candidate is filtered out.
     - Keep existing behavior unchanged for non-split units and `over_limit` clusters.
  2. **`scripts/generate_harness.py` (B1, B6, B7):**
     - In `_merge_dag_harness_sources`: match `referenced_idents` against both `functions_map` and `dag["global_variables"]` (by `name` and `file#name`), passing matched global ids to `_flow_harness_sources` as initial `extra_globals` (fixes `ce6_silent`).
     - In `_flow_harness_sources`: run `unit_split.flow_reach` over the unit's full link closure (`within_all`, B1) starting from `anchors + extra_fns` and seeded with `extra_globals`, then take `unit_split.build_plan(...)["build_sources"]`.
     - When `extra_fns` or `extra_globals` widens `sub["build_sources"]`, record `flow_build_sources` (tree-relative paths) in `harness_<mod>.json` so `fuzz_build._flow_cluster_files` sees the exact widened set, and emit a stderr warning if the widened reach exceeds `dag["unit_split"]` thresholds.
- **Acceptance:**
  - Tests in [`../../tests/test_api_harness_unit_initializers.py`](../../../tests/test_api_harness_unit_initializers.py) and [`../../tests/test_unit_split.py`](../../../tests/test_unit_split.py) proving: (i) an oversized cross-cluster initializer is rejected for a within-limit cluster while an in-cluster or small cross-cluster initializer is still chosen; (ii) `--dispatch-case "(void)api_use(&g_cfg);"` pulls `src/cfg.c` and its initializer callback `src/cb.c` into `sources`; (iii) widened `flow_build_sources` is persisted in `harness_<mod>.json`.

---

### C4. E-ACSL-Safe Stubs, Type-Free `.bss` Globals, Single-Pass Build & Coverage Fix (`B4`, `B5`, `B7`, `B8`, `B9`)

- **Goal:** Make `link_stubs.c` work identically in ASan/UBSan, full E-ACSL, and coverage builds; replace broken header-based `link_globals.c` for address-flow clusters with type-free `.bss` assembly definitions; eliminate double E-ACSL instrumentation; and fix symbol-lookup edge cases.
- **Owns:** [`../../scripts/fuzz_build.py`](../../../scripts/fuzz_build.py), [`../../scripts/fuzz_coverage.py`](../../../scripts/fuzz_coverage.py), [`../../tests/test_link_repair_flow_stubs.py`](../../../tests/test_link_repair_flow_stubs.py), [`../../tests/test_coverage_link_repair.py`](../../../tests/test_coverage_link_repair.py).
- **Changes:**
  1. **E-ACSL-safe function stubs (`fuzz_build.py`, B4 — verified in `framac-analysis:latest`):**
     - In `link_stubs_source`: replace `fprintf(stderr, ...)` with unbuffered `write(2, ...)` (`#include <unistd.h>`, `#include <stdlib.h>`) printing `FRAMAC_LINK_STUB_CALLED: <name> (not in the unit split's address-flow reach)\n` and calling `abort()`.
     - In `_discover_slice_functions`: skip `p.name == LINK_STUBS_FILE` and `name == "__framac_link_stub_called"` so E-ACSL never instruments `__framac_link_stub_called` (and never triggers `validate_format_string_argument` on unregistered `.rodata`).
  2. **Type-free `.bss` global stubs for address-flow clusters (`fuzz_build.py`, B5 — verified in `framac-analysis:latest`):**
     - Extend `link_stubs_source(fn_stubs, global_stubs=(), module=None)` to emit `.bss` definitions for unreached cluster globals:
       ```asm
       .bss
       .balign 16
       .globl <name>
       .type <name>, @object
       .size <name>, <size>
       <name>: .zero <size>
       ```
       using `size` from `phase0_model.json` `global_variables[].size` (defaulting to `16` bytes when `size` is null/unknown, e.g. incomplete arrays like `ngx_modules[]`).
     - In `repair_sources_for_link`: when `flow_files is not None` and `_place_global` returns `"stub"`, route the global into `link_stubs.c` (`stubbed_flow_globals`) instead of `link_globals.c`, completely bypassing non-self-contained headers and by-value struct rejection (`ce5_globals`). Keep `link_globals.c` unchanged for non-flow cross-unit globals.
  3. **Synchronized `flow_files` (`fuzz_build.py`, B7):**
     - In `_flow_cluster_files(dag_path, module, sources=None)`: union DAG `sub["build_sources"]`, sidecar `harness_<module>.json`'s `flow_build_sources` (if present), and the tree paths of the initial non-harness `sources` passed to the build.
  4. **Symbol-lookup hardening (`fuzz_build.py`, B8):**
     - In `_dag_symbol_files`: skip functions with `rec.get("is_static") is True` so static functions never shadow extern functions or extern globals (`ce8_static_clash`).
     - Return `build_only_functions` separately from DAG parsed functions in `repair_sources_for_link` so a `build_only` function is **never** stubbed in `link_stubs.c` (its `.c` file is linked as before).
     - Never stub a function defined in a linked library unit unless that symbol is explicitly outside `flow_files` *and* in `sub["link_stubs"]["functions"]` (defense in depth for B1).
  5. **Eliminate double E-ACSL instrumentation (`fuzz_build.py`, B9):**
     - Add `_preseed_flow_stubs(sources, dag_path, out_bin, link_module)` called at the start of `build_module_binary` and `build_coverage_binary`: when `link_module` is an `address_flow` cluster with non-empty `sub["link_stubs"]`, compute the subset of `sub["link_stubs"]` whose defining files are not in the initial `sources`, write `<out_bin>_link_globals/link_stubs.c` up front, and append it to `sources` before Attempt 1. Record `"preseeded_stubs"` in the build result. Any unexpected residual undefined symbol still uses `repair_link_rounds`.
  6. **Coverage exclusion (`fuzz_coverage.py`):**
     - In `_coverage_file_role`: return `"harness"` when `posixpath.basename(path) in (LINK_STUBS_FILE, LINK_GLOBALS_FILE)` or `"_link_globals/" in f"/{path}"`.
- **Acceptance:**
  - Unit tests in [`../../tests/test_link_repair_flow_stubs.py`](../../../tests/test_link_repair_flow_stubs.py) and [`../../tests/test_coverage_link_repair.py`](../../../tests/test_coverage_link_repair.py) covering `.bss` globals, static-name collision, `build_only_functions`, Attempt-1 pre-seeding (verifying `compile_eacsl_binary` is called once, not twice), `_discover_slice_functions` exclusion, and `_coverage_file_role`.

---

### C5. Crash Triage & Ledger Pipeline-Defect Classification (`B4` / Design Open Item 2)

- **Goal:** Ensure any `FRAMAC_LINK_STUB_CALLED` abort is classified as a pipeline reach defect, never fingerprinted or ingested as a target vulnerability candidate.
- **Owns:** [`../../scripts/failure_identity.py`](../../../scripts/failure_identity.py), [`../../scripts/crash_replay.py`](../../../scripts/crash_replay.py), [`../../scripts/run_eacsl_fuzz.py`](../../../scripts/run_eacsl_fuzz.py), [`../../scripts/ledger.py`](../../../scripts/ledger.py), [`../../tests/test_failure_identity.py`](../../../tests/test_failure_identity.py), [`../../tests/test_crash_replay.py`](../../../tests/test_crash_replay.py), [`../../tests/test_ledger.py`](../../../tests/test_ledger.py).
- **Changes:**
  - Follow the existing `parse_eacsl_resource_abort` / `eacsl_resource_abort` architecture:
    1. In `failure_identity.py`: add `parse_link_stub_abort(text: str) -> dict | None` matching `^FRAMAC_LINK_STUB_CALLED:\s+(?P<symbol>[A-Za-z_]\w*)` (anchored at line start) and extracting `{symbol, message, caller}` (first non-runtime, non-`__framac_link_stub_called` frame from `_STACK_FRAME_RE`). Update `parse_runtime_failure` to return `None` when `parse_link_stub_abort(text)` matches (preventing a target `failure` or fingerprint).
    2. In `crash_replay.py` and `run_eacsl_fuzz.py`: detect `parse_link_stub_abort(out)` alongside `parse_eacsl_resource_abort(out)` and record `entry["link_stub_abort"] = record` on the artifact.
    3. In `ledger.py` (`ingest-fuzz`): filter out artifacts carrying `link_stub_abort` (or matching `parse_link_stub_abort(replay_log_tail)`) before creating target candidates; count them in `stats["link_stub_aborts"]` and record a pipeline-defect warning (`link_stub_aborts: [...]`) naming the module, stubbed symbol, and caller so the run flags the reach defect visibly.
- **Acceptance:**
  - Unit tests in [`../../tests/test_failure_identity.py`](../../../tests/test_failure_identity.py), [`../../tests/test_crash_replay.py`](../../../tests/test_crash_replay.py), and [`../../tests/test_ledger.py`](../../../tests/test_ledger.py) using real ASan and E-ACSL stderr excerpts from `verify_plan_ideas.py`, confirming `failure is None`, `link_stub_abort["symbol"] == "far_fn"`, and zero target candidates created.

---

### C6. Eva Missing-Body & Missing-Global Soundness Gate (`B6` / Design Open Item 3)

- **Goal:** Make an address-flow reach miss loud in Phase 2 (Eva), matching the loudness of `FRAMAC_LINK_STUB_CALLED` in Phase 1.
- **Owns:** [`../../scripts/run_eva_slice.py`](../../../scripts/run_eva_slice.py), [`../../tests/test_eva_slice.py`](../../../tests/test_eva_slice.py).
- **Changes:**
  1. Add `reject_address_flow_gaps(res, out_dir, module, dag_path, sources)` in `run_eva_slice.py`, modelled after `reject_stub_from_defects`, active only when `module` is a DAG submodule with `reach == "address_flow"`:
     - **Missing project bodies:** Parse `missing_spec_messages(eva_log)` and intersect with project functions defined in the unit or its `linked_modules` (excluding external libc/package functions). If non-empty, set `res["missing_project_bodies"]`, downgrade `status` from `"ok"` to `"analysis_error"` with `reason = "address_flow_missing_body"`, and prepend actionable lines to `error_summary`.
     - **Missing project globals:** Using the post-Eva `flows` / `inout` inputs of `eva_main` (when available), check whether any read global matches a project global in `dag["global_variables"]` whose defining `.c` file is not in `sources`. If non-empty, set `res["missing_project_globals"]` and set `status = "analysis_error"` with `reason = "address_flow_missing_global"`.
- **Acceptance:**
  - Unit tests in [`../../tests/test_eva_slice.py`](../../../tests/test_eva_slice.py) verifying that (i) an external libc missing spec does not trigger the gate, (ii) a project function missing body in an `address_flow` cluster turns `status: "ok"` into `analysis_error` (`address_flow_missing_body`), and (iii) reading an omitted project global turns `status: "ok"` into `analysis_error` (`address_flow_missing_global`).

---

### C7. End-to-End Docker Counterexample Suite, Real Nginx Validation & Docs (`B9`)

- **Goal:** Prove every counterexample from the review stays fixed end-to-end in `framac-analysis:latest`, validate real nginx 1.31.9 clusters through Phase 0 -> E-ACSL build -> fuzz -> coverage -> Eva, and bring all docs and skills into sync.
- **Owns:** `tests/test_unit_split_docker.py` (new, `@pytest.mark.integration`, gated on `FRAMAC_DOCKER_TESTS=1`), [`./unit-split-address-flow.md`](../unit-split-address-flow.md), [`../guides/slicing-and-onboarding.md`](../../guides/slicing-and-onboarding.md), [`../../skills/framac-slice/SKILL.md`](../../../skills/framac-slice/SKILL.md) (plus `.agents/` and `.claude/` mirrors via `sync_skill_mirrors.py`), [`../troubleshooting/phase0-build-and-model.md`](../../troubleshooting/phase0-build-and-model.md).
- **Work:**
  1. **Docker integration suite (`tests/test_unit_split_docker.py`):** Encode every counterexample (`ce1` linked library, `ce2` local/struct external callback, `ce3` function-pointer cast, `ce4_inc` included `.inc` global, `ce5` nginx-shaped non-self-contained header + by-value struct global, `ce6` dispatch-case global, `ce7` `__attribute__((constructor))`, plus deliberate stub-hit test in both ASan and E-ACSL verifying `FRAMAC_LINK_STUB_CALLED` and `parse_link_stub_abort`, plus deliberate omitted-body Eva test verifying `address_flow_missing_body`).
  2. **Real nginx 1.31.9 validation (isolated scratch run dir, dedicated `FRAMAC_RUN_TAG`, explicit timeouts):**
     - Run `phase0_model.py` (dump schema 6) + `build_callgraph_dag.py` on nginx 1.31.9.
     - Run `generate_harness.py --api` on at least two within-limit clusters (e.g., `nginx__ngx_bpf` and `nginx__ngx_connection` or `nginx__ngx_conf_file`) and verify `sources` stays narrowed (no `ngx_init_cycle` blowup).
     - Build both clusters with `build_module_binary(..., engine="auto")` and verify: single E-ACSL instrumentation pass, `rc=0`, wall clock and peak RSS well below the 3600 s / 10 GiB failure from run-5.
     - Run a short fuzz pass + `coverage` (verify zero `link_stub_aborts` and no `link_stubs.c` in target coverage) and `run_eva_slice.py` (verify `address_flow_missing_body`/`missing_global` gate passes).
  3. **Documentation updates:**
     - Update [`./unit-split-address-flow.md`](../unit-split-address-flow.md) with real dump-schema-6 nginx measurements, fix Option A (`135 -> 137` target sources, not `134 -> 136`) and indirect-edge counts (`4753` type-match / `4761` total indirect), document the updated stub/global-`.bss`/Eva-gate/triage behavior, and record the policy for the remaining single-anchor `over_limit` clusters (Design Open Item 4).
     - Update [`../guides/slicing-and-onboarding.md`](../../guides/slicing-and-onboarding.md), [`../../skills/framac-slice/SKILL.md`](../../../skills/framac-slice/SKILL.md) (run `python tools/sync_skill_mirrors.py`), and [`../troubleshooting/phase0-build-and-model.md`](../../troubleshooting/phase0-build-and-model.md).

---

## 5. Final Merge Gate

The reworked branch is ready to merge into `main` only when all of the following pass:

1. `ruff check` and `ruff format --check scripts tests` clean.
2. `mypy scripts tests tools` clean.
3. `python -m pytest tests -n auto` green.
4. `FRAMAC_DOCKER_TESTS=1 python -m pytest tests/test_unit_split_docker.py tests/test_phase0_model.py -n 4` green.
5. `python tools/check_generated_text.py`, `python tools/sync_skill_mirrors.py --check`, and `python -m pytest tests/test_docs_structure.py tests/test_extract_references.py -n auto` green.
6. Real nginx 1.31.9 scratch validation (`C7` item 2) recorded with measured E-ACSL build time, peak RSS, zero `link_stub_aborts`, and passing Eva gate.
