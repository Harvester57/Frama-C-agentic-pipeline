# Review of `claude/unit-split-indirect-edges` (Address-Flow Unit Split)

- **Reviewed branch:** `claude/unit-split-indirect-edges` (`63cddeb`..`d1466bd`, 5 commits on top of `origin/main` `7957660`)
- **Design reviewed:** [`./unit-split-address-flow.md`](../unit-split-address-flow.md)
- **Background:** [`../troubleshooting/phase0-build-and-model.md`](../../troubleshooting/phase0-build-and-model.md) ("The Unit Split Leaves One Cluster With Almost the Whole Program"), [`../runs/2026-11-19-nginx-run5-supervision.md`](../../runs/2026-11-19-nginx-run5-supervision.md)
- **Files audited:** [`../../scripts/unit_split.py`](../../../scripts/unit_split.py), [`../../scripts/phase0_dump.ml`](../../../scripts/phase0_dump.ml), [`../../scripts/phase0_model.py`](../../../scripts/phase0_model.py), [`../../scripts/build_callgraph_dag.py`](../../../scripts/build_callgraph_dag.py), [`../../scripts/generate_harness.py`](../../../scripts/generate_harness.py), [`../../scripts/fuzz_build.py`](../../../scripts/fuzz_build.py), [`../../schemas/phase0_model.schema.json`](../../../schemas/phase0_model.schema.json), [`../../schemas/callgraph_dag.schema.json`](../../../schemas/callgraph_dag.schema.json), [`../../skills/framac-slice/SKILL.md`](../../../skills/framac-slice/SKILL.md), [`../guides/slicing-and-onboarding.md`](../../guides/slicing-and-onboarding.md), and the new/modified tests.
- **Note on index:** [`./README.md`](../README.md) was left untouched so this review branch commits only this file; add an index entry if this document is merged.

## Verdict Summary

**Verdict: Rework.** Do not merge `claude/unit-split-indirect-edges` in its current form.

The core direction (extracting per-function `address_refs`/`global_refs` and per-global initializer references in dump schema 6, capping overlap merges, and narrowing per-cluster reach) is promising, and Frama-C CIL handles several non-trivial C patterns (such as `static` locals and compound literals) cleanly under `phase0_dump.ml`. However, running concrete C fixtures through the real pipeline in `framac-analysis:latest` and auditing the nginx run-5 artifacts exposed **nine blocking issues** across soundness, E-ACSL runtime instrumentation, real-target linkability, and harness widening:

1. **B1 (Soundness, direct calls):** Any split unit that links another project library drops all linked-library `.c` files from `build_sources` and replaces direct calls into that library with aborting link stubs (and bodyless calls in Eva).
2. **B2 (Soundness, external library callbacks):** Callbacks stored in a local variable or struct passed to an external library (including nginx's own `z_stream.zalloc`/`zfree` and `sigaction.sa_handler` callbacks) get no `callback-arg` edge and are replaced by aborting link stubs.
3. **B3 (Soundness, function-pointer casts):** Any address-taken function cast to a different function-pointer signature before an indirect call is omitted from `build_sources` and replaced by an aborting stub (and left bodyless in Eva), even though reached code explicitly took its address.
4. **B4 (E-ACSL runtime defect):** In a real `fuzz_build.py` E-ACSL build, `_discover_slice_functions` instruments `__framac_link_stub_called`; E-ACSL's `--validate-format-strings` aborts inside `fprintf` on the unregistered `.rodata` stub string **before** printing `FRAMAC_LINK_STUB_CALLED`, and `failure_identity.py` classifies the abort as a real target `mem_access` RTE bug.
5. **B5 (Broken link repair on nginx):** `link_globals.c` cannot build real nginx clusters: 45 of 155 non-static nginx globals (`struct ngx_module_s`) are rejected as `unresolved`, and 104 depend on non-self-contained nginx headers that fail to compile standalone.
6. **B6 (Silent semantic corruption in harnesses, `.inc` definitions, and Eva):** Globals named in harness snippets (`--dispatch-case`, `--call-expr`) or defined in `#include`d `.inc`/`.h` files are silently zero-initialized in `link_globals.c` (or omitted from `build_sources`); Eva has no gate for missing bodies or missing global definitions, and crash triage does not classify `FRAMAC_LINK_STUB_CALLED`.
7. **B7 (`api_harness` defeats cluster narrowing and desynchronizes `fuzz_build`):** On run-5's model, `api_harness` selects `ngx_init_cycle` (1502 fns / 124 files) and `ngx_http_upstream_init` (405 fns / 58 files) as cross-cluster struct initializers for 125 entry points; `_flow_harness_sources` re-inflates "within-limit" clusters back toward whole-program source lists while DAG metadata and `fuzz_build._flow_cluster_files` stay un-widened.
8. **B8 (Cross-parse/collision/constructor/build-only gaps and unclustered callbacks):** `phase0_model.resolve_refs` silently drops cross-parse `address_refs` and globals from `gcc_fallback` units; producer-consumer splits drop reachable callbacks into `unclustered` in libraries; `__attribute__((constructor))` hooks in compiled files abort on stubs; `_dag_symbol_files` returns static-function files on name collisions and stubs `build_only_functions`.
9. **B9 (Unvalidated on target + double E-ACSL build cost):** No dump-schema-6 run or cluster build has been executed on nginx, and `build_module_binary(..., engine="auto")` runs two full E-ACSL instrumentations on every cluster that needs link stubs because `link_stubs.c` is not pre-generated from `sub["link_stubs"]`.

---

## 1. Soundness

Every counterexample below was built as a small C fixture and executed inside `framac-analysis:latest` (`--network none`, read-only mount of this branch's `scripts/` and `templates/`, isolated scratch directory) through the real path: `phase0_dump.ml` (compiled via `phase0_model.compile_dump_module`) -> `phase0_model.ModelBuilder` -> `build_callgraph_dag.build_dag` -> `generate_harness.generate_module_harness` -> `fuzz_build.build_module_binary` (sanitizers and/or E-ACSL) -> binary execution and `frama-c -eva -main eva_main`.

### 1.1 What the Branch Gets Right

Checking the non-trivial C cases through Frama-C CIL (`phase0_dump.ml` + `phase0_model.py` + `unit_split.py`) confirmed that four patterns work cleanly:

- **Function-local `static` tables (`ce4_ast`):** `static void (*const tbl[1])(void) = { h1 };` inside a function is lifted by Frama-C CIL to a `GVar` (`vglob=true`, `kernel_name=use_sl1_tbl`), recorded in `globals[]` with `init_functions: ["h_sl1"]`, and referenced in `global_refs`. When two functions in `src/a.c` define `static` locals with the same source name `tbl`, `phase0_model.py` merges both under `src/a.c#tbl` (`init_functions: ["src/handlers.c#h_sl1", "src/handlers.c#h_sl2"]`), which is conservative (sound over-approximation).
- **Compound literals (`ce4_ast`):** File-scope `static const struct ops *g_cl = &(struct ops){ .cb = h_cl_glob };` is lifted to a `GVar` (`__constr_expr_0`) linked via `init_globals`; function-local `&(struct ops){ .cb = h_cl_loc }` lands in `address_refs`. Both are reached by `flow_reach`.
- **Static vs. `extern` global name collision in one parse (`ce4_xparse`):** With `static int shared_tbl` in `src/clash.c` and `extern struct tbl shared_tbl` in `src/app.c` (defined in `libcore.a`), Frama-C CIL renamed the static (`shared_tbl_0`) and preserved `shared_tbl` for the `extern`, so `resolve_refs` resolved `app_use_tbl`'s reference to `lib/lib.c#shared_tbl`.
- **Transitive global initializers, `merged()` shortcut, and multi-definition global fallback:** `flow_reach` follows `init_globals` transitively to a fixpoint (`ngx_modules[]` -> module structs -> `ngx_command_t[]` -> `cmd->set`). In `unit_split.cluster`, the subset shortcut `if fa <= fb: return fb, b["globals"]` is mathematically sound by monotonicity of the fixpoint (all of `a["anchors"]` are already in `fa <= fb`). Commit `d1466bd`'s `unresolved_global_refs` and `_incomplete_globals` cleanly force fallback to `call_graph` when multiple non-static definitions of a global exist.

### 1.2 Concrete Soundness Counterexamples

#### CE-1: Direct call into a linked project library is replaced by an aborting stub and dropped from Eva (B1)

- **Code defect:** [`../../scripts/build_callgraph_dag.py`](../../../scripts/build_callgraph_dag.py) (`unit_view`) assigns a linked static/shared library's functions to the library's module, not to the consuming executable's `modules[exe]["functions"]`, while placing the library's files in `modules[exe]["required_sources"]`. [`../../scripts/unit_split.py`](../../../scripts/unit_split.py) sets `within = set(rec["functions"])`, so linked-library callees are never entered by `flow_reach` and their `.c` files never appear in `build_sources`. On `7957660`, [`../../scripts/generate_harness.py`](../../../scripts/generate_harness.py) (line 2308) explicitly appended all files owned by linked libraries (`unit_list`). On this branch, lines 2276-2279 return early with only `flow_rels` (`build_sources`), dropping every linked library `.c` file. [`../../scripts/fuzz_build.py`](../../../scripts/fuzz_build.py) (`repair_sources_for_link`, line 1921) then sees that the undefined library function's file is not in `flow_files` and generates an aborting asm stub for it.
- **Fixture & observed result (`ce1`):** `libcore.a` (`lib/core.c`: `int lib_compute(int x)`) linked by `prog` (`src/a.c` where `api_a -> a2 -> a1 -> lib_compute`; `src/b.c` with `api_b -> b2 -> b1`), split with `max_functions=4`.
  - `prog__a`: `reach: "address_flow"`, `functions: ["a1", "a2", "api_a"]`, `build_sources: ["src/a.c"]`, `link_stubs: {"functions": [], "globals": []}` (does not even record `lib_compute` in DAG `link_stubs`).
  - `generate_module_harness`: `sources: ["workspace/work/src/a.c"]` (`lib/core.c` omitted).
  - `fuzz_build.build_module_binary(..., engine="sanitizers")`: succeeds (`rc=0`) by stubbing `lib_compute` in `link_stubs.c`.
  - Executing the fuzz binary on 4 bytes: aborts (`rc=77`) with `FRAMAC_LINK_STUB_CALLED: lib_compute (not in the unit split's address-flow reach)`.
  - Running `frama-c -eva -main eva_main` on the harness's sources: exits `0` with `Neither code nor specification for function lib_compute, generating default`.
- **Companion cross-parse defect (`ce4_xparse`):** [`../../scripts/phase0_model.py`](../../../scripts/phase0_model.py) (`resolve_refs`, line 996) resolves `address_refs` and `init_functions` via `kmap` only (`fids = {kmap[k] for k in fnames if k in kmap}`), unlike `resolve()` which looks up callees across units via `_lookup_global`. When `src/app.c#app_take_addr` in `prog` takes the address of `lib_cb` defined in `libcore.a`, `dump_prog.json` records `address_refs: ["lib_cb"]`, and `phase0_model.py` silently drops it to `address_refs: []`.

#### CE-2: Callback passed to an external library through a local variable or struct is stubbed and aborts (B2)

- **Design claim refuted:** [`./unit-split-address-flow.md`](../unit-split-address-flow.md) Section 3.1 asserts: *"The library cannot produce a project function's address unless the project passed it in. Passing it in is a callback edge, so the reach follows it."*
- **Code defect:** [`../../scripts/phase0_dump.ml`](../../../scripts/phase0_dump.ml) (lines 268-274) records `function_args` (which creates a `callback-arg` edge) only when a direct call's argument expression is directly `AddrOf(Var v)` or `StartOf(Var v)` (after casts). It emits no `callback-arg` edge when the function pointer is held in a local variable, stored in a struct passed to the library, read from a global table, or returned by a helper. Because the indirect call site lies inside the external library rather than in project code, `flow_reach` puts the function into `pool` but never adds it to `reached`, omits its defining `.c` file from `build_sources`, and places it in `link_stubs`.
- **Fixture & observed result (`ce2`):** Single-unit `prog` (`src/a.c` stores `int (*cmp)(const void *, const void *) = real_cmp;` and calls `qsort(arr, 2, sizeof(int), cmp)`; `real_cmp` defined in `src/cmp.c`; `src/b.c` holds `api_other`), split at `max_functions=3`.
  - `phase0_model`: `src/a.c#api_sort` has `address_refs: ["src/cmp.c#real_cmp"]` and zero `callback-arg` edges.
  - `prog__a`: `build_sources: ["src/a.c"]`, `link_stubs: {"functions": ["real_cmp"], "globals": []}`.
  - `fuzz_build` stubs `real_cmp` in `link_stubs.c`; executing the binary aborts (`rc=77`) inside `qsort_r` with `FRAMAC_LINK_STUB_CALLED: real_cmp`.
- **Real nginx run-5 evidence:** Six of the 10 unreached functions in run-5's `phase0_model.json` are exact instances of this gap: `ngx_http_gzip_filter_alloc`, `ngx_http_gzip_filter_free`, `ngx_http_log_gzip_alloc`, `ngx_http_log_gzip_free` (assigned to `z_stream.zalloc`/`zfree` and passed to `deflateInit2_`), `ngx_signal_handler`, and `ngx_timer_signal_handler` (assigned to `struct sigaction.sa_handler` and passed to `sigaction`). None received a `callback-arg` edge. When such a callback lives in a separate `.c` file from the caller, this branch replaces it with an aborting stub.

#### CE-3: Function-pointer cast across differing signatures is stubbed, aborts, and breaks E-ACSL's stub marker (B3, B4)

- **Code defect (B3):** `phase0_model.py` matches indirect call sites by exact canonical signature equality. If reached code takes `&real_cleanup` (`void(int *)`, defined in `src/handler.c`) and casts it to `void (*)(void *)` before calling it, `real_cleanup` is in `address_refs` (and `pool`) yet absent from `indirect_callees`. On `7957660`, link repair linked `src/handler.c` so the fuzz binary still executed `real_cleanup`. On this branch, `build_plan` omits `src/handler.c` and puts `real_cleanup` in `link_stubs`, so `fuzz_build` stubs it and Eva analyzes the call without a body.
- **Code defect (B4 — E-ACSL instrumentation of `link_stubs.c`):** Design Section 4 and commit `b64a3db` claim `link_stubs.c` was verified under `e-acsl-gcc` and prints `FRAMAC_LINK_STUB_CALLED` (`rc=134`). In the real pipeline, [`../../scripts/fuzz_build.py`](../../../scripts/fuzz_build.py) (`_discover_slice_functions`, lines 144-166) scans every non-`harness_` `.c` file in `sources` — including `link_stubs.c` — and passes `__framac_link_stub_called` to `-e-acsl-functions`. Under `EACSL_GCC_CHECK_OPTIONS` (`--libc-replacements --validate-format-strings`), E-ACSL instruments `fprintf(stderr, "...%s...", name)`. Because `.Lframac_link_stub_0` is emitted in raw file-scope `__asm__` `.rodata`, E-ACSL's shadow memory never registers it.
- **Fixture & observed result (`ce3`):** Single-unit `prog` (`src/a.c`: `cleanup_pt fn = (cleanup_pt)real_cleanup; fn(&v);`; `src/handler.c`: `void real_cleanup(int *p)`).
  - `prog__a`: `address_refs: ["src/handler.c#real_cleanup"]`, `indirect_sites[0].candidates: []`, `build_sources: ["src/a.c"]`, `link_stubs: {"functions": ["real_cleanup"], "globals": []}`.
  - **Sanitizers binary:** aborts (`rc=77`) with `FRAMAC_LINK_STUB_CALLED: real_cleanup`; `failure_identity.parse_runtime_failure` returns `None` (unattributed deadly signal).
  - **Eva:** exits `0` with `Neither code nor specification for function real_cleanup, generating default`.
  - **Real E-ACSL binary (`fuzz_build.build_module_binary(..., engine="eacsl")`):** builds (`rc=0`) with `__framac_link_stub_called` instrumented in `fuzz_prog__a_eacsl.instrumented.c`. Executing it aborts (`rc=77`) inside `validate_format_string_argument` with:
    `fprintf: attempt to access unallocated memory via directive 1 ('%s')`
    **`FRAMAC_LINK_STUB_CALLED` is never printed.** Calling `failure_identity.parse_runtime_failure` on this output returns:
    `{'file': 'unknown', 'line': 0, 'function': 'validate_format_string_argument', 'kind': 'eacsl_format_error', 'alarm_kind': 'mem_access', 'is_rte': True, ...}` — a false target RTE finding. Even implementing open item 2 (matching `FRAMAC_LINK_STUB_CALLED` in crash triage) would fail to catch stub hits in E-ACSL builds.

#### CE-4: `link_globals.c` fails to compile and link nginx-shaped clusters (B5)

- **Code defect:** For address-flow clusters, `fuzz_build.repair_sources_for_link` stubs any undefined global outside `flow_files` via `_declaring_header` (which emits `#include "<header>"` alone, with no prerequisite headers) or `global_definition_text` (which rejects by-value structs/unions/enums).
- **Run-5 measurement (read-only over all 155 non-static globals in `phase0_model.json` and `run-5/workspace/work`):**
  - `45` globals (all `ngx_*_module`, type `struct ngx_module_s`, declared only in `objs/ngx_modules.c` with no `.h` header) end up `unresolved` (`its type 'struct ngx_module_s' is held by value and needs a definition the generated file does not have, and no header of the project declares it`).
  - `104` globals match `_declaring_header` (e.g., `ngx_accept_disabled` in `src/event/ngx_event.h`, `ngx_cached_err_log_time` in `src/core/ngx_times.h`), whose headers are not self-contained in nginx (they require `#include <ngx_config.h>` and `#include <ngx_core.h>` first).
  - Only `6` non-static globals can be defined from `global_definition_text` alone.
- **Fixture & observed result (`ce5_globals`):** `src/a.c` has reached `api_a` and unreached `unreached_in_a` referencing `ngx_accept_disabled` (declared in `src/ngx_event.h` using `ngx_int_t` from `src/ngx_config.h`) and `ngx_http_access_module` (no `.h` declaration, type `struct ngx_module_s`). `build_module_binary(..., engine="sanitizers")` fails (`rc=1`): `link_globals.c` fails to compile (`error: unknown type name 'ngx_int_t'`), and `ngx_http_access_module` is recorded in `unresolved_globals`.

#### CE-5: Globals named in harness snippets or defined in `.inc`/`.h` files are silently zero-stubbed or dropped (B6)

- **Harness-named globals (`ce6_silent`):** [`../../scripts/generate_harness.py`](../../../scripts/generate_harness.py) (`_merge_dag_harness_sources`) scans snippets only for function identifiers (`functions_map`), never for global variables (`global_variables`). With `--dispatch-case "(void)api_use(&g_cfg);"` where `src/cfg.c` initializes `struct cfg g_cfg = { 99, real_fn };`, `generate_harness` keeps `sources: ["workspace/work/src/a.c"]`. `fuzz_build` sees `src/cfg.c` outside `flow_files` and defines `struct cfg g_cfg;` zero-initialized in `link_globals.c`. The build exits `0`, the binary executes and exits `0`, and prints `CE6_OBSERVED magic=0 fn_null=1` — **silently discarding both the global's data and its function pointer without aborting**. Similarly, function-like macros in harness snippets (which are not simple `macro_aliases`) have their callees stubbed out.
- **Globals/functions defined in `#include`d `.inc`/`.h` files (`ce4_inc`):** [`../../scripts/unit_split.py`](../../../scripts/unit_split.py) (`build_plan`, lines 333-336) keeps only paths ending in `.c`. When `src/table.c` `#include "table.inc"` defines `struct ops g_tbl = { h_inc };`, `flow_reach` reaches `g_tbl` (`globals: ["src/table.inc#g_tbl"]`, `functions: ["api_a", "h_inc"]`), yet `build_plan` omits `src/table.c` from `build_sources` (`["src/a.c", "src/h.c"]`) and lists the reached global `src/table.inc#g_tbl` in `link_stubs["globals"]`. The same defect affects non-static functions defined in headers compiled into a `.c` file (such as `mpack`'s `MPACK_INLINE` pattern).
- **Eva silence:** `run_eva_slice.py` runs directly on `harness_<mod>.json`'s `sources` with no gate on `Neither code nor specification` (open item 3) and no check for `extern` globals whose definitions are absent (which Frama-C Eva silently zero-initializes, turning live branches dead and unsoundly discharging alarms).

#### CE-6: `api_harness` cross-cluster initializers re-inflate nginx clusters and desynchronize `fuzz_build` (B7)

- **Measured on run-5's model (`api_harness.initializers`):** `api_harness` searches the whole link unit for struct initializers and selects:
  - `struct ngx_cycle_s *` -> `ngx_init_cycle` (1502 fns / 124 build files in Table 2.1; **31** entry points take `ngx_cycle_t *`),
  - `struct ngx_http_request_s *` -> `ngx_http_upstream_init` (405 fns / 58 build files, `over_limit`; **94** entry points take `ngx_http_request_t *`),
  - `struct ngx_connection_s *` -> `ngx_http_create_request` (**26** entry points),
  - `struct ngx_event_s *` -> `ngx_http_v2_init` (**7** entry points).
- When `generate_harness.py --api` runs on a "within-limit" nginx cluster containing any of those entry points, `_flow_harness_sources` adds the initializer to `starts` and widens `harness_<mod>.json`'s `sources` back to 58-124 files, defeating the cluster size cap and Table 2.1's file-count projection. Meanwhile, `callgraph_dag.json` still records the un-widened `sub["functions"]`, `sub["build_sources"]`, and no `over_limit`, `harness_reach.py` strips `api_helpers` from roots, and `fuzz_build._flow_cluster_files` reads only the un-widened `sub["build_sources"]` from the DAG.

#### CE-7: Producer-consumer split (`rev->handler`), `__attribute__((constructor))`, static-name collisions, and `build_only_functions` (B8)

- **Producer-consumer split in a library (`ce4_prodcons`):** When `api_register` (cluster 1) stores `secret_cb` in `g_cb` (or a struct field like nginx's `rev->handler = ...`) and `api_run` (cluster 2) calls `g_cb()`, `unit_split.apply` reports `reached: 10` (all 10 functions reached by the unit's entry points together), splits into two 4-function clusters (`libfoo_a__reg` and `libfoo_a__run`), and drops `["secret_cb", "secret_leaf"]` into `unclustered` — excluded from every cluster's Eva and fuzzing. On nginx, Option E's `unclustered: 10` hides this effect only because the 4 `over_limit` startup clusters (`main` et al.) keep nearly the entire program together; skipping the 7 over-limit clusters loses cross-cluster runtime-assigned handlers.
- **`__attribute__((constructor))` (`ce7_ctor`):** A constructor in a compiled `.c` file (`src/a.c`) is not reached from `api_ctor`, so `h_ctor` (`src/h.c`) that it assigns to `g_cb` is put in `link_stubs`. At fuzz binary startup, the constructor runs, stores the asm stub address in `g_cb`, and calling `api_ctor()` aborts (`rc=77`) with `FRAMAC_LINK_STUB_CALLED: h_ctor`.
- **Static/extern collision in `_dag_symbol_files` (`ce8_static_clash`):** [`../../scripts/fuzz_build.py`](../../../scripts/fuzz_build.py) (`_dag_symbol_files`, lines 1544-1549) uses `out.setdefault(name, file)` without checking `not rec.get("is_static")`. With `static int helper_clash` in `src/a_static.c` and `int helper_clash` in `src/z_extern.c`, `_dag_symbol_files` returns `src/a_static.c`. Worse, if an extern global shares a name with a static function, `repair_sources_for_link` mistakes the global for a function and emits a `.text` asm stub for a data symbol.
- **`build_only_functions` stubbed in sanitizer builds:** `_dag_symbol_files` includes `build_only_functions` (code hidden from Frama-C by compiler macros, e.g., `#ifdef __SSE2__`), whose files are not in `flow_files`, so `repair_sources_for_link` stubs reachable build-only functions in sanitizer builds.
- **Unparsed/fallback globals:** `phase0_model.resolve_refs` records `unresolved_global_refs` only when `len(cands) > 1`, never when `len(cands) == 0`; an `extern` global defined in a `gcc_fallback` or `unparsed` unit is silently dropped like `errno`.

---

## 2. Numbers (Recomputed Read-Only From Run-5)

Recomputed directly from `C:\Users\Florian\framac-pipeline\nginx-1.31.9\run-5\workspace\reports\phase0_model.json`, `callgraph_dag.json`, `workspace/harnesses/harness_*.json`, `workspace/harnesses/fuzz_*.sanitizer_compile*.log`, and `workspace/reports/fuzz/*.json` (without modifying that directory).

### 2.1 Base Run-5 Facts

- **Model:** `schema_version: 2`, 1 unit (`objs/nginx`, `executable`, `137` files, `parse.status: ok`), `1679` functions (`103,678` total function-body lines; `1669` reached by the `548` candidate entry points, `103,283` lines in reached bodies; `10` unreached), `127,146` total source lines across the `137` compiled `.c` files (`136` defining functions + `objs/ngx_modules.c` defining globals only), `540` `global_variables` (`155` non-static, `385` static), `383` indirect call sites (`4` with 0 candidates), `746` `address_taken` functions.
- **Edges:** `8779` total: `4018` direct (`frama-c-kernel`) and `4761` indirect (`4753` `type-match`, `7` `callback-arg`, `1` `thread-spawn`). Minor precision note: design Section 1 says signature matching gives `4761` edges; strictly `4753` are `type-match` and `8` are `callback-arg`/`thread-spawn`.
- **Missing schema-6 fields in run-5:** `phase0_model.model_features(run5_model)` reports `address_flow: False` (all 7 earlier features `True`). Neither `address_refs`/`global_refs` on functions nor `init_functions`/`init_globals` on `global_variables` nor `indirect_callees`/`global_variables` in `callgraph_dag.json` exist in run-5.

### 2.2 Comparison Against Design Table (Section 2)

| Option | Metric | Design Claim | Recomputed From Run-5 JSONs | Status / Notes |
| :--- | :--- | :--- | :--- | :--- |
| **A. Status quo** | Clusters / over limit / largest within limits / unclustered | `2` / `1` (`1650` fns, `102,784` lines) / `23` fns / `10` | `2` / `1` (`1650` fns, `102,784` lines, `530` anchors) / `23` fns (`601` lines, `18` anchors) / `10` | **Matches.** |
| **A. Status quo** | Files per build (before -> after link repair) | `134 -> 136` (both clusters; *"every file but one of the 137"*) | **`135 -> 137` target sources** (`136 -> 138` `.c` files with `harness_<mod>.c`) | **Design off by 1.** Both `harness_*.json` list `135` unique target `.c` files (missing only `src/core/nginx.c` and `objs/ngx_modules.c`); link repair added both, reaching all `137` of `137` target files. |
| **B. Direct + callback/thread edges** | Clusters / over limit / largest within limits / unclustered | `15` / `1` (`286` fns, `19,250` lines) / `279` fns / `858` | `15` / `1` (`nginx__ngx_http_upstream`: `286` fns, `19,250` lines) / `279` fns (`14,982` lines, `nginx__ngx_data`) / `858` (`821` reached) | **Matches** (strictly direct without the 8 callback-arg/thread-spawn edges gives `860` unclustered / `819` reached). |
| **B. Direct + callback/thread edges** | Files per cluster before link repair | Lexer closures -> whole program after link repair | Lexer closures: min `119`, median `135`, max `136` (all `137` after link repair) | **Matches** qualitatively; exact counts computed here. |
| **B. Direct + callback/thread edges** | Lost callees | `848/858` unclustered in address-flow reach; `8/15` harnesses lose callees (max `1367`, median `6`) | **Not computable from run-5 JSONs alone** (no schema-6 facts). Against full call graph: `12/15` clusters lose `31..1367` callees (median `936` over all 15). | Address-flow loss figures depend on the external ELF build, not run-5's model. |
| **C. All edges, capped merges** | Clusters / over limit / within limits / unclustered / time | `108` / `97` (~`1092` fns, `69,701` lines) / `271` max (median `18`) / `10` / `8.5 s` | `108` / `97` (`78` at `1092` fns / `69,701` lines; range `1092..1587`, median `1092`) / `11` within limits (min `14`, median `18`, max `271`) / `10` / `8.67 s` | **Matches.** Note: this is what the branch actually produces on run-5's unmodified model/DAG. Lexer closures: min `119`, median `119`, max `136`. |
| **D. Eva sharding** | All metrics | Unchanged | Unchanged | **Matches.** |
| **E. Address-flow reach** | Entire row & Table 2.1 (`21` clusters, `7` over limit, `28.5`/`37` median build files, stubs, dropped, `1.2 s`) | Computed from scratch-gcc ELF relocations mapped onto run-5 keys | **Not computable from run-5 JSONs alone** (run-5 predates dump schema 6). | Cross-check on the 7 single-anchor over-limit clusters: `functions + dropped` in Table 2.1 equals the exact run-5 call-graph reach of each anchor (`1587`, `1559`, `1537`, `1519`, `1092`, `1092`, `1092`). However, Table 2.1's `build_sources` ignores `api_harness` cross-cluster initializer widening (B7) and assumes `link_globals.c` links (refuted by B5). |

---

## 3. Tests

### 3.1 Gate Results on the Reviewed Branch (`d1466bd`)

Run from a clean worktree cut from `d1466bd` (`PYTHONIOENCODING=utf-8`):

| Check | Command | Result |
| :--- | :--- | :--- |
| Full unit/integration suite | `python -m pytest tests -n auto` | **`7475 passed, 312 skipped, 1 warning in 48.45s`** (exit 0) |
| Ruff lint | `ruff check` | **`All checks passed!`** (exit 0) |
| Mypy (`scripts/`) | `mypy scripts` | **`Success: no issues found in 76 source files`** (exit 0) |
| Mypy (`scripts tests tools`) | `mypy scripts tests tools` | **`Success: no issues found in 340 source files`** (exit 0) |
| Generated-text guardrail | `python tools/check_generated_text.py` | **Clean** (exit 0) |
| Skill mirrors | `python tools/sync_skill_mirrors.py --check` | **Clean** (exit 0) |
| Frama-C dump selftest | `phase0_model.selftest()` in `framac-analysis:latest` | **`{"ok": true, "status": "ok", "reason": ""}`** |

### 3.2 Do the New and Modified Tests Fail on `7957660`?

Running the 5 added/modified test files from `d1466bd` against `7957660` (`14 failed, 68 passed, 12 skipped`):

- **10 of 11 new tests fail on `7957660` and pass on `d1466bd`:**
  - `test_unit_split.py`: `test_an_entry_inside_an_oversized_cluster_is_not_folded_into_it`, `test_an_indirect_callee_is_reached_only_when_its_address_flows_into_the_reached_code`, `test_the_split_uses_address_flow_reach_when_every_function_has_the_facts`, `test_a_cluster_lists_the_unit_symbols_its_files_name_without_defining_them_as_link_stubs`, `test_a_cluster_harness_compiles_the_address_flow_build_sources`.
  - `test_link_repair_flow_stubs.py`: `test_a_flow_cluster_stubs_what_its_files_name_outside_them`, `test_build_module_binary_accumulates_the_function_stubs`.
  - `test_dag_model_view.py`: `test_the_address_flow_facts_reach_the_dag_with_dag_keys`.
  - `test_phase0_model.py`: `test_dump_schema_6_address_flow_becomes_ids_resolved_across_parses`, `test_a_declared_global_two_programs_define_is_recorded_unresolved`.
- **1 new test passes on `7957660` (expected):** `test_link_repair_flow_stubs.py::test_a_call_graph_cluster_or_a_build_without_a_stub_dir_links_the_file` is a negative regression guard verifying that non-flow clusters and `stub_dir=None` keep the existing file-linking behavior.
- **All 4 modified tests fail on `7957660` and pass on `d1466bd`:** `test_a_unit_under_the_threshold_is_not_split`, `test_overlap_merging_stays_within_the_limits`, `test_model_features_read_a_version_1_model_by_its_fields`, `test_the_dag_records_its_schema_version_and_drops_unread_module_fields`.

### 3.3 Assessment of Test Depth (Shape vs. Soundness)

The new tests verify dictionary transformations, heap-based merge capping, and generated text snippets, **not** end-to-end soundness:

- [`../../tests/test_link_repair_flow_stubs.py`](../../../tests/test_link_repair_flow_stubs.py) replaces `compile_sanitizer_binary` with `fake_compile` and asserts assembly substrings (`'".globl kv_put\\n"'`). It never compiles or executes `link_stubs.c` under clang or E-ACSL, which is why **B4** (E-ACSL aborting on `%s` before printing `FRAMAC_LINK_STUB_CALLED`) and **B5** (`link_globals.c` failing on non-self-contained headers) went undetected. Its fixture also places `lib/b.c` inside `kvd`'s own `functions` rather than a linked library unit, hiding **B1**.
- [`../../tests/test_unit_split.py`](../../../tests/test_unit_split.py) tests only hand-crafted DAG dicts (`flow_dag()`), covering none of: linked libraries, cross-parse `address_refs`, function-pointer casts, struct/local external callbacks, `.inc` definitions, global-referencing dispatch cases, `__attribute__((constructor))`, producer-consumer unclustered callbacks, `api_harness` initializers, or Eva missing-body behavior.
- [`../../scripts/phase0_model.py`](../../../scripts/phase0_model.py) `selftest` is the only Frama-C AST test of dump schema 6 and exercises only a two-line array initializer (`int (*table[1])(int) = { twice };`).

---

## 4. Design and Code Quality

### 4.1 Design Honesty and Gaps

[`./unit-split-address-flow.md`](../unit-split-address-flow.md) is clear and notably candid in Section 6: it discloses that Option E's measurements used ELF relocations rather than dump schema 6, that no cluster has been built/linked yet, that missed globals and missing Eva bodies are silent, and that crash triage of `FRAMAC_LINK_STUB_CALLED` is unimplemented. Commit `d1466bd` also improved honesty (qualifying the `28.5` vs `37` medians and adding `unresolved_global_refs` fallback).

Where the design falls short:

- **Overstated soundness argument (Section 3.1):** Its claim that passing a function pointer to an external library is always a `callback-arg` edge is false (B2), and it omits function-pointer casts (B3), linked libraries (B1), `__attribute__((constructor))` (B8), global/macro references in harness snippets (B6), and producer-consumer unclustered callbacks (B8).
- **Incomplete option space:** It never compares an option that keeps full-unit or link-repaired builds for fast sanitizer/coverage compiles while narrowing only E-ACSL/Eva, nor restricting `api_harness` cross-cluster initializers to stay within cluster limits, nor pre-generating link stubs before Attempt 1.
- **Minor factual drift:** Option A file counts are `135 -> 137` (not `134 -> 136`); signature-matched edges are `4753` (not `4761`, which includes `8` callback-arg/thread-spawn edges); line 5 omits commit `d1466bd`.

### 4.2 Code vs. Design Mismatches and Code-Quality Issues

1. **Double E-ACSL instrumentation in `engine="auto"` (B9):** Verified in `framac-analysis:latest` (`ce3` with `engine="auto"`): because `build_module_binary` does not pre-generate `link_stubs.c` from `dag["submodules"][mod]["link_stubs"]`, Attempt 1 runs full E-ACSL Stage 1 + Stage 2 (failing at link), falls back to sanitizers (failing at link), adds `link_stubs.c`, and Attempt 2 re-runs full E-ACSL Stage 1 + Stage 2 from scratch — doubling E-ACSL build cost on 20 of 21 nginx clusters.
2. **E-ACSL instruments `link_stubs.c` (B4):** `_discover_slice_functions` does not exclude `link_stubs.c` (or `__framac_link_stub_called`), contradicting the design's claim that E-ACSL prints `FRAMAC_LINK_STUB_CALLED`.
3. **Widened harness sources vs. `fuzz_build._flow_cluster_files` (B7):** `_flow_harness_sources` widens a cluster's sources for extra functions named by the harness, while `_flow_cluster_files` reads only the DAG's static `sub["build_sources"]`.
4. **Coverage pollution:** [`../../scripts/fuzz_coverage.py`](../../../scripts/fuzz_coverage.py) (`_coverage_file_role`, lines 295-304) classifies `workspace/build/<bin>_link_globals/link_stubs.c` as `"target"`, adding `__framac_link_stub_called` as an unreached target function in coverage totals.
5. **Undocumented DAG schema fields:** [`../../scripts/build_callgraph_dag.py`](../../../scripts/build_callgraph_dag.py) (lines 982-984) writes `indirect_callees`, `address_refs`, and `global_refs` onto `dag["functions"][k]`, but [`../../schemas/callgraph_dag.schema.json`](../../../schemas/callgraph_dag.schema.json) (`definitions.function.properties`) does not declare them (validation only passes because `definitions.function` leaves `additionalProperties` open).

### 4.3 Regressions for Other Targets

- **Small libraries and units that never split:** No build regression. `unit_split.apply` skips units below the thresholds, produces no `submodules`, and leaves `generate_harness` and `fuzz_build` on their existing paths. (With `address_flow`, `reached` is smaller or equal, never falsely triggering a split.)
- **Multi-unit targets where an executable or consumer library splits:** **Severe regression (B1):** linked-library files are dropped from harness sources and direct calls into linked libraries abort on stubs / become bodyless in Eva.
- **GCC fallback units:** Units containing any `gcc_fallback` function lack `address_refs` on those functions, so `has_flow_facts` returns `False` and the unit cleanly falls back to `reach: call_graph`. (One gap: a parsed unit referencing an `extern` global defined in a separate `gcc_fallback` unit does not trigger `unresolved_global_refs`, B8.)
- **Schema versions and runs made with older models:** `phase0_model.SCHEMA_VERSION` (`2`) and `build_callgraph_dag.DAG_SCHEMA_VERSION` (`1`) stay unchanged and backward-compatible with older artifacts. Rebuilding a DAG from a pre-schema-6 model emits a new `missing_features: ["address_flow"]` warning even for small units (same convention as `call_sites` in dump schema 4). However, on a large callback-heavy run with an older model (like nginx run-5), unconditional merge capping turns Option A's `2` clusters into Option C's `108` clusters (`97` over limit, each compiling 119-136 files) until `phase0_model.py` is re-run.

---

## 5. Verdict and Blocking Issues

**Verdict: Rework.** Keep the dump-schema-6 AST extraction (`phase0_dump.ml`), `unresolved_global_refs` fallback, capped merges, and address-flow reach foundation, but rework the soundness boundary, stubbing mechanics, and harness/build integration before merging.

### Blocking Issues (Must Be Resolved Before Merge)

1. **B1 — Linked project libraries dropped and stubbed (`unit_split.py`, `generate_harness.py`, `fuzz_build.py`, `phase0_model.py`):** Include linked-library closures (or at minimum all functions/globals reachable across linked units, plus linked-library `required_sources` as `generate_harness.py` line 2308 previously did) in `flow_reach`, `build_sources`, and `flow_files`; resolve `address_refs` and `init_functions` across parses in `phase0_model.resolve_refs` via `_lookup_global`.
2. **B2 & B3 — Address-taken functions reachable via external-library structs/locals or signature casts are stubbed (`unit_split.py`, `phase0_dump.ml`, `fuzz_build.py`):** Any function whose address is taken in reached code (or in reached globals' initializers) when a reached function either calls an external function or has a cast/type-mismatched indirect site (or simply any function in `pool` whose defining file is needed for soundness when casts or external calls exist) cannot be replaced by an aborting stub. At minimum, detect casts of function pointers and struct/indirect external callbacks (or follow `pool` conservatively across external calls / cast sites), and add concrete C regression tests for both.
3. **B4 — E-ACSL breaks `link_stubs.c` and reports stub calls as target `mem_access` bugs (`fuzz_build.py`, `failure_identity.py`):** Exclude `link_stubs.c` (and `__framac_link_stub_called`) from `_discover_slice_functions` / `-e-acsl-functions` (and from `fuzz_coverage._coverage_file_role`), emit the stub string as a C literal or uninstrumented `write(2, ...)` + `abort()`, classify `FRAMAC_LINK_STUB_CALLED` in `failure_identity.py` / crash triage as a pipeline defect (never a target finding), and verify with a real Docker test running `fuzz_build.build_module_binary(..., engine="eacsl")` that triggers a stub and checks stderr + `parse_runtime_failure`.
4. **B5 — `link_globals.c` fails to compile/link real nginx globals (`fuzz_build.py`):** Fix `link_globals.c` for non-self-contained project headers (for example, using the harness's include prelude / unit `-include` context, or emitting type-free `.bss` / `.comm` assembly definitions sized from `sizeof` or ELF/Frama-C `bitsSizeOf` in `phase0_dump.ml` for unreached globals — avoiding header inclusion and by-value struct rejection altogether!). Note that any global-stubbing approach must still never silently zero a reached global.
5. **B6 — Silent zeroing of harness-named globals and `.inc`/header definitions, plus missing Eva gate (`generate_harness.py`, `unit_split.py`, `run_eva_slice.py`):** Scan harness snippets for `global_variables` as well as `functions` (and map `.inc`/header definitions back to the `.c` translation unit that compiles them via `build_capture.json` rather than filtering `endswith(".c")`); add the Eva missing-body gate (open item 3) restricted to project functions, and fail or warn loudly on missing project global definitions.
6. **B7 — `api_harness` cross-cluster initializers re-inflate clusters and desynchronize `fuzz_build` (`api_harness.py`, `generate_harness.py`, `fuzz_build.py`):** Bound `api_harness` struct initializers/destructors for address-flow clusters so a small cluster does not pull in an `over_limit` initializer like `ngx_init_cycle` or `ngx_http_upstream_init` (or reflect widened sources consistently in `fuzz_build._flow_cluster_files` and over-limit reporting).
7. **B8 — Edge-case soundness defects (`fuzz_build.py`, `phase0_model.py`, `unit_split.py`):** Fix `_dag_symbol_files` to skip `is_static` functions and never stub `build_only_functions`; record `unresolved_global_refs` when an `extern` global belongs to a `gcc_fallback`/`unparsed` unit; handle `__attribute__((constructor))` functions in compiled `build_sources` as roots of `flow_reach` (or document/reject); address or report reachable callbacks lost to `unclustered` in producer-consumer splits.
8. **B9 — End-to-end validation on nginx + eliminate double E-ACSL instrumentation (`fuzz_build.py`, real target check):** Run dump-schema-6 `phase0_model.py` on nginx 1.31.9, compare AST facts against the ELF estimates, and actually build and run at least two within-limit nginx clusters through `build_module_binary` (E-ACSL + sanitizers), `coverage`, and `run_eva_slice.py`. Pre-generate `link_stubs.c` (or run a fast link check) before E-ACSL Stage 1 so `engine="auto"` does not instrument every stubbed cluster twice.
