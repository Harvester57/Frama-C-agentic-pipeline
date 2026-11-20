# Unit Split for Callback-Heavy C: Address-Flow Reach and Narrow Build Sources

- **Plans index:** [`./README.md`](./README.md)
- **Review & correction plan:** [`./unit-split-address-flow-review.md`](./unit-split-address-flow-review.md), [`./unit-split-address-flow-correction-plan.md`](./unit-split-address-flow-correction-plan.md)
- **Troubleshooting entry:** [`../troubleshooting/phase0-build-and-model.md`](../troubleshooting/phase0-build-and-model.md) ("The Unit Split Leaves One Cluster With Almost the Whole Program")
- **Branch:** `fix/unit-split-address-flow` (reworked from `claude/unit-split-indirect-edges` `d1466bd`, commits `3dc1bfd`..`1fbe43a` plus docs; not yet merged to `main`).
- **Code:** [`../../scripts/phase0_dump.ml`](../../scripts/phase0_dump.ml), [`../../scripts/phase0_model.py`](../../scripts/phase0_model.py), [`../../scripts/build_callgraph_dag.py`](../../scripts/build_callgraph_dag.py), [`../../scripts/unit_split.py`](../../scripts/unit_split.py), [`../../scripts/api_harness.py`](../../scripts/api_harness.py), [`../../scripts/generate_harness.py`](../../scripts/generate_harness.py), [`../../scripts/fuzz_build.py`](../../scripts/fuzz_build.py), [`../../scripts/fuzz_coverage.py`](../../scripts/fuzz_coverage.py), [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py), [`../../scripts/failure_identity.py`](../../scripts/failure_identity.py), [`../../scripts/crash_replay.py`](../../scripts/crash_replay.py), [`../../scripts/run_eacsl_fuzz.py`](../../scripts/run_eacsl_fuzz.py), [`../../scripts/ledger.py`](../../scripts/ledger.py), [`../../scripts/run_eva_slice.py`](../../scripts/run_eva_slice.py), [`../../templates/fc_stubs/fc_compat_types.h`](../../templates/fc_stubs/fc_compat_types.h)

## 1. Problem

On nginx, the unit split ([`../../scripts/unit_split.py`](../../scripts/unit_split.py)) did not divide the program:

- **run-2:** one cluster held 2208 of 2240 functions.
- **run-5:** one cluster held 1650 of 1679 functions (102,784 lines). The other, `nginx__ngx_bpf`, held 23 functions.

There are three causes:

1. **Indirect calls are matched by signature.** The Phase 0 model resolves an indirect call to every address-taken function with a matching signature (`narrowing: none`). On run-5 this produces 4761 indirect edges out of 8779 total edges (4753 `type-match`, 7 `callback-arg`, and 1 `thread-spawn`). nginx's pool cleanup handlers, event handlers and module hooks share a few signatures, so a single entry point such as `ngx_destroy_pool` reaches about 1100 functions. The overlap merge then folds every cluster into one.
2. **Source lists follow the same edges.** `generate_harness._merge_dag_harness_sources` adds the lexer-module closure of every function a harness names, and those closures follow every edge. Even the 23-function `nginx__ngx_bpf` cluster started from 135 target sources.
3. **Link repair adds whole files.** Each file it adds names more symbols. On nginx, every file eventually reaches the whole program. The `objs/ngx_modules.c` chain below starts from a small cluster (4 files):

   `ngx_files.c -[ngx_thread_task_alloc]-> ngx_thread_pool.c -[ngx_spinlock]-> ngx_spinlock.c -[ngx_ncpu]-> ngx_posix_init.c -[ngx_writev_chain]-> ngx_writev_chain.c -[ngx_debug_point]-> ngx_process.c -[ngx_cycle]-> ngx_cycle.c -[ngx_cycle_modules]-> ngx_module.c -[ngx_module_names]-> objs/ngx_modules.c`

   From there, `objs/ngx_modules.c` names every module. Both run-5 builds went from 135 target sources to all 137 (link repair added `src/core/nginx.c` and `objs/ngx_modules.c`). The E-ACSL build of such a cluster is the build that hit the 3600 s wall limit at 10.68 GiB RSS (S14).

The build and Eva time limits stay fixed. The fix comes from smaller units.

## 2. Options Compared on Real nginx 1.31.9 (Dump Schema 6)

The measurements below use a real Frama-C AST dump-schema-6 Phase 0 run on nginx 1.31.9 (`phase0_model.py run`: 414.7 s wall, 2,570 MiB peak RSS; unit `nginx`: 1679 functions, 1677 reached by entry points under address-flow reach, 103,283 lines in function bodies; 8779 edges = 4018 direct + 4761 indirect [4753 `type-match`, 7 `callback-arg`, 1 `thread-spawn`]; 540 globals with 540/540 positive sizes; 440 `address_refs`, 1295 `global_refs`, 490 `init_functions`, 254 `init_globals`, 0 constructors; 137 compiled target `.c` files totaling 127,146 lines). The split runs with `build_callgraph_dag.py` in 3.22 s (80.2 MiB peak RSS) at the default limits: 400 functions, 15,000 lines, overlap 0.5, packing under 10.

In Step C0, real schema-6 AST facts were compared against the earlier ELF-relocation proxy and used to settle Decision D1 (`D1(a)` vs `D1(b)` in [`./unit-split-address-flow-correction-plan.md`](./unit-split-address-flow-correction-plan.md)):

- Under the original prototype reach rule, real Frama-C AST facts matched the ELF proxy to the exact integer (`21` clusters, `7` `over_limit`, `14` within limits, `10` unclustered, within-limit `build_sources` median `28.5` / max `97`).
- Under **D1(b)** (unconditional function-body `address_refs` plus non-`all_indirect` global `init_functions`, keeping signature-pool filtering for module-table initializers), nginx yields **23 clusters**, the same **7** single-anchor `over_limit` clusters, **16** within-limit clusters with **smaller** within-limit sizes (median 79.0 functions / max 236 vs 91.5 / 295; `build_sources` median **26.5** / max **92** vs 28.5 / 97), only **2** unclustered functions (genuinely dead `ngx_crc` and `ngx_crc32c_update`), and **0** `cross_cluster_unclustered` callbacks. D1(b) was therefore adopted.

| Option | Clusters | Over a limit | Largest within limits | Unclustered | Files per build (before -> after link repair) | What a harness can no longer reach |
| :--- | ---: | ---: | :--- | ---: | :--- | :--- |
| A. Status quo (all edges, uncapped merge) | 2 | 1 (1650 fns, 102,784 lines) | 23 fns | 10 | 135 -> 137 target sources (both clusters) | Nothing. The E-ACSL build of the large cluster exceeds 3600 s and 10.68 GiB RSS. |
| B. Direct edges only (type-match edges dropped) | 15 | 1 (286 fns, 19,250 lines) | 279 fns | 858 | Lexer closures, then the whole program after link repair | 848 of the 858 unclustered functions are in the address-flow reach of all entry points taken together. 8 of 15 harnesses lose callees in their own address-flow reach (at most 1367, median 6). Eva sees those callees without bodies. |
| C. All edges, merges capped at the limits | 108 | 97 (about 1092 fns and 69,701 lines each) | 271 fns (median 18) | 10 | Lexer closures, then the whole program after link repair | Nothing, but 97 of the 108 clusters are still over a limit. |
| D. Eva sharding ([`../guides/eva-sharding.md`](../guides/eva-sharding.md)) | unchanged | unchanged | - | - | unchanged | Nothing. It splits one Eva run by dispatch case, so it shortens Eva only, not the E-ACSL build, and a cluster with a single anchor has nothing to shard. |
| **E. Address-flow reach (D1(b)), capped merges, narrow build sources, pre-seeded `.bss` + asm link stubs** | **23** | **7** (below) | **236 fns (median 79.0)** | **2** (`0` cross-cluster) | `build_sources`: min 2, median **26.5**, max **92** over the 16 within-limit clusters; median **38**, max **131** over all 23. Stays at `build_sources` (plus any bounded harness widening) in **1 attempt** with zero `link_repair` rounds (measured in Section 6). | Nothing a generated harness can execute (Section 3). Per cluster it drops 0 to 1421 signature-matched candidates whose address never reaches its code. |

### 2.1 Option E per cluster (Real Dump-Schema-6 nginx 1.31.9)

`Build files` are the cluster's DAG `build_sources`; `Build file lines` sums the lines of those `.c` files on disk; `Stubs (fns / globals)` is the DAG `link_stubs` count; `Dropped` is the number of call-graph-reachable unit functions excluded by address-flow reach.

| Cluster | Functions | Lines | Anchors | Build files | Build file lines | Stubs (fns / globals) | Dropped | Over a limit |
| :--- | ---: | ---: | ---: | ---: | ---: | :--- | ---: | :--- |
| `nginx__nginx` | 1597 | 100,663 | 1 | 131 | 125,189 | 0 / 0 | 0 | yes |
| `nginx__ngx_process_cycle` | 1558 | 98,387 | 1 | 127 | 124,483 | 4 / 0 | 6 | yes |
| `nginx__ngx_process_cycle_2` | 1531 | 96,663 | 1 | 124 | 124,032 | 11 / 0 | 11 | yes |
| `nginx__ngx_cycle` | 1510 | 95,688 | 1 | 124 | 124,032 | 11 / 0 | 14 | yes |
| `nginx__ngx_http_proxy_v2_module` | 464 | 33,844 | 1 | 64 | 85,604 | 45 / 1 | 630 | yes |
| `nginx__ngx_http_upstream` | 407 | 28,301 | 1 | 58 | 72,434 | 49 / 1 | 687 | yes |
| `nginx__ngx_http_request` | 241 | 15,691 | 1 | 38 | 49,478 | 63 / 11 | 851 | yes (lines) |
| `nginx__ngx_string` | 236 | 14,866 | 102 | 91 | 100,006 | 88 / 1 | 969 | no |
| `nginx__ngx_http_priority` | 232 | 14,898 | 10 | 38 | 59,509 | 101 / 12 | 860 | no |
| `nginx__ngx_http_core_module` | 226 | 14,659 | 89 | 44 | 68,631 | 90 / 2 | 871 | no |
| `nginx__ngx_module` | 189 | 10,658 | 11 | 92 | 89,742 | 133 / 4 | 937 | no |
| `nginx__ngx_http_script` | 172 | 9,986 | 29 | 27 | 40,632 | 102 / 21 | 1002 | no |
| `nginx__ngx_http_upstream_round_robin` | 171 | 9,033 | 54 | 43 | 42,511 | 88 / 8 | 933 | no |
| `nginx__ngx_file` | 104 | 5,289 | 42 | 24 | 19,270 | 63 / 6 | 119 | no |
| `nginx__ngx_buf` | 80 | 4,628 | 36 | 28 | 34,001 | 119 / 14 | 1016 | no |
| `nginx__ngx_log` | 78 | 3,810 | 20 | 26 | 23,268 | 90 / 17 | 1037 | no |
| `nginx__ngx_bpf` | 64 | 3,117 | 50 | 29 | 22,256 | 81 / 20 | 115 | no |
| `nginx__ngx_data` | 62 | 2,721 | 29 | 22 | 12,958 | 43 / 8 | 1421 | no |
| `nginx__ngx_http_variables` | 61 | 3,241 | 21 | 23 | 24,892 | 78 / 11 | 16 | no |
| `nginx__ngx_radix_tree` | 16 | 519 | 16 | 13 | 17,839 | 125 / 12 | 1085 | no |
| `nginx__ngx_string_2` | 13 | 395 | 13 | 6 | 3,447 | 16 / 3 | 0 | no |
| `nginx__ngx_files` | 12 | 483 | 9 | 4 | 5,664 | 4 / 3 | 2 | no |
| `nginx__ngx_http_script_2` | 10 | 173 | 10 | 2 | 4,897 | 41 / 7 | 31 | no |

Seven single-anchor clusters remain over a limit:

- **The four startup clusters** (`main` in `nginx__nginx`, `ngx_master_process_cycle` in `nginx__ngx_process_cycle`, `ngx_single_process_cycle` in `nginx__ngx_process_cycle_2`, `ngx_init_cycle` in `nginx__ngx_cycle`). These genuinely reach the program through `ngx_modules`, whose initializer names every module table.
- **`ngx_http_proxy_v2_module`** (464 functions, 33,844 lines) and **`ngx_http_upstream_init`** (`nginx__ngx_http_upstream`, 407 functions, 28,301 lines).
- **`ngx_http_init_connection`** (`nginx__ngx_http_request`, 241 functions, 15,691 lines).

Each has a single anchor, so neither entry-point splitting nor Eva sharding can divide it further (policy recorded in Section 6.2).

## 3. Address-Flow Reach

A function's address flows into a harness's code when one of these holds:

- a reached function's body takes it (`address_refs`: `&f` or `f` used as a value, resolved across linked project units via `phase0_model._lookup_global`);
- it is named in the initializer of a global the reached code reads (`global_refs`, then `init_functions`), or transitively through `init_globals`;
- it is an `__attribute__((constructor))` function (`constructor: true` in dump schema 6) compiled by a `.c` file already pulled into the cluster's reach.

`unit_split.flow_reach` computes this as a fixpoint over the unit's full transitive link closure (`unit_closure_keys`: the unit plus its transitive `linked_modules`), while cluster membership (`sub["functions"]`), limits, and tiers stay scoped to the unit's own functions:

- **Direct calls are always followed**, including callback-argument and thread-spawn edges, across both the unit and its linked project libraries (`B1`).
- **Function-body `address_refs` are followed unconditionally (`D1(b)`).** This structurally closes callbacks stored in locals or structs passed to external libraries (`B2`) and function-pointer casts across differing C signatures (`B3`), even across helper boundaries.
- **Global initializers (`init_functions`) feed the signature-filtered `pool`**, except callbacks whose signature matches no indirect site in the closure (such as nginx's `signals[]` -> `ngx_signal_handler` registered via `sigaction`), which are followed directly.
- **Startup constructors (`constructor: true`)** in any compiled `.c` file join `work` to fixpoint.
- **Included `.inc` and non-static header definitions** map to their compiling `.c` files via `compiled_in` (populated from `build_capture.json` `compiles[].headers` and `defined_functions`).
- **Producer-consumer rescue (`D3(a)`):** after overlap merging, a within-limit rescue pass merges producer and consumer clusters when splitting them drops unit-reachable callbacks into `unclustered`. Any callback that still cannot fit within the limits is recorded in `unit.split["cross_cluster_unclustered"]` with a DAG warning.
- **Fallback (`D4(a)`):** if any unit in the link closure lacks dump-schema-6 facts, fell back to GCC parsing (`callgraph_fallback` / `unparsed`), or hit `unresolved_global_refs` (including unknown globals when a linked unit failed Frama-C parsing), the unit falls back cleanly to `reach: call_graph` with capped merges and a DAG warning advising to re-run `phase0_model.py`.

### 3.1 Soundness Guarantees and Loud Failure Modes

For generated harnesses (`api_harness.py`), a function pointer called by reached code comes from a reached body (`address_refs`), a global initializer (`global_refs` / `init_functions`), a startup constructor, or the harness itself (`api_harness` never fabricates function pointers; struct fields stay zeroed and callback parameters use harness stubs).

Every reach gap is now loud across both dynamic and static phases:

- **Missed function in Phase 1 (fuzz binary):** defined as an E-ACSL-safe assembly stub in `link_stubs.c` that writes `FRAMAC_LINK_STUB_CALLED: <symbol>` directly via unbuffered `write(2, ...)` and calls `abort()`. `failure_identity.parse_link_stub_abort`, `crash_replay.py`, `run_eacsl_fuzz.py`, and `ledger.py` classify this as a pipeline reach defect (`link_stub_abort`, counted in `stats["link_stub_aborts"]` and recorded in ledger warnings), never as a target vulnerability candidate.
- **Missed function body or omitted global in Phase 2 (Eva):** `run_eva_slice.reject_address_flow_gaps` checks post-Eva `missing_spec_messages` against non-static project functions in the link closure (`address_flow_missing_body`) and post-Eva `flows` / `inout` reads against non-static `dag["global_variables"]` omitted from `sources` (`address_flow_missing_global`), downgrading `"ok"` to `"analysis_error"` before cache publication.
- **Missed unreached global in Phase 1 (fuzz binary):** defined zero-initialized in `.bss` inside `link_stubs.c` (sized from `phase0_model.json` `global_variables[].size`, defaulting to 16 bytes when incomplete/unknown); Eva's missing-global gate catches any omission that is actually read.

WP stays context-free and keeps every edge. None of `indirect_calls`, candidates, waves, or unit/lexer `required_sources` is narrowed.

## 4. Narrow Build Sources, Bounded Initializers, Pre-Seeded Stubs, and Scoped E-ACSL

1. **Bounded harness initializers (`api_harness.py`, `D2(a)`):** on within-limit `address_flow` clusters (`"over_limit" not in sub`), `_ClusterInitBudget` ranks in-cluster struct initializers and destructors first and rejects cross-cluster candidates whose combined `flow_reach` would exceed `dag["unit_split"]` limits (for example blocking `ngx_http_v2_init` on `nginx__ngx_buf` with case notes `"initializer <fn> skipped: cross-cluster reach exceeds cluster limit"`).
2. **Synchronized harness sources (`generate_harness.py`):** `_merge_dag_harness_sources` matches harness identifiers against both `dag["functions"]` and `dag["global_variables"]`, computes `_flow_harness_sources` over the full link closure with `extra_globals`, persists any widened set as `flow_build_sources` in `harness_<mod>.json`, and warns on stderr if widening crosses the split thresholds.
3. **Single-pass Attempt-1 pre-seeding & `.bss` globals (`unit_split.py`, `fuzz_build.py`):**
   - `unit_split.link_stubs_for_files` computes unreached non-static functions and globals named by the compiled `.c` files **and** any `header` `static inline` callees those `.c` files compile (e.g. nginx `ngx_crc32_update` -> `ngx_crc32_table256`).
   - `fuzz_build._preseed_flow_stubs` writes `<out_bin>_link_globals/link_stubs.c` before Attempt 1 (recomputing over widened `flow_build_sources` when needed) so both `build_module_binary` and `build_coverage_binary` link in **1 attempt** with zero `link_repair` rounds and populate the build cache cleanly.
   - `link_stubs_source` emits unbuffered `write(2, ...)` + `abort()` function stubs (no `fprintf`/`strlen` on unregistered `.rodata`) and type-free `.bss` global stubs (bypassing non-self-contained project headers and by-value struct rejection).
   - `_dag_symbol_tables` skips `is_static` functions (preventing static/extern name clashes), keeps `build_only_functions` separate (always linked, never stubbed), and blocks stubbing linked-library functions unless explicitly outside `flow_files` and listed in the widened stub set.
4. **Reachable-only E-ACSL instrumentation & Frama-C printer fixes (`fuzz_build.py`, `eacsl_toolchain.py`, `templates/fc_stubs/fc_compat_types.h`):**
   - `_flow_cluster_functions` scopes `-rte-select` / `-e-acsl-functions` on `address_flow` clusters to reachable cluster + harness-called functions (skipping `header` + `is_static` helpers while keeping explicit `_harness_header_entries`), avoiding instrumentation of hundreds of dead functions living in `build_sources`.
   - `build_module_binary` avoids re-running E-ACSL in `repair_link_rounds` after a non-link Stage 2 compile error, timeout, or stub-only repair.
   - `fc_compat_types.h` declares `/*@ assigns \nothing; */ void __sync_synchronize(void);` and `eacsl_toolchain.rewrite_sync_builtins` unmangles Frama-C `gcc_builtins.json` typed `__sync_*_<intN>_t` calls back to polymorphic `__sync_*` builtins before Stage 2 link.
5. **Coverage exclusion (`fuzz_coverage.py`):** `_coverage_file_role` classifies `link_stubs.c`, `link_globals.c`, and `_link_globals/` as `"harness"`, keeping generated stubs out of target coverage.

## 5. What Each Option Gives Up

- **A:** nothing in reach, but one cluster holds the program and its E-ACSL build exceeds 3600 s and 10.68 GiB RSS.
- **B:** 858 functions become unanalysable in any cluster (848 reachable via callbacks); 8 harnesses lose callees they can execute.
- **C:** nothing in reach, but 97 of 108 clusters remain over the limits and every build is still the whole program.
- **D:** shortens Eva only, and only for multi-case dispatch harnesses.
- **E (implemented):** nothing a generated harness can execute under closed-world harnesses and complete schema-6 facts. Seven single-anchor clusters remain `over_limit`. Any reach miss surfaces loudly via `FRAMAC_LINK_STUB_CALLED` in Phase 1 (classified as a pipeline defect) or `address_flow_missing_body` / `address_flow_missing_global` in Phase 2.

## 6. Validation Results & Policy for Over-Limit Clusters

### 6.1 End-to-End Validation (`framac-analysis:latest`)

1. **Docker counterexample suite (`tests/test_unit_split_docker.py`, 9/9 green):** verifies `ce1` (linked library), `ce2` (local/struct external callback), `ce3` (function-pointer cast), `ce4_inc` (included `.inc` global), `ce5` (non-self-contained header + by-value struct global in `.bss`), `ce6` (dispatch-case global), `ce7` (`__attribute__((constructor))`), deliberate stub-hit in both ASan and E-ACSL (`FRAMAC_LINK_STUB_CALLED` + `parse_link_stub_abort`), and deliberate omitted-body Eva C6 gate (`address_flow_missing_body`).
2. **Real nginx 1.31.9 scratch validation (read-only over `run-5` work tree, isolated scratch dir):**

| Cluster | Harness `sources` (DAG -> sidecar) | Cold `build_module_binary` (`engine`, `attempts`, `link_repair`, `preseeded`) | `-rte-select` (`dropped`) | `instrumented.c` | Cold Wall / Peak RSS | 2nd Build `cache.hit` | Short Fuzz (`link_stub_aborts`) | Cold Coverage Build | Eva C6 Gate (`status`, discharged) |
| :--- | :--- | :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- |
| `nginx__ngx_string_2` | 6 -> 6 | **`eacsl`**, `rc=0`, **1 attempt**, `link_repair=null`, `16 / 3` | 13 (`[]`) | 1.113 MB | **68.5 s** (`1:09.38`) / **556.7 MiB** | **`true`** | 665 execs in 0.23 s (**0** aborts; real E-ACSL `\initialized` hit at `ngx_string.c:2009`) | 31.5 s / 115.8 MiB, 1 attempt, `link_repair=null`, `link_stubs.c` = 0 target files | **`ok`** (`missing_bodies=null`, `missing_globals=null`, 97.8% discharged) |
| `nginx__ngx_files` | 4 -> 21 | **`eacsl`**, `rc=0`, **1 attempt**, `link_repair=null`, `72 / 9` | 56 (`[]`) | 18.871 MB | **277.4 s** (`4:38.28`) / **1,328.6 MiB** | **`true`** | **0** aborts (startup hit unrelated upstream E-ACSL PIE `&environ` bug logged in [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md)) | 89.5 s / 117.3 MiB, 1 attempt, `link_repair=null`, `cache.hit=true` on 2nd build | **`ok`** (`missing_bodies=null`, `missing_globals=null`, 95.4% discharged) |
| `nginx__ngx_bpf` | 29 -> 44 (vs 135 in run-5) | `sanitizers` fallback, `rc=0`, **1 attempt**, `link_repair=null`, `74 / 10` | 190 (`[]`) | 77.418 MB | **899.9 s** (`15:00.72`) / **3,178.6 MiB** | `cov` `true` | 258 fork execs (**0** aborts) | 181.6 s / 177.6 MiB, 1 attempt, `link_repair=null`, `link_stubs.c` = 0 target files | **`ok`** (`missing_bodies=null`, `missing_globals=null`, 96.6% discharged) |

Note on `nginx__ngx_bpf` E-ACSL fallback: Stage 1 and Stage 2 ran in a single pass with zero `__sync_*`, `DIR`, `ngx_regex_t`, or link errors; Stage 2 hit only an upstream Frama-C 34 `-rte` bug emitting `_Alignof(ngx_thread_pool_t)` on incomplete `struct ngx_thread_pool_s` in `ngx_http_core_merge_loc_conf` (logged in [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md)).

### 6.2 Policy for the Seven Single-Anchor `over_limit` Clusters (Design Open Item 4)

The seven `over_limit` clusters (`nginx__nginx`, `nginx__ngx_process_cycle`, `nginx__ngx_process_cycle_2`, `nginx__ngx_cycle`, `nginx__ngx_http_proxy_v2_module`, `nginx__ngx_http_upstream`, `nginx__ngx_http_request`) are each anchored by a single entry point whose genuine address-flow reach exceeds 400 functions or 15,000 lines, so neither entry-point splitting nor Eva sharding can subdivide them further:

- The DAG marks each with `over_limit` and lists them in `modules.<unit>.split.over_limit`.
- Within-limit clusters never absorb `over_limit` clusters during overlap merging, D3 rescue, packing, or `api_harness` cross-cluster initializer selection (`D2(a)`).
- **Per-run operator choice:** by default these clusters stay in the Make plan with the fixed Eva and build caps; for modules that hit the fixed caps, the operator records per-module overrides with `pipeline_make.py params set --module <mod> --fuzz-engine sanitizers` (or accepts a partial/capped Eva result and relies on fuzzing + per-function WP, which is context-free and unaffected by cluster size). Never raise the global fixed time limits.
