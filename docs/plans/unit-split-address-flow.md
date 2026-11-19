# Unit Split for Callback-Heavy C: Address-Flow Reach and Narrow Build Sources

- **Plans index:** [`./README.md`](./README.md)
- **Troubleshooting entry:** [`../troubleshooting/phase0-build-and-model.md`](../troubleshooting/phase0-build-and-model.md) ("The Unit Split Leaves One Cluster With Almost the Whole Program")
- **Branch:** `claude/unit-split-indirect-edges` (commits `63cddeb`, `003e261`, `b64a3db`, and the documentation commit after them). The branch is not merged.
- **Code:** [`../../scripts/unit_split.py`](../../scripts/unit_split.py), [`../../scripts/phase0_dump.ml`](../../scripts/phase0_dump.ml), [`../../scripts/phase0_model.py`](../../scripts/phase0_model.py), [`../../scripts/build_callgraph_dag.py`](../../scripts/build_callgraph_dag.py), [`../../scripts/generate_harness.py`](../../scripts/generate_harness.py), [`../../scripts/fuzz_build.py`](../../scripts/fuzz_build.py)

## 1. Problem

On nginx, the unit split ([`../../scripts/unit_split.py`](../../scripts/unit_split.py)) does not divide the program:

- **run-2:** one cluster held 2208 of 2240 functions.
- **run-5:** one cluster held 1650 of 1679 functions (102,784 lines). The other, `nginx__ngx_bpf`, held 23 functions.

There are three causes:

1. **Indirect calls are matched by signature.** The Phase 0 model resolves an indirect call to every address-taken function with a matching signature (`narrowing: none`). On run-5 this gives 4761 of the 8779 edges. nginx's pool cleanup handlers, event handlers and module hooks share a few signatures, so a single entry point such as `ngx_destroy_pool` reaches about 1100 functions. The overlap merge then folds every cluster into one.
2. **Source lists follow the same edges.** `generate_harness._merge_dag_harness_sources` adds the lexer-module closure of every function a harness names, and those closures follow every edge. Even the 23-function `nginx__ngx_bpf` cluster was built from 134 sources.
3. **Link repair adds whole files.** Each file it adds names more symbols. On nginx, every file eventually reaches the whole program. The `objs/ngx_modules.c` chain below starts from the smallest prototype cluster (10 functions in 4 files):

   `ngx_files.c -[ngx_thread_task_alloc]-> ngx_thread_pool.c -[ngx_spinlock]-> ngx_spinlock.c -[ngx_ncpu]-> ngx_posix_init.c -[ngx_writev_chain]-> ngx_writev_chain.c -[ngx_debug_point]-> ngx_process.c -[ngx_cycle]-> ngx_cycle.c -[ngx_cycle_modules]-> ngx_module.c -[ngx_module_names]-> objs/ngx_modules.c`

   From there, `objs/ngx_modules.c` names every module. Both run-5 builds went from 134 sources to 136 (link repair added `src/core/nginx.c` and `objs/ngx_modules.c`), which is every file but one of the 137 the program compiles. The E-ACSL build of such a cluster is the build that hit the 3600 s limit (S14).

The build and Eva time limits stay fixed. The fix must come from smaller units.

## 2. Options Compared on run-5

The measurements use run-5's `callgraph_dag.json` and `phase0_model.json` (unit `nginx`: 1679 functions, 1669 reached, 103,283 lines in function bodies; the program is 137 files and 127,146 lines). They were taken with the final code on the branch, at the default limits: 400 functions, 15,000 lines, overlap 0.5, packing under 10.

The address-flow facts did not come from Frama-C, because run-5's model predates dump schema 6. They were derived from the relocations of a scratch gcc build of the same nginx configuration and mapped onto run-5's DAG keys. Where a function both calls and takes the address of the same function, the ELF data cannot tell the two apart, so the reference counts as address-taken (conservative). The prototype computes these facts from Frama-C's AST instead (`phase0_dump.ml`); the model selftest checks them, but they have not been computed on nginx yet (section 6).

| Option | Clusters | Over a limit | Largest within limits | Unclustered | Files per build (before -> after link repair) | What a harness can no longer reach |
| :--- | ---: | ---: | :--- | ---: | :--- | :--- |
| A. Status quo (all edges, uncapped merge) | 2 | 1 (1650 fns, 102,784 lines) | 23 fns | 10 | 134 -> 136 (both clusters) | Nothing. The E-ACSL build of the large cluster exceeds 3600 s. |
| B. Direct edges only (type-match edges dropped) | 15 | 1 (286 fns, 19,250 lines) | 279 fns | 858 | Lexer closures, then the whole program after link repair | 848 of the 858 unclustered functions are executable from some harness. 8 of 15 harnesses lose callees they can execute (at most 1367, median 6). Eva sees those callees without bodies. |
| C. All edges, merges capped at the limits | 108 | 97 (about 1092 fns and 69,701 lines each) | 271 fns (median 18) | 10 | Lexer closures, then the whole program after link repair | Nothing, but 97 of the 108 clusters are still over a limit. |
| D. Eva sharding ([`../guides/eva-sharding.md`](../guides/eva-sharding.md)) | unchanged | unchanged | - | - | unchanged | Nothing. It splits one Eva run by dispatch case, so it shortens Eva only, not the E-ACSL build, and a cluster with a single anchor has nothing to shard. |
| **E. Address-flow reach, capped merges, narrow build sources, link stubs** | **21** | **7** (below) | **295 fns (median 91.5)** | **10** | `build_sources`: median 28.5, max 97 (131 to 134 if link repair added whole files; stubs keep it at the build files) | Nothing a generated harness can execute (section 3). Per cluster it drops 0 to 1381 signature-matched candidates whose address never reaches its code. |

The split itself takes 1.2 s with address-flow reach and 8.5 s with the call graph.

### 2.1 Option E per cluster

`build files` are the cluster's `build_sources`; `link closure` is the number of files if link repair added whole files instead of stubbing; `stubs` is how many functions and globals `link_stubs` lists; `dropped` is the number of call-graph candidates that the address-flow reach leaves out.

| Cluster | Functions | Lines | Anchors | Build files | Build file lines | Link closure | Stubs (fns / globals) | Dropped | Over a limit |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- | ---: | :--- |
| `nginx__nginx` | 1587 | 100,231 | 1 | 131 | 125,189 | 131 | 0 / 0 | 0 | yes |
| `nginx__ngx_process_cycle` | 1553 | 98,306 | 1 | 127 | 124,483 | 131 | 4 / 0 | 6 | yes |
| `nginx__ngx_process_cycle_2` | 1523 | 96,380 | 1 | 124 | 124,032 | 131 | 11 / 0 | 14 | yes |
| `nginx__ngx_cycle` | 1502 | 95,405 | 1 | 124 | 124,032 | 131 | 11 / 0 | 17 | yes |
| `nginx__ngx_http_proxy_v2_module` | 457 | 33,323 | 1 | 64 | 85,604 | 131 | 45 / 1 | 635 | yes |
| `nginx__ngx_http_upstream` | 405 | 28,216 | 1 | 58 | 72,434 | 131 | 49 / 1 | 687 | yes |
| `nginx__ngx_http_script` | 295 | 14,175 | 132 | 97 | 101,585 | 131 | 85 / 4 | 942 | no |
| `nginx__ngx_http_request_2` | 241 | 15,691 | 1 | 38 | 49,478 | 131 | 63 / 11 | 851 | yes (lines) |
| `nginx__ngx_http_request` | 234 | 14,963 | 36 | 36 | 46,632 | 131 | 72 / 11 | 858 | no |
| `nginx__ngx_http_core_module` | 193 | 10,862 | 88 | 48 | 71,021 | 131 | 74 / 2 | 905 | no |
| `nginx__ngx_module` | 193 | 11,036 | 12 | 92 | 89,820 | 131 | 132 / 4 | 935 | no |
| `nginx__ngx_slab` | 116 | 6542 | 34 | 37 | 37,198 | 131 | 85 / 7 | 982 | no |
| `nginx__ngx_conf_file` | 102 | 4696 | 56 | 28 | 18,804 | 132 | 61 / 9 | 1381 | no |
| `nginx__ngx_connection` | 93 | 6759 | 22 | 20 | 17,550 | 131 | 47 / 14 | 1006 | no |
| `nginx__ngx_buf` | 90 | 4820 | 42 | 29 | 34,341 | 132 | 119 / 14 | 1018 | no |
| `nginx__ngx_bpf` | 72 | 3416 | 57 | 30 | 22,904 | 134 | 76 / 15 | 1134 | no |
| `nginx__ngx_event_accept` | 59 | 2891 | 13 | 23 | 14,644 | 131 | 45 / 11 | 1041 | no |
| `nginx__ngx_radix_tree` | 16 | 466 | 16 | 12 | 17,744 | 132 | 125 / 12 | 1086 | no |
| `nginx__ngx_string` | 14 | 464 | 14 | 4 | 2540 | 131 | 14 / 6 | 0 | no |
| `nginx__ngx_files` | 10 | 187 | 9 | 4 | 1576 | 131 | 2 / 2 | 0 | no |
| `nginx__ngx_http_script_2` | 10 | 173 | 10 | 2 | 4897 | 131 | 41 / 7 | 31 | no |

Seven clusters remain over a limit:

- **The four startup clusters** (`main`, `ngx_master_process_cycle`, `ngx_single_process_cycle`, `ngx_init_cycle`). These really do reach the program: they read `ngx_modules`, whose initializer names every module table, and those tables name every handler.
- **`ngx_http_proxy_v2_module`** (457 functions) and **`ngx_http_upstream_init`** (405 functions, 28,216 lines).
- **`ngx_http_init_connection`** (`nginx__ngx_http_request_2`, 15,691 lines).

Each of these has a single anchor, so no split of entry points can make it smaller.

## 3. Address-Flow Reach

A function's address flows into a harness's code when one of these holds:

- a reached function's body takes it (`address_refs`: `&f` or `f` used as a value);
- it is named in the initializer of a global the reached code reads (`global_refs`, then `init_functions`);
- it is named in the initializer of a global named by such an initializer, transitively (`init_globals`).

`unit_split.flow_reach` computes this as a fixpoint:

- **Direct calls are always followed.** This includes callback-argument and thread-spawn edges, so a comparator passed to `qsort` or a thread entry passed to `pthread_create` counts as called.
- **The address pool grows** from the `address_refs` of reached functions and from the initializers of the globals they read.
- **An indirect callee is followed only if it is in the pool.** The DAG lists these callees per function as `indirect_callees`: the callees reached only through an indirect site's type match.

A cluster takes the reach of the union of its anchors. Pools combine, so merging two clusters can add callees that neither cluster had alone (`flow_dag` in [`../../tests/test_unit_split.py`](../../tests/test_unit_split.py): `h4` joins only when `run` and `elsewhere` share a harness).

### 3.1 Why It Is Sound for the Generated Harnesses

A function pointer called by reached code holds one of three things:

1. An address that reached code stored. Reached code took that address, so it is in the pool.
2. A global's initializer. Eva runs `-main eva_main` without `-lib-entry`, so globals start from their initializers, and the reach follows the initializers of every global it reads.
3. A value the harness wrote. `api_harness` never makes up a function pointer: a struct's function-pointer field stays NULL, and a callback parameter is a stub the harness defines.

The library cannot produce a project function's address unless the project passed it in. Passing it in is a callback edge, so the reach follows it.

What it gives up:

- **Function pointers obtained by `dlsym`, built from integers or read from input.** None of these is reachable from code the pipeline generates. Reading a pointer from input is undefined behavior that the fuzz harness never produces.
- **A hand-written harness.** It is only covered if it follows the same rule as `api_harness`.
- **Complete facts.** The reach is only as good as the model's facts. A unit where any function lacks them falls back to the call-graph reach (`reach: call_graph`, as before), so an old model never yields a narrower cluster.

WP is context-free and keeps every edge. The prototype narrows none of `indirect_calls`, the candidates, the waves, or the unit and lexer `required_sources`. The new data lives only in new fields.

## 4. Narrow Build Sources and Link Stubs

`unit_split.build_plan` gives every address-flow cluster two fields:

- **`build_sources`:** the .c files that define its functions, plus the files that define the globals it reads.
- **`link_stubs`:** the unit's non-static functions and globals that those files name (calls, addresses, global uses, initializers) but do not define.

By construction, a stub is never reachable. A reached function's file is compiled, and so is the file of any global the reached code reads.

- **Harness sources.** `generate_harness._merge_dag_harness_sources(module_name=...)` uses the cluster's `build_sources` instead of the lexer closures. A function the harness names outside the cluster joins the reach. `_flow_harness_sources` recomputes the reach of the anchors plus those functions and takes that plan's `build_sources`.
- **Link repair.** In `fuzz_build.repair_sources_for_link`, when the harness module is an address-flow cluster, a function defined outside the cluster's files is no longer linked from its file. It is defined in the generated `<out_bin>_link_globals/link_stubs.c` (`link_stubs_source`). A global outside those files is defined zero-initialized in `link_globals.c`, as for another link unit's global. The build record lists `stubbed_functions` and `functions_file`.
- **The stub.** Each stub is a file-scope `__asm__` symbol (x86-64, the `gcc_x86_64` machdep) that jumps to `__framac_link_stub_called(name)`, which prints `FRAMAC_LINK_STUB_CALLED: <name>` and aborts. Because the stub has no C type, no project prototype can conflict with it in Frama-C's link or in clang's. It was checked in the analysis image through `frama-c -print`, clang with ASan on the printed code, and a full `e-acsl-gcc` build. Each test program ran once without calling the stub and once calling it (`rc=134`, the marker printed).

The result is that a cluster builds from its median 28.5 files instead of 136.

## 5. What Each Option Gives Up

- **A:** nothing in reach. But one cluster holds the program, and its E-ACSL build does not finish in 3600 s.
- **B:** 858 functions, nearly all executable from some harness (848), become unanalysable in any cluster, mostly the handlers that callbacks reach. 8 harnesses lose callees they can run, and Eva meets those callees without bodies.
- **C:** nothing in reach, but 97 of the 108 clusters still exceed the limits, and every build is still the whole program.
- **D:** nothing in reach. It shortens Eva only, and only for dispatch harnesses with several cases.
- **E:** nothing a generated harness can execute, under the conditions of section 3.1: closed-world harnesses, complete model facts, and indirect callees matched by signature as before. Seven single-anchor clusters stay over the limits.

## 6. Recommendation and Open Items

**Adopt E**, as prototyped on the branch. Of the four options, it is the only one that brings most of nginx within the fixed limits and removes nothing a harness can run. On a unit without indirect calls, the address-flow reach is the call graph's reach. No benchmark unit splits at the default limits, so their builds do not change.

Open before merging:

1. **Run Phase 0 on nginx with dump schema 6.** Compare its `address_refs`, `global_refs` and initializer facts with the ELF-derived ones above, then re-run the split. The measurements here rest on the ELF facts.
2. **Crash triage.** `FRAMAC_LINK_STUB_CALLED` must be classified as a pipeline defect (a reach the split missed), never as a target finding. Today it would surface as an abort.
3. **Eva gate for missing bodies.** A reached project function without a body (Eva's "Neither code nor specification") means the reach missed something. A gate on [`../../scripts/framac_common.py`](../../scripts/framac_common.py) `missing_spec_messages`, restricted to the unit's functions, would make this loud in Eva the way the stub makes it loud in the fuzz build.
4. **The seven over-limit clusters.** These are marked `over_limit` in the DAG, and their Eva runs may reach the cap. Sharding does not apply to a single anchor. Which engine to run on them (Eva up to the cap with a partial result, or fuzzing and WP only) is a decision for the user.
5. **Large `build_sources`.** `nginx__ngx_http_script` (97 files) and `nginx__ngx_module` (92) are within the function limit, but their builds still compile most of the program, because packing gathers 132 and 12 anchors. Whether the E-ACSL build of these fits in 3600 s has to be measured. The E-ACSL parse and pre-analysis are whole-source; only the instrumentation is limited by `-e-acsl-functions`.
6. **No real-target run yet.** The prototype has unit tests only (`tests/test_unit_split.py`, `tests/test_link_repair_flow_stubs.py`, `tests/test_dag_model_view.py`, `tests/test_phase0_model.py`, and the selftest of `phase0_model.py` in `framac-analysis:latest`).
