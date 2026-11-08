# Phase 0 redesign: build-derived inventory, Frama-C call graph

Status: implemented (steps I0–I10, see the note below). It was first validated by the proof of concept in `poc/phase0/` (first results in §7).

> **Later note (2026-11-08):** this design was implemented in steps I0–I10 of [phase0-implementation-plan.md](phase0-implementation-plan.md), and `poc/phase0/` was removed in remediation step R9 (decision D6). The paths below are those of the proof of concept: its reproducers and seeded corpus now live in `tests/fixtures/phase0/reproducers/` and `tests/fixtures/phase0/seeded/` (8 projects, run by `benchmark.py seeded`), and its scripts (`run.ps1`, `ab.py`, `seeded.py`) are gone.

## 1. Why

Phase 0 has to give later phases four things:

| Output | Used by |
| :--- | :--- |
| **Inventory**: every compiled function, named as Eva and WP will name it | ledger units, fingerprints, report |
| **Call edges**: direct and indirect | `wp_scheduler` readiness, `audit-hypotheses`, `required_sources`, reach gate |
| **Modules**: sources, per-file flags, configured `#if` branches | harnesses, Make recipes, Eva slices |
| **Entry points and trust**: the public API, which functions take attacker bytes | harness reach gate, `untrusted_surface`, contract trust-boundary check |

Today all four come from one preprocessor-blind lexer pass (`build_callgraph_dag.py`, `callgraph_source: "regex"`). Each defect from the Phase 0 review comes from that choice:

1. Same-named statics in different files overwrite each other: a function disappears from the ledger, calls resolve to the wrong body, and the module's tier is computed from the other file.
2. Disabled `#if` code is inventoried, becomes an entry point, and the reach gate demands a harness case for code that is never compiled.
3. Function-pointer calls add no edges.
4. Entry points are "non-static and not called in this directory", not the public API.
5. Modules are directories, not link units.
6. Only `-I -D -U -std` survive from `compile_commands.json`.

The redesign also moves the Phase 0 gates (reach, build-check) from skill prose into Make dependencies. That part needs no new analysis and can ship independently.

## 2. Principles

- **One identity for a function: Frama-C's.** Inventory and edges come from the Frama-C kernel run on the same sources and flags Eva and WP will use. Any other source (compiler, linker, lexer) is mapped onto those identities, never the reverse.
- **Ask the build, not the text.** When the target builds, the build says which files are compiled, with which flags, into which artifact, and what is exported.
- **Degrade visibly.** Every fact carries its source (`frama-c-kernel`, `gcc-callgraph-info`, `linker`, `lexer`). A target that does not build, or a module Frama-C cannot parse, is still inventoried, with lower confidence stated in the ledger and the report.
- **Fail early.** A module Frama-C cannot parse would fail in Eva and WP anyway; Phase 0 reports it instead of build-check discovering it.
- **Deterministic, in Make.** No step needs judgment; all of it is a Make target in the container. The parent agent still chooses harness shapes (Phase 0 step 4), on better inputs.

## 3. Pipeline

```text
target (ro) ──copy──▶ scratch ──bear intercept── build ──▶ events.json
                                                            │
             ┌──────────────────────────────────────────────┤
             ▼                                              ▼
   compile_commands.json (citnames)              link/archive steps
   per-file flags, configured TUs                artifacts → objects → sources
             │                                              │
             ▼                                              ▼
   Frama-C per link unit                          nm on .o / nm -D on .so
   (sources + per-file flags, -load-module dump)  statics vs globals, exports
   inventory, direct calls, indirect sites,                 │
   address-taken functions, -cg (fn-pointer over-approx.)   │
             │                                              │
             └──────────────────────┬───────────────────────┘
                                    ▼
                      model.json (+ callgraph_dag.json view)
                      functions, edges(kind, source), units,
                      entry points, externals, thread entries,
                      parse status per unit, provenance
```

### 3.1 Build capture

- Copy the target to scratch (the target stays read-only) and run its build under `bear intercept`. `bear citnames` gives `compile_commands.json`; the raw events also contain link (`cc -o x a.o b.o`, `-shared`) and archive (`ar`) steps, which `citnames` drops.
- The build runs in the hardened container through `sandbox_exec.py`, sized as `phase-dynamic`, exactly as the optional `bear` step of the current skill.
- No build (no Makefile, CMake or Meson, or the build fails): fall back to §3.5.

### 3.2 Link units are the modules

- Each executable, shared library and static library the build produced is a unit; its sources are the compile-command sources of its input objects (`.a` members followed through `ar` steps).
- A unit lists the project units it links (`links`). Inventory and Eva slices use the unit's own sources plus the sources of linked static libraries the call graph actually reaches, which replaces `required_sources`.
- Objects linked into no artifact (tests built but not linked, dead files) form one `unlinked` unit per directory, flagged.
- A unit too large for one Eva run is split later by call-graph clustering (not in the PoC).

### 3.3 Frama-C inventory and edges

Per unit, one Frama-C run over its sources with each file's own flags (`-cpp-extra-args-per-file`, keeping project `-I/-iquote/-include/-D/-U/-std`, dropping host system include paths so Frama-C's libc is used as in Eva) and a small AST dump module, the same technique as `kernel_ast.py`:

- defined functions: kernel name, source name, file, line, `static`, signature;
- direct calls; indirect call sites with the called type;
- address-taken functions (in code and in global initializers), the candidates of every indirect call;
- external callees (declared, called, not defined).

Indirect edges: `-cg` with `-cg-function-pointers` gives a sound over-approximation without Eva; the dump gives the same by matching address-taken functions to the call site's type. Alias (`-alias`) can narrow it; Eva narrows it per harness later (already done by `collect_flows`). The PoC measures how much each narrows.

Static name collisions are solved by construction: the kernel renames (`helper`, `helper_0`) and the dump maps each kernel name back to `(file, name)`.

If Frama-C cannot parse a unit, that unit falls back to GCC: each compile command replayed with `-fcallgraph-info` gives per-TU edges (indirect sites marked) on the compiler's own preprocessing. The unit is flagged `frama-c: parse_failed` with the first error, which is what the build-check repair loop needs anyway.

### 3.4 Entry points and trust

- Shared library: `nm -D --defined-only`, version scripts and `visibility` give the exported API.
- Static library: global functions declared in the library's public headers (installed headers when `make install DESTDIR=` works, else headers outside the source directories).
- Executable: `main`.
- Thread entries: functions passed to `pthread_create` (and similar); their presence marks the unit `concurrent` so the report does not claim sequential soundness for it.
- Trust (`untrusted_surface`): default to the exported API and functions on a call path from input functions (`read`, `recv`, `fread`, argv); `THREAT_MODEL.md` overrides. Optional CodeQL source-to-sink facts (open-source targets) refine it. Not in the first PoC iteration.

### 3.5 Fallback without a build

The lexer stays, run on `cpp` output with the discovered flags so `#if` is resolved, and its facts are marked `callgraph_source: "lexer"` with lower confidence. Its two correctness bugs (static collisions, entry points) are fixed in place regardless.

## 4. Output and compatibility

The new step writes:

- `workspace/reports/phase0_model.json`: the model above, with provenance per fact.
- `workspace/reports/callgraph_dag.json`: a view with the current schema, so `ledger.py seed`, `harness_reach.py`, `generate_harness.py` and `pipeline_make.py gen` keep working unchanged during migration. Field mapping: module = unit, `required_sources` = unit sources plus reached linked sources, `candidate_entry_points` = API entry points, `cppflags` = per-file flags merged per unit, `callgraph_source` = per function.

Tiers (`classify_module_tier`) and security-property inference are out of scope here; they get better inputs (real units, complexity from `-metrics`, real edges) but their redesign is separate (MetAcsl for L4–L6 is the candidate).

## 5. Validation plan (the proof of concept)

`poc/phase0/` holds a self-contained sandbox; nothing in `scripts/` changes until it shows the gain.

- `reproducers/`: small buildable projects, each exercising one defect, each with an exact `truth.json` (functions, not-compiled definitions, direct and indirect edges, units, entry points, thread entries).
- `phase0b.py`: the new extractor (§3.1–3.4), stdlib Python plus the container tools.
- `score.py`: runs the current extractor and the new one on each reproducer and scores both against the truth (precision and recall per fact class); on the benchmark targets (`benchmark/manifest.json`), which have no full truth, it reports whether each known bug's function is inventoried in the right file, whether it is reachable from an entry point, the inventory and edge differences, parse status and time.
- `run.ps1` / `run.sh`: run everything in the existing image with the repository mounted read-only.

Acceptance, before migrating:

1. Reproducers: the new extractor has recall 1.0 for functions, direct edges and indirect edges, precision 1.0 for functions and direct edges, and reports no `not_compiled` function; entry points and units match the truth.
2. Benchmark targets: every known bug's function is inventoried in its file and reachable from an entry point, and Phase 0 time stays within the same order as today.
3. Every unit Frama-C cannot parse is reported with its first error, and its GCC fallback edges are present.

## 6. Migration (after the PoC)

1. Fix the two lexer correctness bugs in place (file-qualified statics, API entry points) and make the gates Make dependencies. Independent, small.
2. Add `phase0b` as a Make target producing the model and the DAG view; select it when the build succeeds, keep the lexer otherwise.
3. Switch modules to link units; `harness_reach.py` and `generate_harness.py` read units and API entry points.
4. Trust from exports, input paths and the threat model; CodeQL as an optional capability.
5. Tier and security-layer redesign on the new inputs.

## 7. Proof-of-concept results (2026-11-07)

Run with `poc/phase0/run.ps1` on `framac-pipeline:latest` (Frama-C 34 dev, GCC 14, bear 3.1.6).

### Reproducers (exact ground truth)

Precision / recall, current lexer → new extractor:

| Reproducer | Functions | Direct edges | Indirect edges (recall) | Entry points | Units exact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| r01 static collision | 1.00/0.75 → 1.00/1.00 | 0.71/0.71 → 1.00/1.00 | n/a | 1.00/1.00 → 1.00/1.00 | 1/2 → 2/2 |
| r02 `#if` and `-D` | 0.62/1.00 → 1.00/1.00 | 0.73/0.89 → 1.00/1.00 | n/a | 0.60/1.00 → 1.00/1.00 | 0/2 → 2/2 |
| r03 function pointers | 1.00/1.00 → 1.00/1.00 | 0.25/1.00 → 1.00/1.00 | 0.00 → 1.00 | 0.50/1.00 → 1.00/1.00 | 1/2 → 2/2 |
| r04 public API | 1.00/1.00 → 1.00/1.00 | 1.00/1.00 → 1.00/1.00 | n/a | 1.00/0.71 → 1.00/1.00 | 2/2 → 2/2 |
| r05 link units | 1.00/1.00 → 1.00/1.00 | 1.00/1.00 → 1.00/1.00 | n/a | 1.00/0.78 → 1.00/1.00 | 2/3 → 3/3 |
| r06 `-include`, `-iquote`, `-isystem` | 0.86/1.00 → 1.00/1.00 | 0.86/1.00 → 1.00/1.00 | n/a | 1.00/1.00 → 1.00/1.00 | 1/2 → 2/2 |
| r07 macro-defined functions | 1.00/0.42 → 1.00/1.00 | 1.00/0.23 → 1.00/1.00 | n/a | 0.75/0.43 → 1.00/1.00 | 1/2 → 2/2 |
| r08 threads | 1.00/1.00 → 1.00/1.00 | 0.85/1.00 → 1.00/1.00 | 0.00 → 1.00 | 0.50/1.00 → 1.00/1.00 | 1/2 → 2/2 |
| r09 mixed HTTP parser | 0.91/0.78 → 1.00/1.00 | 0.72/0.64 → 1.00/1.00 | 0.00 → 1.00 | 0.62/0.83 → 1.00/1.00 | 1/2 → 2/2 |

The new extractor meets acceptance criterion 1 on every reproducer: precision and recall 1.0 on every
fact class, thread entries included, and no disabled function reported. The type-based indirect
resolution was also exact here (no extra targets), because the address-taken sets were small.

### Benchmark targets (no full truth)

All 8 known bugs (MINMEA-01..03, QCBOR-01..03 on two revisions) are inventoried in the right file
and reachable from an entry point with both extractors: these bugs sit in obvious parser entry
paths, so the redesign neither loses nor newly finds them. The differences are elsewhere:

| Target | What changed | Who is right |
| :--- | :--- | :--- |
| x509-parser | 163 indirect edges; the 35 functions the lexer left unreachable are now reached | new |
| oscs-qlz | 4 functions the lexer missed (`qlz_compress`, `qlz_decompress` and their cores, defined under configuration macros) | new |
| oscs-tweetnacl | The lexer inventories the macro names (`crypto_box`); the build and Frama-C see the real symbols (`crypto_box_curve25519xsalsa20poly1305_tweet`). Ledger units under the lexer's names would never match Eva and WP results | new |
| qcbor-dev/master | +472/+324 functions: `static inline` functions of `UsefulBuf.h` and other headers, compiled into every TU | new is right, but this inflates units: see open questions |
| oscs-jsmn, oscs-semver | Fewer functions: the default `make` target builds the library and its test, not the examples | depends on which build target is chosen |
| oscs-tweetnacl | One executable unit, so one entry point (`main`) and 27 API functions unreachable from it | gap: a library compiled straight into its executable has no API boundary |

Two fixes came from running real code, and both are in `phase0b.py`:

- The dump records a function's definition location. A function's first declaration is often the prototype in its header, so that would be the wrong location.
- `-std=c89` is dropped for Frama-C: it rejects the `//` comments in Frama-C's own libc headers.

No target needed the GCC fallback. Every unit parsed in Frama-C.

**Cost**: 1.0 s to 16.5 s per target, against 0.1 s to 1.9 s for the lexer. Both were measured with their scratch tree inside the container.

The new figure includes the target's own build, which is 4.3 s of QCBOR's total and most of minmea's (CMake configure). That build is work Phase 1's build-check does anyway. Frama-C parsing is about half of what remains. An executable unit re-parses the project libraries it links, so qcbortest parses all of QCBOR again. Parsing each source once per flag set, and running units in parallel, would cut that.

A first run had its scratch tree on the Windows bind mount and measured up to 115 s. File I/O, not the method, caused that. Next to Phase 1 and Phase 2 (60 to 900 CPU-seconds of fuzzing and up to 1800 s of Eva per module), the added Phase 0 time is negligible. Acceptance criterion 2 is met in practice.

### A/B through Phases 0–2 (2026-11-07)

`poc/phase0/ab.py` runs the benchmark's own Phases 0–2 twice per target: on the lexer DAG, then on the `dag_view.py` view of the new model. Fuzzing was off and Eva and replay on. The harnesses (from the manifest), the modules and the tiers are held fixed, so only the inventory and the call edges differ.

Each cell is lexer → new view:

| Metric | minmea | qcbor-master | x509-parser | jsmn | semver | stmr | qlz | tweetnacl |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Ledger functions | 22 → 23 | 389 → 709 | 213 → 212 | 27 → 6 | 64 → 60 | 17 → 17 | 18 → 22 | 64 → 64 |
| Units with Eva evidence | 18 → 22 | 12 → 12 | 211 → 210 | 6 → 6 | 33 → 33 | 15 → 15 | 14 → 18 | 61 → 61 |
| Eva-analysed functions with no ledger unit | 1 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | 4 → 0 | 12 → 0 |
| Planned RTE units Eva never saw | 0 → 3 | 1 → 1 | 9 → 8 | 0 → 0 | 12 → 12 | 1 → 1 | 7 → 7 | 34 → 22 |
| Phase 3 queue | 9 → 13 | 5 → 5 | 209 → 208 | 3 → 3 | 30 → 30 | 13 → 13 | 14 → 18 | 60 → 60 |
| Candidate units | 5 → 5 | 2 → 2 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 1 | 1 → 1 |
| Bugs retained | 3 → 3 | 2 → 2 | – | – | – | – | – | – |
| Phase 0 wall s | 5.8 → 8.9 | 7.5 → 16.1 | 8.4 → 17.9 | 4.2 → 5.1 | 4.1 → 5.2 | 3.8 → 5.5 | 4.5 → 8.3 | 4.8 → 6.5 |

qcbor-dev failed Phase 0 in both modes. The cause is an unrelated bug on `main`: `generate_harness.py` checks the arity of a call expression with a splitter that ignores braces, so `UsefulOutBuf_Init(&ob, (UsefulBuf){store, sizeof(store)})` counts as 3 arguments. x509-parser's `x509-parser` module fails Eva identically in both modes.

What it shows:

- **The ledger loses Eva results today.** Under the lexer, Eva analysed functions that have no ledger unit to record the result on. This happens to 4 core functions of qlz (`qlz_compress`, `qlz_decompress` and their cores) and to 12 tweetnacl functions under their real symbol names. With the new view every such function has a unit:
  - minmea gains 4 units with Eva evidence and 4 Phase 3 tasks;
  - qlz gains 4 units with Eva evidence and 4 Phase 3 tasks.
- **Lexer units that no analysis can match disappear.** tweetnacl's 12 macro-named units (`crypto_box`...) never received evidence, so Eva-unseen planned units fall from 34 to 22.
- **An existing finding now lands on a unit.** The Eva Invalid in `qlz_compress_core` (`ptr_value`, line 382) is a candidate in both runs. With the lexer it has no unit, so the ledger never marks anything `candidate` and never excludes the function from WP. With the new view it does both.
- **Unchanged:**
  - the known bugs (all retained in both modes);
  - Eva results on the functions both inventories share;
  - targets where the inventories already agree (stmr, semver).
- **Inventory size changes that need a design decision:**
  - QCBOR's extra 320 units are header `static inline` functions. They are seeded, but they are out of scope or unreached here, so they add no work.
  - jsmn and semver lose units for example and test files their default build doesn't compile.
- **A compatibility gap for migration.** Manifest harnesses call functions through macro aliases (tweetnacl's `crypto_hash`). `generate_harness.py` looks those names up in the DAG and doesn't find them under the real symbol, so it skips its DAG-based source expansion. Here that only dropped `randombytes.c`, which `crypto_hash` never calls. The new DAG should carry macro aliases, or consumers should resolve names through the preprocessor.

Verdict: on this benchmark the redesign changes no bug outcome. What it changes is the bookkeeping: Eva results that the lexer inventory silently dropped are now recorded on a unit. These results come from 2 of the 9 targets plus minmea's header functions, so it is a correctness gain in what the ledger and the report claim. It doesn't show more bugs found. A benchmark with bugs behind function pointers or configuration macros is still needed to test that.

### Seeded-bug benchmark: does Phase 0 change what is found? (2026-11-07)

The benchmark targets above can't answer this question: their harnesses are written by hand and their bugs sit on obvious paths. `poc/phase0/seeded/` (now `tests/fixtures/phase0/seeded/`) holds 7 small libraries. Each has one real, verified bug that is reachable only through one lexer weakness, plus decoys:
- code that is never compiled;
- internal helpers that crash only when called outside their contract.

`poc/phase0/seeded.py` runs each project through the real wrapper in two modes: Phase 0 with the lexer, or with the new extractor using link units as modules. Both modes then go through the same steps:
1. A **fixed mechanical harness policy** (`seeded_inner.py`) builds, for each module, one dispatch harness. It has one case per entry point Phase 0 reports, with arguments built from the prototype, and is compiled from the sources and flags Phase 0 reports.
2. The pipeline's own build, fuzz (30 CPU-seconds per module), Eva and ingest.

Since the harness policy is identical, Phase 0 alone decides what gets fuzzed and analysed.

| Project | Mechanism | Lexer | New Phase 0 |
| :--- | :--- | :--- | :--- |
| s01 | function generated by a macro in another file | missed: the module doesn't link without that file; decoy (a file not in the build) fired | found (fuzz) |
| s02 | handlers registered by token pasting | found, by accident: the handlers were offered as entry points; 3 harness-induced findings | found (fuzz); no noise |
| s03 | body selected by a Makefile `-D` | missed: fuzzed the uncompiled `#else` body and crashed there (false positive) | found (fuzz) |
| s04 | `-include config.h` shrinks a buffer | missed (Eva Unknown only); decoy helper fired | found (fuzz) |
| s05 | public API function also called internally | missed: not offered as an entry point | found (fuzz) |
| s06 | library over two directories (control) | found | found |
| s07 | same-named static helpers (control) | found | found |
| **Total** | | **3/7 bugs, 3 decoys fired, 4 other findings** | **7/7 bugs, 0 decoys, 1 other finding** |

The one remaining other finding, an E-ACSL initialization alarm in `s06`'s `next_field`, is the same in both modes.

Caveats:
- **These rates don't carry over to other code.** The corpus was built to exercise the lexer's known weaknesses. It shows that each weakness, when present, decides whether a bug is found or a false positive is raised. How common each weakness is comes from the real targets: on the 9 benchmark targets, qlz and tweetnacl hit the first two kinds, and x509-parser hits the function-pointer kind.
- **A mechanical policy stands in for the parent agent.** In a real run the agent writes harnesses from the DAG and might work around some gaps, for example by reading the Makefile. The policy measures what Phase 0 hands it, not what a careful agent could recover.
- **Each mode ran once.** Fuzzing is not deterministic, but every bug found here was found in under 30 CPU-seconds.

Two policy and scoring fixes happened during the run, and both apply equally to the two modes:
- the policy now accepts a bare `unsigned` parameter;
- the scorer tells a bug and a decoy apart by line when both are in the same function (s03).

### Alias narrowing of indirect edges (2026-11-08, plan step I4)

`phase0_model.py run --alias` loads a second module, `scripts/phase0_alias.ml`, into the same Frama-C run as the dump. It runs Frama-C 35's Alias plugin (`Alias.Analysis.compute`, a Steensgaard-style may-alias analysis, field-sensitive) on the same AST. Then, for each indirect call `(*e)(...)`, it reads the function variables in the vertex of `*e` in the state before the call. That set is the one the plugin itself uses to resolve the call. The model intersects each site's type match with that set.

A site keeps its full type match, with the reason recorded in `narrowing_reason`, in these cases:
- Alias failed, timed out (300 s, fixed), crashed or did not compile;
- Alias has no state before the call;
- the pointer's vertex holds no function;
- Alias names only functions outside the type match.

Every site records `narrowing` (`alias` or `none`), its reason and the candidates it `dropped`. The edges a narrowed site keeps carry the source `alias`.

Measured with one build capture per project, then the model with Alias off and on, twice each, alternating, on the same build tree (`framac-analysis:latest`, Frama-C 35). Times are the model's own `seconds`, median of the two runs. Sites are counted per parse, so a source parsed for two units counts twice.

| Project | Indirect sites | Narrowed by Alias | Why the others kept their type match | Indirect edges off → on | Precision off → on | Recall off → on | Model s off → on |
| :--- | ---: | ---: | :--- | ---: | ---: | ---: | ---: |
| r03 | 5 | 0 | no target: 5 (pointers read through `bsearch`'s result, struct fields set in `main`) | 13 → 13 | 1.00 → 1.00 | 1.00 → 1.00 | 0.63 → 0.82 |
| r08 | 0 | 0 | (thread spawns only, not type-matched) | 2 → 2 | 1.00 → 1.00 | 1.00 → 1.00 | 0.62 → 0.80 |
| r09 | 5 | 0 | no target: 5 (callback fields set in `main`) | 5 → 5 | 1.00 → 1.00 | 1.00 → 1.00 | 0.71 → 0.92 |
| s02 | 1 | 1 (to the same 5 handlers) | | 5 → 5 | 1.00 → 1.00 | 1.00 → 1.00 | 0.58 → 0.77 |
| other 12 reproducers and seeded | 0 | 0 | | 0 → 0 | | | +0.13 to +0.19 |
| x509-parser | 20 | 14 | no target: 4; empty type match: 2 | **163 → 122** | | | 1.67 → 3.27 |
| qcbor-dev | 14 | 0 | no target: 11; empty type match: 3 | 26 → 26 | | | 2.02 → 2.58 |
| qcbor-master | 8 | 0 | no target: 7; empty type match: 1 | 10 → 10 | | | 1.20 → 1.48 |
| CryptoLib | 262 | 0 | no target: 262 | 142 → 142 | | | 4.88 → 5.25 |
| minmea, jsmn, semver, stmr, qlz, tweetnacl | 0 | 0 | | 0 → 0 | | | +0.16 to +0.20 |

Precision and recall are computed on the four projects whose indirect edges are exact. For r03, r08 and r09 the edges come from their truth files. s02's truth file lists no edges, so its single site, `run_op` → the five `ops[]` handlers, was read from the source. Everything else in the model is identical with Alias off and on, on every project: functions, direct edges, externals and thread entries.

**Cost.** Alias itself takes at most 1.45 s per parse (x509-parser, each of its 3 parses), 0.59 s on CryptoLib, 0.37 s on qcbor-dev and under 0.05 s elsewhere. The fixed cost is the second module's compilation, about 0.15 s per model run. On x509-parser the model's wall time doubles, from 1.7 s to 3.3 s. Elsewhere it grows by 0.15 to 0.55 s.

**What Alias narrows.** It narrows only on x509-parser: 41 of 163 edges are dropped (25 %). Read against the source, every dropped edge is spurious. The algorithm tables are `static const` global initializers (`DECL_PUBKEY_ALG` and similar macros) with several function-pointer fields of the same type. The type match joins those fields, while field-sensitive Alias keeps them apart:
- `alg->parse_pubkey` keeps the 12 `parse_pubkey_*` and drops the 14 `parse_algoid_pubkey_params_*`;
- `talg->parse_algoid_pubkey_params` does the reverse;
- the CRL extension and CRL entry extension tables separate in the same way (12 + 3).

**Where Alias gives nothing.** Every site of the reproducers, the seeded projects and QCBOR that reads a pointer set in another function gets no target. This covers struct fields assigned in `main` and pointers passed as parameters. Alias analyses each function from the global initializers plus the summaries of the functions it calls, so a value written in another function never reaches the call. Those sites keep their type match.

**Where Alias is wrong.** The same design makes it unsound for a global pointer that has an initializer and is reassigned in another function. The fixture `tests/fixtures/phase0/model/alias/` shows it:

```c
static fn g = a;
void set_g(void) { g = b; }
int fire(int x) { return g(x); }
```

Alias answers `{a}` for `fire`, so the true edge `fire → b` would be dropped. No measured project has this pattern, so recall did not move. But nothing in the model can detect when a site falls into it.

**Decision: not adopted. `--alias` stays off by default.** The adoption rule asked for higher precision with unchanged recall on r03, r08, r09 and s02. Recall is unchanged (1.00), but precision cannot rise there: the type match is already exact on all four (1.00). Alias narrows one site of those projects (s02), to the same set. Its only measured gain is x509-parser's 41 spurious edges, which are a real precision gain on a real target. Against that stands a demonstrated unsound case that would silently drop a true edge. The option and its per-site provenance remain available.

A variant worth measuring later: trust Alias only when the called pointer is read from a `const` global. Every x509-parser table is `static const`, so that covers all 14 narrowed sites, and it excludes the unsound case.

## 8. Open questions

- How often do real targets build in the container without manual help? The PoC's benchmark targets give a first number.
- How precise is the type-based indirect over-approximation on real code, and is Alias worth its cost? Measured in step I4 (§7, "Alias narrowing"): exact on the exact projects, 41 spurious edges of 163 on x509-parser; Alias not adopted because it is unsound for reassigned global pointers. Open: a `const`-table-only variant.
- Large units: clustering criterion and size limit for Eva slices.
- Header-only and macro-heavy libraries: is the public-header heuristic enough for static libraries? (It worked on all reproducers once headers are read after preprocessing.)
- Header `static inline` functions: one ledger unit per header definition, or only those reached from a unit's entry points? QCBOR doubles its inventory otherwise.
- Which build targets to capture: the default target skips examples (jsmn) but builds tests (QCBOR). Probably "all buildable artifacts, tests marked as such".
- Libraries compiled directly into an executable (tweetnacl): fall back to globals declared in project headers as entry points, as for static libraries.
- Macro aliases (`#define crypto_hash crypto_hash_sha512_tweet`): record them in the DAG view so that consumers resolving source-level names (`generate_harness.py`, briefs) keep working.
