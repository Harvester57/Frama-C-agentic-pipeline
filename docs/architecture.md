# Pipeline Architecture & Dataflow

This document details the macro-level and micro-level architecture of the Frama-C Agentic Verification Pipeline, how the four plugins (**RTE**, **E-ACSL**, **Eva**, and **WP**) collaborate on a shared AST, and how artifacts flow across phases.

---

## 1. Collaborative Role of Each Frama-C Plugin

| Plugin | Role in Pipeline | Input | Output |
| :--- | :--- | :--- | :--- |
| **RTE (`-rte`)** | **Syntactic Proof-Obligation Generator.** Scans the C AST and inserts explicit ACSL `/*@ assert rte: ...; */` annotations at every potential runtime error (signed/unsigned overflow, `\valid` / `\valid_read` pointer dereference, division by zero, bitshift bounds, float-to-int cast, function pointer call). | Raw C AST | Annotated C AST with numbered RTE assertions |
| **E-ACSL (`-e-acsl`)** | **Executable Contract Compiler & Dynamic Oracle.** Translates ACSL assertions, preconditions, postconditions, loop invariants, and ghost state into runtime C instrumentation backed by shadow memory. Paired with Clang `-fsanitize=fuzzer`. | C AST + RTE / ACSL annotations | Instrumented C binary (`fuzz_runner`) that aborts on any UB or contract violation |
| **Eva (`-eva`)** | **Whole-Slice Abstract Interpreter.** Propagates value intervals, octagons, and symbolic pointer locations from a module's `eva_main()` harness without requiring user-written loop invariants. Automatically proves 80–90% of RTE assertions (`Valid`). | Module C slice + `eva_main()` | Per-assertion status (`Valid`, `Unknown`, `Invalid`) + SARIF |
| **WP (`-wp -wp-rte`)** | **Modular Deductive Verifier.** Translates one C function at a time (`-wp-fct`) and its ACSL contract (`requires`, `assigns`, `ensures`, `loop invariant`, `loop variant`) into first-order logic goals discharged in parallel by `Alt-Ergo`, `Z3`, and `CVC5`. | Single C function + Callee `.h` contracts | Mathematical proof (`100% Valid`) or failed goal sequent |

---

## 2. Macro-Level Pipeline: Slicing & Verifying a Large C Codebase

```mermaid
flowchart TD
    subgraph P0["Phase 0: Build Capture, Frama-C Model & Module Slicing (/framac-slice)"]
        A["Target C Codebase (e.g. 90,000 LoC)"] --> B["Initialize run workspace/ Shadow Copy<br/>(workspace_overlay.py init)"]
        B --> BC{"Build Capture in the build image<br/>(build_capture.py: bear, link units, API, snapshot)"}
        BC -- "Build fails" --> ASK["Stop: needs_build_recipe<br/>Ask the user, then resume"]
        BC -- "OK" --> MO["Frama-C Model per Link Unit<br/>(phase0_model.py; GCC fallback per unit)<br/>+ Trust (trust.py, THREAT_MODEL.md)"]
        MO --> SD["Seeds from the Tests<br/>(seed_harvest.py record, build image)"]
        MO --> C["DAG View: Link-Unit Modules, Waves 0..K,<br/>Tiers from Trust, Unit Split<br/>(build_callgraph_dag.py, tiers.py, unit_split.py)"]
        MO --> SP["MetAcsl Layer 3-6 Properties<br/>(security_props.py)"]
        C --> D["Stub External Boundaries<br/>(__fc_libc + external_stubs.h)"]
        D --> E{"Route Modules by<br/>Risk Tier"}
    end

    E -- "Tier 1A: Untrusted Binary Parser<br/>(e.g. SNMPv3 ASN.1/BER)" --> M1["Module Slice: Binary Parser"]
    E -- "Tier 1B: Structured Emitter<br/>(e.g. Syslog RFC 5424)" --> M2["Module Slice: Packet Emitter"]
    E -- "Tier 2: Recursive Heap / Trees<br/>(e.g. XML Config Parser)" --> M3["Module Slice: Heap/Tree Parser"]
    E -- "Tier 3: Internal Glue & State" --> M4["Spot Eva & On-Demand WP"]

    subgraph P1["Phase 1: Zero-ACSL Dynamic Triage (/framac-fuzz)"]
        M1 & M2 & M3 --> F["Generate Dual Harness (generate_harness.py)<br/>LLVMFuzzerTestOneInput + eva_main"]
        F --> FR{"Reachability Gate (harness_reach.py)<br/>every DAG entry point reached or exempted?"}
        FR -- "No: add dispatch cases" --> F
        FR -- "Yes" --> G["RTE + E-ACSL two-stage build, -fsanitize=fuzzer<br/>seeded from the tests (run_eacsl_fuzz.py campaign)"]
        G --> DR{"Dynamic Reach Gate (harness_reach.py dynamic)<br/>every entry point executed by the corpus?"}
        DR -- "No: repair or exempt" --> F
        G --> H{"Runtime Crash /<br/>RTE Triggered?"}
        H -- "Yes (True Bug)" --> I["Emit Concrete Crash Reproducer<br/>& Exclude Broken Function from Proof Queue"]
    end

    H -- "Clean (Tier 2 XML/Tree)" --> T2_DONE["Keep in CI Fuzzing +<br/>Verify Only Post-Parse Config Validator"]
    H -- "Clean (Tier 1A & Tier 1B)" --> J

    subgraph P2["Phase 2: Module-Level Abstract Interpretation (/framac-eva)"]
        J["Run frama-c -eva -main eva_main ... -then -rte<br/>(run_eva_slice.py)"] --> K{"Inspect RTE Alarm Table"}
        K -- "Green (Valid: ~85%)" --> L["Discharged Automatically"]
        K -- "Red (Invalid)" --> I
        K -- "Orange (Unknown: ~15%)" --> M["Queue Surviving Unknown Functions<br/>(wp_scheduler.py init)"]
    end

    subgraph P3["Phase 3: Continuous Reactive Subagent WP Loop (/framac-wp)"]
        M --> N["Stage 3A: Speculative Header Architect Swarm<br/>Drafts .h Contracts Spliced via 3-Way AST Merge"]
        N --> O["Stage 3B: Reactive Sliding-Window Function Provers<br/>(speculative contract-first dispatch; atomic step)"]
        O --> P{"All Goals Proven<br/>within K Retries?"}
        P -- "Yes" --> Q["Lock Verified Contract in .h<br/>& Process Strengthening Requests"]
        P -- "Stalled after K Retries" --> R["Stage 3C: Spawn Adversarial Breaker Subagent<br/>(Targeted E-ACSL Seed Synthesis)"]
        R -- "Crash Triggered" --> I
        R -- "Unreachable / Non-Linear" --> S["Retain Surgical E-ACSL Runtime Check<br/>for Residual Assertion"]
    end

    Q & S & I & T2_DONE --> Z["Phase 4: Validate ledger + findings, derive REPORT.md,<br/>FINDINGS-DETAIL.md, NEEDS-VALIDATION.md, verified_acsl.patch, & report.sarif"]
```

### Phase 0 in short

Design and measurements: [`./phase0-redesign.md`](./phase0-redesign.md) and [`./phase0-implementation-plan.md`](./phase0-implementation-plan.md).

- **Images.** The build image (`framac-build`) runs the target's own build and tests. The analysis image (`framac-analysis`) runs everything else and holds no target packages. The CodeQL image is optional and off by default. There are no other images: the monolithic `framac-pipeline` image was removed in step I10.
- **Build capture** (`build_capture.py`, build image, scratch volume). The target's build runs under `bear` from a recipe the user gave or confirmed. It gives the link units, per-file flags, test units, API entry points, and a snapshot of the target's headers and libraries in `workspace/snapshot/`. A build that fails stops Phase 0 with `needs_build_recipe` until the user fixes the recipe.
- **Frama-C model** (`phase0_model.py`, analysis image). One Frama-C parse per distinct set of sources and flags gives the functions (`file#name`), direct and indirect edges, macro aliases, thread entries and each function's trust. A unit Frama-C cannot parse falls back to GCC's `-fcallgraph-info`, and is flagged. Alias narrowing of indirect edges exists but is off by default.
- **Trust** (`trust.py`). Library API and functions reached from input readers are untrusted, unless the structured threat model says otherwise. Optional CodeQL facts can only add untrusted marks.
- **DAG view** (`build_callgraph_dag.py`). Modules are the build's link units. Harnesses may be sub-modules of a unit, and `module_map.py` maps every report back to its unit. Tiers come from trust (`tiers.py`), and units too large for one Eva run are split into clusters (`unit_split.py`).
- **Seeds** (`seed_harvest.py`). The API calls the target's tests make are recorded in the build image and written as seeds in each harness's case format.
- **Security properties** (`security_props.py`). The threat model's auth gates, output sinks and secrets become MetAcsl properties (Layers 4 to 6), and pointer writers get Layer 3 frame units.
- **Gates.** The reach gate and the E-ACSL build check write `workspace/reports/phase0_gates.json`, and Make refuses to fuzz, run Eva or queue WP on a module that failed one. Coverage after fuzzing reopens the reach gate for entry points no input executed.

---

## 3. Micro-Level Zoom: Inside Each Function Pod (`/framac-wp`)

```mermaid
flowchart TD
    Start(["Target Function f() (callees merged)<br/>with Unproven RTE or Security Goals"]) --> StepA

    subgraph MicroLoop["Ordered Dual-Oracle ACSL Synthesis Loop"]
        StepA["Step A: Synthesize/Refine Frame Conditions<br/>(assigns & loop assigns)"] --> StepB
        StepB["Step B: Synthesize/Refine Loop Contracts<br/>(loop invariant & loop variant)"] --> StepC
        StepC["Step C: Synthesize/Refine Pre/Postconditions<br/>(requires, ensures, & Layer 4-6 Security Specs)"]

        StepC --> KernelCheck["1. Frama-C Kernel Syntax & Type Check<br/>(frama-c -kernel-warn-key annot-error=abort)"]
        KernelCheck -- "Syntax / Type Error" --> FeedSyntax["Feed Kernel Error Line to Prover Subagent"]
        FeedSyntax --> StepA

        KernelCheck -- "Syntax Valid" --> DynOracle["2. Dynamic Anti-Hallucination Oracle<br/>(run_eacsl_fuzz.py guardrail on Fuzzer Corpus)"]
        DynOracle -- "Assertion Trips on Real Input!" --> FeedDyn["Reject Over-Constrained Contract!<br/>Feed Failing Runtime Trace to Prover Subagent"]
        FeedDyn --> StepA

        DynOracle -- "Passed Dynamic Oracle" --> StatOracle["3. Static Deductive Oracle (run_wp_function.py)<br/>frama-c -wp -wp-rte -wp-fct f -wp-prover alt-ergo,z3,cvc5"]

        StatOracle --> Inspect{"Inspect Bucketed<br/>WP Outcome"}
        Inspect -- "Unproven Goal in Callee g()" --> Negotiate["Register Strengthening Request<br/>(contract_negotiator.py request)"]
        Inspect -- "Unproven Local Goal (Retries < K)" --> FeedWP["Feed Bucketed WP Sequent Diagnostics<br/>back to Step A / B / C"]
        FeedWP --> StepA
    end

    Inspect -- "Stalled (Retries == K)" --> Breaker["Spawn Adversarial Breaker Subagent<br/>(Craft Targeted E-ACSL Input)"]
    Inspect -- "100% Valid!" --> Done(["Save Verified Function Shard<br/>& Unblock Its Callers"])
```

---

## 4. On-Disk Run Directory & Artifact Layout

Each run lives outside the target in `~/framac-pipeline/<repo>/run-<N>/` (mounted at `/framac-run`; the target is mounted read-only at `/target`). See [`./v2-design.md`](./v2-design.md) for ownership rules.

```text
run-<N>/
├── run-metadata.json                         # Run id, source ref, profile, scope, sandbox, toolchain, run_status
├── coverage-ledger.json                      # Coverage claim: one unit per function x obligation class
├── candidates.json                           # Fingerprinted tool hits awaiting an independent verdict
├── findings.json                             # Verdict records: confirmed / needs_validation / rejected
├── REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md, report.sarif   # Derived reports
├── state/
│   ├── progress.json                         # Phase resume pointer
│   ├── phase0.json, phase2.json, phase3.json # Phase completion snapshots (Phase 0 seed, `run wp-queue`, end of Phase 3)
│   ├── phase3_shards/<fn>.json               # Per-function WP completion shards
│   ├── wp_schedule.json                      # Phase-3 task graph (wp_scheduler.py)
│   ├── merge-journal.json                    # Present only while a merge is in flight
│   ├── cache/                                # Per-run caches: E-ACSL builds, WP proofs, Eva results
│   ├── resource-history/<class>/             # Peak memory / OOM records that size future leases
│   └── ingested.json                         # Digests of reports already ingested
├── workspace/
│   ├── baseline/                             # Clean read-only snapshot of original C/H files
│   ├── work/                                 # Active shadow tree (ACSL annotations only)
│   ├── snapshot/                             # The target's headers and libraries from the build (root/, manifest.json)
│   ├── harnesses/                            # Generated harness_<mod>.c, harness_<mod>.json, and E-ACSL binaries
│   ├── build/                                # Generated Makefile, modules.mk, params.json (pipeline_make.py)
│   ├── seed_records/                         # API calls recorded from the target's tests (calls.jsonl)
│   ├── seeds/<mod>/                          # Seeds in the harness's case format (read-only extra corpus)
│   ├── corpus/<mod>/                         # LibFuzzer seed and coverage corpus per module (parent-owned)
│   ├── crashes/<mod>/                        # crash-* inputs triggering E-ACSL assertions
│   ├── contracts/                            # Exported verified .h and .acsl contract headers
│   └── reports/
│       ├── build_capture.json                # Link units, flags, API, snapshot digest, or needs_build_recipe diagnostics
│       ├── phase0_model.json                 # Frama-C model: functions, edges, units, trust, parse status per unit
│       ├── codeql_trust.json                 # Optional CodeQL trust facts
│       ├── seed_harvest.json                 # What the seed recording kept
│       ├── security_props.json               # MetAcsl Layer 3-6 properties and their instances
│       ├── callgraph_dag.json                # DAG view: link-unit modules, waves, tiers, unit split
│       ├── phase0_gates.json                 # Reach gate and E-ACSL build check, per module
│       ├── harness_reach.json                # Static reach gate report (harness_reach_dynamic.json after coverage)
│       ├── strengthen_requests.json          # Caller-Callee contract negotiation ledger
│       ├── wp_queue.json                     # Ordered Phase-3 queue (written by wp_scheduler.py init)
│       ├── verified_acsl.patch               # Unified diff of all verified ACSL annotations
│       ├── fuzz/<mod>.json                   # Phase 1 campaign outputs (fingerprinted failures)
│       ├── coverage/<mod>.json               # Functions and regions each corpus executes
│       ├── eva/<mod>.json                    # Phase 2 Eva + RTE status buckets & per-slice .sarif
│       ├── replay/<fp>.json                  # Deterministic replays of candidate reproducers
│       ├── wp/<fn>.json                      # Phase 3 per-function WP results by obligation class
│       └── wp-sweep/                         # End-of-run re-proof of merged functions
└── agents/<agent-id>/scratch/                # The only place a subagent may write (parent_wp/ holds the parent re-check)
```
