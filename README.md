# Frama-C Agentic Verification & Hybrid Fuzzing Pipeline

An industrial-grade, multi-agent formal verification and dynamic bug-hunting framework for large C codebases (up to 100,000+ LoC), built on **Frama-C** (`RTE`, `Eva`, `WP`, `E-ACSL`, `Mdr/SARIF`), **SMT Solvers** (`Alt-Ergo`, `Z3`, `CVC5`), and **Clang LibFuzzer**.

All verification tools execute exclusively inside a reproducible **`framac-pipeline` Docker container**, orchestrated by modular **Agent Skills** (`/framac-verify`, `/framac-slice`, `/framac-fuzz`, `/framac-eva`, `/framac-wp`) and deterministic Python helper scripts.

---

## Key Capabilities

1. **Zero-ACSL Dynamic Triage (`RTE + E-ACSL + LibFuzzer`):**
   Automatically injects ACSL runtime-error assertions (`-rte`) and compiles them with E-ACSL into shadow-memory and arithmetic runtime checks, linked with LibFuzzer (`e-acsl-gcc`, `-fsanitize=fuzzer`). Catches intra-struct sub-object buffer overflows, use-after-free, uninitialized reads (`-rte-initialized`), signed integer overflow, division by zero, invalid shifts, and functional contract violations before a single minute is spent on formal proofs. Unsigned downcasts are opt-in (`--warn-unsigned-downcast`). Unsigned overflow and signed downcasts are left to Eva and WP, because intentional wrap-around would stop every fuzz campaign.
2. **Module-Level Abstract Interpretation (`Eva`):**
   Simulates all symbolic inputs (`0 .. MAX_INPUT_SIZE`) from per-module `eva_main()` harnesses to automatically discharge **80–90% of RTE assertions** without writing loop invariants.
3. **Dependency-Driven Subagent WP Swarm (`/framac-wp`):**
   A deterministic scheduler (`wp_scheduler.py`) dispatches a **Function Prover Subagent** (`frama-c -wp -wp-rte -wp-fct <fn>`) as soon as the function's callees are merged. Longest caller chains go first, and finished proofs merge in parallel micro-batches. There are no global waves or barriers.
4. **Dual-Oracle Anti-Hallucination Guardrail:**
   Every ACSL contract (`requires`, `assigns`, `ensures`, `loop invariant`) proposed by a subagent is compiled with **E-ACSL** and tested against the live fuzzer corpus before being passed to **WP**, mathematically preventing the LLM from passing proofs via vacuous or contradictory preconditions (`requires \false`).
5. **Adversarial Prover-vs-Breaker Dual-Play:**
   When a WP proof stalls after `K` retries on an assertion, an **Adversarial Breaker Subagent** crafts targeted fuzzer seeds that trigger the assertion at runtime. It never blocks the stalled function's callers.
6. **6 Layers of Security Properties (Beyond Memory Safety):**
   - **Layer 1:** Absence of Run-Time Errors (`AoRTE` via `-rte`)
   - **Layer 2:** Termination & Anti-DoS (`loop variant`, `decreases`)
   - **Layer 3:** Memory Isolation & Sandboxing (`assigns`, `\separated`)
   - **Layer 4:** Authentication & Protocol State-Machine Integrity (`ghost` state variables)
   - **Layer 5:** Output Grammar & Sanitization (`ensures` character-class bounds against CRLF/log injection)
   - **Layer 6:** Secret Zeroization & Information Flow / Non-Interference (`buffer_is_zeroed` + `-eva-domains taint`)
7. **Sizes Itself to Any Machine (see [`docs/resources-and-caching.md`](docs/resources-and-caching.md)):**
   - **Measured resources.** Before every job the pipeline measures what it may use: cgroups, Slurm allocations, the Docker/Podman engine and user caps. A host-side broker leases CPUs and memory to each container (optional CPU pinning on multi-NUMA hosts). Each tool sizes its own parallelism from its lease (`-wp-par`, LibFuzzer workers, `make -j`). Resources added to or removed from a node take effect on the next job.
   - **Machine-independent results.** Limits that decide outcomes (`-wp-memlimit`, `-rss_limit_mb`, seeds) stay fixed.
   - **Make for deterministic work.** Per-module fuzz and Eva runs, builds, ingestion and replays run from a generated Makefile instead of LLM subagents.
   - **Caches.** Content-addressed caches reuse E-ACSL builds, Eva results and WP proofs within a run. A trusted end-of-run sweep shares proofs across runs.
8. **Evidence Discipline (v2, see [`docs/v2-design.md`](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/docs/v2-design.md)):**
   Tool hits are fingerprinted candidates, not findings, until independently verified into `confirmed`, `needs_validation`, or `rejected` records. A deterministic coverage ledger (function x obligation class) records what is proven unconditionally, what is proven under open assumptions, and what is blocked, deferred, or out of scope. All shared artifacts are schema-validated and the target is mounted read-only. The hardened container (no network, all capabilities dropped, no-new-privileges, Docker's default seccomp and AppArmor profiles, resource limits) is the isolation boundary; inside it, target-controlled binaries run through `sandbox_exec.py`, which applies rlimits (CPU, file size, open files, processes), a cleared environment with an explicit allowlist, and a wall-clock timeout with process-group kill. There is no filesystem isolation inside the container (see the residual-risk note in `docs/v2-design.md`, Section 3).

---

## Repository Layout

```text
frama-c/
├── Dockerfile                                # Ubuntu 24.04 + Opam Frama-C + E-ACSL + Alt-Ergo/Z3/CVC5 + Clang/LibFuzzer
├── docker-compose.yml                        # Container service definition & volume mappings
├── wrappers/
│   ├── framac-docker.ps1                     # Windows PowerShell wrapper for container execution
│   └── framac-docker.sh                      # POSIX/Bash wrapper for container execution
├── scripts/
│   ├── checkpoint.py                         # Atomic JSON checkpointing in <run-dir>/state/
│   ├── workspace_overlay.py                  # Manages workspace/ shadow overlay, per-agent overlays & structural merges
│   ├── acsl_ast.py                           # C/ACSL lexical analyzer, ACSL-only verifier & function span splicer
│   ├── promote_artifact.py                   # Safe parent-side promotion from agents/<id>/scratch/
│   ├── build_callgraph_dag.py                # Builds Call-Graph DAG, topological waves, & risk-tier classifications
│   ├── generate_harness.py                   # Generates exact-size dual harnesses + harness_<mod>.json sidecars
│   ├── run_eacsl_fuzz.py                     # E-ACSL + LibFuzzer campaigns & Dynamic Guardrail (sandboxed, fingerprinted)
│   ├── run_eva_slice.py                      # Runs Frama-C Eva + RTE per module slice & exports SARIF
│   ├── run_wp_function.py                    # Runs Frama-C WP + RTE per function (-wp-fct) & buckets unproven goals
│   ├── contract_negotiator.py                # Manages cross-wave Caller-Callee contract strengthening requests
│   ├── sandbox_exec.py                       # rlimits + env allowlist + timeout for target-controlled binaries
│   ├── fingerprint.py                        # Stable <file>#<function>::<kind>::<hash> finding fingerprints
│   ├── ledger.py                             # Coverage ledger seeding, phase/hypothesis/verifier ingestion
│   ├── run_metadata.py                       # run-metadata.json (source ref, profile, toolchain, resources, run status)
│   ├── resources.py                          # Resource probe, job sizing, host and container lease brokers
│   ├── cache.py                              # Content-addressed per-run and shared caches (stats, gc, clear)
│   ├── pipeline_make.py                      # Generates and runs the Makefile for deterministic per-module phases
│   ├── wp_scheduler.py                       # Dependency-driven Phase-3 task scheduler (ready queue, merges, gates)
│   ├── container_entry.sh                    # Container entry point: runs the command, records resource usage
│   ├── validate_artifacts.py                 # Schema + semantic validators for all shared artifacts
│   ├── minischema.py, framac_common.py       # Stdlib-only JSON Schema subset & shared helpers
│   ├── generate_report.py                    # Derives REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md, report.sarif
│   └── extract_references.py                 # Host-side: converts docs/references/*.pdf into greppable .md + INDEX.md
├── schemas/                                  # findings, candidates, coverage-ledger, run-metadata, agent-result contracts
├── tests/                                    # pytest suite (python -m pytest tests)
├── templates/
│   ├── pipeline.mk                           # Make rules for build, fuzz, eva, ingest, replay, wp-queue, wp-sweep, report
│   ├── harness_dual.c.template               # Dual-use Eva + LibFuzzer C harness template
│   ├── eacsl_runtime/fuzz_init.c             # LLVMFuzzerInitialize hook that initializes the E-ACSL runtime (linked into fuzz builds)
│   ├── eacsl_canary/canary.c                 # E-ACSL toolchain canary for `run_eacsl_fuzz.py selftest`
│   ├── fc_stubs/                             # Bodyless ACSL-annotated prototypes for host/library headers
│   └── acsl/
│       ├── external_stubs.h                  # ACSL boundary stubs for crypto, network, and OS calls
│       ├── layer4_auth_state_machine.acsl    # Ghost state machine contracts for authentication gates
│       ├── layer5_output_sanitization.acsl   # Output grammar predicates against CRLF/control-char injection
│       └── layer6_zeroization_and_taint.acsl # Secret zeroization & Eva taint non-interference templates
├── skills/
│   ├── framac-verify/SKILL.md                # Umbrella end-to-end orchestrator (/framac-verify)
│   ├── framac-slice/SKILL.md                 # Phase 0: Slicing, Call-Graph DAG, stubs & harnesses (/framac-slice)
│   ├── framac-fuzz/SKILL.md                  # Phase 1: Zero-ACSL RTE + E-ACSL + LibFuzzer triage (/framac-fuzz)
│   ├── framac-eva/SKILL.md                   # Phase 2: Module-level abstract interpretation (/framac-eva)
│   └── framac-wp/                            # Phase 3: dependency-driven parallel WP swarm (/framac-wp)
│       ├── SKILL.md
│       ├── header_architect_brief.md
│       ├── prover_brief.md
│       ├── breaker_brief.md
│       └── crash_verifier_brief.md
└── docs/
    ├── architecture.md                       # Macro & Micro pipeline workflows and Mermaid diagrams
    ├── slicing-and-onboarding.md             # Strategy for slicing 90k+ LoC C codebases (SNMPv3, Syslog, XML)
    ├── security-properties.md                # Proving Security Layers 1-6 in ACSL
    ├── agentic-swarm.md                      # Levels of parallelism, Dual Oracle, & Contract Negotiation
    ├── resources-and-caching.md              # Resource measurement, broker, job sizing, caches, Make phases, scheduler
    ├── v2-design.md                          # Evidence discipline: verdicts, ledger, isolation, milestones
    ├── troubleshooting.md                    # Common Frama-C, E-ACSL, Eva, and WP troubleshooting guide
    └── references/                           # Upstream manuals (acsl/ language specs, one folder per plug-in): PDFs, greppable .md twins, INDEX.md, e-acsl-quickref.md
```

---

## Quickstart

### 1. Build the Docker Image

From PowerShell on Windows:

```powershell
$env:PYTHONIOENCODING="utf-8"
docker build "-t" "framac-pipeline:latest" "C:\Users\Florian\OneDrive\Documents\Dev\frama-c"
```

### 2. Run a Command Inside the Hardened Container

Use [framac-docker.ps1](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/wrappers/framac-docker.ps1). The target is mounted read-only at `/target`; the run directory (default `~/framac-pipeline/<repo>/run-<N>/`, created by `-NewRun`) is the read-write working directory `/framac-run`. The container has no network, drops all capabilities, keeps Docker's default seccomp and AppArmor profiles, and runs with CPU/memory/PID limits. `sandbox_exec.py probe` prints `{"sandbox": "rlimits"}` inside the container. The legacy `-NoInnerSandbox` / `-AllowDegradedSandbox` switches (`--no-inner-sandbox` / `--allow-degraded-sandbox` in the POSIX wrapper) were removed together with bubblewrap and now fail with exit code 2.

```powershell
& "C:\Users\Florian\OneDrive\Documents\Dev\frama-c\wrappers\framac-docker.ps1" `
  -TargetDir "C:\path\to\c-project" `
  -NewRun `
  -BuildIfMissing `
  "frama-c -version && python3 /opt/framac-pipeline/scripts/sandbox_exec.py probe"
```

Pass the printed run directory as `-RunDir` for every later command of the same run.

The wrapper sizes every container itself; there are no CPU or memory flags to tune:
- With a host Python 3.10+, it leases CPUs and memory from the measured pool and starts the container (Docker or Podman, `FRAMAC_CONTAINER_ENGINE`) with matching limits.
- Caps and knobs are environment variables (`FRAMAC_POOL_CPUS`, `FRAMAC_POOL_MEMORY`, `FRAMAC_MAX_AGENTS`, `FRAMAC_PIN`, `FRAMAC_CACHE`, …).
- `-NoBroker` (`--no-broker`) restores the previous static sizing.
- See [`docs/resources-and-caching.md`](docs/resources-and-caching.md).

### 3. Run the Agent Skills

| Skill | Stage | Purpose |
| :--- | :---: | :--- |
| [`/framac-verify`](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/skills/framac-verify/SKILL.md) | **All (0–4)** | End-to-end pipeline: slices the codebase, fuzzes with E-ACSL, prunes with Eva, proves with parallel WP subagents, records everything in a validated coverage ledger, and emits `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, and `report.sarif`. |
| [`/framac-slice`](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/skills/framac-slice/SKILL.md) | **Phase 0** | Creates the `workspace/` shadow overlay, builds Call-Graph DAG & topological waves, classifies modules by Risk Tier, generates dual harnesses, and seeds the coverage ledger. |
| [`/framac-fuzz`](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/skills/framac-fuzz/SKILL.md) | **Phase 1** | Runs zero-ACSL `RTE + E-ACSL + Clang LibFuzzer` campaigns per module slice. |
| [`/framac-eva`](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/skills/framac-eva/SKILL.md) | **Phase 2** | Runs `frama-c -eva -then -rte` per module slice, discharging 80–90% of RTE checks and emitting per-slice SARIF. |
| [`/framac-wp`](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/skills/framac-wp/SKILL.md) | **Phase 3** | Runs the dependency-driven prover swarm (`Alt-Ergo`, `Z3`, `CVC5`) from `wp_scheduler.py`, with the E-ACSL Dynamic Guardrail and Adversarial Breaker subagents. |

---

## Documentation Index

- [Architecture & Dataflow (`docs/architecture.md`)](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/docs/architecture.md)
- [Slicing & Onboarding 90k+ LoC Codebases (`docs/slicing-and-onboarding.md`)](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/docs/slicing-and-onboarding.md)
- [Proving Security Properties Beyond Memory Safety (`docs/security-properties.md`)](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/docs/security-properties.md)
- [Multi-Agent Swarm & Dual-Oracle Guardrail (`docs/agentic-swarm.md`)](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/docs/agentic-swarm.md)
- [Resources, Scheduling & Caching (`docs/resources-and-caching.md`)](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/docs/resources-and-caching.md)
- [Troubleshooting Guide (`docs/troubleshooting.md`)](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/docs/troubleshooting.md)
- [Frama-C Reference Manuals (`docs/references/README.md`)](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/docs/references/README.md): how to grep the upstream manuals instead of reading them whole
