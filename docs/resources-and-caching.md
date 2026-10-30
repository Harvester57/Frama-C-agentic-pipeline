# Resources, Scheduling and Caching

The pipeline does not assume a machine size. Before every decision it measures what it may use, sizes each invocation from that measurement, and skips work it has already done. This document explains how. The same run works on a laptop with Docker Desktop, on a cluster node whose CPUs and memory are resized between or during runs, and inside a Slurm allocation.

Two rules hold throughout:

1. **Hardware changes throughput, never results.** More CPUs mean more provers or fuzz workers at once. The limits that decide an outcome stay fixed, so proofs and findings are comparable across machines (`docs/v2-design.md`, Section 9):
   - WP `-wp-memlimit` is always 1000 MB per prover.
   - LibFuzzer `-rss_limit_mb` is always 2048.
   - The per-input timeout is fixed: 30 s for guardrail runs, 10 s for campaigns and replays. Guardrails and replays also use a deterministic seed.
2. **Measure, don't remember.** Resources are re-probed on every lease and every scheduling round, with a 5-second memo. CPUs or memory added to or removed from the node take effect on the next job. Running jobs keep the size they started with: their `-wp-par`, `-workers` and `make -j` are fixed at start.

---

## 1. What is measured

The pool is the minimum over every source that applies, minus a reserve for the orchestrator and the OS:

| Source | Where | What it limits |
|---|---|---|
| cgroup v2 `cpu.max`, `memory.max` | the process's cgroup and every ancestor (minimum wins) | CPU quota, memory limit (containers, Kubernetes pods, systemd slices, Slurm jobs) |
| cgroup v1 `cpu.cfs_quota_us`, `memory.limit_in_bytes` | resolved through the mountinfo root | same, on older hosts |
| `cpuset.cpus.effective`, process affinity | `/sys/fs/cgroup`, `sched_getaffinity` | which CPU ids may be used |
| `/proc/meminfo` `MemAvailable` | host or container view | free memory |
| Slurm `SLURM_CPUS_ON_NODE`, `SLURM_CPUS_PER_TASK`, `SLURM_JOB_CPUS_PER_NODE`, `SLURM_MEM_PER_NODE`, `SLURM_MEM_PER_CPU` | environment | the job allocation |
| Container engine (`docker info` / `podman info`) | cached 30 s | the engine's own CPUs and memory (the Docker Desktop VM, a Podman machine); which limits it can enforce |
| `FRAMAC_POOL_CPUS`, `FRAMAC_POOL_MEMORY` | environment | an explicit cap you set for the whole pipeline |
| PSI (`/proc/pressure/*`, `cpu.pressure`) | optional | sustained contention from other tenants shrinks elastic grants |

The reserve is `FRAMAC_RESERVE_CPUS` (default max(0.5, 5 %)) and `FRAMAC_RESERVE_MEMORY` (default max(1 GiB, 10 %)). It is taken once, from the machine. A container whose size comes from a cgroup limit or a lease already holds a reserved grant, so no second reserve is taken inside it.

The probe also records the CPU topology (SMT siblings, L3 domains, NUMA nodes) and the filesystem type of the run directory. On network or virtualized filesystems (NFS, CIFS, 9p, FUSE, virtiofs, Lustre, GPFS) it warns, because the many small files that WP, LibFuzzer and E-ACSL write are slow there; keep run directories on local disk.

```text
python3 /opt/framac-pipeline/scripts/resources.py budget      # this job: cpus, mem_mb, source
python3 /opt/framac-pipeline/scripts/resources.py recommend   # pool, make_jobs, max_agents, per-class grants
```

`run_metadata.py init` stores a summary under `resources` in `run-metadata.json`.

---

## 2. Job classes

Every container invocation belongs to a class. The class sets its CPU range, its memory model, and whether it runs target-controlled code, which decides the shared-cache mount (Section 5).

| Class | Runs target code | CPUs | Memory (before history) | Examples |
|---|---|---|---|---|
| `light` | no | 1, never queued | 1 GiB | ledger, validators, checkpoints, `wp_scheduler.py next`, any command not listed below |
| `wp` | no | 1–8 | 768 MiB + 1000 MiB per prover | `run_wp_function.py` |
| `eva` | no | 1 | 2 GiB | `run_eva_slice.py`, a direct `frama-c` call (parse or annotation check) |
| `build` | no | 1–4 | 2 GiB | `run_eacsl_fuzz.py build` |
| `guardrail` | yes | 1–2 | 2 GiB | `run_eacsl_fuzz.py guardrail` |
| `fuzz` | yes | 1–16 | 512 MiB + 2.5 GiB per worker | `run_eacsl_fuzz.py campaign` |
| `replay`, `selftest` | yes | 1 | 1 GiB | crash replays, the E-ACSL canary, other `sandbox_exec.py run` commands |
| `verify` | yes | elastic | elastic | `merge-agent`, `merge-batch`, `wp_scheduler.py complete/merge-pending` |
| `phase-static` / `phase-dynamic` | no / yes | elastic | elastic | `pipeline_make.py run …`; `phase-dynamic` also covers the target's own build under `sandbox_exec.py run -- bear -- make` (or `cmake`, `ninja`, `meson`, `configure`) |

The wrapper infers the class from the command; `--class` (`-Class`) overrides it. Inference only sizes jobs. It is never a security decision (Section 5). A command the inference does not recognise runs as `light`, with 1 CPU and 1 GiB; give a heavy ad-hoc command an explicit `--class`.

Memory estimates learn from history. Each container records its peak memory, OOM kills and CPU time in `state/resource-history/` (and mirrors them into `/framac-cache/resource-history/` when the shared store is mounted read-write). The next lease for the same class and module gets 1.25 × the largest of the last five peaks across per-run and shared history, counting an OOM-killed run twice. History only ever raises a lease above the class model, never lowers it, so `-wp-memlimit` and `-rss_limit_mb` always fit.

### How tools size themselves

| Tool | Sized from the job budget | Fixed |
|---|---|---|
| WP | `--wp-par auto` = min(CPUs, (memory − 768 MiB) / 1000 MiB). A job limited to less than 1768 MiB (one prover plus Frama-C) is not run: it reports `analysis_error`, `reason: insufficient_memory`, because starved provers fail goals that a properly sized job proves | `-wp-memlimit 1000`, `-wp-timeout` from the profile |
| LibFuzzer campaign | `--workers auto` = min(CPUs, (memory − 512 MiB) / 2.5 GiB); wall time = max(30 s, CPU-second budget / workers). A job limited to less than 2560 MiB (512 MiB overhead + 2048 MiB `-rss_limit_mb`) is not run and reports `status: insufficient_memory` | `-rss_limit_mb 2048`, per-input `-timeout` |
| Guardrail / replay | single process | `-rss_limit_mb 2048`, per-input `-timeout`, deterministic `-seed` |
| Eva | 1 CPU; parallelism comes from running modules side by side | `--timeout` from the profile |
| Parent re-check (`merge-batch`) | per-function WP runs in a pool: workers = min(n, CPUs, memory / 1768 MiB), each `-wp-par = min(CPUs / workers, (memory / workers − 768 MiB) / 1000 MiB)` | as WP |
| Make | `-j` = container CPUs; each recipe is admitted by CPU and memory, running against a stage-private copy of `Makefile` and `modules.mk` rendered directly from memory | — |

The fuzz budget is CPU-seconds per module: quick 60, standard 120, deep 900. A bigger node finishes sooner with the same or more effort. `--max-time` stays as a wall-clock override.

---

## 3. The broker

### Host broker (`resources.py exec`)

The wrappers (`framac-docker.sh` / `framac-docker.ps1`) call `resources.py exec` with the host's Python (3.10 or newer). For each container it:

1. **Leases resources** from the host pool:
   - Requests are served first in, first out. A later request can jump ahead only when that doesn't delay the head of the queue.
   - Grants are elastic: `cpus = clamp(free // (1 + waiting), class min, min(class max, pool / 2))`.
   - Memory comes from the class model or history. CPUs are lowered when memory doesn't fit.
   - `light` jobs are never queued.
   - Nothing is preempted. When the pool shrinks, new grants wait until enough is released.
2. **Starts the container** with `--name framac-<lease> --label framac.lease=<id> --init`, `--cpus` (or `--cpuset-cpus`), `--memory` = `--memory-swap`, and `--pids-limit`. Each limit flag is added only when the engine can enforce it. A caller that puts one of these flags on the engine command line itself is refused (exit 2): fixed sizes go through `exec --cpus/--memory/--pids-limit`, which still registers them with the broker.
3. **Passes the sizing in** as environment:
   - `FRAMAC_JOB_CPUS`, `FRAMAC_JOB_MEM_MB`, `FRAMAC_JOB_CLASS` (and `FRAMAC_JOB_KEY`);
   - `FRAMAC_POOL_CPUS` / `FRAMAC_POOL_MEM_MB`, so in-container code sees the whole node;
   - `FRAMAC_IMAGE_ID`, the toolchain identity in every cache key;
   - `FRAMAC_CACHE_MODE` (`rw`, `ro` or `off`) and, when the shared store is mounted, `FRAMAC_SHARED_CACHE_DIR=/framac-cache`.

   The command string reaches the container through `FRAMAC_CONTAINER_CMD` and the entry shim `container_entry.sh`, which runs it with `bash -lc` and then records the container's usage.
4. **Releases the lease** when the container exits.
   - Ctrl-C and SIGTERM are forwarded as `docker kill`.
   - If the holder process dies, its lease is kept while the labelled container is still running.

While a request waits, the broker prints its queue position. Long phases are meant to run in the background, so a 10-minute foreground tool limit is never the bottleneck.

```text
python3 scripts/resources.py status     # leases held and waiting requests
python3 scripts/resources.py gc         # reclaim leases of dead holders whose containers are gone
```

**Pinning.**
- Whenever this process may only use part of the machine (a Slurm allocation, a cgroup cpuset), containers get `--cpuset-cpus=<allowed set>`, because containers started by `dockerd` would otherwise escape the allocation.
- In `auto` mode on native Linux with more than one NUMA node or L3 domain, each lease also gets an exclusive set of whole cores (SMT siblings together), inside one domain when possible. Light jobs share the allowed set.
- `FRAMAC_PIN=on|off` forces it. Memory is never pinned: the kernel already allocates locally.
- On Docker Desktop (outside WSL2) and Podman machines, pinning is skipped because the hypervisor moves virtual CPUs freely; inside WSL2 distributions sharing the Docker Desktop Linux VM, affinity confinement is preserved.

**Podman and unenforceable limits.**
- Rootless Podman can only enforce the limits whose cgroup controllers are delegated; by default that is often just memory and pids.
- The broker adds only enforceable flags.
- With any engine, Docker included, it refuses classes that run target code when the engine reports that memory or pids limits can't be enforced, unless `FRAMAC_ALLOW_UNENFORCED_LIMITS=1`. Podman runs record `sandbox.outer: podman-hardened` in `run-metadata.json`.

### Container broker (`resources.py run`)

Inside one container (a Make phase, a `merge-batch`), recipes and sub-jobs go through `resources.py run --class C --key K [--output REPORT] -- cmd`. The pool is that container's own budget, re-read from its cgroup on every acquire. With `--output`, the recipe succeeds whenever the report exists, so Make keeps an `analysis_error` report instead of deleting it. A report left over from an earlier run, untouched by the command, does not count. A `run` nested inside another leased `run` passes through instead of waiting for itself.

An OOM-killed job of an idempotent class (`wp`, `eva`, `build`, `replay`) is retried once with twice the memory when the pool allows. Non-idempotent jobs (fuzz campaigns, merges) are never retried automatically:
- A retried campaign would treat the first attempt's crash artifacts as pre-existing.
- A merge has its own journal (Section 8).

An OOM in a tool always shows up in its report (`analysis_error`, `reason: oom_killed`), and the recorded history makes the next lease larger.

### Without the broker

`--no-broker` (`-NoBroker`, or `FRAMAC_BROKER=off`) keeps the previous behavior exactly: one container with `--cpus`, `--memory` and `--pids-limit`, divided by `--agents` (`-Agents`). `FRAMAC_CPUS`, `FRAMAC_MEMORY` and `FRAMAC_PIDS_LIMIT` keep their per-container meaning. The wrapper falls back to this path, with a warning, when no Python 3.10 is found on the host (`FRAMAC_PYTHON` names a specific interpreter). On the broker path `--agents` / `-Agents` is deprecated and ignored with a warning: the broker divides the node itself.

---

## 4. Knobs

| Variable | Meaning | Default |
|---|---|---|
| `FRAMAC_POOL_CPUS`, `FRAMAC_POOL_MEMORY` | Cap for the whole pipeline pool | measured |
| `FRAMAC_RESERVE_CPUS`, `FRAMAC_RESERVE_MEMORY` | Headroom kept free | max(0.5, 5 %), max(1 GiB, 10 %) |
| `FRAMAC_MAX_AGENTS` | Cap on recommended concurrent LLM subagents | 16 |
| `FRAMAC_CONTAINER_ENGINE` | `docker`, `podman` or `auto` | `auto` |
| `FRAMAC_PIN` | `auto`, `on`, `off` | `auto` |
| `FRAMAC_BROKER` | `off` disables the broker | on |
| `FRAMAC_BROKER_DIR` | Lease state directory (local disk only) | `/tmp/framac-pipeline-$UID/broker`, `%LOCALAPPDATA%\framac-pipeline\broker` |
| `FRAMAC_CACHE` | `off` disables every cache, including per-run | on inside a run |
| `FRAMAC_CACHE_DIR` | Shared cross-run store (one partition per repository under `repos/`), `off` to disable | `~/.cache/framac-pipeline` |
| `FRAMAC_CACHE_RW` | `off` mounts the shared store read-only for every command, trusted steps included | on |
| `FRAMAC_CACHE_MAX` | Size cap for a cache store | min(20 GiB, 25 % of (free disk + the store's size)) |
| `FRAMAC_CACHE_MODE`, `FRAMAC_SHARED_CACHE_DIR` | Set by the broker inside the container: how the shared store is mounted, and where | — |
| `FRAMAC_PYTHON` | Host Python the wrappers use for the broker | first `python3` ≥ 3.10 (`py -3` on Windows) |
| `FRAMAC_RESOURCES_VERBOSE` | `1` prints every lease, not only those that waited | off |
| `FRAMAC_SCHEDULER` | `waves` restores the wave-by-wave procedure | ready queue |
| `FRAMAC_SELINUX_TARGET` | `relabel` or `disable` for the read-only target mount on SELinux hosts | required there |
| `FRAMAC_ALLOW_UNENFORCED_LIMITS` | Allow target-executing classes without memory/pids limits | off |
| `FRAMAC_LOCK_TIMEOUT`, `FRAMAC_LOCK_STALE` | Run-lock wait and heartbeat staleness (seconds) | 1800, 120 |
| `FRAMAC_WP_WALL_TIMEOUT` | Wall-clock limit for one WP run (seconds) | 3600 |
| `FRAMAC_CPUS`, `FRAMAC_MEMORY`, `FRAMAC_PIDS_LIMIT`, `FRAMAC_CONCURRENT_AGENTS` | Legacy per-container sizing, used only on the no-broker path | — |

Set every knob on the host, where you run the wrapper. The container's environment is an allowlist, so the wrappers forward exactly those knobs that scripts read inside the container: `FRAMAC_CACHE`, `FRAMAC_CACHE_MAX`, `FRAMAC_MAX_AGENTS`, `FRAMAC_SCHEDULER`, `FRAMAC_LOCK_TIMEOUT`, `FRAMAC_LOCK_STALE`, `FRAMAC_WP_WALL_TIMEOUT` and `FRAMAC_RESOURCES_VERBOSE`. The others are read by the wrappers or the host broker. The pool reaches the container only as the broker's measurement (`FRAMAC_POOL_CPUS` / `FRAMAC_POOL_MEM_MB`).

---

## 5. Caches

### Per-run caches (`state/cache/` in the run directory)

| What | Key | Hit restores |
|---|---|---|
| E-ACSL and sanitizer builds of `workspace/work` (Make builds, parent re-checks, verifiers, breakers) | L1: toolchain identity + effective flags + output path + cwd + dependency manifest; L2 (E-ACSL builds): line-shift-normalized dependency manifest | the binary, `instrumented.c`, the fallback object, `compile.log` |
| Guardrail verdicts (run-local `guardrail` store) | binary sha256 + corpus manifest + `--extra-runs` + `--timeout` + `-seed` + module | `passed_dynamic_oracle`, `rejected_overconstrained`, or `code_fault` verdict |
| WP prover results | Frama-C's own goal digest (`-wp-cache update -wp-cache-dir state/cache/wp`) | unchanged goals across a prover's iterations and in the parent re-check |
| Eva reports with status `ok` | toolchain identity + Eva flags + dependency manifest | report JSON, `alarms.csv`, `red_alarms.csv`, `eva.log`, `slice.sarif` |

**Toolchain identity** is the image ID, plus a digest of `scripts/` and `templates/`, which are bind-mounted and change without an image rebuild.

The **dependency manifest** is the union of the include sets that `gcc -M` (with Frama-C's defines) and `clang -M` report for the effective flags, each file hashed. A header change anywhere in the closure invalidates the entry, including headers found next to the including file, through `../`, `-imacros` or computed includes. Output path and cwd are part of the key because crash attribution reads paths embedded in the binary.

**Not cached:**
- Fuzz campaigns. They are meant to explore.
- An agent's own guardrail builds (`agents/*/scratch`). These are scoped to the agent's function instead (`--functions`), which makes each prover iteration about 11× cheaper on a 200-function module.
- Failures. A failed build or a non-`ok` Eva run is redone every time.
- A result whose inputs changed while it was built, for example when a merge landed in `workspace/work` mid-build. The dependency manifest is hashed again before publishing; on a mismatch the result is used but not stored, and its `cache` field says `not_published` with the changed files.

The parent's guardrail binary for a module is built under `state/parent_guard/<module>-<hash>/`, a path fixed by the module's source list and flags. The output path is part of the build key, so a `merge-batch` re-check of an unchanged module restores the binary from the build cache.

A store is collected least-recently-used first once it exceeds min(`FRAMAC_CACHE_MAX`, 25 % of the disk that would be free without it), checked at most every 10 minutes after a publish. `FRAMAC_CACHE=off` disables every cache, for A/B comparisons.

```text
python3 /opt/framac-pipeline/scripts/cache.py stats
python3 /opt/framac-pipeline/scripts/cache.py gc
python3 /opt/framac-pipeline/scripts/cache.py clear --ns eacsl-build
```

### Shared cross-run store (`/framac-cache`)

The shared store lets later runs reuse builds, Eva results and proofs for unchanged code. Because a forged entry would be trusted later, the store is mounted read-write **only** for these exact commands, which never execute target code:
- `python3 /opt/framac-pipeline/scripts/pipeline_make.py run build`
- `python3 /opt/framac-pipeline/scripts/pipeline_make.py run eva`
- `python3 /opt/framac-pipeline/scripts/pipeline_make.py run wp-sweep`
- `python3 /opt/framac-pipeline/scripts/pipeline_make.py run ingest` (and `… pipeline_make.py ingest`, `… pipeline_make.py run ingest wp-queue`)
- `python3 /opt/framac-pipeline/scripts/cache.py gc` and `… cache.py stats`

The match is token-exact after expanding `$S/` or `${S}/` to `/opt/framac-pipeline/scripts/` (`S=/opt/framac-pipeline/scripts` is exported inside the container): no other target, option, variable or shell syntax is accepted. These steps get write access automatically; `FRAMAC_CACHE_RW=off` keeps the store read-only everywhere. Every other container mounts it read-only. The job class is not used for this decision: it is inferred from a command string an LLM wrote. The flags used by those trusted builds pass an allowlist (Section 6).

- **Mutual exclusion with target code:** On the same run directory (`run_dir`, compared via `realpath`), the host broker never runs a writable-cache (`cache_mode="rw"`) container concurrently with a container that runs target code (`fuzz`, `guardrail`, `replay`, `selftest`, `verify`, `phase-dynamic`, or any unrecognized command which fails closed as running target code), automatically downgrading an allowlisted `rw` step to `ro` when a target-code job is already active on that `run_dir`, and `pipeline_make.py run` executes `make` against a stage-private temporary copy of `Makefile` and `modules.mk` rendered directly from memory. Target code in another container therefore cannot race a trusted build/Eva/sweep step or rewrite the Makefile it executes.
- **WP results** reach the shared store only through `wp-sweep`. That end-of-run step re-proves every merged function on the final tree without reading the per-run cache, which agents could have written. It is also the cheap "WP replay" behind carry-forward.
- **Partitioning and promotion:**
  - The store has one partition per repository (`$FRAMAC_CACHE_DIR/repos/<repo>`, the wrappers' repository name), so a repository's runs only ever read entries that its own runs wrote.
  - Within a partition, entries are keyed by toolchain identity.
  - Per-run entries are never promoted.
- **Lookup order:** run, then shared.

---

## 6. Make-driven phases

Per-module work that needs no judgment runs from a generated Makefile instead of LLM subagents. Make runs inside one container per phase, from the run directory.

```text
python3 $S/pipeline_make.py gen                                         # once, in the foreground
python3 /opt/framac-pipeline/scripts/pipeline_make.py run build         # trusted: fills the shared store
python3 $S/pipeline_make.py run fuzz                                    # \ run these two at the same time,
python3 $S/pipeline_make.py run eva                                     # /  as two background wrapper calls (ro alongside fuzz; use /opt/framac-pipeline/scripts/pipeline_make.py run eva when running Eva standalone with rw shared cache)
python3 /opt/framac-pipeline/scripts/pipeline_make.py run ingest        # trusted: ingests reports and publishes evolved fuzz corpora to /framac-cache/corpora/<module>
python3 $S/pipeline_make.py run replay wp-queue
```

The trusted steps are spelled out in full: only that exact command line gets a writable shared store (Section 5).

| Target | Does | Trust |
|---|---|---|
| `slice-init`, `seed` | overlay + call graph; ledger seed, validation, checkpoint (initialized once, never rewound) | static |
| `build` (`build-<mod>`) | E-ACSL / sanitizer compile of every fuzzable module | static |
| `selftest` | the E-ACSL toolchain canary | dynamic |
| `fuzz` (`fuzz-<mod>`) | one campaign per module; each depends on `selftest` and its `build-<mod>` | dynamic |
| `eva` (`eva-<mod>`) | one Eva run per module | static |
| `ingest` | ingests new reports only (fuzz before Eva), then validates; an expected module without a report gets a `not_run` record (a malformed one is moved aside as `<mod>.json.malformed`) | static |
| `replay` | replays every unverified candidate's reproducers for the crash verifiers: one report per candidate, plus `workspace/reports/replay/index.json` = `{generated_at, candidates_file, by_fingerprint: {<fingerprint>: {report, module, status}}}` | dynamic |
| `wp-queue` | `wp_scheduler.py init` | static |
| `wp-sweep` | trusted end-of-run re-proof of WP-covered functions, without the per-run cache; regressions are ingested into the ledger, so a proof that no longer holds stops counting | static |
| `report` | ACSL diff export, validation, reports | static |
| `module-<mod>` | the module's fuzz and Eva targets, then ingestion of its reports only (the harness-repair loop) | dynamic |

**`pipeline_make.py run`:**
- **Stages.** It runs the requested targets in pipeline order: slicing, then the per-module work, then ingestion and Phase-3 preparation, then the sweep, then reports. Each stage is one `make -j` call, so `run fuzz eva ingest` never ingests before the campaigns finish.
- **Regeneration.** It regenerates `modules.mk` before each call, so tuning and harness repairs take effect without re-running `gen`. It still refuses to run before the first `gen`.
- **Summary.** It prints a JSON summary per target (`ok`, `failed`, `skipped` after a failed prerequisite, `no_output`) and keeps the log under `workspace/build/logs/`.

**Exit codes:**
- `run`: 0 when every target succeeded, 1 on failures, 2 when `gen` never ran, a target is unknown or `make` is missing.
- `gen`: 1 on a malformed DAG or params file.

**Flags.** `gen` uses the harness sidecar's flags verbatim, the same ones the provers, the parent re-check and replays use. That keeps cache keys identical across all of them. DAG flags that the sidecar lacks are reported per module as `dag_cppflags_missing`; add them with `generate_harness.py --cppflags` if they matter.

**Sweep output.** Under `workspace/reports/wp-sweep/`:
- `summary.json`, with status `ok`, `regressions` or `incomplete`;
- one report per function;
- one work directory per source file, so same-named `static` functions never collide.

- **`gen`:**
  - Reads `callgraph_dag.json`, the harness sidecars and the run profile.
  - Validates every module's flags against an allowlist (`-I -D -U -include -imacros -isystem -iquote -idirafter -std= -O -g -W -f[no-]common -l -L`). A module with any other flag, such as `-fplugin`, `-B`, `-fuse-ld` or `-Wl,`, is excluded with a reason.
- **Targets are phony.** Repeated runs are cheap because of the caches and because ingestion records report digests in `state/ingested.json`, not because of timestamps, which are coarse on 9p and NFS.
- **Tuning** that the orchestrator decides (Eva slevel, the taint domain, fuzz dictionaries, budgets) lives in `workspace/build/params.json`:

  ```text
  python3 $S/pipeline_make.py params set --module snmp --eva-slevel 250 --eva-taint --eva-timeout 3600
  python3 $S/pipeline_make.py params set --module snmp --fuzz-dict workspace/dicts/snmp.dict --fuzz-budget 300
  python3 $S/pipeline_make.py params set --module snmp --reset       # back to the profile defaults
  python3 $S/pipeline_make.py params show [--module snmp]
  ```

  A value of `0` clears `--fuzz-budget`, `--fuzz-max-time` and `--eva-timeout`, and `''` clears `--fuzz-dict`. Defaults: Eva slevel 100; a fuzz budget of 60 / 120 / 900 CPU-seconds for quick / standard / deep.

---

## 7. Phase-3 scheduler

`wp_scheduler.py` replaces wave barriers with a ready queue.

**Tasks:**
- `verify:<fingerprint>`
- `repair:<module>` (done by the parent)
- `arch:<module>`
- `prove:<file#function>`
- `breaker:<file#function>`
- `negotiate:<file#function>`

**A prove task becomes ready once all of these are done:**
- its callees are merged (recursion cycles become ready together);
- the architects of its own module and of every callee's module;
- the gate of every fuzz/Eva slice that covers its file, meaning their candidates are verified and harness repairs are done.

**Priority:** the tasks with the longest chains of callers waiting on them go first.

**The orchestrator's loop:**

```text
python3 $S/wp_scheduler.py init                        # after `make ingest replay`
python3 $S/wp_scheduler.py next --slots auto --prepare # hand out ready tasks; renders briefs
# spawn one background subagent per task; on each completion:
python3 $S/wp_scheduler.py complete --agent-id <id>
python3 $S/wp_scheduler.py merge-pending
python3 $S/wp_scheduler.py next --slots auto --prepare
```

- **`--slots auto`:** `recommend().max_agents` minus running tasks, recomputed every round from the measured pool.
- **Breakers** never block callers.
- **Strengthening requests** become `negotiate` tasks as soon as they are ingested, capped per caller/callee pair. The caller is requeued once the negotiation resolves.
- **Briefs carry their context.** `--prepare` renders a negotiation brief with every request it must answer (`needed_clause`, `reason`, caller), and a breaker brief with the unproven goals of the stalled prover's own WP report. Units, module and DAG metadata are matched by file and function, so same-named `static` functions never share a brief's context.
- **Contract changes:** any merge that changes a contract re-checks the already-merged callers, using the cache.
- **`analysis_error`** (a killed or timed-out WP run) is retried once with a larger lease, then the units become `blocked`, never stuck `in_progress`.
- **Commands for interruptions:**
  - `requeue --stale-minutes N` resumes after an interrupted orchestrator.
  - `init --reconcile` adopts an existing run.
  - `refresh --module M` re-syncs after a harness repair.
- **Fallback:** `FRAMAC_SCHEDULER=waves` restores wave-by-wave dispatch.

---

## 8. Locks and crash safety

Every container of a run shares the run directory, so shared state is protected by run-wide locks that work across containers and on network filesystems. The locks are directories created atomically, with a heartbeat; a holder silent for `FRAMAC_LOCK_STALE` seconds is presumed dead.

- **`ledger` lock:** guards `coverage-ledger.json`, `candidates.json`, `findings.json`, `strengthen_requests.json` and the scheduler state.
  - Ledger transitions can be compare-and-set (`ledger.py transition --expect planned`), so a scheduler can never overwrite a unit that an ingest just marked `candidate`.
- **`merge` lock:** guards writes to `workspace/work/`.
  - Each merge journals the files it is about to change in `state/merge-journal.json`.
  - A merge killed between splice and rollback is undone by the next merge or `prepare-agent`, so unverified ACSL never stays in the work tree.
- **Parent WP reports** are written per agent (`agents/<id>/scratch/parent_wp/<fn>.json`), so parallel re-checks of same-named `static` functions never read each other's results.

---

## 9. Troubleshooting

| Symptom | Check |
|---|---|
| A command waits with "queue position N" | `resources.py status`: the pool is busy. Lower `FRAMAC_MAX_AGENTS`, raise the node's resources, or wait. Leases of killed wrappers are released once their container exits (`resources.py gc`). |
| WP report `analysis_error`, `reason: oom_killed` | The prover set exceeded the container's memory. History raises the next lease; the scheduler retries once. Repeated: check `resources.py budget` inside the container. |
| WP report `analysis_error`, `reason: insufficient_memory` | The job was limited to less than 1768 MiB, usually by a fixed `--memory` / `-Memory` or a very small engine VM. Drop the fixed size or give the engine more memory. |
| `analysis_timeout` from Eva | The module exceeded the profile's wall-clock limit. Lower the slevel in `params.json` or raise the timeout. |
| Results differ between cache on and off | Run with `FRAMAC_CACHE=off`, compare, and report it: keys are meant to be sound. `cache.py clear` removes entries. |
| "run dir on a network filesystem" warning | Move the run directory to local disk; NFS and 9p make WP and fuzzing I/O-bound. |
| Podman (or Docker) refuses a fuzz or guardrail job | The engine reports that it cannot enforce memory or pids limits; with rootless Podman the controller is usually not delegated to your user. Enable delegation, or set `FRAMAC_ALLOW_UNENFORCED_LIMITS=1` knowingly. |
| A trusted step ran with `FRAMAC_CACHE_MODE=ro` | Its command line is not an allowlisted one (an extra target, option, or shell operator; note that `$S/` and `${S}/` are expanded before matching). Nothing is wrong with the results; only the shared store was not filled. |
| A result's `cache` field says `not_published` | Its inputs changed while it was built, typically a merge into `workspace/work`. The result is valid for the content it was built from; it is just not stored. |
| A heavy ad-hoc command is OOM-killed at 1 GiB | It ran as `light`. Pass `--class` (`-Class`), for example `build` or `phase-dynamic`. History doubles the next `light` lease after an OOM. |
| `RunLockTimeout` | Another container held the run lock longer than `FRAMAC_LOCK_TIMEOUT`. The message names the holder. |
