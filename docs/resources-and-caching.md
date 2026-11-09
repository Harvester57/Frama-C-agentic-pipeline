# Resources, Scheduling and Caching

The pipeline does not assume a machine size. Before every decision it measures what it may use, sizes each invocation from that measurement, and skips work it has already done. This document explains how. The same run works on a laptop with Docker Desktop, on a cluster node whose CPUs and memory are resized between or during runs, and inside a Slurm allocation.

Two rules hold throughout:

1. **Hardware changes throughput, never results.** More CPUs mean more provers or fuzz workers at once. The limits that decide an outcome stay fixed, so proofs and findings are comparable across machines ([`./v2-design.md`](./v2-design.md#9-profiles-budget-modes-incremental-runs-m5), Section 9):
   - WP `-wp-memlimit` is always 1000 MB per prover.
   - LibFuzzer `-rss_limit_mb` is always 2048.
   - The per-input timeout is fixed: 30 s for guardrail runs, 10 s for campaigns and replays. Guardrails and replays also use a deterministic seed.
2. **Measure, don't remember.** Resources are re-probed on every lease and every scheduling round, with a 5-second memo. CPUs or memory added to or removed from the node take effect on the next job. A running tool invocation keeps the `-wp-par`, `-workers`, and `make -j` it started with, while the host broker can grow running elastic container leases via `<engine> update` (`resources.py rebalance`) when a gated lease releases and no tickets are waiting.

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

The probe also records the CPU topology (SMT siblings, L3 domains, NUMA nodes) and the filesystem type of the run directory. On network or virtualized filesystems (NFS, CIFS, 9p, FUSE, virtiofs, Lustre, GPFS) it warns, because the many small files that WP, LibFuzzer and E-ACSL write are slow there; keep run directories on local disk. The shared cache avoids this on its own (Section 5, *Where the store lives*). The run directory stays a bind mount because the orchestrator and its subagents read and write it from the host. With Docker Desktop on Windows, a run directory on the Windows disk reaches containers over 9p. For speed, put it inside the WSL2 filesystem and run the wrapper from WSL.

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
| `parse` | no | 1 | 2 GiB | one Frama-C parse of a link unit by `phase0_model.py run` (it takes the lease itself), `phase0_model.py selftest` |
| `build` | no | 1–4 | 2 GiB | `run_eacsl_fuzz.py build` |
| `guardrail` | yes | 1–2 | 2 GiB | `run_eacsl_fuzz.py guardrail` |
| `fuzz` | yes | 1–16 | 512 MiB + 2.5 GiB per worker | `run_eacsl_fuzz.py campaign` |
| `replay`, `selftest` | yes | 1 | 1 GiB | crash replays, corpus coverage (`run_eacsl_fuzz.py coverage`), the E-ACSL canary, other `sandbox_exec.py run` commands |
| `verify` | yes | elastic | elastic | `merge-agent`, `merge-batch`, `wp_scheduler.py complete/merge-pending` |
| `phase-static` / `phase-dynamic` | no / yes | elastic | elastic | `pipeline_make.py run …`, `pipeline_make.py build-check`, `phase0_model.py run`; `phase-dynamic` also covers the target's own build under `sandbox_exec.py run -- bear -- make` (or `cmake`, `ninja`, `meson`, `configure`) |

The wrapper infers the class from the command; `--class` (`-Class`) overrides it. Inference only sizes jobs. It is never a security decision (Section 5). A command the inference does not recognise runs as `light`, with 1 CPU and 1 GiB; give a heavy ad-hoc command an explicit `--class`.

Memory estimates learn from history. Each container records its peak memory, OOM kills and CPU time in `state/resource-history/` (and mirrors them into `/framac-cache/resource-history/` when the shared store is mounted read-write). The next lease for the same class and module gets 1.25 × the largest of the last five peaks across per-run and shared history, counting an OOM-killed run twice. History only ever raises a lease above the class model, never lowers it, so `-wp-memlimit` and `-rss_limit_mb` always fit.

### How tools size themselves

| Tool | Sized from the job budget | Fixed |
|---|---|---|
| WP | `--wp-par auto` = min(CPUs, (memory − 768 MiB) / 1000 MiB). A job limited to less than 1768 MiB (one prover plus Frama-C) is not run: it reports `analysis_error`, `reason: insufficient_memory`, because starved provers fail goals that a properly sized job proves | `-wp-memlimit 1000`, `-wp-timeout` from the profile |
| LibFuzzer campaign | `--workers auto` = min(CPUs, (memory − 512 MiB) / 2.5 GiB); wall time = max(30 s, CPU-second budget / workers). A job limited to less than 3072 MiB (512 MiB overhead + 2560 MiB, i.e. 1.25 × 2048 MiB `-rss_limit_mb`) is not run and reports `status: insufficient_memory` | `-rss_limit_mb 2048`, per-input `-timeout` |
| Guardrail / replay | single process | `-rss_limit_mb 2048`, per-input `-timeout`, deterministic `-seed` |
| Eva | 1 CPU; parallelism comes from running modules side by side | `--timeout` from the profile |
| Eva tuning (`eva-tune`) | 1 CPU per trial; rungs run side by side, loop trials one after another | which trials run. A rung's limit is 8 × the base run's time, a loop trial's 2 × the selected rung's (600 s to 7200 s), so a slower machine gets proportionally longer |
| Parent re-check (`merge-batch`) | per-function WP runs in a pool: workers = min(n, CPUs, memory / 1768 MiB), each `-wp-par = min(CPUs / workers, (memory / workers − 768 MiB) / 1000 MiB)` | as WP |
| Make | `-j` = container CPUs; each recipe is admitted by CPU and memory, running against a stage-private copy of `Makefile` and `modules.mk` rendered directly from memory | — |

The fuzz budget is CPU-seconds per module: quick 60, standard 120, deep 900. A bigger node finishes sooner with the same or more effort. `--max-time` stays as a wall-clock override.

---

## 3. The broker

### Host broker (`resources.py exec`)

The wrappers ([`../wrappers/framac-docker.sh`](../wrappers/framac-docker.sh) / [`../wrappers/framac-docker.ps1`](../wrappers/framac-docker.ps1)) call [`../scripts/resources.py`](../scripts/resources.py) `exec` with the host's Python (3.10 or newer). For each container it:

1. **Leases resources** from the host pool:
   - Requests are served by run: the run directory holding the fewest granted (gated) leases goes first, then first in, first out. A later request can jump ahead only when that doesn't delay the head of the queue.
   - Grants are elastic: `cpus = clamp(free // (1 + waiting), class min, min(class max, pool / 2))`. When a single `wp` job is running or scheduled with no competitors, it can expand up to `min(class max, pool)` (up to 8 CPUs) to fully utilize available cores.
   - Memory comes from the class model or history. CPUs are lowered when memory doesn't fit.
   - `light` jobs are never queued.
   - Nothing is preempted. When the pool shrinks, new grants wait until enough is released.
2. **Starts the container** with `--name framac-<lease> --label framac.lease=<id> --init` (the wrappers add `framac.repo` and `framac.run`, see *Several runs at once*), `--cpus` (or `--cpuset-cpus`), `--memory` = `--memory-swap`, and `--pids-limit`. Each limit flag is added only when the engine can enforce it. A caller that puts one of these flags on the engine command line itself is refused (exit 2): fixed sizes go through `exec --cpus/--memory/--pids-limit`, which still registers them with the broker.
3. **Passes the sizing in** as environment:
   - `FRAMAC_JOB_CPUS`, `FRAMAC_JOB_MEM_MB`, `FRAMAC_JOB_CLASS` (and `FRAMAC_JOB_KEY`);
   - `FRAMAC_POOL_CPUS` / `FRAMAC_POOL_MEM_MB`, so in-container code sees the whole node;
   - `FRAMAC_IMAGE_ID`, the toolchain identity in every cache key;
   - `FRAMAC_CACHE_MODE` (`rw`, `ro` or `off`) and, when the shared store is mounted, `FRAMAC_SHARED_CACHE_DIR=/framac-cache`.

   The command string reaches the container through `FRAMAC_CONTAINER_CMD` and the entry shim `container_entry.sh`, which runs it with `bash -lc` and then records the container's usage.
4. **Releases the lease** when the container exits.
   - When a gated lease releases and no tickets are waiting, the broker can grow running elastic container leases via `<engine> update` (`resources.py rebalance`); leases are never shrunk while running.
   - Ctrl-C and SIGTERM are forwarded as `docker kill`.
   - If the holder process dies, its lease is kept while the labelled container is still running.

While a request waits, the broker prints its queue position. Long phases are meant to run in the background, so a 10-minute foreground tool limit is never the bottleneck.

```text
python3 scripts/resources.py status     # leases held and waiting requests
python3 scripts/resources.py rebalance  # grow running elastic container leases when free pool allows
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

### Several runs at once

Runs of different targets, or several runs of one target, can share a machine. Every host on that machine uses one broker, because they all draw on the same CPUs and memory. Nothing else is shared between runs. The wrappers give each run an identity and key every resource on it:

| Name | Value | Used for |
|---|---|---|
| repo key (`FRAMAC_REPO_KEY`) | `<repo>-<first 12 hex of sha256(target path)>` | shared-cache partition and volume `framac-cache-<repo key>`, derived images `framac-build:<repo key>` and `framac-codeql:<repo key>`, label `framac.repo` |
| run tag (`FRAMAC_RUN_TAG`) | `<run id>-<first 12 hex of sha256(run path)>` | label `framac.run` |
| scratch volume | `framac-scratch-<repo>-<run id>-<hash of the run path>` | one per run directory, labelled with both |

`<repo>` (`--repo` / `-Repo`, default the target folder's name) still names the run base directory `~/framac-pipeline/<repo>/`. Two checkouts with the same folder name share that directory's `run-<N>` numbering, but nothing else. `--new-run` (`-NewRun`) claims `run-<N>` by creating it with a call that fails when the directory already exists, then retries with `N+1`. Two concurrent `--new-run` calls therefore never get the same run.

How the runs interact:

- **The queue:** it is shared, and served by run as described above, so a burst of tickets from one run does not hold every other run behind it.
- **Run-directory exclusion:** the rule between a writable-cache job and a target-code job (Section 5) applies only within one run directory. Two runs never wait on each other because of it.
- **Changing an existing setup:** moving from the repository name to the repository key changes the shared-cache partition and the derived image tags once. The first run of a target after the change starts with a cold shared cache and rebuilds its derived build image.

To see or stop one run's containers, and to list its volumes:

```text
docker ps --filter label=framac.repo=<repo key> --filter label=framac.run=<run tag>
docker volume ls --filter label=framac.repo=<repo key>
python3 scripts/resources.py status        # each lease shows its repo, run and run_dir
```

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
| `FRAMAC_MAX_AGENTS` | Cap on recommended concurrent LLM subagents | 16 (scales to 32 on $\ge 32$ CPUs, 64 on $\ge 64$ CPUs) |
| `FRAMAC_CONTAINER_ENGINE` | `docker`, `podman` or `auto` | `auto` |
| `FRAMAC_PIN` | `auto`, `on`, `off` | `auto` |
| `FRAMAC_BROKER` | `off` disables the broker | on |
| `FRAMAC_BROKER_DIR` | Lease state directory (local disk only) | `/tmp/framac-pipeline-$UID/broker`, `%LOCALAPPDATA%\framac-pipeline\broker` |
| `FRAMAC_CACHE` | `off` disables every cache, including per-run | on inside a run |
| `FRAMAC_CACHE_DIR` | Shared cross-run store (one partition per repository key under `repos/`), `off` to disable | `~/.cache/framac-pipeline` |
| `FRAMAC_CACHE_VOLUME` | `auto`, `on` or `off`: keep the shared store in the named volume `framac-cache-<repo key>` instead of bind-mounting `FRAMAC_CACHE_DIR` (Section 5) | `auto` |
| `FRAMAC_CACHE_RW` | `off` mounts the shared store read-only for every command, trusted steps included | on |
| `FRAMAC_CACHE_MAX` | Size cap for a cache store | min(20 GiB, 25 % of (free disk + the store's size)) |
| `FRAMAC_CACHE_MODE`, `FRAMAC_SHARED_CACHE_DIR` | Set by the broker inside the container: how the shared store is mounted, and where | — |
| `FRAMAC_PYTHON` | Host Python the wrappers use for the broker | first `python3` ≥ 3.10 (`py -3` on Windows) |
| `FRAMAC_RESOURCES_VERBOSE` | `1` prints every lease, not only those that waited | off |
| `FRAMAC_SCHEDULER` | `waves` restores wave-by-wave dispatch with barriers | continuous reactive sliding-window loop |
| `FRAMAC_SELINUX_TARGET` | `relabel` or `disable` for the read-only target mount on SELinux hosts | required there |
| `FRAMAC_ALLOW_UNENFORCED_LIMITS` | Allow target-executing classes without memory/pids limits | off |
| `FRAMAC_LOCK_TIMEOUT`, `FRAMAC_LOCK_STALE` | Run-lock wait and heartbeat staleness (seconds) | 1800, 120 |
| `FRAMAC_WP_WALL_TIMEOUT` | Wall-clock limit for one WP run (seconds) | 3600 |
| `FRAMAC_PROVER_WALL_BUDGET_S` | Wall-clock budget for one prover subagent session across retries (seconds) | 600 (`quick`), 900 (`standard`), 1800 (`deep`) |
| `FRAMAC_PROVER_CONTEXT` | `off` renders prover briefs without function facts and reading slice and with every conditional part, for A/B comparisons | on |
| `FRAMAC_FRAME_SKELETON` | `off` drops the frame skeleton (AST-projected `assigns`/`\from`) from function facts, for A/B comparisons | on |
| `FRAMAC_LOOP_TEMPLATES` | `off` drops the loop templates and loop dependence graph from function facts, for A/B comparisons | on |
| `FRAMAC_SPEC_KB` | `off` disables the ACSL knowledge base (retrieved knowledge in prover briefs, repair hints from failed goals), for A/B comparisons | on |
| `FRAMAC_PROOF_CARRY` | `off` disables cross-run proof carry-forward: `wp-sweep` publishes nothing to the `proofs` cache and `wp-replay` replays nothing (Section 5), for A/B comparisons | on |
| `FRAMAC_CPUS`, `FRAMAC_MEMORY`, `FRAMAC_PIDS_LIMIT`, `FRAMAC_CONCURRENT_AGENTS` | Legacy per-container sizing, used only on the no-broker path | — |

Set every knob on the host, where you run the wrapper. The container's environment is an allowlist, so the wrappers forward exactly those knobs that scripts read inside the container: `FRAMAC_CACHE`, `FRAMAC_CACHE_MAX`, `FRAMAC_MAX_AGENTS`, `FRAMAC_SCHEDULER`, `FRAMAC_LOCK_TIMEOUT`, `FRAMAC_LOCK_STALE`, `FRAMAC_WP_WALL_TIMEOUT`, `FRAMAC_PROVER_WALL_BUDGET_S`, `FRAMAC_PROVER_CONTEXT`, `FRAMAC_FRAME_SKELETON`, `FRAMAC_LOOP_TEMPLATES`, `FRAMAC_SPEC_KB`, `FRAMAC_PROOF_CARRY` and `FRAMAC_RESOURCES_VERBOSE` (the same list in both wrappers and in `docker-compose.yml`, checked by `tests/test_remediation_p2_container.py`). The others are read by the wrappers or the host broker, or set by them (`FRAMAC_RUN_ID`, `FRAMAC_REPO`, `FRAMAC_REPO_KEY`, `FRAMAC_RUN_TAG`, `FRAMAC_TARGET_*`, `FRAMAC_OUTER_SANDBOX`, `FRAMAC_JOB_*`, `FRAMAC_POOL_*`, `FRAMAC_CACHE_MODE`, `FRAMAC_SHARED_CACHE_DIR`, `FRAMAC_IMAGE_ID`).

With rootful Docker on a Linux or macOS host, both wrappers run the container as the calling user (`--user $(id -u):$(id -g)`), so the run directory never collects root-owned files; on Windows (Docker Desktop) and with Podman they keep the engine's default. `docker compose` takes the user from `FRAMAC_UID` / `FRAMAC_GID` (default `1000:1000`; set them to `$(id -u)` / `$(id -g)`) and the run id from `FRAMAC_RUN_ID` (default `run-1`, must match `run-<N>`). The image keeps everything a non-root uid reads world-readable and `HOME` (`/home/opam`) writable by any uid. The pool reaches the container only as the broker's measurement (`FRAMAC_POOL_CPUS` / `FRAMAC_POOL_MEM_MB`).

---

## 5. Caches

### Per-run caches (`state/cache/` in the run directory)

| What | Key | Hit restores |
|---|---|---|
| E-ACSL and sanitizer builds of `workspace/work` (Make builds, parent re-checks, verifiers, breakers) | L1: toolchain identity + effective flags + output path + cwd + dependency manifest; L2 (E-ACSL builds): line-shift-normalized dependency manifest | the binary, `instrumented.c`, the fallback object, `compile.log` |
| Guardrail verdicts (run-local `guardrail` store) | binary sha256 + corpus manifest + `--extra-runs` + `--timeout` + `-seed` + module | `passed_dynamic_oracle`, `rejected_overconstrained`, or `code_fault` verdict |
| WP prover results | Frama-C's own goal digest (`-wp-cache update -wp-cache-dir state/cache/wp`) | unchanged goals across a prover's iterations and in the parent re-check |
| Eva reports with status `ok` | toolchain identity + Eva flags + dependency manifest (the output directory is factored out, so a ladder rung and a later `run eva` with the same options share an entry) | report JSON, `alarms.csv`, `red_alarms.csv`, `eva.log`, `slice.sarif`, `flows.log`, `flows.cg.dot` |
| Function facts of a module (`facts`) | toolchain identity + flags + dependency manifest + digest of the Eva flows | `workspace/reports/facts/<module>.json` |
| Swept proofs (`proofs`, written only by `wp-sweep`, read by `wp-replay`) | C tokens of the function's file and header (every annotation and comment stripped), the current contracts of its direct callees, the module's WP cppflags and extra sources, the machdep, plus toolchain identity and the scripts digest | `contract.json` (the annotated definition span, the header prototype span, the top-level ACSL declarations its annotations name, the WP flags it was swept with) and the swept `wp_report.json`, restored to `state/proof-carry/<file>__<function>/` and **re-proved before anything is credited** |
| Parsed translation units for reading slices (`slice-index`) | digest of the preprocessed C, ignoring line markers and whitespace | the declaration and macro index, shared by every prover of a file, because ACSL-only merges leave those tokens unchanged |

**Toolchain identity** is the image ID (or a digest of the tool versions when `FRAMAC_IMAGE_ID` is unset), plus `+snapshot:<digest>` when the run has a target snapshot (`workspace/snapshot/manifest.json`: the target's headers and libraries the analysis image compiles and links against, `cache.toolchain_id`), plus a digest of `scripts/` and `templates/`, which are bind-mounted and change without an image rebuild.

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
- `python3 /opt/framac-pipeline/scripts/pipeline_make.py run eva-tune`
- `python3 /opt/framac-pipeline/scripts/pipeline_make.py run facts`
- `python3 /opt/framac-pipeline/scripts/pipeline_make.py run wp-sweep`
- `python3 /opt/framac-pipeline/scripts/pipeline_make.py run ingest` (and `… pipeline_make.py ingest`). `run ingest wp-queue` is no longer on the list: `wp-queue` depends on `wp-replay`, whose parent guardrail runs target code.
- `python3 /opt/framac-pipeline/scripts/cache.py gc` and `… cache.py stats`

The match is token-exact after expanding `$S/` or `${S}/` to `/opt/framac-pipeline/scripts/` (`S=/opt/framac-pipeline/scripts` is exported inside the container): no other target, option, variable or shell syntax is accepted. These steps get write access automatically; `FRAMAC_CACHE_RW=off` keeps the store read-only everywhere. Every other container mounts it read-only. The job class is not used for this decision: it is inferred from a command string an LLM wrote. The flags used by those trusted builds pass an allowlist (Section 6).

- **Mutual exclusion with target code:** On the same run directory (`run_dir`, compared via `realpath`), the host broker never runs a writable-cache (`cache_mode="rw"`) container concurrently with a container that runs target code (`fuzz`, `guardrail`, `replay`, `selftest`, `verify`, `phase-dynamic`, or any unrecognized command which fails closed as running target code), automatically downgrading an allowlisted `rw` step to `ro` when a target-code job is already active on that `run_dir`, and `pipeline_make.py run` executes `make` against a stage-private temporary copy of `Makefile` and `modules.mk` rendered directly from memory. Target code in another container therefore cannot race a trusted build/Eva/sweep step or rewrite the Makefile it executes.
- **WP results.** Frama-C's own goal cache (`state/cache/wp`) never reaches the shared store. The end-of-run `wp-sweep` re-proves every merged function on the final tree with no proof cache at all (`--cache-dir off`), so nothing an agent wrote into the per-run cache can answer it; a function it cannot re-establish has its WP-covered units `blocked`. Each function it re-proves `all_proven` (not an Eva-only callee) is then published to the `proofs` namespace ([`../scripts/proof_carry.py`](../scripts/proof_carry.py)): the run store always, the shared store with `FRAMAC_CACHE_MODE=rw` (`run wp-sweep` is a trusted step). Prover scratch results, merged-but-unswept functions and partial merges are never published.
- **Proof carry-forward.** On the next run, `wp-replay` (Section 6) looks up every function with `planned` units, callees first, and replays a hit as a splice of the cached definition span (contract and loop annotations) and prototype contract into a parent-owned scratch agent (`carry-<n>`), through the ordinary `merge-agent` path: ACSL-only and scope checks, the parent guardrail and the parent WP re-check on the merged tree, with the reduced checks and WP model of the swept report. Only an `all_proven` re-check credits units (`ledger.py ingest-wp`, then `ledger.py mark-carried` labels the evidence `carried_forward_reproven` and names the restored entry under `details.proof_carry`); anything else rolls back, removes the agent and leaves the units `planned` for the provers. A cached proof never changes a verdict on its own, and the next `wp-sweep` re-proves carried functions like any other. Top-level ACSL declarations the contract names are first added to the header through an architect merge when they are missing; one present with different text rejects the hit (`declaration conflict`). A changed script or template changes every key (`cache.make_key` folds in the scripts digest), so a pipeline update empties the proof store until the next sweep refills it. `FRAMAC_PROOF_CARRY=off` disables both sides. The replay summary is `workspace/reports/proof-carry/summary.json` (`hits`, `reproven`, `misses`, `rejected` with reasons, `unkeyed`, `carried`).
- **Partitioning and promotion:**
  - The store has one partition per repository key (`$FRAMAC_CACHE_DIR/repos/<repo key>`, or the volume `framac-cache-<repo key>`), so a repository's runs only ever read entries that its own runs wrote. The key is the repository name plus a hash of the target path (Section 3, *Several runs at once*), so two checkouts with the same folder name never share a partition.
  - Within a partition, entries are keyed by toolchain identity.
  - Per-run entries are never promoted.
- **Lookup order:** run, then shared.

#### Where the store lives

The host broker either bind-mounts the host directory or mounts a named volume at `/framac-cache`. The broker decides per job with `FRAMAC_CACHE_VOLUME`:

- **`auto` (default):** uses the volume `framac-cache-<repo key>` when a bind mount would be slow or wrong:
  - the engine runs containers in a VM (Docker Desktop on Windows or macOS, a Podman machine), where bind mounts cross the VM boundary over 9p, virtiofs or gRPC FUSE;
  - the engine is remote, so a host path would name a directory on another machine;
  - the cache directory is on a network or virtualized filesystem (NFS, CIFS, or 9p as for `/mnt/c` in WSL2).

  Otherwise (Linux, WSL2 with the cache on the WSL filesystem) it bind-mounts `FRAMAC_CACHE_DIR`.
- **`on` / `off`:** force one or the other.

The read-only and read-write rules above apply to the volume unchanged. The first job that needs the volume creates it, labelled `framac.cache=1` and `framac.repo=<repo key>`. A one-off init container then sets the volume root to mode 1777, so the non-root job user can write it. That container runs as root with no network and no capabilities, and runs no target code. A lock in the broker directory keeps a concurrent job from mounting the volume before its root is set up. If the volume cannot be created or initialized, the job falls back to the bind mount and says so.

A volume lives in the engine, not on the host. Two consequences:

- The host broker does not read the shared resource history in it, so it sizes leases from the run's own history only.
- `cache.py stats`, `gc` and `clear` work as usual inside a container.

To drop a repository's store:

```text
docker volume rm framac-cache-<repo key>
docker volume ls --filter label=framac.cache=1
```

---

## 6. Make-driven phases

Per-module work that needs no judgment runs from a generated Makefile instead of LLM subagents. Make runs inside one container per phase, from the run directory.

```text
python3 $S/pipeline_make.py gen                                         # once, in the foreground
python3 /opt/framac-pipeline/scripts/pipeline_make.py run build         # trusted: fills the shared store
python3 $S/pipeline_make.py run fuzz                                    # \ run these two at the same time,
python3 $S/pipeline_make.py run eva                                     # /  as two background wrapper calls (ro alongside fuzz; use /opt/framac-pipeline/scripts/pipeline_make.py run eva when running Eva standalone with rw shared cache)
python3 /opt/framac-pipeline/scripts/pipeline_make.py run eva-tune      # trusted: the Eva ladder, for modules that still have Unknowns
python3 $S/pipeline_make.py run coverage reach-dynamic                  # after fuzz: what each corpus reached; reopens the reach gate for unexecuted entry points
python3 /opt/framac-pipeline/scripts/pipeline_make.py run ingest        # trusted: ingests reports and publishes evolved fuzz corpora to /framac-cache/corpora/<module>
python3 $S/pipeline_make.py run replay wp-queue
```

The trusted steps are spelled out in full: only that exact command line gets a writable shared store (Section 5). When invoking via `framac-docker.ps1` on Windows PowerShell, wrap `$S/...` commands in single quotes, escape `` `$S ``, or write `/opt/framac-pipeline/scripts/...` in full so host PowerShell does not expand `$S` as an empty host variable.

| Target | Does | Trust |
|---|---|---|
| `slice-init` | the shadow overlay (`/framac-slice` Step 1); the build capture, the Phase 0 model and the seed recording run between it and `dag`, through the wrapper | static |
| `dag` | the call-graph DAG from the Phase 0 model (`workspace/reports/phase0_model.json`, status `ok`) | static |
| `security-props` | the MetAcsl security properties (`workspace/reports/security_props.json`); `seed` depends on it | static |
| `reach-gate` | the static Phase 0 reach gate (`harness_reach.py check`): every DAG entry point of each harnessed module is reached by its harness or exempted; records `workspace/reports/phase0_gates.json` with the digests of each harness and of the DAG, so a harness or DAG changed afterwards fails the gate until it runs again | static |
| `seed` | after `reach-gate` and `security-props`: ledger seed, validation, and `state/progress.json` (initialized once, never rewound). The phase 0 checkpoint is recorded later, by `pipeline_make.py build-check` once every Phase 0 gate passed | static |
| `seeds` | writes each module's seed inputs (`workspace/seeds/<mod>/`) in its harness's case format from the calls recorded by `seed_harvest.py record` (`seed_harvest.py write`); `fuzz-<mod>` rewrites its own before each campaign, and a failure never stops the pipeline | static |
| `build` (`build-<mod>`) | E-ACSL / sanitizer compile of every fuzzable module, after the module's reach gate check | static |
| `selftest` | the E-ACSL toolchain canary | dynamic |
| `fuzz` (`fuzz-<mod>`) | one campaign per module, with its seeds as a read-only extra corpus; each depends on `selftest` and its `build-<mod>`, and checks the module's reach gate and build-check first | dynamic |
| `coverage` (`coverage-<mod>`) | replays each module's corpus and seeds on a Clang source-coverage build and writes per-function reach to `workspace/reports/coverage/<mod>.json`; it starts no campaign | dynamic |
| `reach-dynamic` (`reach-dynamic-<mod>`) | after `coverage-<mod>`: an API entry point of the module that no input executed reopens the reach gate (`harness_reach.py dynamic`), so the module's next `fuzz-`/`eva-` target stops until the harness is repaired or the entry point exempted | static |
| `facts` (`facts-<mod>`) | kernel AST facts of the module's functions, joined with its Eva report's read and write sets, for the prover briefs; `wp-queue` depends on it, and a failure never stops the pipeline | static |
| `eva` (`eva-<mod>`) | one Eva run per module; a module with a current tuning decision replays it (base run plus recorded rungs, combined by `eva_tuning.py finish --replay-only`), so the report equals `run eva-tune`'s; a sharded module runs its `evashard-<mod>--<i>` side by side and merges them (`eva_shards.py merge`) | static |
| `eva-tune` | the Eva ladder: base run, then rungs, selection, per-loop analysis and combination for modules left with Unknowns; rewrites the module's Eva report and records the decision | static |
| `ingest` | ingests new reports only (fuzz before Eva), then validates; an expected module without a report gets a `not_run` record (a malformed one is moved aside as `<mod>.json.malformed`) | static |
| `replay` | replays every unverified candidate's reproducers for the crash verifiers: one report per candidate, plus `workspace/reports/replay/index.json` = `{generated_at, candidates_file, by_fingerprint: {<fingerprint>: {report, module, status}}}` | dynamic |
| `wp-replay` | after the Phase 3 gate: re-applies and re-proves (guardrail + parent WP) the contracts an earlier run's `wp-sweep` published for functions with `planned` units, so the units a re-proof credits never become prove tasks (Section 5, *Proof carry-forward*); never fails the build; `FRAMAC_PROOF_CARRY=off` writes a `skipped` summary | dynamic |
| `wp-queue` | `wp_scheduler.py init`, after `wp-replay` | dynamic (through `wp-replay`) |
| `wp-sweep` | trusted end-of-run re-proof of WP-covered functions, without any proof cache; anything it cannot re-establish is ingested as `blocked`, then the hypothesis audit runs; every function re-proved `all_proven` is published to the `proofs` cache (summary `published_proofs`, per row `published`) | static |
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
- **Tuning** that the orchestrator decides (Eva slevel/mlevel, allowlisted Eva options, the taint domain, recursion fallback, fuzz dictionaries, budgets) lives in `workspace/build/params.json`, next to the decision `eva-tune` records:

  ```text
  python3 $S/pipeline_make.py params set --module snmp --eva-slevel 250 --eva-mlevel 4 --eva-taint --eva-timeout 3600
  python3 $S/pipeline_make.py params set --module snmp --eva-option min-loop-unroll=8 --eva-option split-return=auto
  python3 $S/pipeline_make.py params set --module snmp --eva-retune    # forget the recorded decision: search again
  python3 $S/pipeline_make.py params set --module snmp --fuzz-dict workspace/dicts/snmp.dict --fuzz-budget 300
  python3 $S/pipeline_make.py params set --module snmp --reset       # back to the profile defaults
  python3 $S/pipeline_make.py params show [--module snmp]
  ```

  A value of `0` clears `--eva-mlevel`, `--fuzz-budget`, `--fuzz-max-time` and `--eva-timeout`, `''` clears `--fuzz-dict`, and `--eva-option name=` clears that option. Defaults: Eva slevel 100, mlevel 0; a fuzz budget of 60 / 120 / 900 CPU-seconds for quick / standard / deep.

### Eva tuning (`eva-tune`)

Every Eva Unknown that survives into Phase 3 costs a prover task, so Eva tuning runs as a deterministic, cached Make step rather than a judgment call. The logic is in [`../scripts/eva_tuning.py`](../scripts/eva_tuning.py), and the ladder and option allowlist are in [`../scripts/eva_options.py`](../scripts/eva_options.py).

**The steps.** `run eva-tune` is two Make stages, with `modules.mk` regenerated in between so only modules left with Unknowns get rung targets:

1. `evabase-<mod>`: the module's own settings. This is the reference for every guard, and identical to `eva-<mod>` until a decision is recorded, so they share a cache entry.
2. `evarung-<mod>--<rung>`: each ladder rung, side by side. A failed or timed-out rung never blocks the module. A rung leases memory under its own history key, `<mod>:<rung>`, so a rung that needs less than the base run leaves room for others; with no record of its own yet, the key falls back to the largest peak recorded for the module (never the smaller class default). A rung that times out stays a timeout (`--no-timeout-fallback`: the cheaper fallback settings are less precise than the base run, so they cannot help) and writes no `flamegraph.txt` (`--no-flamegraph`). When the base run took so long that even the cheapest rung (`TUNING_SKIP_MARGIN` = 1.25 × the base run, from measured rung/base ratios of 0.84 to 1.2 for the cheapest rungs) would reach the rung limit, the module gets no rungs at all: `evatune-<mod>` writes the base run's report with `tuning.mode: "skipped"`, runs no loop trials, records nothing, and `gen`/`run` print the reason as a warning.
3. `evatune-<mod>`: applies the guards, selects a run, tries per-loop unrolling, combines, writes `workspace/reports/eva/<mod>.json` and `workspace/reports/eva-tuning/<mod>/decision.json`, and records the decision in `params.json`.

**Sharded modules** (`eva_shards.py`, `docs/eva-sharding.md`). When a module's single run is too slow to tune and its harness has per-case shard guards, `gen` records a shard plan in `workspace/reports/eva-shards/<mod>/plan.json`. From then on, `eva-<mod>`, `evabase-<mod>` and `evatune-<mod>` all depend on `evashard-<mod>--<i>` and merge the shards into the module's report. Each shard is the module's plain run with `-DFRAMAC_EVA_SHARD -DFRAMAC_EVA_SHARD_CASE_<k>...` added to its cppflags, so each has its own Eva cache entry. It leases memory under `<mod>:shard<i>`, which falls back to the module's largest recorded peak until the shard has a peak of its own. So on a small pool, the first sharded run still runs few shards at a time. How many shards there are is fixed by the plan, never by the machine: a machine with fewer slots runs the same shards one after another. Sharded modules get no ladder yet.

**The ladder** changes one concern per rung, because PARF (Wang et al., JCST 2025, Table A2) found no knob dominant on every program. slevel leads on average (0.490), then domains (0.258, mostly on in the base configuration already), and partition-history helps some programs and hurts others. The last rung is Eva's own all-round recipe. `multidim` stays out of the ladder, because Frama-C calls it experimental and a Valid can end a function's verification; it remains a module option for whoever chooses it.

**Guards.** A run is rejected if any of these holds, and the reason is recorded:

| Guard | Why |
|---|---|
| It did not complete | A timeout or crash has no usable statuses |
| Different `input_digest`, entry, `reduced_checks` or `context-depth` | It is a different analysis |
| It degenerated | A stopped analysis (signal, failed initialization, stop at an alarm) exits non-zero with no report, so it fails the first guard; a report without Eva's end-of-analysis summary is rejected as a backstop |
| Any obligation Dead that the base run did not have Dead | Checked per obligation, not by total, so a hidden harness gap cannot cancel out |
| An obligation newly `Inconsistent`, or more than a quarter of the base run's obligations missing, or inputs that changed during the run | The run's statuses can no longer be compared with the base run's. An alarm Eva stops emitting is normal (at most 14 of 815 measured); a quarter means obligations stopped matching, and absent alarms would look like proofs |
| Fewer functions analysed, a lower coverage estimate, or the entry no longer reached | Coverage collapse removes alarms: PARF's miniz-ex1 fell from 1,828 alarms to 1 this way |
| A function newly non-terminating | Eva stopped seeing its return, so what follows is cut |

Red statuses from a run rejected for coverage still reach the report as candidates, because the alarm is often why the coverage was lost.

**Selection** minimizes functions with an Unknown, then Unknowns, then ladder order, counting only rows in target code: a libc function's own row summarizes call sites that have rows of their own, and no ledger unit exists for it.

**Per-loop analysis** follows Loupe's differential analysis (Mattar et al., ASE 2025) without its model. At most 8 trials per module, loop nests of the functions with the most Unknowns first, each with `//@ loop unroll N` on a scratch mirror of the include closure under `workspace/eva/<mod>/tune/mirrors/`. `workspace/work` never changes. The annotation sits on the loop's own line, so obligations keep their identity, and it joins a loop's existing annotation as its first clause, because the kernel rejects a second annotation comment on a loop. A loop is named by file, function and ordinal, so a decision survives ACSL landing above it. N is at least 256, or the harness's maximum input size plus 1 when that is larger: Eva stops at a loop's real bound, so an over-large N costs nothing there.

**Combination** turns an Unknown Valid when any admissible run proves it. No paper states this for Eva, so here is the argument:

- Eva's results hold under the assumption that its alarms hold (Eva manual 5.7, 8.1.2), but only for the execution so far. A Valid status means no execution can violate that property before violating an earlier alarm.
- So in every sound run, the *first* property a real execution violates is reported as not Valid. If any run proves a property, it cannot be the first one violated. An alarm absent from a run that reached as many statements of that function says the same, since Eva emits one whenever it cannot prove the property.
- Therefore, if the properties no run proves all hold, no execution violates anything, by induction on its length. Two runs each assuming what the other proves are no circle, because the assumption only reaches back in time.
- The kernel agrees. Frama-C classifies each Eva parameter as tuning or correctness (`parameters.ml`), and `emitter.mli` says of a tuning parameter that "a valid status cannot become invalid"; `Property_status.emit` keeps the strongest status across runs of one session. Measured on `minmea` with two runs in one session, where each proves obligations the other does not (13 and 7): this combination matches the kernel on 813 of 815 obligation groups and is never weaker. The other 2 are alarms the first run never emitted, so the kernel has no status to keep; that is the absence rule above.
- The argument needs runs that differ only in tuning. Every rung holds the sources, harness and checks fixed, and `context-depth`, the one allowed correctness parameter, is never varied.

Dead is never counted as a proof, since it is a harness gap. A red status beats any Valid, as it does in the kernel, and the conflict is recorded. The CSV merges identical rows and hides columns, so one key (fingerprint and line) can cover several statements, and it counts as proved only if every row under it is Valid.

**Determinism and replay.** Selection and combination read no clocks. Both proofs and red statuses are unions over completed runs, so a machine that finishes fewer trials discharges a subset of the same obligations and leaves more units `planned`. The one case that can differ is a red status only an unfinished rung would have found, on an obligation another run proves: that statement is unreachable unless an earlier alarm fails, so verifying the candidate finds no witness and the final verdict is the same. `params.json` records the selected options, the kept loops, the runs the report relied on for proofs and red statuses, and the rungs that did not finish, with the digests they were made under. `run eva` (and `module-<mod>`) then replays the recorded decision, combination included, and `run eva-tune` on another machine runs only the recorded trials. A stale decision is reported in the `warnings` of `gen` and `run`. Other sources or other module settings, including `--eva-timeout`, mean a new search; `params set --eva-retune` forces one. Bump `LADDER_VERSION` when the ladder changes.

**Measured** with Frama-C 34.0~~dev through `run eva` and `run eva-tune`, one run each on a shared 12-thread machine, counting target code only:

| Target and harness | Functions with Unknown | Unknowns | Valid | Dead | Prover tasks | Time |
|---|---|---|---|---|---|---|
| `minmea`, symbolic 80-byte sentence | 8 → 4 | 146 → 81 | 304 → 355 | 175 → 175 | 17 → 14 | 30 s → 791 s |
| `picohttpparser`, symbolic 32-byte request | 6 → 5 | 81 → 79 | 144 → 144 | 273 → 273 | 25 → 24 | 17 s → 215 s |

- Options cannot fix an imprecise harness. On `jsmn` with a symbolic 16-byte input, every allowlisted option alone left 34 Unknowns in 3 functions, except the `slevel` values that timed out and `remove-redundant-alarms` off (35). Through `run eva-tune` with `--eva-timeout 1200` on a loaded machine, the base run stayed selected at 34 Unknowns and 6 of the 7 rungs timed out. Per-loop trials on this harness have not been measured.
- A concrete input behaves as Loupe reports. On `jsmn` with the fixed string of its `simple.c`, Eva's defaults leave 45 Unknowns, `-eva-auto-loop-unroll 100` still 45, and full unrolling 0, faster (1.3 s against 3.3 s). The pipeline's base settings already reach 0.
- That last case shows what the Dead guard costs: Dead rose from 11 to 74 there, legitimately, because a concrete input really does cut branches. From a less precise base, the guard would reject that run. Symbolic harnesses showed no Dead growth in any run measured.
- On `minmea` and `picohttpparser`, combination discharged nothing beyond the selected run. It costs no extra Eva run, and the pair in the kernel comparison above shows it can matter when no one run dominates.
- Replay on `minmea` took 8 s with the cache and 352 s from empty caches on the recorded runs, with identical obligations. With every trial limited to 60 s, the search chose another rung and left 138 Unknowns against 83 (all rows), with every Unknown of the full run still Unknown and the same red alarms.

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
- its callees have an initial contract in `workspace/work/` (speculative contract-first dispatch; callers do not wait for callee body proofs; internal static callees without contracts are proven first via Option A);
- the architects of its own module and of every callee's module (leaf and internal static functions run concurrently with architects via 3-way AST header declaration splicing);
- the gate of every fuzz/Eva slice that covers its file, where verify tasks gate only functions within their call cone.

**Priority:** the tasks with the longest chains of callers waiting on them go first, followed by Eva unknown count, then function name.

**The orchestrator's loop (continuous reactive sliding window):**

```text
python3 $S/wp_scheduler.py init                                                 # after `make ingest replay`
python3 $S/wp_scheduler.py step --slots auto --prepare                          # initial dispatch; renders briefs
# spawn background subagents; on completions, drive atomically:
python3 $S/wp_scheduler.py step --complete <id1> <id2>... --slots auto --prepare
```

Granular individual subcommands (`complete`, `merge-pending`, `next`) remain fully supported for specialized or step-by-step control.

- **`--slots auto`:** `recommend().max_agents` minus running tasks, recomputed dynamically from the measured pool. On high-spec hardware, agent concurrency scales up to 32 on $\ge 32$ CPUs and 64 on $\ge 64$ CPUs; `wp.max_cpus` scales up to 16, and `guardrail.max_cpus` scales up to 4.
- **Fixed limits invariant:** per-process limits that decide proof and finding outcomes remain strictly constant regardless of pool scale (`WP_MEMLIMIT_MB=1000`, `FUZZ_RSS_LIMIT_MB=2048`).
- **Parallel snapshot preparation and re-checks:** `next --prepare` and `merge-pending` execute agent snapshotting and contract re-checks in parallel via a thread pool under the `merge` lock, strictly observing the `ledger` $\rightarrow$ `merge` lock hierarchy.
- **Breakers** never block callers.
- **Strengthening requests** become `negotiate` tasks as soon as they are ingested, capped per caller/callee pair. The caller is requeued once the negotiation resolves.
- **Briefs carry their context.** `--prepare` renders a negotiation brief with every request it must answer (`needed_clause`, `reason`, caller), and a breaker brief with the unproven goals of the stalled prover's own WP report. Units, module and DAG metadata are matched by file and function, so same-named `static` functions never share a brief's context.
- **Contract changes:** any merge that changes a contract re-checks the already-merged callers in parallel, using the cache.
- **`analysis_error`** (a killed or timed-out WP run) is retried once with a larger lease, then the units become `blocked`, never stuck `in_progress`.
- **Commands for interruptions:**
  - `requeue --stale-minutes N` resumes after an interrupted orchestrator.
  - `init --reconcile` adopts an existing run.
  - `refresh --module M` re-syncs after a harness repair.
- **Fallback:** `FRAMAC_SCHEDULER=waves` restores wave-by-wave dispatch with barriers between topological waves for comparison and regression testing.

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
| `eva-tune` leaves a module unchanged | Read `tuning.runs` in `workspace/reports/eva/<mod>.json`: each run has a verdict and, if rejected, its reasons. Eva options often cannot help when the harness itself is imprecise, for example a symbolic input length. |
| Results differ between cache on and off | Run with `FRAMAC_CACHE=off`, compare, and report it: keys are meant to be sound. `cache.py clear` removes entries. |
| "run dir on a network filesystem" warning | Move the run directory to local disk; NFS and 9p make WP and fuzzing I/O-bound. |
| Podman (or Docker) refuses a fuzz or guardrail job | The engine reports that it cannot enforce memory or pids limits; with rootless Podman the controller is usually not delegated to your user. Enable delegation, or set `FRAMAC_ALLOW_UNENFORCED_LIMITS=1` knowingly. |
| A trusted step ran with `FRAMAC_CACHE_MODE=ro` | Its command line is not an allowlisted one (an extra target, option, or shell operator; note that `$S/` and `${S}/` are expanded before matching). Nothing is wrong with the results; only the shared store was not filled. |
| A result's `cache` field says `not_published` | Its inputs changed while it was built, typically a merge into `workspace/work`. The result is valid for the content it was built from; it is just not stored. |
| A heavy ad-hoc command is OOM-killed at 1 GiB | It ran as `light`. Pass `--class` (`-Class`), for example `build` or `phase-dynamic`. History doubles the next `light` lease after an OOM. |
| `RunLockTimeout` | Another container held the run lock longer than `FRAMAC_LOCK_TIMEOUT`. The message names the holder. |
