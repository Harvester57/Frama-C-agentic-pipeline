# Design: Larger Phase 1 Fuzz Budgets, Spent Where They Pay

Status: proposal, 2026-11-16 (revised 2026-11-16 after codebase review and design iteration). Nothing
here is implemented. It comes from the supervision of c-ares run-1
(`docs/runs/2026-11-16-c-ares-run1-supervision.md`, held on the c-ares supervision branch; see
[`../runs/README.md`](../runs/README.md)) and is meant for every target, not only c-ares. Section 4
says what the evidence does not cover. All ten proposals (`P1`–`P10`, with `P4` rejected) and their
alignment with [`./phase1-remediation-plan.md`](./phase1-remediation-plan.md) (`D1b`, `D4`, `D8`,
`F7`) were settled with the user on 2026-11-16; numeric thresholds remain starting values to be
calibrated once `P5` lands. A reassessment on 2026-11-16 against the scripts and run-1's lease
records corrected section 1.4 and added `P7g` and section 6, whose points are open. Note: held fixes from the c-ares supervision branch are written `CA-F2`,
`CA-F10`, and `CA-F11` below so they do not collide with `F1`–`F17` of
[`./phase1-review.md`](./phase1-review.md).

## 1. Problem

Phase 1 fuzzes for far less time than Phase 2 analyses, although it is the only phase that produces
a concrete crashing input. On c-ares run-1, `run eva` took 9,433 s (2 h 37 min) of wall time. The
seven fuzz campaigns had wall limits of 30 to 64 s each, 274 s together.

### 1.1 Current budgets

[`../../scripts/pipeline_make.py`](../../scripts/pipeline_make.py) (lines 117-124) sets the effort in
CPU-seconds:

| Profile | Per harness case | Cap per link unit | `MIN_FUZZ_BUDGET_S` |
| :--- | :--- | :--- | :--- |
| quick | 60 | 480 | 30 |
| standard | 120 | 1,200 | 30 |
| deep | 900 | 7,200 | 30 |

`run_eacsl_fuzz.campaign_wall_time` turns the budget into wall time as
`max(MIN_FUZZ_WALL_S, ceil(fuzz_budget / workers))`, with `MIN_FUZZ_WALL_S = 30`. On 9 workers,
`standard` gives about 13 s of wall time per case, and a whole unit at its cap about 2 min 15 s.
`deep` gives a unit about 13 min, which is less than one 900 s Eva fallback tier.

Eva, by comparison, gets `wall_timeout_s = 7200` per module, and on a timeout two fallback tiers of
up to 900 s each: about 2 h 30 min of wall time for a timed-out module. An Eva run used 1 to 2 CPUs
on run-1, so that is 9,000 to 18,000 CPU-seconds, 7.5 to 15 times `standard`'s cap for a whole unit.

Two details of the budget matter later:

- **The cap decides, not the per-case figure.** A unit with more than 10 cases (`standard`) has its
  campaigns scaled down to the cap. c-ares's `libcares_a` unit has 40 cases over five campaigns, so
  each case got 30 CPU-seconds, not 120.
- **The wall floor makes the CPU spent depend on the machine.** A campaign whose budget gives less
  than 30 s runs 30 s on every worker it has. On run-1, five of the seven campaigns ran at the floor.
  `libcares_a__channel` had 30 CPU-seconds budgeted and 9 workers for 30 s, up to 270 CPU-seconds.
  In the dual-engine split each half has the same floor, so such a campaign takes 60 s.

### 1.2 What c-ares run-1 shows

Profile `standard`; every module was built and fuzzed with E-ACSL only (section 1.3). All campaigns
had 9 workers.

| Module | `FUZZ_BUDGET` (CPU-s) | Wall limit | Mode | Result | Fuzzing actually done |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `libcares_a__dnsrec` | 570 | 64 s | rounds, 19 cases | clean | 9 jobs for 64 s. The report keeps one job's final statistics: 89,993 executions at 1,384 exec/s, 1,163 edges, 2,946 features, corpus 522. The other eight jobs are not in the report; 1,909 corpus files are on disk. |
| `libcares_a__parsers` | 540 | 60 s | rounds, 18 cases | false positive (`inet_ntop4`, `%u`) | Crashed while reading the seed corpus, after 22 executions. 182 s were charged to the 60 s budget, so the campaign stopped with `time_budget_spent` and no case skipped. The other 17 cases were never fuzzed. |
| `tf_ares-test-fuzz` | 30 | 30 s | fork | same false positive, 17 duplicates omitted | Ran its full 30 s: about 147,000 executions, 1,288 edges, corpus 431. Coverage was still growing at the end (1,227 to 1,288 edges in the last 14 s). |
| `libcares_a__channel` | 30 | 30 s | rounds, 1 case | false positive (`ares_buf_consume_until_charset`) | 1.8 s, 35 executions. Its only case was skipped, so nothing was left to fuzz. |
| `adig`, `ahost`, `tf_ares-test-fuzz-name` | 120, 120, 30 | 30 s | fork | same `ares_buf` false positive, on every input | About 1,300 to 2,000 jobs, each one a crash; `cov: 0`, `corp: 0` throughout. |

What the campaign had to work with was good:

- **Imported corpus** (`fuzz_assets.py`): c-ares ships `test/fuzzinput`. The pipeline mapped 690 real
  DNS packets onto the `parsers` harness cases (50 dropped for exceeding 1,500 bytes). Case 6, for
  example, feeds `ares_dns_parse` and every `ares_parse_*_reply`. A further 74 inputs went to
  `tf_ares-test-fuzz` and 46 to `tf_ares-test-fuzz-name`.
- **Harvested seeds** (`seed_harvest.py`): 56 inputs for `dnsrec` and 14 for `parsers`. `adig`,
  `ahost` and `channel` got none, because no recorded call or data file fits their cases.
- **Dictionaries:** 428 to 605 entries per module.

Most of that material was never used. Two E-ACSL false-positive families account for all 82
artifacts: 56 from tail-merged literals (held c-ares fix `CA-F11`) and 26 from the `%u` format check
(held c-ares fix `CA-F10`). Their effect on the seven campaigns:

- **Five learned nothing.** `adig`, `ahost` and `tf_ares-test-fuzz-name` crashed on every input for
  their whole 30 s. `channel` ended after 1.8 s. `parsers` ended after its first round, for the
  reason in P1c.
- **One fuzzed normally despite the false positive.** `tf_ares-test-fuzz` runs in fork mode with
  crashes ignored, and few of its inputs crash. Its last status line counts one crashing job in 17,
  while the report lists 20 crash files (3 kept, 17 duplicates); the two figures were not
  reconciled. It is also the only campaign that shows the budget itself was too short: its coverage
  had not levelled off after 30 s.
- **One was clean.** `dnsrec` ran its 64 s. Whether its coverage levelled off is unknown: the report
  keeps only the last lines of one job (P5a).

### 1.3 Observation: the dual-engine split did not run

`fuzz_engine` defaults to `auto` (`pipeline_make.py`, `default_params`). With a working E-ACSL build,
`auto` already fuzzes with both engines, half the time each: ASan+UBSan first, then E-ACSL on the
grown corpus (`run_eacsl_fuzz.py`, around line 5850). On run-1, the call-graph DAG had asked for
`sanitizers` on some units, because of the setjmp false positive (held c-ares fix `CA-F2`). The
model then ran `params set --fuzz-engine eacsl` for every module (`cmd-set-eacsl.sh`), which also
disables the dual-engine split. `params set --fuzz-engine auto` would have overridden the DAG's
choice too, and kept the split. The `framac-fuzz` skill says that `eacsl` fuzzes with one engine
only, but no skill names `auto` as the way to undo a DAG choice. So run-1 says nothing about what
`auto` would have found. It does show that a `params set` meant to undo a wrong DAG choice costs the
faster engine, with no warning.

### 1.4 Where Phase 1's wall time went

`run build` took 348 s and `run fuzz` 2,026 s, against 274 s of campaign wall limits. The remaining
29 minutes of `run fuzz` are not broken down in any report, though reading
[`../../templates/pipeline.mk`](../../templates/pipeline.mk),
[`../../scripts/pipeline_make.py`](../../scripts/pipeline_make.py), and
[`../../scripts/run_eacsl_fuzz.py`](../../scripts/run_eacsl_fuzz.py) explains how they arose:

- **Memory, not CPU, was the scarce resource in the broker's accounts.** The broker showed 21,155
  to 25,011 of 25,088 MiB in use while fuzz and build leases waited, with 8 to 12 of 15 CPUs in use.
- **A fuzz lease reserves far more memory than fuzzing uses.** The formula is 512 MiB plus
  2,560 MiB per CPU. The seven fuzz leases got 1 to 7 CPUs and 3,072 to 18,432 MiB
  (`state/resource-history/fuzz/`). libFuzzer's own reports show 56 to 61 MiB of resident memory per
  job, and the broker recorded a largest process of 81 to 125 MiB for five of the campaigns.
- **Every campaign ran 9 workers, whatever its lease.** A campaign with a 1-CPU lease ran the same
  9 workers as one with 7. The cause is a known open bug: inside the run's container, `job_budget`
  ignores the sub-lease and sizes from the whole container (15 CPUs, 25,088 MiB, hence 9 workers)
  because `FRAMAC_CGROUP_ENFORCED=1` is inherited by in-container sub-leases (`FRAMAC_SUBLEASE_ID`).
  See "`pipeline_make.py run fuzz` (Single-Module Target) Uses Only ~20–30% of Host CPU" in
  [`../troubleshooting/resources-and-infra.md`](../troubleshooting/resources-and-infra.md). So the
  broker's CPU figures above understate what ran, and the wall times of section 1.2 come from a
  worker count no lease granted.
- **`run fuzz` built every module again, twice, and three of those builds ran in full without a
  cache key.** Corrected on 2026-11-16 from the records in `state/resource-history/` and the build
  and fuzz reports; the first revision named an engine switch, link repair and container-wide
  `memory.peak`, and none of the three is in the records.
  - **Two places build during `run fuzz`.** In
    [`../../templates/pipeline.mk`](../../templates/pipeline.mk), `build-%` is `.PHONY` and
    `fuzz-%: selftest build-%`, and `STAGE_OF_TARGET` in `pipeline_make.py` puts `build` and `fuzz`
    in the same Make stage. Inside `fuzz-%`, `run_eacsl_fuzz.py campaign` calls
    `build_module_binary` once more. Both are meant to be cache restores.
  - **The builds existed.** All seven modules had full E-ACSL builds (largest process 4.2 to
    4.3 GiB) before `run fuzz` started. `run build` (348 s) had just run seven leases of 155 to
    188 s with a largest process of 81 MiB, which is a restore, not a build.
  - **Six of the seven `build-%` steps were restores, at 154 to 200 s each.**
    `libcares_a__channel` was built in full instead: 882 s, 4,327 MiB.
  - **Two campaigns built in full inside their `fuzz` lease.** `libcares_a__channel` took 986 s
    for 1.8 s of fuzzing, and `ahost` 1,046 s for a 30 s campaign. Both records have the source
    `rusage`, so the 4,333 and 4,208 MiB are a process of the lease itself, a Frama-C run.
  - **All three full builds report `"cache": {"hit": false, "key": null}`**, and neither report
    has a `link_repair` field. `cache.memoize` in [`../../scripts/cache.py`](../../scripts/cache.py)
    gives a build no key when the dependency scan (`gcc -M -MG`, then `clang -M -MG`, over all 95
    to 97 sources) fails or passes `DEPS_TIMEOUT_S = 120`.
  - **The scan is at its limit on c-ares.** Measured on 2026-11-16 in a separate container with
    2 CPUs while the live run was busy on the same host: the `gcc` scan took 242 s, the `clang`
    scan 41 s, and `cache.dependency_manifest` returned `None` after 120.0 s. What makes the
    scan's time vary was not measured: it stayed under 120 s on the restores, and the second full
    build of `libcares_a__channel` started when only one other lease was running.
  - **Not confirmed for run-1 itself.** The scan was timed afterwards, and no report records why a
    key is missing. See "A Module's E-ACSL Build Runs in Full Again Although Nothing Changed" in
    [`../troubleshooting/resources-and-infra.md`](../troubleshooting/resources-and-infra.md).
  - **One module makes the whole 2,026 s.** `libcares_a__channel` waited 156 s for its build
    lease, built for 882 s, and then held its `fuzz` lease for 986 s.

Any larger budget has to be read against this: on run-1 the time that fuzzing did not get went to
two uncached builds of one module and to lease queueing, not to Eva. `P7f` removes the builds inside
`fuzz` leases and `P7g` the lost cache key. `P5d` records
the breakdown per module so future runs do not require log inspection.

## 2. Proposals

The labels P1 to P5 are kept from the first version, because other documents cite them (`P4` is
retained as a heading and rejected). P6 to P10 were added in the revision and refined during the
design review.

The implementation order puts infrastructure and accounting fixes **before** `P5` calibration, so
that speeds and memory peaks are not measured under ignored sub-leases or phony `build-%` stalls:

1. **Step 0 — Infrastructure & accounting prerequisites (`P7e`, `P7f`, `P7g`, `P1c`, `P10c`,
   `P2b`).** Honor `FRAMAC_SUBLEASE_ID` in `job_budget`/`enforced_memory_mb`; separate `build` from
   `fuzz` so no compilation runs inside a `fuzz` lease (aligned with `D8` of
   [`./phase1-remediation-plan.md`](./phase1-remediation-plan.md)); keep a build's cache key when
   the dependency scan is slow, and report a missing key; charge only libFuzzer execution
   time to the round budget; clamp `RLIMIT_CORE` to `min(1, hard)` in `sandbox_exec.py`; warn on
   `--fuzz-engine eacsl`.
2. **Step 1 — Telemetry (`P5a`, `P5b`, `P5d`).** Multi-job coverage/RSS/exec-s series, per-engine
   and judge replay speed, and Phase 1 wall-time breakdown.
3. **Step 2 — Explore/Judge split, per-case blinding, and batch offline symbolization (`P2`,
   `P1a`/`P1b`/`P1d`, `P10a`/`P10b`).** Resolves `D4` and integrates with `D1b` and `F7` of
   [`./phase1-remediation-plan.md`](./phase1-remediation-plan.md).
4. **Step 3 — Per-case floor pass and peak-based memory sizing (`P6`, `P7a`–`P7d`).** `P6a` isolates
   cases via `FRAMAC_FUZZ_ONLY_CASE` and yields per-worker ASan RSS peaks to size `P7` safely with a
   `2,048 MiB` container spike cushion and in-script cgroup `oom_kill` detection.
5. **Step 4 — Calibrated budgets (`P5c` -> `P3`), multi-argument `main` harnesses (`P8`), and
   region-accurate Eva `Unknown` join (`P9`).**

### P1. A false positive must not end the campaign

A larger budget is wasted if the first crash ends the campaign. That crash may be a false positive,
or the same bug found again.

- `dispatch_rounds` harnesses are meant to go on after a crash: they skip the crashing case at run
  time and start the next round. On run-1 this did not work for either rounds campaign that crashed.
  `channel` had one case, so skipping it left nothing (`skippable_cases: 1, skipped_cases: [0]`).
  `parsers` never reached its second round (P1c).
- Fork-mode harnesses (`adig`, `ahost`, the `tf_` targets) run `-fork=<n> -ignore_crashes=1`. Where
  only some inputs crash this works: `tf_ares-test-fuzz` fuzzed normally. Where every input crashes,
  as with the `ares_buf` false positive, libFuzzer goes on running and the corpus stays empty.

Settled design:

- **P1a. Detect blinding per case on `dispatch` harnesses, and per module on single-entry harnesses.**
  Replaying seeds and imported inputs alone is not enough: `adig`, `ahost` and `channel` had
  neither, and they are three of the five campaigns that learned nothing. Conversely, a module-wide
  early stop on a multi-case `dispatch` harness would allow one broken case (such as case 6 of
  `parsers`) to abort the remaining healthy cases. Therefore:
  - **On a `dispatch` harness:** blinding is tracked **per case** (in `P6a`'s floor pass for
    `explore`, in `P2d` for `judge`, and in `P2e`'s `deep` E-ACSL pass). A case whose first
    `K_case = 16` attempts/inputs crash with `0` passing executions on the same fingerprint ends as
    `blinded: <fingerprint>` and is added to `FRAMAC_FUZZ_SKIP_CASES` so healthy cases continue.
    The module itself is `blinded` only when every case is `blinded` or pre-dispatch harness code
    fails; when some cases pass and others blind, the module status is `partial_blinded`.
  - **On a non-dispatch or 1-case harness:** in fork-mode `explore`, stop early as
    `blinded: <fingerprint>` once `64` crashing jobs (starting value) have completed with `corp == 0`
    and `0` non-crashing executions (checked from status lines, never in wall seconds); when seeds
    exist, replay up to `K = 16` seeds first as an earlier check. Keep the remaining budget recorded
    as unspent for rerun after repair, and surface `blinded` / `partial_blinded` explicitly in the
    Phase 1 summary, not merely as `crash_found`.
- **P1b.** For a harness with one case, for fork mode, or for blinded dispatch cases, record the
  fingerprint that blinds it. Point the user or model at the existing remedies: the E-ACSL quick
  reference, `fuzz_engine` `sanitizers` for that module, or a fix to the harness or stub. Do not
  report a 2 s blinded campaign as a finished one.
- **P1c. Charge only libFuzzer execution time to the fuzz budget.** `run_campaign_rounds` in
  [`../../scripts/run_eacsl_fuzz.py`](../../scripts/run_eacsl_fuzz.py) currently times the whole
  `campaign(...)` call, including post-exit crash replay and lazy construction of the ASan+UBSan
  attribution binary. On `parsers` this came to 182 s against a 60 s budget, so the loop stopped
  before it skipped the crashed case. Measure `spent` strictly around the libFuzzer subprocess
  execution, and pre-build binaries in `build-%` (`P7f`). Recorded in
  [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md) ("A Keep-Going
  Campaign Stops After Its First Round").
- **P1d. Carry the attribution result into triage.** For both false-positive families the report
  already says `attribution.reproduced: false`: the sanitizer build does not crash on the input. That
  does not prove a false positive, since E-ACSL checks things the sanitizers do not. It is still the
  cheapest sign that a crash is specific to E-ACSL, and the Phase 1 summary and candidate triage
  fields should show it.

### P2. Explore with the sanitizer engine, judge with E-ACSL

Settled on 2026-11-16; resolves `D4` and integrates with `D1b`, `D8`, and `F7` of
[`./phase1-remediation-plan.md`](./phase1-remediation-plan.md). Under `fuzz_engine = auto` with both
builds available, the two engines get distinct Make stages and resource classes instead of splitting
one campaign 50/50:

- **Today's E-ACSL replay stops at the first failing input.** The E-ACSL half replays the corpus by
  letting libFuzzer read it at start-up, once per job. On run-1's `parsers` it crashed after 22
  executions with 704 inputs supplied, so the others were never judged.
- **Most confirmed bugs are within the sanitizers' reach; none is known to require E-ACSL fuzzing.**
  See [`../bugs-found/README.md`](../bugs-found/README.md) and `D4` in
  [`./phase1-review.md`](./phase1-review.md):
  - The minmea bugs came from UBSan. The QCBOR shift bugs and the CryptoLib bug are reported by
    both engines.
  - On libmnl, session notes of 2026-11-07 have ASan+UBSan alone finding LIBMNL-01, -03, -04 and
    -05, and E-ACSL alone finding -04 and -05. The confirmed witnesses of LIBMNL-02, -03 and -04 in
    [`../bugs-found/libmnl/README.md`](../bugs-found/libmnl/README.md) are E-ACSL ones.
  - LIBMNL-02 and QCBOR-01 are recorded with an E-ACSL witness only; LIBMNL-02 is a heap write of up
    to 3 bytes past a buffer, a kind ASan normally detects.
- **E-ACSL is the engine that was blinded on run-1.** Both false-positive families are its own.

Make stage topology and steps (each stage runs under its matching broker class):

1. **`build` (`--class build`, aligned with `D8`):** Pre-builds both `fuzz_<mod>.san` and
   `fuzz_<mod>.e-acsl` when `fuzz_engine = auto` (or the single requested engine), recording binary
   paths in `workspace/build/<mod>.build.json`. Neither `fuzz` nor `judge` compiles code (`P7f`).
2. **P2a. `fuzz` — Explore with ASan+UBSan (`--class fuzz`).** Under `quick` and `standard`, the
   sanitizer explorer gets **100%** of the module's fuzz budget (`4/5` under `deep`, where `P2e` is
   enabled) and grows `workspace/corpus/<mod>/`. It keeps going past crashes (`P1`, `P6`).
3. **P2d. `judge` — Judge with E-ACSL (`--class replay`, parallel with `coverage`).** Standalone
   Make target `judge-%` (no phony dependency on `fuzz-%`, just as `coverage-%` has none) writing
   `workspace/reports/judge/<mod>.json`:
   - **Case-stratified input selection up to cap `N`.** Every seed, imported input, and explorer
     crash input is judged, plus up to `N` grown-corpus files (`N = 512` `quick`, `2,048`
     `standard`, `4,096` `deep`, starting values) chosen by deterministic **per-case stratified**
     SHA-256 sampling (extending `select_replay_inputs` so one parser case holding 64% of the corpus
     cannot starve low-volume cases). Wall time is only a safety stop. Inputs left unrun are
     reported as `not_judged`.
   - **`O(N)` continuation past batch failures.** Inputs run in batches on `fuzz_<mod>.e-acsl`
     using `Running: <input>` / `Executed <input>` tracking (`_input_running_at_exit` in
     [`../../scripts/run_eacsl_fuzz.py`](../../scripts/run_eacsl_fuzz.py)), but unlike
     `replay_for_coverage` (which must re-run `batch[:culprit]` because an abort loses `.profraw`),
     the judge advances strictly with **`batch[culprit + 1 :]`**, avoiding `O(M * B)` quadratic
     re-execution when `M` inputs in a batch fail.
   - **Fresh-process witness confirmation across all harnesses.** Batched `LLVMFuzzerTestOneInput`
     calls share C static state and accumulate leaked blocks in E-ACSL's shadow heap. Whenever a
     batch failure yields a fingerprint not yet confirmed standalone, the judge replays that one
     witness alone in a fresh process (`replay_artifact`). If it does not reproduce alone, it is
     recorded under `batch_state_only` rather than promoted as a standalone candidate witness, so
     `replay-candidates` and `cvise` minimization always receive self-contained witnesses.
   - **Per-case blinding (`K_case = 16`).** Inputs are interleaved across dispatch cases. When one
     case hits `K_case = 16` consecutive failures with `0` passes on a single fingerprint, only
     *that case* is marked `blinded: <fingerprint>` and skipped (`FRAMAC_FUZZ_SKIP_CASES`) while
     the remaining cases continue to be judged. A non-dispatch or 1-case module stops after `K = 16`
     consecutive identical failures.
   - **Not charged to the fuzz budget** (`P1c`), and **rerunnable alone**: after fixing an E-ACSL
     false positive, `pipeline_make.py run judge ingest` re-judges the existing corpus without
     re-fuzzing (`1` CPU `--class replay` per module instead of holding multi-CPU `fuzz` leases).
   - **Cross-engine candidate linking (`D1b`).** Replaying explorer crash artifacts through the
     E-ACSL judge links observations when one input triggers both engines (even at adjacent lines, as
     in LIBMNL-04), complementing `D1`'s normalized `site` grouping.
4. **P2e. `eacsl-fuzz` — Opt-in 1/5 E-ACSL fuzzing share under `deep` only (`--class fuzz`).**
   Disabled under `quick` and `standard` (where 100% of fuzz CPU goes to `P2a`). Under `deep`,
   `eacsl-fuzz-%` runs after `judge-%` on the judged corpus using the remaining `1/5` of the module
   budget:
   - **Why `deep` only:** An intra-struct sub-object overflow needing a specific length that adds no
     branch coverage in ASan is the sole theoretical gap of `explore + judge`, and `deep` (`43,200`
     CPU-s base cap) is the only profile where a `1/5` share (`8,640` CPU-s) is large enough for
     E-ACSL's slower execution rate to explore meaningfully.
   - **Cases that crashed or blinded in `judge` start skipped** (`FRAMAC_FUZZ_SKIP_CASES`), and if
     the whole module was `blinded` in `judge`, `eacsl-fuzz-%` is skipped and its share is reported
     as `unspent_blinded`.
   - **Every finding records its discovering step:** `explore`, `judge`, or `eacsl_fuzz`. Drop
     `eacsl-fuzz` from `deep` as well if multi-target runs show zero unique bugs beyond `judge`.

Supporting rules:

- **P2b.** `params set --fuzz-engine eacsl` warns that the sanitizer explorer is lost and names
  `auto` as the way to override a wrong DAG `sanitizers` choice while keeping both engines; update
  the DAG reason text and skills accordingly without changing the meaning of recorded `eacsl` values
  in existing `params.json` files.
- **P2c. Step-accurate reporting and ledger supersession (`F7`).** The module's Phase 1 summary
  reports `explore` (executions, coverage, status), `judge` (judged, failed, `not_judged`,
  `blinded` / `partial_blinded` cases), and (under `deep`) `eacsl_fuzz`. `ledger.py` ingests both
  `reports/fuzz/<mod>.json` and `reports/judge/<mod>.json`, **superseding** prior Phase 1 status
  evidence of that module on rerun (instead of leaving contradictory append-only rows when `judge-%`
  reruns after a fix). `fuzz_clean` names E-ACSL only for functions dynamically executed (`coverage-%`
  executions > 0, per `F7`) whose reaching cases were judged without blinding or `not_judged` gaps.
- **P2f. Known false positives are reported, never suppressed at runtime.** Decided on 2026-11-16.
  Replacing E-ACSL's assertion handler (`--external-assert`) to ignore a rejected
  `toolchain_artifact` site would also silence genuine violations of the same check. Instead, a
  blinded case or module stays `blinded` (without E-ACSL `fuzz_clean` credit) until fixed in the
  pipeline or upstream, after which `judge-%` alone is rerun.

Fallback cases stay as today: when the sanitizer build fails, E-ACSL fuzzes alone
(`dual_engine_skipped`); when E-ACSL cannot build the module (`sanitizers`), only `explore` runs and
the report states no judge ran. Corpus reduction with libFuzzer `-merge` before judging remains
excluded because it drops value-distinct inputs sharing edge coverage.

### P3. Raise the budgets, with sublinear scaling for large units

Budgets stay fixed profile constants rather than "until coverage stops growing", so result-deciding
limits do not drift with machine speed. Starting values (to calibrate with `P5`):

| Profile | Per case (CPU-s) | Base unit cap up to 12 cases (CPU-s) | Scaled unit cap above 12 cases | Today |
| :--- | ---: | ---: | :--- | :--- |
| quick | 60 | 480 | `min(1440, round(480 * sqrt(cases / 12)))` | 60 / 480 |
| standard | 600 | 7,200 | `min(21600, round(7200 * sqrt(cases / 12)))` | 120 / 1,200 |
| deep | 3,600 | 43,200 | `min(129600, round(43200 * sqrt(cases / 12)))` | 900 / 7,200 |

What these rules do in practice:

- **Large dispatch units are neither unbounded nor starved.** A flat `7,200` CPU-s cap under
  `standard` would compress c-ares's 40-case `libcares_a` unit to `180` CPU-s/case and QCBOR's
  182-case `libqcbor_a` unit to `39` CPU-s/case (barely enough for a floor pass). With
  `min(3 * base_cap, round(base_cap * sqrt(max(1, cases / 12))))`, 40 cases receive `~13,145` CPU-s
  (`~328` CPU-s/case, ~15 min wall on 15 workers) and 182 cases hit the `21,600` CPU-s ceiling
  (`~118` CPU-s/case, ~24 min wall on 15 workers).
- **Budget scope:** Covers `explore` (`100%` in `quick`/`standard`; `4/5` in `deep`) and `eacsl-fuzz`
  (`1/5` in `deep`). `judge` (`P2d`) is bounded by input count `N` under `--class replay` and is not
  charged to the fuzz CPU budget.
- **Worker count never inflates CPU spent.** `MIN_FUZZ_BUDGET_S = 30` and `MIN_FUZZ_WALL_S = 30`
  stay, but for the shared pass (`P6b`) and non-dispatch campaigns, effective workers are clamped to
  `max(1, min(lease_workers, pass_budget_cpu_s // MIN_FUZZ_WALL_S))`, so a 30 CPU-s pass runs 1
  worker for 30 s rather than 9 workers for 30 s. (In `P6a`'s `-runs`-bounded floor pass, up to
  `min(lease_workers, n_cases)` single-worker case processes run concurrently.)
- **Explicit `fuzz_budget` in `params.json` overrides profile calculation** for that module, keeping
  pinned benchmark budgets unchanged.

### P4. Running Phase 1 fuzzing alongside Phase 2 Eva (Rejected)

Label kept because earlier notes cite `P4`. **Decided on 2026-11-16: do not overlap Phase 1 fuzzing
and Phase 2 Eva.**

The code and the skills do not enforce this today (read on 2026-11-16), so the decision needs a
change, not only restraint:

- **`STAGE_OF_TARGET` puts `fuzz` and `eva` in the same stage (4).** `pipeline_make.py run fuzz eva`
  runs both in one `make` invocation, in parallel.
- **Two skills offer the overlap.** `skills/framac-verify/SKILL.md` (step 3) and
  `skills/framac-fuzz/SKILL.md` (step 3) allow `run fuzz` and `run eva` concurrently when the host
  harness supports background calls.
- **What enforcing it takes:** a later stage for `eva` than for `fuzz` (and for `coverage` and
  `reach-dynamic`, whose gate is meant to stop Eva), and the two skill sentences removed. Not
  decided; listed in section 6.

Why it is rejected:

- **No idle CPUs remain once `P7` lands.** Run-1 had idle CPUs during `run fuzz` only because
  worst-case `2,560 MiB/worker` reservations starved the container for memory. Sizing workers from
  measured RSS (`P7`) lets `fuzz` use all 15 container CPUs (`~8–10 GiB` total), leaving no spare
  CPU capacity for Eva.
- **Shared-cgroup OOM collateral risk.** In-container sub-leases (`resources.py run`) share one
  container `memory.max` cgroup without per-lease child cgroups. If a fuzz worker spikes toward
  `-rss_limit_mb=2048` alongside 3.5 GiB `frama-c -eva` processes, the Linux kernel OOM-killer
  scores the whole container and shoots the highest-RSS `frama-c -eva` process after hours of work.
- **Phase 1 validates harnesses cheaply first.** Fuzzing catches harness/stub defects in minutes
  before Eva spends up to 2.5 hours per module on a stale `harness_digest`.

### P5. Measure, so starting constants can be calibrated

- **P5a.** Add a coverage-and-memory time series to the fuzz report (`cov`, `ft`, `corp`, `exec_s`,
  and `rss_mb` sampled from libFuzzer status lines, plus `stat::peak_rss_mb` and total executions
  aggregated across **all** jobs/workers, per pass and per round). Today `log_tail` keeps only the
  last lines of one job, reporting one ninth of a 9-job campaign's work. Compare cross-engine reach
  using `coverage-%`'s target-source function/region counts rather than instrumented edge counts.
- **P5b.** Record executions per second per engine (`explore`, `eacsl-fuzz`) and batched `judge`
  replay speed (`inputs/s`), calibrating `P2d`'s cap `N`, `P6a`'s `-runs` counts, and `P8c`'s slow
  CLI threshold.
- **P5c.** Extend `benchmark.py` / `benchmark_compare.py` to compare Phase 1 runs across two explicit
  budgets on benchmark targets: time to coverage plateau, bugs found, candidate volume reaching
  Phase 3 verifiers, and `P9` `executed_checked` coverage of Eva `Unknown`s.
- **P5d.** Record Phase 1 wall-time breakdown per module (`build`, broker queue wait, `explore`
  floor pass, `explore` shared pass, `judge` batch replay, fresh-process confirmations, `coverage`).

### P6. Give every case a floor, then let libFuzzer share the rest

Settled on 2026-11-16. Applies to the `ASan+UBSan` explorer (`P2a`) on multi-case `dispatch`
harnesses.

Run-1's `dnsrec` corpus (1,909 files across 19 cases) showed case 11 (`ares_dns_parse`) taking 1,215
files (64%) while cases 10 and 12 got 6 and 8 files, with no per-case execution telemetry, no minimum
effort guarantee, and a crash in one case interrupting all others. Equal fixed shares without a
shared pass would starve complex parsers; two passes give both a guaranteed floor and adaptive
allocation:

- **P6a. Per-case floor pass (`FRAMAC_FUZZ_ONLY_CASE`).** Each dispatch case `k` runs in its own
  single-worker libFuzzer process, up to `min(lease_workers, n_cases)` processes in parallel:
  - **Pin the selector instead of rejecting `255/256` first bytes.** Today's dispatch harnesses use
    `DISPATCH_SELECTOR_IDENTITY` (`uint8_t harness_selector = fuzz_buf[0]`,
    [`../../scripts/generate_harness.py`](../../scripts/generate_harness.py)), returning `-1`
    (`FRAMAC_FUZZ_REJECT()`) for skipped cases and `>= n_cases`. Skipping `N - 1` cases via
    `FRAMAC_FUZZ_SKIP_CASES` rejects `255/256` (99.6%) of startup inputs on an unseeded case (and
    20–50% of byte-0 mutations even after a seed enters the corpus; a toy test on `clang 19.1.7`
    rejected 104,131 of 200,000 attempts). Instead, `templates/harness_dual.c.template` adds
    `FRAMAC_FUZZ_ONLY_CASE=<k>`: when set, the harness still requires `fuzz_len > 0` and advances
    `fuzz_buf += 1; fuzz_len -= 1;` (preserving exact byte offsets), but pins
    `harness_selector = (uint8_t)k` regardless of `fuzz_buf[0]`. Selector rejection drops to `0%`,
    so `reached_executions < attempts` reflects only the case's own length/precondition guards.
    Legacy harnesses without the `FRAMAC_FUZZ_ONLY_CASE` marker fall back to
    `FRAMAC_FUZZ_SKIP_CASES` plus a synthetic `bytes([k])` bootstrap seed.
  - **Per-case seed partitioning and isolated corpus merge.** `seeds` and `imported_corpus` are
    partitioned by `dispatch_case_of(first_byte) == k` so each case reads only its own seeds. Each
    case writes to an isolated scratch corpus directory; before `P6b`, files from case `k`'s floor
    corpus are merged into `workspace/corpus/<mod>/` with byte 0 normalized to `bytes([k]) + buf[1:]`.
  - **Execution-count bound (`-runs`) with derived `-seed`.** Starting values per case (to calibrate
    with `P5b`): `5,000` attempts (`quick`, `15` CPU-s safety stop), `25,000` (`standard`, `120`
    CPU-s stop), and `100,000` (`deep`, `600` CPU-s stop). Note on libFuzzer mechanics verified in
    `framac-analysis:latest`: `-runs=<count>` is exact in single-process mode (`-fork` overshoots
    because it checks between jobs only, so `-fork` is never used in `P6a`). Under ASan, allocator
    layout, container environment (`resolv.conf`), and timeouts can still vary across machines, so
    `-runs` + `-seed` guarantees a **hardware-independent effort floor and local rerun stability**,
    not cross-machine bit-identical corpora.
  - **Crash restarts and per-case outcomes.** On a crash, the case process restarts with its
    remaining `-runs` budget up to `max_restarts = 4` times. Each case records `attempts`,
    `reached_executions`, `edges`, `corpus_files`, `peak_rss_mb`, and end state: `ok`, `crashing`
    (with fingerprints), `blinded` (`K_case = 16` crashes with `0` passes), or `floor_not_reached`
    (hit the CPU safety stop, exhausted crash restarts, or `reached_executions < 0.1 * attempts` due
    to case-internal length/precondition guards).
- **P6b. Shared pass.** All remaining explorer CPU-seconds run one multi-worker shared campaign over
  the merged floor corpus so libFuzzer concentrates mutations where new coverage grows. Cases that
  ended `crashing` or `blinded` in `P6a` start skipped (`FRAMAC_FUZZ_SKIP_CASES`), and new crashes
  in `P6b` use `dispatch_rounds` (with `P1c` fixed).

Non-dispatch harnesses (`argv`, embedded `tf_` targets) skip `P6` and run directly; for a 1-case
`dispatch` harness, `P6a` (with remaining budget in CPU-seconds if needed) is the whole explorer.

### P7. Reserve fuzz memory from measured per-worker peaks, with container spike protection

Settled on 2026-11-16; redesigned after checking [`../../scripts/resources.py`](../../scripts/resources.py).

Why naive OOM-rely fails in today's broker:

1. `resources.py run` (`cmd_run`) creates no child cgroup per Make recipe; `memory.max` sits on the
   outer container (`25,088 MiB`).
2. `_oom_killed()` checks `rc in (-9, 137)` on the outer `run_eacsl_fuzz.py` Python process, which
   catches child libFuzzer `SIGKILL`s and exits `0` via `--output`; moreover `CLASSES["fuzz"]` has
   `idempotent=False` and `cmd_run` retries at most once (`attempt == 1`). Thus the broker today
   **never** detects an OOM-killed fuzz worker.
3. In `-fork` mode, libFuzzer's parent records a `SIGKILL`ed child as a `crash-*` file unless
   filtered. (Not verified in `framac-analysis:latest`; `P7d`'s filter is harmless if it is wrong.)
4. `RUSAGE_CHILDREN` (`maxrss`) measures one child's max RSS, whereas `history_estimate` treats
   `peak_mb` as a whole-job floor; and ASan's default `256 MiB` quarantine per worker makes ASan
   workers larger than run-1's 56–125 MiB E-ACSL processes.

Settled design:

- **P7e. Fix the sub-lease bug first.** In `job_budget()` and `enforced_memory_mb()`
  ([`../../scripts/resources.py`](../../scripts/resources.py)), always honor `FRAMAC_JOB_CPUS` and
  `FRAMAC_JOB_MEM_MB` (`min(grant, cgroup)`) when `FRAMAC_SUBLEASE_ID` is set.
- **P7f. Keep all builds out of `--class fuzz`.** Remove the phony `build-%` prerequisite from
  `fuzz-%` in `templates/pipeline.mk`, stage `build` strictly before `fuzz` in `STAGE_OF_TARGET`,
  and have `fuzz-%` and `judge-%` consume the binaries recorded in `workspace/build/<mod>.build.json`
  (reusing repaired `link_repair` source lists without re-running failed link attempts).
- **P7g. A slow dependency scan must not cost a full build.** Added on 2026-11-16 from the
  reassessment of section 1.4; not yet discussed, and nothing below was tried. `P7f` removes the
  two rebuilds inside `fuzz` leases, but `build-%` itself still builds in full when
  `cache.dependency_manifest` returns `None`. What it needs:
  - **Say why a key is missing.** The `cache` field records `timeout`, `tool_failed` or
    `no_sources`, and the build warns. Today a missing key looks like an ordinary cache miss.
  - **Make the scan's time independent of the module's size**, or size its timeout from the number
    of sources. A full E-ACSL build of a c-ares module costs about 15 minutes and 4.3 GiB; the
    scan it replaces took 242 s at worst.
  - **Measure the scan first.** A cache hit cost 154 to 200 s on run-1, most of it presumably the
    scan; where that time goes (the two tools, hashing, the bind mount) was not measured.
- **P7a. Keep `-rss_limit_mb=2048` and default ASan quarantine unchanged** so OOM and UAF findings
  never change with hardware or reservation sizing.
- **P7b & P7c. Size per-worker leases from libFuzzer `peak_rss_mb` plus a `2,048 MiB` container
  spike cushion.** Record `peak_per_worker_mb` explicitly from `P6a`'s isolated per-case runs (and
  libFuzzer `stat::peak_rss_mb`). Reserve `max(512 MiB, ceil(1.5 * peak_per_worker_mb))` per worker
  (in place of `2,560 MiB/worker`), while keeping a **container-wide `2,048 MiB` unallocated spike
  cushion** whenever `fuzz` leases are active so a single worker growing all the way to
  `-rss_limit_mb=2048` never breaches container `memory.max`. On a `25,088 MiB`, 15-CPU container,
  15 ASan workers at `512 MiB` plus `512 MiB` base and `2,048 MiB` cushion fit in `10,240 MiB`,
  saturating all 15 CPUs safely. Unmeasured non-dispatch modules start their first brief probe or
  campaign at `2,560 MiB/worker` until a peak is recorded.
- **P7d. Detect cgroup `oom_kill` deltas inside `run_eacsl_fuzz.py`.** Snapshot `cgroup_stats()`
  `oom_kill` before and after every libFuzzer subprocess. If `oom_kill` increased: discard any
  `crash-*` artifact lacking a sanitizer/E-ACSL/libFuzzer-OOM report (`container_oom_artifact`, so a
  container kill is never a finding), record `status = "container_oom"`, and retry the case or pass
  with `2x` per-worker reservation up to `2,560 MiB/worker`.

### P8. Fuzz a program's `main` with multiple arguments and clean `getopt`/`exit` state

Settled on 2026-11-16.

Code inspection of [`../../scripts/generate_harness.py`](../../scripts/generate_harness.py)
(`entry_style == "argv"`, lines 1228-1254) exposed three runtime bugs alongside the single-argument
limitation:

1. `eva_main` sets `int argc = Frama_C_interval(0, 5)` (`argv[0]` plus **at most 4** user arguments
   `argv[1..4]`), and leaves `argv[argc]` non-NULL when `argc < 5` (only `argv[5] = 0`, violating
   C99 `argv[argc] == NULL`), whereas the fuzz side hardcodes `main(2, {"prog", argv1})`.
2. POSIX `getopt` / `getopt_long` globals (`optind`, initialized to `1`) are never reset between
   in-process calls: after execution #1 sets `optind = argc`, every subsequent call with
   `argc <= previous_optind` immediately returns `-1` without parsing a single option.
3. CLI `main` functions call `exit(1)` or `exit(0)` in `usage()` on invalid flags, which libFuzzer's
   `AtExit` handler treats as a target crash, and using `longjmp` inside an E-ACSL binary corrupts
   E-ACSL's stack-frame shadow memory (`__e_acsl_delete_block` cleanups skipped).

Settled design:

- **P8a. Align `eva_main` and fuzz NUL-splitting on `argc` in `1..5` (`0..4` user arguments).** Fix
  `eva_main` so `argc = Frama_C_interval(1, 5)` and `argv[argc] = NULL`. On the fuzz side, `size == 0`
  passes `argc = 1, argv = {"prog", NULL}`; non-empty inputs split on NUL bytes into `1..4` user
  arguments of at most 255 bytes each (`argv[argc] = NULL`), keeping existing NUL-free corpora valid
  as single-argument inputs.
- **Reset `getopt` state and wrap `exit()` safely per engine.** Before each `main()` call, set
  `optind = 0; opterr = 0;` (glibc's full internal `nextchar` + index reset). Link `argv` fuzz/judge
  binaries with `-Wl,--wrap=exit`:
  - **In ASan+UBSan (`explore`):** `__wrap_exit` calls `__asan_handle_no_return()` and
    `siglongjmp`s back to `LLVMFuzzerTestOneInput`, preserving fast in-process fuzzing across
    `usage()` exits.
  - **In E-ACSL (`judge`):** `__wrap_exit` flushes streams and calls `_Exit(0)` (never `longjmp`,
    avoiding E-ACSL stack-shadow corruption; real E-ACSL failures call `abort()`, not `exit()`). The
    batched judge treats `returncode == 0` on `Running: <input>` without an E-ACSL error as a clean
    `target_exit` pass and continues with `batch[idx + 1 :]`.
- **P8b. Harvest CLI seeds via `strace` `execve` and `getopt` dictionaries.** Extend
  `seed_harvest.py`'s existing `strace -f` test wrapper (line 902) from `-e trace=openat` to
  `-e trace=openat,execve,execveat -s 256` to capture real CLI invocations of target binaries as
  NUL-joined `argv` seeds, and extract option tokens from `getopt` / `getopt_long` descriptors into
  the module dictionary.
- **P8c. Auto-throttle network-waiting CLIs.** Do not stub sockets/stdin yet; if an `argv` explorer's
  initial probe window measures `< 5 exec/s` (e.g. `adig` waiting on DNS `select` timeouts past
  option parsing), cap its shared budget to `MIN_FUZZ_BUDGET_S` and label it `smoke_cli_only`.
- **P8d.** Generalized to all harnesses in `P2d` (fresh-process confirmation per distinct
  fingerprint).

### P9. Join Phase 1's results with Eva's Unknown alarms

Settled on 2026-11-16: build the deterministic report-only join first, with sub-region coverage
precision; decide on any aimed post-Eva fuzz pass or second judge build only after seeing the join's
numbers across targets.

Observations from the code and c-ares run-1 (`workspace/eva/adig/alarms.csv`: 283 Unknown rows of
13,661 on 139 lines in 72 functions; `fuzz_adig.instrumented.c`: 42,706 compiled assertions):

- **Eva and E-ACSL check only partially overlapping property sets.** Eva enables
  `-warn-invalid-pointer`, `-warn-unsigned-overflow`, `-warn-signed-downcast`, and
  `-warn-right-shift-negative` ([`../../scripts/run_eva_slice.py`](../../scripts/run_eva_slice.py));
  E-ACSL passes `-rte`, `-rte-initialized`, and optional `-warn-unsigned-downcast`, and does not
  execute `\dangling` ([`../references/e-acsl-quickref.md`](../references/e-acsl-quickref.md)).

| Alarm kind | Unknown rows (`adig`) | `rte/<kind>` assertions compiled into `fuzz_adig.instrumented.c` |
| :--- | ---: | :--- |
| `pointer_value` | 64 | None |
| `initialization` | 51 | 10,423 |
| `unsigned_overflow` | 31 | None |
| `precondition of <function>`, at call sites | 32 | Not counted; libc replacements cover a fixed list of functions |
| `precondition`, in the libc headers | 25 | Not at a target line |
| `mem_access` | 22 | 4,218 |
| `ptr_comparison` | 20 | None |
| `pointer_alignment` | 18 | 2,793 |
| `dangling_pointer` | 15 | None |
| Other kinds | 5 | Not looked at |

130 of the 283 rows (46%) are of kinds with no compiled E-ACSL assertion; 91 (32%) are of kinds the
build compiles (the remaining 24,911 records in `fuzz_adig.instrumented.c` are E-ACSL's internal
guard checks).

- **Frama-C's `alarms.csv` has `(file, line)` with no column number** (`read_report_csv` in
  [`../../scripts/framac_common.py`](../../scripts/framac_common.py)), and `_export_coverage` in
  `run_eacsl_fuzz.py` currently passes `-skip-expansions` to `llvm-cov export`. On a short-circuited
  line such as `if (len > 0 && buf[len - 1] == '\n')` or a multi-branch macro, executing the line
  with `len == 0` gives the outer region `count > 0` while the RHS sub-region holding the alarm has
  `count == 0` and its E-ACSL check never ran.

Settled design:

- **P9a. One deterministic Make target per module after Eva (`eva-join-%`).** No agent, no fuzz
  budget, and no change to ledger verdicts or the WP queue (`Unknown` stays `Unknown`).
- **P9b. Six states per Unknown alarm row:**
  - `failed`: a failure of `judge` or `explore` at the same file, line, and compatible kind
    (function + kind when unlocated), linking the existing candidate.
  - `executed_checked`: **every** `llvm-cov` code and macro-expansion region on `(file, line)` has
    `count > 0` on judge-passing inputs, the judge's build checks that row (`P9c`), and nothing
    failed. Evidence for briefs/reports, never a proof.
  - `partially_executed`: at least one region on `(file, line)` has `count > 0` and at least one
    code/expansion region on `(file, line)` has `count == 0` (short-circuit or untaken macro branch,
    so execution of the specific alarm operand is not established without column mapping).
  - `executed_unchecked`: all regions on `(file, line)` ran (`count > 0`), but the kind/site is not
    checked by the judge, or the reaching case was `blinded` / `not_judged`.
  - `not_executed`: every region on `(file, line)` has `count == 0`.
  - `not_joined` (with reason): missing/partial coverage export, row outside target sources (libc
    headers), or `no_alarm_table` when Eva timed out without an alarm CSV.
- **P9c. Compiled assertions decide `checked`.** For E-ACSL, checked when `.instrumented.c` holds an
  `rte/<kind>` assertion at `(file, line)` (automatically accounting for `-rte-select`, dropped
  functions, `va_list_init_checks_skipped`, and `reduced_checks`); for sanitizer-only modules, a
  conservative kind table decides. Anything not established as checked is `unchecked`.
- **P9d. Reuse `coverage-%` when complete; isolate filtered replays otherwise.** Drop
  `-skip-expansions` from `llvm-cov export` so macro-expansion regions are preserved. Whenever
  `judge` had `0` failed inputs and `0` `not_judged` inputs, reuse `workspace/coverage/<mod>/export.json`
  from `coverage-%` directly without a second replay; otherwise replay only judge-passing inputs
  into a separate `workspace/coverage-join/<mod>/` scratch directory so `coverage-%` is never
  overwritten, marking `executed_*` counts as lower bounds when `not_judged > 0`.
- **P9e. Shown in per-module join report and `REPORT.md` state counts** (available as context to
  prover/verifier briefs; ledger status unchanged).

#### Trial: Eva's `-warn-*` options in the E-ACSL build (Decided: keep off)

Tried on 2026-11-16 on `minmea` (minmea run-1: 64 seeds + 312 corpus inputs, 372 passing baseline,
146 Eva Unknown rows) and `libnettle_a__sha3` (nettle run-3: 99 generated inputs across 33 cases, 24
passing baseline in 8 cases), built via `build_module_binary` (cache off) and replayed one process
per input (`replay_inputs`):

`minmea`:

| Option added | Compiled assertions | Unknown rows that gain an assertion | Inputs that newly fail |
| :--- | ---: | ---: | :--- |
| None (baseline) | 864 | 109 of 146 have one | |
| `-warn-invalid-pointer` | 2,502 | 10 (`pointer_value`) | 371 of 372, all on one check at `minmea.c:114` |
| `-warn-unsigned-overflow` | 886 | 4 | None |
| `-warn-signed-downcast` | 896 | 15 | 11, all at `minmea.c:223` |
| `-warn-right-shift-negative` | 864 | 0 | None |
| All four | 2,564 | 29, so 138 of 146 | 371 of 372 |

`libnettle_a__sha3`:

| Option added | Compiled assertions | Inputs that newly fail |
| :--- | ---: | :--- |
| None (baseline) | 3,006 | |
| `-warn-unsigned-overflow` | 3,717 | 15 of 24, all in `nettle_sha3_permute` |
| `-warn-invalid-pointer` | 6,932 | 15 of 24, all on one check at `sha3-permute.c:169` |
| All four | 7,837 | 15 of 24 |

Findings from the trial:

- **`-warn-invalid-pointer` is unusable due to an upstream E-ACSL defect:** `\object_pointer`
  evaluates false on pointers to `.rodata` string literals (`minmea_scan`) and `static const` tables
  (`sha3-permute.c` `rc`), while writable globals/locals pass (see
  [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md); upstream
  draft `docs/upstream/frama-c/frama-c-eacsl-object-pointer-readonly-static.md` held on the
  supervision branch, [`../upstream/README.md`](../upstream/README.md)). Build time also more than
  doubled (15 s -> 39 s on `minmea`, 51 s -> 111 s on nettle).
- **`-warn-unsigned-overflow` blinds hash/crypto bit-rotations** (`C[2] << 1` in SHA-3).
- **`-warn-signed-downcast` halts inputs on implementation-defined narrowings** (`strtol` -> `int`
  at `minmea.c:223`), hiding checks later in the execution unless `--keep-going` were enabled on a
  separate judge-only E-ACSL build.

Decision preserved: keep the E-ACSL build flags unchanged and report those kinds as `unchecked` in
`P9`; revisit a `--keep-going` judge-only build only if `P9` shows a high count of
`executed_unchecked` rows for `unsigned_overflow` / `signed_downcast`.

### P10. Run with `symbolize=0` everywhere and batch-symbolize offline; clamp `RLIMIT_CORE`

Settled on 2026-11-16.

Measured on minmea's fuzz binaries (`framac-analysis:latest`, 2 CPUs, five runs each; see
[`../troubleshooting/resources-and-infra.md`](../troubleshooting/resources-and-infra.md)):

| Execution | E-ACSL build | Sanitizer build |
| :--- | ---: | ---: |
| An input that passes | 85 ms | 89 ms |
| An input that fails, as the pipeline runs it | 452 ms | 440 ms |
| The same with `symbolize=0` in `ASAN_OPTIONS` and `UBSAN_OPTIONS` | 94 ms | 88 ms |

- **`symbolize=0` removes about 350 ms per failure.** A standalone `llvm-symbolizer` call on the
  same binary takes 27 ms (see `P10a`), so the symbolizer's own start-up is not most of it; where
  the rest goes was not measured. Notably,
  `run_fuzz_campaign` in [`../../scripts/run_eacsl_fuzz.py`](../../scripts/run_eacsl_fuzz.py)
  currently runs `-fork` campaigns with `symbolize=1` even though it discards in-campaign stack
  traces and re-runs `replay_artifact` on saved crash files afterwards (about 700 CPU-seconds
  across 2,000 crashes on `adig`/`ahost`, if minmea's 350 ms per failure holds there; not measured
  on c-ares).
- **With `symbolize=0`, ASan, UBSan, and libFuzzer still emit deterministic module-relative frame
  offsets** (`(/path/to/binary+0x42ab0)`) at zero runtime cost.
- **Piped `core_pattern` (`RLIMIT_CORE`):** On WSL2 / piped `core_pattern` hosts, a standalone
  aborting binary took 852 ms with `RLIMIT_CORE = 0` and 14 ms with `RLIMIT_CORE = 1` (Linux skips
  piped core helpers only when `cprm.limit == 1`, while `1 < 4096` also writes no ELF core file
  under file `core_pattern`). However, `_make_preexec` in
  [`../../scripts/sandbox_exec.py`](../../scripts/sandbox_exec.py) calls
  `resource.setrlimit(RLIMIT_CORE, (value, value))` inside a `--cap-drop ALL` container: if the
  container runtime already set hard `RLIMIT_CORE == 0` (`--ulimit core=0:0`), setting `(1, 1)`
  raises `ValueError: not allowed to raise maximum limit` and breaks every sandboxed command.

Settled design:

- **P10a & P10b. Universal `symbolize=0` with single-pass offline `llvm-symbolizer` resolution.**
  Set `symbolize=0` in `ASAN_OPTIONS` and `UBSAN_OPTIONS` across **`explore` (`run_fuzz_campaign`),
  `judge`, and `replay_artifact`**. At the end of a `judge` or `replay` pass, collect all unique
  `(binary, +0xoffset)` pairs from failing outputs and resolve them in **one** `llvm-symbolizer`
  invocation (no binary reruns; measured on 2026-11-16 in `framac-analysis:latest`, five runs each:
  27 ms on minmea's 2 MB sanitizer binary for 1 or for 50 addresses; on c-ares's 17 MB
  `fuzz_adig.e-acsl`, 32 ms for 1 address and about 110 ms for 50, with 230 to 790 ms for the first
  call on a file not yet read), rewriting raw offset
  lines into standard `#N 0x... in fn file:line` frames before `parse_sanitizer_failure` and
  `stack_frames` run. For unlocated E-ACSL libc/format failures (`needs_attribution`), group
  failures by `(eacsl_message, raw_offset_stack)` first and run sanitizer attribution once per unique
  group rather than once per failing input.
- **P10c. Clamp `RLIMIT_CORE` to `min(1, hard)` in `sandbox_exec.py`.** Query
  `soft, hard = resource.getrlimit(RLIMIT_CORE)` in `_make_preexec` and set `(target, target)` with
  `target = 1 if hard != 0 else 0` (`RLIM_INFINITY` is `-1` in Python `resource`, so `hard != 0`
  handles both positive limits and `RLIM_INFINITY` safely). The unmerged branch
  `fix/sandbox-core-limit` (`21a1144`) sets the limit to 1 without this clamp; add it there before
  merging. The pipeline itself never passes `--ulimit core`, so the clamp matters on hosts whose
  runtime sets a hard limit of 0.

## 3. What not to do

- **Do not stop fuzzing when coverage plateaus.** That makes results depend on machine speed.
- **Do not raise budgets before landing Step 0, P1, and P2.** On run-1, five of seven campaigns
  would have spent the extra budget crashing on one false positive or waiting on phony builds.
- **Do not make fuzzing time depend on Eva's**, and **do not overlap Phase 1 fuzzing with Phase 2
  Eva (`P4`)** inside a shared container cgroup.
- **Do not suppress known E-ACSL false positives via `--external-assert` (`P2f`).** Site/predicate
  suppression hides real violations at the same check.
- **Do not add `-use_value_profile=1` or `-max_len` to campaigns for now** (decided 2026-11-16).
  Measured on `minmea` (coverage build, 64 seeds, 3,000,000 executions, three seeds each):

  | Configuration | Edges reached | Corpus files | Run time |
  | :--- | ---: | ---: | ---: |
  | Default | 270 to 271 | about 370 | 14 s |
  | `-max_len=128` (the harness limit) | 270 to 271 | about 370 | 14 s |
  | `-use_value_profile=1` | 271 | about 1,200 | 26 s |
  | Both | 271 | about 1,190 | 27 s |

  Value profiling nearly doubled corpus size and run time for zero new edges on saturated `minmea`;
  revisit on magic-number-heavy targets only after `P5a` provides coverage-over-time curves.

## 4. Limits of the evidence

- **One run, one engine.** Section 1's campaign numbers come from c-ares run-1, fuzzed with E-ACSL
  only under the sub-lease bug (`9` workers regardless of lease).
- **Section 1.4's cause was measured after the run.** The lease records and the missing cache keys
  are run-1's own; the 242 s dependency scan was timed on 2026-11-16 on a busy host, not during
  run-1.
- **The held c-ares fixes change c-ares specifically.** `CA-F2` (`setjmp`), `CA-F10` (`%u`), and
  `CA-F11` (tail-merged literals) remove both c-ares false-positive families and the wrong DAG
  choice; the architectural defects (`P1c`, lack of per-case blinding, single-job telemetry `P5a`,
  sub-lease bug `P7e`, build-in-fuzz-stage `P7f`, `getopt` state in `P8`) apply to every target.
- **Starting constants await `P5` calibration.** `P2d`'s input caps `N`, `P3`'s CPU budgets, `P6a`'s
  `-runs` floors, and `P7b`'s `512 MiB` ASan worker floor are conservative starting values until
  `P5a`/`P5b` measure sanitizer-to-E-ACSL speed ratios and ASan worker RSS across benchmark targets.
- **No join has been computed yet.** `P9`'s counts come from `adig`'s Eva CSV and `.instrumented.c`
  alone; multi-line CIL/LLVM line drift in real headers/macros remains to be measured once `eva-join`
  runs.
- **Candidate volume affects Phase 3 model cost.** Larger budgets must ship with `P1`/`P2`
  deduplication, `D1` `site` grouping, and fresh-process witness confirmation so crash verifiers are
  not flooded with duplicates or batch-state artifacts.

## 5. Remaining calibration questions (to settle from `P5` and `P9` measurements)

- **Calibrating `N` (`P2d`) and `-runs` (`P6a`):** Measured batched E-ACSL replay throughput
  (`inputs/s`) and ASan `explore` `exec/s` across `minmea`, `libmnl`, `QCBOR`, and `c-ares` (`P5b`).
- **Whether `deep`'s `1/5` `eacsl-fuzz` share (`P2e`) finds any defect `explore + judge` misses:**
  If zero unique findings appear across several `deep` target runs, drop `P2e` so `deep` also gives
  `100%` of fuzz CPU to `explore`.
- **Empirical ASan worker RSS peaks (`P7b`):** Confirm whether `512 MiB` per worker covers steady
  ASan quarantine + parser allocations on large targets without hitting `P7d`'s `oom_kill` retry.
- **Eva `Unknown` join alignment (`P9`):** Exact mapping table from sanitizer/libc checks to Eva
  alarm kinds, how often multi-line statements cause 1–3 line offsets between Frama-C CIL (`alarms.csv`),
  E-ACSL `.instrumented.c`, and `llvm-cov` regions, and whether `executed_unchecked` counts on
  `unsigned_overflow` / `signed_downcast` justify an optional `--keep-going` judge build later.

## 6. Open design points from the reassessment of 2026-11-16

The revision was checked against the scripts and run-1's records after it was written. Section 1.4,
`P7g`, the `P4` note and the figures in `P10` were corrected in place. The points below are not
decided. Each is reasoned from the code or from how libFuzzer is known to behave; none was tested.

- **`P6a`: a crash file from the floor pass does not name its case.** Only corpus files get byte 0
  rewritten to the pinned case before `P6b`. A `crash-*` file written under
  `FRAMAC_FUZZ_ONLY_CASE=<k>` keeps whatever byte 0 the mutation left, so the judge, `replay` and
  the crash verifier, which run without the variable, would dispatch it to another case and not
  reproduce it. Either rewrite byte 0 of floor-pass artifacts the same way, or record the case
  with the artifact and replay with the variable set. In an E-ACSL build the variable is only
  visible with the `environ_keep` shim, as for `FRAMAC_FUZZ_SKIP_CASES`.
- **`P8`: leaving `exit()` with `siglongjmp` may be reported as a leak.** Whatever `main`
  allocated before `usage()` stays allocated. libFuzzer checks for leaks by default, and the
  pipeline sets only `abort_on_error=1` in `ASAN_OPTIONS`. Decide between `-detect_leaks=0` for
  `argv` harnesses (real leaks are then not reported there) and classifying a leak found on an
  input that ended in `__wrap_exit` as an artifact of the wrap.
- **`P6a` with `P3`: the floor can use the whole cap.** With 182 cases under `standard`, the safety
  stops alone allow 182 x 120 = 21,840 CPU-s against a cap of 21,600. Say whether the floor pass
  is charged to the unit's budget, and if so, bound its total.
- **`P9d`: dropping `-skip-expansions` changes `coverage-%` too.** `summarize_coverage_export`
  reads the same export for the coverage report and the dynamic reach gate. Check what the extra
  expansion regions do to its function and line counts before changing the flag, or export twice.
- **`P4`: enforcing the rejection.** See the note under `P4`: a stage change in `STAGE_OF_TARGET`
  and two skill sentences.
- **`P7g`: not discussed yet.** Which of its three parts to do, and whether a cache hit that costs
  154 to 200 s on a 95-source module is acceptable once nothing is rebuilt.
- **Labels.** The supervision report has no `CA-F` label: it writes `F2`, `F10` and `F11` for the
  held c-ares fixes that this document calls `CA-F2`, `CA-F10` and `CA-F11`.
