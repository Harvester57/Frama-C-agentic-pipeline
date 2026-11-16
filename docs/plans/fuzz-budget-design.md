# Design: Larger Phase 1 Fuzz Budgets, Spent Where They Pay

Status: proposal, 2026-11-16. Nothing here is implemented. It comes from the supervision of c-ares
run-1 ([`../runs/2026-11-16-c-ares-run1-supervision.md`](../runs/2026-11-16-c-ares-run1-supervision.md))
and is meant for every target, not only c-ares. Revised the same day after a review against the code
and the run-1 fuzz reports (`workspace/reports/fuzz/*.json`); section 4 says what the evidence does
not cover. Six parts were agreed with the user that day and are marked as such: the engine roles
(P2, including the report-only rule P2f), the floor pass limited by executions (P6), memory from
measured peaks (P7), several arguments for program harnesses (P8), the join with Eva's Unknown
alarms (P9) and symbolization on demand (P10). The rest is still a proposal.

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
artifacts: 56 from tail-merged literals (held fix F11) and 26 from the `%u` format check (held fix
F10). Their effect on the seven campaigns:

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
`sanitizers` on some units, because of the setjmp false positive (held fix F2). The model then ran
`params set --fuzz-engine eacsl` for every module (`cmd-set-eacsl.sh`), which also disables the
dual-engine split. `params set --fuzz-engine auto` would have overridden the DAG's choice too, and
kept the split. The `framac-fuzz` skill says that `eacsl` fuzzes with one engine only, but no skill
names `auto` as the way to undo a DAG choice. So run-1 says nothing about what `auto` would have
found. It does show that a `params set` meant to undo a wrong DAG choice costs the faster engine,
with no warning.

### 1.4 Where Phase 1's wall time went

`run build` took 348 s and `run fuzz` 2,026 s, against 274 s of campaign wall limits. The remaining
29 minutes of `run fuzz` are not broken down in any report. The make log of that step shows seven
build steps next to the seven campaigns, and leases waiting in the queue. Two things are known:

- **Memory, not CPU, was the scarce resource in the broker's accounts.** The broker showed 21,155
  to 25,011 of 25,088 MiB in use while fuzz and build leases waited, with 8 to 12 of 15 CPUs in use.
- **A fuzz lease reserves far more memory than fuzzing uses.** The formula is 512 MiB plus
  2,560 MiB per CPU. The seven fuzz leases got 1 to 7 CPUs and 3,072 to 18,432 MiB
  (`state/resource-history/fuzz/`). libFuzzer's own reports show 56 to 61 MiB of resident memory per
  job, and the broker recorded a largest process of 81 to 125 MiB for five of the campaigns.
- **Every campaign ran 9 workers, whatever its lease.** A campaign with a 1-CPU lease ran the same
  9 workers as one with 7. The cause is a known open bug: inside the run's container, `job_budget`
  ignores the sub-lease and sizes from the whole container (15 CPUs, 25,088 MiB, hence 9 workers).
  See "`pipeline_make.py run fuzz` (Single-Module Target) Uses Only ~20-30% of Host CPU" in
  [`../troubleshooting/resources-and-infra.md`](../troubleshooting/resources-and-infra.md). So the
  broker's CPU figures above understate what ran, and the wall times of section 1.2 come from a
  worker count no lease granted.
- **The campaign step sometimes builds.** For `ahost` and `channel` the broker recorded a largest
  process of 4,208 and 4,333 MiB inside the fuzz lease. That is the size of an E-ACSL
  instrumentation (about 4.3 GiB on this target), not of fuzzing; which build ran there was not
  traced.

Any larger budget has to be read against this: on run-1 the time that fuzzing did not get went to
builds and waiting, not to Eva. P5d asks for the breakdown.

## 2. Proposals

The labels P1 to P5 are kept from the first version, because other documents cite them. P6 to P10
were added in the revision. The order of work is different:

1. **P5a, P5b and P5d first.** They are small, and P2 and P3 cannot be calibrated without them.
2. **P1**, including the accounting bug P1c. Without it a larger budget is spent on the first crash.
3. **P2 and P6**, before or with P3. They decide what the budget is spent on.
4. **P3.**
5. **P7**, after P6, whose floor pass gives the first memory measurement.
6. **P8**, after P2 and P5b. Its failures go through the judge, and P8c needs the speed
   measurement.
7. **P9**, after P2d. It needs the judge, a coverage step and a finished Eva run, and no budget.
   **P10a and P10b** come with the judge (P2d); **P10c** is a small fix that can go in at any
   time.
8. **P4** last, after P7, and only if `deep` runs need it.

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

Proposed:

- **P1a. Detect a blinded campaign from its own numbers.** Replaying the seeds and the imported
  corpus first is not enough: `adig`, `ahost` and `channel` had neither, and they are three of the
  five campaigns that learned nothing. The campaign's own status lines already show the state: in
  fork mode, a crash count equal to the job count with `corp: 0`; in rounds, a crash while the seed
  corpus is being read. Check after a fixed number of jobs or executions (to be set, and not in
  seconds). When seeds exist, replay them first as an earlier check. A blinded campaign stops as
  `blinded: <fingerprint>` and keeps its remaining budget for the rerun. It should show up in the
  Phase 1 summary, not just as `crash_found`. With the engine roles of P2, the judge step (P2d)
  gives this verdict for E-ACSL; P1a then covers the explorer and the E-ACSL fuzzing share.
- **P1b.** For a harness with one case, or for fork mode, record the fingerprint that blinds it.
  Point the user or model at the existing remedies: the E-ACSL quick reference, `fuzz_engine`
  `sanitizers` for that module, or a fix to the harness or stub. Do not report a 2 s campaign as a
  finished one.
- **P1c. Charge only fuzzing to the fuzz budget.** `run_campaign_rounds` times the whole campaign
  call. After libFuzzer exits, that call also replays the crash artifacts and builds the ASan+UBSan
  attribution binary. On `parsers` this came to 182 s against a 60 s budget, so the loop stopped
  before it skipped the crashed case. Count only libFuzzer's own run time, or build the attribution
  binary before the first round. This is an open pipeline bug, recorded in
  [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md) ("A Keep-Going
  Campaign Stops After Its First Round"). How the 182 s split between the three was not measured.
- **P1d. Carry the attribution result into triage.** For both false-positive families the report
  already says `attribution.reproduced: false`: the sanitizer build does not crash on the input. That
  does not prove a false positive, since E-ACSL checks things the sanitizers do not. It is still the
  cheapest sign that a crash is specific to E-ACSL, and the Phase 1 summary should show it.

### P2. Explore with the sanitizer engine, judge with E-ACSL

Direction agreed on 2026-11-16; not implemented. The two engines get different jobs instead of half
the time each: the ASan+UBSan build explores, the E-ACSL build judges every input once, and E-ACSL
fuzzing keeps a small share. Three observations lead there:

- **Today's E-ACSL replay stops at the first failing input.** The E-ACSL half replays the corpus by
  letting libFuzzer read it at start-up, once per job. On run-1's `parsers` it crashed after 22
  executions with 704 inputs supplied, so the others were never judged.
- **Most confirmed bugs are within the sanitizers' reach; for two the record does not say.** See
  [`../bugs-found/README.md`](../bugs-found/README.md).
  - The minmea bugs came from UBSan. The QCBOR shift bugs and the CryptoLib bug are reported by
    both engines.
  - On libmnl, session notes of 2026-11-07 (not in this repository) have ASan+UBSan alone finding
    LIBMNL-01, -03, -04 and -05, and E-ACSL alone finding -04 and -05. The confirmed witnesses of
    LIBMNL-02, -03 and -04 in [`../bugs-found/libmnl/README.md`](../bugs-found/libmnl/README.md)
    are E-ACSL ones.
  - LIBMNL-02 and QCBOR-01 are recorded with an E-ACSL witness only. Whether a sanitizer reports
    them was not checked. LIBMNL-02 is a heap write of up to 3 bytes past a buffer, a kind ASan
    normally detects.

  So no bug is known to need E-ACSL, and two are not known to be found without it.
- **E-ACSL is the engine that was blinded on run-1.** Both false-positive families are its own.

The steps, in the order a campaign runs them:

- **P2a. Explore with ASan+UBSan.** The explorer gets four fifths of the module's fuzz budget
  (starting value) and grows the corpus. It keeps going after a crash as in P1. ASan+UBSan binaries
  are expected to run much faster than E-ACSL ones; the factor is not measured (P5b).
- **P2d. Judge with E-ACSL.** The E-ACSL build replays each input exactly once: the seeds, the
  imported corpus, the grown corpus and the explorer's crash inputs.
  - **It continues past a failing input** and fingerprints each failure. The parts exist in
    [`../../scripts/run_eacsl_fuzz.py`](../../scripts/run_eacsl_fuzz.py): `replay_for_coverage` has
    the loop that survives failures (tied to coverage profiles and a 1,200 s deadline today), and
    `replay_inputs` replays one input with its fingerprint.
  - **Its limit is a count, not a time.** Every seed, imported input and crash input is judged, plus
    up to N corpus files chosen by the deterministic sample of `select_replay_inputs`. N is to be
    set; the Phase 3 guardrail's 64 is too few here. Time is only a safety stop. Inputs it leaves
    are reported as `not_judged`, and the module is not reported clean on them.
  - **It gives the blinded verdict.** When the first K inputs all fail on one fingerprint, the judge
    stops and reports `blinded: <fingerprint>` (K to be set). This is cheap: run-1's fork-mode
    counts put one crashing run at about 0.14 to 0.2 CPU-seconds. On this host that figure may
    include the core-dump cost of an open bug ("Every `abort()` ... Takes Minutes" in
    [`../troubleshooting/resources-and-infra.md`](../troubleshooting/resources-and-infra.md)).
  - **It is not charged to the fuzz budget** (the rule of P1c).
  - **It is its own Make step with its own report**, without a dependency on `fuzz-%`, as
    `coverage-%` is. After a fix to an E-ACSL false positive, only the judge runs again on the kept
    corpus. On run-1 that would have replaced a second fuzzing of six modules. The campaign calls
    the same code after exploring. The report has to be ingested as the fuzz and Eva reports are.
  - **It links the two engines' fingerprints.** A crash input that fails on both builds is one
    candidate with two fingerprints. That addresses the open gap "One Defect Gets Different
    Fingerprints on the E-ACSL and the Sanitizer Builds" in
    [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md).
- **P2e. E-ACSL fuzzing keeps one fifth of the budget** (starting value). It runs after the judge,
  on the judged corpus.
  - **Why keep it.** The judge sees only inputs the explorer kept, and the explorer keeps an input
    for new coverage, not for its values. An overflow inside a struct that needs one specific
    length does not crash ASan, and nothing marks that input as worth keeping. No recorded bug is
    known to need it, and for LIBMNL-02 and QCBOR-01 the record does not exclude it. That is why
    the share exists and why it is small.
  - **Cases the judge found failing start skipped**, as in P6b, whether the failure is an artefact
    or not. Otherwise the share is spent finding the same failure again.
  - **Only when the judge is not blinded.** A judge pass over the seeds and the imported corpus runs
    before exploring. If it is blinded, the explorer gets the whole budget. If the blinding shows
    only after exploring, the share is left unspent and the report says so.
  - **Every finding names the step that found it:** `explore`, `judge` or `eacsl_fuzz`. After a few
    targets, drop the share if it has found nothing the judge did not.
- **P2b.** `params set --fuzz-engine eacsl` should not silently drop the sanitizer engine. The value
  that keeps both engines already exists: `auto`. So have `params set --fuzz-engine eacsl` warn that
  the sanitizer engine is lost and name `auto`, and have the DAG's reason and the skills name `auto`
  as the way to undo a wrong `sanitizers` choice. Do not change what `eacsl` means: recorded
  `params.json` files would change behaviour without anyone deciding so.
- **P2c. Report each step.** The module's Phase 1 result says what was explored (executions,
  coverage), what was judged (inputs judged, failed, not judged, or blinded) and whether E-ACSL
  fuzzing ran. The ledger's `fuzz_clean` evidence must not name E-ACSL when the judge was blinded or
  did not run. Otherwise a report hides a module that only the sanitizers checked.

- **P2f. A known false positive is reported, not suppressed.** Decided on 2026-11-16. E-ACSL can
  replace its assertion handler (`--external-assert`), and a handler could let a failure pass that a
  crash verifier has rejected as `toolchain_artifact`. That is not done: suppression goes by site and
  predicate, so it would also let a real violation of the same check pass. Instead:
  - The judge counts the failures per fingerprint, and reports the inputs that stopped at one as
    not judged past that point.
  - A module whose every input stops at an artefact stays `blinded`, without an E-ACSL result,
    until the artefact is fixed in the pipeline or upstream.
  - After the fix, only the judge runs again (P2d).

Two cases stay as they are today. When the sanitizer build fails, E-ACSL fuzzes alone
(`dual_engine_skipped`). When E-ACSL cannot build the module (the DAG's `sanitizers` choice), the
module is explored only, and the report says no judge ran.

Left out on purpose: reducing the corpus with libFuzzer's `-merge` before judging. It drops inputs
that differ only in their values, which changes what is judged, and it was not tried in the image.

### P3. Raise the budgets

The budgets must stay fixed constants, not "until coverage stops growing". The pipeline runs on
hardware it does not know in advance, and a limit that decides results must not depend on the
machine. Starting values, to be calibrated with P5:

| Profile | Per case (CPU-s) | Unit cap (CPU-s) | Wall per unit on 9 workers | Today |
| :--- | :--- | :--- | :--- | :--- |
| quick | 60 | 480 | about 1 min | unchanged |
| standard | 600 | 7,200 | about 13 min | 120 / 1,200 |
| deep | 3,600 | 43,200 | about 80 min | 900 / 7,200 |

What these numbers mean in practice:

- **The per-case figure applies only to units of up to 12 cases.** c-ares's 40-case unit would get
  180 CPU-seconds per case under `standard`, about 20 s of wall time on 9 workers, against 30
  CPU-seconds today. Whether the cap should grow with the case count is an open question.
- **`deep` then costs about as much wall time as one Eva base run.** In CPU-seconds it costs more
  than a timed-out Eva module (43,200 against 9,000 to 18,000). That may be the right price for
  `deep`; it should be a decision, not a side effect.
- **The budget covers exploring and E-ACSL fuzzing, four fifths and one fifth (P2).** The judge is
  limited by a count of inputs and is not charged to it.
- **CPU-seconds still vary with the machine.** The constant is fixed, but a faster CPU runs more
  executions in it. The floor pass (P6a) is therefore limited by an execution count; the rest of
  the budget stays in CPU-seconds, which keeps the total cost predictable.
- **`quick` stays a smoke test.**
- **The CPU a campaign spends must not depend on its worker count.** `MIN_FUZZ_BUDGET_S = 30`
  stays. The 30 s wall floor breaks the rule today (section 1.1). One way to keep both: give a
  campaign only as many workers as its budget pays for at 30 s each, so a 30 CPU-second campaign
  runs one worker for 30 s.
- **A `fuzz_budget` in `params.json` replaces the profile budget.** Runs that set one are not
  changed by P3. That includes the benchmark scripts, which pass their own budget.

The evidence for a larger budget is one campaign: `tf_ares-test-fuzz`, whose coverage was still
growing when its 30 s ended. Raise the budgets only after P1, since without it most of the new
budget is spent on the first false positive.

### P4. Run Phase 1 fuzzing alongside Phase 2

In [`../../templates/pipeline.mk`](../../templates/pipeline.mk), `eva-%` needs only the reach gate
(`$(GATE) --module $* --need reach`), not `fuzz-%`. Phase 2 could therefore start as soon as Phase 0
passes, and run alongside the fuzz campaigns.

The gain is small under `standard`: about 13 minutes per unit, against 2 h 30 min for each Eva
module that times out. It is about 80 minutes under `deep`. P4 changes the skill, the checkpoint
model and the gates, so it should wait until `deep` runs show the need. Points to settle first:

- **Memory.** CPUs were free on run-1 and memory was not (section 1.4). Four Eva runs took about
  3.5 GiB each, and a 9-worker fuzz lease reserves 23,552 MiB. Run side by side as sized today, the
  two phases would queue for memory. P7 has to come first.
- **Phase 1 checks the harness before Eva pays for it.** A crash that turns out to be caused by the
  harness leads to a harness repair, and the repair makes an Eva result on the old harness stale.
  Running Eva first gives up that cheap check.
- **Order of the gates.** `coverage-%` and `reach-dynamic-%` can reopen the reach gate after
  fuzzing ("an API entry point its corpus never executed"). Running `reach-dynamic-%` before the
  campaign is not a way out: the corpus then holds only seeds and imported inputs, and a module
  without any would show every entry point as never executed. (This follows from reading
  `harness_reach.py`; it was not run.) The workable option is to mark Eva reports made before a
  reopened gate as stale, which fits what `harness_digest` already does.
- **Skill orchestration.** `framac-verify` drives phases one after another. Overlapping them changes
  the skill and the progress and checkpoint model (`phase_done`).

### P5. Measure, so the numbers above can be replaced

- **P5a.** Add a coverage-over-time series to the fuzz report (`cov`/`ft`/`corp`/`exec_s` sampled
  from libFuzzer's status lines, per engine and per round), and the totals over all jobs. Today
  `log_tail` holds the last lines of one job, so a 9-job campaign reports one ninth of its work.
  Edge counts differ between the two engines, because the E-ACSL build adds its own code. Use the
  coverage build's per-function result (`coverage-%`) to compare engines.
- **P5b.** Record executions per second per engine, and the judge's replay speed. P2 needs both: the
  ratio between the engines, and how many inputs the judge can take.
- **P5c.** `benchmark.py` / `benchmark_compare.py`: compare Phase 1 runs at two budgets on the
  benchmark targets. Measure the time to first coverage plateau, the bugs found, and the coverage
  that reaches Phase 3 (crash candidates, reproducers for Eva Unknowns). The benchmarks pass their
  budget through `params`, so the comparison has to set both budgets itself.
- **P5d.** Record where Phase 1's wall time goes, per module: build, waiting for a lease, fuzzing,
  crash replay, attribution build. On run-1, fuzzing was about 6 of 34 minutes.

### P6. Give every case a floor, then let libFuzzer share the rest

Direction agreed on 2026-11-16; not implemented. It applies to the explorer (P2a) on a dispatch
harness.

The budget formula gives each case the same share, but nothing enforces it: one campaign runs all
cases and libFuzzer decides. Run-1's `dnsrec` corpus shows the result (1,909 files, 19 cases; the
first byte selects the case):

| Case | Corpus files |
| :--- | :--- |
| 11 (`ares_dns_parse`) | 1,215 (64%) |
| 8 | 95 |
| 14 | 80 |
| 7 | 72 |
| 10 and 12 | 6 and 8 |
| the other 13 | 17 to 63 each |

libFuzzer picks the inputs it mutates from the corpus, so its effort very likely follows these
shares. That is an inference: the report has no per-case execution counts. It is not simply a
defect, since the parser is where the coverage is. A fixed, equal budget per case would cut the
parser from about two thirds of the campaign to one nineteenth. Three things are wrong today:

- **No minimum per case.** A case can get almost nothing, and nothing shows it.
- **No isolation.** A crash in one case ends the whole job, which the rounds logic then has to
  repair (P1, P1c).
- **No per-case numbers.** A finished case cannot be told from a starved one.

Proposed, in two passes:

- **P6a. Floor pass.** Each case runs alone, one libFuzzer process per case, with every other case
  skipped through the existing runtime skip (`FRAMAC_FUZZ_SKIP_CASES`). As many cases run at once
  as the lease has workers.
  - **The limit is a number of executions, with a fixed seed.** Each case runs `-runs=<count>` with
    a `-seed` derived from the module and the case. The count is one constant per profile (to be
    set from P5b). On a deterministic target the pass then gives the same corpus and the same
    findings on every machine, and again on a rerun. Campaigns pass no seed today.
  - **Each case writes to its own corpus directory.** A process that reloads inputs written by
    another would execute them at times that depend on the machine. The directories are merged
    into the module's corpus before the shared pass.
  - **CPU time is only a safety stop.** The stop is the case's share of one quarter of the
    explorer's budget (starting value), with a minimum per case (to be set). Execution speed
    differs widely: on run-1 `channel` ran 35 executions in 1.8 s and one `dnsrec` job about 1,400
    per second. A case that hits the stop is reported as `floor_not_reached` with the executions
    it did, never as done. A harness with very many cases needs more than the quarter for its
    minimum stops (QCBOR had 182 cases); the floor pass then takes what it needs.
  - **After a crash** the process is started again with the executions it has left, up to a fixed
    number of restarts (to be set). Executions still left after that are reported as unspent. Fork
    mode is not used here, because it does not keep to an execution count (see below).
  - **Each case ends in a state:** `ok`, `crashing` (with its fingerprints) or `blinded`: every
    start crashed within a fixed number of executions (to be set) and the corpus stayed empty. The
    rule is a count, so it also holds for a case without seeds.
  - **Each case gets its own numbers:** executions, coverage and corpus size, which is the per-case
    half of P5a.

  The libFuzzer behaviour behind this was checked in `framac-analysis:latest` (clang 19.1.7) on a
  small deterministic target, 2026-11-16:

  | Mode | Flags | Result |
  | :--- | :--- | :--- |
  | Single process | `-runs=200000 -seed=7`, twice | Exactly 200,000 executions each time, and the same corpus files. With `-seed=8`: a different corpus. |
  | Jobs | `-jobs=2 -workers=2 -runs=50000` | Each job ran exactly 50,000: the count is per job. |
  | Fork | `-fork=2 -runs=50000` | Stopped after 1,570,010 executions: the count is checked between jobs only. |
  | Rejected inputs | `-runs=200000`, target returns -1 unless the first byte is 3 | 200,000 counted, of which 104,131 were rejected. |

  So `-runs` counts attempts, not executions that reached the case. In the floor pass every other
  case is skipped, and an input whose first byte selects a skipped case is rejected. Found after
  P6 was agreed; the handling below was confirmed by the user on 2026-11-16:

  - The count stays a number of attempts, which keeps the pass repeatable.
  - The harness counts the executions that reached the case, and the report gives both numbers.
  - A case whose reached count stays under a fixed share of the attempts (to be set) is reported
    as `floor_not_reached`.

  The share in the test (52% rejected) is that of a toy target with short inputs and says nothing
  about a real harness.

  Not checked: that a real harness is deterministic enough for the corpus to repeat. A target that
  reads the clock, the environment or files of the container will differ from run to run.
- **P6b. Shared pass.** The rest of the budget, in CPU-seconds as today, goes to one campaign over
  all cases, where libFuzzer spreads its effort freely. It cannot be made repeatable: its processes
  exchange inputs through the corpus directory, and fork mode overshoots an execution count. Cases that ended `crashing` or `blinded` in the floor pass start
  skipped, so no round is spent finding them again. A new crash is handled by the rounds as today.

A harness without cases (the fork-mode targets, an `argv` harness) has no floor pass. For a harness
with one case, the floor pass is the whole campaign.

The alternative that was not chosen is a fixed budget per case with no shared pass. It is exactly
predictable, but it starves the cases with the most code behind them unless the budget is weighted,
for example by the functions each case reaches in the DAG.

### P7. Reserve fuzz memory from measured peaks

Direction agreed on 2026-11-16; not implemented.

How it works today ([`../../scripts/resources.py`](../../scripts/resources.py)):

- **The limit per worker is fixed:** `-rss_limit_mb=2048`. An input that exceeds it is an
  out-of-memory finding, so this limit decides results.
- **The lease reserves the worst case:** 512 MiB plus 1.25 times that limit for each CPU, which
  would be 23,552 MiB for 9 workers. No worker can then be killed by the container.
- **The worker count is meant to follow from the lease** (`fuzz_workers`), and a campaign whose
  memory is below the worst case for its workers is refused (`insufficient_memory`). On run-1 it
  followed from the whole container instead (section 1.4), so each campaign ran 9 workers on a
  lease of 1 to 7 CPUs.
- **Measured peaks can only raise a reservation.** The broker records each job's peak and whether
  the container killed it for lack of memory, and suggests 1.25 times the recent peaks, or twice
  the peak after a kill (`history_estimate`). That figure is used as a floor under the class's own
  formula, for every class.

On run-1 fuzzing itself used 56 to 125 MiB per process, against 2,560 MiB reserved per CPU (section
1.4). Once the sub-lease bug is fixed, the worst-case formula allows 9 fuzz workers in the whole
25,088 MiB container, shared by all campaigns, with 15 CPUs available. Today's 9 workers per
campaign exist only because of the bug. So P7 is what keeps fuzzing from slowing down when the bug
is fixed.

Proposed:

- **P7e. Fix the sub-lease bug first**, so that a campaign's workers follow its own lease. Without
  it, no reservation means anything.
- **P7f. Keep builds out of the fuzz lease.** The campaign step can build: the skip rebuilds of the
  rounds, the attribution binary, or the module's binary on a cache miss. An E-ACSL instrumentation
  took about 4.3 GiB on c-ares. Such a build needs a lease of its own, or the fuzz lease has to
  cover it; a lease sized from a fuzzing peak of 100 MiB would not.

- **P7a. Keep the 2,048 MiB limit.** What one worker may use does not change, so findings do not
  change. Only how many workers and campaigns fit at once does.
- **P7b. Size the fuzz lease from the module's measured peak**, with a margin and a fixed minimum
  per worker (both to be set), in place of the worst case. The worker count then follows from the
  CPUs, and the `insufficient_memory` refusal compares against the measured figure.
- **P7c. Take the first measurement from the floor pass** (P6a). Each case runs there as one
  process, so the peak per case is known before the shared pass is sized. A module without any
  measurement starts at the worst case, as today.
- **P7d. A container kill is never a finding.** A worker that really grows towards the limit is
  killed by the container before libFuzzer can report it. The broker already detects this. The
  campaign, or in the floor pass the one case, runs again with twice the reservation, until
  libFuzzer's own limit triggers first and reports the input. From a small peak that is up to
  three reruns for such a module.

Not measured: the memory of ASan workers. Run-1's fuzzing peaks are from E-ACSL binaries. ASan
keeps freed memory in quarantine, so the explorer's workers will use more. The broker's figure is
also the largest single process of the job, not the sum over its workers.

Not proposed: lowering the 2,048 MiB limit. It would change what counts as a finding.

### P8. Fuzz a program's `main` with several arguments

Direction agreed on 2026-11-16; not implemented.

`adig` and `ahost` are fuzzed through their `main` (the `argv` entry style of
[`../../scripts/generate_harness.py`](../../scripts/generate_harness.py)). Read in the code and in
run-1's `harness_adig.c`:

- **The fuzz side passes the whole input as one argument:** `main(2, {"prog", input})`. It can try a
  host name or a single flag, never an option with its value, or an option and a name.
- **The Eva side analyses up to five arguments** of 255 unknown bytes each. The two phases do not
  check the same thing.
- **Program harnesses get no seeds.** The seed harvest records wrapped library calls and opened
  files (`strace -e trace=openat`), not the command lines the target's tests run.
- **Past its argument parsing, `adig` waits on the network.** Its `main` reads the resolver
  configuration, sends a query and loops on `select`. Without network that is a wait, at most the
  10 s input timeout. Run-1 has no timing: both modules were blinded.
- **`main` runs many times in one process.** `adig` keeps static state (`final_rv`,
  `global_config`), which carries over from one execution to the next.

Proposed:

- **P8a. Split the input into arguments** at NUL bytes, at most five arguments of 255 bytes, so the
  fuzz side matches what `eva_main` analyses. An input without a NUL byte is one argument, as
  today, so existing corpora stay valid.
- **P8b. Take seeds and dictionary entries from the program's own interface.** Seeds: the command
  lines the target's tests and documentation use. Recording them from the tests means tracing
  program starts as well as file opens. Dictionary: the option letters of the program's `getopt`
  string.
- **P8c. Do not model the network or standard input for now.** For `adig` the untrusted input is
  the DNS reply, which the library harnesses (`parsers`, the shipped fuzz targets) already cover.
  Measure the executions per second of a program harness first (P5b); if most inputs end in a
  network wait, the harness is a check of the command line only and its budget should say so.
- **P8d. A failure counts only if it reproduces alone in a fresh process.** `replay_artifact`
  already replays one input per process. The judge replays in batches (P2d), so it has to confirm
  each failure of a program harness alone before reporting it.

The alternative that was not chosen is to leave program harnesses as a smoke test of the command
line with one argument.

### P9. Join Phase 1's results with Eva's Unknown alarms

Direction agreed on 2026-11-16: build the join first. An aimed fuzz pass after Eva is not decided;
the join's numbers decide whether it is worth building. Not implemented.

Read in the code:

- **Nothing joins the two phases per Unknown alarm.** After Eva, the dynamic work on an Unknown is
  Phase 3's: breakers on stalled proofs, and the guardrail's replay of 64 corpus inputs. One join
  exists in the other direction: `_dead_code_on_disk` in
  [`../../scripts/ledger.py`](../../scripts/ledger.py) checks a `dead_code` rejection against Eva's
  Dead rows at the file and line, and against the coverage report (function never executed).
- **The two phases do not check the same properties.** By default Eva runs with
  `-warn-invalid-pointer`, `-warn-unsigned-overflow`, `-warn-signed-downcast` and
  `-warn-right-shift-negative` ([`../../scripts/run_eva_slice.py`](../../scripts/run_eva_slice.py)).
  All four are off by default in the image's Frama-C (`frama-c -kernel-h`). The E-ACSL build passes
  `-rte`, `-rte-initialized` and, when set, `-warn-unsigned-downcast`
  ([`../../scripts/run_eacsl_fuzz.py`](../../scripts/run_eacsl_fuzz.py)). E-ACSL also does not
  execute `\dangling` ([`../references/e-acsl-quickref.md`](../references/e-acsl-quickref.md)).
- **The E-ACSL build checks only the functions it was given.** It passes the slice's functions as
  `-rte-select` and `-e-acsl-functions`, and records the ones it had to drop (`rte_select_dropped`).
- **The instrumented source lists what is checked.** Each compiled assertion carries its file,
  line, function and name.
- **The coverage report is too coarse for a line.** It keeps at most 32 uncovered line ranges per
  function, from the function's own file only. A line missing from that list is not shown to have
  run. The `export.json` in the coverage scratch directory has the count of every region.
- **Some failures have no line.** The libc-replacement and format-string checks stop with
  `<function>: <message>`.

Measured on run-1, Eva side only (`workspace/eva/adig/alarms.csv`): 283 Unknown rows of 13,661
(11,571 are Dead), on 139 lines in 72 functions.

The third column is measured too. Run-1's instrumented source for `adig`
(`workspace/harnesses/fuzz_adig.instrumented.c`) holds 42,706 compiled assertions. Its recorded
build command has 1,016 selected functions, the library's included, and no `-warn-*` option.

| Alarm kind | Unknown rows | RTE assertions of that kind compiled into the E-ACSL build |
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

The counts are the records named `rte/<kind>`. The other 24,911 records are E-ACSL's own guards
(`uninitialized`, `memory access`, `pointer alignment`), which protect the evaluation of a check
and are not the alarm's assertion.

The percentages below count rows; a header row and a call-site row can state one obligation twice.
130 of the 283 rows (46%) are of kinds with no compiled assertion at all. 91 (32%) are of kinds the
build compiles. Whether the assertion at a given row's line was compiled, and which kinds the
sanitizer build reports, was not checked.

Run-1 cannot show the join itself. No coverage step ran: the session went from `run fuzz` to
`run eva` and left out the skill's `run coverage` and `run reach-dynamic`
([`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md)). Four of
the five Eva runs ended in `analysis_timeout` without an alarm table. The fifth is `adig`, whose
campaign was blinded.

Proposed:

- **P9a. One deterministic step per module after Eva.** A Make target, no agent, no fuzz budget. It
  reads Eva's alarm table (`read_report_csv`, `eva_alarm_in_file`), the coverage export and the
  judge's report (P2d), and writes one report per module. It decides no verdict. An Unknown stays
  Unknown and stays in the WP queue, whatever its state here. The target runs the coverage replay
  it needs itself: on run-1 the session skipped `run coverage` and nothing stopped it.
- **P9b. One state per Unknown alarm:**
  - `failed`: a failure of the judge or of a fuzz engine at the same file, line and kind (function
    and kind for a failure without a line). It links the candidate that exists; it creates none.
  - `executed_checked`: an input the judge ran to its end executed the line, the judge's build
    checks the kind, and nothing failed. This is evidence, not proof.
  - `executed_unchecked`: the line ran, but the kind is not checked, or the judge was blinded or
    did not run.
  - `not_executed`: no input reached the line.
  - `not_joined`, with a reason: no coverage report, a partial one, or a row outside the target's
    sources (the libc header rows).
  - A module without an alarm table gets `no_alarm_table` and no rows.
- **P9c. The compiled assertions decide `checked`.** For the E-ACSL build, a row is checked when
  the instrumented source holds an `rte/<kind>` assertion of that kind at that file and line. This covers the
  function selection, the dropped functions and the checks the build removes
  (`va_list_init_checks_skipped`, `reduced_checks`). For the sanitizer build there is no such list,
  so a table of kinds decides. Whatever is not established as checked counts as unchecked.
- **P9d. Execution comes from the inputs the judge finished.** The coverage replay for the join
  uses the inputs the judge ran to the end without a failure, and reads region counts from
  `export.json`. When the judge only sampled (`not_judged` above 0), the report says the
  `executed_*` counts are lower bounds.
- **P9e. Where it is shown.** The module report and a count per state in `REPORT.md`. A prover or
  crash-verifier brief may cite a row. The ledger's status does not change.

Left for after the first numbers:

- **The aimed pass.** If few Unknowns are `not_executed`, it is not worth building.
- **An ordering hint for WP.** `_priority_key` in
  [`../../scripts/wp_scheduler.py`](../../scripts/wp_scheduler.py) already sorts on `eva_unknowns`,
  so a hint could attach there.
- **Giving the judge Eva's `-warn-*` options.** Tried on 2026-11-16, see below. Decided: not now.

#### Trial: Eva's `-warn-*` options in the E-ACSL build

Tried on 2026-11-16 after the user chose this lever. The question was whether the E-ACSL build can
check the kinds Eva alarms on, and what that costs.

Method:

- **Two modules, in copies of their run directories:** `minmea` of minmea run-1 (64 seeds and 312
  corpus inputs) and `libnettle_a__sha3` of nettle run-3 (hash code). Nettle run-3 has no corpus,
  so 99 inputs were generated: for each of the 33 cases, 16, 200 and 1,000 fixed pseudo-random
  bytes.
- **Built by the pipeline's own function** (`build_module_binary`, cache off), with the options
  added to the Frama-C flags of stage 1. The rebuilt baseline of `minmea` has the same 864
  assertions, name by name, as the run's stored build.
- **Each input replayed once per build**, one process per input (`replay_inputs`).
- **Containers of their own**, 2 CPUs and 4 GB each, next to the live c-ares run. The timings are
  rough for that reason.

`minmea`: 372 of the 376 inputs pass the baseline (the other four fail on `MINMEA-03`), and Eva
has 146 Unknown rows.

| Option added | Compiled assertions | Unknown rows that gain an assertion | Inputs that newly fail |
| :--- | ---: | ---: | :--- |
| None (baseline) | 864 | 109 of 146 have one | |
| `-warn-invalid-pointer` | 2,502 | 10 (`pointer_value`) | 371 of 372, all on one check at `minmea.c:114` |
| `-warn-unsigned-overflow` | 886 | 4 | None |
| `-warn-signed-downcast` | 896 | 15 | 11, all at `minmea.c:223` |
| `-warn-right-shift-negative` | 864 | 0 | None |
| All four | 2,564 | 29, so 138 of 146 | 371 of 372 |

A row counts when an `rte/<kind>` assertion of its kind is compiled at its file and line. The 8
rows left are the 6 preconditions and 2 `mem_access` rows.

`libnettle_a__sha3`: only 24 of the 99 generated inputs pass the baseline, in 8 of the 33 cases.
The rebuilt baseline has the stored build's 3,006 assertions.

| Option added | Compiled assertions | Inputs that newly fail |
| :--- | ---: | :--- |
| None (baseline) | 3,006 | |
| `-warn-unsigned-overflow` | 3,717 | 15 of 24, all in `nettle_sha3_permute` |
| `-warn-invalid-pointer` | 6,932 | 15 of 24, all on one check at `sha3-permute.c:169` |
| All four | 7,837 | 15 of 24 |

What the failures are:

- **`-warn-invalid-pointer` cannot be used today.** E-ACSL's `\object_pointer` is false for a
  pointer to read-only static data. On `minmea` it fails on the format string literal of
  `minmea_scan`; on nettle on the `static const` round-constant table `rc`. A small program shows
  it for a string literal and for a `static const` array, while a local array and a writable
  global array pass
  ([`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md)). The
  E-ACSL manual lists `\object_pointer` as supported, so this looks like an upstream defect; it is
  not filed. The check that fails is E-ACSL's own `invalid pointer` guard (1,114 added on
  `minmea`), which runs first; whether the 152 `rte/pointer_value` assertions would fail too was
  not shown. The option also costs the most: the build went from 15 s to 39 s on `minmea` and from
  51 s to 111 s on nettle.
- **`-warn-unsigned-overflow` blinds hash code.** The 15 nettle failures are the rotations of
  SHA-3 (`C[2] << 1`, `X << 44`): intended wrap-around. All inputs of five of the eight passing
  cases stop there. On `minmea` it costs nothing and nothing fails.
- **`-warn-signed-downcast` reports real narrowings.** `minmea.c:223` stores the `long` result of
  `strtol` in an `int`. That is implementation-defined, not undefined, and it is the statement
  `MINMEA-01` starts from. The 11 inputs stop there and check nothing after it.
- **`-warn-right-shift-negative` changed nothing on `minmea`.** On nettle it was only tried
  together with the other three.

What follows:

- **The largest group stays out of reach.** `pointer_value` is 64 of `adig`'s 283 Unknown rows, and
  it needs the option that cannot be used. `ptr_comparison` and `dangling_pointer` have no option
  at all.
- **The other three options are not safe in the build that fuzzes.** One of them stops every input
  in hash code, and E-ACSL stops an input at its first failed check.
- **A second E-ACSL build for the judge only** could carry `-warn-unsigned-overflow` and
  `-warn-signed-downcast`. It would move 19 of `minmea`'s 146 rows and up to 31 of `adig`'s 283
  to checked. It costs one more E-ACSL build per module. It needs the judge to go on after a failed
  check (`--keep-going` of `e-acsl-gcc`, not tried), or the first rotation hides the rest of the
  input.

Decided with the user on 2026-11-16: the builds stay as they are. The join reports these kinds as
unchecked. The judge-only build is looked at again when the join has numbers: they will show how
many rows are `executed_unchecked` for these two kinds, which is what the second build would buy.

### P10. Symbolize a failure's stack only when it is needed

Direction agreed on 2026-11-16; not implemented.

Measured on 2026-11-16 on minmea's fuzz binaries (`framac-analysis:latest`, a container of its own
with 2 CPUs, five runs each; the details are in
[`../troubleshooting/resources-and-infra.md`](../troubleshooting/resources-and-infra.md)):

| Execution | E-ACSL build | Sanitizer build |
| :--- | ---: | ---: |
| An input that passes | 85 ms | 89 ms |
| An input that fails, as the pipeline runs it | 452 ms | 440 ms |
| The same with `symbolize=0` in `ASAN_OPTIONS` and `UBSAN_OPTIONS` | 94 ms | 88 ms |

- **The 350 ms are stack symbolization.** Without it the stack frames have no function names.
- **The core-dump limit plays no part for a fuzz binary.** libFuzzer catches the signal and exits
  with code 77. The failing input took about 435 ms with `RLIMIT_CORE` at 0, at 1 and unset.
- **A binary with its own `main` does pay the core dump on this host.** A failing E-ACSL check took
  852 ms with the sandbox's limit of 0 and 14 ms with a limit of 1 (the open bug in the same
  troubleshooting entry).

Read in the code: `parse_eacsl_failure` takes file, line and function from E-ACSL's message, not
from the stack. `parse_sanitizer_failure` reads them from the stack frames. A failure without a
usable location (`needs_attribution`: the libc-replacement and format-string checks) is replayed
on a sanitizer build today.

Proposed:

- **P10a. The judge replays without symbolization.** An E-ACSL failure with a location needs no
  stack. This is where the cost counts: the judge replays every input once (P2d), and on a module
  where many inputs fail, each one costs five times what it needs to.
- **P10b. Symbolize on demand.** A failure without a usable location is rerun with symbolization,
  as the attribution replay does today. Each fingerprint keeps one symbolized log, so a candidate
  still has a readable stack for its verifier.
- **P10c. Set the sandbox's core limit to 1** ([`../../scripts/sandbox_exec.py`](../../scripts/sandbox_exec.py)
  sets 0), after checking that nothing reads core files. It helps the steps that run a binary
  with its own `main`; which steps those are was not listed.

Not covered: fuzzing itself. The sanitizer explorer's fingerprints need function names, so a crash
there is symbolized as today. Grouping crashes by their raw frame addresses first, and symbolizing
one input per group, is possible but not worked out.

Limits: one small binary. Symbolization reads debug information, so it may cost more on a large
one (`adig`'s instrumented source is 90 MB); that was not measured. The gain is proportional to
the number of failing inputs and is nothing on a module where inputs pass.

## 3. What not to do

- Do not stop fuzzing when coverage plateaus. That result would depend on machine speed.
- Do not raise budgets as the only change: on run-1, five of seven campaigns would have spent the
  extra time on one false positive, or stopped as early as they did.
- Do not make fuzzing time depend on Eva's: they are independent budgets with different jobs.
- Do not add `-use_value_profile=1` or `-max_len` to the campaign for now (decided with the user
  on 2026-11-16). Measured on minmea's harness with the coverage build, the 64 seeds, 3,000,000
  executions and three libFuzzer seeds each:

  | Configuration | Edges reached | Corpus files | Run time |
  | :--- | ---: | ---: | ---: |
  | Default | 270 to 271 | about 370 | 14 s |
  | `-max_len=128` (the harness limit) | 270 to 271 | about 370 | 14 s |
  | `-use_value_profile=1` | 271 | about 1,200 | 26 s |
  | Both | 271 | about 1,190 | 27 s |

  The value profile found nothing more and nearly doubled the time. `-max_len` changed nothing,
  although without it libFuzzer's length limit grew to 4,096 against a harness limit of 128
  ([`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md)). minmea
  is saturated at that count: the seeds alone reach 268 edges after 20,000 executions. So this
  shows the value profile's cost, and cannot show a benefit on a target that compares against
  magic values. Worth another look when P5a gives coverage over time on a larger target.

## 4. Limits of the evidence

- **One run, one engine.** Everything in section 1 comes from c-ares run-1, fuzzed with E-ACSL
  only. Of the earlier targets, only the bugs-found records were read (P2); their fuzz reports were
  not.
- **The held fixes change the picture for c-ares.** F2 (setjmp), F10 (`%u`) and F11 (tail-merged
  literals) remove both false-positive families and the wrong DAG choice. What stays after they
  merge: the accounting bug (P1c), the lack of blinding detection (P1a, P1b), the one-job report
  (P5a), and the next false positive on the next target.
- **No speed ratio and no plateau data.** The shares in P2 and the numbers in P3 are starting values.
- **No join was computed.** P9's counts are Eva's rows for one module. Run-1 has no coverage report
  and no judge, so how many Unknowns fall into each state is not known for any target.
- **The trial of Eva's options is small.** Two modules. The nettle half rests on 24 generated
  inputs in 8 cases of a harness from an older run; it shows that unsigned overflow blinds SHA-3,
  not how often hash code is hit in general. No judge exists yet, so "the judge goes on after a
  failure" was not tried.
- **More fuzzing costs more than CPU.** Each new fingerprint becomes a candidate for a crash
  verifier, which is model time. A larger budget needs the duplicate and false-positive handling of
  P1 for that reason too.

## 5. Open questions

- For the judge (P2d): the input cap N, the blinded threshold K, and the speed of an E-ACSL replay
  that does not crash, which decides how large N can be.
- Whether the one-fifth share of E-ACSL fuzzing (P2e) finds anything the judge does not.
- For the floor pass (P6a): the execution count per profile, the minimum CPU stop per case, the
  number of restarts after a crash, and whether the shared pass still leaves some cases far behind
  once every case has had its floor.
- For the memory reservation (P7): the margin and the minimum per worker, and the peak memory of
  ASan workers.
- Whether real harnesses are deterministic enough for the floor pass to repeat. Run-1's `channel`
  harness reads the container's resolv.conf, so it is not.
- Whether `standard`'s new unit cap should scale with the number of harness cases beyond the
  current per-case budget.
- The thresholds for P1a, in jobs or executions.
- How to report a blinded module in `REPORT.md` and the ledger, so that a clean Phase 1 is never
  read as "fuzzed without findings".
- Where the 29 unexplained minutes of run-1's `run fuzz` went (P5d).
- For program harnesses (P8): how to record the command lines the target's tests run, and the
  executions per second once the network wait is counted.
- For the join (P9): which Eva alarm kinds the sanitizer build and the libc replacements check;
  how Eva's kind names map to the names in the instrumented source (`uninitialized`,
  `memory access`) and in the failure fingerprints; and whether Eva's paths and lines match the
  coverage export's and the instrumented source's for code from macros and headers.
- Whether the judge later gets a second E-ACSL build with `-warn-unsigned-overflow` and
  `-warn-signed-downcast` (trial in P9; decided not now). It depends on `--keep-going` working in
  the pipeline's build, on the cost of a second build for a large module, and on how many rows the
  join shows as `executed_unchecked`. The old `e-acsl-gcc` call used `--rte=all`, which adds
  `-warn-unsigned-overflow`; whether the two-stage call (`1d151be`) dropped it on purpose is not
  known.
- The `\object_pointer` defect: drafted for upstream, not filed
  ([`../upstream/frama-c/frama-c-eacsl-object-pointer-readonly-static.md`](../upstream/frama-c/frama-c-eacsl-object-pointer-readonly-static.md)).
  The runtime tests the pointer with `\valid`'s check, which requires a writable block. Until it
  is fixed, `pointer_value` rows cannot be checked at run time.
- For the floor pass (P6a): the share of attempts that must reach the case, and whether a real
  harness rejects enough inputs for this to matter.
- For symbolization (P10): what it costs on a large binary, how to group the explorer's crashes
  before symbolizing them, and which pipeline steps run a binary with its own `main` in the
  sandbox.
