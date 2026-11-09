# Design note: sharding a module's Eva run by dispatch case

Status: design only, nothing implemented. Written 2026-11-09 from QCBOR run-5.

## Problem

Eva is single-threaded. A module's `eva_main` covers every dispatch case of its harness in one run, so
the module's wall time is the sum of all its cases. On QCBOR run-5, `libqcbor_a` (179 cases, one
`eva_main`) took 6,964 s in Frama-C (7,715 s with the flows and SARIF steps after it) with a 12.6 GB
peak. The tuning ladder then had no chance: every rung is capped at 7,200 s, so tuning is now skipped
(`eva_options.tuning_skip_reason`), and the module keeps its base-run Unknowns (1,323 of 9,375).

The only parallelism Eva allows is to run several processes. This note proposes running one module
as *k* Eva jobs, each on a subset of the dispatch cases, and merging their statuses.

## Shards

A shard is the module's harness with only some dispatch cases left in the `switch`. Everything else
is the same: sources, flags, options, slevel, checks and the prefix of `eva_main` before the
`switch`.

How cases are removed matters. The fuzz build already has a skip mask (`FRAMAC_FUZZ_SKIP_CASES`, a
run-time test on `harness_selector`). That test does not work for Eva. `harness_selector` is an
unknown byte, so Eva evaluates the test to `{0, 1}`, takes both branches and still enters every case.
A shard has to remove the excluded cases from the source text:

- `generate_harness.py` wraps each `case k:` in `#if !defined(FRAMAC_EVA_SKIP_CASE_k) ... #endif`.
  The shard is then built with `-DFRAMAC_EVA_SKIP_CASE_k` for each excluded case. A `default: break;`
  arm takes the excluded selectors, and those executions call nothing.
- The preprocessor keeps line numbers, so an obligation in harness code keeps its `(file, line)` key
  (`eva_tuning.obligation_key`) in every shard that still contains it.

Shard plan (deterministic, in `pipeline_make.py`, like the ladder):

- Cost of a case: its share of the module's last base-run `flamegraph.txt`. That is the inclusive
  time of the depth-1 callees of `eva_main` that the case calls (`api_cases[*].calls` and `inits`),
  with a callee shared by several cases split evenly between them. With no profile yet, every case
  costs the same.
- Packing: longest-processing-time first into *k* shards. Ties break on the case number, so the same
  profile always gives the same shards.
- Choosing *k*: the smallest *k* whose largest shard is predicted to be under the tuning-skip
  threshold (`TRIAL_TIMEOUT_CEILING_S / TUNING_SKIP_MARGIN`, 5,760 s), so tuning can run again. *k*
  goes higher only while the predicted makespan still falls by at least 10%. *k* is recorded with the
  shard plan. It changes what each run analyses, so, like `LADDER_VERSION`, it is part of the
  settings digest and never comes from the machine size.
- Make targets: `evashard-<mod>--<i>` (base run per shard) and `evarung-<mod>--<i>--<rung>`. Each
  has its own resource-history key, `<mod>:shard<i>` and `<mod>:shard<i>:<rung>`. Before a shard has
  a peak of its own, `history_estimate`'s module-prefix tier gives it the largest peak recorded for the
  module. That is safe, but the first sharded run then leases the full 15.8 GB per shard, as rungs do
  now (see "Memory" below).

## Merging statuses soundly

For each obligation, a shard gives one of: Valid, Unknown, Invalid, Dead, or *not here*. *Not here*
means the obligation's statement is in a case this shard removed, or in a function this shard never
reached (Eva's `Unreached functions`, or no final state for that function). Merge rule:

| Shard statuses (shards where the obligation is not *not here*) | Merged |
|---|---|
| any Invalid | Invalid (red), with the shard named, as `tuning_run` is today |
| no Invalid, any Unknown (or Never tried in a reached function) | Unknown |
| all Valid, or Valid and Dead | Valid |
| all Dead, or *not here* everywhere | Dead |

So an obligation is Valid only if no shard leaves it Unknown or Invalid. *Not here* is counted as
"no execution of this shard reaches it", never as a proof on its own.

Why this is sound. Each execution of the original `eva_main` takes exactly one value of
`harness_selector % N`, so it is an execution of exactly one shard. The prefix before the `switch` is
the same in every shard, and the selector values a shard does not handle go to `default` and call
nothing. Each shard is a sound Eva analysis of its own executions. Eva's Valid statuses hold under the
alarms it reported earlier on the same path (Eva manual 5.7, 8.1.2), and this is the argument
`eva_tuning.py` already makes for its per-obligation combination: in every sound run, the *first*
property that a real execution violates is reported not Valid. Take any execution, and let *i* be its
shard. The first property it violates is not Valid in shard *i*. That shard reaches the statement, so
it is not *not here* there, and the merge cannot call it Valid. If no merged-Valid obligation is
violated by its execution's first violation, then none is violated at all, by induction on the length
of the execution, exactly as in the tuning proof.

Two cases need care:

- Unreached is not proof. A function a shard never calls has RTE obligations with status Never
  tried. The merge must take reachability from that shard's log (`parse_eva_reachability`, the
  `Unreached functions` list). It must not treat Never tried as Unknown (then every function only
  some shards reach would stay Unknown), and it must not treat it as Valid.
- One analysis identity. `analysis_identity` and `input_digest` differ between shards because the
  skip defines change the preprocessed harness. A shard identity must therefore be the module's
  digest without the skip defines, plus the shard's case set. The merge refuses shards whose identity
  without the case set differs, or whose case sets do not cover exactly every case once.

Tuning per shard, then merging: each shard runs the ladder and `eva_tuning.finish` on its own
(guards, selection and per-obligation union within the shard). Each shard's combined statuses are a
sound result for that shard's executions, so the merge across shards stays sound. Order matters: the
union across rungs is only valid within one shard, and the "all shards" rule only across shards. A
shard whose base run does not complete makes the module's report incomplete. Its obligations stay
Unknown, never Valid, and the report says which shard failed.

What else changes:

- `flows` (read and write sets per function) becomes a union over shards. These are hints for prover
  briefs, never verdicts.
- `cost_profile` and `flamegraph.txt`: one per shard, and the published one is the slowest shard's.
- `eva-<mod>` replays the shard plan and each shard's recorded decision, as it now replays one
  decision.
- The ledger reads only the merged report, so it does not change.

## Estimated win on QCBOR run-5 (`libqcbor_a`)

The module report in `workspace/reports/eva/libqcbor_a.json` has no `cost_profile`, because the run
did not time out. I computed the per-case cost from the run's `flamegraph.txt` instead (7.1 M samples,
read line by line, now possible with the streaming `cost_profile`):

- The flamegraph accounts for 4,707 s. The whole Frama-C process took 6,964 s. The other 2,257 s are
  not in any function frame. File times show about 150 s after Eva (red statuses, metrics, report,
  nonterm). The QCBOR run-4 base run on the same sources took 64 s in total, which puts a ceiling on
  parsing plus RTE. So most of the 2,257 s is probably Eva work outside per-function frames, which
  would shrink with each shard. This is not measured.
- Per-case cost is very uneven. The costliest case (171, an encode/decode sequence of about 50 calls)
  is 12% of the Eva time (579 s). The top 10 cases are 58%, the top 20 cases 85%, and the top 50
  cases 99.7%.

Makespan with LPT packing. The lower bound is set by case 171, unless that case is split further by
call:

| shards *k* | largest shard, Eva time | makespan if the other 2,257 s scale with the shard | makespan if every shard pays them in full |
|---|---|---|---|
| 1 | 4,686 s | 6,940 s | 6,950 s |
| 2 | 2,343 s | 3,506 s (2.0x) | 4,607 s (1.5x) |
| 4 | 1,171 s | 1,789 s (3.9x) | 3,436 s (2.0x) |
| 8 | 601 s | 953 s (7.3x) | 2,865 s (2.4x) |
| 12 or more | 579 s (case 171) | 920 s (7.6x) | 2,843 s (2.4x) |

So 8 shards is the useful limit. Run-5's base run would take 16 to 48 minutes instead of 116. Every
shard would also fall under the 5,760 s tuning-skip threshold, so the ladder would run again: 8 rungs
× 8 shards = 64 jobs of a few minutes each in place of 8 doomed 2-hour rungs. These are upper bounds
on the speedup:

- One run reuses callee results across cases (Eva's memexec and per-callstack caching). Shards
  analyse a shared callee such as `QCBORDecode_Init` once each, so the sum of shard times will be
  above 4,707 s.
- Every shard pays the per-run steps after Eva. On run-5 these were `collect_flows`, which timed out
  at 600 s, and SARIF, about 4 minutes. Together that is about 750 s of the 7,715 s wall time, and
  whether it scales with shard size is not measured.

## Memory

Run-5's single run peaked at 12.6 GB. A shard keeps states for fewer cases, so its peak should be
lower, but this is not measured. With per-shard history keys, the first sharded run leases the
module's 15.8 GB per shard, so a 32 GB pool runs only 2 shards at a time. From the second run on,
each shard leases its own peak. A first run could use a cheaper bound: memory scaled by the shard's
predicted time share, with a floor. That is a resource decision, not a result-deciding one, but it
risks an OOM kill (and a retry at 2× the peak), so it should be tried on QCBOR before it becomes the
default.

## Validation before adopting

1. Prototype `#if` case removal in `generate_harness.py`. Check that a shard containing all cases
   gives exactly the unsharded report (same rows, same statuses).
2. On QCBOR run-4's `libqcbor_a` (64 s), compare the merged report of 2, 4 and 8 shards with the
   single run. Every obligation Valid in the single run must be Valid or Dead merged, and every Invalid
   must stay Invalid. Merged Valid where the single run says Unknown is expected: shards are more
   precise, because their states are not joined across cases. Each such case must be checked against
   the soundness argument above, not assumed.
3. Measure on run-5 the sum and maximum of shard times, the per-shard peaks, and the post-Eva steps.
   Then replace the estimates in the table above with the measurements.
