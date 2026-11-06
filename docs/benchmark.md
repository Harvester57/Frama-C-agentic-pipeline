# Benchmark

Measures what a change to the pipeline's filters, Eva configuration or briefs actually does. Run it before and after a change and read the differences. Its primary failure signal is losing a confirmed bug.

- **Repository Root:** [`../README.md`](../README.md)
- **Runner:** [`../scripts/benchmark.py`](../scripts/benchmark.py), comparison rules in [`../scripts/benchmark_compare.py`](../scripts/benchmark_compare.py)
- **What it runs:** [`../benchmark/manifest.json`](../benchmark/manifest.json)
- **Stored baseline:** [`../benchmark/baselines/default.json`](../benchmark/baselines/default.json)

## Usage

Run the deterministic part (Phases 0 to 2 plus reproducer replay, no LLM) and compare it with the stored baseline:

```bash
python3 scripts/benchmark.py run --compare default
```

The command fetches each target at its pinned revision on the host, runs it through the normal wrappers and Make targets, writes one JSON file per run, prints the differences, and exits 1 on a regression. `FRAMAC_BENCH_DIR` or `--work-dir` moves its data (default `~/framac-pipeline/benchmark`). Nothing sizes a machine here: the broker leases CPUs and memory per container, as in any run. The shared cross-run cache is off, so no result comes from an older run. On a 12-CPU machine the whole command took 44 minutes of wall-clock and an hour of CPU: 22 minutes for recall and 22 for comparison, of which `jsmn` alone took 14.

Narrower runs while you iterate:

```bash
python3 scripts/benchmark.py run --set recall --no-fuzz --compare default
```

```bash
python3 scripts/benchmark.py run --target minmea --target oscs-stmr --compare default
```

Compare two run files later, or store a run as the baseline after you accept its differences. Several runs can be merged (later runs win, per target and per bug), so a slow target can be re-baselined alone. Storing refuses a run that loses a bug unless you pass `--force`.

```bash
python3 scripts/benchmark.py compare default path/to/run.json --verbose
```

```bash
python3 scripts/benchmark.py baseline --run path/to/run.json --name default
```

A selection that skips a bug or target reports it as `not_compared`, never as a pass or a loss. `compare --require-all` turns a bug that did not run into a failure.

## The sets

**Recall.** The seven confirmed bugs of [`./bugs-found/README.md`](./bugs-found/README.md), at their recorded revisions. QCBOR-02 and QCBOR-03 replay on both `dev` and `master`. A bug is `retained` only if all of this holds:

1. The reproducer fails at the recorded file, function, alarm kind and line. A failure elsewhere is a `mismatch`: an earlier false alarm must not pass as keeping the bug.
2. The failure survives normal fuzz ingestion as a candidate, so a filter added there is measured.
3. `ledger.py ingest-verifier` accepts the confirmation, and the run directory validates. The judgment text is the original Crash Verifier's, stored in the manifest; no LLM runs.

A build failure or timeout gives `undecided`, which still fails the comparison.

Each bug replays on the engine that confirmed it. MINMEA-01 to 03 need the sanitizer build: E-ACSL alone does not see `abs(INT_MIN)` (MINMEA-02), and with `-rte-initialized` it stops earlier at a false alarm on `strtol`'s `endptr`. Other engines are recorded as informational replays: they can warn, never fail.

**Comparison.** ANSSI [x509-parser](https://github.com/ANSSI-FR/x509-parser) (upstream, not the copy in OSCS) and a practical subset of the [Open Source Case Studies](https://git.frama-c.com/pub/open-source-case-studies) (OSCS): `jsmn`, `semver`, `stmr`, `qlz` and `tweetnacl-usable`, each with a harness pinned in the manifest. The manifest's `left_out` lists what is not included and why. OSCS's own alarm counts use its flags and its entry points, so they are not comparable with these.

The Spec-Skill paper's per-call-layer x509-parser results are in the manifest's `references` as context only. That tool runs WP without `-wp-rte` and counts timed-out call-site `requires` goals as proved, so its numbers mean something else than our `covered`. The comparison never reads them.

**Low-cost briefs.** A fixed sample of 30 small assert programs to A/B prover briefs. See [below](#ab-testing-prover-briefs).

## Metrics

Each run writes one JSON file ([`../schemas/benchmark-run.schema.json`](../schemas/benchmark-run.schema.json)):

| Field | Meaning |
| :--- | :--- |
| `recall` | Bugs retained, lost, undecided, not run. `rates` as below. Per bug: each replay's outcome, the observed fingerprint, the gate result, what Eva says at the bug's line (`eva_site`), and whether the campaign found it unaided (`found_by_campaign`). |
| `targets.<t>.modules.<m>.eva` | Valid, Unknown, Invalid, Dead and Considered valid counts, properties checked, statements and functions reached, Unknown by kind, reduced checks. |
| `targets.<t>.functions_with_unknown` | In-scope functions with at least one Unknown. Each one costs a prover task, so this matters more than the raw alarm count. |
| `targets.<t>.functions_with_unknown_no_unit` | The same, but with no ledger unit: no prover would ever be assigned, so those Unknowns silently stay open. |
| `targets.<t>.prover_tasks` | The tasks really queued, per wave. Lower than the line above when a function has a confirmed bug and is excluded from WP. |
| `targets.<t>.units` | Proof pass rate per call-graph wave and per obligation class, from the coverage ledger. For `l3_frame`, also read each WP report's `frame_summary`: a unit is frame-error-free only when every assigns/loop-assigns/`\separated` goal is discharged and no missing-assigns warning fired (a full proof with an incomplete frame does not count). |
| `targets.<t>.modules_without_harness` | In-scope modules Eva never runs on: their units can only read as tool failures, so widen the harnesses or narrow the scope. |
| `targets.<t>.candidates` | Candidates by source, and how many await a verifier agent. |
| `targets.<t>.stages`, `wall_s`, `cpu_s` | Wall-clock per stage, measured on the host, and CPU from each container's cgroup. |
| `targets.<t>.phase3` | Only with `measure-llm`, below. |
| `limits`, `toolchain`, `machine`, `pipeline` | What produced the run. A changed limit warns, because those decide results. |

Every success rate is reported two ways, because they answer different questions:

- `over_decided`: successes over cases some tool decided.
- `strict`: successes over all cases, with every timeout or tool failure counted as a failure.

In the unit rates, a function Eva did not reach (`not_reached`) lowers only `strict`. A unit no phase attempted (`not_attempted`, such as a termination unit before WP) is listed but in neither rate.

## Reading the differences

| Severity | Meaning |
| :--- | :--- |
| `regression` | Worse. Exit code 1. Recall regressions print first. |
| `warning` | Look at it: the numbers moved in a way that may hide a loss. `--fail-on warning` makes these fail too. |
| `improvement` | Better, and nothing suggests the gain is an artifact. |
| `changed` | Different, neither better nor worse by itself. |
| `info` | Context. Printed with `--verbose`. |
| `not_compared` | One side has no data. Printed with `--verbose`. |

Fewer Unknowns counts as an improvement only if coverage held: the same properties and statements checked, no more Dead code, no more Considered valid, no weaker checks. Otherwise it is a warning. A filter that hides alarms, or a harness that reaches less code, does not look like a gain. If Eva stops flagging the line of a confirmed bug, that warns too, whatever the counts did. Eva counts have zero tolerance because they are deterministic.

What the numbers cannot tell you:

- **Fuzz campaigns are not seeded**, and a campaign's wall time depends on the workers its lease allows. What they find is reported, never scored. A unit a campaign turned into a candidate warns instead of counting as a lost proof.
- **Timeouts depend on machine speed.** An Eva or WP limit reached on a slower machine is a tool failure, not a verdict. Timings warn only beyond a tolerance on the same machine size.
- **Wall-clock includes queueing** when other jobs share the broker. CPU time does not.

## Known gaps in the stored baseline

Each of these is real behavior of the pipeline today. They show up in every comparison until fixed, and fixing one should read as an improvement:

- **`semver`: Eva does not start.** `-warn-unsigned-downcast` rejects the global initializer at `semver.c:23`, so its module reads `analysis_error`.
- **Eva stops early on `tweetnacl`, `qlz` and `cryptolib`.** An `Invalid` alarm ends the analyzed path, so most of the code is Dead: `tweetnacl` reaches 5 of 64 functions (an unsigned downcast in `ts64`), `qlz` 5 of 17 (`src - 2` pointer arithmetic), and `cryptolib` 22 of 234 (a self-overlapping `memcpy` during `Crypto_Init`). That is why `eva_site` reads `dead` for CRYPTOLIB-01.
- **`qlz_compress_core` has an Unknown and no ledger unit.** Braces left unbalanced by `#if` branches end `build_callgraph_dag.py`'s scan of `quicklz.c`, so every function from there on is missing.
- **`build_callgraph_dag.py` applies every `-D` it finds in a target's makefiles.** x509-parser's IKOS rule would break its builds, so a force-included header in the manifest undoes it.
- **x509-parser's fuzz builds fall back to the sanitizer engine.** E-ACSL rejects the target's own annotations (`unbounded ranges`, `x509-crl-parser.c:3313`) and cannot find `__fc_builtin.h`, which `x509-parser.c` includes under `__FRAMAC__`. Eva runs at `slevel 1`, as in the target's own Makefile, because the default exceeded 900 s.
- **Functions defined in headers have no ledger unit** (14 in QCBOR, 1 in minmea), so they get no prover either.
- **MINMEA-02's fingerprint differs from `docs/bugs-found`**, at the same site. The run summary names it.
- **Some campaigns abort without a crash artifact** (`fuzzer_error`, exit code -6, on `semver` and on CryptoLib's `crypto` and `sa`), so they leave no reproducer. On `semver` the log ends in E-ACSL's `Use of invalid address`.

## Phase 3 (optional, LLM-driven)

The deterministic run leaves each target's run directory ready for Phase 3 (`<work-dir>/runs/<run-id>/<target>/run-1`). Drive `/framac-wp` on it from an LLM host, then add its metrics to the run file:

```bash
python3 scripts/benchmark.py measure-llm --run-file run.json --target minmea --out run-llm.json
```

This adds per-wave function rates, stalls, dispatches, WP containers and goal counts. Tokens and exact prover iterations exist only if the host reports them through `--host-usage` (`{"agents": {"<id>": {"input_tokens": N, "output_tokens": N, "iterations": N}}}`); otherwise they stay null rather than estimated.

## A/B testing frame skeletons

The projected frame skeleton (`scripts/frame_skeleton.py`, facts schema 2) can be switched off per run with `FRAMAC_FRAME_SKELETON=off` (same pattern as `FRAMAC_PROVER_CONTEXT=off`), so an A/B run measures exactly the skeleton's contribution to `l3_frame` pass rates and to merge rejections, not the LLM's. Likewise `FRAMAC_LOOP_TEMPLATES=off` disables the loop templates/graph (facts schema 3) and `FRAMAC_SPEC_KB=off` disables the specification knowledge base (`scripts/spec_kb.py`).

## A/B testing prover briefs

[`../scripts/benchmark_briefs.py`](../scripts/benchmark_briefs.py) uses the 901 small assert programs of the spectool dataset (autobench, live24, live25). The dataset stays outside this repository and its path is always a parameter, because some file names look like student identifiers. [`../benchmark/briefs_sample.json`](../benchmark/briefs_sample.json) holds only content digests, so never add file names to it. The sample is 10 programs per corpus, ranked by a salted digest of their content, so moving or renaming the dataset does not change it.

The unannotated programs give a floor with no LLM: none of the 30 is proved in the stored baseline, so every program can tell briefs apart. It took 26 minutes, and `run --briefs-dataset <dir>` also stores it in the run file.

```bash
python3 scripts/benchmark_briefs.py control --dataset path/to/dataset
```

To compare briefs, write one task per program and arm, have an LLM host answer each `task.md` by writing `answer.c` (and optionally `usage.json`) next to it, then judge:

```bash
python3 scripts/benchmark_briefs.py prepare --dataset path/to/dataset --out ab --arm current=skills/framac-wp/prover_brief.md --arm candidate=path/to/new_brief.md
```

```bash
python3 scripts/benchmark_briefs.py judge --dir ab
```

The judge uses this pipeline's oracles, not the dataset's:

1. Pure ACSL: C tokens unchanged; no `admit`, `axiom` or vacuous `\false` (`acsl_ast.verify_acsl_only`).
2. Every annotation the program came with is still there. Deleting or weakening the assert is not a proof.
3. WP with `-wp-rte` and smoke tests on every defined function, through `run_wp_function.py` and its soundness gates.
4. A new value precondition on an entry function may define the problem away, so that proof counts as `proved_conditional`, not as a pass.

It reports each arm's rates both ways, per corpus, and the paired counts (programs only one arm proved), which are what a difference between arms should be judged on with a sample this small. The E-ACSL guardrail is not an oracle here, because these programs have no fuzz corpus: a wrong but consistent contract on an internal function can still pass.

## Adding a target

Add an entry to the manifest's `targets` with a full commit id, a `scope`, and one harness per module (named as `build_callgraph_dag.py` names it). Harnesses use `generate_harness.py`'s options, so `call_expr`, or `eva_expr` and `fuzz_expr`, say what Eva and LibFuzzer call. Files the harness needs go under [`../benchmark/assets/`](../benchmark/assets/). `python3 scripts/benchmark.py check-manifest` validates the result, and `run --target <id> --phase0-only` checks the harness without the analysis. Changing a target's harness, scope or tuning warns in the next comparison, because its counts are no longer like for like.
