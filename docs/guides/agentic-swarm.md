# Multi-Agent Swarm Architecture & Dual-Oracle Guardrail

This document explains:
- how the pipeline parallelizes verification across as many subagents and tool processes as the machine allows;
- how the **Dual-Oracle Guardrail** prevents LLM hallucination;
- how callers and callees negotiate contracts.

How resources are measured, leased and cached is in [`./resources-and-caching.md`](./resources-and-caching.md).

---

## 1. Levels of Parallelism

Concurrency is never a fixed number:
- The host broker leases CPUs and memory to every container from the measured pool.
- Each tool sizes itself from its lease.
- The scheduler hands out as many agent tasks as `resources.py recommend` allows, recomputed every round.

LLM subagents are used only where judgment is needed.

### Level 1: Module-Level Parallelism without Subagents (Phase 1 `/framac-fuzz` & Phase 2 `/framac-eva`)
Independent harness modules share no internal state during slice verification, and their fuzz and Eva runs need no reasoning. A harness module is a link unit of the build (`libqcbor_a`, the DAG's modules) or a sub-module of one (QCBOR has 8 harnesses inside `libqcbor_a`): a path module (the sources of one directory), a cluster of a unit too large for one Eva run, or a harness scoped by its sidecar's `scope_files` or `sources`. Make targets, reports and corpora are per harness module; the ledger groups functions by link unit (`scripts/module_map.py`).
- A generated Makefile (`pipeline_make.py`) runs them. Each recipe is admitted by CPU and memory inside one container per phase.
- Fuzzing (CPU-bound) and Eva (single-threaded, memory-bound) can run either **sequentially in the foreground** (giving standalone `eva` a writable `rw` `/framac-cache` mount) or **concurrently in the background** as two wrapper calls (where `eva` mounts `/framac-cache` read-only while `fuzz` runs target code). Ingestion keeps the fuzz-then-Eva order.
- Each campaign runs as many LibFuzzer workers as its lease allows. Builds and Eva results are cached by content, so a harness repair re-runs only what changed.

### Level 2: Speculative Header Decoupling (architects)
Bottom-up verification would otherwise have to wait for leaf functions before callers.
- A **Speculative Interface Architect Subagent** per `.h` header named by a harness sidecar (`header`; a unit whose harnesses name two headers gets two architects) ([`../../skills/framac-wp/header_architect_brief.md`](../../skills/framac-wp/header_architect_brief.md)) writes baseline `requires`, `assigns`, and `ensures` contracts.
- It validates them dynamically against the Phase 1 fuzzer corpus using `run_eacsl_fuzz.py guardrail`.
- Because `frama-c -wp -wp-fct <caller>` trusts the `.h` contract of any function `<callee>` it calls, a caller only waits for its callees' own provers, never for a global wave.

### Level 3: Dependency-Driven Function Provers (no waves)
`wp_scheduler.py` keeps a ready queue instead of global waves. A function's prover is dispatched as soon as all of these are done:
- its callees are merged (recursion cycles become ready together);
- the architects of its own unit and of every callee's unit (a leaf or static function that touches no module header skips them);
- the gate of every fuzz/Eva slice covering its file; a sub-module's open candidates hold only the functions in its own scope, and the callers whose call cone they lie in.

A callee that ends up without a contract the caller's proof can see (its prove task ended without one, or it has none) does not release the caller. The scheduler files a strengthening request itself (`origin: scheduler`, reason `caller needs a contract`), which opens `negotiate:<callee>` (Section 3), and the caller waits on that negotiation. When no negotiation can run (a crash candidate, a `shell_unverifiable_wp` function, a callee out of scope, a negotiation that ended without a contract or was refused by a cap), the caller is tagged `callees_without_contract`: it is dispatched after every untagged ready task, and its brief ends with a "Calls Without a Contract" section.

Every prover brief also gets a section "How the Callers Use This Function" (`workspace_overlay._caller_usage_section`), so that the contract states what the callers need and not only what the body does. For each direct caller in `callgraph_dag.json` (`internal_callers`), the section shows the first textual call of the function and the lines after it, at most `CALLER_USAGE_LINES_AFTER` (4) and never past the caller's body, read from `workspace/work/`. It shows at most `CALLER_USAGE_MAX_CALLERS` (6) callers and says how many it left out; a caller over the limit and one that calls through a pointer or a macro (no call by name in its body) count as not shown. Comments, string literals and ACSL in the caller are not searched. A function with no caller in the DAG gets a sentence naming it an API entry point. The brief asks the prover to write the `ensures` the callers rely on, treats a postcondition no caller uses as optional, and, when a caller expects what the body does not give, to report a `fault_hypothesis` rather than write the contract around the body. Rule 3 is unchanged: call sites never justify a `requires`. The section is judgment input only: no script checks a contract against it.

A prover brief then gets "Proven Contracts Near This Function" (`workspace_overlay._proven_examples_section`) once a function near it is proven: up to `PROVEN_EXAMPLES_MAX` (2) contracts of functions whose latest WP report (`load_function_wp_report`) is `all_proven`. Candidates are the direct callees (distance 0), then the other callees of the function's direct callers (distance 1); at the same distance a contract whose `limits.contract_shape` is `functional` comes before any other, then DAG order. Each contract is read from `workspace/work/` as Frama-C merges it (definition and the headers the file includes) and inlined with its declarator, cut at `PROVEN_EXAMPLE_MAX_LINES` (30) lines. Nothing is rendered when none is proven. The pointer to the vendored `wp_gallery` examples stays in the brief.

Ordering and merging:
- Functions with the longest chains of callers waiting on them go first, so the critical path starts early. Provers tagged `callees_without_contract` come after all of them.
- Inside each prover's WP run, `-wp-par` follows the lease (min of CPUs and memory at the fixed 1000 MB prover limit).
- Finished provers are merged in micro-batches. Their parent re-checks run in parallel, one WP job per function.

### Level 4: Adversarial Prover-vs-Breaker Dual-Play
When a Function Prover Subagent fails to prove a specific RTE or security assertion after `K` retries (default `K = 4`):
- The scheduler queues an **Adversarial Breaker Subagent** ([`../../skills/framac-wp/breaker_brief.md`](../../skills/framac-wp/breaker_brief.md)). Callers of the stalled function are released immediately: the breaker never blocks them.
- No task waits on a breaker, so it would rank below every ready prover. A quarter of each round's dispatch slots (at least one) is therefore reserved for ready breakers; reserved slots no breaker needs go to the normal order.
- The Breaker analyzes the exact unproven assertion and synthesizes surgical binary seed inputs for `E-ACSL + LibFuzzer` to trigger a runtime crash at that line.
- A crash becomes a candidate for an independent Crash Verifier. It reopens the gates of the slices it affects, so no further proof work starts on code that may be broken.

---

## 2. The Dual-Oracle Anti-Hallucination Guardrail

A fundamental hazard of using LLMs for formal verification is **vacuous truth**: in classical logic, `False ==> Anything` is `Valid`. An unconstrained LLM trying to satisfy `frama-c -wp` might accidentally write an overly restrictive or contradictory precondition such as:
```c
/*@ requires len == 0; */ // Or: requires len < 0 && len > 0;
```
Under that precondition, `frama-c -wp` will report `100% Valid` on every goal inside the function—even if the function contains a blatant buffer overflow when `len > 0`!

### How the Pipeline Prevents Vacuous Contracts

Every single iteration of the Function Prover Subagent ([`../../skills/framac-wp/prover_brief.md`](../../skills/framac-wp/prover_brief.md)) and Interface Architect Subagent ([`../../skills/framac-wp/header_architect_brief.md`](../../skills/framac-wp/header_architect_brief.md)) must pass **two orthogonal oracles** in sequence:

1. **Oracle 1 — The Dynamic E-ACSL Oracle (`run_eacsl_fuzz.py guardrail`):**
   Compiles the newly proposed ACSL annotations (`requires`, `ensures`, `loop invariant`, `assert`) into executable C checks via `e-acsl-gcc` (the same build as Phase 1 fuzzing: instrument with `-n`, full memory tracking, runtime init hook) and replays the module's valid fuzzer corpus (plus 100–200 additional mutations).
   - If *any* real input violates the proposed `requires` or `loop invariant`, the annotation is **immediately rejected as `rejected_overconstrained`**, and the exact failing variable values from the runtime stack trace are fed back to the subagent.
2. **Oracle 2 — The Static Deductive Oracle (`run_wp_function.py`):**
   Only after a contract holds on 100% of real dynamic executions is it passed to `frama-c -wp -wp-rte -wp-fct <fn>` to prove that it holds mathematically across *all* possible inputs.
   - It proves under WP's `Typed` memory model. When that run is not `all_proven` and is held back only by WP's union warning or by byte-wise goals (`memcpy`-style preconditions, pointer casts), it retries once under `Bytes` and keeps that result only when it is sound and strictly better (report field `bytes_retry`). `--no-retry-bytes` or an explicit `--wp-model` turns the retry off.
   - Only `Typed` and `Bytes`, with the options `nocast`, `raw`, `ref`, `int` and `float`, count as evidence. A proof under any other model or option (`Hoare`, `Region`, `+cast`, `+nat`, `+real`) is `unsound_proof`: the merge refuses it and the ledger never credits it. The parent re-check replays only an accepted model, and the ledger records a `Bytes` proof with the assumption that it rests on that experimental model.

### Comparing Contracts by Meaning (Contract Refinement Probe)

[`../../scripts/contract_refinement.py`](../../scripts/contract_refinement.py) decides whether a contract A refines a contract B of the same function `f` by one WP run, not by reading clause names. It writes a probe file outside `workspace/work/` (a temporary directory, or `--keep-dir`, which may not lie under the work tree) holding `#include "<f's source>"`, a declaration `f__given` carrying A and a definition `f__probe` carrying B whose body is the single call `f__given(<parameters>)`, and proves `f__probe` without RTE. Every goal proved means B's `requires` imply A's and A's `ensures` and `assigns` give B's. Each `requires` and `ensures` gets a name `fcprobe_<n>` so a goal maps back to the clause as written (file, line, kind, text); a contract split over a header prototype and the definition is emitted as one declaration per piece, which Frama-C merges as it does for the real file.

- **Verdicts:** `refines`; `weaker`, with the clauses left unproved; `undecided`, which is never read as either. A clause counts as not given only when WP prints a counter-example model for its goal (`-wp-counter-examples`). Measured in `framac-analysis:latest`: a false implication comes back `[Unknown] (CVC5) (Model)` within a second, while a true but hard one (an unbounded nonlinear identity) times out with `(No Model)`; without counter-examples both read `[Timeout]`. A goal left unproved without a model, an unproved goal that is none of the compared clauses, a run with no goal proved, a parse failure and a timed-out run are `undecided`. A model is the solver's candidate, which WP does not check, so a `weaker` verdict on a quantified clause can still be wrong.
- **Constructs it cannot carry (`undecided`):** a variadic prototype, an unnamed formal in the definition, a K&R definition or a nested declarator (a function returning a function pointer), and a compared contract without `assigns`, whose frame the kernel would generate. Static functions and structures passed by value work.
- **Fixed limits:** provers Alt-Ergo, Z3 and CVC5, a 3 s per-goal timeout (`PROBE_GOAL_TIMEOUT_S`) and a 180 s wall limit, whatever the machine; only `-wp-par` follows the job budget.
- **CLI:** `contract_refinement.py compare --file new.c --previous-file old.c --function f` and `contract_refinement.py frame-only --file f.c --function f` (which `ensures` follow from the `requires` and `assigns` alone), both with `--cppflags` and `--out-json`.
- **Cost, measured in `framac-analysis:latest`:** about 0.6 s when every goal is proved, about 3.9 s when a goal is refuted (the 3 s per-goal timeout of the other provers, then the model).

Two places use it:

- **Merge re-check** (`workspace_overlay.record_contract_refinement`). A prover merge that replaces a contract reads the contract before the splice, and once the parent WP re-check has passed it compares the merged contract against it. Single and batch merges both do it; a batch compares after its round passes. The verdict goes into the parent WP report as `contract_refinement` (`verdict`, `reason`, `clauses`, `elapsed_ms`, `probe_run`). It never rejects the merge, because the scheduler already re-checks merged callers when a contract changes: `_on_merged` queues a re-check of every merged caller and recursion-group peer (`_queue_rechecks_for`), and `_apply_recheck` reopens a caller whose parent WP re-check fails and blocks its units. A `weaker` verdict also queues those re-checks when no file was reported modified, and the re-check reason names the clauses the new contract no longer gives. `undecided` (including a probe that failed to run) is recorded and changes nothing. A first contract (nothing merged before) records nothing; an unchanged contract is `refines` without a probe run. The comparison runs while the merge lock is held, after the re-check, and a batch runs its comparisons one after the other. Each costs about 1 to 4 s (180 s at most), and other merges wait for it. The probe uses the default machdep (`gcc_x86_64`), as the parent re-check does. It makes the relative paths of `-I`, `-iquote`, `-isystem`, `-idirafter`, `-include` and `-imacros` absolute against the caller's working directory, because it runs from its own temporary directory.
- **Frame-only postconditions** (`limits.frame_only_ensures`, see [`./v2-design.md`](./v2-design.md)). An `all_proven` WP result also asks which `ensures` follow from the `requires` and `assigns` alone. `REPORT.md` then counts a function whose every `ensures` is frame-only as `safety_only`, whatever its syntactic `contract_shape`.

### Per-Goal Solver Cost (`FRAMAC_WP_GOAL_COSTS`, on by default)

Every WP run also writes WP's own JSON report (`-wp-report-json`, file `wp_<fn>[suffix].wp-report-json` next to the CSV; not `.json`, because `spec_kb.py` and `mutation_check.py` read every `wp_*.json` there as a result object), and [`../../scripts/run_wp_function.py`](../../scripts/run_wp_function.py) adds these fields to its result:

- `unproven_goal_costs`: one object per goal WP reports as not proved, keyed by the WP goal name (the report CSV has no goal name): `{"goal", "property", "file", "line", "verdict_kind", "provers", "time_ms", "cached"}`. `verdict_kind` is `timeout`, `stepout`, `unknown` or `failed`; `property` is WP's property name from the JSON report, and `file` and `line` are where WP reports the goal (all three null when the entry comes from the log). `property` is a name such as `f_assert_rte_signed_overflow_3`, not the predicate text in `unproven_goals[].annotation`, so a goal and its report row are paired through the line and the kind (`scripts/wp_residual_census.py` does this and marks what it cannot pair `unjoined`); `provers` are prover names without their version; `cached` is true when WP took the result from its cache.
- `slowest_proved_goals`: at most five `{"goal", "prover", "time_ms"}`, slowest first, cached results left out, so a goal proved close to the timeout is visible before it flips.
- `goal_costs_source`: `report_json`, `log` (the JSON report was missing or unreadable, so the entries come from the `[wp] [<Verdict>] <goal> (<tags>)` log lines), or null. The result also records `wp_timeout_s` and `wp_provers`, which the hints read.

What WP 34 gives, measured in `framac-analysis:latest`: a proved goal carries the time of the prover that proved it. An unproved goal carries one merged prover entry whose time is a 0 placeholder, so its `time_ms` is null; WP ranks a Timeout above an Unknown when it merges several provers. The log carries no solver time, and under `-wp-cache update` it tags a result `(Cached)` even on the run that first fills the cache, so a log-sourced entry never has a time. The parser fails closed: an entry without a goal name, a smoke goal, another function's goal or a verdict outside the four kinds is left out, and a field it cannot read stays empty or null.

`scripts/wp_residual_census.py` (read-only, over a finished run's `reports/wp/`) also counts the unproved goals per prover: `totals.unproved_by_prover` gives, for each prover, how many goals it timed out on (`timeout`, timeout or stepout), gave up on (`gave_up`, unknown) and failed on, and each function record carries `by_prover`. Because WP merges the provers' verdicts into one entry per unproved goal, a goal is attributed only when its report's `wp_provers` has exactly one prover. Every other goal, and every row of a report without `unproven_goal_costs`, counts in `unproved_without_prover_data`, which the notes and the table state. The census changes no prover list and no timeout. On a run with the default three provers every goal falls in `unproved_without_prover_data`, so a per-prover comparison needs single-prover reports.

`derive_wp_diagnostic_hints` adds two hints from these fields, read against fractions of the run's `-wp-timeout` (`UNKNOWN_FAST_FRACTION` 0.5, `TIMEOUT_REACHED_FRACTION` 0.9; a cached time is never used, and the Degenerated function-pointer goals the result assumes are left out):

- every unproven goal is `unknown`, with no measured time above half the timeout: the provers gave up before the limit, so the goal is probably false or missing a fact. Read the sequent with `--prop <clause> --dump-goal` and check the claim with the guardrail before strengthening. Not on a counter-example run, where an Unknown with a model outranks a Timeout.
- every unproven goal is `timeout` or `stepout` and only one prover was configured: the goal may be true and too large, so isolate it and reduce what it depends on. With several provers, the merged Timeout does not say what the other provers answered (a false goal read `[Timeout] (Alt-Ergo)` with three provers while CVC5 alone answered Unknown), so this hint does not fire.

`FRAMAC_WP_GOAL_COSTS=off` removes the two hints and keeps the fields, for A/B comparisons. Neither changes the tail retry or any timeout.

### The Best Candidate, Not the Last

Both oracles record each iteration in the prover's scratch directory ([`../../scripts/prover_candidates.py`](../../scripts/prover_candidates.py)). Candidates that pass the guardrail are ranked by fewest unproven goals, then most proved goals. Only those compete, because a stronger `requires` can raise the proof ratio by excluding inputs. Clauses the prover added that hold whatever the code does (`\true`, `x == x`, `0 <= 1`; `acsl_ast.is_trivial_predicate`) earn no credit: a candidate with fewer of them wins a tie, and their goals are subtracted from the proved count (`FRAMAC_CANDIDATE_RANK=legacy` restores the plain count). The tracker tells the prover to stop when an iteration improves neither number. Before a stalled prover's report and partial contract are used, `wp_scheduler.py complete` restores its best candidate.

A candidate that adds a top-level ACSL declaration outside the prover's function (a file-scope `/*@ ghost ... */` function, a `predicate`, a `lemma`) is never ranked: `merge-agent` would refuse the whole patch. The tracker diffs the declarations of `scratch/work` against `scratch/base` after every oracle run and lists them as `scope_violation_pending` in the first `candidate` block, with `next_synthesis_focus: "remove_top_level_acsl_declarations"`. A prover whose goal needs an inductive lemma stops with `proof_gap.reason` starting `inductive lemma required`; the ledger tags it `gap_kind: "inductive_lemma_required"` and `REPORT.md` counts those functions ([`../plans/formal-discovery/tier-3-rule3-ghost-lemma.md`](../plans/formal-discovery/tier-3-rule3-ghost-lemma.md)).

### What a Prover Starts From

The deterministic side prepares what a prover would otherwise have to work out by reading code:

- **Function facts** ([`../../scripts/function_facts.py`](../../scripts/function_facts.py), Make target `facts`, cached by content):
  - From the Frama-C kernel AST ([`../../scripts/kernel_ast.py`](../../scripts/kernel_ast.py)): loops with their guard and updated variables, writes and reads in terms of formals and globals, possibly aliased pointer parameters, recursive calls with their decreasing argument, and return paths.
  - From the module's Eva run ([`../../scripts/run_eva_slice.py`](../../scripts/run_eva_slice.py)): write and read sets, and resolved call targets. A large `flows` section is spilled to `workspace/eva/<mod>/flows.json` (also by `eva_tuning.py`), and the report keeps a `flows_file` pointer to it. When that file is missing or unreadable, `function_facts.py` writes a `status: "failed"` facts document naming it and exits 1, so no brief is built from facts without their Eva data.
  - Briefs load only facts of the current schema, so facts written by an older pipeline version are left out until `facts` runs again.
- **A reading slice** ([`../../scripts/function_slice.py`](../../scripts/function_slice.py)): the target's body, callee prototypes with their current contracts, and only the types, macros and globals the target references, resolved with the real compile flags. It is built from the agent's snapshot and is reading context only. The proof target stays the real file, because a slice can differ from the compiled program.
- **A brief assembled for the function:** string, float, union and pointer-walking guidance, and similar parts, appear only for functions with those features. Every strict rule stays. Without facts, the whole brief is rendered.

A function may not reach a prover at all: when an earlier run's `wp-sweep` published its contract and the inputs it depends on are unchanged, `wp-replay` re-applies that contract (with its loop annotations) through the parent merge and re-proves it on the current tree before the scheduler is initialized ([`../../scripts/proof_carry.py`](../../scripts/proof_carry.py); [`./resources-and-caching.md`](./resources-and-caching.md#5-caches), Section 5). Units it credits never become prove tasks; a rejected or missing proof leaves the function to its prover as before.

These are hints. Eva's locations hold only under the harness (`a[0..15]`, not `out[0 .. n - 1]`), so the prover restates them over the formals, and WP remains the only judge of `assigns`.

### Loop Invariant Seeds (`FRAMAC_LOOP_SEEDS=on`, off by default)

Eva does not hold the index-against-length relation at a widened loop head ([`../plans/papers-generalization-plan.md`](../plans/papers-generalization-plan.md), Tier 1, "Step 0 result"), so loop invariant candidates come from the loop facts and are filtered by the two oracles ([`../../scripts/loop_seeds.py`](../../scripts/loop_seeds.py)):

1. **Syntactic candidates**, over the function's own formals and locals:
   - `0 <= i` for a signed counter (a scalar whose every update is `i + k` or `i - k`);
   - `i <= bound` for each header condition that compares a counter with an operand the loop does not write, and the guarded form `0 <= bound ==> i <= bound` when the counter is signed (with a signed `len`, `i <= len` fails establishment);
   - for a pointer walker, its anchor on the formal it starts from (`\at(p, Pre) <= p`, same `\base_addr`) and its end bound;
   - in a nested loop, the enclosing loops' guards and candidates that the inner loop leaves alone, because WP forgets them across an inner loop without `loop assigns`.

   A literal bound is kept only when the literal is written in the function's source, so a harness buffer size or a macro's value never becomes a candidate.
2. **Houdini with WP.** All candidates go into a private copy as `loop invariant seed_<n>: ...;` and only those goals are proved (`-wp-prop`). A candidate WP cannot establish or preserve is dropped, and the rest is proved again until a round drops nothing (at most 6 rounds). Survivors are inductive under the function's current contract and loop annotations. The report says, for each dropped candidate, whether establishment or preservation failed.
3. **Corpus filter.** The candidates WP dropped are compiled as E-ACSL checks with the guardrail's build and replayed on the Phase 1 corpus, without mutation. An input that falsifies a candidate is recorded with it. A candidate no input falsifies is reported as "held on every replayed corpus input, not proven": a hint, never a clause to paste.
4. **No-harm check.** Proven seeds are true, but more hypotheses can make a solver miss another goal (measured on a nested loop with a nonlinear index). The tool runs every goal of the function once without seeds and once with the proven ones. A seed set that loses a goal is reduced by leaving out one seed of the loop the goal sits in, or withheld entirely, and the report lists those seeds as "Proven, but withheld". When the check cannot run, nothing is withheld and the report says the seeds were not checked. It adds two full WP runs per function.

WP runs first because it is the cheaper filter: measured on toy functions, a round on the seed goals costs about one second when nothing fails and about six when a goal times out (the per-goal limit is 5 s), and an E-ACSL build and replay costs about two. A proven candidate needs no corpus check, so the build is paid only for what WP dropped.

**Where it runs.** The prover runs the tool itself, as the first item of Step B, on its scratch overlay. That is the point where the function has the contract and `loop assigns` the seeds are proved under, and where the callees' contracts are already merged. It needs no new task kind and no work under the scheduler's locks. The tool writes nothing but its report (`agents/<agent-id>/scratch/loop_seeds_<function>.json`), works on a copy outside the agent's tree, and never adds a `requires`. `wp_scheduler.py complete` copies the report to `workspace/reports/loop_seeds/<module>/<function>.json`, so the parent stays the only writer outside the scratch overlay and the ledger is not involved. A failure or a timeout only loses hints: the report's `status` says so (`ok`, `partial`, `timeout`, `no_facts`, `no_loops`, `no_candidates`, `disabled`, `error`), and no unit status depends on it. `FRAMAC_PROVER_CONTEXT=off` removes the seeds together with the facts.

---

## 3. Caller-Callee Contract Negotiation

When Caller Function `B` calls Callee Function `A`, `B`'s WP proof may fail because `A`'s `.h` header contract only states:
```c
/*@ ensures \result >= -1; */
int parse_ber_length(const uint8_t *buf, size_t max_len);
```
whereas Caller `B` needs to know that `\result <= (int)max_len` to prove that advancing `buf + \result` stays in bounds.

Instead of allowing Caller Subagent `B` to edit Callee `A`'s contract directly (which could break `A`'s proof or cause race conditions between parallel subagents), `B` lists the clause it needs in the `strengthening_requests` of its result. The parent records it when it completes `B` (`wp_scheduler.py complete`), through [`../../scripts/contract_negotiator.py`](../../scripts/contract_negotiator.py); the record is equivalent to:

```bash
python3 /opt/framac-pipeline/scripts/contract_negotiator.py request \
  --caller snmpv3_parse_pdu \
  --callee parse_ber_length \
  --callee-file src/snmp/ber_decode.c \
  --header-file include/ber_decode.h \
  --needed-clause "ensures \result <= (int)max_len;" \
  --reason "Required by snmpv3_parse_pdu to prove \valid_read(buf + offset + \result)"
```

As soon as the request is ingested (`wp_scheduler.py complete`), the scheduler emits a `negotiate` task for `A`. Requests are capped per caller/callee pair, and `A`'s negotiate task is dispatched at most 3 times (`MAX_NEGOTIATION_ROUNDS_PER_CALLEE`, follow-up rounds, requeues and retries included). `B` is requeued once the request is resolved. The scheduler files such a request itself when a callee has no contract the caller can see (Section 1, Level 3). The negotiation runs as follows:
1. The orchestrator dispatches Callee Subagent `A` to evaluate the requested `ensures \result <= (int)max_len;` clause.
2. Subagent `A` tests the stronger clause against **Oracle 1 (`E-ACSL guardrail`)** and **Oracle 2 (`WP` on `parse_ber_length`)**.
3. **Outcome 1 (True in `A`):** Both oracles pass. Subagent `A` returns the stronger `ensures` clause in its scratch patch; the parent merges it into `include/ber_decode.h`, re-verifies it, marks the request `verified_and_applied`, and requeues Caller `B`.
4. **Outcome 2 (False in `A`):** `parse_ber_length` does *not* actually enforce `\result <= max_len`! That immediately reveals either a missing bounds check inside `parse_ber_length` or a missing bounds check in `snmpv3_parse_pdu`.

A request `A` could not prove (`rejected_by_callee`) is a dead end for every later caller of `A`: the brief of any prover or breaker whose function calls `A` lists it under "Known Dead Ends (Do Not Repeat)" with the callee's note, so no other caller asks for the same clause again ([`../../scripts/spec_kb.py`](../../scripts/spec_kb.py), `obstructions_section_for`). The scheduler's structural rejections (`not dispatched: ...`: callee not found, caps reached, callee not provable) say nothing about the clause and are not listed. That prefix is kept for requests no negotiate agent was handed: a request closed after it was assigned (a round refused at its re-dispatch, for example by the cap) is noted `closed after dispatch to <agent>: ...` and is listed. The same section lists the clauses the E-ACSL guardrail refuted on this function in earlier dispatches, which a re-dispatched prover (a fresh agent id) would otherwise not see.

**Seam evidence in the negotiate brief.** Subagent `A` gets more than the raw clause. Under the JSON block of the requests, `workspace_overlay.py prepare-agent` appends `### Why the callers stalled (seam evidence)`: for each caller, the WP report it stalled on (the report promoted from its latest agent, `agents/<id>/artifacts/wp_<caller>.json`, else the canonical `workspace/reports/wp/<caller>.json` when its `file` is the caller's own, else the baseline's report of the caller's file, `workspace/reports/wp/work/<file slug>_<caller>.json`) and at most 12 of its unproven goals at the seam (bucket `step_c_caller_precondition` or `step_c_contract_postcondition`, or an annotation naming `A`), each with line, kind, verdict and bucket. Then `### Your function's previous prover run` summarizes `prover_candidates.status` of `A`'s last prover scratch (iterations, best rank, last WP and guardrail statuses), so `A` does not retry a clause its own guardrail already refuted. `wp_scheduler.py` collects both in `_prepare_kwargs` (`_caller_evidence`, `_callee_history`); a missing or corrupt report leaves the caller's goal list empty and never blocks the dispatch, and `next` / `status` show the goal count as `caller_evidence_goals`. `FRAMAC_NEGOTIATE_EVIDENCE=off` drops both subsections for A/B runs. The scheduler's negotiation state machine is unchanged.

**Baseline reports.** `wp_scheduler.py baseline` writes each task's WP report to `workspace/reports/wp/work/<file slug>_<function>.json`, keyed by file and function like its work directory, and records that path in the task's `baseline.report`. Its "already proven" test reads only a report whose `file` and `function` are the task's own. The name-only `workspace/reports/wp/<function>.json` that older readers glob is published from it only for a function name that no other file of the queue or the ledger defines (a `static` helper of the same name in two files has none; a merge publishes it under the same rule). `ledger.py ingest-wp workspace/reports/wp/*.json` and the other non-recursive `*.json` globs of that directory do not see the per-file reports; the baseline ingests its own proven reports itself.
