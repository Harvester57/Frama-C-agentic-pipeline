# External Frama-C Projects: Assessment & Ranked Improvement Plan

This document assesses ten public projects built on or around Frama-C for what they can improve in the pipeline ([`../guides/architecture.md`](../guides/architecture.md), [`../guides/agentic-swarm.md`](../guides/agentic-swarm.md)), and sets out an improvement plan **ordered by expected value**. It follows the format of [`./papers-generalization-plan.md`](./papers-generalization-plan.md) and [`./harness-and-spec-papers-generalization-plan.md`](./harness-and-spec-papers-generalization-plan.md): Tiers 1, 3 and 4 start with a Step 0 measurement and a stop rule, and nothing of theirs is built before Step 0 says go. Tier 0, the flag table of Tier 2 and the stub mutant of Tier 5 are small enough to go without one.

**Result in one paragraph.** None of the ten is worth running as a tool inside the pipeline. Three are worth mining: `sysprog21/frama-c-mcp` for its list of ways a green WP run is not a proof, `evdenis/acsl-skills` for about ten specification patterns, and `evdenis/verker` as a worked design for the shared lemma library (Tier 7 of [`./formal-discovery-plan.md`](./formal-discovery-plan.md)). The other seven rate low or none. Reading them also showed four defects in the pipeline's own briefs, hints and Phase 0 gates; they are recorded in [`../troubleshooting/`](../troubleshooting/README.md) and listed in Section 3.1.

Limits on the reading and on the checks:

- **Read:** one subagent per project read the README, the file tree and the source behind the main mechanism through the GitHub API. Nothing was cloned, built or run, so every statement about compatibility with Frama-C 34 is unverified.
- **When:** nine projects were read on 2026-11-14 and verker on 2026-11-20. `frama-c-mcp` and `acsl-skills` have had commits since (their heads were `4b935a0` of 2026-11-18 and `4f913e2` of 2026-11-19 on 2026-11-20); those commits were not read. verker was read at `8d27577`.
- **Spot-checked by the parent:** the claims behind the three medium verdicts. For `frama-c-mcp`: its dropped-flag table (`src/mcp/project.rs`), its plugin's version bounds, and the absence of the same flags in this repository. Also three of its fixtures at `4b935a0` (`decorative-contract.c`, `recursive-logic-unsound.c`, `generated-callee-spec.c`): each is self-contained and has a named target function. For `acsl-skills`: its licence, its file list, its limitation rows C-2 and C-11, the 335-to-311 figure of Tier 5, and that `frama-c-mcp`'s `docs/writing-acsl.md` cites it. For verker: that `src/strlen.h` defines `strlen` and `valid_str` without an axiom and proves the inductive facts as ghost functions with `decreases`, that the Makefile derives the proved set from the README table, and the two commits that removed false lemmas (`1c6ef2e`, `8dad88a`).
- **Overlap with the pipeline:** nine reports compared against the tree of 2026-11-14. On 2026-11-20 the recommended items were checked again against `main` by `git grep`: the compiler flags and parse-warning categories, the WP model list, the stub mutants, a descent check for recursive logic definitions (none in [`../../scripts/acsl_ast.py`](../../scripts/acsl_ast.py) or [`../../scripts/kernel_ast_dump.ml`](../../scripts/kernel_ast_dump.ml)), and the briefs' wording for the Tier 3 patterns. That check changed three things. `+nat` and `+real` WP models are already refused (`wp_model_problem` in [`../../scripts/framac_common.py`](../../scripts/framac_common.py)). Postconditions that say nothing are already detected by meaning (`frame-only` in [`../../scripts/contract_refinement.py`](../../scripts/contract_refinement.py)). The prover brief already asks pointer-advancing parser helpers for "base-preservation and offset-progress postconditions", so the `progress` pattern of Tier 3 is partly present. The other Tier 3 patterns were compared by the subagent on 2026-11-14 and by keyword only on 2026-11-20 (`untouched`, `\result \from` and `-wp-no-init-const` do not occur in the briefs).
- **Not done:** verker's two worked examples were paraphrased by the subagent, not quoted. No independent challenger was run on this plan.
- **Measured:** one number, for Tier 2: the six `build_capture.json` files on disk under `C:\Users\Florian\framac-pipeline\` (c-ares run-2, nginx 1.31.9 run-1 to run-5) contain none of the flags that tier is about.

---

## 1. What each project is

| Project | Licence | Supports | What it really is | Verdict |
| :--- | :--- | :--- | :--- | :---: |
| [sysprog21/frama-c-mcp](https://github.com/sysprog21/frama-c-mcp) | MIT | Frama-C 32.1+, tested on 33.0 | A Rust MCP server and an OCaml plugin driving one live Frama-C. Its core is a `check` verdict that is `proved` only when a list of about 50 `incomplete[]` codes is empty; each code names one way a green run is not a proof. About 80 single-trap C fixtures test the codes | Medium |
| [evdenis/acsl-skills](https://github.com/evdenis/acsl-skills) | MIT | Measured on 33.0 | Five agent skills and 18 reference files of WP experience, each statement tagged as reproduced, read in the WP source, or from the manual. Its sources are ACSL by Example, verker and the ANSSI x509-parser | Medium |
| [evdenis/verker](https://github.com/evdenis/verker) | GPL-3.0 | 33.0 | 44 Linux `lib/string.c`-style functions with contracts; 35 proved on stock WP after AstraVer was removed in September 2026. Logic functions are defined, not axiomatised, and inductive facts are ghost C functions that WP proves and the body calls | Medium |
| [rse-verification/auto-deduct](https://github.com/rse-verification/auto-deduct) | GPL-2.0+ | 33.0 | A Python driver running saida, then ISP, then one whole-file WP run, on one translation unit with a hand-written entry contract | Low |
| [rse-verification/saida](https://github.com/rse-verification/saida) | GPL-2.0+ | 33 (`< 34`) | A wrapper around the TriCera Horn-clause model checker that pastes inferred helper contracts back by line number. No pointer arithmetic, no reinterpreting casts, one file | Low |
| [rse-verification/interface-specification-propagator](https://github.com/rse-verification/interface-specification-propagator) | GPL-2.0+ | 33 (`< 34`) | Runs Eva from one entry point and writes its intervals as `requires` and `ensures` on the helpers. Skips loops and pointer arithmetic | Low |
| [stanleyngugi/formally-verified-code-rl](https://github.com/stanleyngugi/formally-verified-code-rl) | Apache-2.0 | 33.0 | 64 loop-free textbook functions with a fixed contract; the model writes the body | Low |
| [ThalesGroup/frama-c-lsp](https://github.com/ThalesGroup/frama-c-lsp) | LGPL-3.0 (headers say GPL-3) | 32.1 | Each editor request spawns a cold Frama-C run. No hover, definition or completion on `main` | None |
| [rse-verification/VerNFR](https://github.com/rse-verification/VerNFR) | GPL-2.0+ | 33 (`< 34`) | A coding-guideline checker for automotive modules (call allowlist, static globals, no function pointers). No timing, stack or resource property | None |
| [rse-verification/SpecSmith](https://github.com/rse-verification/SpecSmith) | none | unpinned | A 2025 fork of VeCoGen that asks a model for ACSL on one toy function. No problem set, no results | None |

**One lineage, not three votes.** `frama-c-mcp`'s documentation cites `acsl-skills` for its triage ladder and loop advice, and `acsl-skills` names verker as a source. Lemma functions and the negative result on casts therefore come from one line of experience, measured again by a second author on Frama-C 33.

**Licences.** This repository has no licence file. MIT text and fixtures can be copied with their notice. GPL text (verker, the rse-verification plugins) is not copied: the plan ports ideas in the pipeline's own words and cites the source.

---

## 2. Mapping onto the pipeline

| Open problem in the pipeline | What the projects give |
| :--- | :--- |
| Shared lemma and predicate library (Tier 7) | verker: a working design on stock WP (defined logic functions, intro / elim / shift lemmas, ghost lemma functions). `acsl-skills`: the naming scheme for lemma families and the lemma-function recipe. Nothing can be dropped in: verker is GPL, its names collide with Frama-C's `strlen` and `strchr`, and the prover brief forbids the construct |
| Trivial contracts detected by text only | Already narrowed by `contract_refinement.py frame-only` and the stub mutant of `mutation_check.py`. New and small: a `return <parameter>` stub mutant (`frama-c-mcp`), and a check that a recursive `logic` definition descends (`frama-c-mcp`, `acsl-skills`) |
| WP cast blocker (libmnl) | **Nothing.** `acsl-skills` (row C-2) and `frama-c-mcp` both report byte reinterpretation timing out under `Typed`, `Typed+cast`, `Typed+nocast` and `Bytes` alike. Their only routes are a verified core with an unverified shell, or Eva discharging the goal. This agrees with the pipeline's own result |
| A source of relational loop invariants | No generator. `acsl-skills` has hand patterns (Tier 3). TriCera's `-inv` prints integer loop invariants and could feed [`../../scripts/loop_seeds.py`](../../scripts/loop_seeds.py); kept as a watch item |
| Callee contracts without a model | saida, ISP and auto-deduct do this for scalar, global-state code only, and their contracts are fitted to one call context. ISP's ranges are the harness-bound Eva intervals that the Tier 1b trial of [`./papers-generalization-plan.md`](./papers-generalization-plan.md) already rejected |
| The analysed program is the compiled one | `frama-c-mcp`: a table of compiler flags that change meaning and that Frama-C does not read, and a count of what the parser dropped (Tier 2) |
| Content for the spec KB and the prover brief | `acsl-skills` (Tier 3) |
| Benchmark with ground truth | verker is the only candidate, with caveats (Decision D1) |
| Properties beyond Layers 1 to 6 | Nothing. VerNFR has no resource property |

### 2.1 Verified gaps

1. **Semantic compiler flags are not seen.** Every analysis runs under the fixed `-machdep gcc_x86_64`. The capture's architecture guard covers `-m32`, `-mx32`, `-m16` and `--target=`; no script mentions `-fwrapv`, `-fno-strict-overflow`, `-funsigned-char`, `-fshort-enums`, `-fpack-struct`, `-fshort-wchar` or `-funsigned-bitfields` (`git grep` over `scripts/`, `templates/`, `skills/` and `wrappers/`, 2026-11-20). Recorded as an open gap in [`../troubleshooting/phase0-build-and-model.md`](../troubleshooting/phase0-build-and-model.md).
2. **What the parser drops is not counted.** No gate counts Frama-C's `kernel:asm:clobber` or `kernel:attrs:unknown` warnings per link unit (same grep).
3. **The verdict gate has never been run against someone else's traps.** The soundness scan of [`../../scripts/run_wp_function.py`](../../scripts/run_wp_function.py) was written from the pipeline's own runs and audits. `frama-c-mcp`'s fixtures are an independent set of small programs, each built to make WP report success for a wrong reason.
4. **The prover brief recommends an idiom that `acsl-skills` reports as not provable.** Row C-11 of its `skills/frama-c-wp/references/limitations.md` says WP does not derive `p == q + (p - q)` and that asserting the equality leaves the assertion unproved (Frama-C 33). [`../../skills/framac-wp/prover_brief.md`](../../skills/framac-wp/prover_brief.md) recommends `loop invariant ptr_anchor: p == \at(p, Pre) + (p - \at(p, Pre));` and the matching `end_anchor` assertion. Neither claim has been tested on Frama-C 34 here.
5. **Provers cannot contribute or call a lemma**, which is Tier 7 as already recorded in [`./backlog.md`](./backlog.md).

Not gaps (already present): generated callee contracts, skipped annotations, WP's unsound-encoding warnings, memory-model hypotheses checked as goals, smoke tests, unproved lemmas, unresolved indirect calls, the zero-goal gate, the ban on `axiom` and `admit`, WP models that weaken C semantics.

---

## 3. Ranked plan (by expected value)

| Rank | Upgrade | Origin | Value | Cost and risk |
| :---: | :--- | :--- | :--- | :--- |
| 0 | Three wording corrections in the prover brief and the WP hints | Found while comparing | A hint that sends provers to a construct the merge refuses costs a whole attempt each time it is followed | Hours. No behaviour change in any gate |
| 1 | Run `frama-c-mcp`'s trap fixtures through the WP verdict gate on the Frama-C 34 image | `frama-c-mcp` `tests/fixtures/` | High if one fixture comes back `all_proven`: that is a false proof the gate would credit. Evidence: measured elsewhere, on 33. Transfer: same toolchain | Step 0 is hours. Each gap it finds is a pattern in one script |
| 2 | Semantic compiler flags and a parse-loss census in Phase 0 | `frama-c-mcp` `src/mcp/project.rs`, `checkgaps.rs` | Latent: zero hits in the six captures on disk, but a target that uses one of the flags is analysed as another program with no warning | One to two days, report-only first. Low risk |
| 3 | Specification patterns in the spec KB and the briefs | `acsl-skills` `skills/acsl-spec/references/`, `skills/frama-c-wp/references/` | Medium until measured: fewer stalled provers on string, parser and pointer-walk units. Evidence: the author's measurements on 33 with another Alt-Ergo | One to two days plus an A/B run. Risk: a brief that is already 42 KB; idioms the E-ACSL guardrail cannot execute |
| 4 | Lemma functions as the mechanism for Tier 7 | verker `src/*.h`, `acsl-skills` `skills/frama-c-wp/references/auto-active.md` | Decides Tier 7's design. Value depends on how many units stop with `inductive lemma required` | Weeks if it goes ahead: a brief rule, the merge scope check and the guardrail all change |
| 5 | Two small checks: a `return <parameter>` stub mutant, and descent of recursive `logic` definitions | `frama-c-mcp` `wpcli.rs`, `ast_utils_ast.ml` | Low: each closes a narrow hole | Hours each |
| D1 | verker as a ground-truth set for Phase 3 | verker | Depends on whether reference contracts are wanted as a second kind of benchmark | New scoring; training-data contamination |

Tiers 1, 2, 3 and 5 are independent. Tier 4 uses Tier 3's Step 0(a) result only as background.

### Common requirements

The requirements of [`./formal-discovery-plan.md`](./formal-discovery-plan.md) ("Common requirements for every tier") apply unchanged: an A/B environment flag for behaviour changes (added to both wrappers, `docker-compose.yml` and `tests/test_remediation_p2_container.py`), acceptance on a `benchmark.py` run compared with `benchmark_compare.py`, guides and briefs updated in the same change (then `python tools/sync_skill_mirrors.py`), tests run with `-n auto`. Any pipeline bug found on the way goes into [`../troubleshooting/`](../troubleshooting/README.md) in the same session. Per the standing rule for multi-step work, each step runs the unit suite only; one real-target validation comes at the end of a tier.

---

### 3.1 Tier 0: wording corrections (no measurement needed)

All three are open entries in [`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md), written on 2026-11-20.

| Where | Today | Change |
| :--- | :--- | :--- |
| `derive_wp_diagnostic_hints` in [`../../scripts/run_wp_function.py`](../../scripts/run_wp_function.py), on `unproven lemma` | Tells the prover to replace the lemma with a recursive ghost C function | Name the lemma, say it is assumed without proof, and point to the `inductive lemma required` stop rule. Keep or update the assertion in [`../../tests/test_diagnostic_hints.py`](../../tests/test_diagnostic_hints.py) |
| The variant branch of the repair strategy in the same script, and Step B item 2 of [`../../skills/framac-wp/prover_brief.md`](../../skills/framac-wp/prover_brief.md) | Suggests `if (consumed == 0) return -1;`, which is C code and fails the pure-ACSL check | Fix the measure, or state the progress fact as an invariant or a `requires`; report a `proof_gap` when the loop can really fail to progress |
| Rule 5 of the prover brief | Says `Memory model hypotheses for function` fails the run | Say the hypotheses are checked as goals, and that the message is unsound only under `--no-check-memory-model` |

**Acceptance.** The unit suite passes; `python tools/sync_skill_mirrors.py --check` passes; the three troubleshooting entries are changed from open to fixed with the commit.

---

### 3.2 Tier 1: the verdict gate against `frama-c-mcp`'s trap fixtures

**Problem.** Gap 3. Each fixture is a few lines of C and ACSL on which WP reports every goal valid, or generates no goal, for a reason that does not make the function correct. `frama-c-mcp` expects one named `incomplete[]` code per fixture. The pipeline has its own detection for most of those codes; whether it fires on programs written by someone else is not known.

**Step 0: fixture run (no pipeline change).** Fetch `tests/fixtures/` at `frama-c-mcp` commit `4b935a0` into a scratch directory outside the repository (MIT; nothing is vendored at this step). The file names below are from the tree at that commit. Three were opened (`decorative-contract.c` with targets `weak` and `strong`, `recursive-logic-unsound.c` with target `f`, `generated-callee-spec.c` with target `caller`): a few lines each, no include, one comment saying what the trap is. The others are assumed to have the same shape; the first step is to open each and note its target function. In `framac-analysis:latest`, run [`../../scripts/run_wp_function.py`](../../scripts/run_wp_function.py) with its default flags on the target function of each of:

- callee contracts: `generated-callee-spec.c`, `uncontracted-callee.c`;
- memory model: `memory-model-hypothesis.c`, `memory-model-no-hypothesis.c` (control), `pointer-cast-anomaly.c`, `pointer-formation.c`;
- WP limits: `wp-unsound-encoding.c`, `wp-annotation-skipped.c`, `wp-non-natural-loop.c`, `uninterpreted-operator.c`;
- vacuity and trust: `smoke-vacuous.c`, `smoke-kinds.c`, `lemma-unproved.c`, `axiom-licensed.c`, `assumption-unproved.c`, `recursive-logic-unsound.c`, `decorative-contract.c`;
- indirect calls: `indirect-call.c`, `indirect-call-annotated.c` (control);
- the pair `abs-int-buggy.c` and `abs-int-fixed.c` (control: the fixed one must end `all_proven`).

Record per fixture: the code `frama-c-mcp` expects (from the fixture's header comment and its `tests/unit/check-gaps.rs` and `tests/test-mcp-stdio.rs`), the pipeline's `status`, `soundness.ok`, the `tier_a_aborts` and `tier_b_unsound` entries, and for `decorative-contract.c` the result of `mutation_check.py` and of `contract_refinement.py frame-only`. For `axiom-licensed.c` and `recursive-logic-unsound.c` also run the unsound-construct check of [`../../scripts/acsl_ast.py`](../../scripts/acsl_ast.py), since the pipeline refuses those constructs before WP.

**Stop or go.**

- **Stop** if no trap fixture ends `all_proven` with `soundness.ok` true and every control ends as expected. Record the table here and close the tier.
- **Go, per fixture,** for each trap that the pipeline credits. One fixture is one defect: write the troubleshooting entry first, then the pattern.
- **Stop and report** if a control fails (the fixed twin not proved, or the annotated indirect call refused): that is a pipeline bug of another kind, or a Frama-C 34 difference, and is recorded before anything else.

**Change (only for the gaps found).** A pattern or a parsed field in `scan_wp_log_soundness` of `run_wp_function.py`, with the fixture's own log lines in a unit test. Where the fixture is short and MIT, the test can carry it with the notice. One candidate is already known from reading: the Why3 abort `Invalid_argument("unbound variable in of_term")` that `frama-c-mcp` documents under `Typed+nocast` leaves goals `FAILED` with no prover answer; check how the runner classifies it.

**Acceptance.** Every trap fixture that Step 0 found credited now ends `unsound_proof`, `wp_aborted` or `unproven_goals_remain`; the benchmark's recall and its count of `all_proven` units do not move (`benchmark_compare.py` against the current baseline).

**Not transferred.** The server, its sandboxes, its proof receipts and its `verify_program_step`: the scratch overlays, the caches and the scheduler already do those jobs. Its `run_e_acsl` runs the instrumented program with a timeout only, without rlimits or a cleared environment, and must never see a target.

---

### 3.3 Tier 2: semantic compiler flags and a parse-loss census

**Problem.** Gaps 1 and 2. Under `-fwrapv` or `-fno-strict-overflow` every `signed_overflow` alarm and E-ACSL stop is on behaviour the build defines, so candidates are false positives. Under the layout and signedness flags the analysed value ranges and struct layouts are not the compiled ones, so alarms and proofs may be about another program.

**Step 0 (no pipeline change).**

- **Flags.** Done for the captures on disk: six `build_capture.json` (c-ares run-2, nginx 1.31.9 run-1 to run-5), no hit for any of the seven flags. The run directories of libmodbus and QCBOR on disk hold no capture file, and the earlier targets (libmnl, minmea, libpng, libseccomp, nettle, mpack) have no run directory under that path; no other location was searched. Still to do: read the build recipes of the benchmark's targets under [`../../benchmark/`](../../benchmark/) for the same flags.
- **Parse losses.** Count the `[kernel:...]` warning categories in the Frama-C parse logs of the finished runs on disk, per link unit, and list those that no script reads today.

**Stop or go.**

- **Flags: go as a report-only table whatever the count.** The check is a table lookup in a script that already reads every compile command, and a silent wrong-program analysis is the costliest failure the pipeline can have. A count of zero only says no behaviour needs deciding yet.
- **Parse losses: stop** if the logs show no category beyond those a script already reads. **Go** if `kernel:asm:clobber`, `kernel:attrs:unknown` or an unclassified category appears in a unit whose functions reach Phase 2 or 3.

**Change.**

- [`../../scripts/build_capture.py`](../../scripts/build_capture.py): a table of semantic flags, each with what it changes. `build_capture.json` gains `semantic_flags` per unit (schema change). The report names the units. No analysis changes at this step.
- Later, and only when a target shows a flag: for the layout and signedness flags, a stop with instructions, as the architecture guard does; for the overflow flags, a recorded per-unit decision to run RTE, Eva, WP and the E-ACSL build without the signed-overflow alarm. That is a behaviour change with its own flag and A/B run.
- Parse losses, if Step 0 says go: a per-unit census in the Phase 0 model ([`../../scripts/phase0_model.py`](../../scripts/phase0_model.py)), with unclassified categories listed, shown in the report.

**Acceptance.** A unit test per flag on a synthetic compile command; the capture of one benchmark target is unchanged apart from the new empty field; the open entry in [`../troubleshooting/phase0-build-and-model.md`](../troubleshooting/phase0-build-and-model.md) is updated.

---

### 3.4 Tier 3: specification patterns in the spec KB and the briefs

**Problem.** `acsl-skills` holds patterns the prover brief lacks. Its mechanical half (flag set, log scan, smoke tests) the pipeline already has. Candidates, each with its file under `skills/` in `acsl-skills`:

| Pattern | File (under `skills/`) | For |
| :--- | :--- | :--- |
| Contract over the `Pre` state with pointwise `untouched` and `copied` invariants | `acsl-spec/references/patterns.md` | Functions that write a buffer while reading it |
| `progress` clause bounding the consumed count on both sides; errors without behaviors; export offsets, not pointers. Partly present: the prover brief already asks pointer-advancing helpers for offset-progress postconditions | `acsl-spec/references/parsers.md` | Parser units that return a count |
| Restating a quantified invariant over the entry pointer so the solver's term matches | `acsl-spec/references/loops.md`, `frama-c-wp/references/auto-active.md` | Preservation goals that time out |
| Signed index with a lower bound of minus one for backward scans; an existential witness invariant | `acsl-spec/references/loops.md` | Search loops |
| A fast `Unknown` means a missing hypothesis, a `Timeout` means the goal is too big | `frama-c-wp/references/triage.md` | Triage |
| `annot:missing-spec` on a header means the contract sits in the `.c`; `wp:pedantic-assigns` wants `assigns \result \from` | `frama-c-wp/references/triage.md` | Symptom rows for the hints |
| An unproved `pointer_value` goal means a pointer formed before the NULL or empty-window test | `verifiable-c/references/style.md` | Symptom row; classification only |
| `-wp-no-init-const` for large constant tables | `frama-c-wp/references/limitations.md` | Units with lookup tables |

The rows are as the subagent reported them on 2026-11-14; the parent opened `limitations.md` and `logic-defs.md` only. Step 0(b)'s codebook is written from the files themselves, at a pinned commit.

**Step 0 (no pipeline change).** Two measurements.

- **(a) The pointer-difference idiom on Frama-C 34.** Three toy pointer-walk functions (a `strlen`-style walk, a `const char *` parser helper returning the advanced pointer, an end-pointer loop), each proved twice in the image: with the brief's `ptr_anchor` / `end_anchor` idiom, and with the ghost-index idiom `acsl-skills` recommends. Record the goals proved and the time.
- **(b) Would the patterns have mattered.** Over the stalled provers of the finished runs on disk (libmodbus run-1 and QCBOR run-6 had 53 and 17), code each `proof_gap` by hand against the table above: which pattern, if any, addresses it. Fix the codebook before reading the gaps.

**Stop or go.**

- **(a)** If the anchor idiom proves and the ghost index does not do better, keep the brief and note that row C-11 does not hold on 34. If the anchor assertions stay unproved, replace the idiom in the brief; that is a correction, done whatever (b) says.
- **(b) Stop** if fewer than one stalled prover in ten has a gap one of the patterns addresses. **Narrow** to the patterns with at least two hits each. **Go** otherwise.

**Change.**

- [`../../scripts/spec_kb.py`](../../scripts/spec_kb.py): a curated seed source beside the INDEX slices. Today `build_seed_kb` reads only INDEX lines with a page number and cuts items at 1,200 characters, and the diagnostic hints read `kind == "repair"` items only. The curated items are written in the pipeline's own words, keyed to the existing feature queries (`pointer_walk`, `strings`, `pointer_len_params`, `indirect_calls`), each with its source cited (MIT notice kept).
- Symptom rows in `derive_wp_diagnostic_hints`.
- The architect brief gains the `progress` clause and `assigns \result \from` for parser entry points. The prover brief gains nothing in its body: the patterns arrive through the KB block, which is retrieved per function.

**Conflicts to keep out.** `acsl-skills` restructures C (`verifiable-c`); the pipeline never changes C, so that skill is used for classification only. It writes `buf == \null || \valid_read(...)` for empty buffers; keep the pipeline's guarded form, which E-ACSL can execute. It says `terminates` and `decreases` must precede `assigns`, which Frama-C 34 relaxed. Its timings and step budgets are the author's, on Alt-Ergo 2.6.3; the image has 2.4.3.

**Acceptance.** A/B on `FRAMAC_SPEC_KB` with and without the curated items, on the parser units of libmnl, minmea and QCBOR: prover iterations, stalls, and the `rejected_overconstrained` count. Keep the items only if stalls or iterations drop and rejections do not rise.

---

### 3.5 Tier 4: lemma functions as the mechanism for Tier 7

**Problem.** Gap 5. Since Tier 3 of the formal-discovery plan, a prover that needs an inductive fact stops with `inductive lemma required`. verker shows the same facts proved on stock WP with SMT solvers only: the logic function is defined recursively, the base and step facts are ordinary lemmas, and the inductive ones are ghost C functions with a contract and `decreases`, which the body calls from ghost code. The author's port also found three lemmas that the earlier toolchain had assumed and that were false, which is the argument for proving every lemma and assuming none.

**Step 0 (no pipeline change).**

- **Count.** The units with `details.gap_kind: "inductive_lemma_required"` in the ledgers of the finished runs, grouped by the fact they need (string length, bounded string length, comparison, count, sum). This is the count [`./backlog.md`](./backlog.md) already asks for before Tier 7.
- **Feasibility probe,** in the image, on one fact written in the pipeline's own words over its canonical names (not copied from verker): (i) WP proves the lemma function's own contract; (ii) a function whose body calls it from ghost code proves a goal that failed without it; (iii) the E-ACSL guardrail builds and runs that function with the ghost call; (iv) what the merge scope check says about a ghost call inside the assigned function.

**Stop or go.**

- **Stop** if fewer than five units across the runs need an inductive fact, or if the facts needed do not repeat (no two units share one): a library has nothing to share.
- **Stop** if (iii) fails and no build option leaves the ghost call out of the instrumented program.
- **Go** otherwise, to a design note for Tier 7: a fixed set of lemma functions in a sibling of [`../../templates/acsl/acsl_vocabulary.h`](../../templates/acsl/acsl_vocabulary.h), proved once by the parent and listed in the brief; a prover may call them from ghost code inside its function and may not write new ones.

**What changes if it goes ahead.** Step B item 3 of the prover brief (today: never a ghost function, no in-body workaround), the scope and pure-ACSL checks of [`../../scripts/acsl_ast.py`](../../scripts/acsl_ast.py) (what they say today about a ghost call inside the function is point (iv) of the probe), the parent re-check (the lemma set's own proof is part of the evidence), and the guardrail build.

**Risks.** Name collisions with Frama-C's `__fc_string_axiomatic.h`, on which the current vocabulary rests; version drift from 33 to 34; lemma functions that prove under `-wp-fct` of the caller without their own contract ever being proved, which is the defect Tier 3 closed and must not reopen.

---

### 3.6 Tier 5: two small checks

- **`return <parameter>` stub mutant.** `trivial_stub_mutant` in [`../../scripts/mutation_check.py`](../../scripts/mutation_check.py) tries an empty body and `return 0;`. A contract that only bounds the result by a parameter survives both. Add one mutant per parameter of the return type. Step 0: none needed; acceptance is a unit test and an unchanged mutation total on the benchmark apart from the new mutant's rows.
- **Descent of recursive `logic` definitions.** `acsl-skills` (`skills/acsl-spec/references/logic-defs.md`) reports one file with a non-descending recursive definition on which 335 of 346 goals "proved", and 311 of 346 once the recursion was corrected. `frama-c-mcp`'s fixture `recursive-logic-unsound.c` is the minimal case: `logic integer bad(integer n) = bad(n) + 1;` under a false postcondition. Provers cannot add a top-level definition (the merge refuses it), so this concerns definitions written by a header architect or shipped in `templates/`. Step 0: list the recursive logic definitions in `templates/` and in the headers of the finished runs. **Stop** if there are none outside Frama-C's own libc. Otherwise add a check in [`../../scripts/kernel_ast_dump.ml`](../../scripts/kernel_ast_dump.ml) (strongly connected components over logic definitions, each recursive call on a smaller argument or flagged).

---

### 3.7 Decision D1: verker as a ground-truth set

**Question.** Whether Phase 3 should be measured against reference contracts, besides the seeded-defect recall of [`../../scripts/benchmark.py`](../../scripts/benchmark.py). This is the same question as Decision D1 of [`./harness-and-spec-papers-generalization-plan.md`](./harness-and-spec-papers-generalization-plan.md), with one concrete candidate.

**For.** 35 functions with proved contracts on stock WP, a status table the Makefile enforces, and a `contract_refinement.py compare` that could score a synthesized contract against the reference by meaning.

**Against.** Tiny leaf functions, unlike the pipeline's targets. The references are functional contracts, while Phase 3 aims at absence of runtime errors and Layers 1 to 6. The older specifications are likely in a model's training data. verker's proofs run with the unsigned overflow and downcast alarms off; the pipeline has them on. The code carries `CODE_CHANGE` edits in four functions.

**Recommendation.** Not now. Reconsider after Tier 4's Step 0: if a lemma library is built, verker's string functions are its natural acceptance set, fetched at a pinned revision as an external target and never copied into the repository.

---

### Not pursued

| Item | Why |
| :--- | :--- |
| Running `frama-c-mcp` as a server for provers | One stateful project per server, its own defaults, and it duplicates overlays, caches and the scheduler. Its plugin is untested on Frama-C 34 |
| `frama-c-lsp` | No live session: a cold Frama-C run per request, and nothing the WP runner does not already return |
| saida, ISP, auto-deduct as a pre-pass before the provers | Pinned below Frama-C 34; no pointer arithmetic, casts or loops; contracts fitted to one call context. On the pipeline's targets nearly every function is outside the subset |
| ISP's one transferable idea, `requires \valid_read(p)` for formals dereferenced on every path | Provers write it unprompted; no measured need |
| VerNFR | No resource, timing or information-flow property. An allowlist of external calls per unit, if ever wanted, is a query on the Phase 0 model's call edges |
| SpecSmith, formally-verified-code-rl | The first does at toy scale what Phase 3 does; the second's checks are a subset of the pipeline's and its tasks are loop-free |
| `acsl-skills`' Coq skill | Needs an interactive prover in the image and a gate against `Admitted`. It targets inductive lemmas, which provers may not write before Tier 7, and it does nothing for the cast-limited units. The author's own order puts it last, after lemma functions. See also the Rocq trial of [`./proof-papers-generalization-plan.md`](./proof-papers-generalization-plan.md) |
| `frama-c-mcp`'s textual lints on `assigns` targets no postcondition mentions and on results not tied to inputs | The implementation mutants of `mutation_check.py` and the `frame-only` probe measure the same weakness by meaning |
| A technique for the WP cast blocker | None found in any of the ten |

### Watch

- **Ports to Frama-C 34:** saida, ISP and VerNFR declare `frama-c < 34`; `frama-c-mcp`'s CI accepts 33.0 only. Nothing here depends on them.
- **TriCera `-inv`** as a source of integer loop invariants for `loop_seeds.py`, run directly, without saida. A two-hour trial on one integer loop if the loop-seed acceptance run is ever done.
- **Seen in passing, not assessed:** `rse-verification/acsldiff` (compares two contracts; `contract_refinement.py` already does this), the CASP corpus behind formally-verified-code-rl, and the LOGOS contract skill used by auto-deduct.

---

## 4. Verification commands

```powershell
$env:PYTHONIOENCODING="utf-8"
python tools/check_generated_text.py
python -m pytest tests/test_docs_structure.py tests/test_extract_references.py -n auto
python tools/sync_skill_mirrors.py --check
python -m pytest -n auto
ruff check
mypy
```

Tier 1's Step 0 runs in the analysis image through the wrapper, one function at a time, with the runner's own per-goal timeout; no fuzz or Eva step is involved.
