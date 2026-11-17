# Paper Assessments Register

One place to answer "did we already assess this paper?". Each row names the paper, where its assessment lives, and what was decided. Papers that led to a plan are assessed in that plan; papers that led to nothing are assessed here, in the sections below the table.

Claims about a paper come from the paper itself (the part read is stated). Claims about the pipeline were checked against the scripts on the date given, unless marked "not checked".

## Register

| Paper | Identifier | Assessed | Where | Decision |
|---|---|---|---|---|
| Loop Invariants from Counterexamples; Heurix; Responsibility Analysis; Agentic Interpretation; A Lattice of Union-Finds; Abstract Interpretation for Heuristic Search; Empirical Sound Resource Bounds | see the plan | before 2026-11-16 | [`./papers-generalization-plan.md`](./papers-generalization-plan.md) | see the plan |
| ProofCoder | arXiv 2611.14106 | 2026-11-16 | [`./proof-papers-generalization-plan.md`](./proof-papers-generalization-plan.md) | per-goal cost, residual census, Rocq trial |
| VeriGen-C | arXiv 2610.30725 | 2026-11-16 | same plan | contract shape |
| LLM-Assisted Verification in Dafny | arXiv 2611.16886 | 2026-11-16 | same plan | see the plan |
| Agentic Verified Optimization | arXiv 2610.30188 | 2026-11-16 | same plan | see the plan |
| From Formal Methods to Fuzzing and Back | arXiv 2611.12338 | 2026-11-16 | same plan | see the plan |
| Partial Contracts Suffice | arXiv 2607.10291 | 2026-11-17 | [`./caller-sufficient-contracts-plan.md`](./caller-sufficient-contracts-plan.md) | refinement probe, caller-sufficient contracts |
| FM-Agent | arXiv 2604.11556 | 2026-11-17 | same plan | call sites in the prover brief |
| RagVerus | arXiv 2502.05344 | 2026-11-17 | same plan | same-target proven examples in the brief |
| Evaluating LLM-Generated ACSL Annotations | arXiv 2602.13851 | 2026-11-17 | same plan | verdicts by prover in the census; its figures are not used |
| NL2ACSL | SSRN 5490609 | 2026-11-17 | same plan | nothing taken |
| STAFF: Translating Formal Verification Benchmarks | DOI 10.1145/3843777.3844531 | 2026-11-17 | [section 1](#1-staff) | nothing to implement |
| End-to-end verification of elliptic curve cryptographic primitives | DOI 10.32362/2500-316X-2026-14-5-9-25 | 2026-11-17 | [section 2](#2-elliptic-curve-primitives-coq-and-frama-c) | nothing to implement; prompted the Rocq step 0 trial |
| On-the-fly Abstract Debugging for Frama-C/Eva | HAL cea-05673292 | 2026-11-17 | [section 3](#3-eva-abstract-debugger) | nothing to implement; one idea noted |
| Domaines formellement vérifiés | HAL hal-05231818 | 2026-11-17 | [section 4](#4-formally-verified-domains-why3) | nothing taken |
| On-the-Fly Generation of K-Path Tests for C Functions | HAL hal-01810203 | 2026-11-17 | [section 5](#5-pathcrawler-k-path-and-abstract-paths) | nothing to implement; one idea noted |
| Abstract path testing with PathCrawler | HAL hal-01810297 | 2026-11-17 | [section 5](#5-pathcrawler-k-path-and-abstract-paths) | same |

## 1. STAFF

Sevenhuijsen, ASYDE 2026. Read in full except the references.

- **Claim.** An LLM translates verified Dafny programs into ACSL-annotated C, repairs them with Frama-C feedback, and five checks together judge the translation.
- **Evidence.** 130 of 162 files verify after three repair rounds, 113 of them at the first attempt; rounds two and three add 5. Only 5 files pass all five checks. Of 157 files with mutants, 74 leave at least one mutant that still verifies; equivalent mutants are not separated out, so 74 is an upper bound on weak contracts. The repair loop over-annotates: assertions go from 6 to 1353, and assertions the model added itself become the main cause of failure after the first round. Programs are small (median 36 lines), one model, no baseline.
- **Transfer.** Low. [`../../scripts/mutation_check.py`](../../scripts/mutation_check.py) already mutates both the contract and the implementation of proven functions and judges them under WP; STAFF mutates the implementation only. The over-annotation finding suggests a brief rule (remove a self-added assertion that fails before adding more); whether the prover brief already says so was not checked.

## 2. Elliptic-curve primitives, Coq and Frama-C

Erokhin, Gorin, Bunina, Russian Technological Journal 14(5), 2026, in Russian. Read in full except the references.

- **Claim.** A Coq to Frama-C pipeline synthesizes Curve25519 field arithmetic with a machine-checked proof, within 7% of hand-written code, and Frama-C then checks overflow, bounds and constant time.
- **Evidence.** The Coq part follows the published Fiat-Crypto design. The proof of the central lemma is elided in the figure and no artifact is linked. The Frama-C part is a toy example whose contract is inconsistent (it ensures a result that overflows under its own precondition), and whose corrected bound still does not prevent the overflow. Range analysis, constant-time checking and the Frama-C integration are listed as later stages that the paper does not present. The 7% figure has no table and no method.
- **Transfer.** Very low. Its one-line `frama-c -wp -wp-prover coq` prompted the Rocq step 0 trial (record `docs/runs/2026-11-17-rocq-step0.md`, on branch `trial/rocq-step0` when this was written), which found that the route works with Coq 8.20.1 and that WP credits cheating scripts unless a guard is added.

## 3. Eva Abstract Debugger

Massart, Alberti, Bühler, Prevosto, DEBT workshop at ECOOP 2026, four pages. Read in full.

- **Claim.** The first debugger that steers an abstract interpreter while it runs: stepping, breakpoints on abstract states, choice of branch order, and ACSL annotations injected at a breakpoint, through the Debug Adapter Protocol with a VS Code client. Eva's iteration order is changed from a weak topological order to a weak partial order to make this possible.
- **Evidence.** A tool description with stepping rules and one session on `cmdparse.c` of chrony: nine buffer-overflow alarms share one cause (a pointer offset with no upper bound), and one loop invariant or `loop unroll` removes all nine. There is no evaluation and no user study. The prototype supports a subset of ACSL and shows intervals only.
- **Transfer.** Low. The tool is interactive and needs an editor; the pipeline runs Eva in batch ([`../../scripts/run_eva_slice.py`](../../scripts/run_eva_slice.py), with slevel and fallback tiers). Whether the debugger ships with the Frama-C 34 of the analysis image was not checked.
  - **Idea noted, not planned:** group Eva alarms by the imprecise location they share before they are queued for Phase 3, so that one annotation is tried for the group. Whether the pipeline already groups alarms this way was not checked.
  - The protocol runs over standard input and output, so an agent could in principle drive it. That is speculation until the tool's availability is known.

## 4. Formally verified domains (Why3)

Dubois, JFPC 2025, in French, four pages. Read in full.

- **Claim.** Sparse sets, and a new sparse-subset variant for set variables, are specified, implemented and proved in Why3 for use as variable domains in a constraint solver, with backtracking restored by reversible integers. OCaml code is extracted.
- **Evidence.** WhyML listings with ghost model fields and type invariants; verification conditions are discharged automatically by Alt-Ergo, CVC4 and Z3 with a few lemmas. No proof times and no comparison. Moving from mathematical to 63-bit integers needed one extra bound in the specification to avoid an overflow.
- **Transfer.** None. This is code written to be proved, in WhyML; the pipeline verifies existing C and may not add file-scope ghost code or global lemmas (Rule 1 of [`../../skills/framac-wp/prover_brief.md`](../../skills/framac-wp/prover_brief.md)).

## 5. PathCrawler: k-path and abstract paths

Williams, Marre, Mouy, ASE 2004 (four pages) and Williams, AST 2010 (eight pages). Both read in full except the references.

- **Claim (2004).** Tests covering all feasible paths of a C function, or all paths with at most k loop iterations, are generated by running instrumented code, turning the executed path into a predicate, and solving for an input outside the paths already covered. An infeasible prefix is detected once and prunes every path that contains it.
- **Claim (2010).** Abstract path trees give precise definitions of weaker coverage criteria (function calls not inlined, multiple conditions not decomposed, loops grouped) and of search strategies that reach them with fewer solver calls.
- **Evidence.** 2004: one program, k = 5, 4536 theoretical paths, 337 tests generated, 317 infeasible prefixes eliminating 4215 paths, 1.6 s; the C implementation was in progress. 2010: definitions and one worked example (11 partial paths explored instead of 18); no implementation result. Functions with pointer casts are not handled.
- **Transfer.** Low today. No concolic or symbolic test generator is in the pipeline or the image (no match for PathCrawler, KLEE or concolic under `scripts/`, `skills/` and the `Dockerfile`, 2026-11-17), and whether PathCrawler can be obtained for Frama-C 34 was not checked.
  - **Idea noted, not planned:** Phase 1 records the API entry points no fuzz input executed as a dynamic gap, which holds their units out of WP. A path-directed generator aimed at exactly those functions would produce seeds where the fuzzer has none, and a proof that a path is infeasible is stronger than the absence of coverage. This would need a tool choice first.
  - The 2004 paper's suggestion to use pre- and postconditions as the test oracle is what E-ACSL already does in Phase 1.
