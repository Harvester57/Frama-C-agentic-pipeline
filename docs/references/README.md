# Frama-C Reference Manuals

Upstream manuals for the tools the pipeline drives, all for Frama-C 33.0 (Arsenic). The container now runs Frama-C 34.0~~dev (Selenium); re-extract these manuals from the 34.0 PDFs with `scripts/extract_references.py` when they are published (the bundled PDFs stay labeled with their source version). They are large (19 to 112 pages each), so treat them as a **last resort**: first use the skill or brief you were given and [`../troubleshooting.md`](../troubleshooting.md). Consult a manual when you need the exact semantics of an option, an ACSL construct, an alarm kind, or a WP/Eva/E-ACSL message, and those sources don't cover it.

Each `<name>.pdf` has a generated, greppable twin `<name>.md` in the same folder. **Search the `.md`, never read a manual whole.** Don't open a PDF unless the `.md` passage is garbled (see step 4). For E-ACSL, start with the hand-written [`./e-acsl-quickref.md`](./e-acsl-quickref.md), which covers wrapper and plug-in options, runtime output formats, and limitations that change verdicts.

## How to look something up

1. **Find the section.** Grep [`./INDEX.md`](./INDEX.md), which has one line per section of every manual. Don't Read it whole:
   ```text
   Grep  pattern="(?i)loop annotations"  path=docs/references/INDEX.md
   -> acsl/frama-c-acsl-implementation.md:1741-2071       2.4.2 Loop annotations  (p. 33)
   ```
   Paths are relative to `docs/references/`. `1741-2071` is the section's line range in the `.md`, and `p. 33` is the physical PDF page.
2. **Or grep the term itself** in the one manual that owns it (see the table below). Option definitions start at column 0 in WP §2.4 and RTE §3. Eva introduces its options in running text, so grep the bare name there. With shell `grep`, put `-e` before a pattern that starts with `-`.
   ```text
   Grep  pattern="^-wp-(timeout|steps)"  path=docs/references/wp/frama-c-wp-manual.md  -n
   Grep  pattern="-eva-auto-loop-unroll"  path=docs/references/eva/frama-c-eva-manual.md  -n
   Grep  pattern="\\separated"  path=docs/references/acsl/frama-c-acsl-implementation.md  -n  head_limit=20
   ```
   To get one manual's outline with line numbers, grep its headings: `Grep pattern="^#" path=<manual>.md -n`.
3. **Read only that range.** Use `Read offset=<first> limit=<last-first+1>`, at most ~200 lines per read. For a long chapter, read the subsection you need rather than the whole chapter.
4. **Figures and math.** Text is extracted with layout, so code listings, grammars and option lists stay readable. Colour, symbols and two-column tables are partly lost. If a passage is unreadable, find the nearest `<!-- page N -->` marker above it and Read just that PDF page: `Read file_path=docs/references/<folder>/<name>.pdf pages="N"`.

Budget: answer a question in at most 3 lookups. In results and briefs, cite the section (for example `WP manual §2.4.8`), not long quotes.

## Catalog

Language specifications are in `acsl/`; one folder per plug-in holds that plug-in's manual.

| Markdown file | Manual | Look here for |
| :--- | :--- | :--- |
| [`./acsl/frama-c-acsl-implementation.md`](./acsl/frama-c-acsl-implementation.md) | **ACSL 1.24** language reference, as implemented in Frama-C 33.0 | Contracts and behaviors §2.3. `assigns` and location sets §2.3.4. Loop annotations §2.4.2. `\at` and labels §2.4.3. Termination and `decreases` §2.5. Logic functions, lemmas and axiomatics §2.6. `\valid`, `\separated` and allocation §2.7. `\initialized` §2.8. Ghost code §2.13. Built-in list App. A.2 |
| [`./acsl/e-acsl-implementation.md`](./acsl/e-acsl-implementation.md) | E-ACSL 1.24 language, as executed by Frama-C 33.0's E-ACSL plug-in | Which ACSL constructs the runtime checker can execute. Figure 1.1 (PDF p. 6) lists the unsupported ones; in the PDF, unsupported constructs are printed **in red**, a colour the `.md` loses |
| [`./acsl/e-acsl.md`](./acsl/e-acsl.md) | E-ACSL 1.24 language, tool-independent | Rarely needed; prefer [`./acsl/e-acsl-implementation.md`](./acsl/e-acsl-implementation.md) |
| [`./eacsl/e-acsl-manual.md`](./eacsl/e-acsl-manual.md) | E-ACSL plug-in, Frama-C 33.0 (summarized in [`./e-acsl-quickref.md`](./e-acsl-quickref.md)) | `e-acsl-gcc` wrapper and its options §2.2. Runtime errors inside annotations §2.3.1. Integers and GMP §2.3.3. Memory models and `-M` §2.3.4. Monitor output, `--fail-with-code` and `--keep-going` §2.3.5. Format-string and libc checks §2.4. Programs without `main`, undefined functions and `-e-acsl-functions` §2.5. Combining with RTE and Eva §2.6. Known limitations §3 |
| [`./wp/frama-c-wp-manual.md`](./wp/frama-c-wp-manual.md) | WP plug-in, Frama-C 33.0 | Command-line options §2.4: goal selection (`-wp-fct`, `-wp-prop`) §2.4.1, models §2.4.3, smoke tests §2.4.5, provers, timeouts and steps §2.4.8. Supported annotations and VC counts §2.1. Memory models and their hypotheses §1.4, §3. Qed simplifier §4. ACSL built-ins §5.2. JSON reports §2.7 |
| [`./eva/frama-c-eva-manual.md`](./eva/frama-c-eva-manual.md) | Eva plug-in, Frama-C 33.0 | What Eva checks (alarm kinds) §3.2. Log messages §3.3. Entry point and initial context §6.3. Loop precision (`-eva-auto-loop-unroll`, widening) §6.4. Partitioning §6.5. Domains (octagons, taint, …) §6.7. `Frama_C_*` builtins §9. Limitations §5. FAQ §10. ACSL quick guide App. A |
| [`./rte/frama-c-rte-manual.md`](./rte/frama-c-rte-manual.md) | RTE plug-in, Frama-C 33.0 | The assertion generated for each operation: integer overflow, shifts and division §2.1, pointer validity and `mem_access` §2.2, downcasts §2.3–2.5, initialization §2.7. Undefined behaviours RTE does **not** cover §2.6, §2.8. Options §3 |

The container installs whatever `opam install frama-c` resolves to, so for exact option names and defaults trust the installed tool: `frama-c -version`, `frama-c -wp-help`, `frama-c -eva-help`, `frama-c -rte-help`, `e-acsl-gcc -h`.

Executable upstream examples mined from the Frama-C master archive (Eva/WP/E-ACSL test patterns, the `eva_main` argv stub, make-wrapper repair tips) are vendored in [`../upstream/sources/`](../upstream/sources/README.md) — consult them before writing annotations or flags from scratch.

## Key facts for this pipeline

- **The E-ACSL guardrail does not check everything a prover writes.** Figure 1.1 of [`./acsl/e-acsl-implementation.md`](./acsl/e-acsl-implementation.md) lists constructs E-ACSL does not execute. Among them: `assigns` clauses (including `loop assigns`), `decreases` clauses, lemmas, axiomatic definitions, inductive predicates, `\dangling`, behavior-specific annotations (`for b:`), `let`-bound predicates, quantification over pointers or enums, and labelled memory built-ins. Those clauses are validated only by WP. Loop invariants are checked at runtime on each iteration but lose their inductive meaning (App. A.2). Loop variants are supported.
- **E-ACSL fuzz builds need special handling because a libFuzzer harness has no `main`.** The pipeline builds them with `-n`, full memory tracking (`-M`), and an `LLVMFuzzerInitialize` hook that initializes the runtime. Without those, the build fails, valid stack accesses raise false `\valid` alarms, or every input crashes (E-ACSL manual §3.3.1). Even so, violations that depend on undefined functions, recursion, function pointers or incomplete types go undetected (§3.3.2–3.6), so a clean run is not a proof. See [`./e-acsl-quickref.md`](./e-acsl-quickref.md), including its "Verified in the pipeline container" section.
- **WP** does not support statement contracts. For a function without a body, the kernel infers `assigns` from the prototype, which is unsafe and comes with a warning, so external stubs need explicit `assigns` (WP §2.1).
- **RTE** covers only a subset of undefined behaviour. It does not cover relational comparison of pointers into different objects, out-of-range floating-point demotion, or strict-aliasing violations (§2.8). It generates initialization assertions only for functions selected by `-rte-initialized` (default: none) (§2.7, §3). The pipeline's E-ACSL builds pass `-rte-initialized @all`. Eva reports uninitialized reads without it (Eva manual §3.2), and WP does not use it.
- **RTE before Eva is not redundant here.** The RTE manual notes that Eva already emits its own alarms, so combining the two adds no detection. The pipeline still runs `-rte -then -eva` for bookkeeping: RTE produces the full list of obligations, and Eva gives each one a status. The ledger marks a function `covered` only when it has RTE properties and all of them are Valid, and it reports unreached code as Dead. With Eva's alarms alone, "no alarm" would look the same for a function Eva proved safe and one it never reached. Phase 1 needs RTE outright (E-ACSL only checks annotations), and so does Phase 3 (`-wp-rte` proves the obligations for every caller, not just the harness context).

## Regenerating

The `<folder>/<name>.md` files and [`./INDEX.md`](./INDEX.md) are generated, so don't edit them. [`./README.md`](./README.md) and [`./e-acsl-quickref.md`](./e-acsl-quickref.md) are hand-written. After adding, replacing, moving or deleting a PDF under `docs/references/<folder>/`, run this on the host (it needs poppler's `pdftotext` and `pip install pypdf`):

```text
python scripts/extract_references.py          # rewrites every <name>.md and INDEX.md, deletes orphaned .md files
python scripts/extract_references.py --check  # fails if a .md is missing, stale or orphaned (run by pytest)
```

Then update the catalog above, and [`./e-acsl-quickref.md`](./e-acsl-quickref.md) if the E-ACSL manual changed.
