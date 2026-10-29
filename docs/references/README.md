# Frama-C Reference Manuals

Upstream manuals for the tools the pipeline drives, all for Frama-C 33.0 (Arsenic). They are large (19 to 112 pages each), so treat them as a **last resort**: first use the skill or brief you were given and [`docs/troubleshooting.md`](../troubleshooting.md). Consult a manual when you need the exact semantics of an option, an ACSL construct, an alarm kind, or a WP/Eva/E-ACSL message, and those sources don't cover it.

Each `<name>.pdf` has a generated, greppable twin `<name>.md` in the same folder. **Search the `.md`, never read a manual whole.** Don't open a PDF unless the `.md` passage is garbled (see step 4). For E-ACSL, start with the hand-written [`e-acsl-quickref.md`](e-acsl-quickref.md), which covers wrapper and plug-in options, runtime output formats, and limitations that change verdicts.

## How to look something up

1. **Find the section.** Grep [`INDEX.md`](INDEX.md), which has one line per section of every manual. Don't Read it whole:
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
| `acsl/frama-c-acsl-implementation.md` | **ACSL 1.24** language reference, as implemented in Frama-C 33.0 | Contracts and behaviors §2.3. `assigns` and location sets §2.3.4. Loop annotations §2.4.2. `\at` and labels §2.4.3. Termination and `decreases` §2.5. Logic functions, lemmas and axiomatics §2.6. `\valid`, `\separated` and allocation §2.7. `\initialized` §2.8. Ghost code §2.13. Built-in list App. A.2 |
| `acsl/e-acsl-implementation.md` | E-ACSL 1.24 language, as executed by Frama-C 33.0's E-ACSL plug-in | Which ACSL constructs the runtime checker can execute. Figure 1.1 (PDF p. 6) lists the unsupported ones; in the PDF, unsupported constructs are printed **in red**, a colour the `.md` loses |
| `acsl/e-acsl.md` | E-ACSL 1.24 language, tool-independent | Rarely needed; prefer `e-acsl-implementation.md` |
| `eacsl/e-acsl-manual.md` | E-ACSL plug-in, Frama-C 33.0 (summarized in [`e-acsl-quickref.md`](e-acsl-quickref.md)) | `e-acsl-gcc` wrapper and its options §2.2. Runtime errors inside annotations §2.3.1. Integers and GMP §2.3.3. Memory models and `-M` §2.3.4. Monitor output, `--fail-with-code` and `--keep-going` §2.3.5. Format-string and libc checks §2.4. Programs without `main`, undefined functions and `-e-acsl-functions` §2.5. Combining with RTE and Eva §2.6. Known limitations §3 |
| `wp/frama-c-wp-manual.md` | WP plug-in, Frama-C 33.0 | Command-line options §2.4: goal selection (`-wp-fct`, `-wp-prop`) §2.4.1, models §2.4.3, smoke tests §2.4.5, provers, timeouts and steps §2.4.8. Supported annotations and VC counts §2.1. Memory models and their hypotheses §1.4, §3. Qed simplifier §4. ACSL built-ins §5.2. JSON reports §2.7 |
| `eva/frama-c-eva-manual.md` | Eva plug-in, Frama-C 33.0 | What Eva checks (alarm kinds) §3.2. Log messages §3.3. Entry point and initial context §6.3. Loop precision (`-eva-auto-loop-unroll`, widening) §6.4. Partitioning §6.5. Domains (octagons, taint, …) §6.7. `Frama_C_*` builtins §9. Limitations §5. FAQ §10. ACSL quick guide App. A |
| `rte/frama-c-rte-manual.md` | RTE plug-in, Frama-C 33.0 | The assertion generated for each operation: integer overflow, shifts and division §2.1, pointer validity and `mem_access` §2.2, downcasts §2.3–2.5, initialization §2.7. Undefined behaviours RTE does **not** cover §2.6, §2.8. Options §3 |

The container installs whatever `opam install frama-c` resolves to, so for exact option names and defaults trust the installed tool: `frama-c -version`, `frama-c -wp-help`, `frama-c -eva-help`, `frama-c -rte-help`, `e-acsl-gcc -h`.

## Key facts for this pipeline

- **The E-ACSL guardrail does not check everything a prover writes.** Figure 1.1 of `acsl/e-acsl-implementation.md` lists constructs E-ACSL does not execute. Among them: `assigns` clauses (including `loop assigns`), `decreases` clauses, lemmas, axiomatic definitions, inductive predicates, `\dangling`, behavior-specific annotations (`for b:`), `let`-bound predicates, quantification over pointers or enums, and labelled memory built-ins. Those clauses are validated only by WP. Loop invariants are checked at runtime on each iteration but lose their inductive meaning (App. A.2). Loop variants are supported.
- **E-ACSL can miss memory violations, so a clean run is not a proof.** A program without `main`, such as every libFuzzer harness, gets only partial instrumentation for memory-related annotations (`\valid`, RTE `mem_access`) unless it is built with `-M` / `-e-acsl-full-mtracking` (E-ACSL manual §3.3.1). Violations that depend on undefined functions, recursion, function pointers or incomplete types also go undetected (§3.3.2–3.6). See [`e-acsl-quickref.md`](e-acsl-quickref.md) for the full list.
- **WP** does not support statement contracts. For a function without a body, the kernel infers `assigns` from the prototype, which is unsafe and comes with a warning, so external stubs need explicit `assigns` (WP §2.1).
- **RTE** covers only a subset of undefined behaviour. It does not cover relational comparison of pointers into different objects, out-of-range floating-point demotion, or strict-aliasing violations (§2.8). It generates initialization assertions only for functions selected by `-rte-initialized` (default: none) (§2.7, §3).

## Regenerating

The `<folder>/<name>.md` files and `INDEX.md` are generated, so don't edit them. `README.md` and `e-acsl-quickref.md` are hand-written. After adding, replacing, moving or deleting a PDF under `docs/references/<folder>/`, run this on the host (it needs poppler's `pdftotext` and `pip install pypdf`):

```text
python scripts/extract_references.py          # rewrites every <name>.md and INDEX.md, deletes orphaned .md files
python scripts/extract_references.py --check  # fails if a .md is missing, stale or orphaned (run by pytest)
```

Then update the catalog above, and `e-acsl-quickref.md` if the E-ACSL manual changed.
