# Agent Instructions for `docs/troubleshooting/`

Whenever you hit a bug, gap, or workaround in the pipeline itself while running or developing it (a script, a generator, a gate, the wrapper, a skill, or a brief that is wrong or incomplete), record it in `docs/troubleshooting/` **in the same session**, so maintainers and future runs can inspect and resolve it. This applies to every agent: the parent, forks, subagents, and anyone working a target run. Do not leave findings only in chat or in a progress report.

Subagents running in isolated scratch overlays that cannot edit shared repository documentation must include the formatted troubleshooting entry in their returned result so the parent agent can write it before the run ends.

---

## 1. Choosing the Right Thematic File

Place each entry in the thematic sub-document matching the component or phase where the symptom surfaces. Update an existing `### Symptom:` entry instead of adding a duplicate.

| File | Add or update entries here when the issue involves... |
| :--- | :--- |
| [`./toolchain-upgrades.md`](./toolchain-upgrades.md) | Frama-C version upgrades (`Changelog` diffs on base-image bumps), OCaml/kernel behavior changes across releases, or tool-wide flag/environment deprecations. |
| [`./phase0-build-and-model.md`](./phase0-build-and-model.md) | `build_capture.py`, `bear`, architecture guards, target build recipes, CRLF checkouts, `phase0_model.py` (`phase0_dump.ml`, `gcc_fallback`), `trust.py`, `THREAT_MODEL.md` block extraction, or test/product unit classification. |
| [`./harnesses-and-seeds.md`](./harnesses-and-seeds.md) | `generate_harness.py`, `api_harness.py`, auto-prelude headers, opaque handle lifecycles, `harness_reach.py` (static and dynamic reach gates, exemptions), `build-check` triage, `llvm-cov` coverage builds, `seed_harvest.py`, or `fuzz_assets.py`. |
| [`./kernel-and-stubs.md`](./kernel-and-stubs.md) | Frama-C C/ACSL parsing & preprocessing (`-nostdinc`, `-machdep`), `__fc_libc` missing types/macros, `fc_cpp_wrapper.py`, `templates/fc_stubs/`, `templates/acsl/acsl_vocabulary.h`, `stub_check.py`, `stub_gen.py`, or `libc_gap_report.py`. |
| [`./eacsl-and-fuzzing.md`](./eacsl-and-fuzzing.md) | `e-acsl-gcc`, `eacsl_toolchain.py`, `run_eacsl_fuzz.py` builds/campaigns, E-ACSL shadow memory (`LLVMFuzzerInitialize`, `errno`, formal/result init, uninstrumented library pointers), E-ACSL quantifier limits, ASan/UBSan/LSan runtime behavior, crash fingerprinting (`fingerprint.py`), or `minimize`. |
| [`./eva.md`](./eva.md) | `run_eva_slice.py`, `eva_tuning.py`, `eva_options.py`, `eva_loops.py`, `eva_flamegraph.py`, `Unknown` alarm clusters, global initializer evaluation, `-nonterm`, or Eva `repair_hints`. |
| [`./wp-and-guardrail.md`](./wp-and-guardrail.md) | `run_wp_function.py`, WP memory models (`Typed`), loop invariants/assigns, vacuity smoke tests, Dual-Oracle E-ACSL guardrail (`fc_cpp_wrapper_eacsl.py`, replay exclusions), `acsl_ast.py` scope/unsound checks, `wp_scheduler.py` prover/negotiate dispatch, `function_facts.py`, `frame_skeleton.py`, `spec_kb.py`, `mutation_check.py`, or `proof_carry.py`. |
| [`./security-properties.md`](./security-properties.md) | `security_props.py`, `templates/metacsl/`, `schemas/threat_model.schema.json` (L4 auth gates, L5 sanitization/format strings, L6 secret wiping and `--eva-taint`). |
| [`./ledger-and-verifier.md`](./ledger-and-verifier.md) | `ledger.py`, `validate_artifacts.py`, `schemas/*.schema.json` validation errors, Crash Verifier scaffolding/ingestion (`scaffold-verifier`, `ingest-verifier`), or candidate reopening. |
| [`./resources-and-infra.md`](./resources-and-infra.md) | `resources.py`, `cache.py`, `loop_seeds.py`, `pipeline_make.py` / `templates/pipeline.mk`, `benchmark.py`, `extract_references.py`, `patterns.py`, `wrappers/framac-docker.*`, PowerShell/Windows host quirks, skill mirrors, or test-suite infrastructure. |

If you add a new thematic sub-document, add it both to the table in [`./README.md`](./README.md) and to the table above.

[`./resolved.md`](./resolved.md) is not a thematic file: never add a new entry there. It only receives entries archived under section 4.

---

## 2. Entry Format

Write every entry as a level-3 heading (`### Symptom: ...`) with structured bullets matching the surrounding entries:

```markdown
### Symptom: <Exact error excerpt, gate failure, or observable misbehavior>
- **Seen on:** <target, run number, module/function, and date (YYYY-MM-DD); or test/audit context>.
- **Cause:** <diagnosed root cause after reading the logs and relevant script/source — never guess>.
- **Fix:** <how to resolve it, or what pipeline change fixed it, with tests>.
```

### Required Details

1. **Exact diagnostics:** Quote the exact Frama-C, compiler, linker, schema, or gate message so `git grep` finds the entry immediately.
2. **Root cause from logs:** Open the relevant log (`build_capture.json`, `fuzz_<mod>.compile.log`, `eva.log`, `wp.log`, etc.) before diagnosing. State clearly whether the root cause is a **pipeline bug**, an **upstream Frama-C / E-ACSL bug or limitation**, or a **target-side / checkout issue** (for example CRLF line endings or invalid C).
3. **Explicit status:**
   - **Fixed pipeline bug:** Name the script/template/schema modified, the commit hash (or say `uncommitted` if still in the working tree), and the regression test covering it.
   - **Open pipeline bug:** Mark it explicitly with `**Open pipeline bug:**` (or `**Open pipeline gap:**`) so `git grep -i "open pipeline" docs/troubleshooting/` finds every unresolved defect.
   - **Workarounds:** Never silently work around a pipeline bug. If you patched code in a worktree, say so. If you worked around it only inside a run directory, state the workaround and keep the pipeline defect marked **open**.

---

## 3. Formatting, Links, and Guardrails

Because files in `docs/troubleshooting/` live **two levels below** the repository root (`docs/troubleshooting/<theme>.md`), follow these rules strictly:

1. **Relative links only (with `./` or `../`):**
   - To another troubleshooting file in this folder: `[`./harnesses-and-seeds.md`](./harnesses-and-seeds.md)`
   - To a sibling directory under `docs/`: `[`../guides/resources-and-caching.md`](../guides/resources-and-caching.md)`, `[`../references/README.md`](../references/README.md)`, `[`../upstream/frama-c/frama-c-e-acsl-issues.md`](../upstream/frama-c/frama-c-e-acsl-issues.md)`
   - To a file at the repository root (`scripts/`, `tests/`, `templates/`, `schemas/`, `skills/`, `wrappers/`): `[`../../scripts/run_wp_function.py`](../../scripts/run_wp_function.py)`
2. **File-writing tools only (no shell heredocs):**
   - Never write or edit Markdown files containing ACSL (`\result`, `\valid_read`, `\forall`, `\false`, `\old`) or regex backslashes via Bash heredocs or PowerShell here-strings. Always use direct file-writing/editing tools with LF line endings.
3. **No emojis:** Never use emojis anywhere in troubleshooting docs.
4. **Run the generated-text checker before committing:**
   ```powershell
   $env:PYTHONIOENCODING="utf-8"
   python tools/check_generated_text.py docs/troubleshooting/
   ```
   This catches control characters, mangled ACSL escapes (`alse`, `orall`), and missing backslashes inside `/*@ ... */` or `//@ ...` regions.

---

## 4. Archiving Resolved Entries (`./resolved.md`)

The thematic files list what is still actionable. Move an entry to [`./resolved.md`](./resolved.md) only when nothing in it is:

- **Fixed:** every pipeline defect it records is fixed on `main`. Check that the commits are ancestors of `main` (`git merge-base --is-ancestor <sha> main`) and that the named regression test exists. A fix on an unmerged branch, or one that is "uncommitted", is not enough.
- **Stale:** the script, flag, gate or file it describes no longer exists, or another entry supersedes it.
- **One-off:** an upstream or target-side issue whose workaround is no longer needed, for example because the analysis image's opam patch queue now carries the upstream fix.

These entries stay in their thematic file:

- an entry with any part still open (an `**Open pipeline bug:**` / `**Open pipeline gap:**` marker, a "Still open" item, an unfiled upstream defect that still bites);
- an upstream limitation or target-side issue whose workaround still applies, which is current guidance;
- an entry that code comments, runtime messages or tests point to (`git grep -n "docs/troubleshooting" -- scripts tests skills`).

To archive an entry:

1. Cut it verbatim and put it under the `## From ./<file>` section of [`./resolved.md`](./resolved.md) for the file it came from.
2. Add, as its first bullet, `- **Archived YYYY-MM-DD:** <fixed on main | stale | one-off>. <one-sentence reason with the commit or evidence>.`
3. Reword any open marker left in it (for example `Pipeline bug (closed, see the archive note)`). Then `git grep -n -i "open pipeline" docs/troubleshooting/` still lists only open work.

If an archived symptom comes back, move the entry back to its thematic file and mark the new part open. When a kept entry's status changes (a branch merges, an upstream report is filed), update its text in the same session.
