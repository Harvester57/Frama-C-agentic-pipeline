# Regex hardening plan

Follow-up to the regex audit of 2026-11-11 (about 800 uses reviewed, 79 findings). Ten confirmed defects are
already fixed (uncommitted, see [`../troubleshooting/README.md`](../troubleshooting/README.md) entries dated 2026-11-11 and
`tests/test_regex_hardening.py`). This plan covers the rest: regexes to replace by a structured source,
regexes to correct in place, and regexes to remove.

Line numbers are from the working tree of 2026-11-11 on `phase1-remediation`. Search for the pattern name
before editing.

## Rules for every item

- Write the failing test first, in `tests/test_regex_hardening.py` or next to the module's existing tests.
  Use a wording or input the real tool produces; where the audit inferred a wording, capture a real log in
  the analysis image before changing the pattern (items marked **capture first**).
- A parser that guards a verdict must fail closed: an input it does not recognise is `unknown` or an error,
  never "nothing found". `loop_seeds.py:612-624` is the model (the CSV row decides, the regex only labels).
- Record each fixed defect in [`../troubleshooting/README.md`](../troubleshooting/README.md), in the sub-document of its phase.
- `scripts/run_eacsl_fuzz.py`, `generate_harness.py`, `api_harness.py` and `harness_reach.py` had another
  session's uncommitted work on 2026-11-11. Start the workstreams that own them (C, D) after that work is
  committed, in a worktree cut from the integration branch.

## Workstream A: remaining verdict-affecting defects (do first)

Not re-checked by the parent session; each needs its reproduction confirmed before the fix.

| Item | Where | Change | Note |
|---|---|---|---|
| A1 | `run_wp_function.py` `_TIER_B_PATTERNS`, `run_eva_slice.py:680` | Flag every `Neither code nor <X> for function` unless X is only exits/terminates | **capture first** |
| A2 | `run_wp_function.py:118` Doomed pattern, `classify_vacuity_log` | Drop the `typed_` prefix; parse `Smoke Tests: k / n`; return `inconclusive` when k < n and nothing was recognised | |
| A3 | `run_wp_function.py:461-462`, `:1602-1606` | With a report CSV and no `Proved goals` line, do not return `all_proven` | backstop of the Degenerated-goal waiver |
| A4 | `run_eacsl_fuzz.py` `_FN_RE`, `_ERR_RE`, `_OLD_RE`, `_UBSAN_RE` | File part `[^\s:'"]+`, anchored on `:\d+: Error:` / `: runtime error:` | workstream D owns the file |
| A5 | `run_eacsl_fuzz.py` `_STACK_FRAME_RE` (attribution, fingerprint) | Parse the function apart from the file; no parsable frame must not fingerprint as `unknown#unknown_function` | workstream D |
| A6 | Six tests that pass while the guard is broken | See "Tests" in workstream E | |

Owner files: `run_wp_function.py`, `run_eva_slice.py` (A1-A3). Done when each has a test on a captured log.

## Workstream B: replace by a structured source

| Item | Regex today | Replace with | Files owned |
|---|---|---|---|
| B1 | `stub_check._WARNING_RE` on the Eva log | `-report-csv` rows read with `framac_common.read_report_csv`, as `run_eva_slice.py` does | `stub_check.py` |
| B2 | Clause splitting at the first `;`: `mutation_check._ENSURES_CLAUSE_RE`, `acsl_ast.find_named_clause`, `acsl_ast._ASSIGNS_RE` + 6-character `loop` look-back | One helper in `acsl_ast.py`, `iter_clauses(text) -> (kind, label, predicate, span)`, built on `_scan_clause_end` and the segment parser; `_first_vacuous_clause` moves onto it too | `acsl_ast.py`, `mutation_check.py` |
| B3 | Comment and literal stripping by regex (about ten places: `generate_harness._strip_c_comments`, `pipeline_make.py:677`, `workspace_overlay.py:534`, `benchmark_briefs.py:115`, `stub_check.py:596, 616`, `c_definitions.py:169, 268`, `function_slice.py:906, 1774`, `acsl_ast.py:870, 982`) | One `acsl_ast.mask_comments_and_literals(text)` on `tokenize_c_acsl`, keeping offsets (blank, do not delete) | `acsl_ast.py` first, then one caller file per agent |
| B4 | Single-line patterns on two-line Frama-C messages: `ACSL_ERROR_RE`, `_KERNEL_ERR_RE`, the Tier B consumers, `Missing assigns clause` (`run_wp_function.py:460`) | One `framac_common.fold_messages(log) -> [(plugin, file, line, kind, text)]`, generalising `kernel_parse_errors`; fix the one-line fixture in `tests/test_workspace_overlay.py:305` | `framac_common.py`, `run_wp_function.py`, `run_eva_slice.py` |
| B5 | C signatures from raw header text: `generate_harness.py:484, 648` `sig_head_re`, `_PARAM_DECL_RE` fallback | Phase 0 model `formals` / `signature`, as `api_harness.plan_params` uses; keep the regex only for GCC-fallback units, as one function | `generate_harness.py` |
| B6 | `build_capture.py:971` declaration test on a preprocessed header | Parsed declarations of the Phase 0 model per header | `build_capture.py`, `phase0_model.py` |
| B7 | `_MAIN_DEF_RE` (`pipeline_make.py:669`, `generate_harness.py:2123`) | `defined_functions` of the capture (nm) | `pipeline_make.py`, `generate_harness.py` |
| B8 | The pipeline re-reading its own dispatch harness: `run_eacsl_fuzz.py:181`, `seed_harvest.py:1061`, `api_harness.py:1031`, `seed_harvest.case_bindings` | Case count and bindings written to `harness_<module>.json`; schema `harness_sidecar.schema.json` | `generate_harness.py`, `api_harness.py`, `seed_harvest.py`, `run_eacsl_fuzz.py`, schema |
| B9 | `function_facts._TEMP_RE` (`tmp`, `tmp_1`, `__retres`) | A `temp` flag per variable from `kernel_ast_dump.ml` (`v.vtemp`) | `kernel_ast_dump.ml`, `kernel_ast.py`, `function_facts.py` |
| B10 | `function_slice._SYNTAX_LINE_RE` on the repo's own exception text | `line` and `kind` attributes on `AcslSyntaxError` | `acsl_ast.py`, `function_slice.py` |
| B11 | `harness_reach._used_identifiers` (token heuristic, added 2026-11-11) | Callee references from clang's JSON AST, which `api_harness._walk_records` already reads; keep the token rule as the fallback without clang | `harness_reach.py` |
| B12 | C declarators by regex: `stub_check.struct_members`, void-return detection in `stub_gen.py:240` and `stub_check.py:130` | `c_definitions._resolve_declarator` and `_strip_trailing_attributes`; one shared `returns_void` | `stub_check.py`, `stub_gen.py`, `c_definitions.py` |

Order: B2, B3 and B4 first (they add the shared helpers the others use); then B1, B9, B10, B12 in parallel;
B5-B8 and B11 after the other session's harness work lands. B8 changes a schema and three readers: one agent.

## Workstream C: correct in place (pipeline logic)

| Item | Where | Change |
|---|---|---|
| C1 | `minischema.py:155`; `.match` with `^...$` in `pipeline_make.py:125`, `ledger.py:113`, `cache.py:76`, `run_metadata.py:189, 285`, `trust.py`, `validate_artifacts.py:52`, `workspace_overlay.py:1095`, `run_eva_slice.py:100, 398`, `eva_loops.py:37`, `framac_common.py:356` | `fullmatch`; in `minischema`, translate a trailing `$` to `\Z` at load |
| C2 | Schema pattern `"#"` (20 uses in `phase0_model`, `build_capture`, `security_props`) | One `$defs` entry `^[^#\s]+#[A-Za-z_][A-Za-z0-9_]*$`; move the copied fingerprint, identifier and sha256 patterns to `$defs` too |
| C3 | `threat_model.schema.json:51` | Reject `*/` and `/*` in the C expression |
| C4 | `resources.py:1706-1737` `is_known_static_command` | Decide from `pipeline_make.STAGE_OF_TARGET` with an allow-list; require the `/opt/framac-pipeline/scripts/` prefix; unknown target is not static |
| C5 | `benchmark.py:80` `_HOST_PATH_RE` | Any absolute path outside the run and tree prefixes |
| C6 | `framac_common.py:770` | Accept GCC's curly quotes |
| C7 | `eva_loops.py:39, 160` | Recognise `/*@\n  @ loop`; **capture first** whether Frama-C accepts the doubled annotation |
| C8 | `frame_skeleton.py:108-113` | Named groups; bound up to the next `&&` / `||`; `unknown` unless the bound is one identifier or literal; remove the dead `lastindex` branch |
| C9 | `mutation_check.py:68, 98` | Token-aware `return` mutation (as `_c_operators`); do not turn `<==>` into `<=>` |
| C10 | `acsl_ast.py:66-70` | Logic signatures with a label list `{L}`, bare `unsigned`, `uintptr_t` |
| C11 | `run_wp_function.py:95, 123`, `loop_seeds.py:545` | Anchor on folded messages (after B4); `(?<![\w./-])` before the file name |
| C12 | `trust._FENCE_RE` | Line scanner instead of a lazy DOTALL match (quadratic on unclosed fences) |
| C13 | `wp_scheduler.py:167` `_PLACEHOLDER_RE` | Derive from the render keys |
| C14 | `build_capture._COMPILER_RE` | Add `tcc`, `icx`, `afl-clang-fast`, versioned `gcc-13-posix`; log a skipped compiler-like executable |

## Workstream D: correct in place (fuzz, harness, E-ACSL)

After the other session's work on these files is committed. One agent per file.

| Item | Where | Change |
|---|---|---|
| D1 | `run_eacsl_fuzz.py` `_ASAN_ERR_RE` | Multi-word kinds (`attempting double-free`, `attempting free on address which was not malloc()-ed`, `requested allocation size`), so the `bad-free` branch can fire |
| D2 | `run_eacsl_fuzz.py` `_ASAN_OP_RE` | Drop the access size from the fingerprinted predicate, as `stable_ubsan_message` does for UBSan |
| D3 | `run_eacsl_fuzz.py:2790`, `eacsl_toolchain.py:777` | lld wording `undefined symbol:` |
| D4 | `eacsl_toolchain.py:1041` `_CALL_SITE_RE` | **capture first** the forms Frama-C prints (`if (f) fclose(f);`, `return close(fd);`); log when a libc call gets no shim |
| D5 | `eacsl_toolchain.py:314, 479` | `\d+U?L*`; warn when store_block lines exist and none match |
| D6 | `api_harness.py:98-100` | Word-bounded `Init` / `Free` / `Destroy` / `Release` |
| D7 | `generate_harness.py:138` | Multi-dimensional arrays and pointers to arrays (or B5) |
| D8 | `fingerprint.py:69, 134` | Strip a label only before `:`; compile the kind alternation once |

## Workstream E: remove, dedupe, tests

Removals (plain string operations):
`workspace_overlay.py:788, 2609` and `build_capture.py:1241-1256` (`removeprefix` / `removesuffix`),
`validate_artifacts.py:452` (`startswith`), `eva_options.py:46` and `framac_common.py:90` (`partition(":")`),
`frame_skeleton.py:82` (`==`), `prover_candidates.py:322` (`endswith`), `run_wp_function.py:463`
`_ASSIGN_VC_FAIL_RE` (the CSV bucket `step_a_assigns`), `resources.py:1687` `_PLAIN_COMMAND`,
`c_definitions.py:169, 268` fallback (use `function_slice._tokenize_tolerant`).

One definition instead of several, in a new `scripts/patterns.py` (no imports from the pipeline, so every
script can use it): C identifier, slug sanitiser, tree prefix (`workspace/work`, `agents/<id>/scratch/work`),
`file:line` location, module name, call site `name(`. Then:
`parse_make_deps` (keep `cache.py:1063`, drop `build_capture.py:959`), `_parse_size` / `parse_mem` (one,
accepting `Gi`), the three `(.+)_\d+` copies, `stub_gen._LOC_RE` (use `kernel_ast.parse_location`, which
must stop returning line 0 silently), `_FUZZER_INIT_DEF_RE` ×3, `_FUZZER_ENTRY_DEF_RE` ×2, `_DOMAIN_RE`,
`_ASSIGNS_RE` (`libc_gap_report`, `stub_gen`).

Tests:
- `test_remediation_p2_container.py:132-133`: `findall`, two services, no uid or gid `0`; `:151`: `shlex` and
  membership instead of `\b`.
- `test_r8_capture.py:264`: no `^RUN` anchor; `:257-261` and `test_run_identity_wrappers.py:161`: one helper
  returning the set of chmod / mkdir arguments; anchored `^ARG ...{64}$`.
- `test_image_toolchain.py:40`: unnamed stages included.
- `test_ci_workflows.py:105-113`: `[|>][+-]?\d*` block headers; job indent not hard-coded.
- `Proved goals` in five test files: one helper in `conftest.py`, asserting `total > 0`.
- Four loose `pytest.raises(match=...)`, the three Makefile recipe parsers (one helper), and
  `test_function_facts.py:763` (import `_IF_RE` / `_ENDIF_RE`).

## Dispatch

Disjoint file ownership per agent, as for earlier large changes:

1. A (one agent: `run_wp_function.py`, `run_eva_slice.py`), with B4 since it owns the same files.
2. B2 + B3 + B10 + C10 (one agent: `acsl_ast.py`, `mutation_check.py`, `function_slice.py`), then the B3
   caller files split between two agents.
3. B1 + B12 (one agent: `stub_check.py`, `stub_gen.py`, `c_definitions.py`).
4. C1-C5, C12-C14 and the schema work (one agent: `minischema.py`, schemas, `resources.py`, `benchmark.py`,
   `trust.py`, `build_capture.py`); B6 joins it.
5. E tests (one agent, `tests/` only), E `patterns.py` and dedupe last, since it touches most scripts.
6. D and B5, B7, B8, B11 after the harness files are free.

After each group: `pytest -n auto`, `ruff check`, `mypy scripts`. Before merging: one Phase 0 to Phase 3 run
on libmnl, since C1, C4, B8 and the reach-gate change alter gates that unit tests cover only in part.

## Not judged by the audit

About 75 uses were seen as patterns only: `fc_cpp_wrapper.py:104-340` and its `<==>` rewriter,
`generate_harness.py:1635` `_HARNESS_IDENT_RE`, most of `fuzz_dictionary.py`. Review them with workstream D.
