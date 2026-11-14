# Frama-C 34 option review (2026-11-14)

Every option of the kernel and of the 36 plugins in `framac-analysis:latest` (Frama-C 34.0~beta), set against what the pipeline passes today, to find features the pipeline does not use. Nothing here is built yet; candidates 1-4 were tried on 2026-11-14 (see "Trial results"). Each candidate needs its own trial before any pipeline change, as with Tier 1b of [`./papers-generalization-plan.md`](./papers-generalization-plan.md).

## Method

- **Help read:** `frama-c -<plugin>-help` for every plugin listed by `frama-c -plugins`, plus:
  - `-kernel-help` and `-eva-help-options`. `-eva-help` is only a 9-line overview; the option list is in `-eva-help-options`.
  - `-eva-help-domains`, `-wp-auto '?'`, and the option parser of `e-acsl-gcc`, whose `--help` shows only basic options.
- **Usage check:** each option name was searched for in `scripts/`, `templates/`, `skills/`, `wrappers/`, `tools/` and the `Dockerfile`. Eva tuning options were checked against the allowlist in [`../../scripts/eva_options.py`](../../scripts/eva_options.py), which spells them without the `-eva-` prefix.
- **What the pipeline uses, out of the options each tool has (boilerplate `-X-help`, `-X-log`, `-X-verbose` and so on included):**

  | Plugin or tool | Used / available |
  |---|---|
  | Kernel | 35 / 131 |
  | Eva | 16 / 109 on the command line, plus about 40 tuning options through the allowlist |
  | WP | 21 / 114 |
  | E-ACSL | 10 / 36 |
  | RTE | 3 / 19 |
  | MetAcsl | 3 / 23 |
  | Report | 2 / 30 |
  | Metrics | 2 / 18 |
  | Nonterm | 2 / 11 |
  | Inout / From | 4 / 17 and 1 / 12 |
  | Callgraph | 1 / 15 |
  | Markdown report | 3 / 18 |

  ACSL importer, Aorai, Dive, Impact, Instantiate, Occurrence, PDG, Reduction, Scope, Slicing, Sparecode, Studia, Server and Obfuscator are not used at all.

## Defect found: Eva allowlist entries Frama-C 34 rejects (fixed)

Three entries of the allowlist produced command lines Frama-C 34 aborts on. They are fixed in [`../../scripts/eva_options.py`](../../scripts/eva_options.py), and the entry is in [`../troubleshooting/eva.md`](../troubleshooting/eva.md).

## Candidates, ranked

Ranked by expected effect on findings or proofs, against the cost of a trial.

| # | Option or plugin | Phase | What it adds | Why it may matter here | First trial |
|---|---|---|---|---|---|
| 1 | `e-acsl-gcc --temporal` (`-e-acsl-temporal-validity`) | 1 | Temporal validity: a pointer to a freed block stays invalid even after the address is reused | E-ACSL campaigns build with `-fsanitize=fuzzer` only; ASan and UBSan are only in the fallback build ([`../../scripts/run_eacsl_fuzz.py`](../../scripts/run_eacsl_fuzz.py), `compile_sanitizer_binary`). A use-after-free on reused memory is invisible to spatial `\valid` checks | Seeded benchmark: a UAF-after-realloc and a dangling stack pointer. Measure detection, exec/s and build failures with and without |
| 2 | `e-acsl-gcc --libc-replacements` (`-e-acsl-replace-libc-functions`) | 1 | Checked `memcpy`, `memmove`, `memset`, `memcmp`, `str[n]cpy`, `str[n]cat`, `str[n]cmp`, `strlen` | Without ASan's interceptors, a bad length passed to these in an E-ACSL build goes unchecked inside libc | Same seeded benchmark, plus libmnl's known over-reads (LIBMNL-04) |
| 3 | `e-acsl-gcc --validate-format-strings` | 1 | Format string checked against the argument types at run time | Format-string bugs (CWE-134) and type mismatches are not checked by any phase today | One seeded format bug; libseccomp's `tools/` print through `printf` |
| 4 | `-wp-auto` strategies (`wp:split`, `wp:range`, `wp:bitrange`, `wp:bittestrange`, `wp:bitwised`, `wp:bitshift`, `wp:congruence`, `wp:replace`) | 3 | Automatic tactics on goals the provers leave Unknown, with no LLM | libmnl's remaining Unknowns are `MNL_ALIGN` masks (`& ~(4 - 1)`), the kind of goal the bit tactics target. A goal closed this way costs no prover iteration | Re-run WP on the 30 libmnl and a sample of libseccomp run-4 Unknown RTE goals with `-wp-auto wp:bitrange,wp:bitwised,wp:range,wp:split`; count goals closed and time |
| 5 | Instantiate plugin (`-instantiate`) | 3 | Replaces `memcpy`, `memset`, `memcmp`, `memmove`, `malloc`, `calloc`, `free` calls with type-specialised versions whose contracts WP handles better | WP proofs of callers of these functions go through `void *` contracts | Count the `call_memcpy_requires`-style goals left Unknown in the last runs first; trial only if there are some |
| 6 | Structured outputs: `-wp-report-json`, `-report-classify -report-output <file.json>`, `-metrics-output <file.json>` | 2, 3 | JSON instead of console text | Several parsers read Frama-C's console output (see [`./regex-hardening-plan.md`](./regex-hardening-plan.md)). JSON from Frama-C itself removes a class of parser breakage on upgrades | Diff each JSON against what the current parsers extract on one run, then decide per parser |
| 7 | `-from-verify-assigns` | 3 | Checks `assigns ... \from` clauses of functions with bodies using the From analysis | A cheap second check on prover-written `assigns` clauses | One module with merged contracts: compare with WP's assigns verdicts |
| 8 | Dive (`-dive-from-alarms <f> -dive-output-json`) | 2 | A JSON graph of where the imprecision behind an Eva alarm comes from | Would point `eva-tune` and stub decisions at the source of an Unknown instead of the function it surfaces in | On libseccomp's `getopt` Unknowns (Cause C in [`../troubleshooting/eva.md`](../troubleshooting/eva.md)), check that the graph names `getopt` |
| 9 | `-audit-prepare` | 0, 2 | Every source and header used in parsing, with checksums, as JSON | Cache keys and run identity are built by the pipeline; Frama-C's own list includes headers the pipeline may not hash | Compare with the cache input digest of one module |
| 10 | `-eva-warn-signed-converted-downcast` | 2 | Warns on the second half of a signed downcast that the default skips | More precise downcast alarms where the pipeline already checks downcasts | Count new alarms on the benchmark; keep only if they are real |
| 11 | `-compilation-db` | 0 | Per-file flags from `compile_commands.json`, which Phase 0 already writes | Could replace the per-module `cppflags` the pipeline assembles | Only if per-file flags differ within a module somewhere; check the captured databases first |

## Trial results (2026-11-14): candidates 1-4

All runs on `framac-analysis:latest` (34.0~beta). E-ACSL builds use the pipeline's two-stage commands from [`../../scripts/run_eacsl_fuzz.py`](../../scripts/run_eacsl_fuzz.py):
- stage 1: `e-acsl-gcc -n --no-constfold -G clang -F "-rte -e-acsl-full-mtracking -rte-initialized @all" -E "-Dregister=" ...`;
- stage 2: `e-acsl-gcc -C -G clang -e "<EACSL_CODEGEN_FLAGS>"`.

The flag under test is added to both stages.

### E-ACSL flags: seeded defects

One program with nine seeded defects and a clean control. Cell = the defect is reported by E-ACSL (abort with a message naming it).

| Case | Today | `--temporal` | `--libc-replacements` | `--validate-format-strings` | All three |
|---|---|---|---|---|---|
| clean control | clean | clean | clean | clean | clean |
| `p[8] = 1` on `malloc(8)` | yes | yes | yes | yes | yes |
| use after free, block reused at the same address | **no** (runs on) | yes | no | no | yes |
| dangling pointer to a returned frame | yes (`\initialized`) | yes | yes | yes | yes |
| `memcpy(dst8, src, 16)` | **no** (corrupts, exit 65) | no | yes | no | yes |
| `strcpy` into a too-small buffer | **no** (SIGSEGV) | no | yes | no | yes |
| `strlen` on an unterminated buffer | **no** (returns garbage) | no | yes | no | yes |
| `printf("%s", long)` | **no** (SIGSEGV) | no | no | yes | yes |
| `printf(user_fmt)` with `%s%s%s%n` | **no** (SIGSEGV) | no | no | yes | yes |
| `memset(p4, 0, 8)` | **no** (runs on) | no | yes | no | yes |

The "Today", `--temporal` and `--libc-replacements` columns were built without `-e` (`e-acsl-gcc`'s clang defaults). The other two were built with the pipeline's `-e` backend flags. The outcome for an unreported defect (exit code, signal) varies between those builds, but whether a defect is reported does not. Today's build reports 2 of the 9 defects. With all three flags, it reports 9 of 9. Each flag catches exactly the class it claims. Before the flags, the libc cases crashed later or not at all, with no message pointing at the call.

### E-ACSL flags: build and cost

- **Build.** `--temporal` and `--libc-replacements` build as-is.
  - `--validate-format-strings` fails to build its runtime under `-G clang` alone: `vabort`, `isdigit` and `vsyslog` are undeclared, and the link fails on `valid_string`.
  - Both come from `e-acsl-gcc`'s clang branch dropping `-O2` and `-Wno-implicit-function-declaration` (upstream Issue 10, consequence added to [`../upstream/frama-c/frama-c-eacsl-gcc-clang-cflags.md`](../upstream/frama-c/frama-c-eacsl-gcc-clang-cflags.md)).
  - The pipeline's backend flags (`EACSL_CODEGEN_FLAGS`: `-O1 ... -Wno-implicit-function-declaration`) already restore both, and with them it builds and runs.
- **Runtime cost.**
  - Probe program (heap churn, string calls, `snprintf`; about 1.2 s; best of 3): `--temporal` +7 %, `--libc-replacements` +4 %, `--validate-format-strings` +5 %, all three +13 %.
  - Replaying libmnl's 1,405-file `callback` corpus (`-runs=0`): base 5.27 s, libc + format 5.28 s, all three 5.30 s.
  - A WP job shared the machine during these runs, so the figures are indicative.

### E-ACSL flags on libmnl (run3-rep, `attr`, `nlmsg`, `callback` harnesses)

The run's annotated `workspace/work` tree does not instrument without the pipeline's E-ACSL preprocessor wrapper. It hits the known `<==>` E-ACSL bug, Issue 14, which the 34.0~beta release has too. So the libmnl builds below use the run's `workspace/baseline` sources, with the module's own `-rte-select` and `-e-acsl-functions` lists taken from its recorded breaker command.

- **`--libc-replacements` + `--validate-format-strings`.** These build and fuzz on all three harnesses.
  - On `nlmsg` the first stop is `memcpy: overlapping memory areas` in `mnl_nlmsg_batch_reset`. That is the root cause of the known LIBMNL-01, reported at the call during seed replay; the current build stops at an RTE assertion instead.
  - On `attr` both builds stop at the same `attr.c:101` assertion.
  - On `callback` neither build stopped in 3 × 90 s with fixed seeds. One earlier unseeded base run hit the `callback.c:29` signed overflow by chance.
- **`--temporal`.** It does not work in a fuzz target, for two reasons:
  1. **The entry point.** The instrumented `LLVMFuzzerTestOneInput` pulls temporal metadata for `data` that libFuzzer (not instrumented) never saved, so the first input aborts with `Unreachable`.
     - A wrapper in `fuzz_init.c` (`__e_acsl_temporal_save_nblock_parameter(data, 0)` then the renamed entry, through `-DLLVMFuzzerTestOneInput=framac_fuzz_entry`) fixes this part.
  2. **Callbacks under full tracking.** With `-e-acsl-full-mtracking`, which fuzz targets need, a callee pulls metadata for a function-pointer parameter that the call site never saves.
     - libmnl's `mnl_attr_parse_nested(nest, &cb, data)` aborts, and so does a 10-line reproducer.
     - This is an upstream bug: [`../upstream/frama-c/frama-c-eacsl-temporal-function-address-argument.md`](../upstream/frama-c/frama-c-eacsl-temporal-function-address-argument.md) (Issue 15). The pipeline cannot work around it.

### E-ACSL flags: decision

- **Adopt `--libc-replacements` and `--validate-format-strings`.** Adopted 2026-11-14 (uncommitted):
  - `EACSL_GCC_CHECK_OPTIONS` in [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py) passes both options to both stages of [`../../scripts/run_eacsl_fuzz.py`](../../scripts/run_eacsl_fuzz.py)'s build. Stage 2 needs `--validate-format-strings` for the runtime define. The options are also in the build cache key.
  - Before this change the classifier did not read their stops. The messages are bare lines (`memcpy: insufficient space in destination space , at least 16 bytes required`, `printf: directive 1 ('%s') expects argument of type 'char*' ...`), with no `file:line: Assertion failed`. `parse_eacsl_failure` now matches the runtime's closed list of templates:
    - `kind` is `eacsl_libc_error` or `eacsl_format_error`.
    - The alarm kind is `mem_access`, `separation`, `valid_string` or none.
    - Sizes, directive numbers and the format string are dropped from the fingerprinted predicate.
    - The calling function comes from libFuzzer's stack; `file` is `unknown` and `line` 0.
    - The existing sanitizer replay then attributes the memory errors. The format errors keep no source location (backlog).
  - A stop at seed replay masks everything behind it, as LIBMNL-01 does on `nlmsg`. That is the existing stop-at-first-crash gap (libmnl gate experiment), not new.
  - Checked through the production path (`run_eacsl_fuzz.py`, mounted repo, `framac-analysis:latest`):
    - The canary selftest passes.
    - libmnl `nlmsg` on `workspace/work`: the LIBMNL-01 input stops on `memcpy: overlapping memory areas`, and the sanitizer replay attributes it to `src/nlmsg.c:580` in `mnl_nlmsg_batch_reset` (`separation`).
    - A control harness found false alarms on strings libc allocated itself: `fprintf("%s", strerror(e))` and `strncpy(d, strerror(e), n)` stop. Five other controls ran clean, including `getenv` strings, `snprintf` and `strcpy` from a literal.
    - Hence the per-module opt-out `pipeline_make.py params set --module <mod> --no-fuzz-libc-checks`, recorded in `reduced_checks` as `-no-libc-checks`.
  - The "8/9" figure is derived from the per-flag runs; no build with exactly these two flags ran the seeded cases.
- **Do not adopt `--temporal`** until Issue 15 is fixed upstream. The entry-point wrapper alone is not enough.

### `-wp-auto`

**Setup.** WP ran as [`../../scripts/run_wp_function.py`](../../scripts/run_wp_function.py) runs it:
- Typed model, `-wp-rte -wp-split`, `-wp-check-memory-model`;
- provers Alt-Ergo, Z3 and CVC5, 15 s timeout, `-wp-par 4`, `-wp-cache none`;
- the run's warning flags.

Each function ran twice, without and with `-wp-auto wp:bitrange,wp:bitshift,wp:bittestrange,wp:bitwised,wp:congruence,wp:range,wp:replace,wp:split`. The functions were:
- **libmnl:** the 4 functions with Unknown goals in run3-rep (`work` tree with merged contracts).
- **libseccomp:** 16 run-4 functions with Unknown RTE goals: 12 arithmetic-heavy, plus 4 pointer-validity controls.

The auto logs show `(Tactics N)` on goals, so the strategies were applied.

| Target | Goals | Proved without | Proved with `-wp-auto` | Time without | Time with |
|---|---|---|---|---|---|
| libmnl `mnl_attr_next`, `mnl_attr_nest_cancel`, `mnl_nlmsg_batch_next` | 49 | 43 | 43 | 51 s | 113 s |
| libmnl `mnl_nlmsg_fprintf_payload` | 1077 | 976 | not finished (30 min cap; 19 min without) | 1143 s | > 1800 s |
| libseccomp, 16 functions | 199 | 107 | **118** | 948 s | 2180 s |

The 11 goals closed only with `-wp-auto` are all integer RTE goals:
- `_htot16`: `signed_overflow`, `unsigned_downcast`;
- `_htot32`: two `unsigned_overflow`;
- `_get_bintree_levels`: one `unsigned_downcast`;
- `hash`: six `signed_overflow` / `unsigned_downcast` parts.

`hash` gives 30 → 36 of 67 but takes 1295 s instead of 418 s. The pointer-validity controls (`_hsh_find_bkt`, `db_col_valid`, `_db_chain_eq`, `_pfc_arg`, `_blk_alloc`) and libmnl's `MNL_ALIGN` goals gained nothing.

`mnl_nlmsg_fprintf_payload` overlapped the E-ACSL fuzz runs, so its times are indicative. The libseccomp batch ran mostly alone.

**Decision.** Worth adopting as a **second pass**, not on every WP run. Over a whole function it costs 2.3× the time and slows large functions past any practical cap. The gain is concentrated on the arithmetic RTE goals that otherwise go to a prover subagent.

Next step:
- re-run only the goals still Unknown after the normal run, with `-wp-auto` and the same strategies, under its own time budget;
- count how many goals it removes from the prover queue on a full run.

That needs a goal filter, for example `-wp-prop` on the unproved property names. Check which of those names `run_wp_function.py` can already get.

### Considered and not proposed

### Considered and not proposed

- **Reduction plugin (`-reduc`).** Same Eva states as `-eva-annot`, with many more assertions and no per-function selection. See "Tier 1b" in [`./papers-generalization-plan.md`](./papers-generalization-plan.md).
- **`-eva-secure-flow`, `-eva-taint-auto`.**
  - Secure flow needs custom attributes on the target's data. The pipeline expresses Layers 5 and 6 through MetAcsl instead.
  - `-eva-taint-auto` only taints parameters of input functions (`scanf`, `fgets`). The pipeline's harnesses do not read through those, and the taint domain is already reachable through `--extra-domains`.
- **Slicing, Sparecode, Impact, PDG, Scope, Occurrence, Studia.** Code-navigation and slicing tools. The pipeline slices by link unit and call graph itself, and Studia has no command-line option beyond the boilerplate.
- **Aorai, Volatile, Region, Alias, ACSL importer, Server, Obfuscator, Mthread (`-mthread`, `-mt-*`).**
  - These are out of scope for the targets so far, which are single-threaded, have no automata properties and no volatile hardware access.
  - The ACSL importer would keep contracts out of the sources, but splicing into the overlay is how the pipeline checks scope today.
- **`-lib-entry`.** An alternative to harnesses for Eva. The harnesses carry the trust boundary and the seeds, so it would be a different analysis, not a tuning.
- **WP simplification switches** (`-wp-split-cnf`, `-wp-prenex`, `-wp-simplify-forall` and similar). These are worth trying only after `-wp-auto`, on the goals it leaves.
