# [e-acsl] demote the string literals registered under full memory tracking

- Source branch: `fix/eacsl-full-mtracking-literals` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`; re-validated on `95408044f7` (2026-11-17), the base to branch from. Patch: [`../patches/28-eacsl-full-mtracking-tail-merged-literals.patch`](../patches/28-eacsl-full-mtracking-tail-merged-literals.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2817.

## Problem

With `-e-acsl-full-mtracking`, `Global_observer` registers every global as a block, including the variables that represent string literals. The memory tracking analysis demotes the literals it monitors to named arrays (`Demote_string_literal.demote` in `Varinfos.add`), but the public `must_monitor_*` functions do not run it under full tracking. So the literals stay literals and are printed as such in `__e_acsl_globals_init` and at their uses, and the registered blocks depend on how the toolchain lays out literals. With clang and GNU ld, `","` is stored at the end of `" ,"`, the two blocks overlap, and `\valid_read(" ," + 1)` fails on correct code (#2817). The commit message of `9e28a826d0` already says why a monitored literal must not be printed as a literal.

## Change

- `plugins/e-acsl/src/code_generator/injector.ml`: under full tracking, before the injection, demote every string literal global that will be registered (`Ast_info.is_string_literal vi && Memory_tracking.must_monitor_vi vi`). Without full tracking nothing changes: the analysis demotes the literals it monitors, as before.
- `src/kernel/services/ast_transformations/demote_string_literal.ml(i)`: new `demote_list`, which demotes a list of literals in one traversal of the AST and calls `Ast.mark_as_changed` once; `demote vi` is now `demote_list [vi]`. This kernel part is there only for cost. Calling `demote` once per literal costs one traversal of the AST per literal; instrumenting a generated file with 400 functions and 4,000 literals under full tracking took:

  | literals used as | master | `demote` per literal | `demote_list` |
  | :-- | --: | --: | --: |
  | `const char *p = "..."` (4,000) | 2.0 s | 98 s | 2.4 s |
  | `char a[] = "..."` (4,000) | 1.9 s | 117 s | 2.1 s |

  (One traversal but `Ast.mark_as_changed` once per rewritten `Local_init`, as `demote` did, still took 12 to 13 s on the second line. Single runs, wall-clock time of `frama-c -e-acsl -e-acsl-full-mtracking -then-last -print`.) The default mode has the same per-literal cost today: on `master`, the same file with an assertion on each literal and without full tracking takes 217 s for 4,000 literals (76 s for 2,000). This merge request does not change that path; `demote_list` could serve there too.

Semantics after the change, as without full tracking: each literal occurrence is its own `char const __fc_lit_stringN[]` (two occurrences of `","` give two arrays), registered once in `__e_acsl_globals_init` and marked read-only (`\valid_read` true, `\valid` false); a local `char buf[] = "ab";` becomes a compound initializer; the literals that E-ACSL itself generates (`"Assertion"`, file and function names) are not registered and stay literals.

New test `full-mtracking/literal_strings.c`: `" ,"` and its suffix `","`, `","` twice, a literal in a loop, a local array initialized from a literal, and `\valid_read` / `!\valid` on literals. The test suite compiles with gcc and `-fno-merge-constants`, so the run-time failure of #2817 cannot show there; the regression test is the generated-code oracle `gen_literal_strings.0.c`, where the literals are named arrays. Built by hand with `e-acsl-gcc -G clang -F -e-acsl-full-mtracking`, the same test fails at run time on `master` (`literal_strings.c:19`, `\valid_read(s + j) && !\valid(s + j)`, `j: 1`, exit 134) and passes with the patch.

Existing oracles changed: `concurrency/oracle/gen_parallel_threads.0.c` and `concurrency/oracle/gen_threads_debug.0.c` (the concurrency support turns full tracking on). Only their literals change: 14 `perror` messages become `__fc_lit_stringN` arrays, declared before their function and registered by name.

Overlap with other open merge requests: !28 also rewrites these two concurrency oracles (formals marked initialized); `git am --3way` of this patch after it applies cleanly, but that is a textual merge: whichever of the two lands second should regenerate these oracles. The full-tracking oracle `libc/oracle/gen_getenv.1.c` of !33 registers the literal `"PATH"` as a literal; whichever of !33 and this merge request lands second needs that oracle regenerated (`"PATH"` becomes `__fc_lit_string1`).

## Testing

All on Debian 13 (gcc 14.2.0, clang 19.1.7, GNU ld 2.44), `master` at `3dff90fc70` built with dune, then the same tree with this patch:

- Reproducer of #2817, built with `e-acsl-gcc -q -G clang -F -e-acsl-full-mtracking`, `-G gcc -F -e-acsl-full-mtracking` and `-G clang`. Before: the clang + full tracking build aborts at `suffix.c:6` (`\valid_read(charset + j)`, `j: 1`, exit 134), the two others exit 0; same on 34.0~beta. After: all three exit 0, and the full-tracking builds register `__fc_lit_string2` and `__fc_lit_string1` instead of `" ,"` and `","`.
- A global initializer `const char *tbl[] = {" ,", ",", "x"};` with clang and full tracking: `tbl` is initialized with the named arrays, and the program runs clean before and after.
- The new test, built with clang and full tracking as above, aborts on `master` and runs clean with the patch. Its oracle check fails on unpatched `master` (oracle difference: the five literals are printed as literals, registered as `__e_acsl_store_block((void *)" ,",3UL)`, and `char buf[3UL] = "ab";`) and passes with the patch.
- `frama-c-ptests -create-missing-oracles plugins/e-acsl/tests`, then `dune build --release -j 8 @plugins/e-acsl/tests/ptests_config` (198 results): the only differences are the new test's oracles and the two concurrency oracles above, which I promoted; on the final run every test matches its oracle.
- `ptests_config_dev` (compiled and run) of `full-mtracking`, `concurrency`, `builtin`, `special`, `bts` and `memory`: every test matches its oracle.
- Rerun on current `master` (`95408044f7`): the patch applies with `git am`; the reproducer gives the same results before and after; the new test's oracle check fails on the unpatched sources and passes with the patch; the default configuration of the whole E-ACSL suite (198 results) passes; and the `dev` configuration of `format/` (`fprintf.c`, `printf.c`, `sprintf.c`), which also runs with full tracking, passes.
- `tests/misc/string_literal.ml` (`dune build @tests/misc/runtest`, the kernel test that calls `Demote_string_literal.demote`) passes; a negative control (an extra line in its `.expected`) fails.
- `./dev/check-files.sh -p HEAD~1` (`make check-lint` and `make check-headers` on the changed files, with ocp-indent 1.10.0, headache 1.08 and clang-format 19.1.7): passes; the new test is clang-formatted.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the reproducer and tests described above.
