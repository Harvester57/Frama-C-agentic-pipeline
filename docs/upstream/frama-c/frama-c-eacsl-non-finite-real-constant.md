# E-ACSL: non-finite suffixed floating-point constants (`1e40f`, `1e400d`) emit undeclared `inf` and `__gmpq_set_d(..., inf)`

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 53 of this folder, drafted on 2026-11-22. Filing remains paused pending the
maintainers' reply on [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/53-eacsl-non-finite-real-constant-issue.md),
[MR text](./filing/53-eacsl-non-finite-real-constant-mr.md),
[reproducer](./repro/53-eacsl-non-finite-real-constant.sh) with its
[C file](./repro/53-eacsl-non-finite-real-constant.c), and
[patch](./patches/53-eacsl-non-finite-real-constant.patch) (validated on `master` `189053d4a2`).

## Summary

When an ACSL annotation contains a suffixed floating-point literal that overflows its target format
(such as `1e40f`, `1e400d`, or `0x1p2000d`), `Logic_utils.parse_float` produces a `logic_real` with
`r_lower = r_upper = r_nearest = infinity`. E-ACSL checks only `lr.r_lower = lr.r_upper` without
checking `Floating_point.is_finite lr.r_nearest`, so it emits `CReal(infinity, FDouble, None)`:

1. `e-acsl-gcc` fails to compile the generated C with `error: 'inf' undeclared` (even without
   `-constfold` and even with `-float-print hex`).
2. In a rational context (such as `assert 0.1 < 1e40f;`), E-ACSL emits
   `__gmpq_set_d(__gen_e_acsl__3, (double)((float)inf));`, where passing IEEE infinity to GMP's
   `mpq_set_d` raises `SIGFPE` (exit 136) at run time even if the kernel printer is fixed to print a
   valid C infinity expression.

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-22) | **fails to compile** (`error: 'inf' undeclared`, `__gmpq_set_d(..., (double)((float)inf))`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-22) | **fails to compile**, identical messages (`RESULT: bug present (5 of 5 cases fail)`) |
| `master` `189053d4a2` + [`./patches/53-eacsl-non-finite-real-constant.patch`](./patches/53-eacsl-non-finite-real-constant.patch) | **fixed** (`RESULT: fixed`, 5/5 cases warn `not yet supported`, compile cleanly, and exit 0) |

Debian 13 (trixie), OCaml 5.5, gcc 14.2.0.

## Root cause

1. `Logic_utils.parse_float` (`src/kernel/services/ast_queries/logic_utils.ml:294-308`) parses
   suffixed literals (`f`, `d`, `f32`, `f64`) via `real_of_float literal nearest`, which sets
   `r_lower = r_upper = r_nearest = infinity` on overflow (consistent with ACSL Section 2.2.5).
2. The kernel's `Cil.isExactFloat` (`src/kernel/services/ast_queries/cil.ml:2494-2495`) checks
   `r.r_upper = r.r_lower && isFiniteFloat fk r.r_nearest`.
3. By contrast, E-ACSL checks only `lr.r_lower = lr.r_upper` in two places:
   - `plugins/e-acsl/src/analyses/interval.ml:530-532` (`Interval.infer`),
   - `plugins/e-acsl/src/code_generator/translate_terms.ml:128-131` (`constant_to_exp_old`).
4. Because OCaml's `infinity = infinity` evaluates to `true`, E-ACSL enters the finite-float branch
   and calls `Cil.kfloat ~loc FDouble infinity` (`CReal(infinity, FDouble, None)`).
5. Even if `cil_printer.ml` is patched to print non-finite `CReal` values as valid C infinity
   expressions, GMP's `mpq_set_d` cannot represent infinity and terminates with `SIGFPE` (verified
   directly against system GMP 6: `mpq_set_d(q, (double)((float)INFINITY))` exits 136). Therefore
   E-ACSL needs its own guard independently of kernel C-printer fixes.

## Subtlety notes

- **Unsuffixed overflowing reals (`1e400`):** `Logic_utils.parse_float` parses unsuffixed `1e400`
  with `r_lower = max_float <> infinity = r_upper`, so it takes the `else` (`Rational`) branch and
  is unaffected by this patch (preserving compatibility with package 43 / `real_constants.c`).
- **Remaining annotations:** `Error.not_yet` causes E-ACSL to emit a clean warning and ignore only
  the annotation containing the non-finite constant; subsequent annotations in the same function
  (such as `assert x == 0.5;`) are still translated and checked at run time.

## Fix and validation

Patch [`./patches/53-eacsl-non-finite-real-constant.patch`](./patches/53-eacsl-non-finite-real-constant.patch):
one commit (`99b6c2336b`) on `master` `189053d4a2`, 5 files (81 insertions, 3 deletions:
`interval.ml`, `translate_terms.ml`, and new regression test
`plugins/e-acsl/tests/arith/non_finite_real.c` with its 2 oracles).

Validated on 2026-11-22 in `framac-master-audit:189053d` (`master`
`189053d4a2bd460c5c557dba8569474ff0419e73`):

- **Patch hygiene:** `git format-patch` produces zero file-mode changes and no executable files.
- **New test against unpatched `master`:** `non_finite_real.c` FAILS in both default (oracle diff
  showing `x < inf` and `__gmpq_set_d(..., (double)((float)inf))`) and `dev` (`e-acsl-gcc` fails
  with `error: 'inf' undeclared`).
- **New test against patched sources:** `non_finite_real.c` PASSES in both default and `dev`
  configurations.
- **Entire E-ACSL suite, default configuration:** `./dev/test.sh -p plugins/e-acsl` PASSES (exit 0,
  zero diffs on existing oracles).
- **`./dev/check-files.sh -p HEAD~1`:** PASSES (`Debian clang-format version 19.1.7`,
  `Lint 5 file(s)`).
- **Installed patched tree + reproducer:** `RESULT: fixed` (5/5 cases pass, exit 0; before patch:
  `RESULT: bug present (5 of 5 cases fail)`).

Not run: 32-bit targets and `make default-tests` outside `plugins/e-acsl`.

## Duplicates

Searched live on 2026-11-22 via read-only GitLab API (`pub/frama-c`, issues and merge requests, all
states) for `non-finite`, `r_lower`, `r_nearest`, `1e40f`, `inf undeclared`, `mpq_set_d`, and
`LReal`. Zero duplicates in `pub/frama-c` issues/MRs, the CSV snapshot, or packages `01`-`50`.
Complementary to the kernel `cil_printer.ml` non-finite `CReal` printing issue.

## For the pipeline

Low/optional impact for `opam/` patching: only affects ACSL annotations containing overflowing
suffixed floating-point constants (such as `1e40f` or `1e400d`), which otherwise cause `e-acsl-gcc`
compilation failure or runtime `SIGFPE` in GMP.
