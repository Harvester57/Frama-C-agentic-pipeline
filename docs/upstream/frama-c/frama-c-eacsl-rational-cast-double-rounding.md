# E-ACSL: rational casts to `double` and `float` truncate toward zero via `__gmpq_get_d` (true assertions abort, false assertions pass)

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 52 of this folder, drafted on 2026-11-22. Filing remains paused pending the
maintainers' reply on [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/52-eacsl-rational-cast-double-rounding-issue.md),
[MR text](./filing/52-eacsl-rational-cast-double-rounding-mr.md),
[reproducer](./repro/52-eacsl-rational-cast-double-rounding.sh) with its
[C file](./repro/52-eacsl-rational-cast-double-rounding.c), and
[patch](./patches/52-eacsl-rational-cast-double-rounding.patch) (validated on `master` `189053d4a2`).

## Summary

When translating an ACSL cast from a mathematical real/rational (`\real`, represented at run time as
a GMP `mpq_t`) to `double` or `float`, E-ACSL generates a call to `__gmpq_get_d` (and casts the
`double` result to `float` for `(float)`). Because GMP's `mpq_get_d` rounds **toward zero**
(truncation), whereas ACSL Section 2.2.5 specifies IEEE 754 **round-to-nearest-even**, roughly half
of all non-representable rational values produce the wrong floating-point value at run time:

- Valid assertions abort (e.g. `double d = 0.1; assert d == (double)0.1;` fails with exit 134).
- False assertions pass silently (e.g. `assert (double)0.1 < 0.1;` and
  `assert 0x1.9999999999999p-4 == (double)0.1;` exit 0 with no warning).
- `(float)` casts additionally suffer from double rounding through `double` (e.g.
  `assert 16777218.0f == (float)16777217.0000000001;` fails with exit 134).

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-22) | **unsound** (true assertions abort exit 134; false assertions pass exit 0) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-22) | **unsound**, identical messages (`RESULT: bug present (7 of 7 cases fail)`) |
| `master` `189053d4a2` + [`./patches/52-eacsl-rational-cast-double-rounding.patch`](./patches/52-eacsl-rational-cast-double-rounding.patch) | **fixed** (`RESULT: fixed`, 7/7 cases pass: 5 true exit 0, 2 false abort exit 134) |

Debian 13 (trixie), OCaml 5.5, gcc 14.2.0.

## Root cause

In `plugins/e-acsl/src/code_generator/gmp.ml` (`Gmp.Q.add_cast`, lines 339-376):

- `TFloat FDouble` emits `__gmpq_get_d`, which truncates toward zero regardless of the active FPU
  rounding mode and has system-dependent exponent overflow/underflow behaviour.
- `TFloat FFloat` calls `get_double` (suffering from the same truncation) and then casts the
  `double` to `float` (introducing double rounding as well), emitting only a warning
  `R to float: double rounding might cause unsoundness`.
- An existing `TODO` at `gmp.ml:340-342` already noted that dedicated C runtime builtins should be
  written for these conversions.

## Fix and validation

Patch [`./patches/52-eacsl-rational-cast-double-rounding.patch`](./patches/52-eacsl-rational-cast-double-rounding.patch):
one commit (`ae85817118`) on `master` `189053d4a2`, 11 files (914 insertions, 33 deletions:
`e_acsl_gmp_api.h`, `e_acsl_floating_point.c`, `gmp.ml`, new test
`plugins/e-acsl/tests/arith/rational_cast.c` + 2 oracles, and 5 existing E-ACSL oracle updates for
`__gmpq_get_d` -> `__e_acsl_mpq_get_d`/`__e_acsl_mpq_get_f` and removal of the double-rounding
warning).

Implementation notes:

- E-ACSL's numerical runtime does not `#include <gmp.h>`; it declares GMP/RTL symbols in
  `numerical_model/e_acsl_gmp_api.h` (`eacsl_mpq_t`, `export_alias(...)`) and `e-acsl-gcc` always
  links `-lgmp -lm`.
- `eacsl_mpq_get_ieee(q, prec, emin, emax)` computes the exact IEEE 754 round-to-nearest-even value
  directly from `mpz_t` numerator and denominator (`__gmpz_sizeinbase`, `__gmpz_tdiv_qr`,
  `__gmpz_tstbit`, `__gmpz_add_ui`, `ldexp`), handling zero, signs, ties-to-even, subnormals,
  carry into the next exponent, underflow to `+-0.0`, and overflow to `+-INFINITY` without double
  rounding.

Validated on 2026-11-22/23 in `framac-master-audit:189053d` (`master`
`189053d4a2bd460c5c557dba8569474ff0419e73`):

- **Patch hygiene:** `git format-patch` produces zero file-mode changes and no executable files.
- **New test against unpatched `master`:** `rational_cast.c` FAILS in both default (oracle diff)
  and `dev` (`d == (double)0.1` aborts with exit 134).
- **New test against patched sources:** `rational_cast.c` PASSES in both default and `dev`
  configurations.
- **Entire E-ACSL suite, default configuration:** `./dev/test.sh -p plugins/e-acsl` PASSES (exit 0,
  only the 5 expected existing oracle updates).
- **`dev` configuration on `rationals.c`:** `./dev/test.sh -p -c dev plugins/e-acsl/tests/arith/rationals.c`
  PASSES.
- **Stacking with Issue 43 ([`./patches/43-eacsl-real-constant-notation.patch`](./patches/43-eacsl-real-constant-notation.patch)):**
  `git am --3way --keep-non-patch` applies cleanly in both orders (`43` then `52`, and `52` then
  `43`) with zero conflicts, builds, and passes both `real_constants.c` and `rational_cast.c` in
  `dev`.
- **`./dev/check-files.sh -p HEAD~1`:** PASSES (`Debian clang-format version 19.1.7`,
  `Lint 11 file(s)`).
- **Installed patched tree + reproducer:** `RESULT: fixed` (7/7 cases pass, exit 0; before patch:
  `RESULT: bug present (7 of 7 cases fail)` on both `master` `189053d4a2` and `34.0~beta`).

Not run: 32-bit targets and `make default-tests` outside `plugins/e-acsl`.

## Duplicates

Searched live on 2026-11-22 via read-only GitLab API (`pub/frama-c`, issues and merge requests, all
states) for `mpq_get_d`, `add_cast`, `double rounding`, `R to float`, and `rational cast`. Zero
duplicates in `pub/frama-c`, the CSV snapshot, or packages `01`-`50`.

## For the pipeline

**Recommended for the local `opam/` patch queue:** soundness bug where false assertions on
`(double)`/`(float)` casts of rationals pass silently and true assertions spuriously abort during
Phase 1 E-ACSL runtime checking.
