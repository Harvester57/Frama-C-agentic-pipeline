# E-ACSL: real constants that are not exactly a double (crash with an exponent, 0 for a `long double`)

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 43 of this folder, drafted on 2026-11-18. Filing needs the owner's go-ahead:
the go-ahead given that day covered 42 only.

**Package:**
[issue text](./filing/43-eacsl-real-constant-notation-issue.md),
[MR text](./filing/43-eacsl-real-constant-notation-mr.md),
[reproducer](./repro/43-eacsl-real-constant-notation.sh) with its
[C file](./repro/43-eacsl-real-constant-notation.c), and
[patch](./patches/43-eacsl-real-constant-notation.patch) (validated on `master` `b80fcac74f`).

## Summary

Found on 2026-11-18 while looking for siblings of 42 (a plug-in that reads the text of a literal
again with a narrower parser than the kernel's). E-ACSL takes a real constant that is exactly a
`double` from the kernel's value, and gives any other one to GMP as a fraction built from its
text by `Gmp.Q.normalize_str` (`plugins/e-acsl/src/code_generator/gmp.ml`). That function knows
plain decimal expansions only:

| Constant, not exactly a `double` | Result on `master` |
| :-- | :-- |
| With an exponent: `1e-9`, `1.5e-3`, `1e400` | `Unexpected error (E_ACSL__Gmp.Q.Not_a_decimal("1e-9"))`, exit code 125. A tolerance such as `x - y <= 1e-9` is enough |
| Hexadecimal: `0x1.00000000000000001p0` | the same crash. Rare: almost every hexadecimal constant is exactly a `double` |
| With a suffix, in practice `long double`: `0.1L` | no message; the generated code calls `__gmpq_set_str(q, "0.1L", 10)`, which fails, and the constant is **0** at run time. `0.1L > 0.05` aborts, `0.1L == 0` holds |
| Plain decimal: `0.1` | correct (`"01/10"`) |

**Is it a true positive?** Yes for both rows that fail:

- **The crash was not meant.** `normalize_str` has a handler that turns the failure into "number
  not written in decimal expansion: not yet supported". Commit `11b9381ab0` (2019-08-02) changed
  what the conversion raises from `Invalid_argument` to a new `Not_a_decimal` and left the handler
  on `Invalid_argument`, so the message has been unreachable since.
- **Support is wanted.** The manual says rationals are supported
  (`doc/refman/speclang_modern.tex`, "Real numbers and floating point numbers"), the ACSL lexer
  accepts these forms, and upstream's `tests/arith/rationals.c` lists `1e5` and a `long double`
  case under "Not yet", commented out.
- **Hexadecimal annotations mostly work already**, because a constant that is exactly a `double`
  never reaches this function. "E-ACSL does not read hexadecimal" would be the wrong title.

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `b80fcac74f` (the audit image's tree moved to it and reinstalled) | both symptoms; the reproducer prints `RESULT: bug present (6 of 6 cases fail)` |
| `35.0~~dev (Bromine)`, `master` at `95408044f7` (image `framac-master-audit:9540804` as built) | the same on the commands of the issue; `plugins/e-acsl` is identical on both commits |
| `34.0~beta (Selenium)` (image `framac-analysis:latest`) | the same on the commands of the issue |
| `master` at `b80fcac74f` with the patch installed | `RESULT: fixed` |

## Fix

[`./patches/43-eacsl-real-constant-notation.patch`](./patches/43-eacsl-real-constant-notation.patch):
one commit on `b80fcac74f`, five files. The source change is 12 lines added and 20 removed in
`gmp.ml`, plus one sentence in `gmp.mli`:

- **Suffix first:** `normalize_str` looks at the suffix with the kernel's
  `Floating_point.extract_suffix`. A constant that still has one is reported with `Error.not_yet`
  and the annotation is ignored with a warning: its value depends on the `long double` format of
  the target.
- **Exponent and hexadecimal:** the decimal conversion is tried as before, so the strings of plain
  decimals do not change and no existing oracle moves. When it raises `Not_a_decimal`, Zarith's
  `Q.of_string` gives the exact fraction. It reads decimal exponents since Zarith 1.10 and
  hexadecimal notation since 1.11 (checked in the sources of the releases); Frama-C requires 1.13.
- **Removed:** the suffix cases of `decimal_to_fractional`, which can no longer be reached.

A two-line alternative would only correct the handler (`with Not_a_decimal _`). It restores the
"not yet supported" message and leaves `1e-9` unchecked; the `long double` case needs its own
change either way.

New test `plugins/e-acsl/tests/arith/real_constants.c`: eight assertions that hold (exponent,
hexadecimal) and two `long double` ones that are reported as not yet supported.

### Validation

Run on 2026-11-18 in one container of `framac-master-audit:9540804` moved to `b80fcac74f`
(`git ls-remote` that day), with
[`../../../tools/upstream_audit/revalidate.sh`](../../../tools/upstream_audit/revalidate.sh)
`package 43`:

- **Commit:** `d873cd8fdc` on `fix/eacsl-real-constants`, tree `6e3cf1163c`, author and committer
  the GitLab noreply address, no file-mode change. The exported patch applied with
  `git am --keep-non-patch` gives the same tree.
- **A, new test with `master`'s `gmp.ml`:** fails in the default and in the `dev` configuration
  (`Unexpected error (E_ACSL__Gmp.Q.Not_a_decimal("1e-1"))`).
- **B, with the patch:** passes in both.
- **C, `plugins/e-acsl`, default configuration:** passes, no existing oracle changes.
- **`plugins/e-acsl/tests/arith`, `dev` configuration** (run by hand): passes.
- **D, `./dev/check-files.sh -p HEAD~1`:** passes (`Lint 5 file(s)`).
- **E, reproducer:** `RESULT: bug present (6 of 6 cases fail)` before, `RESULT: fixed` after.
- **The commands of the issue text**, before and after, as the MR text reports them.

Not run: the `dev` configuration of the other E-ACSL directories, and the tests of the other
plug-ins and of the kernel.

## Not covered

- **Unary minus on a rational** (`-1e-2`): `reals: Neg | BNot` is not yet supported, before and
  after. A clean limitation.
- **Very large exponents** (`1e2000`): the fraction has as many digits. `1e999999999` would be
  built in memory.
- **Three other defects seen on the way**, candidates H10, H11 and H15 of
  [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md):
  floating-point constants without source text are printed with 12 significant digits (only
  `double` values change), a cast from a rational to `double` truncates (so a true assertion can
  fail and a false one can pass), and an infinite constant is printed as `inf`. A second review
  confirmed all three on plain `master` and on `34.0~beta`.

## Duplicates

Searched live on 2026-11-18 through the read-only API: `Not_a_decimal`, `not written in decimal`,
`decimal expansion`, `e-acsl exponent`, `e-acsl real literal`, `scientific notation`. Nothing
related (#2698, closed, is a WP question about real comparisons).

## Filing

Not filed: no branch was pushed, and no issue or merge request was created. The MR text holds
`#<issue>`. Steps, when the owner gives the go-ahead, as for 42
([`./frama-c-wp-hexadecimal-float-literals.md`](./frama-c-wp-hexadecimal-float-literals.md)):
`git ls-remote`; `make_branches.sh "43 fix/eacsl-real-constants"` in a container moved to
upstream's head (the tree must be `6e3cf1163c`); push from the bundle; `file_upstream.py issue 43`,
`subst`, `mr 43`.

## For the pipeline

Phase 1 builds E-ACSL binaries from the target's own annotations. A contract with a tolerance
written with an exponent (`1e-6`) stops that build on Frama-C 34.0 and earlier, with an
`Unexpected error` that names the constant. Until a release carries the fix, such a constant can
be written as a plain decimal (`0.000001`). Recorded in
[`../../troubleshooting/eacsl-and-fuzzing.md`](../../troubleshooting/eacsl-and-fuzzing.md).
