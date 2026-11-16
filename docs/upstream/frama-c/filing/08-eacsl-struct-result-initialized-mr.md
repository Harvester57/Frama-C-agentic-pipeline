# [e-acsl] no initialization guard on the fields of \result

- Source branch: `fix/e-acsl-struct-result-initialized` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/08-eacsl-struct-result-initialized.patch`](../patches/08-eacsl-struct-result-initialized.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2801.

## Problem

With initialization checks on (`-e-acsl-rte-initialized`, or `-rte -rte-initialized`), a
postcondition that reads a field of a struct `\result`, such as `ensures \result.a == x;`, fails on
every call with a false `\initialized(&\result.a)`. The wrapper stores the result in `__retres`,
which is registered with `__e_acsl_store_block` but never marked initialized.

`needs_guard` (`plugins/e-acsl/src/analyses/rte_analysis.ml`) already skips the guard for
`\result`, since the kernel ensures that `__retres` is always initialized, but only for
`TNoOffset`. A field access falls into the generic case and gets a guard.

## Change

`rte_analysis.ml`: `| TResult _, TNoOffset -> false` becomes `| TResult _, _ -> false`, which
extends the existing exemption to the fields of `\result`. This matches what E-ACSL does for any
other struct copy: the caller's `struct S s = f();` is followed by `__e_acsl_full_init(&s)`. A
user-written `\initialized(&\result.a)` is rejected by the kernel (`not an addressable left value`),
so the guard was the only reader of the shadow memory of `__retres`.

Cost: a field of the returned struct that the function left uninitialized is no longer reported
when the postcondition reads it (I checked this on a function that sets only `\result.a`: the
postcondition on `\result.b` now reads the garbage value). Today that check also fails on correct
functions, so it could not tell the two cases apart. An alternative that keeps a guard is to emit
`__e_acsl_full_init(&__retres)` after `__retres = f(...)` in the wrapper; it has the same cost.

Regression test: `plugins/e-acsl/tests/acsl-rte/struct_result.c` (`STDOPT: #"-e-acsl-rte-initialized"`,
`ensures \result.a == x && \result.b == x + 1`), with its default-configuration oracles
`struct_result.0.res.oracle` and `gen_struct_result.0.c`. On `master` its `dev` run (compile and
execute) fails on the postcondition; with the patch it exits 0.

Related: the separate MR that marks formal parameters as initialized on function entry (!28, for
#2797, a regression of #177) fixes the same family of false `\initialized` failures. The two patches are
independent; each applies on `3dff90fc70` alone, and they apply and work together.

## Testing

On `3dff90fc70` (Debian 13, OCaml 5.5 switch, gcc 14.2.0), with the patch built and installed:

| Check | `master` | Patched |
|---|---|---|
| `ensures \result.a == x;` on a struct return, plain `e-acsl-gcc` | exit 0 | exit 0 |
| same, `-F "-rte -rte-initialized @all"` | `E-ACSL RTE failed: \initialized(&\result.a)`, abort | exit 0 |
| same, `-F -e-acsl-rte-initialized` | false `\initialized(&\result.a)`, abort | exit 0 |
| Uninitialized local read (`int y; /*@ assert y == 0; */`) with initialization checks | reported | still reported |

- ptests `plugins/e-acsl/tests`, default configuration (198 results with the new test): only the
  two new oracles; promoted, and the rerun passes. `dev` configuration (every test compiled and
  run): passes with the patch, the new test included.
- Together with the formal-parameter fix: with both patches applied on `3dff90fc70`, the ptests of
  `plugins/e-acsl/tests` with the oracles of both MRs pass in the default and `dev` configurations
  with no difference.
- `./dev/check-files.sh -p` (that is, `make check-lint` and `make check-headers` on the changed
  files) with ocp-indent 1.10.0 and clang-format 19.1.7: clean. The first commit's new test was not
  clang-formatted; the second commit formats it, and its generated oracle follows the new line
  numbers (the default configuration of `acsl-rte/` rerun after it passes).
- `git diff --check`: clean except the blank line at the end of the new `gen_struct_result.0.c`,
  which every generated E-ACSL oracle has.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
