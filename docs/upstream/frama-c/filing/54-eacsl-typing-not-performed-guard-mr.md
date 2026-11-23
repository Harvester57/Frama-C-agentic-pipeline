# [e-acsl] type all sibling subterms and quantifier goals after Not_yet

- Source branch: `fix/eacsl-typing-not-performed-guard` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/54-eacsl-typing-not-performed-guard.patch`](../patches/54-eacsl-typing-not-performed-guard.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

In `plugins/e-acsl/src/analyses/typing.ml`, composite predicates such as `Pand`/`Prel` and `Tapp`
already ensure that all sibling children are typed even when an earlier child raises
`Error.Not_yet`, because `Labels.preprocess` registers `\at`/`\old` subterms across the whole
annotation for `Translate_ats.for_stmt`, and `Loops.mk_nested_loops` translates quantifier goals
before their bounds.

Other composite cases in `typing.ml` still short-circuited on the first `Error.Not_yet` /
`Error.Typing_error` (either while computing a typing context via `Interval` or while typing
children sequentially), causing E-ACSL to abort with an internal error (`exit 4`):

- `Pforall`/`Pexists` and `type_bound_variables` stopped before typing remaining guards and the
  quantifier goal (`Failure: typing was not performed on construct 0` on quantifiers with an
  unsupported bound, and `construct 1` on Frama-C's `stpncpy` contract `dest_nul_padded`).
- `TBinOp` stopped after typing the first operand before typing the second operand
  (`Failure: typing was not performed on construct 1` when `Translate_ats.for_stmt` pre-translated
  the `\aligned(..., 1)` RTE guard of `\old(src)` in `strlcat`'s `bounded_result` postcondition, or
  in any `f(a) + f(b)` where `f` has a `reads` clause).
- The same short-circuiting pattern affected `TUnOp (Neg | BNot)`, `TCast`, `Tif`, `Trange`,
  `Tlet`, `Pif`, `Plet`, `Papp`, `Pseparated`, and `Paligned`.

This defect is distinct from #2806 (!37), which normalizes lookup keys in `Typing`'s getters:
applying !37 on `189053d4a2` still aborts on all four reproducers (`quant.c`, `binop.c`,
`stpncpy.c`, and `strlcat.c`).

## Change

`plugins/e-acsl/src/analyses/typing.ml`:

- Introduce shared helpers `do_both`, `do_all`, and `with_opt_ctx` (catching `Error.Not_yet` and
  `Error.Typing_error`, finishing sibling/child typing with `ctx = None` when context inference
  failed, and re-raising the first exception).
- Use these helpers across `TUnOp (Neg | BNot)`, `TBinOp` (arithmetic, shift, comparison, logical,
  and pointer arithmetic), `TCast`, `Tif`, `Trange`, `Tlet`, `type_bound_variables`, `Papp`, `Pif`,
  `Plet`, `Pforall`/`Pexists`, `Pseparated`, and `Paligned` (and reuse `do_both` in
  `type_predicate`).
- New test `plugins/e-acsl/tests/constructs/typing_unsupported_sibling.c` (plus oracles
  `oracle/gen_typing_unsupported_sibling.0.c` and `oracle/typing_unsupported_sibling.0.res.oracle`)
  covering an unsupported quantifier bound, `f(a) + f(b)` with a `reads` clause, `stpncpy`, and
  `strlcat`.

No existing oracle changes.

Interaction with open merge requests touching `plugins/e-acsl/src/analyses/typing.ml`: this commit
leaves the regions edited by !25, !26, and !37 untouched and stacks cleanly on top of all three via
`git am --3way --keep-non-patch`.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Reproducer (4 cases: unsupported quantifier bound, `f(a) + f(b)` with `reads` clause,
  `stpncpy`, and `strlcat`):**
  - Before (on `master` `189053d4a2`, `34.0~beta`, and `master` + !37): 4 of 4 cases abort with
    exit 4 (`Failure: typing was not performed on construct 0` / `1`).
  - After (installed patched `master`): 4 of 4 cases exit 0 with the expected `not yet supported`
    warnings.
- **New test on unpatched `master`:** `plugins/e-acsl/tests/constructs/typing_unsupported_sibling.c`
  fails with exit 4 (`Failure: typing was not performed on construct 0`). With the patch, it passes
  in both the default and `dev` configurations.
- **ptests, default configuration:** `./dev/test.sh -p plugins/e-acsl` passes with zero diffs on
  any existing oracle.
- **Stacking with !25, !26, and !37 (`typing.ml`):** `git am --3way --keep-non-patch` applies all
  four patches cleanly with zero conflicts, builds, and passes `typing_unsupported_sibling.c`.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Debian clang-format version 19.1.7`,
  `Lint 4 file(s)`).
- **Not run:** 32-bit targets, and `make default-tests` outside `plugins/e-acsl` (the change is
  local to `plugins/e-acsl/src/analyses/typing.ml`).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
