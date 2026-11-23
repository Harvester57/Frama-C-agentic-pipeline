# [kernel] handle IBool range and conversion in Cil.fitsInInt and truncateInteger64

- Source branch: `fix/kernel-bool-cast-dropped-logic` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/57-kernel-bool-cast-dropped-logic.patch`](../patches/57-kernel-bool-cast-dropped-logic.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Cil.fitsInInt` (`src/kernel/services/ast_queries/cil.ml:2419-2438`) treated `IBool` as an 8-bit
unsigned integer (`0..255`), so `Logic_utils.numeric_coerce` (`logic_utils.ml:330-337`) dropped
`(_Bool)` casts on integer and enum literals in `2..255`. Likewise, `Cil.truncateInteger64`
(`cil.ml:2443-2470`) reduced `IBool` modulo `2^8` instead of applying ISO C11 6.3.1.2p1 boolean
conversion (`0 -> 0`, non-zero -> `1`).

## Change

- `src/kernel/services/ast_queries/cil.ml`:
  - In `fitsInInt`, handle `IBool` as `Z.(equal zero i || equal one i)`.
  - In `truncateInteger64`, when `not (fitsInInt k i)`, handle `IBool` by returning `Z.one, true`.
- New test `tests/spec/bool_cast_literal.c` with 2 oracles (`-print` and `-eva`), confirming that
  `(_Bool)0` and `(_Bool)1` are simplified while `(_Bool)2`, `(_Bool)255`, and `(_Bool)TWO` retain
  their casts and evaluate to `1`.
- Zero existing oracle changes.

## Testing

All on Debian GNU/Linux 13 (trixie; OCaml 5.5, glibc 2.41, gcc 14.2.0), upstream `master` at
`189053d4a2`:

- **New test on unpatched `master`:** `tests/spec/bool_cast_literal.c` fails on unpatched `master`
  and passes with the patch.
- **ptests, default configuration:** `./dev/test.sh -p tests/spec tests/syntax tests/cil` passes
  with zero diffs on any existing oracle.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 4 file(s)`).
- **Standalone reproducer:** flips from `RESULT: bug present (3 of 3 checks fail)` (on both
  `master` `189053d4a2` and `34.0~beta`) to `RESULT: fixed` with the patch.
- **Stacking:** applies cleanly with `git am --3way --keep-non-patch` alongside sibling `cil.ml`
  fixes (`Cil.isExactFloat`, `Cil.charConstToInt`, `Cil.interpret_character_constant`).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
