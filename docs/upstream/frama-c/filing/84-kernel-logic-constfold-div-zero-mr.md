# [kernel] fix division-by-zero crash in Logic_utils.constFoldBinOpToInt

- Source branch: `fix/kernel-logic-constfold-div-zero` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/84-kernel-logic-constfold-div-zero.patch`](../patches/84-kernel-logic-constfold-div-zero.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

In `src/kernel/services/ast_queries/logic_utils.ml:2385-2387`, `constFoldBinOpToInt` wrote:

```ocaml
| Div ->
  if Z.(equal zero i2) && Z.(is_zero (erem i1 i2)) then None
  else Some (Z.ediv i1 i2)
```

Whenever `i2 = 0` (for example in `/*@ loop unroll 1 / 0; */` or `/*@ loop unfold 0 / 0; */`), the
`&&` evaluates `Z.erem i1 i2` with `i2 = 0` and crashes Frama-C with `Unexpected error
(Division_by_zero)`.

## Change

`src/kernel/services/ast_queries/logic_utils.ml` (line 2385):

- Guard `Div` on `if Z.(equal zero i2) then None else Some (Z.ediv i1 i2)`, matching the `Mod`
  branch on the following line and preserving existing behavior for all non-zero divisors.

New regression test `tests/misc/unroll_div_zero.i` (+ oracles) exercising both `-eva` (`loop unroll
1 / 0`) and `-ulevel-force -print` (`loop unfold 0 / 0`). No existing oracle changes.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Standalone reproducer (`eva_unroll` and `ulevel_unfold`):**
  - Before (`master` `189053d4a2` and `34.0~beta`): both cases crash with exit 125
    (`Unexpected error (Division_by_zero)`), `RESULT: bug present (2 of 2 cases fail)`.
  - After (installed patched `master`): both cases exit 0 with clean warnings (`RESULT: fixed`).
- **New test on unpatched `master`:** `tests/misc/unroll_div_zero.i` fails with exit 125; passes
  with the patch.
- **ptests, default configuration:** `./dev/test.sh -p tests/misc -- -j 2` passes with zero diffs
  on any existing oracle.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 6 file(s)`).
- **Not run:** suites outside `tests/misc` (the change is a one-line zero-divisor guard in
  `Logic_utils.constFoldBinOpToInt`).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
