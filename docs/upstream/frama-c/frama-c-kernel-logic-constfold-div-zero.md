# Kernel: `Logic_utils.constFoldBinOpToInt` crashes with `Division_by_zero` on `loop unroll`/`loop unfold` with `1/0`

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 84 of this folder, drafted on 2026-11-23. Filing remains paused pending the
maintainers' reply on [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/84-kernel-logic-constfold-div-zero-issue.md),
[MR text](./filing/84-kernel-logic-constfold-div-zero-mr.md),
[reproducer](./repro/84-kernel-logic-constfold-div-zero.sh) with its
[input file](./repro/84-kernel-logic-constfold-div-zero.i), and
[patch](./patches/84-kernel-logic-constfold-div-zero.patch) (validated on `master` `189053d4a2`).

## Summary

In `src/kernel/services/ast_queries/logic_utils.ml:2385-2387`, `constFoldBinOpToInt` checks
`if Z.(equal zero i2) && Z.(is_zero (erem i1 i2)) then None else Some (Z.ediv i1 i2)`. When the
divisor `i2` is zero, `&&` evaluates `Z.erem i1 i2`, raising an uncaught `Division_by_zero`
exception (exit 125) on `/*@ loop unroll 1 / 0; */` (under `-eva`) and `/*@ loop unfold 0 / 0; */`
(under `-ulevel-force`).

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **crashes** (`exit 125`, `Unexpected error (Division_by_zero)`, `RESULT: bug present (2 of 2 cases fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **crashes**, identical backtrace (`RESULT: bug present (2 of 2 cases fail)`) |
| `master` `189053d4a2` + [`./patches/84-kernel-logic-constfold-div-zero.patch`](./patches/84-kernel-logic-constfold-div-zero.patch) | **fixed** (both cases exit 0 with clean warnings, `RESULT: fixed`) |

Debian 13 (trixie; glibc 2.41, gcc 14.2.0), OCaml 5.5.

## Root cause

Line 2386 of `src/kernel/services/ast_queries/logic_utils.ml` combines `Z.(equal zero i2)` with
`&& Z.(is_zero (erem i1 i2))`. When `i2 = 0`, the left operand is `true`, so `Z.erem i1 zero` is
always evaluated and throws `Division_by_zero`. When `i2 <> 0`, `&&` short-circuits to `false` so
`Some (Z.ediv i1 i2)` is always returned.

## Fix and validation

Patch [`./patches/84-kernel-logic-constfold-div-zero.patch`](./patches/84-kernel-logic-constfold-div-zero.patch):
one commit (`edac4e1d26`) on `master` `189053d4a2`, 6 files (`src/kernel/services/ast_queries/logic_utils.ml`
1 line changed, plus regression test `tests/misc/unroll_div_zero.i` and its 4 oracles).

- Changes the `Div` branch to `if Z.(equal zero i2) then None else Some (Z.ediv i1 i2)` (matching
  `Mod` on line 2388).
- Validated on 2026-11-23 in `framac-master-audit:189053d`:
  - New test `tests/misc/unroll_div_zero.i` fails with exit 125 on unpatched `master`, passes with
    patch.
  - Full `./dev/test.sh -p tests/misc -- -j 2` passes with zero diffs on existing oracles.
  - `./dev/check-files.sh -p HEAD~1` passes (`Lint 6 file(s)`).
  - Standalone reproducer flips from `RESULT: bug present (2 of 2 cases fail)` (exit 1) to
    `RESULT: fixed` (exit 0).
- Local `opam/` queue recommendation: **NO** (triggered only by malformed `loop unroll`/`unfold`
  with constant division by zero; low impact on normal C targets).
