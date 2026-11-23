# Kernel: `Cil.fitsInInt` and `Cil.truncateInteger64` treat `_Bool` (`IBool`) as an 8-bit unsigned integer

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 57 of this folder, drafted on 2026-11-23 (hunt candidate `N8`). Filing remains
paused pending the maintainers' reply on
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/57-kernel-bool-cast-dropped-logic-issue.md),
[MR text](./filing/57-kernel-bool-cast-dropped-logic-mr.md),
[reproducer](./repro/57-kernel-bool-cast-dropped-logic.sh) with its
[C file](./repro/57-kernel-bool-cast-dropped-logic.c), and
[patch](./patches/57-kernel-bool-cast-dropped-logic.patch) (validated on `master` `189053d4a2`).

## Summary

`Logic_utils.numeric_coerce` (`src/kernel/services/ast_queries/logic_utils.ml:330-337`) drops an
explicit `(TInt ik)` cast on an integer or enum literal whenever `Cil.fitsInInt ik v` holds.
Because `Cil.fitsInInt` (`src/kernel/services/ast_queries/cil.ml:2419-2438`) computes
`nrBits = 8 * bytesSizeOfInt IBool = 8` (unsigned), it returns `true` for all `0 <= v < 256`
instead of `{0, 1}`. `Cil.truncateInteger64` (`cil.ml:2443-2470`) delegates to `fitsInInt` and
otherwise reduces modulo `2^8`, returning `2` on `2` and `0` on `256` instead of ISO C11 6.3.1.2p1
conversion (`0 -> 0`, non-zero -> `1`).

In ACSL logic, `(_Bool)2` and `(_Bool)TWO` lose their casts, so WP proves `(_Bool)2 == 2` and Eva
marks `(_Bool)2 == 1` invalid while validating both `(_Bool)x == 1` and `(_Bool)x == (_Bool)2`
(for `x = 2`), unsoundly entailing `1 == 2`.

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **reproduces** (`RESULT: bug present (3 of 3 checks fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **reproduces**, identical output (`RESULT: bug present (3 of 3 checks fail)`) |
| `master` `189053d4a2` + [`./patches/57-kernel-bool-cast-dropped-logic.patch`](./patches/57-kernel-bool-cast-dropped-logic.patch) | **fixed** (`RESULT: fixed`) |

Debian GNU/Linux 13 (trixie; OCaml 5.5, glibc 2.41, gcc 14.2.0).

## Root cause and fix

In `src/kernel/services/ast_queries/cil.ml`:

- `fitsInInt`: add `| IBool -> Z.(equal zero i || equal one i)`.
- `truncateInteger64`: when `not (fitsInInt k i)`, add `| IBool -> Z.one` (returning `Z.one, true`
  for any non-zero integer outside `{0, 1}`).

Stacks cleanly via `git am --3way --keep-non-patch` with sibling `cil.ml` packages `56`, `61`, and
`62`.

## Duplicate search

Live read-only `glab api` search on `pub/frama-c` (project 780, issues and MRs, all states,
2026-11-23), `pub-frama-c_work_items_2026-11-09.csv`, and packages `01`–`50` for `_Bool`,
`fitsInInt`, `IBool`: zero duplicates (only `#2832` overview).

## Local `opam/` patch queue recommendation

**YES** (small soundness fix in `Cil.fitsInInt` and `Cil.truncateInteger64` preventing unsound
`1 == 2` derivations in WP/Eva).
