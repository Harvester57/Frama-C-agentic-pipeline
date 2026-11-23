# Kernel: `Cil.isExactFloat` drops `(float)` casts on `double`-exact literals in ACSL logic

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 56 of this folder, drafted on 2026-11-23 (hunt candidate `H4`). Filing remains
paused pending the maintainers' reply on
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/56-kernel-float-cast-dropped-exact-issue.md),
[MR text](./filing/56-kernel-float-cast-dropped-exact-mr.md),
[reproducer](./repro/56-kernel-float-cast-dropped-exact.sh) with its
[C file](./repro/56-kernel-float-cast-dropped-exact.c), and
[patch](./patches/56-kernel-float-cast-dropped-exact.patch) (validated on `master` `189053d4a2`).

## Summary

`Logic_utils.numeric_coerce` (`src/kernel/services/ast_queries/logic_utils.ml:332-333`) strips an
explicit `(float)` cast on a real literal whenever `Cil.isExactFloat FFloat r` returns `true`.
Because `Cil.isExactFloat` (`src/kernel/services/ast_queries/cil.ml:2494-2495`) checks only that
`r` is exact as a `double` (`r.r_upper = r.r_lower`) and remains finite when rounded to `float`,
any `double`-exact literal that rounds when cast to `float` (such as `16777217.0`, `2147483647.0`,
or `1e11`) loses its cast. WP proves false equalities (`(float)16777217.0 == 16777217.0`), and Eva
marks true assertions invalid, stopping propagation and dropping downstream alarms.

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **reproduces** (`RESULT: bug present (3 of 3 checks fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **reproduces**, identical output (`RESULT: bug present (3 of 3 checks fail)`) |
| `master` `189053d4a2` + [`./patches/56-kernel-float-cast-dropped-exact.patch`](./patches/56-kernel-float-cast-dropped-exact.patch) | **fixed** (`RESULT: fixed`) |

Debian GNU/Linux 13 (trixie; OCaml 5.5, glibc 2.41, gcc 14.2.0).

## Root cause and fix

Commit `e180d54c70` (2020, "[kernel] fix cast on non-exact floats") replaced `isFiniteFloat` with
`isExactFloat`, intending to drop casts only when exact in `fk`, but omitted checking that rounding
`r.r_nearest` to `fk` leaves the value unchanged.

Fix in `src/kernel/services/ast_queries/cil.ml:2494-2498`:

```ocaml
let isExactFloat fk r =
  r.r_upper = r.r_lower &&
  let f = Floating_point.round_if_single_precision fk r.r_nearest in
  Floating_point.is_finite f && Float.equal f r.r_nearest
```

The only other caller is `plugins/aorai/src/aorai_utils.ml:393`, which also benefits.

## Duplicate search

Live read-only `glab api` search on `pub/frama-c` (project 780, issues and MRs, all states,
2026-11-23), `pub-frama-c_work_items_2026-11-09.csv`, and packages `01`–`50` for `isExactFloat`,
`cast float double`, `numeric_coerce`: zero duplicates (only `#2832` overview).

## Local `opam/` patch queue recommendation

**YES** (small, zero-risk 3-line soundness fix preventing false WP proofs and lost Eva alarms).
