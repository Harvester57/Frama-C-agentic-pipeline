# Kernel: `Cil.interpret_character_constant` types multi-character constants as `unsigned long` / `unsigned long long` instead of `int`

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 62 of this folder, drafted on 2026-11-23 (hunt candidate `H8`). Filing remains
paused pending the maintainers' reply on
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/62-kernel-multichar-const-type-issue.md),
[MR text](./filing/62-kernel-multichar-const-type-mr.md),
[reproducer](./repro/62-kernel-multichar-const-type.sh) with its
[C file](./repro/62-kernel-multichar-const-type.c), and
[patch](./patches/62-kernel-multichar-const-type.patch) (validated on `master` `189053d4a2`).

## Summary

`Cil.interpret_character_constant` (`src/kernel/services/ast_queries/cil.ml:4150-4161`) gives
multi-character integer character constants type `unsigned long` (`24930UL` for `'ab'`) or
`unsigned long long` (`4294967295ULL` for `'\377\377\377\377'`), violating ISO C11 6.4.4.4p10
("An integer character constant has type `int`"). It also treats two-character constants with value
`< 256` (such as `'\0\200'`) as single-character `CChr`, sign-extending them to `-128` on
signed-`char` machdeps instead of `128`.

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **reproduces** (`RESULT: bug present (2 of 2 checks fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **reproduces**, identical output (`RESULT: bug present (2 of 2 checks fail)`) |
| `master` `189053d4a2` + [`./patches/62-kernel-multichar-const-type.patch`](./patches/62-kernel-multichar-const-type.patch) | **fixed** (`RESULT: fixed`) |

Debian GNU/Linux 13 (trixie; OCaml 5.5, glibc 2.41, gcc 14.2.0).

## Root cause and fix

In `src/kernel/services/ast_queries/cil.ml:4150-4161`: match `char_list` on `[ _ ]` with
`0 <= value < 256` for `CChr`, and otherwise wrap `value` via
`truncateInteger64 IInt (Z.of_int64 value)` and return `(CInt64 (v, IInt, None), Cil_const.intType)`.

Stacks cleanly via `git am --3way --keep-non-patch` with sibling `cil.ml` packages `56`, `57`, and
`61` (forward and reverse order), and is completely disjoint from Wave 2 `86` (`N18`, `cparser.mly`).
Updates 1 expected line in `tests/syntax/oracle/define_string_logic_pp_bts2101.0.res.oracle`
(`(char)7815260946135808373` -> `(char)1768454517`, 32-bit `int` instead of 64-bit `unsigned long long`).

## Duplicate search

Live read-only `glab api` search on `pub/frama-c` (project 780, issues and MRs, all states,
2026-11-23), `pub-frama-c_work_items_2026-11-09.csv`, and packages `01`–`50` for
`interpret_character_constant`, `multi-character`, `multichar`: zero duplicates (only `#2832`
overview).

## Local `opam/` patch queue recommendation

**NO** (rare input: multi-character constants like `'ab'` / FourCC tags).
