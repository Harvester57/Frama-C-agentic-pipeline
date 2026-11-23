# Kernel: `Cil.charConstToInt` always sign-extends character constants >= 128 on unsigned-`char` machdeps (`ppc_32`)

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 61 of this folder, drafted on 2026-11-23 (hunt candidate `H5`). Filing remains
paused pending the maintainers' reply on
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/61-kernel-char-const-unsigned-machdep-issue.md),
[MR text](./filing/61-kernel-char-const-unsigned-machdep-mr.md),
[reproducer](./repro/61-kernel-char-const-unsigned-machdep.sh) with its
[C file](./repro/61-kernel-char-const-unsigned-machdep.c), and
[patch](./patches/61-kernel-char-const-unsigned-machdep.patch) (validated on `master` `189053d4a2`).

## Summary

`Cil.charConstToInt` (`src/kernel/services/ast_queries/cil.ml:2547-2551`) unconditionally
sign-extends character constants with byte values `>= 128`, ignoring `Machine.char_is_unsigned ()`.
On `ppc_32` (and any custom unsigned-`char` machdep such as ARM/PowerPC Linux), `'\377'` evaluates
to `-1` while `(char)255` and `"\377"[0]` evaluate to `255`, contradicting ISO C11 6.4.4.4p10 and
`gcc -funsigned-char` and turning live branches dead in Eva, WP, and constant folding.

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **reproduces** (`RESULT: bug present (2 of 2 checks fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **reproduces**, identical output (`RESULT: bug present (2 of 2 checks fail)`) |
| `master` `189053d4a2` + [`./patches/61-kernel-char-const-unsigned-machdep.patch`](./patches/61-kernel-char-const-unsigned-machdep.patch) | **fixed** (`RESULT: fixed`) |

Debian GNU/Linux 13 (trixie; OCaml 5.5, glibc 2.41, gcc 14.2.0).

## Root cause and fix

In `src/kernel/services/ast_queries/cil.ml:2547-2551`, change `if c' < 128` to
`if Machine.char_is_unsigned () || c' < 128`.

Stacks cleanly via `git am --3way --keep-non-patch` with sibling `cil.ml` packages `56`, `57`, and
`62`.

## Duplicate search

Live read-only `glab api` search on `pub/frama-c` (project 780, issues and MRs, all states,
2026-11-23), `pub-frama-c_work_items_2026-11-09.csv`, and packages `01`–`50` for `charConstToInt`,
`unsigned char`, `ppc_32`, `character constant`: zero duplicates (only `#2832` overview).

## Local `opam/` patch queue recommendation

**NO** (our pipeline uses `gcc_x86_64` where `char` is signed; only unsigned-`char` machdeps such
as `ppc_32` or ARM are affected).
