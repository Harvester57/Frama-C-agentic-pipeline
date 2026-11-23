# Kernel: `sizeof` of an ACSL string literal counts raw escaped characters instead of unescaped bytes

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 58 of this folder, drafted on 2026-11-23 (hunt candidate `H7`). Filing remains
paused pending the maintainers' reply on
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/58-kernel-acsl-string-sizeof-escaped-issue.md),
[MR text](./filing/58-kernel-acsl-string-sizeof-escaped-mr.md),
[reproducer](./repro/58-kernel-acsl-string-sizeof-escaped.sh) with its
[C file](./repro/58-kernel-acsl-string-sizeof-escaped.c), and
[patch](./patches/58-kernel-acsl-string-sizeof-escaped.patch) (validated on `master` `189053d4a2`).

## Summary

In `src/kernel/services/ast_queries/logic_typing.ml:2684-2685`, `PLconstant (StringConstant s)`
passes raw `s` (containing backslashes and escape characters) to `typeOf_string_literal loc s`
while storing `unescape s` in `LStr`. Every ACSL `sizeof` on a string literal with escapes (such
as `"\n"`, `"a\0b"`, `"\x41"`, `"\\"`, or `#define GREETING "hello\n"`) overcounts the array size,
causing WP to refute true postconditions and Eva to mark valid `\valid` preconditions invalid and
halt analysis (`NON TERMINATING FUNCTION`).

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **reproduces** (`RESULT: bug present (2 of 2 checks fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **reproduces**, identical output (`RESULT: bug present (2 of 2 checks fail)`) |
| `master` `189053d4a2` + [`./patches/58-kernel-acsl-string-sizeof-escaped.patch`](./patches/58-kernel-acsl-string-sizeof-escaped.patch) | **fixed** (`RESULT: fixed`) |

Debian GNU/Linux 13 (trixie; OCaml 5.5, glibc 2.41, gcc 14.2.0).

## Root cause and fix

Introduced by commit `db4b010a04` (2025-07-24, "[logic] type string literal as arrays and stabilize
spec oracles"). Fix: `let s = unescape s in TConst (LStr s), typeOf_string_literal loc s`
(matching `WStringConstant` on the next two lines).

Stacks cleanly via `git am --3way --keep-non-patch` with sibling `logic_typing.ml` packages `59`
and `60`.

## Duplicate search

Live read-only `glab api` search on `pub/frama-c` (project 780, issues and MRs, all states,
2026-11-23), `pub-frama-c_work_items_2026-11-09.csv`, and packages `01`–`50` for `sizeof string`,
`typeOf_string_literal`, `unescape`: zero duplicates (`#2672` open is wide-string pointer size;
`#2832` is overview).

## Local `opam/` patch queue recommendation

**YES** (1-line fix eliminating false-invalid preconditions and dead code on ordinary C string
macros with `\n` or other escapes).
