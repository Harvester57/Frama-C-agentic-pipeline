# Kernel: ACSL wide-string `wcharlist_of_string` treats `8` and `9` as octal digits and omits `\v`

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 60 of this folder, drafted on 2026-11-23 (hunt candidate `N11`). Filing remains
paused pending the maintainers' reply on
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/60-kernel-acsl-wstring-octal-escapes-issue.md),
[MR text](./filing/60-kernel-acsl-wstring-octal-escapes-mr.md),
[reproducer](./repro/60-kernel-acsl-wstring-octal-escapes.sh) with its
[C file](./repro/60-kernel-acsl-wstring-octal-escapes.c), and
[patch](./patches/60-kernel-acsl-wstring-octal-escapes.patch) (validated on `master` `189053d4a2`).

## Summary

`Logic_typing.wcharlist_of_string` (`src/kernel/services/ast_queries/logic_typing.ml:23-87`)
matches `'0' <= x && x <= '9'` when parsing octal escapes in ACSL wide string literals (turning
`L"\18"` into `[16]` and `L"\79"` into `[65]`, instead of `[1, '8']` and `[7, '9']`), and omits
the standard C escape `\v` (emitting `Ill-formed escape sequence in wide string` and storing `'v'`).

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **reproduces** (`RESULT: bug present (3 of 3 checks fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **reproduces**, identical output (`RESULT: bug present (3 of 3 checks fail)`) |
| `master` `189053d4a2` + [`./patches/60-kernel-acsl-wstring-octal-escapes.patch`](./patches/60-kernel-acsl-wstring-octal-escapes.patch) | **fixed** (`RESULT: fixed`) |

Debian GNU/Linux 13 (trixie; OCaml 5.5, glibc 2.41, gcc 14.2.0).

## Root cause and fix

In `src/kernel/services/ast_queries/logic_typing.ml`:

- Lines 30 and 62: narrow `'0' <= x && x <= '9'` to `'0' <= x && x <= '7'`.
- Line 71: add `| 'v' -> incr i; res:= Int64.of_int 11 :: !res`.

Stacks cleanly via `git am --3way --keep-non-patch` with sibling `logic_typing.ml` packages `58`
and `59`.

## Duplicate search

Live read-only `glab api` search on `pub/frama-c` (project 780, issues and MRs, all states,
2026-11-23), `pub-frama-c_work_items_2026-11-09.csv`, and packages `01`–`50` for
`wcharlist_of_string`, `oct_escape`, `wide character`, `escape sequence`: zero duplicates (only
`#2832` overview).

## Local `opam/` patch queue recommendation

**NO** (rare input: wide string literals with octal escapes followed by `8`/`9` or `\v` in ACSL).
