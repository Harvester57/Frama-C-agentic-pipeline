# Kernel: narrow character constants with out-of-range octal/hex escapes silently accepted

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 86 of this folder, drafted on 2026-11-23. Filing remains paused pending the
maintainers' reply on [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/86-kernel-narrow-char-escape-range-issue.md),
[MR text](./filing/86-kernel-narrow-char-escape-range-mr.md),
[reproducer](./repro/86-kernel-narrow-char-escape-range.sh) with its
[C file](./repro/86-kernel-narrow-char-escape-range.c), and
[patch](./patches/86-kernel-narrow-char-escape-range.patch) (validated on `master` `189053d4a2`).

## Summary

Frama-C rejects out-of-range octal/hex escapes in narrow string literals (`"\777"`, `"\x1ff"`) with
`User Error: integral literal 0x1ff too big`, but silently accepts the same out-of-range escapes in
narrow character constants (`'\777'`, `'\x1ff'`, `'a\x100'`), turning them into `511` (`511UL`) or
`25088` without any warning or error, violating ISO C11 6.4.4.4p9.

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **bug present** (`oct`, `hex`, `multi` silently exit 0 as `511`/`511`/`25088`, `RESULT: bug present (3 of 4 cases fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **bug present**, identical output (`RESULT: bug present (3 of 4 cases fail)`) |
| `master` `189053d4a2` + [`./patches/86-kernel-narrow-char-escape-range.patch`](./patches/86-kernel-narrow-char-escape-range.patch) | **fixed** (`oct`, `hex`, `multi` rejected with exit 1; `valid` accepted with exit 0; `RESULT: fixed`) |

Debian 13 (trixie; glibc 2.41, gcc 14.2.0), OCaml 5.5.

## Root cause

In `src/kernel/internals/parsing/cparser.mly`, `string_constant` (lines 751-754) validates every
`int64` element of a narrow string literal with `int64_to_char` (lines 185-190, enforcing
`0 <= v <= 255`), whereas the `CST_CHAR` production (line 742) passes `fst $1` directly to
`CONST_CHAR` without range validation.

## Fix and validation

Patch [`./patches/86-kernel-narrow-char-escape-range.patch`](./patches/86-kernel-narrow-char-escape-range.patch):
one commit (`39f1780634`) on `master` `189053d4a2`, 10 files (`src/kernel/internals/parsing/cparser.mly`
plus regression test `tests/syntax/char_escape_range.c` and its 8 oracles).

- Validates each element of `CST_CHAR` with `int64_to_char ~loc`, leaving `CST_WCHAR` untouched.
- Disjoint from `cil.ml:4150-4161` (package `62`).
- Validated on 2026-11-23 in `framac-master-audit:189053d`:
  - New test `tests/syntax/char_escape_range.c` fails on unpatched `master` (cases 1-3 exit 0
    instead of 1), passes with patch.
  - Full `./dev/test.sh -p tests/syntax -- -j 2` passes with zero diffs on existing oracles.
  - `./dev/check-files.sh -p HEAD~1` passes (`Lint 10 file(s)`).
  - Standalone reproducer flips from `RESULT: bug present (3 of 4 cases fail)` (exit 1) to
    `RESULT: fixed` (exit 0).
- Local `opam/` queue recommendation: **NO** (rejects invalid C11 character escapes rather than
  fixing sound analysis of valid C code).
