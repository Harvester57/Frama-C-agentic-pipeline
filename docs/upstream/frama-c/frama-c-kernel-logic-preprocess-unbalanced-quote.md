# Kernel: unbalanced quote or C23 digit separator (`1'000`) in ACSL annotation aborts with `Kernel.fatal`

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 87 of this folder, drafted on 2026-11-23. Filing remains paused pending the
maintainers' reply on [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/87-kernel-logic-preprocess-unbalanced-quote-issue.md),
[MR text](./filing/87-kernel-logic-preprocess-unbalanced-quote-mr.md),
[reproducer](./repro/87-kernel-logic-preprocess-unbalanced-quote.sh) with its
[C file](./repro/87-kernel-logic-preprocess-unbalanced-quote.c), and
[patch](./patches/87-kernel-logic-preprocess-unbalanced-quote.patch) (validated on `master` `189053d4a2`).

## Summary

An unbalanced quote (`//@ check o5: "abc == 1;`, `//@ check ch: 'a == 1;`) or C23 digit separator
(`//@ check c23: 1'000 == 1000;`) inside an ACSL annotation makes `Logic_preprocess` emit a user
error (`Can't preprocess annotation: eof while parsing a string/char literal`) and immediately crash
Frama-C with `Kernel.fatal` (`too few annotations in result file while preprocessing annotations`,
exit 4).

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **crashes** (exit 4, `Failure: too few annotations...`, `RESULT: bug present (3 of 3 cases fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **crashes**, identical backtrace (`RESULT: bug present (3 of 3 cases fail)`) |
| `master` `189053d4a2` + [`./patches/87-kernel-logic-preprocess-unbalanced-quote.patch`](./patches/87-kernel-logic-preprocess-unbalanced-quote.patch) | **fixed** (all 3 cases exit 1 with clean `User Error`, zero internal errors, `RESULT: fixed`) |

Debian 13 (trixie; glibc 2.41, gcc 14.2.0), OCaml 5.5.

## Root cause

In `src/kernel/internals/parsing/logic_preprocess.mll`, `char` (lines 426-444) and `string` (lines
446-461) scan past `\n` to `eof` and call `abort_preprocess` (lines 90-96, non-fatal `Kernel.error`)
without closing the open `annot_beg` marker in `preprocess_buffer`. `preprocess_annots` then calls
`next_preprocessed` (lines 120-127), which hits `End_of_file` and raises `Kernel.fatal`.

## Fix and validation

Patch [`./patches/87-kernel-logic-preprocess-unbalanced-quote.patch`](./patches/87-kernel-logic-preprocess-unbalanced-quote.patch):
one commit (`5ad1241b26`) on `master` `189053d4a2`, 8 files (`src/kernel/internals/parsing/logic_preprocess.mll`
plus regression test `tests/spec/pp_unbalanced_quote.c` and its 6 oracles).

- Tracks `in_annot` and `aborted` flags (reset in `reset ()`), closes an open annotation with
  `annot_end` on `abort_preprocess`, strips surrounding quotes from `!curr_file` for clean
  path normalization, adds an `eof` arm to `annot`, and skips invoking `cpp` in `preprocess_annots`
  when `!aborted` is true.
- Validated on 2026-11-23 in `framac-master-audit:189053d`:
  - `tests/spec/pp_unbalanced_quote.c` fails on unpatched `master` (exit 4), passes with patch
    (exit 1, clean user error, portable oracle paths).
  - Full `./dev/test.sh -p tests/spec -- -j 2` passes with zero diffs on existing oracles.
  - `./dev/check-files.sh -p HEAD~1` passes (`Lint 8 file(s)`).
  - Standalone reproducer flips from `RESULT: bug present (3 of 3 cases fail)` (exit 1) to
    `RESULT: fixed` (exit 0).
- Local `opam/` queue recommendation: **NO** (triggered only by unbalanced quotes or unsupported C23
  digit separators inside ACSL annotations).
