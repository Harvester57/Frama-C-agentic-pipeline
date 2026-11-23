# [kernel] avoid fatal error when logic preprocessing aborts on malformed input

- Source branch: `fix/kernel-logic-preprocess-unbalanced-quote` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/87-kernel-logic-preprocess-unbalanced-quote.patch`](../patches/87-kernel-logic-preprocess-unbalanced-quote.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

When `Logic_preprocess` (`src/kernel/internals/parsing/logic_preprocess.mll`) encountered an
unbalanced `"` or `'` inside an ACSL annotation (such as `//@ check o5: "abc == 1;`,
`//@ check c23: 1'000 == 1000;`, or `//@ check ch: 'a == 1;`), `char` / `string` scanned to `eof`
and called `abort_preprocess` (a non-fatal `Kernel.error`) without writing a matching `annot_end`
marker to `preprocess_buffer`. `preprocess_annots` then ran `cpp` and `next_preprocessed`, hitting
`End_of_file` and aborting Frama-C with `Kernel.fatal "too few annotations in result file while
preprocessing annotations"` (exit code 4).

## Change

`src/kernel/internals/parsing/logic_preprocess.mll`:

- Track `in_annot` (set in `process_annot_start`, cleared on every `annot_end*` transition) and
  `aborted` (set in `abort_preprocess`), both reset in `reset ()`.
- In `abort_preprocess`, close an open annotation in `preprocess_buffer` with `annot_end` when
  `!in_annot` is true, and strip surrounding double quotes from `!curr_file` before
  `Filepath.of_string` so diagnostic paths normalize cleanly.
- Add `| eof { abort_preprocess "eof while parsing annotation" }` to `annot`.
- In `preprocess_annots`, skip invoking `cpp` and fall back directly to `ppname` when `!aborted` is
  true, keeping annotations as is without hitting `Kernel.fatal`.

New regression test `tests/spec/pp_unbalanced_quote.c` (+ oracles) covering unbalanced string, C23
digit separator (`1'000`), and unbalanced char in ACSL annotations. No existing oracle changes.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Standalone reproducer (`unbalanced_str`, `c23_sep`, `unbalanced_char`):**
  - Before (`master` `189053d4a2` and `34.0~beta`): all 3 cases abort with exit 4 (`Failure: too
    few annotations in result file while preprocessing annotations`, `RESULT: bug present (3 of 3
    cases fail)`).
  - After (installed patched `master`): all 3 cases exit 1 cleanly with `User Error` and zero
    internal errors (`RESULT: fixed`).
- **New test on unpatched `master`:** `tests/spec/pp_unbalanced_quote.c` fails (exit 4 instead of
  1); passes with the patch.
- **ptests, default configuration:** `./dev/test.sh -p tests/spec -- -j 2` passes with zero diffs
  on any existing oracle.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 8 file(s)`).
- **Not run:** suites outside `tests/spec` (the change is local to `logic_preprocess.mll`).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
