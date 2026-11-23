# [kernel] support universal character names in C character and string literals

- Source branch: `fix/kernel-clexer-universal-char-names` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/83-kernel-clexer-universal-char-names.patch`](../patches/83-kernel-clexer-universal-char-names.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`src/kernel/internals/parsing/clexer.mll` did not recognize ISO C99/C11 universal character names
(`\uXXXX` / `\UXXXXXXXX`, ISO C11 6.4.3) in C character and string literals, rejecting valid code
such as `L"\u20AC"`, `L"\U0001F600"`, `L'\u20AC'`, and `"\u20AC"` with `User Error: Unrecognized
escape sequence: \u`.

## Change

`src/kernel/internals/parsing/clexer.mll`:

- Add `ucn4`, `ucn8`, and `bad_ucn` regexps and `scan_ucn ~wide`.
- Validate UCN code points per ISO C11 6.4.3p2 (rejecting `< 0x00A0` other than `$`/`@`/`` ` ``,
  surrogates `0xD800..0xDFFF`, and `> 0x10FFFF`, plus incomplete `\u`/`\U` escapes).
- Thread `wide : bool` through `str` and `chr`: wide literals emit `[cp]`; narrow literals UTF-8
  encode `cp` via `Buffer.add_utf_8_uchar`.
- Universal character names in C identifiers are out of scope of this change.

New regression test `tests/syntax/ucn_literals.c` (+ oracles) verifying valid wide/narrow UCNs
(5/5 Eva assertions valid) and rejection of surrogate, low, out-of-range, and incomplete UCNs. No
existing oracle changes.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Standalone reproducer (`valid`, `surrogate`, `low`, `high`):**
  - Before (`master` `189053d4a2` and `34.0~beta`): all 4 cases fail with `Unrecognized escape
    sequence: \u`/`\U` (`RESULT: bug present (4 of 4 cases fail)`).
  - After (installed patched `master`): `valid` proves 4/4 Eva checks valid, `surrogate`/`low`/`high`
    exit 1 with `Invalid universal character name` (`RESULT: fixed`).
- **New test on unpatched `master`:** `tests/syntax/ucn_literals.c` fails; passes with the patch.
- **ptests, default configuration:** `./dev/test.sh -p tests/syntax -- -j 2` passes with zero diffs
  on any existing oracle.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 12 file(s)`).
- **Not run:** suites outside `tests/syntax` (the change is local to `clexer.mll` literal rules).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
