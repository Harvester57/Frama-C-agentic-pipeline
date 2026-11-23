# [kernel] avoid double-escaping ACSL wide strings and handle empty L""

- Source branch: `fix/kernel-acsl-wstring-double-escape` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/78-kernel-acsl-wstring-double-escape.patch`](../patches/78-kernel-acsl-wstring-double-escape.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

In `Cil_printer.logic_constant` (`src/kernel/services/ast_printing/cil_printer.ml`, lines
2399-2413):

- The `LWStr` arm formatted `Escape.escape_char (Char.chr (Int64.to_int elt))` with `"%S"`,
  escaping every backslash and quote a second time (`L"\n\t"` became `L"\\n" "\\t" `, turning
  valid `sizeof` checks into invalid ones on re-parse).
- When `s = []` (empty `L""`), `List.iter` printed nothing after `L`, emitting invalid syntax
  (`sizeof(L)`) that aborted re-parsing with `unbound logic variable L`.

## Change

`src/kernel/services/ast_printing/cil_printer.ml` (3 lines added, 1 line changed):

- Add `| LWStr [] -> fprintf fmt "L\"\""` before `| LWStr(s) ->`.
- Replace `fprintf fmt "%S"` with `fprintf fmt "\"%s\""` (matching `LStr` at line 2398).

New regression test `tests/pretty_printing/acsl_wstring.c` with its oracle.

No existing oracle changes.

Interaction with open merge requests:

- **!43 (#2812, `_Alignas` printing in `cil_printer.ml`):** touches lines 1893-2195, disjoint from
  lines 2396-2408.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Reproducer (3 cases: escaped ACSL wide strings re-parsed under Eva and WP, plus empty `L""`
  re-parsed under Eva):**
  - Before (`master` `189053d4a2` and `34.0~beta`): 3 of 3 cases fail (`invalid=5` under Eva,
    `true=2, false=5` under WP, `unbound logic variable L` on `L""`).
  - After (installed patched `master`): 3 of 3 cases pass (`invalid=0` under Eva, `true=7,
    false=0` under WP, `RESULT: fixed`).
- **New test on unpatched `master`:** `tests/pretty_printing/acsl_wstring.c` fails (`unbound logic
  variable L`, exit 1, and double-escaped strings). With the patch, it passes and re-parsing is
  idempotent.
- **ptests, default configuration:** `./dev/test.sh -p tests/pretty_printing`,
  `./dev/test.sh -p tests/spec`, and `./dev/test.sh -p plugins/e-acsl` all pass with zero diffs on
  existing oracles.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 3 file(s)`).
- **Not run:** 32-bit targets and `make default-tests` outside the suites listed above.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
