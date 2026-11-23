# [wp] size void objects as char instead of int

- Source branch: `fix/wp-void-object-size` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/64-wp-void-object-size.patch`](../patches/64-wp-void-object-size.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Ctypes.object_of` (`plugins/wp/src/ctypes.ml:285-289`) already maps `TPtr TVoid` (`void *`) to `C_pointer Cil_const.charType` (1-byte `char *`), so `MemTyped` already treats `void *` as `sint8*`. However, lines 316-318 mapped `TVoid` itself to `C_int (c_int IInt)` (`sizeof(int)` bytes: 4 on 32/64-bit targets, 2 on `x86_16`). As a result:

- in the default `Typed` model, `\block_length(p)` on `void *p = buf` (`char buf[8]`) scaled by `sizeof(int)`, proving `\block_length(p) == 32` while leaving `\block_length(p) == 8` unproved;
- in the `Bytes` model, pointer shifts (`p + 4`) and pointer differences (`q - p`) on `void *` stepped by `sizeof(int)`, proving `(char *)(p + 4) == buf + 16`, `q - p == 1`, and false assertions on Frama-C's `mempcpy` contract (`share/libc/string.h:148`).

## Change

`plugins/wp/src/ctypes.ml` (1 line changed):

- Map `| TVoid -> ... C_int (c_char ())` instead of `C_int (c_int IInt)`, consistent with `TPtr TVoid` at line 287 and GNU C `sizeof(void) == 1`.

New test `plugins/wp/tests/wp_acsl/void_object.i` (3 runs, 3 oracles): `Typed` `\block_length(void *)` on `x86_64`, `Bytes` `void *` shift and pointer difference, and `Typed` `\block_length(void *)` on `x86_16`.

No existing oracle changes.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0, Alt-Ergo 2.6.4), upstream `master` at `189053d4a2`:

- **Reproducer (`Typed` `\block_length`, `Bytes` shift and `q - p`, `x86_16` `\block_length`, `Bytes` `mempcpy`):**
  - Before (stock `master` `189053d4a2` and stock `34.0~beta`): 4 of 4 cases fail.
  - After (patched `master`): 4 of 4 cases pass (`RESULT: fixed`).
- **New test on unpatched `master`:** `plugins/wp/tests/wp_acsl/void_object.i` fails on unpatched `master` and passes with the patch.
- **ptests, default configuration:** `./dev/test.sh -p plugins/wp` passes with zero existing oracle diffs.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 5 file(s)`).
- **Not run:** `make default-tests` outside `plugins/wp` and the WP `qualif` configuration (offline cache).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and tests described above.
