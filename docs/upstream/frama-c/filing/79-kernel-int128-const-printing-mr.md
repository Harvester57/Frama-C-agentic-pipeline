# [kernel] print __int128 constants without out-of-range LL/ULL suffixes

- Source branch: `fix/kernel-int128-const-printing` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/79-kernel-int128-const-printing.patch`](../patches/79-kernel-int128-const-printing.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Cil_printer.constant` (`src/kernel/services/ast_printing/cil_printer.ml`, lines 627-628) printed
`IInt128` and `IUInt128` constants with `LL` and `ULL` suffixes. Neither ISO C nor GCC/Clang has a
128-bit integer literal suffix. Whenever `-constfold` (enabled by default in `e-acsl-gcc`)
synthesizes a 128-bit constant outside 64-bit range (such as `((__int128)1 << 100) + 5`,
`~(unsigned __int128)0`, or `INT128_MIN`), GCC silently truncates it to 64 bits with only a
warning, Clang rejects it as a compile error, and Frama-C itself aborts on re-parse with
`Cannot represent the integer`.

## Change

`src/kernel/services/ast_printing/cil_printer.ml` (28 lines added, 2 lines changed):

- Add `pretty_int128_constant`:
  - When `i` fits in 64-bit `ILongLong` / `IULongLong`, emit `(__int128)<lit>` or
    `(unsigned __int128)<lit>` via `pretty_C_constant` (preserving exact 128-bit C type).
  - Otherwise, extract two's-complement 64-bit unsigned high and low halves via `Z.extract i 64 64`
    and `Z.extract i 0 64` and emit `(((unsigned __int128)0x<hi>ULL << 64) | 0x<lo>ULL)` (omitting
    `| 0x0ULL` when the low half is 0), wrapped in `((__int128)...)` for signed `IInt128`.

New regression test `tests/pretty_printing/int128_const.c` with its oracle, plus the two affected
lines of `plugins/e-acsl/tests/constructs/oracle/gen_typedef.0.c` (`2LL` -> `(__int128)2LL`,
`18446744073709551615ULL` -> `(unsigned __int128)18446744073709551615ULL`).

Interaction with open merge requests:

- **!43 (#2812, `_Alignas` printing in `cil_printer.ml`):** disjoint (`cil_printer.ml:1893-2195`);
  stacks cleanly via `git am --3way --keep-non-patch` in either order (also verified 4-way stacked
  with the floating-point and ACSL wide-string `cil_printer.ml` fixes).

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0, clang 19.1.7), upstream `master` at `189053d4a2`:

- **Reproducer (4 cases: `gcc -Wall -Wextra`, `clang -Wall -Wextra`, Frama-C re-parse, and
  default `e-acsl-gcc` on positive >64-bit, `UINT128_MAX`, `INT128_MIN`, negative >64-bit, and
  64-bit-fitting `__int128` constants):**
  - Before (`master` `189053d4a2` and `34.0~beta`): 4 of 4 cases fail (GCC and `e-acsl-gcc`
    silently truncate to 64 bits; Clang fails to compile; Frama-C fails to re-parse).
  - After (installed patched `master`): 4 of 4 cases pass with zero warnings (`RESULT: fixed`).
- **New test on unpatched `master`:** `tests/pretty_printing/int128_const.c` fails (`Cannot
  represent the integer`, exit 1). With the patch, it passes and re-parsing is idempotent.
- **ptests, default configuration:** `./dev/test.sh -p tests/pretty_printing`,
  `./dev/test.sh -p tests/syntax`, and `./dev/test.sh -p plugins/e-acsl` all pass (with only the
  two expected lines updated in `plugins/e-acsl/tests/constructs/oracle/gen_typedef.0.c`).
- **4-way stacking (`cil_printer.ml`):** `!43` + floating-point (`CReal`) + ACSL `LWStr` + this
  commit apply cleanly via `git am --3way --keep-non-patch` in both forward and reverse orders,
  build cleanly, and pass both `tests/pretty_printing` and `plugins/e-acsl`.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 4 file(s)`).
- **Not run:** 32-bit targets (128-bit integers require 64-bit GCC-like machdeps) and
  `make default-tests` outside the suites listed above.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
