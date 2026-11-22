# [e-acsl] handle enum arguments and enum pointers in --validate-format-strings

- Source branch: `fix/eacsl-format-enum-argument` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/50-eacsl-format-enum-argument.patch`](../patches/50-eacsl-format-enum-argument.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

With `-e-acsl-validate-format-strings`, `Functions.Libc.get_printf_argument_str`
(`plugins/e-acsl/src/libraries/functions.ml`) put `TEnum _` in the `assert false` branch at line
155-156. Because `default_argument_promotion` (`src/kernel/internals/typing/cabs2cil.ml:3847`)
preserves `TEnum ei`, any `enum` variable, `typedef` enum, or enum bit-field passed to `printf`,
`fprintf`, `sprintf`, `snprintf`, `dprintf`, or `syslog` crashed Frama-C:

```text
[kernel] Unexpected error (File "plugins/e-acsl/src/libraries/functions.ml", line 156, characters 33-39: Assertion failed).
```

In the same function, `get_pkind_str` (lines 131-147) did not handle `TEnum _`, so passing a
pointer to an enum (such as `&s` for `%n` when `enum S` has underlying type `int`, or a mismatched
`%p`/`%s`) aborted E-ACSL with `Options.fatal`:

```text
[e-acsl] Failure: unexpected argument type in printf: type enum S of arg & s
```

## Change

`plugins/e-acsl/src/libraries/functions.ml` (`Functions.Libc.get_printf_argument_str`, 4 lines
added, 2 lines changed):

- Map `| TEnum { ekind } -> get_ikind_str ekind ^ acc` in `param_str`, removing `TEnum _` from the
  `assert false` catch-all.
- Make `get_pkind_str` recursive and add
  `| TEnum { ekind } -> get_pkind_str a (Cil_const.mk_tint ekind)` (matching
  `libraries/interval_utils.ml`), so pointers to enums are described by their underlying integer
  pointer type (C11 6.7.2.2p4 and 6.7.6.1p2).

New test `plugins/e-acsl/tests/format/printf_enum.c` (14 sub-tests: 7 valid calls covering unsigned
`enum`, signed `enum`, 64-bit unsigned/signed enums, `const` `typedef` enum, enum bit-fields,
`__attribute__((packed))` enums, `snprintf`, and `%n` on a signed `enum *`; 7 mismatched calls
confirming runtime aborts for `%s`, signedness mismatch `%d`/`%u`, width mismatch `%lu`/`%d` on
`long`, `%n` on an unsigned `enum *`, and `%p` on `enum *`).

No existing oracle changes.

Interaction with open merge requests:

- **!48 (#2819, promoted unsigned char/short):** this commit leaves the `| TInt k -> ...` arm
  untouched, so `!48` and this commit apply cleanly together with `git am --3way` in either order.
  With `!48` applied, `get_ikind_str IUChar` returns `'C'`, so packed unsigned enums also work with
  `%u`/`%x`; if `!48` lands first, `oracle/gen_printf_enum.0.c` updates `"ddd"` to `"dCC"` on the
  packed-enum line.
- **!28 (#2797, formals marked initialized):** `printf_enum.c` includes `utils/signalled.h`, whose
  `signal_eval` has formals. If `!28` lands first, `oracle/gen_printf_enum.0.c` needs regenerating
  (as `gen_printf.0.c` does in `!28`).

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Reproducer (12 cases: unsigned/signed/64-bit/typedef+const+bitfield/packed enums, `%n` on
  signed `enum *`, `snprintf`, `-enums int`, and 4 mismatched cases `%s`, `%lu`, `%d` on unsigned
  enum, `%n` on unsigned `enum *`):**
  - Before (on `master` `189053d4a2` and `34.0~beta`): 12 of 12 cases fail during instrumentation (10
    with `Assertion failed` at `functions.ml:156`, 2 with `Failure: unexpected argument type in
    printf`).
  - After (installed patched `master`): 12 of 12 cases pass (8 valid calls exit 0; 4 mismatched
    calls abort cleanly at run time with exit 134 and the expected type-mismatch message).
- **New test on unpatched `master`:** `plugins/e-acsl/tests/format/printf_enum.c` fails in both the
  default (`exit 125`, `functions.ml:156: Assertion failed`) and `dev` configurations. With the
  patch, it passes in both (14/14 sub-tests).
- **ptests, default configuration:** `./dev/test.sh -p plugins/e-acsl` passes with zero diffs on
  any existing oracle.
- **ptests, `dev` configuration:** `./dev/test.sh -p -c dev plugins/e-acsl/tests/format` (all 4
  tests: `printf.c`, `fprintf.c`, `sprintf.c`, `printf_enum.c`) passes.
- **Stacked with !48:** `git am --3way --keep-non-patch` applies cleanly in both orders (`!48` then
  this patch, and this patch then `!48`), builds, and passes both `printf_promoted.c` and
  `printf_enum.c` in `dev`.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Debian clang-format version 19.1.7`,
  `Lint 5 file(s)`).
- **Not run:** 32-bit targets, and `make default-tests` outside `plugins/e-acsl` (the change is
  local to `Functions.Libc.get_printf_argument_str`).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
