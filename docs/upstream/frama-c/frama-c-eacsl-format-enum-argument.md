# E-ACSL `--validate-format-strings`: `Assert_failure` in `functions.ml:156` on `enum` arguments to `printf`-family functions

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 50 of this folder, drafted on 2026-11-22. Filing remains paused pending the
maintainers' reply on [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/50-eacsl-format-enum-argument-issue.md),
[MR text](./filing/50-eacsl-format-enum-argument-mr.md),
[reproducer](./repro/50-eacsl-format-enum-argument.sh) with its
[C file](./repro/50-eacsl-format-enum-argument.c), and
[patch](./patches/50-eacsl-format-enum-argument.patch) (validated on `master` `189053d4a2`).

## Summary

With `--validate-format-strings` (`-e-acsl-validate-format-strings`), passing any expression of
enumeration type (`TEnum _`) to `printf`, `fprintf`, `sprintf`, `snprintf`, `dprintf`, or `syslog`
aborts Frama-C during E-ACSL instrumentation with an uncaught `Assert_failure`:

```text
[kernel] Unexpected error (File "plugins/e-acsl/src/libraries/functions.ml", line 156, characters 33-39: Assertion failed).
```

Passing a pointer to an enumeration (`enum E *`, for example `&s` to `%n` when `enum S`'s
underlying integer type is `int`, or a mismatched `%p`/`%s`) aborts E-ACSL with an internal error
instead of validating the pointer type at run time:

```text
[e-acsl] Failure: unexpected argument type in printf: type enum S of arg & s
```

Plain enumerator constants (`RED`) are already typed as `TInt ekind` by `Cil.typeOf`, which is why
only enum variables, parameters, `typedef` enums, enum return values, enum bit-fields, and pointers
to enums trigger the bug.

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-22) | **crashes** (`RESULT: bug present (12 of 12 cases fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-22) | **crashes**, identical messages (`RESULT: bug present (12 of 12 cases fail)`) |
| `master` `189053d4a2` + [`./patches/50-eacsl-format-enum-argument.patch`](./patches/50-eacsl-format-enum-argument.patch) | **fixed** (`RESULT: fixed`, 12/12 cases pass: 8 valid runs exit 0, 4 mismatched calls abort cleanly at run time with exit 134) |

Debian 13 (trixie), OCaml 5.5, gcc 14.2.0.

## Root cause

1. In `src/kernel/internals/typing/cabs2cil.ml` (`default_argument_promotion`, line 3847), variadic
   argument promotion intentionally leaves `TEnum ei` as `mk_tenum ei` rather than converting it to
   `TInt ei.ekind`.
2. In `plugins/e-acsl/src/libraries/functions.ml`, `Functions.Libc.get_printf_argument_str` matches
   `Cil.(Ast_types.C.unroll_node (typeOf exp))` at lines 151-156 and puts `TEnum _` in the
   unreachable `assert false` branch:

   ```ocaml
   | TInt k -> get_ikind_str k ^ acc
   | TFloat k -> get_fkind_str k ^ acc
   | TPtr ty -> get_pkind_str exp (Ast_types.C.unroll ty) ^ acc
   | TVoid | TArray _ | TFun _ | TNamed _ | TComp _ | TEnum _
   | TBuiltin_va_list -> assert false
   ```

   The rest of E-ACSL already maps `TEnum { ekind }` onto its underlying integer kind `ekind`
   (for instance `analyses/typing.ml`, `code_generator/assert.ml`, `code_generator/translate_terms.ml`,
   and `libraries/interval_utils.ml`).
3. In the same function, `get_pkind_str` (lines 131-147) only matches `TInt _` and `TVoid`, falling
   through to `Options.fatal "unexpected argument type in printf: ..."` for `TPtr (TEnum _)`. Under
   C11 6.7.2.2p4 and 6.7.6.1p2, each enumerated type is compatible with its underlying integer type
   `ekind`, so `enum S *` with `ekind = IInt` is compatible with `int *` (gcc 14 accepts
   `printf("hi%n\n", &s)` with `-Wall -Wextra -Wformat=2 -Wformat-signedness`), and mismatched enum
   pointers (`%n` on an unsigned enum, `%p` or `%s` on any enum pointer) should be caught by
   `validate_format_type` at run time just like `int *` / `unsigned int *`.

## Subtlety notes

- **Underlying `ekind` and signedness:** `cabs2cil.ml` sets `enum.ekind` using `Cil.intKindForValue`
  (only `IUChar | IUShort | IUInt | IULong | IULongLong | ISChar | IShort | IInt | ILong | ILongLong`,
  never `IBool` or 128-bit kinds). Under default GCC enum rules (`-enums gcc-enums`), an enum with
  only non-negative enumerators has `ekind = IUInt` (described as `"D"`, matching `%u`/`%x` and
  rejecting `%d`, matching gcc `-Wformat-signedness` and `format/printf.c`); an enum with a negative
  enumerator has `ekind = IInt` (`"d"`, matching `%d`/`%i`); 64-bit enums get `IULong` (`"L"`) or
  `ILong` (`"l"`); under `-enums int`, all enums get `IInt` (`"d"`).
- **Packed / short enums (`__attribute__((packed))`, `-enums gcc-short-enums`):** `ekind` is
  `IUChar` / `ISChar` / `IUShort` / `IShort`. Passing `ekind` to `get_ikind_str` produces `"d"` on
  `master` (matching `unsigned char` / `signed char` promotion to `int`), and automatically produces
  `"C"` / `"H"` when stacked with [!48](https://git.frama-c.com/pub/frama-c/-/merge_requests/48)
  (Issue 30, `#2819`) so `%u`/`%x` also accept packed unsigned enums.
- **Interaction with `!48` (Issue 30):** placing `| TEnum { ekind } -> get_ikind_str ekind ^ acc`
  after `| TPtr ty -> ...` (leaving `| TInt k -> ...` untouched) makes both patches stack cleanly
  via `git am --3way --keep-non-patch` in either order (`30` then `50`, or `50` then `30`). If `!48`
  lands first, `oracle/gen_printf_enum.0.c` changes `"ddd"` to `"dCC"` on the packed-enum line; the
  `dev` test passes unchanged in both orders. If `!28` (`#2797`, formals initialized) lands first,
  `oracle/gen_printf_enum.0.c` gains `__e_acsl_full_init` on `signal_eval`'s formals, just like
  `gen_printf.0.c` and `gen_printf_promoted.0.c`.

## Fix and validation

Patch [`./patches/50-eacsl-format-enum-argument.patch`](./patches/50-eacsl-format-enum-argument.patch):
one commit (`53ebd5fc4a`) on `master` `189053d4a2`, 5 files (4 insertions, 2 deletions in
`plugins/e-acsl/src/libraries/functions.ml`, plus regression test
`plugins/e-acsl/tests/format/printf_enum.c` with 14 sub-tests and its 3 oracles).

Validated on 2026-11-22 in fresh containers of `framac-master-audit:189053d` (`master`
`189053d4a2bd460c5c557dba8569474ff0419e73`):

- **`revalidate.sh package 50`:**
  - `git am --keep-non-patch`: exit 0, no file-mode changes, no executable files created.
  - **A (new test against unpatched `master`):** `printf_enum.c` FAILS in both default (`exit 125`,
    `File "plugins/e-acsl/src/libraries/functions.ml", line 156, characters 33-39: Assertion failed`)
    and `dev` configurations.
  - **B (new test against patched sources):** `printf_enum.c` PASSES in both default and `dev`
    configurations (14/14 sub-tests: 7 expected executions, 7 expected aborts).
  - **C (entire E-ACSL suite, default configuration):** `plugins/e-acsl` PASSES (exit 0, zero
    changes to any existing oracle).
  - **D (`./dev/check-files.sh -p HEAD~1`):** PASSES (`Debian clang-format version 19.1.7`,
    `Lint 5 file(s)`).
  - **E (installed patched tree + reproducer):** `RESULT: fixed` (12/12 cases pass, exit 0; before
    patch: `RESULT: bug present (12 of 12 cases fail)` on both `master` `189053d4a2` and
    `34.0~beta`).
- **Full `plugins/e-acsl/tests/format` `dev` suite** (`printf.c`, `fprintf.c`, `sprintf.c`,
  `printf_enum.c`) on patch 50 alone: PASSES (exit 0).
- **Stacking with Issue 30 (`!48`):** `revalidate.sh combined 30 50` and `combined 50 30` both
  auto-merge `plugins/e-acsl/src/libraries/functions.ml` cleanly (`git am --3way --keep-non-patch`),
  build cleanly, and pass both `printf_promoted.c` and `printf_enum.c` in `dev`.

Not run: 32-bit targets and `make default-tests` outside `plugins/e-acsl` (the change is local to
`Functions.Libc.get_printf_argument_str`, which only runs under `-e-acsl-validate-format-strings`).

## Duplicates

Searched live on 2026-11-22 via read-only GitLab API (`pub/frama-c`, issues and merge requests, all
states) for `validate-format-strings`, `get_printf_argument_str`, `functions.ml`, `TEnum`,
`printf enum`, `format enum`, `e-acsl-validate-format-strings`, and `enum` (MRs). Zero duplicates;
the only related items are our own format-validation reports (`#2819`–`#2822`, `!48`–`!51`).

## For the pipeline

Any target that prints an `enum` variable (or passes `&enum_var` to a `printf`-family function)
aborts E-ACSL Stage 1 instrumentation when `--validate-format-strings` is active, causing the fuzz
build to fall back to sanitizers-only. Until an upstream Frama-C release carries this fix, work
around it by disabling `--validate-format-strings` for that module or casting the `enum` argument
to its integer type. Recorded in
[`../../troubleshooting/eacsl-and-fuzzing.md`](../../troubleshooting/eacsl-and-fuzzing.md).
