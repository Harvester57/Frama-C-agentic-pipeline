# [kernel] print _Alignas with the base type, never inside the declarator

- Source branch: `fix/alignas-printing` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `b80fcac74f`. Patch: [`../patches/20-kernel-alignas-member-printed-after-declarator.patch`](../patches/20-kernel-alignas-member-printed-after-declarator.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2812.

## Problem

`_Alignas` is a declaration specifier (C17 6.7.5), but the printer emits it after the declarator of
struct and union members (`uint64_t u64[2] _Alignas(16) ;`) and after the `*` of pointer declarators
(`int *_Alignas(16) gp;`, `int (*_Alignas(16) gfp)(int );`, `char * _Alignas(8)gap[2];`), and
silently drops it on `__builtin_va_list` declarations (and, once `TPtr` forwards `?alignas`, on
pointers to `__builtin_va_list` under `-no-variadic-translation`). GCC, Clang and Frama-C itself
reject the misplaced specifiers, so `-print`/`-ocode` and E-ACSL's generated code do not compile as
soon as a member or a pointer has an alignment specifier, and both GCC and Clang accept `_Alignas`
on `__builtin_va_list` objects and pointers.

## Change

`src/kernel/services/ast_printing/cil_printer.ml`:

- `typ`: the `TPtr`, `TArray` and `TFun` cases no longer print the alignment inside the declarator;
  they pass `?alignas` to the recursive call on the pointed, element or return type, so it is
  printed by the leaf case after the base type and its qualifiers: `int _Alignas(16) *gp;`,
  `char _Alignas(8) *gap[2];`, `int _Alignas(16) (*gfp)(int );`.
- `typ`: the `TBuiltin_va_list` case now prints `palignas true` like the other leaf cases (removing
  the stale comment claiming `_Alignas` does not make sense there), preserving `_Alignas` on
  `__builtin_va_list` and `__builtin_va_list *` under `-no-variadic-translation`.
- `fieldinfo`: passes `?alignas:fi.falignas` to `typ`, like `vdecl`, instead of appending the
  specifier after the member name.

The `Printer_api.typ` signature is unchanged.

Tests:

- new `tests/pretty_printing/alignas.c`: members, pointers, function pointers, arrays of pointers,
  `__builtin_va_list` and `__builtin_va_list *` with `_Alignas`, as globals, locals and members. The
  default configuration of this directory runs with `-no-variadic-translation`, prints the file and
  merges/re-parses the printed code; before the fix that fails on pristine `master` with a syntax
  error at the first `_Alignas` (and drops `_Alignas` on `gva`).
- oracle updates, spacing only or the member fix itself:
  `tests/syntax/oracle/alignas_typing_constrains.{2,3,29,30}.res.oracle`
  (`int field _Alignas(8) ;` becomes `int _Alignas(8) field ;`) and
  `plugins/rte/tests/basic/oracle/unaligned_pointer.0.res.oracle`
  (`int8_t  _Alignas(4)c4[4];` becomes `int8_t _Alignas(4) c4[4];`).

## Testing

On a fresh build of `master` (`b80fcac74f`) with the patch (Debian 13, OCaml 5.5 switch, gcc 14.2,
clang 19):

- Reproducer from the issue: before, gcc, clang and the Frama-C re-parse all reject the printed
  code (and `gva` loses `_Alignas(16)`); after, all three accept it, and `_Static_assert`s on
  `_Alignof(union blk) == 16`, `_Alignof(struct s) == 16`, `__alignof__(gp) == 16`,
  `__alignof__(gap) == 8`, `__alignof__(gva) == 16`, and `__alignof__(gvap) == 16` hold on the
  printed file.
- New test `tests/pretty_printing/alignas.c`: fails on `master` sources (exit 1), passes with the
  patch (exit 0); both `alignas.c` and the printed output compile cleanly with `gcc` and `clang`
  (`-std=gnu11` and `-std=c11`).
- Default ptests suites: `tests/pretty_printing`, `tests/syntax`, `plugins/rte/tests/basic`, and
  `plugins/e-acsl` all pass (exit 0).
- `./dev/check-files.sh -p HEAD~1` (lint and header check across all 8 files): exit 0.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
