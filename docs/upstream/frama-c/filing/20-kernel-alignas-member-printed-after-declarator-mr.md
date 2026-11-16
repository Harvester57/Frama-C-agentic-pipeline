# [kernel] print _Alignas with the base type, never inside the declarator

- Source branch: `fix/alignas-printing` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/20-kernel-alignas-member-printed-after-declarator.patch`](../patches/20-kernel-alignas-member-printed-after-declarator.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2812.

## Problem

`_Alignas` is a declaration specifier (C17 6.7.5), but the printer emits it after the declarator of
struct and union members (`uint64_t u64[2] _Alignas(16) ;`) and after the `*` of pointer declarators
(`int *_Alignas(16) gp;`, `int (*_Alignas(16) gfp)(int );`, `char * _Alignas(8)gap[2];`). GCC,
Clang and Frama-C itself reject that output, so `-print`/`-ocode` and E-ACSL's generated code do not
compile as soon as a member or a pointer has an alignment specifier.

## Change

`src/kernel/services/ast_printing/cil_printer.ml`:

- `typ`: the `TPtr`, `TArray` and `TFun` cases no longer print the alignment inside the declarator;
  they pass `?alignas` to the recursive call on the pointed, element or return type, so it is
  printed by the leaf case after the base type and its qualifiers: `int _Alignas(16) *gp;`,
  `char _Alignas(8) *gap[2];`, `int _Alignas(16) (*gfp)(int );`.
- `fieldinfo`: passes `?alignas:fi.falignas` to `typ`, like `vdecl`, instead of appending the
  specifier after the member name.

The `Printer_api.typ` signature is unchanged.

Tests:

- new `tests/pretty_printing/alignas.c`: members, pointers, function pointers and arrays of pointers
  with `_Alignas`, as globals, locals and members. The default configuration of this directory
  prints the file and parses the printed code again; before the fix that re-parse fails with a
  syntax error at the first `_Alignas`.
- oracle updates, spacing only or the member fix itself:
  `tests/syntax/oracle/alignas_typing_constrains.{2,3,29,30}.res.oracle`
  (`int field _Alignas(8) ;` becomes `int _Alignas(8) field ;`) and
  `plugins/rte/tests/basic/oracle/unaligned_pointer.0.res.oracle`
  (`int8_t  _Alignas(4)c4[4];` becomes `int8_t _Alignas(4) c4[4];`).

## Testing

On a build of `3dff90fc70` with the patch (Debian 13, OCaml 5.5 switch, gcc 14.2, clang 19):

- Reproducer from the issue: before, gcc, clang and the Frama-C re-parse all reject the printed
  code; after, all three accept it, and `_Static_assert(_Alignof(union blk) == 16)`,
  `_Alignof(struct s) == 16`, `__alignof__(gp) == 16`, `__alignof__(gap) == 8` hold on the printed
  file.
- ptests, default configuration: `dune build @tests/ptests_config` (all of `tests/`, 1217 results)
  and `@plugins/rte/tests/ptests_config` (87 results) pass, with the oracle changes listed above.
  `grep -rli alignas` over `tests` and `plugins` finds no other oracle, generated `gen_*.c` or cram
  expectation that prints an alignment. (`tests/libc/c2y.t` fails in my environment before and
  after the patch because gcc 14 does not know `-std=c2y`; it does not print declarations.)
- `dune build --profile dev @src/kernel/check`: exit 0, no output.
- `git diff --check`: only the trailing spaces and final blank line of the new `.res.oracle`, which
  are Frama-C's own output (as in the other oracles of `tests/pretty_printing`).
- `./dev/check-files.sh -p` (that is, `make check-lint` and `make check-headers` on the changed
  files) with ocp-indent 1.10.0 and clang-format 19.1.7: clean.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
