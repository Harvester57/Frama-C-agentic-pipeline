# Kernel: `_Alignas` printed after the declarator of struct members and after `*` in pointer declarators, so `-print`/`-ocode` and E-ACSL output do not compile

**Filed upstream on 2026-11-15:** issue [#2812](https://git.frama-c.com/pub/frama-c/-/work_items/2812), merge request [!43](https://git.frama-c.com/pub/frama-c/-/merge_requests/43).

Issue 20 of this folder.

**Filing package:** [issue](./filing/20-kernel-alignas-member-printed-after-declarator-issue.md), [MR](./filing/20-kernel-alignas-member-printed-after-declarator-mr.md), [reproducer](./repro/20-kernel-alignas-member-printed-after-declarator.sh), [patch](./patches/20-kernel-alignas-member-printed-after-declarator.patch)

## Summary

`_Alignas` is an alignment specifier, one of the declaration specifiers (C17 6.7.5). Frama-C's
printer puts it after the declarator of struct and union members, and after the `*` of any pointer
declarator, and silently drops it on `__builtin_va_list` declarations (and, once `TPtr` forwards
`?alignas`, on `__builtin_va_list *` under `-no-variadic-translation`):

```c
union blk {
   uint64_t u64[2] _Alignas(16) ;      /* member */
   uint8_t b[16] ;
};
int *_Alignas(16) gp;                  /* global pointer */
int (*_Alignas(16) gfp)(int );         /* function pointer */
char * _Alignas(8)gap[2];              /* array of pointers */
__builtin_va_list gva;                 /* _Alignas(16) silently dropped */
__builtin_va_list *_Alignas(16) gvap = & gva;
```

GCC, Clang and Frama-C itself reject all the misplaced specifiers, and both GCC and Clang accept
`_Alignas` on `__builtin_va_list` objects and pointers. Only non-pointer globals and locals
(`int _Alignas(16) l;`, `uint64_t  _Alignas(16)ga[2];`) come out valid, which is why the problem
first looked member-only.

E-ACSL prints its instrumented file with the same printer, so a program with one aligned member
cannot be compiled after instrumentation. The pipeline hit it on nettle (run-3), whose
`nettle-types.h` declares `alignas(16) uint64_t u64[2];` in `union nettle_block16`: every module
including that header failed `build-check` with `error: expected ';' at end of declaration list`
(`xts`, `version`, `umac_l2`, `poly1305_internal`, `chacha_poly1305`, `arcfour`; see
[`../../troubleshooting/harnesses-and-seeds.md`](../../troubleshooting/harnesses-and-seeds.md)).

### Cause

In `src/kernel/services/ast_printing/cil_printer.ml` on `b80fcac74f`:

- `fieldinfo` prints the member through `self#typ` and then appends
  `self#alignas ~space:true fi.falignas` after the name. `vdecl` passes the alignment to
  `self#typ ?alignas:v.valignas` instead.
- `typ` prints the alignment at the base type for `TInt`, `TNamed`, `TComp`, ... (valid), but the
  `TPtr` case prints it inside the pointer declarator, right after `*`, and the
  `TArray` case prints it in front of the name inside the array declarator, which
  ends up after a `*` when the element type is a pointer.
- `TBuiltin_va_list` omits `palignas` entirely (with a stale comment claiming `_Alignas` does not
  make sense there), silently dropping `_Alignas` on `__builtin_va_list` and (once `TPtr` forwards
  `?alignas`) on `__builtin_va_list *` under `-no-variadic-translation`.

All came with `_Alignas` support (`681e1fc0b0`, "[kernel] typing: _Alignas", 2025-02-27).

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `b80fcac74f` (image `framac-master-audit:b80fcac`, first seen on `3dff90fc70`) | **bug present**: 8 misplaced `_Alignas` specifiers and 1 silently dropped (`gva`) in the reproducer (only the plain array is valid) |
| `34.0~beta (Selenium)`, opam build (image `framac-analysis:fc34`) | **bug present**, identical output |

## Reproduction

[`./repro/20-kernel-alignas-member-printed-after-declarator.c`](./repro/20-kernel-alignas-member-printed-after-declarator.c)
has a union and a struct with aligned members, aligned global and local pointers, a function pointer,
an array of pointers, and aligned `__builtin_va_list` / `__builtin_va_list *` globals.
[`./repro/20-kernel-alignas-member-printed-after-declarator.sh`](./repro/20-kernel-alignas-member-printed-after-declarator.sh)
prints it with `frama-c -no-variadic-translation -print -ocode`, lists the `_Alignas` lines, appends
`_Static_assert`s on the alignments, and compiles the result with gcc and clang, then re-parses it
with Frama-C:

```
--- _Alignas in the code printed by frama-c -print
4:   uint64_t u64[2] _Alignas(16) ;
9:   char d _Alignas(8) ;
10:   int *p _Alignas(16) ;
12:int *_Alignas(16) gp;
13:int (*_Alignas(16) gfp)(int );
14:char * _Alignas(8)gap[2];
15:uint64_t  _Alignas(16)ga[2];
17:__builtin_va_list *_Alignas(16) gvap = & gva;
21:  int *_Alignas(16) lp = (int *)0;
--- gcc -fsyntax-only: FAILED
--- clang -fsyntax-only: FAILED
--- frama-c re-parse: FAILED
RESULT: bug present
```

## Fix

[`./patches/20-kernel-alignas-member-printed-after-declarator.patch`](./patches/20-kernel-alignas-member-printed-after-declarator.patch),
one commit on `b80fcac74f`, "[kernel] print _Alignas with the base
type, never inside the declarator":

- `typ`: `TPtr`, `TArray` and `TFun` pass `?alignas` down to the recursive call and no longer print
  it in the declarator, so the leaf case prints it after the base type and its qualifiers
  (`int _Alignas(16) *gp;`). `TBuiltin_va_list` also prints `palignas true` (removing the stale
  comment). The `Printer_api.typ` signature is unchanged.
- `fieldinfo`: passes `?alignas:fi.falignas` to `typ`, like `vdecl`.
- New test `tests/pretty_printing/alignas.c` (the directory's default configuration runs with
  `-no-variadic-translation` and re-parses/merges the printed code, covering `__builtin_va_list` and
  `__builtin_va_list *` as well). Oracle updates:
  `tests/syntax/oracle/alignas_typing_constrains.{2,3,29,30}` (the member fix) and
  `plugins/rte/tests/basic/oracle/unaligned_pointer.0` (spacing only).

Output with the fix:

```
4:   uint64_t _Alignas(16) u64[2] ;
9:   char _Alignas(8) d ;
10:   int _Alignas(16) *p ;
12:int _Alignas(16) *gp;
13:int _Alignas(16) (*gfp)(int );
14:char _Alignas(8) *gap[2];
15:uint64_t _Alignas(16) ga[2];
16:__builtin_va_list _Alignas(16) gva;
17:__builtin_va_list _Alignas(16) *gvap = & gva;
21:  int _Alignas(16) *lp = (int *)0;
--- gcc -fsyntax-only: ok
--- clang -fsyntax-only: ok
--- frama-c re-parse: ok
RESULT: fixed (printed code compiles, alignments preserved)
```

## Validation

Validated on a fresh `framac-master-audit:b80fcac` container (`master` at `b80fcac74f`, Debian 13,
OCaml 5.5, gcc 14.2, clang 19) using `JOBS=4 /w/revalidate.sh before 20` and
`JOBS=4 /w/revalidate.sh package 20`:

| Check | `master` (`b80fcac74f`) | Patched |
|---|---|---|
| Reproducer (gcc, clang, Frama-C re-parse) | 3 of 3 reject (`exit=1`) | 3 of 3 accept (`exit=0`) |
| `_Static_assert` on the 6 alignments of the printed file (incl. `gva`, `gvap`) | not reached | hold |
| `tests/pretty_printing/alignas.c` (default) | fails (`exit=1`) | passes (`exit=0`) |
| `plugins/e-acsl` (default) | — | passes (`exit=0`) |
| `tests/pretty_printing`, `tests/syntax`, `plugins/rte/tests/basic` (default) | — | all pass (`exit=0`) |
| `./dev/check-files.sh -p HEAD~1` (lint + headers on 8 files) | — | passes (`exit=0`) |

`tests/libc/c2y.t` fails in this environment before and after the patch (gcc 14 has no
`-std=c2y`); it does not print declarations.

## Workaround

[`../../../scripts/eacsl_toolchain.py`](../../../scripts/eacsl_toolchain.py)
(`rewrite_trailing_alignas`) runs between the two E-ACSL stages and turns an `_Alignas(N)` that ends
a declarator into `__attribute__((__aligned__(N)))`, which compilers accept there and which keeps the
alignment. It only rewrites an `_Alignas(N)` followed by attributes and then `;`, `,` or `=`: the
member forms (`uint64_t u64[2] _Alignas(16) ;`, `int *p _Alignas(16) ;`). The forms inside a pointer
declarator (`int *_Alignas(16) gp;`, `int (*_Alignas(16) gfp)(int );`, `char * _Alignas(8)gap[2];`)
are followed by the name and are left as they are, so an instrumented file with an aligned pointer
global or local still fails to compile; none was seen on a target yet. Never use
`-D_Alignas(x)=`: it drops the alignment.

## Tracker

Not filed at the time of writing (see the filing note at the top). Nothing matches in the 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)), and a live
search on 2026-11-15 found nothing either.
