# Kernel: `_Alignas` printed after the declarator of struct members and after `*` in pointer declarators, so `-print`/`-ocode` and E-ACSL output do not compile

**Filed upstream on 2026-11-15:** issue [#2812](https://git.frama-c.com/pub/frama-c/-/work_items/2812), merge request [!43](https://git.frama-c.com/pub/frama-c/-/merge_requests/43).

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues). Not
filed yet. Issue 20 of this folder.

**Filing package:** [issue](./filing/20-kernel-alignas-member-printed-after-declarator-issue.md), [MR](./filing/20-kernel-alignas-member-printed-after-declarator-mr.md), [reproducer](./repro/20-kernel-alignas-member-printed-after-declarator.sh), [patch](./patches/20-kernel-alignas-member-printed-after-declarator.patch)

## Summary

`_Alignas` is an alignment specifier, one of the declaration specifiers (C17 6.7.5). Frama-C's
printer puts it after the declarator of struct and union members, and after the `*` of any pointer
declarator:

```c
union blk {
   uint64_t u64[2] _Alignas(16) ;      /* member */
   uint8_t b[16] ;
};
int *_Alignas(16) gp;                  /* global pointer */
int (*_Alignas(16) gfp)(int );         /* function pointer */
char * _Alignas(8)gap[2];              /* array of pointers */
```

GCC, Clang and Frama-C itself reject all of these. Only non-pointer globals and locals
(`int _Alignas(16) l;`, `uint64_t  _Alignas(16)ga[2];`) come out valid, which is why the problem
first looked member-only.

E-ACSL prints its instrumented file with the same printer, so a program with one aligned member
cannot be compiled after instrumentation. The pipeline hit it on nettle (run-3), whose
`nettle-types.h` declares `alignas(16) uint64_t u64[2];` in `union nettle_block16`: every module
including that header failed `build-check` with `error: expected ';' at end of declaration list`
(`xts`, `version`, `umac_l2`, `poly1305_internal`, `chacha_poly1305`, `arcfour`; see
[`../../troubleshooting/harnesses-and-seeds.md`](../../troubleshooting/harnesses-and-seeds.md)).

### Cause

In `src/kernel/services/ast_printing/cil_printer.ml` on `3dff90fc70`:

- `fieldinfo` (lines 1895-1906) prints the member through `self#typ` and then appends
  `self#alignas ~space:true fi.falignas` after the name. `vdecl` (line 728) passes the alignment to
  `self#typ ?alignas:v.valignas` instead.
- `typ` prints the alignment at the base type for `TInt`, `TNamed`, `TComp`, ... (valid), but the
  `TPtr` case (lines 2069-2076) prints it inside the pointer declarator, right after `*`, and the
  `TArray` case (lines 2112-2119) prints it in front of the name inside the array declarator, which
  ends up after a `*` when the element type is a pointer.

Both came with `_Alignas` support (`681e1fc0b0`, "[kernel] typing: _Alignas", 2025-02-27).

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `3dff90fc70` (image `framac-master-audit:3dff90f`) | **bug present**: 7 of the 8 printed alignment specifiers of the reproducer are invalid (only the plain array is not) |
| `34.0~beta (Selenium)`, opam build (image `framac-analysis:fc34`) | **bug present**, identical output |

## Reproduction

[`./repro/20-kernel-alignas-member-printed-after-declarator.c`](./repro/20-kernel-alignas-member-printed-after-declarator.c)
has a union and a struct with aligned members, aligned global and local pointers, a function pointer
and an array of pointers.
[`./repro/20-kernel-alignas-member-printed-after-declarator.sh`](./repro/20-kernel-alignas-member-printed-after-declarator.sh)
prints it with `frama-c -print -ocode`, lists the `_Alignas` lines, appends `_Static_assert`s on the
alignments, and compiles the result with gcc and clang, then re-parses it with Frama-C:

```
--- _Alignas in the code printed by frama-c -print
4:   uint64_t u64[2] _Alignas(16) ;
9:   char d _Alignas(8) ;
10:   int *p _Alignas(16) ;
12:int *_Alignas(16) gp;
13:int (*_Alignas(16) gfp)(int );
14:char * _Alignas(8)gap[2];
15:uint64_t  _Alignas(16)ga[2];
19:  int *_Alignas(16) lp = (int *)0;
--- gcc -fsyntax-only: FAILED
--- clang -fsyntax-only: FAILED
--- frama-c re-parse: FAILED
RESULT: bug present
```

## Fix

[`./patches/20-kernel-alignas-member-printed-after-declarator.patch`](./patches/20-kernel-alignas-member-printed-after-declarator.patch),
one commit on `fix/alignas-printing` from `3dff90fc70`, "[kernel] print _Alignas with the base
type, never inside the declarator":

- `typ`: `TPtr`, `TArray` and `TFun` pass `?alignas` down to the recursive call and no longer print
  it in the declarator, so the leaf case prints it after the base type and its qualifiers
  (`int _Alignas(16) *gp;`). The `Printer_api.typ` signature is unchanged.
- `fieldinfo`: passes `?alignas:fi.falignas` to `typ`, like `vdecl`.
- New test `tests/pretty_printing/alignas.c` (the directory's default configuration re-parses the
  printed code). Oracle updates: `tests/syntax/oracle/alignas_typing_constrains.{2,3,29,30}` (the
  member fix) and `plugins/rte/tests/basic/oracle/unaligned_pointer.0` (spacing only).

Output with the fix:

```
4:   uint64_t _Alignas(16) u64[2] ;
9:   char _Alignas(8) d ;
10:   int _Alignas(16) *p ;
12:int _Alignas(16) *gp;
13:int _Alignas(16) (*gfp)(int );
14:char _Alignas(8) *gap[2];
15:uint64_t _Alignas(16) ga[2];
19:  int _Alignas(16) *lp = (int *)0;
--- gcc -fsyntax-only: ok
--- clang -fsyntax-only: ok
--- frama-c re-parse: ok
RESULT: fixed (printed code compiles, alignments preserved)
```

## Validation

Patched `3dff90fc70`, built and installed over the switch of a throwaway copy of
`framac-master-audit:3dff90f` (Debian 13, gcc 14.2, clang 19).

| Check | `master` | Patched |
|---|---|---|
| Reproducer (gcc, clang, Frama-C re-parse) | 3 of 3 reject | 3 of 3 accept |
| `_Static_assert` on the 4 alignments of the printed file | not reached | hold |
| ptests `@tests/ptests_config` (1217 results) | — | pass, with the 4 `alignas_typing_constrains` oracle updates and the new `alignas.0.res.oracle` |
| ptests `@plugins/rte/tests/ptests_config` (87 results) | — | pass, with the `unaligned_pointer` spacing update |
| `grep -rli alignas` over `tests/`, `plugins/` | — | no other oracle, `gen_*.c` or cram expectation prints an alignment |
| `dune build --profile dev @src/kernel/check` | — | exit 0, no output |
| `git diff --check` | — | only the trailing spaces and final blank line of the new oracle (Frama-C output, as in the other oracles) |
| `make check-lint`, `make check-headers` | — | not run (tools not installed) |

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
