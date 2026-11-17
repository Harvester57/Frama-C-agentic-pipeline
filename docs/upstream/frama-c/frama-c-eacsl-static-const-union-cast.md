# E-ACSL: a monitored const union global makes E-ACSL fail with `implicit cast: cast from union u to void *`

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues). Filed on 2026-11-15 as [#2795](https://git.frama-c.com/pub/frama-c/-/work_items/2795); the fix is Issue 27's merge request [!26](https://git.frama-c.com/pub/frama-c/-/merge_requests/26).

**Filing package:** [issue](./filing/23-eacsl-static-const-union-cast-issue.md), [reproducer](./repro/23-eacsl-static-const-union-cast.sh). The patch and the merge request are those of Issue 27: [MR](./filing/27-eacsl-readonly-scalar-global-address-mr.md), [patch](./patches/27-eacsl-readonly-scalar-global-address.patch).

**Same root cause as [frama-c-eacsl-readonly-scalar-global-address.md](./frama-c-eacsl-readonly-scalar-global-address.md)**
(Issue 27): E-ACSL passes the value of a const global to `__e_acsl_mark_readonly` instead of its
address. For a scalar the program aborts at run time; for a union, Frama-C rejects the generated cast.
One patch fixes both. File them together.

## Summary

With `-e-acsl-full-mtracking` (`e-acsl-gcc -M`), this program does not instrument:

```c
union u { unsigned char b[16]; unsigned long w[2]; };

static const union u zero_block;

int main(void) { return zero_block.b[0]; }
```

```text
[kernel] 23-eacsl-static-const-union-cast.c:20: User Error: 
  implicit cast: cast from union u to void *
e-acsl-gcc: fatal error: aborted by Frama-C
```

- `static` does not matter: a non-static `const union u zero_block;` fails the same way, and so does a
  `static const` union local to `main` (Frama-C turns it into the global `main_zero_block`).
- An initializer does not matter: `= { { 0 } }` fails the same way.
- A `static const` struct with the same members instruments and runs. So does a non-const `static`
  union.
- Without `-M`, E-ACSL does not monitor the global in this program, emits nothing for it, and the
  program runs.
- `frama-c -print` on the same file is clean: the cast comes from E-ACSL's generated code.

In the pipeline, 10 libnettle modules lost their E-ACSL build to `static const union nettle_block16 zero_block;`
(`block16_zero` in `block-internal.h`, `ocb_set_key`, `cmac128_set_key`).

### Cause

`Global_observer.mk_init_function` marks each monitored const global read-only. For any type but an
array or a struct, it passes the global itself (`Cil.evar ~loc vi`,
`plugins/e-acsl/src/code_generator/global_observer.ml:130`) to `Smart_stmt.mark_readonly`, which builds
`__e_acsl_mark_readonly((void *)zero_block)`. Converting a union to `void *` is not a valid C cast, and
the kernel's check of the generated code rejects it. Structs have their own branch (each field's
address, `global_observer.ml:123-129`, from e-acsl#223), which is why a const struct is fine. The full
analysis, which also covers scalars, pointers and structs with bitfields, is in
[frama-c-eacsl-readonly-scalar-global-address.md](./frama-c-eacsl-readonly-scalar-global-address.md#cause).

## Versions

- Reproduced on Frama-C `35.0~~dev (Bromine)`, `master` at `3dff90fc70` (2026-11-13), and on
  `34.0~beta (Selenium)`, Debian 13, gcc 14.2.0. Same output on both.

## Reproduction

[`./repro/23-eacsl-static-const-union-cast.c`](./repro/23-eacsl-static-const-union-cast.c) selects a
variant with `-D` (the default is the program above).
[`./repro/23-eacsl-static-const-union-cast.sh`](./repro/23-eacsl-static-const-union-cast.sh) builds each
with `e-acsl-gcc -X` (instrumented program only) and runs it. On master (34.0~beta prints the same, with
its version):

```text
35.0~~dev (Bromine)
--- e-acsl-gcc -q -X  -e -DDEFAULT -E -DDEFAULT 23-eacsl-static-const-union-cast.c
build: exit 0
run: exit 0
--- e-acsl-gcc -q -X -M -e -DDEFAULT -E -DDEFAULT 23-eacsl-static-const-union-cast.c
[kernel] 23-eacsl-static-const-union-cast.c:20: User Error:
  implicit cast: cast from union u to void *
e-acsl-gcc: fatal error: aborted by Frama-C
build: exit 1
--- e-acsl-gcc -q -X -M -e -DLOCAL_STATIC -E -DLOCAL_STATIC 23-eacsl-static-const-union-cast.c
[kernel] 23-eacsl-static-const-union-cast.c:6: User Error:
  implicit cast: cast from union u to void *
e-acsl-gcc: fatal error: aborted by Frama-C
build: exit 1
--- e-acsl-gcc -q -X -M -e -DINITIALIZED -E -DINITIALIZED 23-eacsl-static-const-union-cast.c
[kernel] 23-eacsl-static-const-union-cast.c:8: User Error:
  implicit cast: cast from union u to void *
e-acsl-gcc: fatal error: aborted by Frama-C
build: exit 1
--- e-acsl-gcc -q -X -M -e -DNON_STATIC -E -DNON_STATIC 23-eacsl-static-const-union-cast.c
[kernel] 23-eacsl-static-const-union-cast.c:11: User Error:
  implicit cast: cast from union u to void *
e-acsl-gcc: fatal error: aborted by Frama-C
build: exit 1
--- e-acsl-gcc -q -X -M -e -DCONST_STRUCT -E -DCONST_STRUCT 23-eacsl-static-const-union-cast.c
build: exit 0
    __e_acsl_mark_readonly((void *)(& zero_block.b));
    __e_acsl_mark_readonly((void *)(& zero_block.w));
run: exit 0
--- e-acsl-gcc -q -X -M -e -DNON_CONST_UNION -E -DNON_CONST_UNION 23-eacsl-static-const-union-cast.c
build: exit 0
run: exit 0
--- frama-c -print 23-eacsl-static-const-union-cast.c (no E-ACSL)
frama-c: exit 0
```

## Fix

Pass the address of the global (`Cil.mkAddrOfVi vi`) for every type but arrays. This is the patch of
Issue 27: [`./patches/27-eacsl-readonly-scalar-global-address.patch`](./patches/27-eacsl-readonly-scalar-global-address.patch).

### Validation

`master` at `3dff90fc70` in `framac-master-audit:3dff90f`, then the same tree with the Issue 27 patch,
rebuilt with dune and installed (Debian 13, gcc 14.2.0).

| Check | `master` | Patched |
|---|---|---|
| `DEFAULT` (`static const union u zero_block;`), `-M` | `implicit cast: cast from union u to void *`, build exit 1 | `__e_acsl_mark_readonly((void *)(& zero_block));`, runs, exit 0 |
| `LOCAL_STATIC`, `-M` | same error, build exit 1 | `(void *)(& main_zero_block)`, runs, exit 0 |
| `INITIALIZED`, `-M` | same error, build exit 1 | `(void *)(& zero_block)`, runs, exit 0 |
| `NON_STATIC`, `-M` | same error, build exit 1 | `(void *)(& zero_block)`, runs, exit 0 |
| `CONST_STRUCT`, `-M` | per-field calls, runs, exit 0 | unchanged |
| `NON_CONST_UNION`, `-M` | runs, exit 0 | unchanged |
| `DEFAULT` without `-M`; `frama-c -print` | exit 0 | exit 0 |
| Regression test `full-mtracking/const_globals.c` (Issue 27 patch), which has an initialized const union and a `static` one without initializer | `implicit cast` error (line 16, the first union) | passes; both unions are `\valid_read` and not `\valid` at run time |

The ptests run of the Issue 27 patch is in
[frama-c-eacsl-readonly-scalar-global-address.md](./frama-c-eacsl-readonly-scalar-global-address.md#validation-of-the-proposed-fix).

## Workaround

None from the command line. The pipeline's `build-check` names the failure
(`reason_code: eacsl_static_const_union`) and tells the user to switch the module to the sanitizers
engine. Dropping `const` from the declaration in a shadow copy of the source instruments, at the cost of
E-ACSL no longer treating the object as read-only. Since O9 in
[`../../plans/open-topics-remediation-plan.md`](../../plans/open-topics-remediation-plan.md), the pipeline does
this itself for `static const union` declarations, in the E-ACSL frontend's text only
(`scripts/fc_cpp_wrapper_eacsl.py`, switch `REWRITE_STATIC_CONST_UNIONS`); it goes when an image carries the fix. The entry
is in [`../../troubleshooting/harnesses-and-seeds.md`](../../troubleshooting/harnesses-and-seeds.md)
("implicit cast: cast from union nettle_block16 to void *").

## Tracker

No match in the 202 open issues of the 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)): I searched titles
and descriptions for `implicit cast`, `union` and `readonly`. A live search of git.frama-c.com on
2026-11-15 found no duplicate either.
