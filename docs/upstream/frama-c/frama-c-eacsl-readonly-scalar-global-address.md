# E-ACSL: `__e_acsl_mark_readonly` gets the value of a const global instead of its address (scalar: runtime abort; union: rejected cast; bitfield struct: crash)

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues). Filed on 2026-11-15 as [#2794](https://git.frama-c.com/pub/frama-c/-/work_items/2794); the fix is merge request [!26](https://git.frama-c.com/pub/frama-c/-/merge_requests/26), which also closes Issue 23 ([#2795](https://git.frama-c.com/pub/frama-c/-/work_items/2795)).

**Filing package:** [issue](./filing/27-eacsl-readonly-scalar-global-address-issue.md), [MR](./filing/27-eacsl-readonly-scalar-global-address-mr.md), [reproducer](./repro/27-eacsl-readonly-scalar-global-address.sh), [patch](./patches/27-eacsl-readonly-scalar-global-address.patch)

**Same root cause as [frama-c-eacsl-static-const-union-cast.md](./frama-c-eacsl-static-const-union-cast.md)**
(Issue 23, the const union case). One patch, filed here, fixes both. File the two issues together, or
file this one and mention the union case in it.

## Summary

When E-ACSL monitors a const global, its globals initializer marks the global read-only with
`__e_acsl_mark_readonly`. For a scalar, it passes the value:

```c
const uint64_t kMaxEmbeddedInt = 23;
```

becomes

```c
    __e_acsl_mark_readonly((void *)kMaxEmbeddedInt);
```

and the program aborts before `main` does anything:

```text
share/e-acsl/observation_model/segment_model/e_acsl_segment_tracking.c:226: Use of invalid address 0x17 in predicate
Aborted (core dumped)
```

The same code path fails in four more ways:

- a const **union** global: the generated `(void *)u` is a cast from a union to a pointer, and the
  kernel rejects E-ACSL's own code: `User Error: implicit cast: cast from union u to void *`
  (Issue 23);
- a const **struct with a bitfield** member: E-ACSL aborts with
  `Taking the address of a bitfield with &[ cb.a ]`;
- a **multi-field const struct** (`struct pair { int a; int b; }; static const struct pair cp = { 1, 2 };`):
  E-ACSL emits one `__e_acsl_mark_readonly` call per field (`& cp.a`, `& cp.b`). Because
  `eacsl_mark_readonly(ptr)` calls `mark_readonly_region((uintptr_t)ptr, _block_length(ptr))` where
  `_block_length(ptr)` is the whole enclosing block size, any non-first field writes read-only shadow
  bits past the end of the struct: under `--rt-debug` it aborts with
  `Attempt to mark read-only 8 bytes past block boundaries` (`e_acsl_segment_tracking.c:497`), and
  without `--rt-debug` it silently corrupts adjacent global shadow memory. An empty `const struct {}`
  emits zero calls;
- a const **pointer** global (`int *const p = &x;`): E-ACSL emits `__e_acsl_mark_readonly((void *)p)`,
  so the block `p` points to is marked read-only instead of `p`.

The globals are monitored under `-e-acsl-full-mtracking` (`e-acsl-gcc -M`), or when an annotation
needs them. Without either, nothing is emitted for them and the programs run. In the pipeline, the scalar
case made libcbor's fuzz binaries abort before they read any input (`const uint64_t kMaxEmbeddedInt = 23;`),
and the union case cost 10 libnettle modules their E-ACSL build.

### Cause

`Global_observer.mk_init_function` (`plugins/e-acsl/src/code_generator/global_observer.ml:121-136`):

```ocaml
           let rec mark_readonly ty = match ty.tnode with
             | TNamed {ttype} -> mark_readonly ttype
             | TComp {cstruct = true; cfields = Some fields} ->
               List.map
                 (fun field ->
                    let lval = Var vi, Field (field, NoOffset) in
                    Smart_stmt.mark_readonly ~loc @@ Cil.mkAddrOf ~loc lval)

                 fields
             | _ -> [Smart_stmt.mark_readonly ~loc @@ Cil.evar ~loc vi]
```

- `Cil.evar vi` is the value of the global. That is right for an array only, which decays to its
  address (string literals are the most common case in the test oracles). For a scalar or a pointer it
  is a value; for a union it cannot be cast to `void *` at all.
- For a struct, `Cil.mkAddrOf` on a bitfield member aborts (`src/kernel/services/ast_queries/cil.ml:4874`),
  an empty struct produces an empty list of calls, and every field at a non-zero offset triggers an
  out-of-bounds shadow write because `eacsl_mark_readonly(void *ptr)` marks `_block_length(ptr)` bytes
  starting at `ptr` (`plugins/e-acsl/share/e-acsl/observation_model/segment_model/e_acsl_segment_observation_model.c:118-122`,
  `DVASSERT` in `mark_readonly_region` at `e_acsl_segment_tracking.c:497`).

`__e_acsl_mark_readonly(void *ptr)` expects the base address of the enclosing block.

The code came with [e-acsl#223](https://git.frama-c.com/frama-c/e-acsl/-/issues/223) (`dc9cf84924`,
"[e-acsl] fix mark_readonly for structs", 2026-02-19), which fixed the same typing error for structs
by marking each field. Before it, `15b2c6f412` ("mark const globals as readonly", 2025-08-04) passed
`Cil.evar vi` for every type. Both are in 34.0~beta.

## Versions

- Reproduced on Frama-C `35.0~~dev (Bromine)`, `master` at `b80fcac74f` (also `3dff90fc70`) and on
  `34.0~beta (Selenium)`, Debian 13, gcc 14.2.0. Same output on both.
- `git tag --contains 15b2c6f412` lists 32.0 onwards; I did not run releases before 34.

## Reproduction

[`./repro/27-eacsl-readonly-scalar-global-address.c`](./repro/27-eacsl-readonly-scalar-global-address.c):

```c
#include <stdint.h>

const uint64_t kMaxEmbeddedInt = 23;

int main(void)
{
  return kMaxEmbeddedInt != 23;
}
```

[`./repro/27-eacsl-readonly-scalar-global-address-bitfield.c`](./repro/27-eacsl-readonly-scalar-global-address-bitfield.c)
is `struct B { unsigned a : 3; unsigned b : 5; }; const struct B cb = { 1, 2 };` read in `main`.
[`./repro/27-eacsl-readonly-scalar-global-address-struct.c`](./repro/27-eacsl-readonly-scalar-global-address-struct.c)
is `struct pair { int a; int b; }; static const struct pair cp = { 1, 2 };` read in `main`.
[`./repro/27-eacsl-readonly-scalar-global-address.sh`](./repro/27-eacsl-readonly-scalar-global-address.sh)
builds them with `e-acsl-gcc -X` (instrumented program only), shows the `mark_readonly` calls and runs
them. On `master` at `b80fcac74f` (34.0~beta prints the same, with its version):

```text
35.0~~dev (Bromine)
--- e-acsl-gcc -q -X  27-eacsl-readonly-scalar-global-address.c
build: exit 0
run: exit 0
--- e-acsl-gcc -q -X -M 27-eacsl-readonly-scalar-global-address.c
build: exit 0
    __e_acsl_mark_readonly((void *)kMaxEmbeddedInt);
share/e-acsl/observation_model/segment_model/e_acsl_segment_tracking.c:226: Use of invalid address 0x17 in predicate
Aborted
run: exit 134
--- e-acsl-gcc -q -X -M 27-eacsl-readonly-scalar-global-address-bitfield.c
[kernel] Failure: Taking the address of a bitfield with &[ cb.a ]
e-acsl-gcc: fatal error: aborted by Frama-C
build: exit 1
--- e-acsl-gcc -q -X -M --rt-debug 27-eacsl-readonly-scalar-global-address-struct.c
build: exit 0
    __e_acsl_mark_readonly((void *)(& cp.a));
    __e_acsl_mark_readonly((void *)(& cp.b));
share/e-acsl/observation_model/segment_model/e_acsl_segment_tracking.c:497: Attempt to mark read-only 8 bytes past block boundaries
starting at 0x41-500c with block length 8 at base address 0x41-5008
...
Aborted
run: exit 134
```

The union case is reproduced by
[`./repro/23-eacsl-static-const-union-cast.sh`](./repro/23-eacsl-static-const-union-cast.sh).

## Proposed fix

[`./patches/27-eacsl-readonly-scalar-global-address.patch`](./patches/27-eacsl-readonly-scalar-global-address.patch)
(one commit on `fix/eacsl-readonly-global-address` from `b80fcac74f`, "[e-acsl] mark const globals
read-only through their base address"). It also fixes Issue 23.

```diff
            let rec mark_readonly ty = match ty.tnode with
              | TNamed {ttype} -> mark_readonly ttype
-             | TComp {cstruct = true; cfields = Some fields} ->
-               List.map
-                 (fun field ->
-                    let lval = Var vi, Field (field, NoOffset) in
-                    Smart_stmt.mark_readonly ~loc @@ Cil.mkAddrOf ~loc lval)
-
-                 fields
-             | _ -> [Smart_stmt.mark_readonly ~loc @@ Cil.evar ~loc vi]
+             | TArray _ ->
+               (* the array decays to its address *)
+               Smart_stmt.mark_readonly ~loc @@ Cil.evar ~loc vi
+             | _ ->
+               (* scalars, pointers, unions and structs: the runtime expects
+                  the base address of the global block *)
+               Smart_stmt.mark_readonly ~loc @@ Cil.mkAddrOfVi vi
            in
            let stmts =
              if Ast_types.C.is_const vi.vtype then
                (* a const global can't be modified after initialization. *)
-               mark_readonly vi.vtype @ stmts
+               mark_readonly vi.vtype :: stmts
              else stmts
            in
```

- The per-field `TComp` branch is removed completely, fixing bitfield structs, empty structs, and the
  out-of-bounds read-only shadow write on multi-field structs.
- Arrays keep `Cil.evar`, so the existing oracles with string literals do not change.
- Every other type (scalars, pointers, unions and structs) gets `Cil.mkAddrOfVi vi`, emitting a single
  call on the base address of the whole block:
  `__e_acsl_mark_readonly((void *)(& kMaxEmbeddedInt));`, `(void *)(& cp)`, etc.

One existing oracle changes: `plugins/e-acsl/tests/concurrency/oracle/gen_sequential_threads.0.c`
(`__e_acsl_mark_readonly((void *)(& s.i));` -> `__e_acsl_mark_readonly((void *)(& s));`).

The patch adds the regression test `plugins/e-acsl/tests/full-mtracking/const_globals.c` with its
oracles: a const scalar, a const union (initialized and not), a multi-field non-bitfield const struct,
a const struct with bitfields, and a const pointer. Its `dev` configuration runs with
`--full-mtracking --rt-debug` and asserts that each const global is `\valid_read` and not `\valid`
(marked read-only), and that for the const pointer `ptr`, `\valid(ptr) && \valid_read(&ptr) && !\valid(&ptr)`
holds.

## Validation of the proposed fix

`master` at `b80fcac74f` in `framac-master-audit:b80fcac`, validated with
[`../../../tools/upstream_audit/revalidate.sh`](../../../tools/upstream_audit/revalidate.sh)
(`JOBS=4 /w/revalidate.sh before 27 23` and `JOBS=4 /w/revalidate.sh package 27`, plus reproducer 23 on
the installed patched tree; Debian 13, gcc 14.2.0):

| Check | `master` (`b80fcac74f`) | Patched |
|---|---|---|
| `27-eacsl-readonly-scalar-global-address.c`, `-X` | runs, exit 0 | runs, exit 0 |
| Same, `-X -M` | `(void *)kMaxEmbeddedInt`, "Use of invalid address 0x17", exit 134 | `(void *)(& kMaxEmbeddedInt)`, runs, exit 0 |
| `27-...-bitfield.c`, `-X -M` | "Taking the address of a bitfield", build exit 1 | `(void *)(& cb)`, runs, exit 0 |
| `27-...-struct.c`, `-X -M --rt-debug` | per-field calls (`& cp.a`, `& cp.b`), "Attempt to mark read-only 8 bytes past block boundaries", exit 134 | `(void *)(& cp)`, runs, exit 0 |
| Issue 23 union variants (4), `-X -M` | "implicit cast: cast from union u to void *", build exit 1 | `(void *)(& zero_block)` / `(& main_zero_block)`, runs, exit 0 |
| Issue 23 `CONST_STRUCT`, `-X -M` | per-field calls (`& zero_block.b`, `& zero_block.w`), runs, exit 0 | single call `(void *)(& zero_block)`, runs, exit 0 |
| Issue 23 `NON_CONST_UNION`, `-X -M` | runs, exit 0 | unchanged |
| New test `full-mtracking/const_globals.c` | fails in default (`exit=1`, `implicit cast` on line 25) and `dev` (`exit=1`) | passes in default (`exit=0`) and `dev` (`--full-mtracking --rt-debug`, `exit=0`) |
| `./dev/test.sh -p plugins/e-acsl` (default suite) | — | passes (`exit=0`); only `const_globals` (new) and `concurrency/oracle/gen_sequential_threads.0.c` (1 line) updated; `concurrency/sequential_threads.c` also passes in `dev` |
| `./dev/check-files.sh -p HEAD~1` (lint + headers) | — | passes (`exit=0`) on all 5 files |

## Workaround

[`../../../scripts/eacsl_toolchain.py`](../../../scripts/eacsl_toolchain.py)
(`fix_readonly_scalar_globals`, `_READONLY_SCALAR_RE`, commit `9b0246b`, found on libcbor) rewrites
`__e_acsl_mark_readonly((void *)name);` into `__e_acsl_mark_readonly((void *)(& name));` in the
instrumented C, when it follows the `__e_acsl_store_block` and `__e_acsl_full_init` of the same
global. It covers scalars and pointers. It cannot help the union and bitfield cases, which fail inside
Frama-C before any C is printed; for those the pipeline falls back to the sanitizers (see Issue 23).

## Tracker

No match in the 202 open issues of the 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)): I searched titles
and descriptions for `readonly`, `read-only`, `mark_readonly`, `implicit cast` and `bitfield`. A live
search of git.frama-c.com on 2026-11-15 found no duplicate either. e-acsl#223 is on the private E-ACSL
tracker, which I cannot read.
