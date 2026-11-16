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

The same code path fails in three more ways:

- a const **union** global: the generated `(void *)u` is a cast from a union to a pointer, and the
  kernel rejects E-ACSL's own code: `User Error: implicit cast: cast from union u to void *`
  (Issue 23);
- a const **struct with a bitfield** member: E-ACSL aborts with
  `Taking the address of a bitfield with &[ cb.a ]`;
- a const **pointer** global (`int *const p = &x;`): E-ACSL emits `__e_acsl_mark_readonly((void *)p)`,
  so the block `p` points to is marked read-only instead of `p`. I saw no failure from it in a small
  program (`*p = 1` with `\valid(p)` checked passes); I did not look for a case where it shows.

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
- For a struct, `Cil.mkAddrOf` on a bitfield member aborts (`src/kernel/services/ast_queries/cil.ml:4874`).

`__e_acsl_mark_readonly(void *ptr)` expects the address of the block
(`share/e-acsl/observation_model/segment_model/e_acsl_segment_observation_model.c:118-122` marks
`_block_length(ptr)` bytes from `ptr`).

The code came with [e-acsl#223](https://git.frama-c.com/frama-c/e-acsl/-/issues/223) (`dc9cf84924`,
"[e-acsl] fix mark_readonly for structs", 2026-02-19), which fixed the same typing error for structs
by marking each field. Before it, `15b2c6f412` ("mark const globals as readonly", 2025-08-04) passed
`Cil.evar vi` for every type. Both are in 34.0~beta.

## Versions

- Reproduced on Frama-C `35.0~~dev (Bromine)`, `master` at `3dff90fc70` (2026-11-13), and on
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
[`./repro/27-eacsl-readonly-scalar-global-address.sh`](./repro/27-eacsl-readonly-scalar-global-address.sh)
builds them with `e-acsl-gcc -X` (instrumented program only), shows the `mark_readonly` calls and runs
them. On master (34.0~beta prints the same, with its version):

```text
35.0~~dev (Bromine)
--- e-acsl-gcc -q -X  27-eacsl-readonly-scalar-global-address.c
build: exit 0
run: exit 0
--- e-acsl-gcc -q -X -M 27-eacsl-readonly-scalar-global-address.c
build: exit 0
    __e_acsl_mark_readonly((void *)kMaxEmbeddedInt);
share/e-acsl/observation_model/segment_model/e_acsl_segment_tracking.c:226: Use of invalid address 0x17 in predicate
Aborted (core dumped)
run: exit 134
--- e-acsl-gcc -q -X -M 27-eacsl-readonly-scalar-global-address-bitfield.c
[kernel] Failure: Taking the address of a bitfield with &[ cb.a ]
e-acsl-gcc: fatal error: aborted by Frama-C
build: exit 1
```

The union case is reproduced by
[`./repro/23-eacsl-static-const-union-cast.sh`](./repro/23-eacsl-static-const-union-cast.sh).

## Proposed fix

[`./patches/27-eacsl-readonly-scalar-global-address.patch`](./patches/27-eacsl-readonly-scalar-global-address.patch)
(one commit on `fix/eacsl-readonly-global-address` from `3dff90fc70`, "[e-acsl] mark const globals
read-only through their address"). It also fixes Issue 23.

```diff
            let rec mark_readonly ty = match ty.tnode with
              | TNamed {ttype} -> mark_readonly ttype
-             | TComp {cstruct = true; cfields = Some fields} ->
+             | TComp {cstruct = true; cfields = Some fields}
+               when List.for_all (fun f -> f.fbitfield = None) fields ->
                List.map
                  (fun field ->
                     let lval = Var vi, Field (field, NoOffset) in
                     Smart_stmt.mark_readonly ~loc @@ Cil.mkAddrOf ~loc lval)
 
                  fields
-             | _ -> [Smart_stmt.mark_readonly ~loc @@ Cil.evar ~loc vi]
+             | TArray _ ->
+               (* the array decays to its address *)
+               [Smart_stmt.mark_readonly ~loc @@ Cil.evar ~loc vi]
+             | _ ->
+               (* scalars, pointers, unions and structures with a bitfield
+                  (which has no address): the runtime expects the address of
+                  the global, not its value *)
+               [Smart_stmt.mark_readonly ~loc @@ Cil.mkAddrOfVi vi]
            in
```

- Arrays keep `Cil.evar`, so the existing oracles with string literals do not change.
- Scalars, pointers, unions, incomplete structs and structs with a bitfield member get the address of
  the whole global: `__e_acsl_mark_readonly((void *)(& kMaxEmbeddedInt));`.
- Structs without bitfields keep the per-field calls of e-acsl#223. I did not merge them into one call
  on the whole struct, which would be simpler, because e-acsl#223 chose per-field marking and I do not
  know why.

The patch adds the regression test `plugins/e-acsl/tests/full-mtracking/const_globals.c` with its
oracles: a const scalar, a const union (initialized and not), a const struct with bitfields and a const
pointer. It asserts that each is `\valid_read` and not `\valid` (marked read-only), and that the
pointee of the const pointer is still `\valid`.

## Validation of the proposed fix

`master` at `3dff90fc70` in `framac-master-audit:3dff90f`, then the same tree with the patch, rebuilt
with dune and installed (Debian 13, gcc 14.2.0).

| Check | `master` | Patched |
|---|---|---|
| `27-eacsl-readonly-scalar-global-address.c`, `-X` | runs, exit 0 | runs, exit 0 |
| Same, `-X -M` | `(void *)kMaxEmbeddedInt`, "Use of invalid address 0x17", exit 134 | `(void *)(& kMaxEmbeddedInt)`, runs, exit 0 |
| `27-...-bitfield.c`, `-X -M` | "Taking the address of a bitfield", build exit 1 | `(void *)(& cb)`, runs, exit 0 |
| Issue 23 union variants (4), `-X -M` | "implicit cast: cast from union u to void *", build exit 1 | `(void *)(& zero_block)` / `(& main_zero_block)`, runs, exit 0 |
| Issue 23 const struct and non-const union variants | run, exit 0 | unchanged |
| New test `full-mtracking/const_globals.c` | "implicit cast" (line 16) | passes, default and `dev` configurations |
| ptests `plugins/e-acsl/tests`, default configuration (198 results) | — | only the new oracles; every other test matches its oracle (string literals keep `Cil.evar`) |
| ptests, `dev` configuration (compiled and run) in every directory but `libc/` and `format/` (188 results) | — | all match `oracle_dev` |
| `git diff --check` | — | clean in the source and the test; the generated oracles have the trailing space after `Warning:` and the final blank line that every E-ACSL oracle has |
| `ocp-indent` 1.9.0, repository `.ocp-indent` | — | `global_observer.ml` unchanged |
| `make check-lint`, `make check-headers` | — | not run: the image's tree is not a git checkout |

Not completed: the `dev` configuration of `libc/` and `format/`. Their tests abort child processes on
purpose, and the crash handler of the Docker host (`core_pattern` piped to a WSL crash collector) made
`format/printf.c` exceed a 40-minute timeout. Their default configuration ran and matches the oracles.

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
