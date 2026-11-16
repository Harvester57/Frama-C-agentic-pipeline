# E-ACSL: a `register` local makes E-ACSL abort with "Taking the address of a register variable" under `-e-acsl-full-mtracking`

**Filed upstream on 2026-11-15:** issue [#2804](https://git.frama-c.com/pub/frama-c/-/work_items/2804), merge request [!35](https://git.frama-c.com/pub/frama-c/-/merge_requests/35).

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues). Not filed yet at the time of writing; see the filing note at the top.

**Filing package:** [issue](./filing/21-eacsl-register-local-full-mtracking-issue.md), [MR](./filing/21-eacsl-register-local-full-mtracking-mr.md), [reproducer](./repro/21-eacsl-register-local-full-mtracking.sh), [patch](./patches/21-eacsl-register-local-full-mtracking.patch)

## Summary

E-ACSL aborts on any function with a `register` local that it monitors:

```text
[kernel] Failure: Taking the address of a register variable with &[ i ]
[kernel] Frama-C aborted: internal error (Taking the address of a register variable with &[ i ]).
```

- Under `-e-acsl-full-mtracking` (`e-acsl-gcc -M`), E-ACSL monitors every local, so a plain
  `register unsigned i;` loop counter is enough.
- Without it, a memory predicate on the local is enough: `/*@ assert \initialized(&i); */` on
  `register int i = 1;`.

The kernel parses and prints the program without complaint, and E-ACSL without `-M` instruments it
when no annotation names the local. Every target with a `register` local loses E-ACSL under full memory
tracking. In the pipeline, 19 libnettle clusters failed this way (nettle `arcfour.c:78`,
`register uint8_t i, j;`; also `arctwo`, `md5`, `sha256`).

### Cause

E-ACSL observes a monitored variable through its address. In the reproducer, the crash comes from the
initialization of `i`:

```text
  Called from Frama_c_kernel_base__Cil.mkAddrOf.fatal in file "src/kernel/services/ast_queries/cil.ml", line 4871, characters 4-81
  Called from E_ACSL__Smart_stmt.initialize in file "plugins/e-acsl/src/code_generator/smart_stmt.ml", line 151, characters 32-52
  Called from E_ACSL__Injector.add_initializer in file "plugins/e-acsl/src/code_generator/injector.ml", line 173, characters 13-42
```

`Smart_stmt.initialize` builds `__e_acsl_full_init(&i)` with `Cil.mkAddrOf`, which aborts on a
`Register` variable (`src/kernel/services/ast_queries/cil.ml:4875`). `Smart_stmt.store_stmt`
(`smart_stmt.ml:171`, `__e_acsl_store_block(&i, ...)`) and `Smart_stmt.delete_stmt` take the address
the same way, through `Cil.mkAddrOfVi`. Nothing in E-ACSL looks at the storage class of the variables
it monitors.

`register` is a hint (C11 6.7.1p6). The constraint that comes with it is that the program cannot
compute the variable's address, and the original program does not (the kernel rejects `&i` in C code,
`src/kernel/internals/typing/cabs2cil.ml:1204`). So E-ACSL can drop the storage class from the variables
of the program it generates without changing what the program does.

## Versions

- Reproduced on Frama-C `35.0~~dev (Bromine)`, `master` at `3dff90fc70` (2026-11-13), and on
  `34.0~beta (Selenium)`, Debian 13, gcc 14.2.0. Same output on both.
- A `register` formal (`int sum(register int n)` with a contract, under `-M`) instruments and runs
  fine on both: `frama-c -print` shows `int sum(int n)`, so the formal no longer carries `register`
  when E-ACSL sees it.

## Reproduction

[`./repro/21-eacsl-register-local-full-mtracking.c`](./repro/21-eacsl-register-local-full-mtracking.c):

```c
int main(void)
{
  register unsigned i;
  unsigned sum = 0;
  for (i = 0; i < 4; i++)
    sum += i;
  return sum != 6;
}
```

[`./repro/21-eacsl-register-local-full-mtracking-assert.c`](./repro/21-eacsl-register-local-full-mtracking-assert.c)
is `register int i = 1; /*@ assert \initialized(&i); */ return i - 1;`.
[`./repro/21-eacsl-register-local-full-mtracking.sh`](./repro/21-eacsl-register-local-full-mtracking.sh)
builds both with `e-acsl-gcc -X` (instrumented program only) and runs them. On master (34.0~beta
prints the same, with its version):

```text
35.0~~dev (Bromine)
--- e-acsl-gcc -q -X  21-eacsl-register-local-full-mtracking.c
build: exit 0
run: exit 0
--- e-acsl-gcc -q -X -M 21-eacsl-register-local-full-mtracking.c
[kernel] Failure: Taking the address of a register variable with &[ i ]
e-acsl-gcc: fatal error: aborted by Frama-C
build: exit 1
--- e-acsl-gcc -q -X  21-eacsl-register-local-full-mtracking-assert.c
[kernel] Failure: Taking the address of a register variable with &[ i ]
e-acsl-gcc: fatal error: aborted by Frama-C
build: exit 1
```

## Proposed fix

[`./patches/21-eacsl-register-local-full-mtracking.patch`](./patches/21-eacsl-register-local-full-mtracking.patch)
(one commit on `fix/eacsl-register-locals` from `3dff90fc70`, "[e-acsl] drop the register storage
class of observed variables"). `Injector.inject_in_fundec` already rewrites the formals of each function
it instruments (it drops their ghost attribute); it now also resets the storage class of the
`register` locals and formals:

```diff
   List.iter unghost_formal fundec.sformals;
+  (* E-ACSL observes variables through their address ([__e_acsl_store_block],
+     [__e_acsl_full_init], [\initialized(&x)], ...), which C forbids for a
+     [register] variable. This storage class has no other effect on the
+     program, so drop it. *)
+  let unregister vi =
+    if vi.vstorage = Register then vi.vstorage <- NoStorage
+  in
+  List.iter unregister fundec.slocals;
+  List.iter unregister fundec.sformals;
```

The instrumented program declares `unsigned int i;` instead of `register unsigned int i;`. Doing it for
every local, monitored or not, keeps the change in one place; the storage class has no other effect on
the program. The formals are covered for safety, although the kernel had already dropped `register` from
the formal in my test.

The patch adds the regression test `plugins/e-acsl/tests/full-mtracking/register.c` with its oracles: a
`register` loop counter, and a `register` local named in `\initialized(&j)`. The `full-mtracking`
directory runs it with `-e-acsl-full-mtracking` (default configuration) and with
`e-acsl-gcc --full-mtracking` (`dev` configuration).

## Validation of the proposed fix

`master` at `3dff90fc70` in `framac-master-audit:3dff90f`, then the same tree with the patch, rebuilt
with dune and installed (Debian 13, gcc 14.2.0).

| Check | `master` | Patched |
|---|---|---|
| `21-eacsl-register-local-full-mtracking.c`, `e-acsl-gcc -X` | builds, runs, exit 0 | builds, runs, exit 0 |
| Same, `-X -M` | "Taking the address of a register variable", build exit 1 | builds, runs, exit 0 |
| `21-eacsl-register-local-full-mtracking-assert.c` (`\initialized(&i)`), no `-M` | same failure, build exit 1 | builds, runs, exit 0 |
| New test `full-mtracking/register.c` | same failure | passes, default and `dev` configurations |
| ptests `plugins/e-acsl/tests`, default configuration (198 results) | — | only the two new oracles; every other test matches its oracle |
| ptests, `dev` configuration (compiled and run) in every directory but `libc/` (191 results) | — | all match `oracle_dev` |
| `git diff --check` | — | clean in the source and the test; the generated `gen_register.0.c` ends with the blank line every E-ACSL oracle has |
| `ocp-indent` 1.9.0, repository `.ocp-indent` | — | `injector.ml` unchanged |
| `make check-lint`, `make check-headers` | — | not run: the image's tree is not a git checkout |

I left out the `dev` configuration of `libc/`: its tests abort child processes on purpose, and the
crash handler of the Docker host (`core_pattern` piped to a WSL crash collector) slowed every abort so
much that the directory did not finish in my time budget. The default configuration of `libc/` did run,
and the code generated for its tests matches the oracles.

## Workaround

Remove `register` from the locals before E-ACSL sees them. The pipeline passes `-Dregister=` to the
E-ACSL frontend only (`EACSL_FULL_MTRACKING_DEFINES` in
[`../../../scripts/eacsl_toolchain.py`](../../../scripts/eacsl_toolchain.py), added in commit `9b3d2f3`),
never to Eva or WP. The define would change the meaning of a global register variable
(`register T x asm("reg")`), which Frama-C does not parse anyway. The entry is in
[`../../troubleshooting/harnesses-and-seeds.md`](../../troubleshooting/harnesses-and-seeds.md)
("Taking the address of a register variable").

## Tracker

No match in the 202 open issues of the 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)): I searched titles
and descriptions for `register variable`, `mkAddrOf` and `full-mtracking`. A live search of
git.frama-c.com on 2026-11-15 found no duplicate either.
