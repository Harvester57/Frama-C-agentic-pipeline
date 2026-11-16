# E-ACSL: `Unexpected error (E_ACSL__Rtl.Symbols.Unregistered("__gmpz_clear"))` when the program uses GMP and an annotation needs GMP

**Filed upstream on 2026-11-15:** issue [#2816](https://git.frama-c.com/pub/frama-c/-/work_items/2816), no merge request. The issue lists the possible fixes (the validated patch below, a separate table, keeping the RTL declaration) and asks the maintainers which they prefer; the MR text stays ready for their answer.

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

**Filing package:** [issue](./filing/22-eacsl-gmp-symbol-unregistered-issue.md), [MR](./filing/22-eacsl-gmp-symbol-unregistered-mr.md), [reproducer](./repro/22-eacsl-gmp-symbol-unregistered.sh), [patch](./patches/22-eacsl-gmp-symbol-unregistered.patch)

## Summary

E-ACSL stops with an unexpected error when two conditions hold together:

- the program declares and calls GMP functions itself, usually through `<gmp.h>` (`mpz_init` and
  `mpz_clear` are macros for `__gmpz_init` and `__gmpz_clear`);
- an annotation or RTE check needs E-ACSL's own GMP code, for example
  `/*@ assert a * b + 1 > 0; */` on two `unsigned long`, whose value can exceed 64 bits.

```text
[kernel] Unexpected error (E_ACSL__Rtl.Symbols.Unregistered("__gmpz_clear")).
  Please report as 'crash' at https://git.frama-c.com/pub/frama-c/issues
```

Either condition alone is fine. The name in the exception is the first GMP function that E-ACSL needs
and that the program also uses. In the pipeline, libnettle's `libhogweed_a` and `libhogweed_a__mpz`
lost E-ACSL this way (they use GMP for public-key arithmetic) and fell back to sanitizers.

### Cause

`Rtl.link` (`plugins/e-acsl/src/project_initializer/rtl.ml:519`) merges the E-ACSL runtime library's
declarations into the user's AST. `lookup_rtl_globals` sorts each RTL function
(`rtl.ml:210-220`):

- if the user's AST has no function of that name, `add` registers the RTL varinfo in
  `Rtl.Symbols` (`Symbols.add_vi vi.vname vi`), and the RTL declaration is inserted;
- if it has one, `assoc` only records the pair in `Assocs`, so that `merge_rtl_spec` can merge the
  RTL contract into the user's function. The name never enters `Rtl.Symbols`.

The RTL declares the GMP functions under their real names (`__gmpz_clear` in
`plugins/e-acsl/share/e-acsl/numerical_model/e_acsl_gmp_api.h:198`). When the program declares `__gmpz_clear` too,
the second branch applies. When E-ACSL then generates GMP code for an annotation,
`Smart_stmt.rtl_call` (`plugins/e-acsl/src/code_generator/smart_stmt.ml:130-139`) looks the name up
with `Rtl.Symbols.find_vi`, which raises `Unregistered`. Nothing catches it on that path.

Without the annotation, E-ACSL never looks the name up. Without the program's declaration, the RTL's
varinfo is registered. A program that includes `<gmp.h>` but calls no GMP function instruments and
runs fine in my runs; I did not check whether the kernel drops the unused prototypes before E-ACSL
links its library.

[#197](https://git.frama-c.com/pub/frama-c/-/work_items/197) ("Plug-in crash with
`Unregistered_library_function` error", Mantis 2192, closed in 2021, fixed in Frama-C 14 Silicon) had a
similar message for `__store_block` and `atoi`'s contract, raised as `Misc.Unregistered_library_function`,
which no longer exists in the sources. It does not involve GMP or a function the program declares: I do
not think it is the same bug.

## Versions

- Reproduced on Frama-C `35.0~~dev (Bromine)`, `master` at `3dff90fc70` (2026-11-13), and on
  `34.0~beta (Selenium)`, Debian 13, gcc 14.2.0, libgmp 6.3. Same output on both.

## Reproduction

[`./repro/22-eacsl-gmp-symbol-unregistered.c`](./repro/22-eacsl-gmp-symbol-unregistered.c) declares
the two GMP functions itself, so it needs no GMP headers:

```c
struct my_mpz { int alloc; int size; unsigned long *d; };
void __gmpz_init(struct my_mpz *z);
void __gmpz_clear(struct my_mpz *z);

int f(unsigned long a, unsigned long b)
{
  struct my_mpz z;
  __gmpz_init(&z);
  __gmpz_clear(&z);
  /*@ assert a * b + 1 > 0; */
  return 0;
}

int main(void)
{
  return f(3, 4);
}
```

[`./repro/22-eacsl-gmp-symbol-unregistered-gmp-h.c`](./repro/22-eacsl-gmp-symbol-unregistered-gmp-h.c)
is the same with `#include <gmp.h>`, `mpz_t`, `mpz_init` and `mpz_clear`.
[`./repro/22-eacsl-gmp-symbol-unregistered.sh`](./repro/22-eacsl-gmp-symbol-unregistered.sh) builds
them with `e-acsl-gcc -X` (instrumented program only), plus a control without the assertion. On master
(34.0~beta prints the same, with its version):

```text
35.0~~dev (Bromine)
--- e-acsl-gcc -q -X  22-eacsl-gmp-symbol-unregistered.c
[kernel] Unexpected error (E_ACSL__Rtl.Symbols.Unregistered("__gmpz_clear")).
e-acsl-gcc: fatal error: aborted by Frama-C
build: exit 1
(control: the same program without the assertion)
--- e-acsl-gcc -q -X  /tmp/tmp.c9tDvzkPgc/noassert.c
build: exit 0
run: exit 0
--- e-acsl-gcc -q -X -l -lgmp 22-eacsl-gmp-symbol-unregistered-gmp-h.c
[kernel] Unexpected error (E_ACSL__Rtl.Symbols.Unregistered("__gmpz_clear")).
e-acsl-gcc: fatal error: aborted by Frama-C
build: exit 1
```

## Proposed fix

[`./patches/22-eacsl-gmp-symbol-unregistered.patch`](./patches/22-eacsl-gmp-symbol-unregistered.patch)
(one commit on `fix/eacsl-rtl-user-gmp-symbols` from `3dff90fc70`, "[e-acsl] register RTL functions
the user's code also declares"). In the `assoc` branch for functions, also register the user's varinfo
under the RTL name:

```diff
       let assoc g =
         let kf = Globals.Functions.find_by_name vi.vname in
-        Assocs.add_kf g kf
+        Assocs.add_kf g kf;
+        (* the user's function is the one the RTL function is linked with
+           (e.g. [__gmpz_clear] declared by <gmp.h>): register it under the
+           RTL name, so that the generated code can call it. *)
+        Symbols.add_vi vi.vname (Kernel_function.get_vi kf)
       in
```

The generated code then calls the program's declaration of the same function. `Smart_stmt.do_call`
casts the arguments to that declaration's parameter types, so the header-free reproducer gets
`__gmpz_clear((struct my_mpz *)(__gen_e_acsl_mul));`. The patch adds the regression test
`plugins/e-acsl/tests/bts/rtl_user_gmp_symbols.c` (the reproducer, in one `main`) with its two oracles.

**Side effect.** `Rtl.Symbols.mem_vi` is now true for these names as well. Its only user,
`Memory_tracking.must_never_monitor`, tests variables by name, so a local variable named like one of
these functions would no longer be monitored. A separate table for the user's functions would avoid
that, at the cost of a second lookup in `rtl_call`. Issue #2816 asks the maintainers which they prefer.

## Validation of the proposed fix

`master` at `3dff90fc70` in `framac-master-audit:3dff90f`, then the same tree with the patch, rebuilt
with dune and installed (Debian 13, gcc 14.2.0, libgmp 6.3).

| Check | `master` | Patched |
|---|---|---|
| `22-eacsl-gmp-symbol-unregistered.c` (header-free), `e-acsl-gcc -X` | `Unregistered("__gmpz_clear")`, build exit 1 | builds, runs, exit 0 |
| Same program without the assertion (control) | builds, runs, exit 0 | builds, runs, exit 0 |
| `22-eacsl-gmp-symbol-unregistered-gmp-h.c` (`<gmp.h>`), `-l -lgmp` | `Unregistered("__gmpz_clear")`, build exit 1 | builds, runs, exit 0 |
| New test `bts/rtl_user_gmp_symbols.c` | `Unregistered("__gmpz_clear")` | passes, default and `dev` configurations |
| ptests `plugins/e-acsl/tests`, default configuration (198 results) | — | only the two new oracles; every other test matches its oracle |
| ptests, `dev` configuration (compiled and run) in every directory but `libc/` (191 results) | — | all match `oracle_dev` |
| `git diff --check` | — | clean in the source and the test; the generated oracles have the trailing space after `Warning:` and the final blank line that every E-ACSL oracle has |
| `ocp-indent` 1.9.0, repository `.ocp-indent` | — | `rtl.ml` unchanged |
| `make check-lint`, `make check-headers` | — | not run: the image's tree is not a git checkout |

I left out the `dev` configuration of `libc/`: its tests abort child processes on purpose, and the
crash handler of the Docker host (`core_pattern` piped to a WSL crash collector) slowed every abort
so much that the directory did not finish in my time budget. The default configuration of `libc/` did
run, and the code generated for its tests matches the oracles.

## Workaround

None from the command line: E-ACSL's GMP code cannot be turned off, and the program's GMP declarations
are what the program needs. The pipeline names the failure in `build-check`
(`reason_code: eacsl_gmp_symbol_unregistered`, `pipeline_make.KNOWN_EACSL_FAILURES` in
[`../../../scripts/pipeline_make.py`](../../../scripts/pipeline_make.py)) and tells the user to switch the
module to the sanitizers engine, which loses E-ACSL's checks. The entry is in
[`../../troubleshooting/harnesses-and-seeds.md`](../../troubleshooting/harnesses-and-seeds.md)
("`E_ACSL__Rtl.Symbols.Unregistered(\"__gmpz_clear\")`").

## Tracker

- No match in the 202 open issues of the 2026-11-09 export
  ([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)): I searched
  titles and descriptions for `Unregistered`, `__gmpz` and `gmp`.
- A live search of git.frama-c.com on 2026-11-15 found only the closed
  [#197](https://git.frama-c.com/pub/frama-c/-/work_items/197), discussed in [Cause](#cause): not a
  duplicate.
