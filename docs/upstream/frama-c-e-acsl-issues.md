# E-ACSL / `e-acsl-gcc` / Variadic issues found while fuzzing a production codebase (Frama-C 35 reassessment)

Upstream report from the Frama-C agentic verification pipeline. Each issue under
[Issues to file](#issues-to-file) has its own ready-to-file draft (linked in the table below) for the
Frama-C tracker (https://git.frama-c.com/pub/frama-c/-/issues). Each draft has a description, a
minimal reproducer, a proposed patch against `master` `ad24dca`, and the before/after results of
that patch. This page keeps the cross-issue view: the Frama-C 35 status, root causes, how our
pipeline works around each issue, and the [validation](#validation-of-the-proposed-fixes) of all
patches together.

> [!NOTE]
> Issues 1-8 were found with Frama-C 33.0, reassessed on `34.0~~dev (Selenium)`, and reassessed again
> on **2026-11-09** against **Frama-C `35.0~~dev (Bromine)`** in `framac-analysis:latest`, the
> image the pipeline runs today. Every reproducer below was re-run in that image. The source was
> cross-checked against upstream `master` at `ad24dca` (2026-11-02). The `e-acsl-gcc` script is
> byte-identical in the 34 image, the 35 image and on `master`, so script line numbers refer to
> all three (`/home/opam/.opam/5.5/bin/e-acsl-gcc`, `plugins/e-acsl/scripts/e-acsl-gcc`). The
> public tracker has no existing report for any of them. We searched for `e-acsl`, `variadic`,
> `rte`, `fallback`, `unbounded`, `incomplete`, `alignof`, `print-data`, `CFLAGS` and `rte-select`.
> Issues 12 and 13 were found during this reassessment. A search for `_DEFAULT_SOURCE` and `strdup`
> found no report of Issue 12. Issue 13 is
> [#177](https://git.frama-c.com/pub/frama-c/-/work_items/177), closed in 2022 as fixed, which fails
> again. None of the 202 open issues in the 2026-11-09 export
> ([`pub-frama-c_work_items_2026-11-09.csv`](pub-frama-c_work_items_2026-11-09.csv)) duplicates any
> issue on this page.

## Filing decision

| # | Issue | Frama-C 35 | File upstream? | Why | Draft |
|---|---|---|---|---|---|
| 1 | `e-acsl-gcc` re-parses `-e`/`-E`/`-l`/`-F` values as script options | **Present** | **Yes, high** | `-E "-I inc"` and `-l "-L dir -lm"` abort with `no input files`; `-e "-g"` silently enables GMP and drops the first input file | [option-arguments-reparsed](frama-c-eacsl-gcc-option-arguments-reparsed.md) |
| 3 | Variadic fallback names printed in declaration initializers | **Present** | **Yes, high** | Kernel bug, not E-ACSL-specific: `int fd = open(p, O_RDONLY);` printed by any `frama-c -no-frama-c-stdlib -print` does not link | [variadic-fallback-local-init](frama-c-variadic-fallback-local-init.md) |
| 4 | Unbounded ranges in Frama-C's own libc abort E-ACSL | **Present** | **Yes, medium** | `e-acsl-gcc -L` cannot instrument any program calling `strtok_r`, `getsockopt` or `wcschr` | [unbounded-range-abort](frama-c-eacsl-unbounded-range-abort.md) |
| 5 | `alignof`/`sizeof` emitted on incomplete (opaque) struct types | **Present** | **Yes, medium** | Opaque handles (`typedef struct X X;`) are ubiquitous; the generated C does not compile with gcc or clang | [incomplete-type-sizeof](frama-c-eacsl-incomplete-type-sizeof.md) |
| 8 | Wrapper `__retres` left uninitialized, struct `\result.f` false positive | **Present** | **Yes, high** | False runtime failure from E-ACSL's own `-e-acsl-rte 2`; no RTE plugin or `-M` needed | [struct-result-initialized](frama-c-eacsl-struct-result-initialized.md) |
| 9 | `-e-acsl-assert-print-data` aliased to `-e-acsl-O-valid` | **Present** | **Yes, trivial fix** | One-line copy-paste error in `options.ml` | [assert-print-data-alias](frama-c-eacsl-assert-print-data-alias.md) |
| 10 | `e-acsl-gcc -G clang` overwrites `CFLAGS` | **Present** | **Yes, medium** | Drops `-std=c99`, `-m<bits>`, `-g -O2`, `--rt-debug` flags; the `--rt-debug` backtrace comes out empty. File together with 12 | [clang-cflags](frama-c-eacsl-gcc-clang-cflags.md) |
| 12 | `e-acsl-gcc` compiles with `-std=c99` but without the `-D_DEFAULT_SOURCE` Frama-C preprocessed with | **Present** | **Yes, medium** | With gcc 14, any program calling `strdup`, `strtok_r`, `fileno`, … fails to build; clang works only because of Issue 10 | [default-source](frama-c-eacsl-gcc-default-source.md) |
| 13 | Formals registered with `__e_acsl_store_block` but never marked initialized | **Present** (also 34) | **Yes, high** | Any `\initialized` on a by-value struct field fails on every call, with or without `-rte`. Same bug as closed #177, which fails again. Same family as 8: file together | [formal-params-initialized](frama-c-eacsl-formal-params-initialized.md) |
| 2 | `-O` builds plain + `.e-acsl`; `-X`/`--oexec-e-acsl` absent from `-h` | Unchanged | No | Documented behaviour (`man e-acsl-gcc` describes `-O`, `-X`, `--oexec-e-acsl`; `-h` says it lists only basic options) | — |
| 6 | RTL abort in `unsafe_initialize` has no target location | Unchanged | No | `--rt-debug` already prints a backtrace naming the target function; its failure under clang is Issue 10 | — |
| 7 | Unknown names in `-rte-select`/`-e-acsl-functions` abort | Unchanged | No | Same convention as `-wp-fct`; deliberate kernel-wide behaviour | — |
| 11 | Kernel/RTE/ACSL changes in 34 | n/a | No | Changelog notes, not an issue | — |

The related libc contract bug for `getsockopt` (an unsatisfiable unbounded range, which also breaks
Eva and WP) has its own draft:
[frama-c-getsockopt-unbounded-range.md](frama-c-getsockopt-unbounded-range.md).

## Environment

| Component | Version |
|---|---|
| Frama-C | `35.0~~dev (Bromine)` (opam switch 5.5, image `framac/frama-c:dev` pinned by digest), `e-acsl-gcc` at `/home/opam/.opam/5.5/bin/e-acsl-gcc` |
| OS / libc | Debian GNU/Linux 13 (trixie), glibc 2.41 (`Debian GLIBC 2.41-12+deb13u4`) |
| Compiler | `Debian clang version 19.1.7 (3+b1)` via `-G clang`; gcc 14.2 for comparison |
| Mode | host-header mode (the script's default `-no-frama-c-stdlib`), `-fsanitize=fuzzer` in the pipeline |

Earlier baselines: Frama-C 33.0 on Ubuntu 24.04 (glibc 2.39), and `34.0~~dev (Selenium)` in the same
Debian 13 image.

---

# Issues to file

## Issue 1: values of `-e` / `-E` / `-l` / `-F` are split on whitespace and re-parsed as script options; a standalone `-g` enables `--gmp` and shifts positional arguments

**Status in Frama-C 35.** **Present.** The script is unchanged on `master`.

**Observed.** After `getopt` and `eval set -- "$ARGS"` (lines 431-439), `e-acsl-gcc` iterates
with an unquoted `for i in $@` (line 442). The script has no `--) shift; break ;;` branch before
the final `shift;` at line 814. The word list is split on `IFS` once, when the loop starts, while
each `case` branch `shift`s the real positional parameters. Every whitespace-separated token
inside an option value is therefore matched against `case "$i" in`. Any token that equals a script
option runs that option's branch and shifts the real argument list out of step.

- `-e "-g -O1"`: `-g` matches `-g|--gmp)` (lines 578-580). That branch sets
  `OPTION_GMP="-e-acsl-O-gmp-only"` and runs an extra `shift`.
  - Single file, `-e` before `-o`/`-O`: the extra shift removes `-o`, so `-o` and `-O` each
    consume the next token. Line 814 then shifts away the only input file:
    `e-acsl-gcc: fatal error: no input files`.
  - Several files, `-e` after `-o`: the extra shift consumes `--`, and line 814 **silently drops
    the first input file**. The logged Frama-C command is
    `frama-c ... -no-frama-c-stdlib t2.c -e-acsl -e-acsl-O-gmp-only ...`, with `t1.c` gone and
    GMP-only mode on.
- `-E "-I inc"`: `-I` matches `-I|--frama-c)` (line 588) and the run aborts with `no input files`.
  The joined form `-E "-Iinc"` works.
- `-l "-L /usr/lib -lm"`: `-L` matches `-L|--frama-c-stdlib)` and the run aborts with
  `no input files`.

**Expected.** Option arguments are never re-parsed as `e-acsl-gcc` options and never shift the
positional parameters.

**Reproducer** (verified on 35).

```sh
cat > t1.c <<'EOF'
int helper(int x) { return x + 1; }
EOF
cat > t2.c <<'EOF'
int main(void) { return 0; }
EOF
mkdir -p inc && echo '#define FOO 1' > inc/foo.h
printf '#include "foo.h"\nint main(void) { return FOO - 1; }\n' > inc_use.c

# 1. aborts: "e-acsl-gcc: fatal error: no input files"
e-acsl-gcc -G clang -F "-rte -machdep gcc_x86_64" -e "-g -O1" -o t.instrumented.c -O t t2.c

# 2. succeeds, but drops t1.c and passes -e-acsl-O-gmp-only to Frama-C
e-acsl-gcc -n -G clang -o t.instrumented.c -e "-g -O1" t1.c t2.c
grep -c helper t.instrumented.c   # 0
e-acsl-gcc -n -G clang -o t.instrumented.c -e "-gline-tables-only -O1" t1.c t2.c
grep -c helper t.instrumented.c   # 1

# 3. separated -I / -L forms abort: "e-acsl-gcc: fatal error: no input files"
e-acsl-gcc -n -E "-I inc" -o i.inst.c inc_use.c
e-acsl-gcc -l "-L /usr/lib -lm" -o t.inst.c -O tl t2.c
```

Include paths containing spaces cannot be passed through `-E`/`-e` either.

**Workaround in our pipeline.** [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py)
(`normalize_passthrough`) rewrites `-g` to `-gline-tables-only` and joins `-I dir` into `-Idir`.
It rejects any other standalone single-letter token, and any path containing whitespace, before
calling `e-acsl-gcc`.

**Proposed fix (validated).** Replace `for i in $@` (line 442) with `while [ $# -gt 0 ]; do case "$1" in`,
with each branch shifting its own flag and argument. Add `--) shift; break ;;` and a catch-all
`*) error ...`, and drop the trailing `shift;`. Patch and results:
[frama-c-eacsl-gcc-option-arguments-reparsed.md](frama-c-eacsl-gcc-option-arguments-reparsed.md).

---

## Issue 3: Variadic prints `<fn>_fallback_<N>` for calls in declaration initializers, so printed code does not link

**Status in Frama-C 35.** **Present.** This is a kernel bug in the Variadic transformation, not an
E-ACSL bug. It hits E-ACSL users first because `e-acsl-gcc` runs in host-header mode
(`-no-frama-c-stdlib`, line 359) by default and compiles Frama-C's printed output.

**Observed.** Without Frama-C's libc, a call to a libc variadic function that Variadic knows as
overloaded (`open`, `openat`, `fcntl`) finds none of the `__va_<fn>_*` variants
(`Unable to locate function __va_open_void which should be in the Frama-C LibC`). Variadic then
replaces the callee with a generated prototype `<fn>_fallback_<N>`. The printer extension that
Variadic installs restores the original name, with the fallback name in a comment, but only for
`Call` instructions. When the call initializes a local declaration
(`Local_init(v, ConsInit(open_fallback_1, args, Plain_func))`), the fallback name is printed as
the callee. Nothing defines it, so the output does not link:

```c
/* v3.c below, declaration initializers (Local_init): fallback name printed */
int open_fallback_1(char const *__file, int __oflag);
int fcntl_fallback_1(int __fd, int __cmd);
  int fd = open_fallback_1((char const *)*(argv + 0),00);
  int fl = fcntl_fallback_1(fd,3);

/* same call as an assignment, `fd = open("/dev/null", O_RDONLY, 0);` (Call): restored */
  fd = open("/dev/null",00,0); /* open_fallback_1 */
```

```
undefined reference to `open_fallback_1'
undefined reference to `fcntl_fallback_1'
```

**Root cause** (`master`). In `src/kernel/services/ast_transformations/variadic/variadic.ml`,
`change_printer` (line 17) overrides `#instr` and matches only
`Call(res, Var vi, args, loc) when Replacements.mem vi` (line 30). Its own comment states the
intent: the generated prototypes make the printed code uncompilable, so the printer prints the
original functions. `translate.ml:235` also produces fallback callees inside
`Local_init(v, ConsInit(c, args, kind), loc)`, and the printer has no branch for that case.

**Expected.** Printed code names the original function in both forms, so it compiles and links.

**Reproducer** (verified on 35, no E-ACSL involved).

```sh
cat > v3.c <<'EOF'
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  int fd = open(argv[0], O_RDONLY);
  int fl = fcntl(fd, F_GETFL);
  close(fd);
  return fl < 0;
}
EOF
frama-c -no-frama-c-stdlib v3.c -print -ocode v3p.c
grep -n fallback v3p.c          # int fd = open_fallback_1(...); int fl = fcntl_fallback_1(...);
gcc -w v3p.c -o v3p             # undefined reference to `open_fallback_1' / `fcntl_fallback_1'

# Same failure through e-acsl-gcc (default host-header mode):
e-acsl-gcc -G clang -o v.instrumented.c -O v v3.c
```

**Workaround.** After instrumentation, [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py)
(`find_variadic_fallbacks`, `build_fallback_object`) parses the fallback prototypes when linking
fails on `<fn>_fallback_<N>`. It generates a link-only object (`eacsl_fallbacks.o`) that forwards
each fallback to the real function, or sets `errno = ENOSYS` when the base function is unknown.
These definitions must stay out of the instrumented sources, because adding one shifts the `_N`
numbering at the call sites. Passing `-no-variadic-translation` also avoids the problem (verified:
the instrumented `v3.c` links). That kernel option replaced the Variadic plugin's
`-variadic-no-translation`, which Frama-C 34 and 35 reject as unknown.
`run_eacsl_fuzz.py --no-variadic-translation` passed the old spelling; it now passes the kernel
option (branch `eacsl-flag-fixes`).

**Proposed fix (validated).** Add the matching branch to `change_printer`:
`Local_init(v, ConsInit(f, args, k), loc) when Replacements.mem f`, printed with the original
varinfo name and the fallback name in a comment, as the `Call` branch already does. Four Variadic
oracles change, all intended. Patch and results:
[frama-c-variadic-fallback-local-init.md](frama-c-variadic-fallback-local-init.md).

---

## Issue 4: Frama-C libc mode (`-L`) aborts on libc contracts containing unbounded ranges (`unbounded ranges are not part of E-ACSl`)

**Status in Frama-C 35.** **Present.** The three libc contracts are unchanged on `master`.

**Observed.** With `e-acsl-gcc -L` (`-frama-c-stdlib`), any program calling a function whose
Frama-C libc `requires`/`ensures` uses an unbounded range aborts the whole instrumentation:

```
[e-acsl] FRAMAC_SHARE/libc/string.h:352: User Error:
  unbounded ranges are not part of E-ACSl
[kernel] Plug-in e-acsl aborted: invalid user input.
```

The contracts involved, in `FRAMAC_SHARE/libc/`:
1. `string.h:352-355` (`strtok_r`): `requires separation: \separated(..., *saveptr+(0..));`
2. `sys/socket.h:398` (`getsockopt`): `optval == \null || \valid(((char*)optval)+(0..));`
3. `wchar.h:110` (`wcschr`): `\result == \null || \subset(\result, wcs+(0..));`

Other libc constructs E-ACSL cannot translate are skipped with a warning. On the same build, a
`strchr` call produces `E-ACSL construct ... is not yet supported. Ignoring annotation.` and
instrumentation succeeds.

**Root cause** (`master`). E-ACSL raises `Options.abort` for `Trange(None, _) | Trange(_, None)`
in `analyses/typing.ml:666`, `analyses/interval.ml:520`, `analyses/memory_tracking.ml:390` and
`code_generator/memory_translate.ml:180`. The neighbouring unsupported term-set cases (`Tunion`,
`Tinter`, `Tcomprehension`) use `Error.not_yet`, which leads to the annotation being ignored with a
warning.

**Expected.** E-ACSL instruments programs that use Frama-C's own libc. Either it ignores the
clause with a warning, as for other unsupported constructs, or the three contracts are rewritten
with bounded ranges.

**Reproducer** (verified on 35).

```sh
cat > s.c <<'EOF'
#include <string.h>
int main(void) {
  char buf[] = "a:b";
  char *save = 0;
  char *tok = strtok_r(buf, ":", &save);
  return tok != 0;
}
EOF
e-acsl-gcc -L -G clang -o s.instrumented.c -O s s.c
```

**Workaround.** Host-header mode (`-no-frama-c-stdlib`), which brings Issue 3.

**Proposed fix (validated).** Report unbounded ranges through `Error.untypable "unbounded range"` at
all four sites, so that only the annotation is dropped. This also removes the `E-ACSl` typo. Patch
and results: [frama-c-eacsl-unbounded-range-abort.md](frama-c-eacsl-unbounded-range-abort.md).

---

## Issue 5: E-ACSL and RteGen emit `alignof` / `sizeof` on incomplete (opaque) struct types

**Status in Frama-C 35.** **Present.** The generated C fails with both clang 19 and gcc 14.

**Observed.** Library handle types are often declared opaque (`typedef struct json_object json_object;`)
and used only through pointers. Two common patterns generate uncompilable code:

1. **Pointer cast under `-rte`** (`-warn-unaligned-pointer` is on by default). RteGen emits
   `/*@ assert rte: pointer_alignment: \aligned(p,alignof(json_object)); */`, visible with plain
   `frama-c -rte -print`. E-ACSL translates it to `__e_acsl_aligned(p,_Alignof(json_object))`:
   ```
   error: invalid application of 'alignof' to an incomplete type 'json_object' (aka 'struct json_object')
   ```
2. **`\valid` / `\valid_read` on an opaque pointer**, with no RTE plugin involved.
   `/*@ requires obj == \null || \valid_read(obj); */` becomes
   `__e_acsl_valid_read((void *)obj, sizeof(json_object const), ...)`:
   ```
   error: invalid application of 'sizeof' to an incomplete type 'const json_object' (aka 'const struct json_object')
   ```

E-ACSL already checks completeness for **its own** guards. On the same input it warns
`cannot create the pointer alignment guard of obj because json_object const is an incomplete type`,
and then emits `sizeof` on that type anyway when translating the user's `\valid_read`.

**Root cause** (`master`). RteGen's `trivially_aligned` (`plugins/rte/src/rte.ml:425`) exempts
`void` and function targets but not incomplete types, so `pointer_alignment` (line 463) raises the
alarm. E-ACSL's `analyses/rte_analysis.ml` guards its own alignment and pointer-value checks with
`Cil.isCompleteType` (lines 515, 566). `code_generator/memory_translate.ml:281` builds
`Smart_exp.ptr_sizeof ~loc ty` for `\valid`/`\valid_read` with no such check.

**Expected.**
- RteGen does not emit `\aligned(p, alignof(T))` for incomplete `T`, just as it skips `void`, or
  E-ACSL skips such an annotation with a warning.
- For `\valid(p)` / `\valid_read(p)` on a pointer to an incomplete type, E-ACSL warns and skips the
  annotation (or reduces it to a non-null, 1-byte validity check) instead of emitting `sizeof(T)`.

**Reproducer** (verified on 35).

```sh
cat > opaque_cast.c <<'EOF'
typedef struct json_object json_object;
json_object *from_void(void *p) { return (json_object *)p; }
int main(void) { return from_void(0) != 0; }
EOF
e-acsl-gcc -G clang -F "-rte" -o opaque_cast.inst.c -O opaque_cast opaque_cast.c

cat > opaque_valid.c <<'EOF'
typedef struct json_object json_object;
/*@ requires obj == \null || \valid_read(obj); */
int is_set(const json_object *obj) { return obj != 0; }
int main(void) { return is_set(0); }
EOF
e-acsl-gcc -G clang -o opaque_valid.inst.c -O opaque_valid opaque_valid.c
```

**Workaround.** Our header stubs ([`../../templates/fc_stubs/json-c/json.h`](../../templates/fc_stubs/json-c/json.h))
give opaque handles a complete dummy definition (`struct json_object { int _fc_opaque; };`). This
is sound only when the code under analysis never allocates or dereferences the struct itself.

**Proposed fix (validated).** Two E-ACSL-side checks, each ending in `Error.not_yet` so the
annotation is ignored with a warning:

- In `typing.ml`, `sizeof`/`alignof` of an incomplete struct or union (this covers the RTE
  alignment assertion).
- In `memory_translate.ml`, memory predicates whose pointee is incomplete (this covers `\valid`,
  `\valid_read` and `\initialized`).

A check placed only in typing does not work for `\valid`: translation then fails with
`typing was not performed on construct obj`. The RteGen-side change is listed as an alternative.
Patch and results: [frama-c-eacsl-incomplete-type-sizeof.md](frama-c-eacsl-incomplete-type-sizeof.md).

---

## Issue 8: `__gen_e_acsl_<fn>` wrapper leaves `__retres` uninitialized under `-rte-initialized`

**Status in Frama-C 35.** **Present.** The reproducer can now be reduced to an E-ACSL option
alone. Any of `-e-acsl-rte 2`, `-e-acsl-rte-initialized` or `-rte-initialized @all` triggers it.
Neither the RTE plugin (`-rte`) nor `-e-acsl-full-mtracking` is needed.

**Observed.** For a function with a contract, E-ACSL generates `__gen_e_acsl_<fn>`. The wrapper
declares `struct S __retres;`, registers it with `__e_acsl_store_block`, checks `requires`, runs
`__retres = make_s(x);`, and checks `ensures`. It never marks `__retres` as initialized after the
call. When initialization guards are enabled, E-ACSL guards the read of `\result.a` in
`ensures \result.a == x;` with `__e_acsl_initialized(&__retres.a, sizeof(int))`, and every call
fails:

```
struct_repro.c: In function 'make_s'
struct_repro.c:4: Error: E-ACSL RTE failed:
	The failing predicate is:
	uninitialized:
		\initialized(&\result.a).
	With values at failure point:
	- uninitialized: \initialized(&\result.a): 0
Aborted
```

Scalar results are not affected (`ensures \result >= 0;` runs clean).

**Root cause** (`master`). In `plugins/e-acsl/src/analyses/rte_analysis.ml`,
`add_initialized`'s `needs_guard` (lines 492-505) exempts `TResult _, TNoOffset` with the comment
"Frama-C kernel ensures that '__retres' is always initialized". A field of the result
(`TResult _, TField _`) falls through to the default case and gets the guard. The wrapper never
initializes `__retres` in shadow memory, so the guard always fails.
`needs_initialized` (lines 126-133) turns these guards on for `-e-acsl-rte-initialized`, for
`-rte-initialized`, or for `-e-acsl-rte` greater than 1.

**Expected.** No false failure. Either exempt `TResult _` with any offset, matching the comment's
rationale, or emit `__e_acsl_full_init((void *)(& __retres));` right after
`__retres = <fn>(...);` in the wrapper. E-ACSL already does this for `__retres` inside `<fn>` and
for `tmp = __gen_e_acsl_<fn>(...);` in callers.

**Reproducer** (verified on 35).

```c
/* struct_repro.c */
struct S { int a; };

/*@ requires x >= 0;
    ensures \result.a == x; */
struct S make_s(int x) {
  struct S s = { x };
  return s;
}

int main(void) {
  struct S s = make_s(0);
  return s.a;
}
```
```sh
e-acsl-gcc -G clang -F "-e-acsl-rte 2" -o struct_inst.c -O struct_bin struct_repro.c
./struct_bin.e-acsl    # E-ACSL RTE failed: \initialized(&\result.a), exit 134
```

**Workaround.** [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py)
(`mark_wrapper_results_initialized`) post-processes `instrumented.c`. In every `__gen_e_acsl_*`
wrapper that registered `__retres`, it inserts
`__e_acsl_initialize((void *)(& __retres), sizeof(__retres));` after `__retres = <fn>(...);`.
Frama-C prunes the declaration of `__e_acsl_initialize` unless E-ACSL itself emits a call to it,
so the workaround also inserts a forward declaration when none precedes the first patched wrapper.

**Proposed fix (validated).** `| TResult _, _ -> false` in `needs_guard`, the first option above. A
genuinely uninitialized local is still reported. The `full_init` variant is described as an
alternative but was not implemented. Patch and results:
[frama-c-eacsl-struct-result-initialized.md](frama-c-eacsl-struct-result-initialized.md).

---

## Issue 9: `-e-acsl-assert-print-data` is wired as a deprecated alias for `-e-acsl-O-valid` instead of `-e-acsl-O-print-values`

**Status in Frama-C 35.** **Present**, on `master` too.

**Observed.** Frama-C 34 moved `-e-acsl-assert-print-data` under `-e-acsl-O-print-values` and
`-e-acsl-valid` under `-e-acsl-O-valid`. `e-acsl-gcc` maps `--assert-print-data` correctly to
`-e-acsl-O-print-values` (lines 742-749). The plugin itself registers the old flag as an alias of
the wrong option:

```
[kernel] Warning: -e-acsl-assert-print-data is a deprecated alias for option -e-acsl-O-valid.
[kernel] Warning: -e-acsl-no-assert-print-data is a deprecated alias
  for option -e-acsl-O-no-valid. ...
```

Any script still passing `-e-acsl-assert-print-data` silently re-instruments annotations already
proven valid. `-e-acsl-no-assert-print-data` does not turn off value printing.

**Root cause** (`master`). `plugins/e-acsl/src/options.ml:212` reads
`let () = Verify_valid.add_aliases ~deprecated:true ~visible:false ["-e-acsl-assert-print-data"]`
directly after `module Print_values`. It is a copy of line 202 that should say `Print_values`.

**Reproducer** (verified on 35).

```sh
cat > valid_test.c <<'EOF'
int main(void) {
  int x = 1;
  /*@ assert x == 1; */
  return 0;
}
EOF
frama-c -machdep gcc_x86_64 valid_test.c -wp -then -e-acsl -then-last -print | grep -c __e_acsl_assert                            # 32
frama-c -machdep gcc_x86_64 valid_test.c -wp -then -e-acsl -e-acsl-assert-print-data -then-last -print | grep -c __e_acsl_assert  # 40
frama-c -machdep gcc_x86_64 valid_test.c -wp -then -e-acsl -e-acsl-O-valid -then-last -print | grep -c __e_acsl_assert            # 40
```

**Proposed fix (validated).** `Print_values.add_aliases` on line 212. Patch and results:
[frama-c-eacsl-assert-print-data-alias.md](frama-c-eacsl-assert-print-data-alias.md).

**Our pipeline.** [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py) passed
`-e-acsl-assert-print-data` in `EACSL_FC_EXTRA_FLAGS`, so it hit this bug. Branch
`eacsl-flag-fixes` drops the flag (print-values is already on at the default `O = 2`), and a test
keeps it out.

---

## Issue 10: `e-acsl-gcc -G clang` overwrites `CFLAGS` instead of appending to it

**Status in Frama-C 35.** **Present** (lines 892-917, unchanged on `master`).

**Observed.** Lines 892-908 build `CFLAGS` from `$OPTION_CFLAGS -std=c99 $GCCMACHDEP $OPT_CFLAGS
-fno-builtin -fno-merge-constants -Wall -Wno-...`. The clang branch then replaces it:

```sh
# Disable extra warning for clang
if [ "`basename $CC`" = 'clang' ]; then
  CFLAGS="-Wno-unknown-warning-option \
    -Wno-extra-semi \
    -Wno-tautological-compare \
    -Wno-gnu-empty-struct \
    -Wno-incompatible-pointer-types-discards-qualifiers"
fi
```

Under `-G clang` this silently loses:
- `$OPT_CFLAGS`: `-g -O2` by default, and `-g3 -O0 -fno-omit-frame-pointer` under `-D` /
  `--rt-debug`. Without frame pointers, the RTL's frame-walking `trace()`
  (`e_acsl_trace.c`) prints an **empty backtrace** on failure, so the main diagnostic
  `--rt-debug` offers is lost (see Issue 6).
- `$GCCMACHDEP` (`-m$MACHDEPFLAGS`). Frama-C still gets `-machdep gcc_x86_$MACHDEPFLAGS` from
  `--mbits`, while clang builds for its default target. We read this from the script; it was not
  exercised in the container.
- `-std=c99 -fno-builtin -fno-merge-constants` and every `-Wno-*` from lines 895-908. Clang 19
  then prints 169 `-Wunknown-attributes` warnings (`__FC_BUILTIN__`) per compile.

**Reproducer** (verified on 35).

```sh
e-acsl-gcc -D -G gcc   -o t.inst.c -O t_gcc   t2.c 2>&1 | grep -- "-o t_gcc"
# gcc -std=c99 -m64 -g3 -O0 -fno-omit-frame-pointer -fno-builtin -fno-merge-constants -Wall ...
e-acsl-gcc -D -G clang -o t.inst.c -O t_clang t2.c 2>&1 | grep -- "-o t_clang"
# clang -Wno-unknown-warning-option -Wno-extra-semi -Wno-tautological-compare -Wno-gnu-empty-struct
#       -Wno-incompatible-pointer-types-discards-qualifiers t2.c -o t_clang -no-pie

# Consequence for --rt-debug: compare the backtrace of an RTL failure
cat > bad_write.c <<'EOF'
void write_ptr(int *p) { *p = 42; }
int main(void) { write_ptr((int *)0x1000); return 0; }
EOF
e-acsl-gcc -D -M          -o bw.inst.c -O bwg bad_write.c && ./bwg.e-acsl  # backtrace: write_ptr, main
e-acsl-gcc -D -M -G clang -o bw.inst.c -O bwc bad_write.c && ./bwc.e-acsl  # empty backtrace
```

**Workaround.** We pass codegen flags explicitly through `-e` (`-gline-tables-only -O1 ...`). With
`-e "-gline-tables-only -fno-omit-frame-pointer -O0"`, the clang backtrace is complete again.

**Proposed fix (validated).** Append instead of replacing: `CFLAGS="$CFLAGS -Wno-unknown-warning-option ..."`.
No `-Wno-unknown-attributes` is needed: the restored `-Wno-attributes` already silences the
`__FC_BUILTIN__` warnings, and 5 warnings remain, all in the runtime's own `e_acsl_rtl_error.c`. This
fix must land with [Issue 12](#issue-12-e-acsl-gcc-compiles-with--stdc99-but-without-the--d_default_source-that-frama-c-preprocessed-with):
restoring `-std=c99` makes clang hide POSIX declarations as gcc already does. Patch and results,
including the man-page nit (`.e.acsl` suffix, wrong `--oexec-e-acsl` default):
[frama-c-eacsl-gcc-clang-cflags.md](frama-c-eacsl-gcc-clang-cflags.md).

---

## Issue 12: `e-acsl-gcc` compiles with `-std=c99` but without the `-D_DEFAULT_SOURCE` that Frama-C preprocessed with

**Status in Frama-C 35.** **Present**, and new in this reassessment. We found it while validating the
Issue 10 fix.

**Observed.** Frama-C's preprocessing gets `-std=c99 -D_DEFAULT_SOURCE` (`FRAMAC_CPP_EXTRA`,
lines 862-868), but the compiler gets `-std=c99` alone (line 893). In strict C99 mode, glibc hides
POSIX/BSD declarations (`strdup`, `strtok_r`, `fileno`, `getline`, …). Frama-C sees and instruments
the calls, while the compiler sees implicit `int` declarations:

- With gcc 14, `-Wint-conversion` is an error, so the build fails
  (`fail to compile/link un-instrumented code`).
- With `-L`, the instrumented code fails the same way (`#include "string.h"`,
  `implicit declaration of function ‘strdup’`).
- Clang works today only because of Issue 10.

**Reproducer** (verified on 35).

```sh
cat > posix_dup.c <<'EOF'
#include <string.h>
#include <stdlib.h>
int main(void) {
  char *d = strdup("abc");
  int ok = d != 0 && d[0] == 'a';
  free(d);
  return !ok;
}
EOF
e-acsl-gcc -o pd.c -O pd posix_dup.c
# posix_dup.c:4:13: error: initialization of ‘char *’ from ‘int’ makes pointer from integer without a cast
# e-acsl-gcc: fatal error: fail to compile/link un-instrumented code
```

**Workaround.** `-e -D_DEFAULT_SOURCE` (verified with and without `-L`). Our pipeline is not
affected today. It builds with `e-acsl-gcc -G clang` ([`../../scripts/run_eacsl_fuzz.py`](../../scripts/run_eacsl_fuzz.py)),
where Issue 10 drops `-std=c99`. Once Issue 10 is fixed upstream, the pipeline will need
`-D_DEFAULT_SOURCE` in its backend flags unless Issue 12 is fixed in the same release.

**Proposed fix (validated).** `-std=c99 -D_DEFAULT_SOURCE` in `CFLAGS`. Patch and results:
[frama-c-eacsl-gcc-default-source.md](frama-c-eacsl-gcc-default-source.md).

**Not investigated.** On the same build, `fileno(stdin)` under `-L` fails the libc precondition
`\valid(stream)` at runtime. That may be a separate E-ACSL/libc-model issue, and it is not part of
the Issue 12 draft.

---

## Issue 13: formal parameters are registered in shadow memory but never marked initialized

**Status in Frama-C 35.** **Present**, also in `34.0~~dev (Selenium)`. It is
[#177](https://git.frama-c.com/pub/frama-c/-/work_items/177) (2017, Toyota ITC `uninit_var.c` case
012). A maintainer closed #177 in 2022 with "The assertion does not fail anymore". Its own program
fails again on 34 and 35, with gcc and clang, with and without `-M`. Same family as
[Issue 8](#issue-8-__gen_e_acsl_fn-wrapper-leaves-__retres-uninitialized-under--rte-initialized).

**Observed.** Every tracked formal gets `__e_acsl_store_block((void *)(& p), sizeof(p));` at function
entry, but never `__e_acsl_full_init`. Any `\initialized` check on a field of a by-value struct
parameter therefore fails on every call. That covers a user `assert` or `requires`, with no option,
and the RTE guard under `-rte -rte-initialized`. A scalar formal read through a pointer
(`int *pk = &k; return *pk;`) fails E-ACSL's own `\initialized(pk)` check, even after `k = 7;`. The
assertion is blocking and usually sits at the function's first statement. In QCBOR run-5 it caused
13 of 29 false crash candidates.

**Root cause** (`master`). `inject_in_stmt` (`plugins/e-acsl/src/code_generator/injector.ml:470`)
stores the formals with `Memory_observer.store`, which emits `__e_acsl_store_block` only. The rest
of E-ACSL assumes formals are initialized:

- `add_initializer` (`injector.ml:161-168`) skips assignments to a whole formal.
- `needs_guard` (`rte_analysis.ml:493-501`) skips guards on reads of a whole formal.

Field reads and pointer reads do consult shadow memory, where the formal was never marked
initialized. Globals were fixed for the same reason in 2014 (#975): `global_observer.ml:138` emits
`store_block` and then `full_init`.

**Expected.** No false failure on a correct call.

**Reproducer** (verified on 35 and 34; #177's program).

```c
/* i177.c */
struct S1 { int t; };
int foo(struct S1 s) {
  /*@assert \initialized(&s.t); */
  if (s.t > 0) return 0;
  return 1;
}
int main(int argc, const char **argv) {
  struct S1 s;
  s.t = 1;
  foo(s);
  return 0;
}
```
```sh
e-acsl-gcc -G clang -o i.c -O i i177.c
./i.e-acsl    # Assertion failed: \initialized(&s.t), exit 134
```

**Workaround.** [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py)
(`mark_formals_initialized`) post-processes the instrumented C between `e-acsl-gcc -n` and `-C`. It
inserts `__e_acsl_full_init((void *)(& p));` after each formal's first `__e_acsl_store_block`. The
build report counts the formals it patched in `compile.formal_inits`.

**Proposed fix (validated).** A new `Memory_observer.store_formals` emits `__e_acsl_store_block`
followed by `__e_acsl_full_init` for each tracked formal, as `global_observer.ml` does for globals.
The cost is that a struct passed with an uninitialized member is no longer reported when the callee
reads that member. Today that check fails on every call anyway. A scalar argument is still checked
at the call site. A more precise variant, which copies the argument's initialization state the way
temporal analysis passes its per-parameter metadata, is described but not implemented. Patch and
results: [frama-c-eacsl-formal-params-initialized.md](frama-c-eacsl-formal-params-initialized.md).

---

## Validation of the proposed fixes

All eight patches, applied together to `master` `ad24dca`, were built in a throwaway copy of
`framac-analysis:latest` (`dune build` and install over the image's switch). Each draft's diff
also applies on its own to pristine `ad24dca`.

| Check | Result |
|---|---|
| Every reproducer above, before and after | Each issue fixed; results in each draft's validation table |
| Regression guards: joined long options, `-X`, `--oexec-e-acsl`, `--zone-sizes`, `-D`, no input file (Issue 1); a genuine uninitialized read (Issue 8); `Call`-form variadic printing (Issue 3); a `strchr` control (Issue 4) | unchanged |
| ptests, default configuration: `tests/variadic` (69 results), `tests/libc` (121), `tests/pretty_printing` (8), `plugins/rte/tests` (87), `plugins/e-acsl/tests` (197) | only 4 diffs, all in `tests/variadic/known` (`open.0`, `ioctl.0`, `fcntl.0`, `printf_garbled_mix.0`), each a `Local_init` line now printed as `fn(...); /* generated */`, as intended by Issue 3 |
| ptests, E-ACSL `dev` configuration (`dune build @plugins/e-acsl/tests/ptests_config_dev`): 195 tests, each compiled by the patched `e-acsl-gcc` and run | all match `oracle_dev` (exit 0) |

The E-ACSL test suite compiles with gcc, so the clang branch (Issue 10) is covered only by the
reproducers.

Issue 13 came later. Its patch was validated on its own against `ad24dca`, and then together with
Issue 8's:

| Check | Result |
|---|---|
| Issue 13 reproducers, before and after | fixed; results in the draft's validation table |
| Regression guards: an uninitialized local, an uninitialized scalar argument | still reported |
| ptests `plugins/e-acsl/tests`, default configuration (197 results) | 57 `gen_*.c` oracle changes, each only adding `__e_acsl_full_init((void *)(& <formal>));` after the formal's `__e_acsl_store_block` (210 lines added, none removed) |
| ptests, E-ACSL `dev` configuration (195 tests) | all match `oracle_dev` |
| Issues 8 and 13 together | both apply cleanly; each reproducer runs clean; both regression guards still report |

---

# Not filed upstream

## Issue 2: `-O <name>` builds both a plain and an instrumented executable (`<name>.e-acsl`), while `-X` and `--oexec-e-acsl` are omitted from `-h`

**Status in Frama-C 35.** Unchanged. **Not a bug.** `e-acsl-gcc -h` shows
`-O <file>  output the generated executables to <file> [a.out, a.out.e-acsl]` and ends with
"This help page shows only basic options. See man (1) e-acsl-gcc for full up-to-date
documentation". The man page documents `-X, --instrumented-only` and
`--oexec-e-acsl=<FILE>`. The only real defect is the man-page wording, which is mentioned under
Issue 10. With `-O t`, the plain `t` has 0 `__e_acsl_` symbols and `t.e-acsl` has 103; with
`-X --oexec-e-acsl t_inst`, only `t_inst` is built.

**Our handling.** We instrument in one call (`-n -o instrumented.c`), compile with `-C` in a
second call, pick `<out>.e-acsl` when it exists, and refuse any executable without E-ACSL symbols.

## Issue 6: RTL crash reports without a target source location in the segment model (`unsafe_initialize`)

**Status in Frama-C 35.** Unchanged in the default build:
`e_acsl_segment_tracking.c:1018: Use of invalid address 0x1000 in unsafe_initialize`. This
happens with `-M` alone, or with `-rte -rte-select main -e-acsl-functions main` when the write sits
in an unselected helper. With `-rte` on that helper, the `\valid(p)` assertion fires first and
gives `bad_write.c:1`. **Not filed.** The RTL already answers this: built with `--rt-debug` (`-D`)
under gcc, the same failure prints

```
/** Backtrace **************************/
trace at e_acsl_trace.c:73
 - raise_abort at e_acsl_private_assert.c:26
 - private_assert_fail at e_acsl_private_assert.c:57
 - unsafe_initialize at e_acsl_segment_tracking.c:1019
 - __e_acsl_initialize at e_acsl_segment_observation_model.c:110
 - write_ptr at bwg.inst.c:216
 - main at bwg.inst.c:227
```

That names the target function, with lines in the instrumented file. Under `-G clang`, the
backtrace is empty because of Issue 10.

**Our handling.** [`../../scripts/run_eacsl_fuzz.py`](../../scripts/run_eacsl_fuzz.py)
(`needs_attribution`) replays inputs that crash in RTL-internal functions (`unsafe_*`,
`__e_acsl_*`) on a Clang `ASan + UBSan` build of the same slice, which gives the original
`file:line`. A `-O0` debug RTL is too slow to fuzz with.

## Issue 7 (feature request): unknown names in `-rte-select` / `-e-acsl-functions` abort the run

**Status in Frama-C 35.** Unchanged. **Not filed.** WP treats `-wp-fct` the same way
(`[wp] User Error: incorrect argument for option -wp-fct (no function 'nonexistent_fn')`), so a
missing function in a selection option is a deliberate, consistent user error across plugins, not
an E-ACSL/RTE defect.

```sh
frama-c -machdep gcc_x86_64 -rte -rte-select nonexistent_fn t2.c
frama-c -machdep gcc_x86_64 -e-acsl -e-acsl-functions nonexistent_fn t2.c
frama-c -wp -wp-fct nonexistent_fn t2.c
```

**Our handling.** [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py)
(`preprocess_source`, `parse_missing_functions`) computes the function list from `clang -E`
output. On `no function 'X'`, it drops the missing names and retries Stage 1 once.

## Issue 11: kernel/RTE/ACSL behaviour changes in 34 (notes, not an issue)

Changes picked up when moving to `34.0~~dev (Selenium)`. All of them still hold on 35:

- RTE option hooks were fixed: per-function `-rte-initialized=@all,-f` now works for `static`
  functions.
- The missing unsequenced-effect warning in local definitions was fixed (#@1219, UB CC.35).
- The implicit array-to-pointer conversion was removed in comparisons.
- Empty named behaviors (`behavior b: ;`) are now a fatal annot-error.
- `terminates`/`decreases` may sit anywhere between `requires` and `behavior`.
- GCC `mode(...)` attributes are partially supported.

`acsl_ast.py` rejects empty behaviors before splicing, and `kernel_ast_dump.ml` matches array
operands in comparisons. Cache keys hash `frama-c -version`, so all caches invalidate on upgrade.
See `docs/troubleshooting.md` §0.
