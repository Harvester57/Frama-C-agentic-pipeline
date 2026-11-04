# E-ACSL / `e-acsl-gcc` issues found while fuzzing a production codebase (Frama-C 33 & 34 reassessment)

Upstream report from the Frama-C agentic verification pipeline. Each section below stands on its
own, so it can be filed as a separate issue on the Frama-C tracker
(https://git.frama-c.com/pub/frama-c/-/issues). Every section gives the Frama-C 34 reassessment
status, the observed behaviour, the expected behaviour, a minimal standalone reproducer verified
in the `framac-pipeline:latest` container, the workaround we use, and a suggested fix.

> [!NOTE]
> Issues 1-8 were originally discovered during a campaign on a C code base (9 module slices,
> LibFuzzer harnesses) with Frama-C 33.0 and have been reassessed against **Frama-C `34.0~~dev (Selenium)`**
> in the `framac-pipeline:latest` container. All reproducers below (including Issues 5 and 6,
> which were previously marked *to be minimized*) are now standalone C programs verified on
> Frama-C 34. Issues 9 and 10 document two additional bugs uncovered in Frama-C 34 / `e-acsl-gcc`
> during the reassessment. Script line numbers refer to `/home/opam/.opam/5.5/bin/e-acsl-gcc`
> installed with Frama-C `34.0~~dev (Selenium)`.

## Environment

| Component | Original Baseline (Frama-C 33) | Reassessed Container (Frama-C 34) |
|---|---|---|
| Frama-C | 33.0 (opam), `e-acsl-gcc` short-option CLI | `34.0~~dev (Selenium)` (opam 5.5), `/home/opam/.opam/5.5/bin/e-acsl-gcc` |
| OS / libc | Ubuntu 24.04, glibc 2.39 | Debian GNU/Linux 13 (trixie), glibc 2.41 (`Debian GLIBC 2.41-12+deb13u4`) |
| Compiler | Ubuntu 24.04 `clang`, used via `-G clang` | `Debian clang version 19.1.7 (3+b1)`, used via `-G clang` |
| Mode | host-header mode (the script's default `-no-frama-c-stdlib`), `-fsanitize=fuzzer` | host-header mode (`-no-frama-c-stdlib`), `-fsanitize=fuzzer` |

---

## Issue 1: values of `-e` / `-E` / `-l` / `-F` are split on whitespace, and a standalone `-g` triggers `--gmp` and shifts positional arguments

**Status in Frama-C 34.** **Still present (reconfirmed).**

**Observed.** After running `getopt` and `eval set -- "$ARGS"` (lines 431-439), `e-acsl-gcc`
iterates over options with an unquoted `for i in $@` loop (line 442) and no `--) shift; break ;;`
branch before the final `shift;` at line 814. Because `$@` is unquoted in `for i in $@`, the shell
splits every option value (`-e`, `-E`, `-F`, `-l`, `-o`, `-O`, etc.) on `IFS` whitespace and tests
each word against `case "$i" in`.

When `-e` contains a standalone `-g` token, `case "$i" in` matches `-g|--gmp)` (lines 578-580):

```sh
    # Use GMP everywhere
    -g|--gmp)
      shift;
      OPTION_GMP="-e-acsl-O-gmp-only"
    ;;
```

(In Frama-C 34, `-e-acsl-gmp-only` was renamed to `-e-acsl-O-gmp-only`; the old flag is a
deprecated alias.) Because `-g|--gmp)` both sets `OPTION_GMP="-e-acsl-O-gmp-only"` and executes
an extra `shift;` against `$@`, it causes two severe failure modes:

1. **Positional argument desynchronization (`no input files` or corrupted `-o`/`-O` targets):**
   In a single-file invocation where `-e "-g -O1"` precedes `-o` and `-O`, the extra `shift;`
   inside `-g|--gmp)` shifts `-o` off `$@`; when the loop later visits `i=-o` and `i=-O`, each
   consumes the next flag token, and line 814's `shift;` shifts away the sole input file `t.c`,
   aborting with:
   ```
   e-acsl-gcc: fatal error: no input files
   ```
2. **Silent `--gmp` activation and silent loss of the first input file on multi-file builds:**
   In a multi-file invocation (such as a harness plus target slice `t1.c t2.c`) where `-e "-g -O1"`
   follows `-o`, the extra `shift;` consumes `--` inside the loop, line 814's `shift;` **silently
   drops the first input file (`t1.c`)**, and Frama-C instruments only `t2.c` with
   `-e-acsl-O-gmp-only` enabled.

**Expected.** Option arguments passed to `-e`, `-E`, `-F`, and `-l` are never re-parsed as
`e-acsl-gcc` script options or allowed to shift the positional parameter stack.

**Reproducer.**

```sh
cat > t1.c <<'EOF'
int helper(int x) { return x + 1; }
EOF
cat > t2.c <<'EOF'
int main(void) { return 0; }
EOF

# 1. Single-file invocation with -e "-g -O1" before -o/-O:
#    aborts with "e-acsl-gcc: fatal error: no input files" because -g triggers an extra shift.
e-acsl-gcc -G clang -F "-rte -machdep gcc_x86_64" -e "-g -O1" -o t.instrumented.c -O t t2.c

# 2. Multi-file invocation with -e "-g -O1":
#    silently drops t1.c AND passes -e-acsl-O-gmp-only to Frama-C!
e-acsl-gcc -n -G clang -o t.instrumented.c -e "-g -O1" t1.c t2.c
grep -c helper t.instrumented.c   # prints 0 (t1.c was silently dropped)

# Compare with -e "-gline-tables-only -O1", which preserves both files and does not enable GMP.
e-acsl-gcc -n -G clang -o t.instrumented.c -e "-gline-tables-only -O1" t1.c t2.c
grep -c helper t.instrumented.c   # prints > 0
```

**Related consequences of the same `for i in $@` splitting:**
- include paths containing spaces cannot be passed through `-E`/`-e`;
- separated forms such as `-e "-I inc -O1"` or `-l "-L dir -lm"` produce standalone `-I` / `-L` /
  `-l` tokens that match script options (`-I|--frama-c`, `-L|--frama-c-stdlib`, `-l|--ld-flags`),
  corrupting options and shifting away input files.

**Workaround in our pipeline.** [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py) (`normalize_passthrough`)
rewrites `-g` to `-gline-tables-only`, joins `-I dir` into `-Idir`, and rejects any other
standalone single-letter token or whitespace-containing path before calling `e-acsl-gcc`.

**Suggested fix.** Replace `for i in $@` (line 442) with `while [ $# -gt 0 ]; do case "$1" in`
and add an explicit `--) shift; break ;;` branch. In a `while [ $# -gt 0 ]` loop inspecting `$1`,
each option handler shifts its own flag and argument (`shift 2`), so tokens inside `$1`'s value
are never visited by the outer `case`.

---

## Issue 2: `-O <name>` builds both a plain and an instrumented executable (`<name>.e-acsl`), while `-X` and `--oexec-e-acsl` are omitted from `-h`

**Status in Frama-C 34.** **Options exist (`-X` / `--instrumented-only` and `--oexec-e-acsl`),
but default `-O` behaviour and `-h` help omission remain unchanged.**

**Observed.** With `-O out`, `e-acsl-gcc` compiles the original sources to `out` and the
instrumented code to `out.e-acsl` (`EACSL_OUTPUT_EXEC="$OPTION_OUTPUT_EXEC.e-acsl"`, lines
1018-1022). An integration that assumes `-O out` writes the instrumented binary to `out` ends up
running or fuzzing the uninstrumented executable, and for main-less LibFuzzer harnesses without
`-fsanitize=fuzzer` on the plain link (or where the plain build fails on its own), the plain build
at lines 1085-1088 aborts the command even though instrumentation succeeded.

Reassessment of `/home/opam/.opam/5.5/bin/e-acsl-gcc` in Frama-C 34 confirms that two long/short
options already address the build mechanics, although neither is listed in `e-acsl-gcc -h`
(`manpage()`, lines 399-428):
- `--oexec-e-acsl <file>` (lines 526-530) sets `OPTION_EACSL_OUTPUT_EXEC="$1"`, naming the
  instrumented executable explicitly instead of `<out>.e-acsl`.
- `-X` / `--instrumented-only` (lines 563-566, checked at line 1085) skips compiling the original
  uninstrumented source file while still compiling the instrumented executable. (By contrast, `-n`
  / `--no-compile` at lines 487-490 disables compilation of *both* the plain and the instrumented
  executables.)

**Expected.**
1. Surface `-X` (`--instrumented-only`) and `--oexec-e-acsl <file>` in `e-acsl-gcc -h` alongside
   `-o` and `-O`.
2. Print a summary message or echo the final instrumented output binary path when `-q` is not set.

**Reproducer.**

```sh
e-acsl-gcc -G clang -e "-O1" -o t.instrumented.c -O t t2.c && ls -l t t.e-acsl
nm t | grep -c __e_acsl_ ; nm t.e-acsl | grep -c __e_acsl_   # 0 vs > 0

# Using -X and --oexec-e-acsl builds only the named instrumented binary:
e-acsl-gcc -G clang -X --oexec-e-acsl t_inst -e "-O1" -o t.instrumented.c t2.c && ls -l t_inst
```

**Workaround.** We instrument in one call (`-n -o instrumented.c`), compile with `-C` in a second
call, select `<out>.e-acsl` when it exists, and refuse any executable that has no E-ACSL symbols.

---

## Issue 3: host-header mode emits `<fn>_fallback_<N>` calls for variadic functions in declaration initializers that nothing defines (link failure)

**Status in Frama-C 34.** **Partially fixed for ordinary `Call` statements; still broken for
local variable declaration initializers (`Local_init` / `ConsInit`).**

**Observed.** In host-header mode (`-no-frama-c-stdlib`, hardcoded at line 359 of `e-acsl-gcc`),
a variadic libc call without a Frama-C specification is translated by the Variadic plugin into a
call to `open_fallback_1`, `open_fallback_2`, ... and a prototype `int open_fallback_1(...);` is
emitted into the instrumented file.

In **Frama-C 34**, the CIL printer was partially updated:
- When the call is an ordinary CIL `Call` instruction (for example `fd = open("/dev/null", O_RDONLY, 0);`,
  or `int fd = open(argc > 1 ? argv[1] : "/dev/null", O_RDONLY, 0);` where CIL lowers the ternary
  `?:` into an `if/else` followed by a `Call` instruction `tmp_0 = open(tmp, 00, 0);`), the printer
  now restores the original variadic function name and emits the fallback name only as a comment:
  ```c
  int open_fallback_1(char const *__file, int __oflag, int param0);
  ...
  tmp_0 = open(tmp,00,0); /* open_fallback_1 */
  ```
- **However**, when the variadic call is the initializer of a local variable declaration without
  control-flow lowering (for example `int fd = open("/dev/null", O_RDONLY, 0);` or
  `int fd = open(path, O_RDONLY, 0);`, which CIL represents as
  `Local_init(fd, ConsInit(open_fallback_1, args, Plain_func))`), the printer does **not** restore
  the original function name and still emits:
  ```c
  int fd = open_fallback_1("/dev/null",00,0);
  ```
  Because `open_fallback_1` is declared in the instrumented file but defined neither there nor in
  the E-ACSL RTL, linking still fails:
  ```
  /usr/bin/ld: ...: undefined reference to `open_fallback_1'
  clang: error: linker command failed with exit code 1
  ```

**Expected.** Instrumented code links in the default host-header mode regardless of whether the
variadic call appears in a statement (`Instr(Call(...))`) or a variable initializer
(`Local_init(..., ConsInit(...))`). Applying the same variadic fallback printer rewrite to
`ConsInit` in `Cil_printer` (or passing `-variadic-no-translation` in host-header mode) resolves
the link failure completely.

**Reproducer.**

```sh
cat > v.c <<'EOF'
#include <fcntl.h>
#include <unistd.h>
int main(void) {
  int fd = open("/dev/null", O_RDONLY, 0);
  if (fd >= 0) close(fd);
  return 0;
}
EOF
e-acsl-gcc -G clang -o v.instrumented.c -O v v.c
grep -n "_fallback_" v.instrumented.c
```

Output on Frama-C `34.0~~dev (Selenium)`:
```
/usr/bin/ld: /tmp/v-...o: in function `main':
v.instrumented.c:(.text+0x2c): undefined reference to `open_fallback_1'
clang: error: linker command failed with exit code 1 (use -v to see invocation)
e-acsl-gcc: fatal error: fail to compile/link instrumented code
203:int open_fallback_1(char const *__file, int __oflag, int param0);
209:  int fd = open_fallback_1("/dev/null",00,0);
```

**Workaround.** After instrumentation, [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py)
(`find_variadic_fallbacks`, `build_fallback_object`) parses the fallback prototypes from the
instrumented file when linking fails on `<fn>_fallback_<N>` and generates a link-only object
(`eacsl_fallbacks.o`) that forwards each fallback to the real function (`open`, `fcntl`, `ioctl`,
...) or sets `errno = ENOSYS` when the base function is unknown. These definitions must not go into
the instrumented sources: adding a definition shifts the `_N` numbering at the call sites.

---

## Issue 4: Frama-C libc mode (`-L`) aborts on libc contracts containing unbounded ranges (`unbounded ranges are not part of E-ACSl`)

**Status in Frama-C 34.** **Improved for functions whose unbounded ranges appear only in `assigns`
clauses (such as `strchr`), which now warn and succeed; still aborts on Frama-C libc functions
whose `requires` or `ensures` clauses contain unbounded ranges `(0..)` (`strtok_r`, `getsockopt`,
`wcschr`).**

**Observed.** Switching to Frama-C's libc (`-L` / `--frama-c-stdlib`) to avoid host-header
problems aborts instrumentation whenever the program calls a libc function whose Frama-C stdlib
`requires` or `ensures` contract uses an unbounded range `(0..)`.

In Frama-C `34.0~~dev (Selenium)`:
- Because `e-acsl-gcc` passes `-keep-unused-functions none` (line 998) and E-ACSL ignores
  `assigns` clauses with a warning (`Warning: E-ACSL construct 'assigns clause' is not yet supported. Ignoring annotation.`),
  programs that only call `strchr` now succeed under `e-acsl-gcc -L`.
- However, three specifications in `FRAMAC_SHARE/libc/` still use `(0..)` inside `requires` or
  `ensures` clauses:
  1. `FRAMAC_SHARE/libc/string.h:352-355` (`strtok_r`):
     `requires separation: \separated(delim+(0..strlen(delim)), s+(0..strlen(s)), *saveptr+(0..));`
  2. `FRAMAC_SHARE/libc/sys/socket.h:398` (`getsockopt`):
     `optval == \null || \valid(((char*)optval)+(0..));`
  3. `FRAMAC_SHARE/libc/wchar.h:110` (`wcschr`):
     `\result == \null || \subset(\result, wcs+(0..));`

Calling any of these functions under `-L` aborts Frama-C with a fatal user error instead of
ignoring the unsupported clause with a warning:

```
[e-acsl] FRAMAC_SHARE/libc/string.h:352: User Error: 
  unbounded ranges are not part of E-ACSl
[kernel] Plug-in e-acsl aborted: invalid user input.
```

**Expected.** The libc specifications shipped with Frama-C are accepted by E-ACSL, or E-ACSL
ignores (with a warning) specification clauses containing unbounded ranges, just as it already
ignores unsupported `assigns` clauses, read-performing logic predicates, and non-integer
quantifications in `FRAMAC_SHARE/libc/string.h`.

**Reproducer.**

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

**Impact.** Any target slice that calls `strtok_r`, `getsockopt`, or `wcschr` (or includes headers
unavailable in Frama-C's stdlib) must use host-header mode (`-no-frama-c-stdlib`).

---

## Issue 5: E-ACSL and RteGen emit `alignof` / `sizeof` on incomplete (opaque) struct types

**Status in Frama-C 34.** **Still present (reconfirmed) and minimized to a standalone reproducer.**

**Observed.** In Frama-C 34, E-ACSL's internal RTE guard generator (`-e-acsl-O-rte`) checks whether
a pointee type is complete before creating its own alignment guard and emits a warning:

```
[e-acsl] Warning: cannot create the pointer alignment guard of p because void is an incomplete type
```

However, two common patterns with library opaque handle types (such as json-c
`typedef struct json_object json_object;`, used only through pointers) still emit `_Alignof` or
`sizeof` on the incomplete struct type in Frama-C 34, producing instrumented C that fails to
compile:

1. **Pointer cast with `-rte` (`-warn-unaligned-pointer`, enabled by default in Frama-C):**
   Casting `void *` or `char *` to `json_object *` causes RteGen (`-rte`) to emit
   `/*@ assert rte: pointer_alignment: \aligned(p, alignof(json_object)); */` without checking
   whether `json_object` is complete. E-ACSL then translates that assertion into
   `__e_acsl_aligned(p, _Alignof(json_object))`, which fails to compile:
   ```
   opaque_cast.inst.c:322:47: error: invalid application of 'alignof' to an incomplete type 'json_object' (aka 'struct json_object')
   ```
2. **ACSL `\valid` / `\valid_read` contract on an opaque pointer:**
   An ACSL precondition `/*@ requires obj == \null || \valid_read(obj); */` on `const json_object *obj`
   is translated by E-ACSL into `__e_acsl_valid_read((void *)obj, sizeof(json_object const), ...)`,
   which fails to compile:
   ```
   opaque_valid.inst.c:378:53: error: invalid application of 'sizeof' to an incomplete type 'const json_object' (aka 'const struct json_object')
   ```

**Expected.**
- RteGen (`-rte` under `-warn-unaligned-pointer`) should not emit `\aligned(p, alignof(T))` when
  `T` is an incomplete type, and E-ACSL should skip `alignof(T)` on incomplete types with a warning
  (matching the check E-ACSL 34 already performs for its internal alignment guards).
- For `\valid(p)` / `\valid_read(p)` on a pointer to an incomplete type, E-ACSL should either warn
  and skip the annotation or degrade the check to 1-byte / non-null address validity rather than
  emitting uncompilable `sizeof(T)`.

**Reproducer.**

```sh
cat > opaque_cast.c <<'EOF'
typedef struct json_object json_object;

json_object *from_void(void *p) {
  return (json_object *)p;
}

int main(void) {
  return from_void(0) != 0;
}
EOF
e-acsl-gcc -G clang -F "-rte -machdep gcc_x86_64" -o opaque_cast.inst.c -O opaque_cast opaque_cast.c
```

**Workaround.** In our header stubs ([`../../templates/fc_stubs/json-c/json.h`](../../templates/fc_stubs/json-c/json.h)),
opaque handles are given a complete dummy definition (`struct json_object { int _fc_opaque; };`).
This is sound only when the target code under analysis never allocates or dereferences the opaque
struct directly.

---

## Issue 6: RTL crash reports without a target source location in the segment model (`unsafe_initialize`)

**Status in Frama-C 34.** **Still present (reconfirmed) and minimized to a standalone reproducer.**

**Observed.** Before every memory write `*p = ...;` in an instrumented function, E-ACSL emits
`__e_acsl_initialize((void *)p, sizeof(*p));`, which calls `unsafe_initialize(ptr, n)` in
`FRAMAC_SHARE/e-acsl/observation_model/segment_model/e_acsl_segment_tracking.c:1016`:

```c
void unsafe_initialize(void *ptr, size_t n) {
  TRY_SEGMENT((uintptr_t)ptr, initialize_heap_region((uintptr_t)ptr, n),
              initialize_static_region((uintptr_t)ptr, n))
}
```

When `p` holds an invalid address (outside tracked heap and static/stack segments) and the write is
not preceded by an active `-rte` `\valid(p)` assertion (for example, when `-rte` is not used, or
when `-rte-select` / `-e-acsl-functions` restricts assertion checking to a subset of entry
functions while E-ACSL still instruments memory writes in helper functions to keep shadow memory
coherent), `TRY_SEGMENT` (`e_acsl_segment_tracking.h:295-299`) aborts inside the RTL:

```
/home/opam/.opam/5.5/bin/../share/frama-c/share/e-acsl/observation_model/segment_model/e_acsl_segment_tracking.c:1018: Use of invalid address 0x1000 in unsafe_initialize
Aborted (core dumped)
```

Because `private_assert` only prints `e_acsl_segment_tracking.c:1018` and `__func__`
(`unsafe_initialize`), the crash report contains no target source file, function name, or line
number.

**Expected.** Either `__e_acsl_initialize` accepts source location metadata (or records the last
instrumented site in thread-local RTL state) so `TRY_SEGMENT` can report the target `file:line`, or
`TRY_SEGMENT` prints a stack trace / target caller context before aborting.

**Reproducer.**

```sh
cat > bad_write.c <<'EOF'
void write_ptr(int *p) { *p = 42; }
int main(void) { write_ptr((int *)0x1000); return 0; }
EOF

# Either without -rte, or with -rte-select/-e-acsl-functions excluding the helper:
e-acsl-gcc -G clang -M -F "-rte -rte-select main -e-acsl-functions main" -o bw.inst.c -O bw bad_write.c
./bw.e-acsl
```

**Workaround.** When [`../../scripts/run_eacsl_fuzz.py`](../../scripts/run_eacsl_fuzz.py) (`needs_attribution`)
sees a crash attributed to an RTL-internal function (`unsafe_*`, `__e_acsl_*`), it automatically
replays the crashing input on a Clang `ASan + UBSan` build of the same slice to recover the target
`file:line`.

---

## Issue 7 (feature request): unknown names in `-rte-select` / `-e-acsl-functions` abort the run

**Status in Frama-C 34.** **Still present (reconfirmed).**

**Observed.** If a function named in `-rte-select` or `-e-acsl-functions` is absent from the
parsed AST (for example because it is excluded by `#if`), Frama-C 34 aborts with a fatal user
error:

```
[rte] User Error: incorrect argument for option -rte-select (no function 'nonexistent_fn').
[kernel] Plug-in rte aborted: invalid user input.
```
```
[e-acsl] User Error: incorrect argument for option -e-acsl-functions
  (no function 'nonexistent_fn').
[kernel] Plug-in e-acsl aborted: invalid user input.
```

For selection options on multi-configuration code bases, a fatal abort is stricter than needed.

**Expected.** A warning (`function 'X' not found, ignored`), or a `-warn-key` category allowing
users to downgrade unknown function names in selection lists to a warning.

**Reproducer.**

```sh
frama-c -machdep gcc_x86_64 -rte -rte-select nonexistent_fn t2.c
frama-c -machdep gcc_x86_64 -e-acsl -e-acsl-functions nonexistent_fn t2.c
```

**Workaround.** [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py) (`preprocess_source`,
`parse_missing_functions`) computes the function list from `clang -E` preprocessed sources, and on
`no function 'X'` drops the missing names and retries Stage 1 once.

---

## Issue 8: `__gen_e_acsl_<fn>` wrapper leaves `__retres` uninitialized under `-rte-initialized`

**Status in Frama-C 34.** **Partially mitigated for scalar `\result` postconditions; still present
in wrapper codegen and still aborts at runtime when `ensures` reads a struct/union member of
`\result` (e.g. `\result.a`).**

**Observed.** When a function carries a contract and is instrumented with `-e-acsl-full-mtracking`
(`-M`), E-ACSL generates a wrapper `__gen_e_acsl_<fn>` that declares a return temporary
(`__retres`), registers it in shadow memory with `__e_acsl_store_block((void *)(& __retres), ...)`,
checks `requires`, calls `__retres = <fn>(...);`, and checks `ensures` before returning `__retres`.

Inside `<fn>` itself, E-ACSL emits `__e_acsl_full_init((void *)(& __retres));` before assigning
`__retres`. Inside the generated wrapper `__gen_e_acsl_<fn>`, however, E-ACSL **never** calls
`__e_acsl_full_init((void *)(& __retres));` or
`__e_acsl_initialize((void *)(& __retres), sizeof(__retres));` after `__retres = <fn>(...);`.

In **Frama-C 34**:
- For a **scalar** return type (`int id_nonneg(int x)` with `ensures \result >= 0;`), E-ACSL 34's
  specification RTE pass no longer emits an `__e_acsl_initialized(&__retres, ...)` check on a
  direct scalar read of `\result`, so scalar postconditions no longer abort at runtime even though
  `__retres` remains uninitialized in shadow memory inside `__gen_e_acsl_<fn>`.
- For a **struct or union** return type whose `ensures` clause reads a field of `\result` (for
  example `struct S { int a; };` with `ensures \result.a == x;`), under
  `-rte -rte-initialized @all -e-acsl-full-mtracking`, E-ACSL 34 emits an `E-ACSL RTE`
  initialization guard on `&__retres.a`:
  ```c
  __retres = make_s(x);
  {
    int __gen_e_acsl_initialized;
    ...
    __gen_e_acsl_initialized = __e_acsl_initialized((void *)(& __retres.a), sizeof(int));
    ...
    __e_acsl_assert(__gen_e_acsl_initialized, & __gen_e_acsl_assert_data_3);
  ```
  Because `__retres = make_s(x);` was never recorded as initialized in shadow memory, every call to
  `make_s` aborts at runtime with a false-positive `E-ACSL RTE` failure:
  ```
  struct_repro.c: In function 'make_s'
  struct_repro.c:4: Error: E-ACSL RTE failed:
  	The failing predicate is:
  	uninitialized:
  		\initialized(&\result.a).
  	With values at failure point:
  	- uninitialized: \initialized(&\result.a): 0
  	- sizeof(int): 4
  	- &\result.a: 0x7ffc...
  Aborted (core dumped)
  ```

**Expected.** Whenever `__gen_e_acsl_<fn>` registers `__retres` via `__e_acsl_store_block`, E-ACSL
should emit `__e_acsl_full_init((void *)(& __retres));` alongside `__retres = <fn>(...);` (just as
it already does for assignments to `__retres` inside `<fn>` and for `tmp = __gen_e_acsl_<fn>(...);`
in callers).

**Reproducer.**

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
e-acsl-gcc -G clang -F "-rte -machdep gcc_x86_64 -e-acsl-full-mtracking -rte-initialized @all" \
  -o struct_inst.c -O struct_bin struct_repro.c
./struct_bin.e-acsl
```

**Workaround.** [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py) (`mark_wrapper_results_initialized`)
post-processes `instrumented.c` to insert
`__e_acsl_initialize((void *)(& __retres), sizeof(__retres));` immediately after
`__retres = <fn>(...);` in any `__gen_e_acsl_*` wrapper that registered `__retres` with
`__e_acsl_store_block`. (Note: under `-keep-unused-functions none` with Clang 19, if a translation
unit only uses `__e_acsl_full_init` and Frama-C prunes the declaration of `__e_acsl_initialize`,
either `__e_acsl_full_init((void *)(& __retres));` or a forward declaration of
`__e_acsl_initialize` is required so Clang 19 does not reject the implicit function declaration.)

---

## Issue 9 (new in Frama-C 34): `-e-acsl-assert-print-data` is wired as a deprecated alias for `-e-acsl-O-valid` instead of `-e-acsl-O-print-values`

**Status in Frama-C 34.** **New bug in Frama-C `34.0~~dev (Selenium)`.**

**Observed.** Frama-C 34 reorganized several E-ACSL flags under `-e-acsl-O-*` optimization
controls:
- `-e-acsl-O-print-values` (`O <= 3`, enabled by default at default `O = 2`) replaces
  `-e-acsl-assert-print-data` ("print values of variables involved in a failed verification along
  with the runtime error message"). Indeed, `e-acsl-gcc` lines 742-749 now map
  `--assert-print-data` to `-e-acsl-O-print-values` and `--no-assert-print-data` to
  `-e-acsl-O-no-print-values`.
- `-e-acsl-O-valid` (`O = 0`, disabled by default at `O = 2`) replaces `-e-acsl-valid` ("verify
  annotations which have been proven valid").

However, in the E-ACSL plugin's OCaml option registration, `-e-acsl-assert-print-data` and
`-e-acsl-no-assert-print-data` were accidentally registered as deprecated aliases for
**`-e-acsl-O-valid`** and **`-e-acsl-O-no-valid`** instead of `-e-acsl-O-print-values` and
`-e-acsl-O-no-print-values`:

```
[kernel] Warning: -e-acsl-assert-print-data is a deprecated alias for option -e-acsl-O-valid.
  Please use -e-acsl-O-valid instead.
[kernel] Warning: -e-acsl-no-assert-print-data is a deprecated alias
  for option -e-acsl-O-no-valid. Please use -e-acsl-O-no-valid instead.
```

As a result, any script or Makefile migrating from Frama-C 33 that passes
`-e-acsl-assert-print-data` silently enables `-e-acsl-O-valid` (forcing E-ACSL to instrument
assertions that were already discharged statically by WP or Eva), and passing
`-e-acsl-no-assert-print-data` fails to disable value printing at runtime.

**Expected.** `-e-acsl-assert-print-data` and `-e-acsl-no-assert-print-data` are deprecated aliases
for `-e-acsl-O-print-values` and `-e-acsl-O-no-print-values`.

**Reproducer.**

```sh
cat > valid_test.c <<'EOF'
int main(void) {
  int x = 1;
  /*@ assert x == 1; */
  return 0;
}
EOF

# Proven valid by WP, so E-ACSL skips instrumenting the assert at default O=2 (32 __e_acsl_assert occurrences in headers/RTL):
frama-c -machdep gcc_x86_64 valid_test.c -wp -then -e-acsl -then-last -print | grep -c "__e_acsl_assert"

# Passing -e-acsl-assert-print-data wrongly enables -e-acsl-O-valid and instruments the proven assert (40 occurrences):
frama-c -machdep gcc_x86_64 valid_test.c -wp -then -e-acsl -e-acsl-assert-print-data -then-last -print | grep -c "__e_acsl_assert"
```

**Suggested fix.** In E-ACSL's option registration (`options.ml`), bind the deprecated aliases
`-e-acsl-assert-print-data` / `-e-acsl-no-assert-print-data` to `Print_values`
(`-e-acsl-O-print-values` / `-e-acsl-O-no-print-values`) rather than `Valid` (`-e-acsl-O-valid`).

---

## Issue 10: `e-acsl-gcc -G clang` overwrites `CFLAGS` instead of appending to it

**Status in Frama-C 34.** **Present in Frama-C `34.0~~dev (Selenium)` (`e-acsl-gcc` lines 892-917).**

**Observed.** In `e-acsl-gcc` lines 892-917, `CFLAGS` is initialized with the standard compiler,
architecture, optimization, and warning-suppression flags, and then an `if` block for `clang`
**overwrites** `CFLAGS` instead of appending to `$CFLAGS`:

```sh
CFLAGS="$OPTION_CFLAGS
  -std=c99 $GCCMACHDEP $OPT_CFLAGS
  -fno-builtin -fno-merge-constants
  -Wall \
  -Wno-long-long \
  -Wno-attributes \
  -Wno-nonnull \
  -Wno-undef \
  -Wno-unused \
  -Wno-unused-function \
  -Wno-unused-result \
  -Wno-unused-value \
  -Wno-unused-function \
  -Wno-unused-variable \
  -Wno-unused-but-set-variable \
  -Wno-implicit-function-declaration \
  -Wno-empty-body"

# Disable extra warning for clang
if [ "`basename $CC`" = 'clang' ]; then
  CFLAGS="-Wno-unknown-warning-option \
    -Wno-extra-semi \
    -Wno-tautological-compare \
    -Wno-gnu-empty-struct \
    -Wno-incompatible-pointer-types-discards-qualifiers"
fi
```

When `-G clang` is used, overwriting `CFLAGS` at line 912 silently discards:
- `$OPT_CFLAGS` (`-g -O2` by default, or `-g3 -O0 -fno-omit-frame-pointer` when `-D` / `--rt-debug`
  is requested);
- `$GCCMACHDEP` (`-m64` / `-m32` from `--mbits`);
- `-std=c99 -fno-builtin -fno-merge-constants`;
- all warning suppressions from lines 895-908 (`-Wno-attributes`,
  `-Wno-implicit-function-declaration`, `-Wno-unused-*`). With Clang 19 on Debian 13, dropping
  `-Wno-attributes` (or omitting `-Wno-unknown-attributes`) produces 169
  `warning: unknown attribute '__FC_BUILTIN__' ignored [-Wunknown-attributes]` diagnostics on
  every compile.

**Expected.** The `clang` branch appends to `$CFLAGS` (`CFLAGS="$CFLAGS -Wno-unknown-warning-option ... -Wno-unknown-attributes"`)
rather than replacing it.

**Reproducer.**

```sh
# Compare the compiler invocation echoed by e-acsl-gcc with -G gcc vs -G clang:
e-acsl-gcc -D -G gcc   -o t.inst.c -O t_gcc   t2.c 2>&1 | grep " -o t_gcc"
e-acsl-gcc -D -G clang -o t.inst.c -O t_clang t2.c 2>&1 | grep " -o t_clang"
# With -G gcc:   passes -std=c99 -m64 -g3 -O0 -fno-omit-frame-pointer -fno-builtin -fno-merge-constants ...
# With -G clang: drops all of them and passes only the 5 -Wno-* flags from lines 912-916.
```

**Suggested fix.** Change line 912 of `e-acsl-gcc` from `CFLAGS="-Wno-unknown-warning-option \` to
`CFLAGS="$CFLAGS -Wno-unknown-warning-option -Wno-unknown-attributes \`.

---

## Summary table

| # | Kind | Frama-C 33.0 | Frama-C `34.0~~dev (Selenium)` | Severity for users | Our workaround |
|---|---|---|---|---|---|
| 1 | Bug (`e-acsl-gcc` option parsing) | Present (`-e-acsl-gmp-only`) | **Still present** (`for i in $@` splits values; `-g` enables `-e-acsl-O-gmp-only` and `shift`s positional args / drops first input file) | High: silent semantic change or dropped input file | Argv normalization (`-gline-tables-only`, joined short flags) |
| 2 | Usability / documentation | Present | **Partially addressed** (`-X` and `--oexec-e-acsl` exist in script, but omitted from `-h` and default `-O` unchanged) | High: silently fuzzing an uninstrumented binary | Two-stage build (`-n`, then `-C`), `.e-acsl` selection, instrumentation check |
| 3 | Bug (Variadic in host-header mode) | Present on all variadic calls | **Partially fixed** (`Instr(Call)` now prints `open(...) /* open_fallback_1 */`, but `Local_init` / `ConsInit` `int fd = open(...)` still emits `open_fallback_1(...)` and fails to link) | High: link failure for variadic calls in declaration initializers | Generated link-only forwarding object (`eacsl_fallbacks.o`) |
| 4 | Limitation (Frama-C libc mode `-L`) | Aborts on `<string.h>` | **Improved** (`strchr` now warns and succeeds; still aborts on `strtok_r` at `string.h:352`, `getsockopt` at `sys/socket.h:398`, and `wcschr` at `wchar.h:110`) | Medium: forces host-header mode when those functions or non-stdlib headers are used | Host-header mode (`-no-frama-c-stdlib`) |
| 5 | Bug (opaque struct `alignof`/`sizeof`) | Present | **Still present** (minimized: pointer cast `(json_object *)p` under `-rte` emits `_Alignof(json_object)`; `\valid_read(obj)` emits `sizeof(json_object const)`) | Medium: instrumented C fails to compile | Complete opaque types in header stubs |
| 6 | Diagnostics (RTL `unsafe_initialize`) | Present | **Still present** (minimized: write through invalid pointer in unannotated function aborts at `e_acsl_segment_tracking.c:1018` with no target `file:line`) | Medium: missing crash location | Differential replay on an ASan+UBSan build |
| 7 | Feature request (`-rte-select` / `-e-acsl-functions`) | Present | **Still present** (aborts on unknown function name) | Low | Preprocessed discovery (`clang -E`) and retry |
| 8 | Bug (`__gen_e_acsl_*` wrapper `__retres`) | Aborts on scalar and struct `\result` | **Partially mitigated** (scalar `\result` no longer checked by E-ACSL RTE, but `__retres` is still left uninitialized in shadow memory and **still aborts** on struct/union `\result.field` in `ensures`) | High: false-positive abort on struct-returning contracted functions | Post-process `__gen_e_acsl_*` wrapper `__retres` in `instrumented.c` |
| 9 | Bug (deprecated option alias) | N/A | **New in 34.0~~dev** (`-e-acsl-assert-print-data` is aliased to `-e-acsl-O-valid` instead of `-e-acsl-O-print-values`) | Medium: silently re-instruments assertions already proven valid | Use `-e-acsl-O-print-values` (or default `O=2`) on Frama-C 34+ |
| 10 | Bug (`e-acsl-gcc -G clang` `CFLAGS`) | Present | **Still present** (line 912 overwrites `CFLAGS`, dropping `$OPT_CFLAGS`, `$GCCMACHDEP`, `-std=c99`, `-fno-builtin`, and `-Wno-*`) | Medium: `-D` (`--rt-debug`), `--mbits`, and warning suppressions ignored under `-G clang` | Pass explicit codegen flags via `-e` |
