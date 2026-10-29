# E-ACSL / `e-acsl-gcc` issues found while fuzzing a production codebase (Frama-C 33)

Upstream report from the Frama-C agentic verification pipeline. Each section below stands on its
own, so it can be filed as a separate issue on the Frama-C tracker
(https://git.frama-c.com/pub/frama-c/-/issues). Every section gives the observed behaviour, the
expected behaviour, a minimal reproducer, the workaround we use, and a suggested fix.

> [!NOTE]
> These findings come from a campaign on a proprietary C code base (9 module slices, LibFuzzer
> harnesses). The reproducers below are minimized standalone programs that show the same
> mechanism. Script line numbers refer to the `e-acsl-gcc` script installed with our Frama-C 33
> build and may differ slightly in other builds. Items marked **(to be minimized)** were seen on
> the production code; we have not yet reduced them to a standalone program and will attach one
> on request.

## Environment

| Component | Version |
|---|---|
| Frama-C | 33.0 (opam), `e-acsl-gcc` short-option CLI |
| OS / libc | Ubuntu 24.04, glibc 2.39 |
| Compiler | Ubuntu 24.04 `clang` (fill in from `clang --version` when filing), used via `-G clang` |
| Mode | host-header mode (the script's default `-no-frama-c-stdlib`), `-fsanitize=fuzzer` |

Before filing, fill in the exact versions in the table from `frama-c -version`, `clang --version`
and `ldd --version`.

---

## Issue 1: values of `-e` / `-E` / `-l` are split on whitespace, and a standalone `-g` silently enables `--gmp`

**Observed.** `e-acsl-gcc` splits the value of `-e` (compiler flags) on spaces and re-parses the
tokens. A standalone `-g` token is treated as the script's own `-g`/`--gmp` option (around lines
578-580 in our copy), which adds `-e-acsl-gmp-only`. Nothing is reported to the user. With GMP-only
mode on, instrumentation of ordinary code fails later with errors that do not point at the cause.
On our code base:

```
implicit cast: cannot cast from __e_acsl_mpz_t to size_t
```

at a `strchr` call site.

**Expected.** Either the value of `-e` is passed to the compiler verbatim, or the documentation
states that it is re-parsed and that `-g` inside it means `--gmp`. Ideally a token inside an option
value should never be interpreted as a script option.

**Reproducer.**

```sh
cat > t.c <<'EOF'
#include <stddef.h>
#include <string.h>
size_t f(const char *s) { const char *p = strchr(s, ':'); return p ? (size_t)(p - s) : 0; }
int main(void) { return (int)f("a:b"); }
EOF
# Debug info requested via -e:
e-acsl-gcc -G clang -F "-rte -machdep gcc_x86_64" -e "-g -O1" -o t.instrumented.c -O t t.c
# Compare with the same command using -e "-gline-tables-only -O1".
```

Check whether the Frama-C invocation contains `-e-acsl-gmp-only` (script trace, e.g. `sh -x`, or
verbose output). With `-e "-g -O1"` it does; with `-e "-gline-tables-only -O1"` it does not.

**Related consequences of the same splitting:**
- include paths containing spaces cannot be passed through `-E`/`-e`;
- separated forms such as `-I dir` and `-l lib` become standalone `-I` / `-l` tokens and may
  collide with script options.

**Workaround in our pipeline.** Rewrite `-g` to `-gline-tables-only`, join `-I dir` into `-Idir`,
and refuse any other standalone single-letter token or whitespace-containing path before calling
`e-acsl-gcc`.

**Suggested fix.** Collect `-e`/`-E`/`-l` values into arrays without re-parsing them as script
options (for example with `getopt` long-option handling plus quoted array expansion), or reject
values that contain script options with an explicit error.

---

## Issue 2: `-O <name>` builds both a plain and an instrumented executable; the instrumented one is `<name>.e-acsl`

**Observed.** With `-O out`, the script compiles the original sources to `out` and the
instrumented code to `out.e-acsl` (`EACSL_OUTPUT_EXEC="$OPTION_OUTPUT_EXEC.e-acsl"`, around line
1046 in our copy). Our first integration fuzzed `out`, which has no instrumentation at all. Every
run was then silently "clean", and a dynamic contract check against `out` always passed.

**Expected.** This is documented behaviour, but it is easy to get wrong. Two improvements would
prevent it:
1. an option to name the instrumented executable explicitly, or to skip the plain build (the plain
   build can also fail on its own and abort the whole command even though instrumentation
   succeeded);
2. a final message such as `E-ACSL executable: out.e-acsl`.

**Reproducer.**

```sh
e-acsl-gcc -G clang -e "-O1" -o t.instrumented.c -O t t.c && ls -l t t.e-acsl
nm t | grep -c __e_acsl_ ; nm t.e-acsl | grep -c __e_acsl_   # 0 vs > 0
```

**Workaround.** We instrument in one call (`-o instrumented.c`), compile with `-C` in a second
call, select `<out>.e-acsl` when it exists, and refuse any executable that has no E-ACSL symbols.

---

## Issue 3: host-header mode emits `<fn>_fallback_<N>` calls for variadic functions that nothing defines (link failure)

**Observed.** In host-header mode (`-no-frama-c-stdlib`, hardcoded around line 359 in our copy),
a variadic libc call without a Frama-C specification is translated by the Variadic plugin into a
call to `open_fallback_1`, `open_fallback_2`, ... These symbols are declared in the instrumented
file but defined neither there nor in the E-ACSL RTL, so the link fails:

```
undefined reference to `open_fallback_1'
```

**Expected.** Instrumented code links in the default mode. For example, the fallbacks could be
defined to forward to the real function, the Variadic translation could be skipped for functions
that have no specification in host-header mode, or `e-acsl-gcc` could pass
`-variadic-no-translation` by default in host-header mode.

**Reproducer.**

```sh
cat > v.c <<'EOF'
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  int fd = open(argc > 1 ? argv[1] : "/dev/null", O_RDONLY, 0);
  if (fd >= 0) close(fd);
  return 0;
}
EOF
e-acsl-gcc -G clang -o v.instrumented.c -O v v.c
grep -n "_fallback_" v.instrumented.c
```

**Workaround.** After instrumentation we parse the fallback prototypes from the instrumented file
and generate a link-only object that forwards each fallback to the real function (`open`, `fcntl`,
`ioctl`, ...) or sets `errno = ENOSYS` when the base function is unknown. These definitions must
not go into the instrumented sources: adding a definition shifts the `_N` numbering at the call
sites.

---

## Issue 4: Frama-C libc mode is unusable with E-ACSL (`unbounded ranges are not part of E-ACSL`)

**Observed.** Switching to Frama-C's libc (`-L` / `--frama-c-stdlib`) to avoid host-header
problems aborts instrumentation:

```
share/libc/string.h:352: ... unbounded ranges are not part of E-ACSL
```

**Expected.** The libc specifications shipped with Frama-C are accepted by E-ACSL, or E-ACSL
ignores (with a warning) the specification clauses it cannot translate, as it does for other
unsupported constructs.

**Reproducer.** Any program that includes `<string.h>` and calls one of its functions:

```sh
e-acsl-gcc -L -G clang -o s.instrumented.c -O s t.c
```

**Impact.** Host-header mode is the only way to use E-ACSL on real code, so issues 3 and 5 are
unavoidable today.

---

## Issue 5: E-ACSL emits `alignof` on an incomplete (opaque) struct type (to be minimized)

**Observed.** Instrumenting code that handles a library's opaque handle type (json-c
`typedef struct json_object json_object;`, used only through pointers) produced instrumented C
that does not compile:

```
invalid application of 'alignof' to an incomplete type 'json_object'
```

**Expected.** No `alignof`/`sizeof` is generated for incomplete types (they are never
dereferenced), or the checks on such pointers are degraded to address validity only.

**Workaround.** In our header stubs, opaque handles are complete types with one dummy member
(`struct json_object { int _fc_opaque; };`). This is safe only because the target code never
dereferences the handle.

---

## Issue 6: RTL crash reports without a source location in the segment model (to be minimized)

**Observed.** After heap corruption in the target, the E-ACSL RTL sometimes crashed inside its
own code before printing the failing assertion. The only message was

```
Use of invalid address ... in unsafe_initialize
```

followed by a deadly signal. `unsafe_initialize` is an RTL-internal function, so the report gives
no target file or line.

**Expected.** The RTL message names the instrumented source location (file:line of the access
being recorded), or the RTL validates its arguments before using them, so the original assertion
is reported.

**Workaround.** We replay the crashing input on an ASan/UBSan build of the same slice to get
file:line.

---

## Issue 7 (feature request): unknown names in `-rte-select` / `-e-acsl-functions` abort the run

**Observed.** If a function named in `-rte-select` or `-e-acsl-functions` is absent from the
parsed AST (for example because it is excluded by `#if`), the run aborts with `no function 'X'`.
For selection options this is stricter than needed.

**Expected.** A warning (`function 'X' not found, ignored`), or an option to make it a warning.

**Workaround.** We compute the function list from preprocessed sources, and on `no function 'X'`
we drop the names and retry once.

---

## Summary table

| # | Kind | Severity for users | Our workaround |
|---|---|---|---|
| 1 | Bug (option parsing) | High: silent semantic change | Argv normalization (`-gline-tables-only`) |
| 2 | Usability / documentation | High: silently fuzzing an uninstrumented binary | Two-stage build, `.e-acsl` selection, instrumentation check |
| 3 | Bug (host-header mode) | High: link failure for any variadic call | Generated link-only forwarding object |
| 4 | Limitation | Medium: forces host-header mode | None (host-header mode only) |
| 5 | Bug (codegen) | Medium | Complete opaque types in stubs |
| 6 | Diagnostics | Medium | Differential replay on a sanitizer build |
| 7 | Feature request | Low | Preprocessed discovery and retry |
