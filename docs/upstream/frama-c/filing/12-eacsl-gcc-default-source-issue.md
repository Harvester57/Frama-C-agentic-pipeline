# [e-acsl-gcc] Frama-C preprocesses with `-std=c99 -D_DEFAULT_SOURCE` but the compiler gets `-std=c99` alone: programs calling strdup, stpcpy, ... fail to build

<!-- Everything below this line is the issue description. -->

### Summary

Frama-C preprocesses the program with `-std=c99 -D_DEFAULT_SOURCE`, but `e-acsl-gcc` compiles it with `-std=c99` alone. With glibc and gcc 14, functions such as `strdup` or `stpcpy` are then undeclared at compile time, and programs calling them fail to build.

### Steps to reproduce the issue

`posix_dup.c`:

```c
#include <string.h>
#include <stdlib.h>

int main(void) {
  char *d = strdup("abc"); /* POSIX: declared only with _DEFAULT_SOURCE & co */
  int ok = d != 0 && d[0] == 'a';
  free(d);
  return !ok;
}
```

```sh
e-acsl-gcc -o pd.c -O pd posix_dup.c
e-acsl-gcc -L -o pd.c -O pd posix_dup.c
```

(Debian 13: glibc 2.41, gcc 14.2.0.)

### Expected behaviour

Both commands build `pd` and `pd.e-acsl`, which exit with 0. Frama-C parses the program with
`strdup` declared, so the compiler should see the same declaration.

### Actual behaviour

```text
$ e-acsl-gcc -o pd.c -O pd posix_dup.c
posix_dup.c:5:13: error: initialization of ‘char *’ from ‘int’ makes pointer from integer without a cast [-Wint-conversion]
e-acsl-gcc: fatal error: fail to compile/link un-instrumented code
```

The same error with `-L`. With `-X` (instrumented code only, as in the E-ACSL `dev` tests), the
build succeeds without `-L`, since the instrumented code carries the prototypes Frama-C printed,
and fails with `-L`, since the instrumented code then includes the libc headers:

```text
$ e-acsl-gcc -X -L -o pd.c -O pd posix_dup.c
pd.c:354:12: error: assignment to ‘char *’ from ‘int’ makes pointer from integer without a cast [-Wint-conversion]
e-acsl-gcc: fatal error: fail to compile/link instrumented code
```

**Cause.** `plugins/e-acsl/scripts/e-acsl-gcc` (master `3dff90fc70`) uses two feature settings for
the same sources:

- Frama-C's preprocessing (`FRAMAC_CPP_EXTRA`, lines 862-868) gets `-std=c99 -D_DEFAULT_SOURCE`,
  with the comment "use C99 + default features";
- compilation (`CFLAGS`, lines 892-893) gets `-std=c99` alone.

With glibc, `-std=c99` defines `__STRICT_ANSI__`, which turns `_DEFAULT_SOURCE` off. Declarations
guarded by POSIX or BSD feature macros disappear (`strdup`, `strndup`, `stpcpy`, `strtok_r`,
`fileno`, `fdopen`, `getline`, ...). The compiler sees an implicit `int` declaration (its warning
is hidden by `-Wno-implicit-function-declaration`), and gcc 14 makes the resulting
`-Wint-conversion` an error. Older gcc only warns, and the pointer result goes through an `int`.

With `-G clang`, the same programs build today only because the clang branch of the script
overwrites `CFLAGS` and so drops `-std=c99` altogether, which is a separate bug (issue to be filed
next, with its own merge request that builds on this one).

**Fix.** Add `-D_DEFAULT_SOURCE` next to `-std=c99` in `CFLAGS`, so that the compiler sees the same
declarations as Frama-C. `-std=gnu99` would also work, but `-D_DEFAULT_SOURCE` is exactly what the
Frama-C side uses and leaves `-std=c99` unchanged. A merge request with a fix follows.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

Same behaviour on 34.0~beta (Selenium) and on master `3dff90fc70`.

Workaround: `e-acsl-gcc -e -D_DEFAULT_SOURCE ...` (the program then builds and runs, with and
without `-L`).

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
