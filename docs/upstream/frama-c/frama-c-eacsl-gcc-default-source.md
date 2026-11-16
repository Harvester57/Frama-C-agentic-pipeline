# e-acsl-gcc: Frama-C preprocesses with `-std=c99 -D_DEFAULT_SOURCE` but the compiler gets `-std=c99` alone, so programs calling `strdup`, `strtok_r`, `fileno`, … fail to build

**Filed upstream on 2026-11-15:** issue [#2809](https://git.frama-c.com/pub/frama-c/-/work_items/2809), merge request [!40](https://git.frama-c.com/pub/frama-c/-/merge_requests/40).

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

**Filing package:** [issue](./filing/12-eacsl-gcc-default-source-issue.md), [MR](./filing/12-eacsl-gcc-default-source-mr.md), [reproducer](./repro/12-eacsl-gcc-default-source.sh), [patch](./patches/12-eacsl-gcc-default-source.patch)

**Land before [frama-c-eacsl-gcc-clang-cflags.md](./frama-c-eacsl-gcc-clang-cflags.md) (Issue 10).**
This fix is independent; the Issue 10 patch is stacked on it.

## Summary

`e-acsl-gcc` uses two different feature settings for the same sources.

- Frama-C's preprocessing (`FRAMAC_CPP_EXTRA`, lines 862-868) gets `-std=c99 -D_DEFAULT_SOURCE`.
  The script's comment explains why: "use C99 + default features".
- Compilation (`CFLAGS`, line 893) gets `-std=c99` alone.

With glibc, `-std=c99` defines `__STRICT_ANSI__`, which turns off `_DEFAULT_SOURCE`. Declarations
guarded by POSIX or BSD feature macros then disappear: `strdup`, `strndup`, `strtok_r`, `fileno`,
`fdopen`, `getline`, and others. Frama-C sees the declarations and instruments the program, but the
compiler does not see them. The call is implicitly declared as returning `int`.

- **gcc 14 and later** make `-Wint-conversion` an error, so the build fails. The un-instrumented
  program is compiled first, so the message is
  `e-acsl-gcc: fatal error: fail to compile/link un-instrumented code`.
- **gcc 13 and earlier** only warn. The build succeeds and the pointer result goes through an
  `int` (not tested here).
- **With `-L`** (Frama-C's libc), the instrumented code prints `#include "string.h"` and also fails
  to compile, with `implicit declaration of function ‘strdup’`.
- **clang** works today only because `-G clang` drops `-std=c99` altogether, which is itself a bug
  ([frama-c-eacsl-gcc-clang-cflags.md](./frama-c-eacsl-gcc-clang-cflags.md)). Once that is fixed,
  clang fails the same way.

## Versions

- Reproduced on 2026-11-15 with Frama-C `35.0~~dev (Bromine)`, `master` at `3dff90fc70`
  (2026-11-13), and with `34.0~beta (Selenium)`: same failure on both, Debian 13, glibc 2.41,
  gcc 14.2.0 ([reproducer](./repro/12-eacsl-gcc-default-source.sh)).
- First seen on `master` `ad24dca` (2026-11-02); the script was byte-identical in
  `34.0~~dev (Selenium)`.

## Reproduction

`posix_dup.c`:

```c
#include <string.h>
#include <stdlib.h>
int main(void) {
  char *d = strdup("abc");
  int ok = d != 0 && d[0] == 'a';
  free(d);
  return !ok;
}
```

```text
$ e-acsl-gcc -o pd.c -O pd posix_dup.c
posix_dup.c:4:13: error: initialization of ‘char *’ from ‘int’ makes pointer from integer without a cast [-Wint-conversion]
e-acsl-gcc: fatal error: fail to compile/link un-instrumented code

$ e-acsl-gcc -L -o pd.c -O pd posix_dup.c
posix_dup.c:4:13: error: initialization of ‘char *’ from ‘int’ makes pointer from integer without a cast [-Wint-conversion]
e-acsl-gcc: fatal error: fail to compile/link un-instrumented code

$ e-acsl-gcc -L -n -o pdl.c posix_dup.c        # instrument only
$ gcc -std=c99 -fsyntax-only -I"$FRAMAC_SHARE/e-acsl" pdl.c
pdl.c:355:14: error: implicit declaration of function ‘strdup’; did you mean ‘strcmp’? [-Wimplicit-function-declaration]
pdl.c:355:12: error: assignment to ‘char *’ from ‘int’ makes pointer from integer without a cast [-Wint-conversion]
$ gcc -std=c99 -D_DEFAULT_SOURCE -fsyntax-only -I"$FRAMAC_SHARE/e-acsl" pdl.c   # no error
```

The glibc guard, in `/usr/include/string.h`:

```c
#if (defined __USE_XOPEN_EXTENDED || defined __USE_XOPEN2K8	\
     || __GLIBC_USE (LIB_EXT2) || __GLIBC_USE (ISOC23))
/* Duplicate S, returning an identical malloc'd string.  */
extern char *strdup (const char *__s)
```

## Fix (patch)

[`patches/12-eacsl-gcc-default-source.patch`](./patches/12-eacsl-gcc-default-source.patch), one
commit (`34fb547fb4`) on `fix/eacsl-gcc-default-source` from `3dff90fc70`,
"[e-acsl] e-acsl-gcc: compile with -D_DEFAULT_SOURCE, as Frama-C preprocesses":

- `plugins/e-acsl/scripts/e-acsl-gcc:893`: `-std=c99 -D_DEFAULT_SOURCE` in `CFLAGS`.
  `-std=gnu99` would also expose the declarations; `-D_DEFAULT_SOURCE` is exactly what the
  Frama-C side uses and leaves `-std=c99` unchanged.
- Regression test `plugins/e-acsl/tests/libc/default_source.c` (calls `stpcpy`), with its
  default-configuration oracles. Its `dev` run uses `-L`: the `dev` configuration always passes
  `-X`, so it never compiles the original program (and `ROOT_EACSL_GCC_MISC_OPTS` cannot be
  overridden from a test: `EACSL_EXEC` expands it when it is defined). Without `-L`, the
  instrumented code carries Frama-C's own prototypes and builds anyway.
- `plugins/e-acsl/doc/Changelog`: one entry.

**Order with Issue 10.** This patch is independent. It does not change clang builds on its own,
since the clang branch still overwrites `CFLAGS`. The Issue 10 patch is stacked on this commit:
restoring `-std=c99` under clang without `-D_DEFAULT_SOURCE` breaks clang builds of POSIX programs
(checked, see [frama-c-eacsl-gcc-clang-cflags.md](./frama-c-eacsl-gcc-clang-cflags.md)).

## Validation

Validated on 2026-11-15: patch built over `framac-master-audit:3dff90f` (master `3dff90fc70`) and
installed; Debian 13, glibc 2.41, gcc 14.2.0, clang 19.1.7.

| Check | `master` `3dff90fc70` | Patched |
|---|---|---|
| `posix_dup.c` (`strdup`), gcc, without and with `-L` | `fail to compile/link un-instrumented code` | builds; runs, exit 0 |
| `posix_dup.c`, gcc, `-X -L` | `fail to compile/link instrumented code` | — (covered by the test below) |
| New test `libc/default_source.c`, `dev` run (`-X -L`) | fails (`assignment to ‘char *’ from ‘int’`) | pass |
| ptests `plugins/e-acsl/tests`, `dev` configuration (196 tests, each compiled with gcc and run) | — | all pass |
| ptests `libc`, default configuration | — | pass; only the new oracles added |
| `posix_dup.c`, `-G clang`, with this patch and Issue 10's | builds (only because `-std=c99` is dropped) | builds; runs, exit 0 |
| `34.0~beta (Selenium)` | same failure as `master` | — |

`git diff --check` is clean except for the generated oracles (trailing spaces after `Warning:`,
final empty line). `clang-format-19 --dry-run` passes on the test file. `make check-lint` /
`make check-headers` were not run (no `ocp-indent` or `headache` in the image).

The `dev` suite was first run without a core-size limit and stalled: on this Docker/WSL2 host every
`abort()` goes through the `core_pattern` pipe helper (`/wsl-capture-crash`), which took up to
156 s per crash, so `format/printf.c` (hundreds of forked aborts) alone ran for over 40 minutes.
Rerun under `prlimit --core=1:1`, where the kernel skips the pipe dump; the whole suite then takes a
few minutes. This is a property of the test host, not of Frama-C.

## Workaround

`-e -D_DEFAULT_SOURCE` (verified: `posix_dup.c` builds and runs, with and without `-L`).
