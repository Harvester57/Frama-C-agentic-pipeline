# e-acsl-gcc: Frama-C preprocesses with `-std=c99 -D_DEFAULT_SOURCE` but the compiler gets `-std=c99` alone, so programs calling `strdup`, `strtok_r`, `fileno`, … fail to build

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

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
  ([frama-c-eacsl-gcc-clang-cflags.md](frama-c-eacsl-gcc-clang-cflags.md)). Once that is fixed,
  clang fails the same way.

## Versions

- Reproduced with Frama-C `35.0~~dev (Bromine)`, built from `master` at `ad24dca` (2026-11-02),
  Debian 13, glibc 2.41, gcc 14.2.0, clang 19.1.7.
- `plugins/e-acsl/scripts/e-acsl-gcc` is byte-identical in `34.0~~dev (Selenium)`.

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

## Proposed fix

Compile with the feature macros that Frama-C preprocessed with:

```diff
--- a/plugins/e-acsl/scripts/e-acsl-gcc
+++ b/plugins/e-acsl/scripts/e-acsl-gcc
@@ -890,7 +890,7 @@ fi
 # Gcc and related flags
 CC="$OPTION_CC"
 CFLAGS="$OPTION_CFLAGS
-  -std=c99 $GCCMACHDEP $OPT_CFLAGS
+  -std=c99 -D_DEFAULT_SOURCE $GCCMACHDEP $OPT_CFLAGS
   -fno-builtin -fno-merge-constants
   -Wall \
   -Wno-long-long \
```

`-std=gnu99` would also expose the declarations. `-D_DEFAULT_SOURCE` is better because it is exactly
what the Frama-C side uses, so the compiler and Frama-C see the same declarations, and it leaves
`-std=c99` itself unchanged.

## Validation of the proposed fix

Built from `ad24dca` with this patch and the clang `CFLAGS` patch:

| Check | `master` | Patched |
|---|---|---|
| `posix_dup.c`, gcc | build fails | builds; runs, exit 0 |
| `posix_dup.c`, gcc, `-L` | build fails | builds; runs, exit 0 |
| `posix_dup.c`, clang (with or without `-L`) | builds (only because `-std=c99` is dropped) | builds; runs, exit 0 |
| `strtok_r`, clang, `-L` (needs the unbounded-range fix) | — | builds; runs |
| ptests `plugins/e-acsl/tests`, `dev` configuration (195 tests compiled and run through `e-acsl-gcc`) | — | no change |

## Workaround

`-e -D_DEFAULT_SOURCE` (verified: `posix_dup.c` builds and runs, with and without `-L`).
