# e-acsl-gcc: with `-G clang`, CFLAGS is overwritten, so `-std=c99`, `-m32/-m64`, `-g`, `-O2`, `-fno-builtin` and all warning settings are dropped (`--rt-debug` backtraces are empty)

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

**Land together with
[frama-c-eacsl-gcc-default-source.md](frama-c-eacsl-gcc-default-source.md).** Restoring `-std=c99`
under clang exposes the same missing `-D_DEFAULT_SOURCE` that already breaks gcc builds.

## Summary

`e-acsl-gcc` builds its compiler flags at lines 892-907, then adds clang-specific warning flags at
lines 910-917. The clang branch assigns `CFLAGS` instead of appending to it:

```sh
CFLAGS="$OPTION_CFLAGS
  -std=c99 $GCCMACHDEP $OPT_CFLAGS
  -fno-builtin -fno-merge-constants
  -Wall \
  ...
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

Under clang, both the original and the instrumented program are therefore compiled without:

| Dropped flag | Effect |
|---|---|
| `$OPT_CFLAGS`: `-g -O2`, or `-g3 -O0 -fno-omit-frame-pointer` with `-D`/`--rt-debug` | no debug info: the `--rt-debug` backtrace is **empty**; binaries are unoptimized by default |
| `-std=c99` | a different language standard from the one Frama-C parsed with |
| `$GCCMACHDEP` (`-m32`/`-m64`) | the binary may not match the machdep Frama-C used (by reading the code; not tested) |
| `-fno-builtin -fno-merge-constants` | clang may expand libc calls inline (by reading the code; not tested) |
| `-Wall` and the `-Wno-*` list | 169 warnings on an empty `main` |

Users choose clang for libFuzzer and sanitizers, so this affects every E-ACSL + libFuzzer setup.

## Versions

- Reproduced with Frama-C `35.0~~dev (Bromine)`, built from `master` at `ad24dca` (2026-11-02),
  Debian 13, clang 19.1.7.
- `plugins/e-acsl/scripts/e-acsl-gcc` is byte-identical in `34.0~~dev (Selenium)`.

## Reproduction

`t2.c` is `int main(void) { return 0; }`. `bad_write.c`:

```c
void write_ptr(int *p) { *p = 42; }
int main(void) { write_ptr((int *)0x1000); return 0; }
```

Compile commands (`-D` should add `-g3 -O0 -fno-omit-frame-pointer`):

```text
$ e-acsl-gcc -D -G clang -o t.inst.c -O t_clang t2.c 2>&1 | grep -- '-o t_clang'
+ /usr/bin/clang -Wno-unknown-warning-option -Wno-extra-semi -Wno-tautological-compare -Wno-gnu-empty-struct -Wno-incompatible-pointer-types-discards-qualifiers t2.c -o t_clang -no-pie
+ /usr/bin/clang -DE_ACSL_SEGMENT_MMODEL -DE_ACSL_DEBUG -Wno-unknown-warning-option -Wno-extra-semi -Wno-tautological-compare -Wno-gnu-empty-struct -Wno-incompatible-pointer-types-discards-qualifiers …
```

With gcc the same command line starts with
`/usr/bin/gcc -std=c99 -m64 -g3 -O0 -fno-omit-frame-pointer -fno-builtin -fno-merge-constants -Wall …`.

Runtime-debug backtrace, clang and then gcc:

```text
$ e-acsl-gcc -D -M -G clang -o bwc.c -O bwc bad_write.c && ./bwc.e-acsl
…/e_acsl_segment_tracking.c:1018: Use of invalid address 0x1000 in unsafe_initialize
/** Backtrace **************************/
/***************************************/

$ e-acsl-gcc -D -M -o bwg.c -O bwg bad_write.c && ./bwg.e-acsl
…/e_acsl_segment_tracking.c:1017: Use of invalid address 0x1000 in unsafe_initialize
/** Backtrace **************************/
trace at e_acsl_trace.c:73
 - raise_abort at e_acsl_private_assert.c:26
 - private_assert_fail at e_acsl_private_assert.c:57
 - unsafe_initialize at e_acsl_segment_tracking.c:1019
 - __e_acsl_initialize at e_acsl_segment_observation_model.c:110
 - write_ptr at bwg.c:216
 - main at bwg.c:227
/***************************************/
```

Warnings:

```text
$ e-acsl-gcc -G clang -o t.inst.c -O t_cd t2.c 2>&1 | grep 'warnings generated'
16 warnings generated.
169 warnings generated.
```

## Proposed fix

Append to `CFLAGS` instead of replacing it:

```diff
--- a/plugins/e-acsl/scripts/e-acsl-gcc
+++ b/plugins/e-acsl/scripts/e-acsl-gcc
@@ -909,7 +909,7 @@ CFLAGS="$OPTION_CFLAGS
 
 # Disable extra warning for clang
 if [ "`basename $CC`" = 'clang' ]; then
-  CFLAGS="-Wno-unknown-warning-option \
+  CFLAGS="$CFLAGS -Wno-unknown-warning-option \
     -Wno-extra-semi \
     -Wno-tautological-compare \
     -Wno-gnu-empty-struct \
```

### Why it must land with the `_DEFAULT_SOURCE` fix

With this patch alone, clang gets `-std=c99`. In strict C99 mode glibc hides POSIX declarations
(`strdup`, `strtok_r`, `fileno`, …), so programs that call them stop compiling under clang. They
already fail under gcc today, for the same reason. Today's clang builds only work because `-std=c99`
is dropped. [frama-c-eacsl-gcc-default-source.md](frama-c-eacsl-gcc-default-source.md) adds
`-D_DEFAULT_SOURCE`, as the Frama-C preprocessing step already does.

## Validation of the proposed fix

Built from `ad24dca` with this patch and the `_DEFAULT_SOURCE` patch:

| Check | `master` | Patched |
|---|---|---|
| `-D -G clang` compile command | 5 `-Wno-*` flags only | `clang -std=c99 -D_DEFAULT_SOURCE -m64 -g3 -O0 -fno-omit-frame-pointer -fno-builtin -fno-merge-constants -Wall … -Wno-unknown-warning-option …` |
| `--rt-debug` backtrace under clang (`bad_write.c`) | empty | `write_ptr at bwc.c:216`, `main at bwc.c:227` |
| Warnings, `-G clang` on `t2.c` | 16 + 169 | 5 (all in the runtime's `e_acsl_rtl_error.c`) |
| `-G clang` builds of `struct_repro.c`, `scalar_repro.c`, `bad_write.c`, a variadic `open` call, and a `strdup` call | build | build, no errors |
| `strtok_r` with `-L -G clang` (needs the unbounded-range fix) | — | builds; runs |
| ptests `plugins/e-acsl/tests` (default and `dev` configurations) | — | no change |

The E-ACSL test suite runs with gcc, so it does not exercise the clang branch.

## Related documentation nit (same script)

`man e-acsl-gcc` (`plugins/e-acsl/man/e-acsl-gcc.1:69-80`), on output names:

- `-O, --oexec`: "is appended the *.e.acsl* suffix". The suffix is `.e-acsl`.
- `--oexec-e-acsl`: "Unless specified, the executable is named as indicated by the **--oexec**
  option". It is named `<oexec>.e-acsl` (script line 1028).

## Workaround

Pass the dropped flags back with `-e`. They reach the compiler through `CPPFLAGS`, which the clang
branch does not touch. Verified on `master`: with
`-e "-std=c99 -D_DEFAULT_SOURCE -g3 -O0 -fno-omit-frame-pointer -fno-builtin"`, the `--rt-debug`
backtrace under clang names `write_ptr` and `main` again.

Avoid a bare `-g` inside the `-e` argument: `e-acsl-gcc` re-reads it as its own `-g` (`--gmp`) and
drops an input file. Use `-g2` or `-g3` instead; see
[frama-c-eacsl-gcc-option-arguments-reparsed.md](frama-c-eacsl-gcc-option-arguments-reparsed.md).
