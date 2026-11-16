# [e-acsl-gcc] With `-G clang`, CFLAGS is overwritten: -std=c99, -m64, -g/-O, -fno-builtin and the warning flags are dropped, and the `--rt-debug` backtrace is empty

<!-- Everything below this line is the issue description. -->

### Summary

With `-G clang`, `e-acsl-gcc` assigns its clang warning flags to `CFLAGS` instead of appending them, which drops `-std=c99`, `-m64`, `-g`, `-O`, `-fno-builtin` and the other flags it set. Among the visible effects, the `--rt-debug` backtrace is empty.

### Steps to reproduce the issue

`bad_write.c`:

```c
void write_ptr(int *p) { *p = 42; }
int main(void) { write_ptr((int *)0x1000); return 0; }
```

```sh
e-acsl-gcc -D -M -G clang -o bw.c -O bw bad_write.c   # -D = --rt-debug
./bw.e-acsl
```

(Debian 13, clang 19.1.7.)

### Expected behaviour

clang gets the same base flags as gcc: `-std=c99 -m64`, `-g3 -O0 -fno-omit-frame-pointer` for
`--rt-debug` (`-g -O2` otherwise), `-fno-builtin -fno-merge-constants` and the warning settings,
plus the clang-only `-Wno-*` flags. The runtime error prints a backtrace through `write_ptr` and
`main`, as it does with gcc:

```text
$ e-acsl-gcc -D -M -o bw.c -O bw bad_write.c && ./bw.e-acsl     # gcc
.../e_acsl_segment_tracking.c:1017: Use of invalid address 0x1000 in unsafe_initialize
/** Backtrace **************************/
trace at e_acsl_trace.c:73
 - raise_abort at e_acsl_private_assert.c:26
 - private_assert_fail at e_acsl_private_assert.c:57
 - unsafe_initialize at e_acsl_segment_tracking.c:1019
 - __e_acsl_initialize at e_acsl_segment_observation_model.c:110
 - write_ptr at bw.c:216
 - main at bw.c:227
/***************************************/
```

### Actual behaviour

The compile command (echoed by e-acsl-gcc) only has the five clang-only flags, clang prints 172
warnings, and the backtrace is empty:

```text
$ e-acsl-gcc -D -M -G clang -o bw.c -O bw bad_write.c
+ /usr/bin/clang -Wno-unknown-warning-option -Wno-extra-semi -Wno-tautological-compare -Wno-gnu-empty-struct -Wno-incompatible-pointer-types-discards-qualifiers bad_write.c -o bw -no-pie
...
$ ./bw.e-acsl
.../e_acsl_segment_tracking.c:1018: Use of invalid address 0x1000 in unsafe_initialize
/** Backtrace **************************/
/***************************************/
```

With `--validate-format-strings`, the runtime does not even build under clang, since clang 16 and
later reject implicit function declarations that `-Wno-implicit-function-declaration` normally
hides:

```text
$ e-acsl-gcc -c -G clang --validate-format-strings -o t.i.c -O t t.c    # t.c: int main(void){return 0;}
e_acsl_stdio.c:136:3: error: call to undeclared function 'vabort'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
e_acsl_stdio.c:284:12: error: call to undeclared library function 'isdigit' with type 'int (int)'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
e_acsl_stdio.c:998:10: error: call to undeclared function 'vsyslog'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
e-acsl-gcc: fatal error: fail to compile/link instrumented code
```

**Cause.** `plugins/e-acsl/scripts/e-acsl-gcc` (master `3dff90fc70`) builds `CFLAGS` at lines
892-908, then the clang branch (lines 910-917) assigns it instead of appending to it:

```sh
# Disable extra warning for clang
if [ "`basename $CC`" = 'clang' ]; then
  CFLAGS="-Wno-unknown-warning-option \
    -Wno-extra-semi \
    ...
    -Wno-incompatible-pointer-types-discards-qualifiers"
fi
```

So under clang, both the original and the instrumented program lose `$OPT_CFLAGS` (no debug info
and no frame pointers, hence the empty backtrace; `-O0` instead of `-O2` by default), `-std=c99`
(a different language standard from the one Frama-C preprocessed with), `$GCCMACHDEP`
(`--mbits` never reaches the compiler), `-fno-builtin -fno-merge-constants`, `-Wall` and every
`-Wno-*` of the base list. Users pick clang for libFuzzer and the sanitizers, so every
E-ACSL + libFuzzer setup is affected.

**Fix.** `CFLAGS="$CFLAGS -Wno-unknown-warning-option ..."`. A merge request with a fix follows.

**It depends on the `_DEFAULT_SOURCE` issue** (e-acsl-gcc compiles with `-std=c99` but without the
`-D_DEFAULT_SOURCE` Frama-C preprocesses with; filed just before this one). Today, clang builds of
programs that call POSIX functions such as `strdup` work only because `-std=c99` is dropped.
Restoring `-std=c99` without `-D_DEFAULT_SOURCE` breaks them, as it already breaks them under gcc.
I checked it: with this fix alone, the `strdup` program of that issue fails under `-G clang` with
`incompatible integer to pointer conversion initializing 'char *' with an expression of type 'int'
[-Wint-conversion]`, with and without `-L`; with both fixes it builds and runs. The merge request
for this issue therefore builds on the one for the `_DEFAULT_SOURCE` issue.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

Same behaviour on 34.0~beta (Selenium) and on master `3dff90fc70` (172 warnings, empty backtrace).

Workaround: pass the dropped flags back with `-e`, which reaches the compiler through `CPPFLAGS`
(not overwritten): `-e "-std=c99 -D_DEFAULT_SOURCE -g3 -O0 -fno-omit-frame-pointer -fno-builtin"`.

Two small inaccuracies of `man e-acsl-gcc` about output names, seen while checking this:
`-O, --oexec` says the instrumented executable gets the suffix `.e.acsl`, but it is `.e-acsl`;
`--oexec-e-acsl` says that by default "the executable is named as indicated by the `--oexec`
option", but it is `<oexec>.e-acsl`.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
