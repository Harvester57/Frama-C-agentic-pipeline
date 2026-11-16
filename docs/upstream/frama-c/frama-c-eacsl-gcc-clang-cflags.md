# e-acsl-gcc: with `-G clang`, CFLAGS is overwritten, so `-std=c99`, `-m32/-m64`, `-g`, `-O2`, `-fno-builtin` and all warning settings are dropped (`--rt-debug` backtraces are empty)

**Filed upstream on 2026-11-15:** issue [#2810](https://git.frama-c.com/pub/frama-c/-/work_items/2810), merge request [!41](https://git.frama-c.com/pub/frama-c/-/merge_requests/41).

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

**Filing package:** [issue](./filing/10-eacsl-gcc-clang-cflags-issue.md), [MR](./filing/10-eacsl-gcc-clang-cflags-mr.md), [reproducer](./repro/10-eacsl-gcc-clang-cflags.sh), [patch](./patches/10-eacsl-gcc-clang-cflags.patch)

**Depends on [frama-c-eacsl-gcc-default-source.md](./frama-c-eacsl-gcc-default-source.md)
(Issue 12), which must land first.** Restoring `-std=c99` under clang exposes the same missing
`-D_DEFAULT_SOURCE` that already breaks gcc builds (checked: with this patch alone, the `strdup`
program of Issue 12 stops building under `-G clang`). The Issue 10 patch is stacked on the Issue 12
commit and applies on top of
[`patches/12-eacsl-gcc-default-source.patch`](./patches/12-eacsl-gcc-default-source.patch).

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

- Reproduced on 2026-11-15 with Frama-C `35.0~~dev (Bromine)`, `master` at `3dff90fc70`
  (2026-11-13), and with `34.0~beta (Selenium)`: same output on both (172 warnings, empty
  `--rt-debug` backtrace), Debian 13, clang 19.1.7
  ([reproducer](./repro/10-eacsl-gcc-clang-cflags.sh)).
- First seen on `master` `ad24dca` (2026-11-02); the script was byte-identical in
  `34.0~~dev (Selenium)`.

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

## Fix (patch)

[`patches/10-eacsl-gcc-clang-cflags.patch`](./patches/10-eacsl-gcc-clang-cflags.patch), one commit
on `fix/eacsl-gcc-clang-cflags`, stacked on the Issue 12 commit (`34fb547fb4`, itself on
`3dff90fc70`), "[e-acsl] e-acsl-gcc: with -G clang, append to CFLAGS instead of replacing it". It
holds the one-line script change below and a Changelog entry. The script hunk alone would apply on
pristine `3dff90fc70`; the Changelog hunk needs the Issue 12 entry as context. I kept two stacked
merge requests rather than one: Issue 12 is a gcc bug that stands alone and can land first, and
each review stays one line.

No regression test: the E-ACSL suite compiles with gcc, and clang is not guaranteed in the CI image.
I ran the whole `dev` suite under clang by hand instead (see Validation).

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
is dropped. [frama-c-eacsl-gcc-default-source.md](./frama-c-eacsl-gcc-default-source.md) adds
`-D_DEFAULT_SOURCE`, as the Frama-C preprocessing step already does.

## Validation

Validated on 2026-11-15: the Issue 12 and Issue 10 patches built over `framac-master-audit:3dff90f`
(master `3dff90fc70`) and installed; Debian 13, clang 19.1.7, gcc 14.2.0.

| Check | `master` `3dff90fc70` | Issue 12 + Issue 10 patches |
|---|---|---|
| `-D -M -G clang` compile command (`bad_write.c`) | the 5 clang-only `-Wno-*` flags only | `clang -std=c99 -D_DEFAULT_SOURCE -m64 -g3 -O0 -fno-omit-frame-pointer -fno-builtin -fno-merge-constants -Wall -Wno-… -Wno-unknown-warning-option …` |
| `--rt-debug` backtrace under clang | empty | 7 frames, ending `write_ptr at bw.c:216`, `main at bw.c:227` |
| Warnings on that build | 172 | 8: `-fno-merge-constants` ignored by clang (3), and 5 in the runtime (`e_acsl_rtl_error.c`, `e_acsl_patricia_trie.c`) |
| `-c -G clang --validate-format-strings` on an empty `main` | runtime fails to build (`vabort`, `isdigit`, `vsyslog` undeclared) | builds |
| Issue 12's `strdup` program, `-G clang`, without and with `-L` | builds | builds; runs, exit 0 |
| Same, Issue 10 patch **alone** | — | fails: `incompatible integer to pointer conversion initializing 'char *' …` (this is the dependency) |
| `-G gcc` command lines | unchanged | unchanged |
| ptests `plugins/e-acsl/tests`, `dev` configuration, gcc (196 tests) | — | all pass |
| `dev` suite with `-G clang` added to `ROOT_EACSL_GCC_MISC_OPTS` (local change) | 10 of 197 fail (see below) | 194 of 196 pass |
| `34.0~beta (Selenium)` | same as `master` | — |

`dev` suite under clang. On `master`, `concurrency/` (4 tests) and `format/` `fprintf`, `printf`,
`sprintf` do not build (implicit declarations of `__e_acsl_pthread_create`,
`__e_acsl_builtin_sprintf`, …, rejected by clang), `special/e-acsl-bittree-model` aborts at run time
(exit 134), `arith/neg_rte_int` exits with 5 instead of 0 (its `main` is `void main(void)`), and the
10th is the Issue 1 regression test, which that tree also contained. With both patches,
`arith/neg_rte_int` fails to build instead (clang rejects `void main` under `-std=c99`: a test-side
issue), and `format/printf` passes its checks but its oracle differs in the line the runtime reports
for each format error (`e_acsl_stdio.c:552` instead of `:549`: the `private_assert(...)` call spans
lines 549-552, and gcc and clang expand `__LINE__` to different lines of it).

`git diff --check` is clean. `make check-lint` / `make check-headers` were not run (no
`ocp-indent` or `headache` in the image).

### Further consequence: `--validate-format-strings` does not build under clang

Found 2026-11-14 on `34.0~beta (Selenium)` (opam build, Debian 13, clang 19.1.7). With
`--validate-format-strings`, the runtime compiles `libc_replacements/e_acsl_stdio.c`, which:

- calls `vabort`, `isdigit` and `vsyslog` with no declaration in scope. clang 16 and later treat an
  implicit function declaration as an error, and the clang branch has dropped
  `-Wno-implicit-function-declaration`:

  ```
  e_acsl_stdio.c:136:3: error: call to undeclared function 'vabort'; ISO C99 and later do not support implicit function declarations
  e_acsl_stdio.c:284:12: error: call to undeclared library function 'isdigit' with type 'int (int)'
  e_acsl_stdio.c:998:10: error: call to undeclared function 'vsyslog'
  e-acsl-gcc: fatal error: fail to compile/link instrumented code
  ```

- calls `valid_string`, defined as a plain C99 `inline` function in `libc_replacements/e_acsl_string.h:66`
  (`long inline valid_string(...)`) with no external definition. At `-O0`, which is what the clang
  branch leaves, the call is not inlined and the link fails:

  ```
  e_acsl_rtl.c:(.text+0x947a): undefined reference to `valid_string'
  ```

With gcc (`-G gcc`), the same build works and reports both seeded format bugs. The proposed fix
above restores `-O2` and the warning flags, which hides both problems. Each is also a defect of its
own: `e_acsl_stdio.c` should include `<ctype.h>` and `<syslog.h>` and declare `vabort` (it is
defined nowhere in `share/e-acsl`), and `valid_string` should be `static inline` or have an
`extern` declaration in one translation unit.

Reproducer: any program, for example `int main(void) { return 0; }`, with
`e-acsl-gcc -c -G clang --validate-format-strings -O t t.c`. Workaround: pass
`-e "-O1 -Wno-implicit-function-declaration"` (the pipeline's backend flags already contain both).

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
[frama-c-eacsl-gcc-option-arguments-reparsed.md](./frama-c-eacsl-gcc-option-arguments-reparsed.md).
