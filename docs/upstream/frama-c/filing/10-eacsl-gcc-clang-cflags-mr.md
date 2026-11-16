# [e-acsl] e-acsl-gcc: with -G clang, append to CFLAGS instead of replacing it

- Source branch: `fix/eacsl-gcc-clang-cflags` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70` **plus** the commit of `fix/eacsl-gcc-default-source` (`825ddcf5f1` on the fork, the
  `_DEFAULT_SOURCE` merge request !40). Patch: [`../patches/10-eacsl-gcc-clang-cflags.patch`](../patches/10-eacsl-gcc-clang-cflags.patch)
  applies on top of [`../patches/12-eacsl-gcc-default-source.patch`](../patches/12-eacsl-gcc-default-source.patch),
  not on pristine `3dff90fc70`: its script hunk alone would apply there, but its Changelog hunk uses
  the `_DEFAULT_SOURCE` entry as context. Open it after (or together with) that merge request,
  with `fix/eacsl-gcc-default-source` as its base until that one is merged.

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2810.

**Depends on !40** (branch `fix/eacsl-gcc-default-source`), which
this branch contains as its first commit. Only the last commit belongs to this merge request.

## Problem

The clang branch of `plugins/e-acsl/scripts/e-acsl-gcc` (lines 910-917) assigns `CFLAGS` instead
of appending to it. Under `-G clang`, the original and the instrumented program are compiled
without `-std=c99`, `-m<bits>`, `-g -O2` (or `-g3 -O0 -fno-omit-frame-pointer` with `--rt-debug`),
`-fno-builtin -fno-merge-constants` and the warning settings. The `--rt-debug` backtrace is empty,
clang prints 172 warnings on a two-line program, and with `--validate-format-strings` the runtime
does not build (clang 16 and later reject the implicit declarations in `e_acsl_stdio.c` that
`-Wno-implicit-function-declaration` normally hides).

## Change

- `plugins/e-acsl/scripts/e-acsl-gcc`: `CFLAGS="$CFLAGS -Wno-unknown-warning-option ..."`.
- `plugins/e-acsl/doc/Changelog`: one entry.

**Why it needs the `_DEFAULT_SOURCE` fix first.** Today, clang builds of programs that call POSIX
functions such as `strdup` work only because `-std=c99` is dropped. With this change alone,
`-std=c99` comes back without `-D_DEFAULT_SOURCE`, and such programs stop building under clang, as
they already fail under gcc. I checked it on a build with this change only: the `strdup` program of
the `_DEFAULT_SOURCE` issue fails under `-G clang`, with and without `-L`, with
`incompatible integer to pointer conversion initializing 'char *' with an expression of type 'int'
[-Wint-conversion]` (it builds on master). With both changes it builds and runs.

**No regression test.** The E-ACSL test suite compiles with gcc, and clang is not guaranteed in the
CI image, so the clang branch has no natural test. I ran the whole `dev` suite under clang by hand
instead (below). If the CI image has clang, a `dev` test with `-G clang` could be added.

## Testing

On master `3dff90fc70` (Debian 13, clang 19.1.7, gcc 14.2.0), built with the `_DEFAULT_SOURCE`
commit and this one, and installed:

| Check | master | with both patches |
|---|---|---|
| `e-acsl-gcc -D -M -G clang` compile command | the 5 clang-only `-Wno-*` flags only | `-std=c99 -D_DEFAULT_SOURCE -m64 -g3 -O0 -fno-omit-frame-pointer -fno-builtin -fno-merge-constants -Wall -Wno-...` then the 5 clang-only flags |
| `--rt-debug` backtrace under clang (`bad_write.c`) | empty | 7 frames, ending `write_ptr at bw.c:216`, `main at bw.c:227` |
| warnings on that build | 172 | 8: `-fno-merge-constants` ignored by clang (3, one per compile), and 5 in the runtime itself (`e_acsl_rtl_error.c`, `e_acsl_patricia_trie.c`) |
| `-c -G clang --validate-format-strings` on an empty `main` | runtime fails to build (`vabort`, `isdigit`, `vsyslog` undeclared) | builds |
| `strdup` program, `-G clang`, with and without `-L` | builds | builds; runs, exit 0 |
| same command lines with `-G gcc` | unchanged | unchanged |

E-ACSL `dev` suite run under clang: I added `-G clang` to `ROOT_EACSL_GCC_MISC_OPTS` in
`plugins/e-acsl/tests/test_config_dev` (local change, not part of the patch):

- master script: 10 of 197 tests fail. `concurrency/` (4 tests) and `format/` `fprintf`, `printf`
  and `sprintf` do not build (implicit declarations of runtime functions such as
  `__e_acsl_pthread_create` and `__e_acsl_builtin_sprintf`, rejected by clang);
  `special/e-acsl-bittree-model` aborts at run time (exit 134); `arith/neg_rte_int` builds but
  exits with 5 instead of 0 (its `main` is `void main(void)`); the 10th is the regression test of
  an unrelated pending fix (option arguments re-parsed), which that tree also contained.
- with both patches: 194 of 196 pass. `arith/neg_rte_int` now fails to build: clang rejects its
  `void main(void)` under `-std=c99` (`'main' must return 'int'`), a test-side issue under clang
  either way. `format/printf` runs and passes its checks, but its oracle differs in the line the
  runtime reports for each format error (`e_acsl_stdio.c:552` instead of `:549`): the
  `private_assert(...)` call there spans lines 549-552, and gcc and clang expand `__LINE__` to a
  different line of it.

ptests in the normal configuration (gcc), with both patches: E-ACSL `dev` suite
(`@plugins/e-acsl/tests/ptests_config_dev`, 196 tests with the `_DEFAULT_SOURCE` regression test):
all pass. The change does not touch the gcc path.

- `git diff --check`: clean.
- `./dev/check-files.sh -p` (that is, `make check-lint` and `make check-headers` on the changed
  files) with ocp-indent 1.10.0 and clang-format 19.1.7: clean.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
