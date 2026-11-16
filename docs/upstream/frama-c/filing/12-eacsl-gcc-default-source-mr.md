# [e-acsl] e-acsl-gcc: compile with -D_DEFAULT_SOURCE, as Frama-C preprocesses

- Source branch: `fix/eacsl-gcc-default-source` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/12-eacsl-gcc-default-source.patch`](../patches/12-eacsl-gcc-default-source.patch)
- Lands first: the `-G clang` CFLAGS merge request (`fix/eacsl-gcc-clang-cflags`) builds on this
  branch. This one is independent and can be merged alone.

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2809.

## Problem

`e-acsl-gcc` preprocesses for Frama-C with `-std=c99 -D_DEFAULT_SOURCE` (`FRAMAC_CPP_EXTRA`,
lines 862-868 of `plugins/e-acsl/scripts/e-acsl-gcc`) but compiles with `-std=c99` alone (`CFLAGS`,
lines 892-893). With glibc, `-std=c99` alone hides POSIX/BSD declarations (`strdup`, `stpcpy`,
`strtok_r`, `fileno`, ...). Frama-C instruments the calls, the compiler sees implicit `int`
declarations, and gcc 14 rejects the int-to-pointer conversion: any program that calls such a
function fails with `fail to compile/link un-instrumented code` (and, with `-L`, the instrumented
code fails the same way).

## Change

- `plugins/e-acsl/scripts/e-acsl-gcc`: `-std=c99 -D_DEFAULT_SOURCE` in `CFLAGS`, so that the
  compiler sees the declarations Frama-C saw. `-std=c99` itself is unchanged.
- New test `plugins/e-acsl/tests/libc/default_source.c`, which calls `stpcpy`. Its `dev` run uses
  `-L`: the `dev` configuration always passes `-X`, so it never compiles the original program, and
  without `-L` the instrumented code carries Frama-C's own prototypes and builds anyway. With `-L`,
  the instrumented code includes `<string.h>` and failed before the fix with
  `assignment to ‘char *’ from ‘int’ makes pointer from integer without a cast`. The
  default-configuration oracles come from E-ACSL instrumenting the libc contract of `stpcpy`.
- `plugins/e-acsl/doc/Changelog`: one entry.

**Relation with the `-G clang` fix.** Under `-G clang`, the same programs build today only because
the clang branch of the script overwrites `CFLAGS` and drops `-std=c99`. The merge request that
fixes that (`fix/eacsl-gcc-clang-cflags`) restores `-std=c99` under clang and therefore needs this
change first; it is stacked on this branch. This change on its own does not alter clang builds
(the clang branch still overwrites `CFLAGS`, `-D_DEFAULT_SOURCE` included).

## Testing

On master `3dff90fc70` (Debian 13, glibc 2.41, gcc 14.2.0), built with the patch and installed:

| Check | master | with the patch |
|---|---|---|
| `e-acsl-gcc -o pd.c -O pd posix_dup.c` (calls `strdup`) | `fail to compile/link un-instrumented code` | builds; `pd.e-acsl` exits 0 |
| same with `-L` | same failure | builds; `pd.e-acsl` exits 0 |
| new test `libc/default_source.c`, `dev` run | `fail to compile/link instrumented code` | pass |

- ptests, E-ACSL `dev` configuration (`@plugins/e-acsl/tests/ptests_config_dev`, 196 tests with the
  new one, each compiled with gcc through `e-acsl-gcc` and run): all pass.
- ptests, `libc` directory, default configuration: pass (only the new test's oracles added).
- `git diff --check`: clean, except for the trailing spaces after `Warning:` and the final empty line
  in the two generated oracles, as in every existing oracle.
- The new test passes `clang-format-19 --dry-run` with `plugins/e-acsl/.clang-format`.
- `./dev/check-files.sh -p` (that is, `make check-lint` and `make check-headers` on the changed
  files) with ocp-indent 1.10.0 and clang-format 19.1.7: clean.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
