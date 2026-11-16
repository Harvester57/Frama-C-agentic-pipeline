# [e-acsl] ignore annotations with unbounded ranges instead of aborting

- Source branch: `fix/e-acsl-unbounded-range` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/04-eacsl-unbounded-range-abort.patch`](../patches/04-eacsl-unbounded-range-abort.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2798.

## Problem

E-ACSL reacts to an unbounded range (`Trange(None, _) | Trange(_, None)`) with `Options.abort` in
four places (`interval.ml`, `typing.ml`, `memory_tracking.ml`, `memory_translate.ml`). That stops
the whole run: nothing is instrumented, and every other annotation is lost. With `-L`, the libc
contracts of `strtok_r`, `getsockopt` and `wcschr` (among others) contain unbounded ranges, so a
program calling one of them cannot be instrumented at all.

## Change

Raise `Error.untypable "unbounded range"` at the four sites instead, like the other constructs
outside the E-ACSL subset. The annotation that contains the range is ignored with
``invalid E-ACSL construct `unbounded range'. Ignoring annotation.``, and the rest of the program
is instrumented. `untypable` rather than `not_yet`: an unbounded range cannot be checked at
runtime, so this is a limit of the language subset. The two "E-ACSl" typos go away with the
messages.

Regression test: `plugins/e-acsl/tests/memory/unbounded_range.c` (a `requires` and two `assert`s
with unbounded ranges, next to checkable clauses), with its default-configuration oracles
`unbounded_range.0.res.oracle` and `gen_unbounded_range.0.c`. On `master` the test aborts
(`unbounded ranges are not part of E-ACSl`); with the patch the three annotations are ignored with
the warning, `requires n >= 0` and `assert x == 'a'` are still translated, and the `dev`
configuration builds and runs it (exit 0, empty error log).

The recent interval changes for semi-bounded intervals (`interval_utils.ml`, join/meet of `Ival`
and `Float`) do not touch these sites; the abort is unchanged on `3dff90fc70`.

## Testing

On `3dff90fc70` (Debian 13, OCaml 5.5 switch, gcc 14.2.0), with the patch built and installed:

| Check | `master` | Patched |
|---|---|---|
| `e-acsl-gcc u.c` (`requires \valid_read(p + (0..)); requires n >= 0;`, called with `n = -1`) | `unbounded ranges are not part of E-ACSl`, aborted | warning, builds; `requires n >= 0` fails at runtime as it should |
| `e-acsl-gcc -L` on a `strtok_r` caller | aborted (`string.h:352`) | builds, runs, exit 0 |
| `e-acsl-gcc -L` on a `getsockopt` caller | aborted (`sys/socket.h:377`) | warning on `socket.h:398`, builds, runs, exit 0 |
| `e-acsl-gcc -L` on a `wcschr` caller | aborted (`wchar.h:106`) | builds, runs, exit 0 |
| `e-acsl-gcc -L` on `wcspbrk`, `wcsrchr`, `wcsstr` callers | aborted (`wchar.h:196`, `:205`, `:221`) | build, run (exit 1, the value the program returns) |

(`-L` runs used `-e -D_DEFAULT_SOURCE` so that the compiler sees the POSIX prototypes; that is a
separate `e-acsl-gcc` matter.)

- ptests `plugins/e-acsl/tests`, default configuration (198 results with the new test): only the
  two new oracles; no other change. `dev` configuration (every test compiled and run): passes
  with the patch, the new test included. On unpatched `3dff90fc70` the `dev` run of the existing
  tests passes too, and the new test fails there (the abort).
- `make check-lint` on the 7 changed files (`LINTCK_FILES_INPUT`, ocp-indent 1.10.0): clean.
  `clang-format` was not installed, so the indentation of the new C test file was not checked.
- `git diff --check`: clean except trailing spaces in the new `.res.oracle` (`Warning: ` lines)
  and the blank line at the end of the new `gen_*.c`, as in every E-ACSL oracle.
- `make check-headers`: not run.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
