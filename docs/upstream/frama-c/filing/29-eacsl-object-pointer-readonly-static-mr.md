# [e-acsl] \object_pointer does not require the object to be writable

- Source branch: `fix/eacsl-object-pointer-readonly` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`; re-validated on `95408044f7` (2026-11-17), the base to branch from. Patch: [`../patches/29-eacsl-object-pointer-readonly-static.patch`](../patches/29-eacsl-object-pointer-readonly-static.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`eacsl_object_pointer`, the runtime implementation of `\object_pointer`, calls `eacsl_valid` on `ptr` and on
`ptr - size`. `eacsl_valid` implements `\valid`, which requires the block to be writable, so
`\object_pointer(p)` is false whenever `p` points into a block marked read-only: a string literal, a `const`
global array, or `stdin` (a non-writable safe location). The ACSL definition of `\object_pointer` does not
ask for writability. With `-warn-invalid-pointer`, the guard `\null == p || \object_pointer(p)` then fails on
the first read through such a pointer (#<issue>).

The ACSL contract of the builtin in `e_acsl_observation_model.h` uses `\valid` in its behaviours `valid`,
`minus_one` and `invalid_pointer_ptr`, so it states the same requirement; Eva, run on the instrumented code
in the test suite, concludes from it that `\object_pointer` is false on a `const` array.

## Change

- `plugins/e-acsl/share/e-acsl/observation_model/e_acsl_observation_model.c`: `eacsl_object_pointer` calls
  `eacsl_valid_read` instead of `eacsl_valid`. The base check and the one-past-the-end case (`ptr - size`)
  are unchanged, and `eacsl_valid_read` has the same `--temporal` check as `eacsl_valid`.
- `plugins/e-acsl/share/e-acsl/observation_model/e_acsl_observation_model.h`: `\valid_read` instead of
  `\valid` in the three behaviours of the contract of `eacsl_object_pointer`, and a doc comment like the
  ones of the neighbouring builtins.

New test `memory/object_pointer_readonly.c`, with `check` annotations so that one run reports every
failing case. For a `static const` array and for a string literal, it checks that the block is read-only
(`\valid_read(p) && !\valid(p)`), that `\object_pointer` holds at the start, inside and one past the end,
and that it does not hold two past the end or one before the start. It also checks
`\object_pointer(stdin)`.

## Testing

All on Debian 13 (gcc 14.2.0, clang 19.1.7), `master` at `3dff90fc70` built with dune, then the same tree
with this patch, rebuilt and installed:

- Reproducers from #<issue>, each run on its four objects. Before: the `const` array and the string literal
  abort (exit 134) on `\object_pointer(p)`, and on the `invalid pointer` guard with
  `-rte -warn-invalid-pointer`, with gcc and `-G clang`, with and without `-M`, and with `--temporal`; same
  on 34.0~beta. After: every run exits 0. (`-m bittree` passes before and after, see the note below.)
- The new test on unpatched `master`: in the `dev` configuration (compiled and run), `T0`, `T3`, `T4`, `S0`,
  `S4` and `IN` fail at run time and the error log differs from the (empty) oracle; the read-only checks
  and the negative cases pass. In the default configuration, Eva reports
  `function __e_acsl_assert, behavior non_blocking: precondition got status invalid` on the lines of
  `T0`, `T3`, `T4`, `S0` and `S4`, from the old contract. With the patch both configurations pass, and the
  same run-time result holds with `-G clang`, `-M`, both, and `--temporal`.
- `frama-c-ptests -create-missing-oracles plugins/e-acsl/tests`, then `dune build --release -j 8` on
  `@plugins/e-acsl/tests/ptests_config` (198 results, all regenerated after the patched install) and on
  `ptests_config_dev` in `memory/`, `acsl-rte/`, `temporal/` and `libc/` (the suites whose generated code
  calls `__e_acsl_object_pointer`). The only differences are the new oracles, which I promoted; every other
  test, including `memory/objects.c` and `acsl-rte/rte.c`, matches its oracle. No existing oracle changes.
- `./dev/check-files.sh -p HEAD~1` (`make check-lint` and `make check-headers` on the changed files, with
  ocp-indent 1.10.0, headache 1.08 and clang-format 19.1.7): passes.
- The patch applies with `git am` on `3dff90fc70` alone, and on top of my other open merge requests
  (applied in sequence) without conflict. Its test has no function formal, so it does not depend on !28.
- Rerun on current `master` (`95408044f7`): the patch applies with `git am`; the reproducers give the
  same results before and after; the new test fails on the unpatched sources in both configurations
  and passes with the patch; the default configuration of the whole E-ACSL suite (198 results) and
  `./dev/check-files.sh -p HEAD~1` pass.

Note, not changed here: with `-m bittree`, the read-only mark does not take effect (`\valid(p)` holds on a
`const` array or a string literal), and `stdin`, `stdout`, `stderr` and `errno` are not registered as safe
locations, because the bittree `eacsl_memory_init` does not call `collect_safe_locations()`. The new test's
`!\valid` and `stdin` checks fail with `-m bittree` for those reasons, before and after this patch; the test
suite runs the segment model.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
