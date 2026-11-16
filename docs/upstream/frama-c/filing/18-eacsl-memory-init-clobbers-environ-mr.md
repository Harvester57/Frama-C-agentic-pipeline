# [e-acsl] do not modify `environ` when tracking the environment strings

- Source branch: `fix/eacsl-environ` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/18-eacsl-memory-init-clobbers-environ.patch`](../patches/18-eacsl-memory-init-clobbers-environ.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2802.

## Problem

When `main` takes `argc` and `argv`, `eacsl_memory_init` calls `argv_alloca`, which also
registers the environment strings. Both observation models walk them with
`while (*environ) { ...; environ++; }`, incrementing the global `environ` itself. When the loop
ends, `environ` points to its terminating NULL entry: the instrumented program sees an empty
environment and every `getenv` returns NULL.

## Change

- `segment_model/e_acsl_segment_observation_model.c` and
  `bittree_model/e_acsl_bittree_observation_model.c`: walk the environment with a local
  `char **env = environ;`, as `get_stack_start` in `e_acsl_shadow_layout.c` already does.
  `environ` keeps its value. With temporal analysis, the segment model still replaces each entry by
  its shadow copy, as before.
- New test `plugins/e-acsl/tests/libc/getenv.c`: `main(int argc, char **argv)` asserts that
  `getenv("PATH")` is not NULL. Default configuration: two runs (default and
  `-e-acsl-full-mtracking`), with new oracles `libc/oracle/getenv.{0,1}.res.oracle` and
  `libc/oracle/gen_getenv.{0,1}.c`. `dev` configuration: segment model, then bittree model with
  `--full-mtracking`. No other oracle changes. (`temporal/t_getenv.c` accepts a NULL result, which
  is why it did not catch the bug.)

## Testing

On a build of this branch (Debian 13, OCaml 5.5 switch, gcc 14):

- Reproducer of the issue (`EACSL_REPRO_VAR=hello`, `main(int argc, char **argv)`): the
  instrumented program printed `(null)` and exited with 1 with both memory models before the
  change; it prints `hello` and exits with 0 with both after.
- `libc/getenv.c`, `dev` configuration: both runs (segment; bittree with `--full-mtracking`) fail
  before the change (`Assertion failed`, failing predicate `path ≢ \null`, value `path: (nil)`), and pass after.
- E-ACSL ptests, every suite, default and `dev` configurations, on this branch and on `master`:
  the only difference is the new test (fails on `master`, passes here). In my environment
  `format/printf.c` hangs in the `dev` configuration on `master` as well (no progress after its
  28th check), so the `format` suite was compared in the default configuration only.
- `git diff --check` reports only the new oracle files (the trailing space after `Warning:` and the
  trailing blank line that ptests writes in every oracle). The patch applies with
  `git apply --check` on `3dff90fc70`.
- `make check-lint` and `make check-headers` were not run (my build tree is not a Git checkout);
  `clang-format` 19 (`--dry-run -Werror`, with `plugins/e-acsl/.clang-format`) on the two
  observation models and the new test is clean.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
