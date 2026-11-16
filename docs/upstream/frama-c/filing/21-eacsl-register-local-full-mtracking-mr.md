# [e-acsl] drop the register storage class of observed variables

- Source branch: `fix/eacsl-register-locals` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/21-eacsl-register-local-full-mtracking.patch`](../patches/21-eacsl-register-local-full-mtracking.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2804.

## Problem

E-ACSL observes a monitored variable through its address (`__e_acsl_store_block`,
`__e_acsl_full_init`, `__e_acsl_delete_block`, `\initialized(&x)`). For a `register` local,
`Cil.mkAddrOf` aborts with "Taking the address of a register variable". Under `-e-acsl-full-mtracking`
every local is monitored, so any function with a `register` local makes Frama-C abort; without it, a
memory predicate on such a local is enough.

## Change

`plugins/e-acsl/src/code_generator/injector.ml`, `inject_in_fundec`: before instrumenting a function,
reset the storage of its `register` locals and formals to `NoStorage`, next to where the function already
rewrites them (ghost status). `register` is a hint whose only constraint is that the program cannot take
the variable's address, which the original program does not do (the kernel rejects it). The instrumented
program declares `unsigned int i;` instead of `register unsigned int i;` and behaves the same.

New test `full-mtracking/register.c`: a `register` loop counter, and a `register` local named in
`\initialized(&j)`. The `full-mtracking` directory runs it with `-e-acsl-full-mtracking` (default
configuration) and with `e-acsl-gcc --full-mtracking` (E-ACSL `dev` configuration).

## Testing

All on Debian 13 (gcc 14.2.0), `master` at `3dff90fc70` built with dune, then the same tree with this
patch:

- Reproducer from the issue, built with `e-acsl-gcc -X` and run: before, `-M` on the loop counter and
  the `\initialized(&i)` variant without `-M` both abort with "Taking the address of a register
  variable" (build exit 1). After, both build and run with exit 0, as does the plain build.
- The new test `full-mtracking/register.c` aborts the same way on unpatched `master`; with the patch it
  passes in the default configuration and in the `dev` configuration (compiled and run).
- `frama-c-ptests -create-missing-oracles plugins/e-acsl/tests`, then `dune build --release -j 6` on
  `@plugins/e-acsl/tests/ptests_config` and on `ptests_config_dev` in every test directory except
  `libc/` (its tests abort child processes on purpose, and the crash handler of my host made them
  crawl): 198 default-configuration results and 191 `dev` results. The only differences are the two
  new oracles of the new test, which I promoted; on a second run every test matches its oracle. No
  existing oracle changes.
- `git diff --check` reports nothing in the source and the test; in the generated oracles it reports
  the final blank line of `gen_register.0.c`, as for the existing oracles.
- `ocp-indent` 1.9.0 with the repository's `.ocp-indent`: `injector.ml` unchanged.
- Not run: `make check-lint` and `make check-headers` (my build tree is not a git checkout). The patch
  adds no source file; the new test has no header, like its neighbours.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
