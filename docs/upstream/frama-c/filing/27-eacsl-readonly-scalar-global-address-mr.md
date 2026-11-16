# [e-acsl] mark const globals read-only through their address

- Source branch: `fix/eacsl-readonly-global-address` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/27-eacsl-readonly-scalar-global-address.patch`](../patches/27-eacsl-readonly-scalar-global-address.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2794, closes #2795.

## Problem

`Global_observer.mk_init_function` marks each monitored const global read-only. For every type but
structs it passes the global itself (`Cil.evar ~loc vi`) to `__e_acsl_mark_readonly`, which expects an
address:

- scalar (`const uint64_t k = 23;`): the runtime aborts with "Use of invalid address 0x17 in predicate"
  before `main` runs (#2794);
- union: the kernel rejects the generated `(void *)u`, "implicit cast: cast from union u to void *"
  (#2795);
- pointer (`int *const p = &x;`): the block `p` points to is marked instead of `p`.

Structs get one call per field address since e-acsl#223, but `Cil.mkAddrOf` aborts on a bitfield member
("Taking the address of a bitfield").

## Change

`plugins/e-acsl/src/code_generator/global_observer.ml`, `mark_readonly`:

- arrays keep `Cil.evar`, which decays to the array's address (so the oracles with string literals do not
  change);
- scalars, pointers, unions, incomplete structs and structs with a bitfield member get
  `Cil.mkAddrOfVi vi`;
- structs without bitfields keep the per-field calls of e-acsl#223.

New test `full-mtracking/const_globals.c`: a const scalar, a const union (initialized and not), a const
struct with bitfields and a const pointer. It checks at run time that each is `\valid_read` and not
`\valid`, that is, marked read-only, and that the pointee of the const pointer is still `\valid`.

## Testing

All on Debian 13 (gcc 14.2.0), `master` at `3dff90fc70` built with dune, then the same tree with this
patch:

- Reproducers from #2794 and #2795, built with `e-acsl-gcc -X -M` and run. Before: the scalar
  aborts at run time ("Use of invalid address 0x17 in predicate", exit 134), the bitfield struct aborts
  Frama-C ("Taking the address of a bitfield"), and the four union variants (static, static local,
  initialized, non-static) are rejected ("implicit cast: cast from union u to void *"). After: all build
  and run with exit 0, with `__e_acsl_mark_readonly((void *)(& kMaxEmbeddedInt));`,
  `(void *)(& cb)` and `(void *)(& zero_block)`. The const struct and non-const union variants are
  unchanged.
- The new test `full-mtracking/const_globals.c` fails on unpatched `master` (implicit cast on its first
  union); with the patch it passes in the default configuration and in the `dev` configuration
  (compiled and run, so the `\valid_read` / `!\valid` assertions are checked at run time).
- `frama-c-ptests -create-missing-oracles plugins/e-acsl/tests`, then `dune build --release -j 6` on
  `@plugins/e-acsl/tests/ptests_config` (198 results) and on `ptests_config_dev` in every test directory
  except `libc/` and `format/` (188 results). The only differences are the new oracles, which I promoted;
  on the final run every test matches its oracle. No existing oracle changes (the string literals, which
  are arrays, keep `Cil.evar`). Not completed: the `dev` configuration of `libc/` and `format/` (their
  tests abort child processes on purpose, and the crash handler of my host made `format/printf.c`
  exceed a 40-minute timeout); their default configuration ran and matches.
- `git diff --check` reports nothing in the source and the test; in the generated oracles it reports
  the trailing space after `Warning:` and the final blank line, as for the existing oracles.
- `ocp-indent` 1.9.0 with the repository's `.ocp-indent`: `global_observer.ml` unchanged.
- Not run: `make check-lint` and `make check-headers` (my build tree is not a git checkout). The patch
  adds no source file; the new test has no header, like its neighbours.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
