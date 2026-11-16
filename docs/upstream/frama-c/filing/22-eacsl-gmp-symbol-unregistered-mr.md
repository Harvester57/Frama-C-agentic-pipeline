# [e-acsl] register RTL functions the user's code also declares

- Source branch: `fix/eacsl-rtl-user-gmp-symbols` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/22-eacsl-gmp-symbol-unregistered.patch`](../patches/22-eacsl-gmp-symbol-unregistered.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #ISSUE-22.

## Problem

When the program declares and calls a GMP function (`__gmpz_clear`, through `<gmp.h>` or directly) and
an annotation needs E-ACSL's own GMP code, Frama-C stops with
`Unexpected error (E_ACSL__Rtl.Symbols.Unregistered("__gmpz_clear"))`. `Rtl.lookup_rtl_globals` only
records an RTL function the user's AST already has in `Assocs` (to merge the contracts); it never enters
`Rtl.Symbols`, so `Smart_stmt.rtl_call` cannot find it.

## Change

`plugins/e-acsl/src/project_initializer/rtl.ml`, `lookup_rtl_globals`, `assoc` branch for functions:
also register the user's varinfo (`Kernel_function.get_vi kf`) in `Rtl.Symbols` under the RTL name. The
generated code then calls the program's declaration of the same function; `Smart_stmt.do_call` already
casts the arguments to its parameter types, e.g. `__gmpz_clear((struct my_mpz *)(__gen_e_acsl_mul));`.

`Rtl.Symbols.mem_vi` is now also true for those names. Its only user,
`Memory_tracking.must_never_monitor`, tests variables by name: a local variable named like one of these
functions (for instance a local `printf`, if the RTL and the program both declare `printf`) would no
longer be monitored. Keeping a separate table for these functions would avoid that, at the cost of a
second lookup in `rtl_call`; tell me if you prefer it.

New test `bts/rtl_user_gmp_symbols.c`: the program declares `__gmpz_init` and `__gmpz_clear` with its own
struct type, calls them, and asserts `a * b + 1 > 0` on two `unsigned long`.

## Testing

All on Debian 13 (gcc 14.2.0, libgmp 6.3), `master` at `3dff90fc70` built with dune, then the same tree
with this patch:

- Reproducer from the issue, built with `e-acsl-gcc -X` and run: before, the header-free program and
  the `<gmp.h>` variant (`-l -lgmp`) both stop with `Unregistered("__gmpz_clear")` (build exit 1), and the
  control without the assertion builds and runs. After, all three build and run with exit 0.
- The new test `bts/rtl_user_gmp_symbols.c` stops with the same error on unpatched `master`; with the
  patch it passes in the default configuration and in the `dev` configuration (compiled and run).
- `frama-c-ptests -create-missing-oracles plugins/e-acsl/tests`, then `dune build --release -j 6` on
  `@plugins/e-acsl/tests/ptests_config` and on `ptests_config_dev` in every test directory except
  `libc/` (its tests abort child processes on purpose, and the crash handler of my host made them
  crawl): 198 default-configuration results and 191 `dev` results. The only differences are the two
  new oracles of the new test, which I promoted; on a second run every test matches its oracle. No
  existing oracle changes.
- `git diff --check` reports nothing in the source and the test; in the generated oracles it reports
  the trailing space after `Warning:` and the final blank line, as for the existing oracles.
- `ocp-indent` 1.9.0 with the repository's `.ocp-indent`: `rtl.ml` unchanged.
- `./dev/check-files.sh -p` (that is, `make check-lint` and `make check-headers` on the changed
  files) with ocp-indent 1.10.0 and clang-format 19.1.7: clean.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
