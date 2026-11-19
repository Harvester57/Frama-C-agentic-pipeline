# [e-acsl] mark const globals read-only through their base address

- Source branch: `fix/eacsl-readonly-global-address` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `b80fcac74f`. Patch: [`../patches/27-eacsl-readonly-scalar-global-address.patch`](../patches/27-eacsl-readonly-scalar-global-address.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2794, closes #2795.

## Problem

`Global_observer.mk_init_function` marks each monitored const global read-only by calling
`__e_acsl_mark_readonly`, which expects the base address of the enclosing block (in the segment model,
`eacsl_mark_readonly(ptr)` calls `mark_readonly_region((uintptr_t)ptr, _block_length(ptr))`, where
`_block_length(ptr)` is the size of the whole block).

Previously:

- for every type but structs, `Global_observer` passed the global's value (`Cil.evar ~loc vi`):
  - scalar (`const uint64_t k = 23;`): the runtime aborts with "Use of invalid address 0x17 in predicate"
    before `main` runs (#2794);
  - union: the kernel rejects the generated `(void *)u`, "implicit cast: cast from union u to void *"
    (#2795);
  - pointer (`int *const p = &x;`): the block `p` points to is marked instead of `p`.
- for structs (since e-acsl#223), `Global_observer` emitted one call per field address (`Cil.mkAddrOf`):
  - any non-first field passes a non-zero offset with the whole enclosing `_block_length(ptr)`, writing
    read-only shadow bits past the end of the struct: under `--rt-debug` `mark_readonly_region` aborts
    with "Attempt to mark read-only ... bytes past block boundaries" (`e_acsl_segment_tracking.c:497`),
    and without `--rt-debug` it silently corrupts adjacent global shadow memory;
  - a bitfield member aborts Frama-C in `Cil.mkAddrOf` ("Taking the address of a bitfield");
  - an empty struct emits zero calls.

## Change

`plugins/e-acsl/src/code_generator/global_observer.ml`, `mark_readonly`:

- remove the per-field `TComp` branch completely;
- arrays keep `Cil.evar`, which decays to the array's base address (so the oracles with string literals
  do not change);
- every other type (scalars, pointers, unions and structs) gets `Cil.mkAddrOfVi vi`, marking the whole
  block once from its base address.

Updated existing oracle:

- `plugins/e-acsl/tests/concurrency/oracle/gen_sequential_threads.0.c`: the single-field const struct `s`
  now emits `__e_acsl_mark_readonly((void *)(& s));` instead of `(void *)(& s.i)`.

New test `plugins/e-acsl/tests/full-mtracking/const_globals.c`: a const scalar, a const union
(initialized and not), a multi-field non-bitfield const struct, a const struct with bitfields, and a
const pointer. Its `dev` configuration runs with `--full-mtracking --rt-debug` and checks at run time
that each const global is `\valid_read` and not `\valid`, and that for the const pointer `ptr`,
`\valid(ptr) && \valid_read(&ptr) && !\valid(&ptr)` holds.

## Testing

All on Debian 13 (gcc 14.2.0), `master` at `b80fcac74f` built with dune, then the same tree with this
patch:

- Reproducers from #2794 and #2795, built with `e-acsl-gcc -X -M` and run:
  - Before: the scalar aborts at run time ("Use of invalid address 0x17 in predicate", exit 134), the
    bitfield struct aborts Frama-C ("Taking the address of a bitfield"), the multi-field struct with
    `--rt-debug` aborts at run time ("Attempt to mark read-only 8 bytes past block boundaries", exit
    134), and the four union variants (static, static local, initialized, non-static) are rejected
    ("implicit cast: cast from union u to void *").
  - After: all build and run with exit 0, emitting a single base-address call
    `__e_acsl_mark_readonly((void *)(& kMaxEmbeddedInt));`, `(void *)(& cb)`, `(void *)(& cp)`, and
    `(void *)(& zero_block)` (including for `CONST_STRUCT`, which no longer emits per-field calls).
- The new test `plugins/e-acsl/tests/full-mtracking/const_globals.c` fails on unpatched `master` in both
  default and `dev` configurations (`implicit cast: cast from union u to void *`); with the patch it
  passes in both default and `dev` (`--full-mtracking --rt-debug`) configurations.
- `./dev/test.sh -p plugins/e-acsl` (default configuration of the whole E-ACSL suite): passes after
  promoting the new `const_globals` oracles and the 1-line change in
  `concurrency/oracle/gen_sequential_threads.0.c`. `concurrency/sequential_threads.c` also passes in
  `dev` configuration.
- `./dev/check-files.sh -p HEAD~1`: passes (exit 0; lint and header checks on all 5 files).

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
