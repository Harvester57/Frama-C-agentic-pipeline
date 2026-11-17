# [e-acsl] compute the zone sizes of --zone-sizes in size_t

- Source branch: `fix/eacsl-zone-size-overflow` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `95408044f7`. Patch: [`../patches/36-eacsl-heap-zone-size-overflow.patch`](../patches/36-eacsl-heap-zone-size-overflow.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`e-acsl-gcc --zone-sizes` passes each size, in MB, to the segment-model runtime as
`E_ACSL_HEAP_SIZE`, `E_ACSL_STACK_SIZE`, `E_ACSL_TLS_SIZE` and `E_ACSL_THREAD_STACK_SIZE`. The runtime
converts them to bytes with `size * MB`, where `MB` is the `int` constant `1024 * 1024`. From 2048 MB
the product overflows `int`: `heap:2048` to `heap:4095` and `stack:2048` crash every run at start-up,
larger heaps wrap to (N mod 4096) MB, larger stacks are ignored, and `thread-stack:2048` makes
`pthread_create` fail (#<issue>).

## Change

In `plugins/e-acsl/share/e-acsl/observation_model/segment_model/`, the size is converted to `size_t`
before the multiplication:

- `e_acsl_shadow_layout.h`: `PGM_HEAP_SIZE` and `PGM_TLS_SIZE`;
- `e_acsl_segment_observation_model.c`: the argument of `increase_stack_limit`;
- `e_acsl_shadow_concurrency.c`: the two uses of `E_ACSL_THREAD_STACK_SIZE * MB`.

New test `special/e-acsl-zone-sizes.c`: `malloc`, a `\valid` check and `free`, run in the `dev`
configuration with `--zone-sizes heap:2048,stack:2048`. It reserves about 2 GB of address space for
the heap and its shadows (not memory). Default-configuration oracles added.

Not changed here: `--zone-sizes tls:N` has no effect, because `PGM_TLS_SIZE` is never read
(`get_tls_size()` returns the TLS size measured at start-up). The cast is applied to the macro anyway.

## Testing

All on Debian 13 (gcc 14.2.0, clang 19.1.7), `master` at `95408044f7` built with dune, then the same
tree with this patch, rebuilt and installed:

- Reproducer from #<issue>, a program that allocates and writes 2 MB, built with gcc and with
  `-G clang` for heap:1024, 2047, 2048, 4095, 4096, 4097 and stack:2047, 2048. Before: exit 139 for
  heap:2048, heap:4095 and stack:2048, exit 134 ("Exceeded heap allocation limit") for heap:4096 and
  heap:4097, and gcc warns `integer overflow in expression of type 'int'`; same on 34.0~beta. After:
  every run exits 0 and there is no warning.
- By hand, with the patch: heap:8192 up to heap:1048576 and stack:4096 up to stack:65536 exit 0 with gcc
  and clang; with `--concurrency` (gcc), `thread-stack:2048` and `thread-stack:4096` exit 0 (before:
  `pthread_create` failed for 2048). `-G clang` cannot build the concurrency case on `master` (#2810), so
  `thread-stack` was checked with gcc only.
- The new test on unpatched `master`: the `dev` run exits 139. With the patch it passes.
- `frama-c-ptests -create-missing-oracles plugins/e-acsl/tests`, then `dune build --release -j 6` on
  `@plugins/e-acsl/tests/special/result/ptests_config` (only the new test's oracles were missing; I
  promoted them), and on `ptests_config_dev` in `special/` and `memory/`: all pass.
- `./dev/check-files.sh -p HEAD~1`: passes.
- The patch applies with `git am` on `95408044f7`, alone, and with `git am --3way` together with !33 and
  the other E-ACSL runtime fixes I am preparing (bittree model, `\object_pointer`), in three orders,
  without conflict.

Not run: the other E-ACSL test directories; no other test uses `--zone-sizes`.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
