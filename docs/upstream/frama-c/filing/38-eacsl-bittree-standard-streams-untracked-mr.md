# [e-acsl] bittree model: track the safe locations

- Source branch: `fix/eacsl-bittree-safe-locations` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `95408044f7`. Patch: [`../patches/38-eacsl-bittree-standard-streams-untracked.patch`](../patches/38-eacsl-bittree-standard-streams-untracked.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

The segment model registers `errno`, `stdout`, `stderr` and `stdin` as safe locations at start-up
(`collect_safe_locations`). The bittree model's `eacsl_memory_init` has the comment "Tracking safe
locations" but no call, so in that model every run-time check on these objects fails: `\valid` of a
copy of `stdout`, `\object_pointer(stdout)`, the `-rte -warn-invalid-pointer` guard of
`fputs(..., stdout)`, `\valid(p)` with `p = &errno` (#<issue>).

## Change

- `plugins/e-acsl/share/e-acsl/observation_model/bittree_model/e_acsl_bittree_observation_model.c`:
  call `collect_safe_locations()` in `eacsl_memory_init`. The bittree model does not support threads
  (`eacsl_pthread_create` aborts), so the call on the main thread covers the program.
- New test `special/e-acsl-bittree-std-streams.c`, run in the `dev` configuration with
  `--memory-model bittree` and `--memory-model segment`: `\valid` of copies of `stdout` and `stderr`,
  `\valid_read` of a copy of `stdin` (copies, because E-ACSL resolves predicates on the bare terms when
  instrumenting). Default-configuration oracles added.

## Testing

All on Debian 13 (gcc 14.2.0, clang 19.1.7), `master` at `95408044f7` built with dune, then the same
tree with this patch, rebuilt:

- Reproducer from #<issue>, two programs × {segment, bittree} × {gcc, `-M`, `-G clang`}. Before, with
  bittree: the four checks fail, and `-rte -warn-invalid-pointer` aborts on `fputs` (gcc, `-M` and
  clang); same on 34.0~beta. After: every bittree build passes, except the checks program with
  `-G clang`, which aborts on the unrelated #<issue-37> (it passes with that fix too). Segment builds
  pass before and after.
- The new test on unpatched `master`: the bittree `dev` run reports `out`, `err` and `in` failed and its
  error log differs from the empty oracle; the segment run passes. With the patch both pass.
- `frama-c-ptests -create-missing-oracles plugins/e-acsl/tests`, then `dune build --release -j 6` on
  `@plugins/e-acsl/tests/special/result/ptests_config` (only the new test's oracles were missing; I
  promoted them) and on `ptests_config_dev` in `special/`: all pass.
- `memory/` in the `dev` configuration with `--memory-model bittree` added locally (not part of this
  MR): `errno.c` fails on `master` and passes with the patch. The other failures of that run are
  #<issue-37>.
- `./dev/check-files.sh -p HEAD~1`: passes.
- The patch applies with `git am` on `95408044f7`, alone, and with `git am --3way` together with !33
  (which also edits `e_acsl_bittree_observation_model.c`), the fix for #<issue-37> and my other prepared
  E-ACSL runtime fixes, in three orders, without conflict.

Not run: the other E-ACSL test directories with the bittree model.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
