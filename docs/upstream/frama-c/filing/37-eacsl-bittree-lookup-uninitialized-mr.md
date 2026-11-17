# [e-acsl] bittree model: return the block found by pt_lookup

- Source branch: `fix/eacsl-bittree-lookup` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `95408044f7`. Patch: [`../patches/37-eacsl-bittree-lookup-uninitialized.patch`](../patches/37-eacsl-bittree-lookup-uninitialized.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

In the bittree memory model, `pt_lookup` (the exact-address lookup of the Patricia trie behind
`bt_lookup`) never assigns its result when it finds the block: the assignment was lost in
`29af68df0e` ("[eacsl] Add C support for concurrency"). `full_init`, `mark_readonly`, `\freeable`,
`delete_block`, `store_block_duplicate`, `realloc` and `free` then read an indeterminate pointer:
with `-O2`, checks fail and every `free` aborts with "Not a start of block"; without optimisation
(`-G clang`, #2810) the program crashes. Also, `bt_clean` and `pt_lookup` dereference an empty tree:
a program that stores no block crashes at exit (#<issue>).

## Change

- `plugins/e-acsl/share/e-acsl/observation_model/internals/e_acsl_patricia_trie.c`, `pt_lookup`:
  `res` starts at NULL, an empty trie returns NULL (instead of `DASSERT(pt->root != NULL)` and a
  dereference), and `res = tmp->leaf` when the leaf holds the address looked for.
- `plugins/e-acsl/share/e-acsl/observation_model/bittree_model/e_acsl_bittree.c`, `bt_clean`: return
  when the tree was never created, instead of `DASSERT(bittree != NULL)`.

Tests, `dev` configuration:

- New `special/e-acsl-bittree-lookup.c`, run with `--memory-model bittree`, with and without
  `--full-mtracking`: a local checked valid and initialized in its scope and invalid after it,
  `\freeable` before `free` and not after. Default-configuration oracles added.
- `special/e-acsl-bittree-model.c` (`int main()`): a second run without `--full-mtracking`, where no
  block is stored. Its default oracles do not change.

## Testing

All on Debian 13 (gcc 14.2.0, clang 19.1.7), `master` at `95408044f7` built with dune, then the same
tree with this patch, rebuilt and installed:

- Reproducer from #<issue>, two programs × {segment, bittree} × {gcc, `-M`, `-G clang`,
  `-G clang -M`}. Before: 7 of the 8 bittree builds fail (exit 139 or 134; with gcc, the checks `RO`,
  `IN_SCOPE`, `OUT_OF_SCOPE` and `FREEABLE` fail, then "Not a start of block"); same on 34.0~beta. After:
  all 16 builds exit 0 with no failed check.
- The new and changed tests on unpatched `master`, `dev` configuration: `e-acsl-bittree-lookup` exits
  134 in both runs (`in_scope`, `out_of_scope`, `freeable` fail), and `e-acsl-bittree-model` without
  `--full-mtracking` exits 139. With the patch, all pass.
- A program with five memory errors (heap out of bounds, use after free, write to a `const` global,
  double `free`, dangling local), `--rte=all`, gcc and clang: before, the bittree model reports two of
  them wrongly, crashes on the `const` write and, with clang, aborts in every case; after, it reports
  all five with the same predicates as the segment model. Segment model results are unchanged.
- `frama-c-ptests -create-missing-oracles plugins/e-acsl/tests`, then `dune build --release -j 6` on
  `@plugins/e-acsl/tests/special/result/ptests_config` (only the new test's oracles were missing; I
  promoted them) and on `ptests_config_dev` in `special/`: all pass.
- `memory/` in the `dev` configuration with `--memory-model bittree` added locally to
  `ROOT_EACSL_GCC_MISC_OPTS` (not part of this MR): 26 tests fail on `master`, 3 with this patch.
  The 3 are `errno.c` (`errno` is not a safe location in the bittree model, a separate issue with
  its own merge request), `constructor.c` (allocation in a constructor, before `eacsl_memory_init`)
  and `ranges_in_builtins.c` (line 65, `\initialized` on a range past the end of a block); I did not
  look into the last two.
- `./dev/check-files.sh -p HEAD~1`: passes.
- The patch applies with `git am` on `95408044f7`, alone, and with `git am --3way` together with !33
  and my other prepared E-ACSL runtime fixes, in three orders, without conflict.

Not run: the other E-ACSL test directories with the bittree model.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
