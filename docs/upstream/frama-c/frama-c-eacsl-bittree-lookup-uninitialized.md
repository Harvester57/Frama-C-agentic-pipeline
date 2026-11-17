# E-ACSL: in the bittree memory model, `pt_lookup` returns an uninitialized pointer when it finds the block, so `free` aborts, `\freeable` and read-only marks are wrong, and `int main(void)` crashes at exit

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Filed on 2026-11-18 as [#2826](https://git.frama-c.com/pub/frama-c/-/work_items/2826), with merge request [!54](https://git.frama-c.com/pub/frama-c/-/merge_requests/54).** Number 37 in this folder's index.

**Filing package (2026-11-17):** issue text
[`./filing/37-eacsl-bittree-lookup-uninitialized-issue.md`](./filing/37-eacsl-bittree-lookup-uninitialized-issue.md),
merge request text
[`./filing/37-eacsl-bittree-lookup-uninitialized-mr.md`](./filing/37-eacsl-bittree-lookup-uninitialized-mr.md),
patch [`./patches/37-eacsl-bittree-lookup-uninitialized.patch`](./patches/37-eacsl-bittree-lookup-uninitialized.patch)
(validated, see "Validation"), reproducer
[`./repro/37-eacsl-bittree-lookup-uninitialized.sh`](./repro/37-eacsl-bittree-lookup-uninitialized.sh) with
[`./repro/37-eacsl-bittree-lookup-uninitialized.c`](./repro/37-eacsl-bittree-lookup-uninitialized.c) and
[`./repro/37-eacsl-bittree-lookup-uninitialized-empty.c`](./repro/37-eacsl-bittree-lookup-uninitialized-empty.c).

The item started as "bittree with `main(void)` segfaults without `-M`; clang with `-M` aborts". Both
are symptoms of the two defects below; the slug names the main one.

## Summary

`e-acsl-gcc -m bittree` (`--memory-model bittree`) selects the Patricia-trie memory model, documented as
supported (user manual, `provides.tex`) and recommended where the segment model does not apply
(`limitations.tex`: non-x86_64 or big-endian targets). On `master` and 34.0~beta it is broken for any
program that frees memory:

1. `pt_lookup` (`observation_model/internals/e_acsl_patricia_trie.c:423-464`), the exact-address lookup
   behind `bt_lookup`, declares `pt_leaf_t res;` and never assigns it when it finds the leaf. Every
   operation that looks a block up by its start address gets an indeterminate pointer: `full_init`,
   `mark_readonly`, `\freeable`, `delete_block` (end of scope), `store_block_duplicate`, `realloc` and
   `free`.
   - With gcc `-O2` (the `e-acsl-gcc` default) it acts as "not found": read-only marks are lost
     (`\valid` holds on a `const` array), a local is not initialized when assigned and stays valid after
     its scope, `\freeable(malloc(...))` is false, and every `free` aborts with
     "Not a start of block (0x...) in free".
   - Without optimisation (`-G clang`, which drops `-O2`, #2810; or `--rt-debug`) it is stack garbage,
     handed to the allocator: segmentation fault or abort before any check.
2. The empty tree is not handled. `bt_clean` (`bittree_model/e_acsl_bittree.c:125-133`) starts with
   `DASSERT(bittree != NULL)` and dereferences the tree, which is only created when the first block is
   stored: a program that stores no block (`int main(void)` without `--full-mtracking`) crashes at
   exit. `pt_lookup` also asserts `pt->root != NULL` and dereferences it, but the root is NULL again
   once every block has been removed (a double `free` of the only block).

The existing test `special/e-acsl-bittree-model.c` is `int main() { return 0; }` run with
`--full-mtracking`, which stores blocks and frees nothing, so neither defect shows. MR !41 (#2810)
already saw that test abort (exit 134) once `-G clang` lost `-O2`, without a diagnosis; this is the
diagnosis.

The read-only loss noted in package 29 ("Also seen": with `-m bittree`, `\valid(p)` holds on a `const`
array) is defect 1: `mark_readonly` does not find the block.

## Versions

- Reproduced on `35.0~~dev (Bromine)`, `master` at `95408044f7` (image `framac-master-audit:9540804`,
  gcc 14.2.0, clang 19.1.7) and on `34.0~beta (Selenium)` (`framac-analysis:latest`). Same output.
- Defect 1 was introduced by `29af68df0e` ("[eacsl] Add C support for concurrency", 2021-10-18, first
  in 25.0), which replaced `return tmp->leaf;` by the `res`/`goto end` form with the read lock and
  dropped the assignment on the found path.

## Reproduction

See the reproducer script; its header holds the output before and after. Matrix on `master`
(segment model: every cell passes):

| Program | gcc | gcc `-M` | `-G clang` | `-G clang -M` |
| :-- | :-- | :-- | :-- | :-- |
| `int main(void) { return 0; }` | 139 (`bt_clean`) | 0 | 139 | 134 |
| `int main(int argc, char **argv) { return 0; }` (hand probe; argv blocks are stored) | 0 | 0 | 0 | 134 |
| `37-...c`: const table, scoped local, `malloc`/`free` | 134: `RO`, `IN_SCOPE`, `OUT_OF_SCOPE`, `FREEABLE` fail, then "Not a start of block" | same | 134, no check reached | 134 |

With `--rt-debug` the empty program reports `e_acsl_bittree.c:126: bittree != NULL`; under gdb the
clang `-M` abort is in `__e_acsl_mspace_free` called from `__e_acsl_full_init` with a garbage pointer.

## Cause

`pt_lookup` after `29af68df0e`:

```c
  pt_leaf_t res;
  pt_node_t *tmp = pt->root;
  while (!tmp->is_leaf) {
    ...  /* res = NULL; goto end; when the prefix does not match */
  }
  if (pt->get_ptr_fct(tmp->leaf) != ptr) {
    res = NULL;
  }
end:
  E_ACSL_RWUNLOCK(pt->lock);
  return res;
```

On a match, `res` is never set. The header contract (`e_acsl_patricia_trie.h:103-106`) does not
require a non-empty trie, and `bt_lookup` is called on an empty tree after the last block is removed.

## Proposed fix

- `pt_lookup`: initialize `res` to NULL, return early on an empty trie, set `res = tmp->leaf` on a
  match (and drop `DASSERT(pt->root != NULL)`).
- `bt_clean`: return when the tree was never created.

A lookup-only variant (only `res = tmp->leaf`) was tried: it fixes every lookup symptom and the clang
aborts, but `int main(void)` without `-M` still crashes in `bt_clean`, and a double `free` of the only
block still crashes in `pt_lookup` (`--rt-debug`: `e_acsl_patricia_trie.c:428: pt->root != NULL`)
instead of reporting "Not a start of block". So the three changes go together.

### Patch proposed (2026-11-17)

[`./patches/37-eacsl-bittree-lookup-uninitialized.patch`](./patches/37-eacsl-bittree-lookup-uninitialized.patch),
one commit on `95408044f7`, "[e-acsl] bittree model: return the block found by pt_lookup":

- `observation_model/internals/e_acsl_patricia_trie.c` and `bittree_model/e_acsl_bittree.c` as above.
- New test `special/e-acsl-bittree-lookup.c` (a scoped local checked initialized then out of scope,
  `\freeable` before and after `free`), run in the `dev` configuration with `--memory-model bittree`,
  with and without `--full-mtracking`; default-configuration oracles added.
- `special/e-acsl-bittree-model.c`: a second `dev` run without `--full-mtracking`, the case that crashed
  in `bt_clean`. Its default oracles do not change.

## Negative controls

A program with five errors (heap out of bounds, use after free, write to a `const` global, double
`free`, dangling local), `--rte=all`, gcc and clang:

- Stock bittree: wrong message for the use after free and the dangling local (the `free` abort comes
  first), segmentation fault on the `const` write, and with clang every case aborts in the allocator.
- Patched bittree: all five caught, with the same predicates and messages as the segment model
  (`\valid(p + 2)`, `\valid_read(p + 0)`, `\valid(&(table[0]))`, "Not a start of block",
  `\valid_read(q)`).
- Segment model: unchanged.

## Also seen, not fixed here

- With the patch, two tests of `memory/` still fail when the whole directory is run with
  `--memory-model bittree` (with patch 38 too): `constructor.c` (segmentation fault: a
  `__attribute__((constructor))` allocates before `eacsl_memory_init`; the segment model handles this
  pre-main case, bts #2405, the bittree model does not) and `ranges_in_builtins.c` (line 65,
  `!\initialized(s.b + (0 .. 1))` with `s.b` pointing to one `float`: the bittree model answers 1 for a
  range that runs past the end of the block). Not investigated further.
- `eacsl_free` in the bittree model does not release the `bt_block` of a block freed by `free`; the
  bittree `eacsl_memory_init` calls `eacsl_make_memory_spaces(MB_SZ(64), MB_SZ(64))`, which is 0 and 0
  (the comment says the sizes do not matter). Read in the source only; not changed.
- `eacsl_memory_init` in the bittree model is not run-once (a recursive `main` would initialise twice).

## Validation

All in container `framac-master-audit:9540804` (Debian 13, gcc 14.2.0, clang 19.1.7), `master` at
`95408044f7`, then commit `1d623bb0fb` on it, rebuilt and installed.

| Check | `master` | Patched |
| :-- | :-- | :-- |
| Reproducer, bittree rows (8) | see the matrix: 139/134 in 7 of 8 rows | all exit 0, no failed check |
| Reproducer, segment rows (8) | all exit 0 | all exit 0 |
| Reproducer on 34.0~beta | same as `master` | not run |
| New test `e-acsl-bittree-lookup`, `dev` | `.0` and `.1`: exit 134, `in_scope`, `out_of_scope`, `freeable` fail, then "Not a start of block" | passes |
| `e-acsl-bittree-model`, `dev` | new run without `-M`: exit 139; `-M` run passes | both pass |
| ptests `special/`, default configuration | — | only the new test's two oracles were missing (promoted) |
| ptests `special/`, `dev` configuration | — | all pass |
| ptests `memory/`, `dev`, with `--memory-model bittree` added locally to `ROOT_EACSL_GCC_MISC_OPTS` (not in the patch) | 26 tests fail | 3 fail: `errno.c` (issue 38), `constructor.c`, `ranges_in_builtins.c` |
| Same with patches 37 and 38 | — | 2 fail: `constructor.c`, `ranges_in_builtins.c` |
| Negative controls (above) | wrong or missing reports | all five caught, as in segment |
| `./dev/check-files.sh -p HEAD~1` | — | passes ("Lint 6 file(s)") |
| `git am` alone on `95408044f7` | — | applies |
| `git am --3way` with patches 18, 29, 36, 38 (three orders) | — | applies, no conflict |

Patch 18 (`environ`, !33) does not change any of these symptoms. Not run: the other E-ACSL test
directories under `--memory-model bittree`, and their default configuration (which does not run
the runtime).

## Effect on package 29

Package 29's reproducer and test under `-m bittree` (exit codes of objects 0-3):

| Runtime | `29-...static.c`, gcc | same, `-G clang` | `object_pointer_readonly.c` (29's test), gcc |
| :-- | :-- | :-- | :-- |
| `master` | 0 0 0 0 | 134 134 134 134 | `RO_T`, `RO_S`, `IN` fail |
| + 37 | 0 0 134 134 (the 29 bug, now visible) | 0 0 134 134 | more checks fail, `IN` among them |
| + 29 | 0 0 0 0 | 134 134 134 134 | `RO_T`, `RO_S`, `IN` fail |
| + 29 + 37 | 0 0 0 0 | 0 0 0 0 | `IN` fails |
| + 29 + 38 | 0 0 0 0 | 134 134 134 134 | `RO_T`, `RO_S` fail |
| + 29 + 37 + 38 | 0 0 0 0 | 0 0 0 0 | passes |

So 29's `-m bittree: 0 0 0 0` row before its fix is right only because of this bug, and its "Also
seen" paragraph on the lost read-only mark is explained here. 29's test runs the segment model in the
suite, so it does not depend on 37 or 38.

## Tracker

Searched on 2026-11-17 (`pub/frama-c`, issues and merge requests, all states) for `bittree`,
`patricia`, `pt_lookup`, `Not a start of block`, `memory-model`, `main(void)`. No duplicate. Neighbours:
#980 (closed; bittree, adjacent blocks), #2810 / !41 (clang CFLAGS; saw `e-acsl-bittree-model` abort),
#2802 / !33 (patch 18).
