# E-ACSL: the bittree memory model never registers `stdin`, `stdout`, `stderr` and `errno` as safe locations, so every run-time check on them fails

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Number 38 in this folder's index.

**Filing package (2026-11-17):** issue text
[`./filing/38-eacsl-bittree-standard-streams-untracked-issue.md`](./filing/38-eacsl-bittree-standard-streams-untracked-issue.md),
merge request text
[`./filing/38-eacsl-bittree-standard-streams-untracked-mr.md`](./filing/38-eacsl-bittree-standard-streams-untracked-mr.md),
patch [`./patches/38-eacsl-bittree-standard-streams-untracked.patch`](./patches/38-eacsl-bittree-standard-streams-untracked.patch)
(validated, see "Validation"), reproducer
[`./repro/38-eacsl-bittree-standard-streams-untracked.sh`](./repro/38-eacsl-bittree-standard-streams-untracked.sh)
with [`./repro/38-eacsl-bittree-standard-streams-untracked.c`](./repro/38-eacsl-bittree-standard-streams-untracked.c)
and [`./repro/38-eacsl-bittree-standard-streams-untracked-rte.c`](./repro/38-eacsl-bittree-standard-streams-untracked-rte.c).

First noted in package 29 ("Also seen"); this package confirms and fixes it.

## Summary

The E-ACSL runtime treats a few objects that the program never allocates as "safe locations": `errno`,
`stdout`, `stderr` (writable) and `stdin` (read-only), collected by `collect_safe_locations()`
(`observation_model/internals/e_acsl_safe_locations.c`). The segment model calls it at start-up
(`segment_model/e_acsl_shadow_layout.c:566`) and for each thread
(`segment_model/e_acsl_shadow_concurrency.c:175`). The bittree model's `eacsl_memory_init`
(`bittree_model/e_acsl_bittree_observation_model.c:581-593`) has the comment `/* Tracking safe
locations */` but no call. So with `-m bittree`:

- `\valid(out)` with `out == stdout`, `\valid(err)`, `\valid_read(in)` and `\object_pointer(stdout)` are
  false;
- with `-rte -warn-invalid-pointer`, the `invalid pointer` guard on the first `fputs(..., stdout)` or
  `fprintf(stderr, ...)` fails and the program aborts;
- `\valid(p)` with `p = &errno` is false (`memory/errno.c` fails in that model).

What a user does not see: `\valid(stdout)` written on the global itself, and `\valid_read`,
`\initialized` and `\freeable` on the bare terms `stdin`, `stdout`, `stderr` and `errno`, are resolved
when instrumenting (`src/analyses/memory_tracking.ml:17-29`,
`src/code_generator/translate_predicates.ml`), so they pass in both models. Plain programs that only
print, without `-rte -warn-invalid-pointer`, run normally.

## Versions

- Reproduced on `35.0~~dev (Bromine)`, `master` at `95408044f7` (image `framac-master-audit:9540804`,
  gcc 14.2.0, clang 19.1.7) and on `34.0~beta (Selenium)` (`framac-analysis:latest`). Same output.

## Reproduction

The reproducer script; its header holds the output before and after. On `master`, with `-m bittree`
(gcc, with and without `-M`): the four checks of the `.c` file fail (`check` reports and continues,
exit 0), and the `-rte.c` file aborts (134) on
`\null ≡ stdout ∨ \object_pointer(stdout)` at `fputs("to stdout\n", stdout)`. With the segment model
everything passes.

With `-G clang`, the `.c` file aborts (134) before any check: that is issue 37 (the uninitialized
`pt_lookup` result reaches the allocator without `-O2`), and it still aborts with only this patch.

## Cause and fix

The missing call. Fix: call `collect_safe_locations()` in the bittree `eacsl_memory_init`, where the
comment is. The locations live in a `__thread` array; the bittree model does not support threads
(`eacsl_pthread_create` aborts with "Concurrency is not supported for bittree model"), so one call on
the main thread covers the program. `eacsl_memory_init` is not run-once in that model, so a program
calling it twice would collect twice; out of scope.

### Patch proposed (2026-11-17)

[`./patches/38-eacsl-bittree-standard-streams-untracked.patch`](./patches/38-eacsl-bittree-standard-streams-untracked.patch),
one commit on `95408044f7`, "[e-acsl] bittree model: track the safe locations":

- `bittree_model/e_acsl_bittree_observation_model.c`: one line.
- New test `special/e-acsl-bittree-std-streams.c`: copies of `stdout`, `stderr` and `stdin` checked with
  `\valid`, `\valid` and `\valid_read` (copies, because the bare terms are resolved statically), run in
  the `dev` configuration with `--memory-model bittree` and `--memory-model segment`; default oracles
  added. `main(int, char **)` stores the `argv` blocks, so the test does not hit issue 37's empty-tree
  crash and passes with this patch alone.

## Validation

All in container `framac-master-audit:9540804` (Debian 13, gcc 14.2.0, clang 19.1.7), `master` at
`95408044f7`, then commit `1003c650f8` on it, rebuilt; the reproducer used the patched runtime copy
through `--e-acsl-share` (extracted with `git archive` from the commit).

| Check | `master` | Patched |
| :-- | :-- | :-- |
| Reproducer, bittree gcc and `-M` (4 rows) | `.c`: `OUT ERR IN OUT_OBJ` fail; `-rte.c`: exit 134 on `invalid pointer` | all exit 0, no failed check |
| Reproducer, bittree `-G clang` (2 rows) | `.c`: 134 (issue 37); `-rte.c`: 134 (`invalid pointer`) | `.c`: 134 (issue 37); `-rte.c`: 0 |
| Same, with patches 37 and 38 | — | all 12 rows exit 0 |
| Reproducer, segment (6 rows) | all exit 0 | all exit 0 |
| Reproducer on 34.0~beta | same as `master` | not run |
| New test, `dev` | bittree run: `out`, `err`, `in` fail (error log differs from the empty oracle); segment run passes | both pass |
| ptests `special/`, default configuration | — | only the new test's two oracles were missing (promoted) |
| ptests `special/`, `dev` | — | all pass |
| `memory/`, `dev`, with `--memory-model bittree` added locally (not in the patch) | 26 fail | 25 fail: `errno.c` now passes; the others are issue 37 |
| `./dev/check-files.sh -p HEAD~1` | — | passes ("Lint 4 file(s)") |
| `git am` alone on `95408044f7` | — | applies |
| `git am --3way` with patches 18, 29, 36, 37 (three orders) | — | applies, no conflict |

Patch 18 also edits `e_acsl_bittree_observation_model.c`; both apply in either order.

## One package or two with 37

Two. Different defects in different functions (a lost assignment in the trie, against a missing call
at start-up), and each test passes with its own patch alone on `master`. 38's effect is only fully
visible under clang with 37 also applied, which the texts say. Filing them together would tie a
one-line fix to the larger trie change.

## Effect on package 29

29's test (`memory/object_pointer_readonly.c`) checks `\object_pointer(stdin)` (`IN`). Under
`-m bittree` it passes only with 29, 37 and 38 together (table in
[`./frama-c-eacsl-bittree-lookup-uninitialized.md`](./frama-c-eacsl-bittree-lookup-uninitialized.md),
"Effect on package 29"): `IN` needs 38 and 29, `RO_T` and `RO_S` need 37. The suite runs 29's test with
the segment model, so 29 does not depend on 37 or 38.

## Tracker

Searched on 2026-11-17 (`pub/frama-c`, issues and merge requests, all states) for `safe location`,
`collect_safe_locations`, `bittree`, `memory-model`. No duplicate.
