# E-ACSL: `eacsl_builtin_memcmp` (`--libc-replacements`) falsely aborts on overlapping or identical buffers with `memcpy: overlapping memory areas`

**Filed upstream on 2026-11-15:** issue [#2803](https://git.frama-c.com/pub/frama-c/-/work_items/2803), merge request [!34](https://git.frama-c.com/pub/frama-c/-/merge_requests/34).

Draft for the Frama-C tracker (https://git.frama-c.com/pub/frama-c/-/issues). Issue 17 of this
folder and of the master catalog
([`./frama-c-e-acsl-issues.md`](./frama-c-e-acsl-issues.md)).

**Filing package:** [issue](./filing/17-eacsl-memcmp-overlapping-buffers-issue.md), [MR](./filing/17-eacsl-memcmp-overlapping-buffers-mr.md), [reproducer](./repro/17-eacsl-memcmp-overlapping-buffers.sh), [patch](./patches/17-eacsl-memcmp-overlapping-buffers.patch)

## Summary

Under `e-acsl-gcc --libc-replacements` (`frama-c -e-acsl -e-acsl-replace-libc-functions`), any call
to `memcmp(s1, s2, n)` with `n > 0` where `[s1, s1 + n)` and `[s2, s2 + n)` overlap, including
`memcmp(p, p, n)` or comparing two overlapping slices of the same buffer, aborts at run time:

```
memcpy: overlapping memory areas
Aborted (core dumped)
```

In ISO C (C99/C11/C17/C23 7.24.4.1), `int memcmp(const void *s1, const void *s2, size_t n)` only
reads `s1` and `s2`, carries no `restrict` qualifier on either parameter, and is well-defined on
identical or overlapping objects. By contrast, `eacsl_builtin_strcmp` and `eacsl_builtin_strncmp` in
the same file do not call `validate_overlapping_spaces`.

Found 2026-11-14 in QCBOR `run-6`
([`../../runs/2026-11-14-qcbor-run6-supervision.md`](../../runs/2026-11-14-qcbor-run6-supervision.md))
when `UsefulInputBuf_Compare` compared two caller-selected sub-ranges of the same `UsefulInputBuf`
via `UsefulBuf_Compare` -> `memcmp`, producing a false `separation` crash candidate
(`unknown#UsefulBuf_Compare::separation::357c824f07`).

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `3dff90fc70`, image `framac-master-audit:3dff90f` | **aborts (exit 134)** |
| `34.0~beta (Selenium)`, image `framac-analysis:fc34` | **aborts (exit 134)** |

## Reproduction

[`./repro/17-eacsl-memcmp-overlapping-buffers.c`](./repro/17-eacsl-memcmp-overlapping-buffers.c),
run by [`./repro/17-eacsl-memcmp-overlapping-buffers.sh`](./repro/17-eacsl-memcmp-overlapping-buffers.sh):

```c
#include <string.h>

int main(void) {
  char buf[8] = "abababa";
  int same = memcmp(buf, buf, 4);        /* identical ranges */
  int overlap = memcmp(buf, buf + 2, 4); /* overlapping ranges */
  return (same == 0 && overlap == 0) ? 0 : 1;
}
```

On `master`:

```
e-acsl-gcc exit code: 0
prog (not instrumented) exit code: 0
memcpy: overlapping memory areas
prog.e-acsl exit code: 134
```

Each of the two calls aborts on its own. `memcmp(buf, buf + 4, 3)` (disjoint) and
`memcmp(buf, buf, 0)` exit 0 on `master` (`disjoint_spaces` treats zero-length ranges as
disjoint).

## Analysis

`plugins/e-acsl/share/e-acsl/libc_replacements/e_acsl_string.c` on `master` `3dff90fc70`, lines
237-250:

```c
int eacsl_builtin_memcmp(const void *s1, const void *s2, size_t n) {
  validate_allocated_space((void *)s1, n, "memcmp", "space 1 ");
  validate_allocated_space((void *)s2, n, "memcmp", "space 2 ");
  validate_overlapping_spaces((uintptr_t)s1, n, (uintptr_t)s2, n, "memcpy");
  return memcmp(s1, s2, n);
}

void *eacsl_builtin_memmove(void *dest, const void *src, size_t n) {
  validate_allocated_space((void *)src, n, "memcmp", "source space ");
  validate_writeable_space((void *)dest, n, "memcmp", "destination space ");
  ...
```

1. `eacsl_builtin_memcmp` copied the overlap check (line 240) from `eacsl_builtin_memcpy`, function
   name included. `memcmp` has no non-overlap requirement. This is the bug.
2. Unrelated diagnostics name the wrong function: `eacsl_builtin_memmove` passes `"memcmp"` (lines
   245-246), `eacsl_builtin_strcpy` passes `"strlen"` (lines 142 and 145), `eacsl_builtin_strncat`
   passes `"strcat"` (lines 201 and 210). They are genuine but cosmetic: a `memmove` into a freed
   buffer reports `memcmp: destination space  space unallocated or cannot be written` on `master`.
   They are kept out of the patch (one logical change per MR) and listed in the issue text as a
   possible follow-up.

## Fix

Patch: [`./patches/17-eacsl-memcmp-overlapping-buffers.patch`](./patches/17-eacsl-memcmp-overlapping-buffers.patch)
(subject `[e-acsl] memcmp replacement: do not reject overlapping arguments`, branch
`fix/eacsl-memcmp-overlap` from `3dff90fc70`): removes line 240. The checks that both ranges are
allocated stay.

Regression test `plugins/e-acsl/tests/builtin/memcmp.c`: identical, overlapping and disjoint
ranges of one array, results asserted. The `builtin` suite is the one for the libc replacements
(`test_config`: `-e-acsl-replace-libc-functions`; `test_config_dev`:
`--libc-replacements --full-mtracking`), and it had tests for `memcpy`, `strcat`, `strcmp`,
`strcpy` and `strlen` but none for `memcmp`. New oracles `memcmp.0.res.oracle` and
`gen_memcmp.0.c`.

## Validation

Built from `3dff90fc70` with the patch in a copy of `framac-master-audit:3dff90f`
(`dune build @install --release`, `dune install`).

| Check | `master` | Patched |
|---|---|---|
| Reproducer | `memcpy: overlapping memory areas`, exit 134 | exit 0 |
| `builtin/memcmp.c`, `dev` configuration | same abort, test fails | pass |
| ptests, every suite, default and `dev` configurations (`format`: default only, see below) | all pass | only difference: the new test (oracles added); then all pass |
| `clang-format` 19 (`--dry-run -Werror`) on the changed C files | | clean |
| `git diff --check` | | clean except the new oracles (trailing space after `Warning:`, trailing blank line: the ptests output format, as in every existing oracle) |
| `git apply --check` on `3dff90fc70` | | clean |

`format`: on `master` (unpatched) in this image, `format/printf.c` in the `dev` configuration stops
making progress after its 28th check and was killed after 90 minutes, so the `dev` configuration of
`format` was not compared; its default configuration matches the oracles on `master` and with the
patch.

`make check-lint` itself was not run (the build tree in the image is not a Git checkout); the
`clang-format` check above is what it runs on these files.

## Workaround

Without patching the installed RTL, a build using `--libc-replacements` can either pass
`-Wl,--wrap=__e_acsl_builtin_memcmp` with a wrapper that checks readable validity via
`__e_acsl_valid_read(s1, n, (void *)s1, NULL)` and `__e_acsl_valid_read(s2, n, (void *)s2, NULL)`
before calling `memcmp(s1, s2, n)` (when `n > 0`), or rewrite `__e_acsl_builtin_memcmp(` calls in
the generated `instrumented.c` between Stage 1 (`e-acsl-gcc -n`) and Stage 2 (`e-acsl-gcc -C`).
Disabling `--libc-replacements` (`--no-libc-checks` in the pipeline) also avoids the false abort at
the cost of dropping all other `string.h` / format-string runtime checks.

## Tracker

Not filed at the time of writing (see the filing note at the top). No issue in the 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)) mentions
`eacsl_builtin_memcmp`, `memcmp` with E-ACSL, or `overlapping memory areas`.
