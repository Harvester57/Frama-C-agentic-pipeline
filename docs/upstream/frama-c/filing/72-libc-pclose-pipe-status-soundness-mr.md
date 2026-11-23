# [libc] pclose: add __fc_pipe_status reads/assigns for is_open_pipe

- Source branch: `fix/libc-pclose-pipe-status-soundness` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/72-libc-pclose-pipe-status-soundness.patch`](../patches/72-libc-pclose-pipe-status-soundness.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

In `share/libc/stdio.h:607-634`, `predicate is_open_pipe{L}(FILE *stream);` has no `reads` clause
and `pclose` only assigns `\result` while requiring `is_open_pipe(stream)` and ensuring
`!is_open_pipe(stream)`. WP interprets `is_open_pipe` as reading nothing and derives a
contradiction at every `pclose()` call, proving `\false` by Qed and failing `-wp-smoke-tests`.

## Change

**`share/libc/stdio.h`:**

- Declares `/*@ ghost __FC_EXTERN int __fc_pipe_status; */` (following `__fc_heap_status` in
  `share/libc/__fc_alloc_axiomatic.h:17`).
- Adds `reads __fc_pipe_status;` to `predicate is_open_pipe{L}(FILE *stream)`.
- Adds `assigns __fc_pipe_status \from indirect:*command, indirect:*mode, __fc_pipe_status;` to
  `popen` and `assigns __fc_pipe_status \from indirect:*stream, __fc_pipe_status;` to `pclose`.
  Using a dedicated ghost state variable rather than `reads *stream` / `assigns *stream` ensures
  intermediate stream operations (`fread`, `fwrite`, `fgetc`, `fprintf`, etc.) do not invalidate
  `is_open_pipe(p)` before `pclose(p)`.

**New test `tests/libc/pclose_wp.c` (`-wp -wp-par 1 -wp-prover none -wp-print`):**

- Verifies that `check unreachable_false: \false` after `pclose(p)` is no longer proved by Qed
  (no `reads nothing` warning; `P_is_open_pipe` is parameterized by pre/post `fc_pipe_status`),
  while `open_pipe` in `read_then_close` (`popen` -> `fread` -> `pclose`) is proved by Qed.

## Testing

Validated on a fresh build of `master` `189053d4a2` (Debian 13, OCaml 5.5 switch, gcc 14.2.0, glibc 2.41):

- **Reproducer (`72-libc-pclose-pipe-status-soundness.sh`):** fails before on both `189053d4a2` and
  `34.0~beta` (`RESULT: bug present (2 of 3 checks fail)`); passes after installing the patch
  (`RESULT: fixed`).
- **New test on unpatched `master`:** `tests/libc/pclose_wp.c` fails on unpatched `master` and
  passes with the patch.
- **ptests, default configuration:** `tests/libc` (including `fc_libc`, `stdio_h`, and all
  `check_*` checks) passes with zero existing oracle diffs.
- **Stacking:** stacks cleanly with the `<wchar.h>` stream-declaration patch (which also modifies
  `share/libc/stdio.h`) via `git am --3way --keep-non-patch` in both orders.
- **`./dev/check-files.sh -p HEAD~1`:** clean (`exit=0`).
- **Not run:** unrelated plugin test suites outside `tests/libc`.

The analysis and fix were prepared with LLM assistance (Antigravity / Gemini); I reviewed them and
ran the reproducer and tests described above.
