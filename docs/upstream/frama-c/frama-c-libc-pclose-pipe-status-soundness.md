# Frama-C libc: `pclose` proves `\false` under WP (draft 72)

- **Upstream index:** [`./README.md`](./README.md)
- **Hunt candidate:** `L2` in [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md)
- **Issue text:** [`./filing/72-libc-pclose-pipe-status-soundness-issue.md`](./filing/72-libc-pclose-pipe-status-soundness-issue.md)
- **MR text:** [`./filing/72-libc-pclose-pipe-status-soundness-mr.md`](./filing/72-libc-pclose-pipe-status-soundness-mr.md)
- **Patch:** [`./patches/72-libc-pclose-pipe-status-soundness.patch`](./patches/72-libc-pclose-pipe-status-soundness.patch)
- **Reproducer:** [`./repro/72-libc-pclose-pipe-status-soundness.sh`](./repro/72-libc-pclose-pipe-status-soundness.sh) ([`./repro/72-libc-pclose-pipe-status-soundness.c`](./repro/72-libc-pclose-pipe-status-soundness.c))

**Status:** full filing package validated on `master` `189053d4a2` and `34.0~beta`; **not filed**
(filing remains paused pending maintainer response in
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832), annex ref `L2`). Recommended for
our local `opam/` patch queue (high-severity WP soundness defect).

## Summary

In `share/libc/stdio.h:607-634`, `predicate is_open_pipe{L}(FILE *stream);` omits its `reads`
clause and `pclose` assigns only `\result \from indirect:*stream;` while requiring
`is_open_pipe(stream)` and ensuring `!is_open_pipe(stream)`. WP interprets `is_open_pipe` as
reading nothing and derives a contradiction at every `pclose()` call, proving `\false` by Qed and
failing `-wp-smoke-tests` (`Doomed`).

## Diagnosis

1. **Missing `reads` clause (`share/libc/stdio.h:608`):** unlike `is_allocable` in
   `share/libc/__fc_alloc_axiomatic.h:20-21` (`reads __fc_heap_status;`) and
   `abs_clock_in_range`/`valid_clock_id` in `share/libc/time.h:224-228` (`reads __fc_time;`),
   `is_open_pipe` omits `reads`, so WP emits
   `Warning: No definition for 'is_open_pipe' interpreted as reads nothing`.
2. **Contradictory frame condition (`share/libc/stdio.h:629-633`):** `pclose` assigns no memory,
   so `is_open_pipe{Pre}(stream)` and `!is_open_pipe{Post}(stream)` are contradictory under ACSL
   frame semantics for any `reads` footprint.
3. **Sibling audit:** grepping every `predicate` in `share/libc/` confirms `is_open_pipe` is the
   only state-dependent predicate missing a `reads` clause. `closedir` (`share/libc/dirent.h:45-51`)
   assigns `*dirp` and is consistent.

## Fix and validation

[`./patches/72-libc-pclose-pipe-status-soundness.patch`](./patches/72-libc-pclose-pipe-status-soundness.patch)
is one commit on `master` `189053d4a2`:

- Adds `/*@ ghost __FC_EXTERN int __fc_pipe_status; */` in `share/libc/stdio.h`, adds
  `reads __fc_pipe_status;` to `is_open_pipe`, and assigns `__fc_pipe_status` in `popen` and
  `pclose`. Using a dedicated ghost variable rather than `*stream` preserves `is_open_pipe(p)`
  across intermediate `fread`/`fwrite`/`fgetc`/`fprintf` calls on the pipe.
- Adds `tests/libc/pclose_wp.c` (`-wp -wp-par 1 -wp-prover none -wp-print`), verifying that
  `\false` is no longer proved by Qed, no `reads nothing` warning is emitted, and `popen` ->
  `fread` -> `pclose` proves `open_pipe` by Qed.
- Validated on `framac-master-audit:189053d` (`189053d4a2`) and `framac-analysis:latest`
  (`34.0~beta`): reproducer flips `RESULT: bug present (2 of 3 checks fail)` -> `RESULT: fixed`,
  new test fails on unpatched `master` and passes patched, full `tests/libc` passes with zero
  existing oracle changes, `./dev/check-files.sh -p HEAD~1` passes, and stacks cleanly with
  [`./patches/76-libc-wchar-stdio-streams.patch`](./patches/76-libc-wchar-stdio-streams.patch) on
  `share/libc/stdio.h` in both orders.

## Duplicate check

Live read-only `glab api` search on `pub/frama-c` (project 780, issues and MRs, all states) for
`pclose`, `popen`, `is_open_pipe`, `pipe_streams`, plus `pub-frama-c_work_items_2026-11-09.csv`
and packages `01`-`50`: zero duplicates (only `#2832`).
