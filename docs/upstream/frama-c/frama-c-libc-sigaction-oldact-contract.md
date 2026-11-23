# Frama-C libc: `sigaction` `oldact` assigns and `\old` contract defects (draft 73)

- **Upstream index:** [`./README.md`](./README.md)
- **Hunt candidate:** `L3` in [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md)
- **Issue text:** [`./filing/73-libc-sigaction-oldact-contract-issue.md`](./filing/73-libc-sigaction-oldact-contract-issue.md)
- **MR text:** [`./filing/73-libc-sigaction-oldact-contract-mr.md`](./filing/73-libc-sigaction-oldact-contract-mr.md)
- **Patch:** [`./patches/73-libc-sigaction-oldact-contract.patch`](./patches/73-libc-sigaction-oldact-contract.patch)
- **Reproducer:** [`./repro/73-libc-sigaction-oldact-contract.sh`](./repro/73-libc-sigaction-oldact-contract.sh) ([`./repro/73-libc-sigaction-oldact-contract.c`](./repro/73-libc-sigaction-oldact-contract.c))

**Status:** full filing package validated on `master` `189053d4a2` and `34.0~beta`; **not filed**
(filing remains paused pending maintainer response in
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832), annex ref `L3`). Recommended for
our local `opam/` patch queue (stops Eva analysis on standard POSIX `sigaction` save-and-restore
and query patterns).

## Summary

In `share/libc/signal.h:247-253`, the `sigaction` contract assigns `*oldact \from &__fc_sigaction;`
(array address rather than entry value `__fc_sigaction[signum]`) and evaluates `oldact_assigned`
against the post-state `__fc_sigaction[signum]` instead of `\old(__fc_sigaction[signum])`. In Eva,
installing any non-null signal handler while saving `oldact` (single-call or two-call) emits
`[eva:ensures-false]` and stops propagation (`NON TERMINATING FUNCTION`), and querying an
installed handler with `act == NULL` marks `old.sa_handler == h1` invalid.

## Diagnosis

- `share/libc/signal.h:247`: `assigns *oldact \from &__fc_sigaction;` generates a garbled mix of
  `&__fc_sigaction` (also recorded in `tests/libc/oracle/signal_c_h.0.res.oracle:136`).
- `share/libc/signal.h:252-253`: `ensures oldact_assigned: oldact == \null || \subset({*oldact}, __fc_sigaction[signum]);`
  compares `*oldact` with the newly installed post-state handler instead of the previous action.
- Note on single-call trigger: installing an all-zero `struct sigaction b = {0}` does not stop Eva
  because `0` intersects the garbled mix; installing any non-null handler (`b.sa_handler = h1`)
  stops immediately with `[eva:ensures-false]` and `NON TERMINATING FUNCTION`.

## Fix and validation

[`./patches/73-libc-sigaction-oldact-contract.patch`](./patches/73-libc-sigaction-oldact-contract.patch)
is one commit on `master` `189053d4a2`:

- Changes `share/libc/signal.h:247` to `assigns *oldact \from __fc_sigaction[signum], indirect:signum;`
  and line 253 to `\subset({*oldact}, \old(__fc_sigaction[signum]));`.
- Adds `tests/libc/sigaction_oldact.c` + oracle and updates `tests/libc/oracle/signal_c_h.{0,1}.res.oracle`
  (removing the garbled-mix warning on `*oldact`).
- Validated on `framac-master-audit:189053d` (`189053d4a2`) and `framac-analysis:latest`
  (`34.0~beta`): reproducer flips `RESULT: bug present (3 of 3 checks fail)` -> `RESULT: fixed`,
  new test fails on unpatched `master` and passes patched, full `tests/libc` passes, and
  `./dev/check-files.sh -p HEAD~1` passes.

## Duplicate check

Live read-only `glab api` search on `pub/frama-c` (project 780, issues and MRs, all states) for
`sigaction`, `oldact`, `__fc_sigaction`, `sigaction oldact`, plus
`pub-frama-c_work_items_2026-11-09.csv` and packages `01`-`50`: zero duplicates (only `#2832`;
closed `#2756` is unrelated `sa_restorer`).
