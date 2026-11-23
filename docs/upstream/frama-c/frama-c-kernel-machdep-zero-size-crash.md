# Kernel: custom YAML machdep with non-positive type size or alignment crashes with `Z.shift_left` `Invalid_argument`

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 85 of this folder, drafted on 2026-11-23. Filing remains paused pending the
maintainers' reply on [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/85-kernel-machdep-zero-size-crash-issue.md),
[MR text](./filing/85-kernel-machdep-zero-size-crash-mr.md),
[reproducer](./repro/85-kernel-machdep-zero-size-crash.sh) with its
[C file](./repro/85-kernel-machdep-zero-size-crash.c), and
[patch](./patches/85-kernel-machdep-zero-size-crash.patch) (validated on `master` `189053d4a2`).

## Summary

Loading a custom YAML machdep file with `sizeof_int: 0` or `sizeof_long: -1` crashes Frama-C with
`Unexpected error (Invalid_argument("Z.shift_left: count argument must be positive"))` (exit 125)
in `Machdep.max_val` (`src/kernel/internals/runtime/machdep.ml:451`). Non-positive alignments for
concrete scalar/pointer types (`alignof_ptr: 0`) are accepted without error.

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **crashes** (`sizeof_int_0` & `sizeof_long_neg` exit 125, `alignof_ptr_0` exit 0, `RESULT: bug present (3 of 3 cases fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **crashes**, identical backtrace (`RESULT: bug present (3 of 3 cases fail)`) |
| `master` `189053d4a2` + [`./patches/85-kernel-machdep-zero-size-crash.patch`](./patches/85-kernel-machdep-zero-size-crash.patch) | **fixed** (all 3 cases exit 1 with clean `User Error: Error during machdep parsing`, `RESULT: fixed`) |

Debian 13 (trixie; glibc 2.41, gcc 14.2.0), OCaml 5.5.

## Root cause

`Machdep.mach_of_yaml` (`src/kernel/internals/runtime/machdep.ml:102`) derives YAML decoding
without validating positivity of concrete scalar/pointer `sizeof_*` and `alignof_*` fields. When
`Machdep.gen_std_min_max` (line 538) passes `8 * mach.sizeof_int` (`0`) to `Machdep.max_val` (line
451), `to_shift` becomes `-1` and `Z.shift_left Z.one (-1)` raises `Invalid_argument`.

## Fix and validation

Patch [`./patches/85-kernel-machdep-zero-size-crash.patch`](./patches/85-kernel-machdep-zero-size-crash.patch):
one commit (`11e49ed1fd`) on `master` `189053d4a2`, 2 files (`src/kernel/internals/runtime/machdep.ml`
and Cram test `tests/misc/machdep.t/run.t`).

- Wraps `mach_of_yaml` with `validate_mach` requiring strictly positive (`> 0`) values for the 16
  concrete scalar/pointer `sizeof_*` and `alignof_*` fields (`short`, `int`, `long`, `longlong`,
  `ptr`, `float`, `double`, `longdouble`), while leaving optional/sentinel fields (`sizeof_void`,
  `sizeof_fun`, `alignof_void`, `alignof_fun`, `alignof_aligned`, `alignof_max_align_t`,
  `max_extended_alignment`, `gcc_alignof_*`) unrestricted.
- Validated on 2026-11-23 in `framac-master-audit:189053d`:
  - Cram test `tests/misc/machdep.t` fails on unpatched `master`, passes with patch.
  - Full `./dev/test.sh -p tests/misc -- -j 2` passes with zero diffs on existing oracles.
  - `./dev/check-files.sh -p HEAD~1` passes (`Lint 2 file(s)`).
  - Standalone reproducer flips from `RESULT: bug present (3 of 3 cases fail)` (exit 1) to
    `RESULT: fixed` (exit 0).
- Local `opam/` queue recommendation: **NO** (triggered only by invalid custom YAML machdep files).
