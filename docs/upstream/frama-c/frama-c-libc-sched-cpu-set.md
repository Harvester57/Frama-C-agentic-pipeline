# Frama-C libc: `<sched.h>` lacks `cpu_set_t`, `CPU_*` and `sched_{set,get}affinity` (draft 46)

- **Upstream index:** [`./README.md`](./README.md)
- **Issue text:** [`./filing/46-libc-sched-cpu-set-issue.md`](./filing/46-libc-sched-cpu-set-issue.md)
- **MR text:** [`./filing/46-libc-sched-cpu-set-mr.md`](./filing/46-libc-sched-cpu-set-mr.md)
- **Patch:** [`./patches/46-libc-sched-cpu-set.patch`](./patches/46-libc-sched-cpu-set.patch)
- **Reproducer:** [`./repro/46-libc-sched-cpu-set.sh`](./repro/46-libc-sched-cpu-set.sh) ([`./repro/46-libc-sched-cpu-set.c`](./repro/46-libc-sched-cpu-set.c))
- **Pipeline entry:** [`../../troubleshooting/kernel-and-stubs.md`](../../troubleshooting/kernel-and-stubs.md) (the `cpu_set_t` symptom)

**Status:** full filing package (issue text, MR text, validated patch on `master` `189053d4a2`,
standalone `.sh`/`.c` reproducer) completed on 2026-11-22; **not filed** (filing remains paused
pending maintainer response in [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832),
where this item is listed under annex ref `46`).

## Summary

Frama-C's libc `share/libc/sched.h` declares `struct sched_param`, `SCHED_{OTHER,FIFO,RR,SPORADIC}`,
and the seven POSIX `sched_*` calls. It has none of glibc's CPU-affinity interface:

- the type `cpu_set_t` (and `__cpu_mask`, `__CPU_SETSIZE`, `__NCPUBITS`, `CPU_SETSIZE`);
- the macros `CPU_ZERO`, `CPU_SET`, `CPU_CLR`, `CPU_ISSET`, `CPU_COUNT`, `CPU_EQUAL`, `CPU_AND`,
  `CPU_OR`, `CPU_XOR`, their `_S` forms, and `CPU_ALLOC_SIZE`;
- the functions `sched_setaffinity`, `sched_getaffinity`, and `__sched_cpucount`.

Any source that pins a thread or process to CPUs stops at parse time with `User Error: syntax error`,
even with `_GNU_SOURCE` defined. Without `-no-frama-c-stdlib` there is no way to shadow `<sched.h>`,
because `share/libc` precedes user `-I` directories in the preprocessor command.

Note on feature-test guards: the initial rough draft suggested guarding under `__USE_GNU`, matching
glibc's `<sched.h>`. Inspecting `share/libc/features.h` on `master` `189053d4a2` showed that
Frama-C's `features.h` does **not** define `__USE_GNU` from `_GNU_SOURCE`, and existing GNU
extensions in `share/libc/` (`pthread.h`, `unistd.h`, `errno.h`, `fcntl.h`, `string.h`) are
declared unconditionally under `// GNU extensions`. Guarding under `#ifdef __USE_GNU` would leave
`#define _GNU_SOURCE; #include <sched.h>` broken unless `features.h` were changed too.

## Found on

nginx 1.31.9, pipeline run `nginx-1.31.9/run-1` (2026-11-19). nginx's `configure` detects
`sched_setaffinity` on glibc, and `src/os/unix/ngx_setaffinity.h:16` declares
`typedef cpu_set_t ngx_cpuset_t;`. Frama-C parsed neither of nginx's units, so Phase 0 stopped with
`no_unit_parsed`.

## Reproduction

[`./repro/46-libc-sched-cpu-set.sh`](./repro/46-libc-sched-cpu-set.sh) runs four checks (`basic`
on `gcc_x86_64`, `basic` on `x86_32`, `macros` on `gcc_x86_64`, and `dynamic_s` on `gcc_x86_64`)
against both `frama-c` and `gcc -fsyntax-only -Wall -Wextra`:

| Version | `46-libc-sched-cpu-set.sh` | `gcc -fsyntax-only -Wall -Wextra` |
| :--- | :--- | :--- |
| `34.0~beta (Selenium)`, `framac-analysis:latest` | rc 1, `RESULT: bug present (4 of 4 checks fail)` (`syntax error` on `cpu_set_t mask;`) | rc 0 (all 4 ok) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`), unpatched | rc 1, `RESULT: bug present (4 of 4 checks fail)` | rc 0 (all 4 ok) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` + [`./patches/46-libc-sched-cpu-set.patch`](./patches/46-libc-sched-cpu-set.patch) | rc 0, `RESULT: fixed` (4 of 4 ok) | rc 0 (all 4 ok) |

## Proposed patch and validation

[`./patches/46-libc-sched-cpu-set.patch`](./patches/46-libc-sched-cpu-set.patch) is one commit on
upstream `master` `189053d4a2` authored with the GitLab noreply address:

- **`share/libc/sched.h`:**
  - includes `"__fc_define_size_t.h"`;
  - defines `__cpu_mask`, `__CPU_SETSIZE` (`1024`), `__NCPUBITS`, `CPU_SETSIZE`, and named
    `struct __fc_cpu_set_t` (`typedef cpu_set_t`, 128 bytes on both `x86_32` and `x86_64`, passing
    `check_libc_anonymous_tags`);
  - defines `CPU_ZERO`, `CPU_SET`, `CPU_CLR`, `CPU_ISSET`, `CPU_COUNT`, `CPU_EQUAL`, `CPU_AND`,
    `CPU_OR`, `CPU_XOR`, their `_S` forms, and `CPU_ALLOC_SIZE` without `void *` casts (WP `Typed`
    compatible) and indexing via `(&(cpusetp)->__bits[0])[__CPUELT(__fc_cpu)]` (no out-of-bounds
    array-index alarms in Eva on sets larger than 1024 CPUs);
  - selects the 16-word or 32-word explicit-zero compound literal in `CPU_ZERO` via
    `__FC_ULONG_MAX` (with `{{0}}` fallback), and dispatches `CPU_ZERO_S` to `CPU_ZERO` for
    `sizeof(cpu_set_t)` and to `__FC_EXTERN_FOR_MACRO(CPU_ZERO_S) void __fc_cpu_zero_s(...)` for
    other sizes;
  - adds ACSL contracts for `__fc_cpu_zero_s`, `__sched_cpucount`, `sched_setaffinity`, and
    `sched_getaffinity` (all naming conventions, `const` rules, `assigns`, and `errno` matching the
    rest of `sched.h`). `CPU_ALLOC` / `CPU_FREE` (`__sched_cpualloc` / `__sched_cpufree`) are
    omitted for now.
- **`tests/libc/sched_cpu_set.c` + `tests/libc/oracle/sched_cpu_set.{0,1}.res.oracle`:**
  - Eva test run on both default (`x86_32`) and `-machdep x86_64`; every assertion and precondition
    is valid with 0 alarms, and `gcc -fsyntax-only -Wall -Wextra -Wpedantic` accepts the file.

Validated end-to-end on 2026-11-22 in `framac-master-audit:189053d` with
[`../../../tools/upstream_audit/revalidate.sh`](../../../tools/upstream_audit/revalidate.sh)
(`before 46` and `package 46`):

- `git am --keep-non-patch`: exit 0, zero mode changes, zero executable files;
- `A1 default` (`tests/libc/sched_cpu_set.c` on unpatched `master`): fails with `syntax error ... before or at token: mask`;
- `B1 default` & `B2 dev` (`tests/libc/sched_cpu_set.c` patched): exit 0;
- `C1 default` (`plugins/e-acsl`): exit 0;
- `C2 default` (`tests/libc`, including `fc_libc`, `sched_h`, and all `check_*` scripts): exit 0,
  zero existing oracles changed;
- `D lint` (`./dev/check-files.sh -p HEAD~1`): exit 0 (`Lint 4 file(s)`);
- `E` (`dune install` + `reproducer 46 (after)`): exit 0 (`RESULT: fixed`);
- WP spot check (`-wp -wp-rte` on `CPU_ZERO`, `CPU_ZERO_S`, `CPU_SET`, `CPU_CLR`, `CPU_ISSET`,
  `CPU_COUNT`, `sched_setaffinity`, `sched_getaffinity`): 81 / 81 goals proved on both `x86_64` and
  `x86_32`.

## Duplicate check

Live search on `pub/frama-c` via `glab api` (issues and merge requests, all states, queries
`cpu_set_t`, `sched_setaffinity`, `sched.h`, `CPU_SET`) re-run on 2026-11-22: only `#2832` (our own
overview discussion, annex ref `46`). No duplicates.

## What the pipeline does meanwhile

[`../../../templates/fc_stubs/fc_compat_types.h`](../../../templates/fc_stubs/fc_compat_types.h)
(`cb78e8b`) declares the interface in its `__fc_libc` branch, guarded by `#ifndef CPU_SETSIZE` so
that it steps aside when a Frama-C release ships it:

- `cpu_set_t` with glibc's x86_64 layout: 16 `unsigned long` words, 128 bytes;
- the macros, written without casts so that WP proves code that uses them;
- contracts with `assigns` for both functions. `sched_getaffinity` initializes the mask only on
  success.

The tests in [`../../../tests/test_fc_stub_repairs.py`](../../../tests/test_fc_stub_repairs.py)
compare the layout and 223,498 macro evaluations with glibc's. The same commit adds three more
`__fc_libc` gaps that nginx hit next (`struct in_pktinfo`, `struct tcp_info`, and Linux `IP_`/`TCP_`
constants such as `IP_BIND_ADDRESS_NO_PORT`), which are outside this report.

## Not done

- No issue filed, no branch pushed, no merge request opened (MR text holds `#<issue>`). Filing
  requires explicit owner go-ahead once `#2832` unpauses.
