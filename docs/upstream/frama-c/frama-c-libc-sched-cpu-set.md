# Frama-C libc: `<sched.h>` has no `cpu_set_t`, `CPU_*` or `sched_{set,get}affinity` (draft 46)

- **Upstream index:** [`./README.md`](./README.md)
- **Issue text:** [`./filing/46-libc-sched-cpu-set-issue.md`](./filing/46-libc-sched-cpu-set-issue.md)
- **Reproducer:** [`./repro/46-libc-sched-cpu-set.c`](./repro/46-libc-sched-cpu-set.c)
- **Pipeline entry:** [`../../troubleshooting/kernel-and-stubs.md`](../../troubleshooting/kernel-and-stubs.md) (the `cpu_set_t` symptom)

**Status:** drafted on 2026-11-19 and not filed. Listed in the annex of [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832) (ref `46`) since 2026-11-20. There is no issue, merge request or patch.

## Summary

Frama-C's libc `share/libc/sched.h` declares `struct sched_param` and the scheduler calls. It has none of the glibc CPU-affinity interface, which glibc declares under `__USE_GNU`:

- the type `cpu_set_t`;
- the macros `CPU_SETSIZE`, `CPU_SET`, `CPU_CLR`, `CPU_ISSET`, `CPU_ZERO`, `CPU_COUNT`, their `_S` forms and `CPU_ALLOC_SIZE`;
- the functions `sched_setaffinity` and `sched_getaffinity`.

So any source that pins a thread or process to CPUs stops at parse time with `User Error: syntax error`, even with `_GNU_SOURCE` defined. Without `-no-frama-c-stdlib` there is no way around it: `share/libc` comes before the user's `-I` directories, so the user cannot shadow `sched.h`.

## Found on

nginx 1.31.9, pipeline run `nginx-1.31.9/run-1` (2026-11-19). nginx's `configure` detects `sched_setaffinity` on glibc, and `src/os/unix/ngx_setaffinity.h:16` declares `typedef cpu_set_t ngx_cpuset_t;`. Frama-C parsed neither of nginx's units, so Phase 0 stopped with `no_unit_parsed`.

## Reproduction

[`./repro/46-libc-sched-cpu-set.c`](./repro/46-libc-sched-cpu-set.c), run with `frama-c -machdep gcc_x86_64 46-libc-sched-cpu-set.c`:

| Version | Frama-C | `gcc -fsyntax-only -Wall` |
| :--- | :--- | :--- |
| `34.0~beta (Selenium)`, `framac-analysis:latest` | rc 1, `46-libc-sched-cpu-set.c:14: User Error: syntax error ... before or at token: mask` | rc 0 |
| `35.0~~dev (Bromine)`, `master` `b80fcac74f` (`framac-master-audit:b80fcac`) | rc 1, the same error | rc 0 |

Both were run by the supervisor on 2026-11-19 with `--network none`.

## What the pipeline does meanwhile

`templates/fc_stubs/fc_compat_types.h` (`cb78e8b`) declares the interface in its `__fc_libc` branch, guarded by `#ifndef CPU_SETSIZE` so that it steps aside when a release ships it:

- `cpu_set_t` with glibc's x86_64 layout: 16 `unsigned long` words, 128 bytes;
- the macros, written without casts so that WP proves code that uses them;
- contracts with `assigns` for both functions. `sched_getaffinity` initializes the mask only on success.

The tests compare the layout and 223,498 macro evaluations with glibc's. The same commit adds three more `__fc_libc` gaps that nginx hit next: `struct in_pktinfo`, `struct tcp_info`, and Linux `IP_`/`TCP_` constants such as `IP_BIND_ADDRESS_NO_PORT`. These could make a second report. They are not part of this one.

## Not done

- No patch against `share/libc/sched.h`, and no test under `tests/libc`.
- Live duplicate check on `pub/frama-c` (2026-11-20, `glab api` searches `cpu_set_t`, `sched_setaffinity`, `sched.h`): no matches.
- Filing needs the owner's go-ahead.
