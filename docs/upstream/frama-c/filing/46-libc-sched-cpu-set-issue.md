# Issue 46 (draft): libc `sched.h` lacks `cpu_set_t`, the `CPU_*` macros and `sched_{set,get}affinity`

- **Analysis:** [`../frama-c-libc-sched-cpu-set.md`](../frama-c-libc-sched-cpu-set.md)
- **Reproducer:** [`../repro/46-libc-sched-cpu-set.c`](../repro/46-libc-sched-cpu-set.c)

Not filed. The paste-ready text follows.

---

**Title:** libc: `sched.h` lacks `cpu_set_t`, the `CPU_*` macros and `sched_setaffinity`/`sched_getaffinity` (`_GNU_SOURCE`)

### Summary

Frama-C's libc `<sched.h>` has no `cpu_set_t`, no `CPU_SETSIZE` / `CPU_SET` / `CPU_CLR` / `CPU_ISSET` / `CPU_ZERO` / `CPU_COUNT` (or their `_S` forms and `CPU_ALLOC_SIZE`), and no `sched_setaffinity` / `sched_getaffinity`. glibc declares them under `_GNU_SOURCE`. Code that sets CPU affinity, nginx's `src/os/unix/ngx_setaffinity.h` for example, therefore fails to parse. A user cannot shadow the header, because `share/libc` comes before the `-I` directories in the preprocessor command.

### Steps to reproduce

```c
#define _GNU_SOURCE
#include <sched.h>

int pin_to_cpu0(void)
{
  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET(0, &mask);
  return sched_setaffinity(0, sizeof(mask), &mask);
}
```

```
$ frama-c -machdep gcc_x86_64 repro.c
[kernel] Parsing repro.c (with preprocessing)
[kernel] repro.c:14: User Error:
  syntax error:
  Location: "repro.c", line 14, before or at token: mask
[kernel] Frama-C aborted: invalid user input.
$ gcc -fsyntax-only -Wall repro.c; echo $?
0
```

(Line 14 is `cpu_set_t mask;` in the attached file, which starts with a comment.)

### Expected

The file parses. `<sched.h>` provides, under `__USE_GNU`:

- `cpu_set_t` with glibc's layout (`__cpu_mask __bits[1024 / (8 * sizeof(__cpu_mask))]`, 128 bytes on x86_64);
- the `CPU_*` macros, written so that WP can use them, without casts through `void *`;
- specifications with `assigns` clauses for `sched_setaffinity` and `sched_getaffinity`, where `sched_getaffinity` initializes the mask only on success.

### Versions

- 34.0~beta (Selenium)
- `master` `b80fcac74f` (35.0~~dev)

Both with `-machdep gcc_x86_64`.
