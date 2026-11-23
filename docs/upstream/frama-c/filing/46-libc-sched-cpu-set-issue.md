# [Libc] `<sched.h>` lacks `cpu_set_t`, the `CPU_*` macros and `sched_{set,get}affinity`

<!-- Everything below this line is the issue description. -->

### Summary

Frama-C's libc `<sched.h>` declares `struct sched_param` and the POSIX scheduler functions, but has
none of glibc's CPU-affinity interface: `cpu_set_t`, `CPU_SETSIZE`, the `CPU_*` and `CPU_*_S`
macros (`CPU_ZERO`, `CPU_SET`, `CPU_CLR`, `CPU_ISSET`, `CPU_COUNT`, `CPU_EQUAL`, `CPU_AND`,
`CPU_OR`, `CPU_XOR`, `CPU_ALLOC_SIZE`), or `sched_setaffinity` / `sched_getaffinity`. Linux C code
that pins processes or threads to CPUs (for example nginx's `src/os/unix/ngx_setaffinity.h`)
therefore fails to parse even when `_GNU_SOURCE` is defined. Because `FRAMAC_SHARE/libc` precedes
user `-I` directories in the preprocessor command, a user cannot shadow `<sched.h>` without
dropping the Frama-C standard library altogether.

### Steps to reproduce the issue

`repro.c`:

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

```sh
frama-c -machdep gcc_x86_64 repro.c
```

### Expected behaviour

The file parses (and can be analysed with Eva and WP), matching `gcc -fsyntax-only -Wall -Wextra repro.c`
(exit status `0` with glibc 2.41). `<sched.h>` provides:

- `__cpu_mask`, `__CPU_SETSIZE` (`1024`), `__NCPUBITS` (`8 * sizeof(__cpu_mask)`), `CPU_SETSIZE`,
  and `cpu_set_t` matching glibc's layout (128 bytes on both 32-bit and 64-bit x86);
- the `CPU_*` and `CPU_*_S` macros (`CPU_ZERO`, `CPU_SET`, `CPU_CLR`, `CPU_ISSET`, `CPU_COUNT`,
  `CPU_EQUAL`, `CPU_AND`, `CPU_OR`, `CPU_XOR`, and `CPU_ALLOC_SIZE`), written without `void *`
  pointer casts so WP's `Typed` memory model accepts them and without out-of-bounds array-index
  alarms in Eva for dynamically sized sets (`setsize > sizeof(cpu_set_t)`);
- contracts for `sched_setaffinity`, `sched_getaffinity` (initializing the mask only on success and
  assigning `errno` like the rest of `share/libc/sched.h`), and `__sched_cpucount`.

### Actual behaviour

```text
[kernel] Parsing repro.c (with preprocessing)
[kernel] repro.c:6: User Error: 
  syntax error:
  Location: "repro.c", line 6, before or at token: mask
  4     int pin_to_cpu0(void)
  5     {
  6       cpu_set_t mask;
                   ^
  7       CPU_ZERO(&mask);
  8       CPU_SET(0, &mask);
[kernel] Frama-C aborted: invalid user input.
```

Exit status: `1`. The same error occurs with the default machdep (`x86_32`), and on `34.0~beta`.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at `189053d4a2`; also 34.0~beta (Selenium), same output
- Plug-in used: kernel (Frama-C libc)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

I hit this on nginx 1.31.9: its `configure` detects `sched_setaffinity` on glibc, so
`src/os/unix/ngx_setaffinity.h` declares `typedef cpu_set_t ngx_cpuset_t;` and
`src/os/unix/ngx_setaffinity.c` uses `CPU_SETSIZE`, `CPU_ZERO`, `CPU_SET`, `CPU_ISSET`, and
`sched_setaffinity`.

**Cause.** `share/libc/sched.h` (lines 1-82 on `189053d4a2`) only provides `struct sched_param`,
`SCHED_{OTHER,FIFO,RR,SPORADIC}`, and the seven POSIX `sched_*` declarations. It has no CPU-set
types, macros, or affinity functions.

**Two design points for the maintainers:**

1. **Feature-test guard.** In glibc 2.41, `<sched.h>` exposes `CPU_*` and `sched_{set,get}affinity`
   under `#ifdef __USE_GNU`, which glibc's `<features.h>` defines when `_GNU_SOURCE` is set.
   Frama-C's `share/libc/features.h` does not currently map `_GNU_SOURCE` to `__USE_GNU`, and
   existing GNU extensions in `share/libc/` (`pthread.h`, `unistd.h`, `errno.h`, `fcntl.h`,
   `string.h`) are declared unconditionally under a `// GNU extensions` comment. A proposed patch
   therefore declares the CPU-affinity interface unconditionally under `// Non-POSIX; GNU extensions`;
   let me know if you prefer `#ifdef _GNU_SOURCE` or adding a `_GNU_SOURCE` -> `__USE_GNU` mapping
   in `share/libc/features.h`.
2. **`CPU_ZERO` / `CPU_ZERO_S` and omitted symbols.** glibc implements `CPU_ZERO` / `CPU_ZERO_S`
   with `__builtin_memset`, which WP's `Typed` model rejects (`Cast with incompatible pointers types`
   from `cpu_set_t *` to `void *`). Using an explicit-zero compound literal for `CPU_ZERO` (sized
   via `__FC_ULONG_MAX` for both 32-bit and 64-bit machdeps) and a contracted
   `__FC_EXTERN_FOR_MACRO(CPU_ZERO_S)` helper `__fc_cpu_zero_s` for non-default `setsize` keeps Eva
   exact on fixed sets, alarm-free on dynamic sets, and 100% provable in WP. `CPU_ALLOC` /
   `CPU_FREE` (`__sched_cpualloc` / `__sched_cpufree`), `sched_getcpu`, `clone`, `unshare`, and
   `setns` are omitted for now.

**Related.** #2828 discusses Linux-specific gaps in Frama-C's libc; this issue is specific to the
existing `<sched.h>` header. A validated merge request with the `<sched.h>` additions and a
`tests/libc/sched_cpu_set.c` test (covering `x86_32` and `x86_64`) is ready to follow.

The analysis and fix were prepared with LLM assistance (Antigravity / Gemini); I reviewed them and
ran the reproducer and tests described above.
