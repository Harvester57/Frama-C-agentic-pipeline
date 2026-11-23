# [libc] add cpu_set_t, CPU_* macros and sched_{set,get}affinity to sched.h

- Source branch: `fix/libc-sched-cpu-set` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/46-libc-sched-cpu-set.patch`](../patches/46-libc-sched-cpu-set.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`share/libc/sched.h` declares `struct sched_param` and the POSIX scheduler functions, but has none
of glibc's CPU-affinity interface (`cpu_set_t`, `CPU_SETSIZE`, the `CPU_*` / `CPU_*_S` macros,
`CPU_ALLOC_SIZE`, `sched_setaffinity`, `sched_getaffinity`). Linux code using CPU affinity (such as
nginx's `src/os/unix/ngx_setaffinity.h`) stops at parse time with a syntax error on `cpu_set_t`.

## Change

**`share/libc/sched.h`:**

- Includes `"__fc_define_size_t.h"` (matching glibc's `<sched.h>`, which provides `size_t`).
- Adds glibc's CPU-set types and constants under `// Non-POSIX; GNU extensions`:
  - `typedef unsigned long int __cpu_mask;`, `#define __CPU_SETSIZE 1024`,
    `#define __NCPUBITS (8 * sizeof(__cpu_mask))`, `#define CPU_SETSIZE __CPU_SETSIZE`;
  - named `typedef struct __fc_cpu_set_t { __cpu_mask __bits[__CPU_SETSIZE / __NCPUBITS]; } cpu_set_t;`
    (named struct tag for `check_libc_anonymous_tags`, 128 bytes on both `x86_32` and `x86_64`).
- Adds the `CPU_*` and `CPU_*_S` macros (`CPU_ZERO`, `CPU_SET`, `CPU_CLR`, `CPU_ISSET`, `CPU_COUNT`,
  `CPU_EQUAL`, `CPU_AND`, `CPU_OR`, `CPU_XOR`, their `_S` forms, and `CPU_ALLOC_SIZE`):
  - accesses words through `(&(cpusetp)->__bits[0])[__CPUELT(__fc_cpu)]` instead of a
    `(__cpu_mask *)` cast, so WP's `Typed` model accepts them cleanly and Eva does not raise
    out-of-bounds array-index alarms on dynamically sized sets (`setsize > sizeof(cpu_set_t)`);
  - implements `CPU_ZERO` with an explicit-zero compound literal (16 words for 64-bit `unsigned long`
    and 32 words for 32-bit `unsigned long` via `__FC_ULONG_MAX`, with `{{0}}` fallback), so both
    Eva (exact `{0}`) and WP (all words proved zero and initialized) handle it without `void *`
    casts;
  - implements `CPU_ZERO_S` by dispatching `setsize == sizeof(cpu_set_t)` to `CPU_ZERO` and other
    sizes to `__FC_EXTERN_FOR_MACRO(CPU_ZERO_S) void __fc_cpu_zero_s(size_t setsize, cpu_set_t *setp)`.
- Adds ACSL contracts (following `tests/libc/check_libc_naming_conventions.ml`, `check_const.ml`,
  and `check_assigns.ml`) for `__fc_cpu_zero_s`, `__sched_cpucount`, `sched_setaffinity`, and
  `sched_getaffinity`. Both `sched_setaffinity` and `sched_getaffinity` assign `errno` like the
  existing functions in `sched.h`, and `sched_getaffinity` guarantees `\initialized` on `mask` only
  when `\result == 0`.
- Leaves out `CPU_ALLOC` / `CPU_FREE` (`__sched_cpualloc` / `__sched_cpufree`), `sched_getcpu`,
  `clone`, `unshare`, and `setns` for now (`CPU_ALLOC` / `CPU_FREE` allocate heap memory and would
  need a `share/libc/sched.c` body for Eva).

**New test `tests/libc/sched_cpu_set.c` with two oracles (`x86_32` and `x86_64`):**

- Exercises `CPU_SETSIZE`, `sizeof(cpu_set_t)`, `CPU_ALLOC_SIZE(1024)` / `(2048)`, `CPU_ZERO`,
  `CPU_SET`, `CPU_CLR`, `CPU_ISSET`, `CPU_COUNT`, `CPU_EQUAL`, `CPU_OR`, `CPU_AND`, `CPU_XOR`,
  `const cpu_set_t *` arguments, out-of-range CPU numbers (ignored without out-of-bounds access),
  `sched_setaffinity` (including `errno == EINVAL` reachability), `sched_getaffinity`, and the
  dynamic `_S` macros on a 2048-CPU heap allocation.
- Every assertion and precondition is valid with 0 alarms on both `x86_32` and `x86_64`, and the
  test file passes `gcc -fsyntax-only -Wall -Wextra -Wpedantic` against host glibc.
- No existing oracle changes (including `tests/libc/oracle/fc_libc.*.res.oracle` and
  `tests/libc/oracle/sched_h.0.res.oracle`).

**Two points open to maintainer preference:**

- Feature-test guard: declared unconditionally to match the other GNU extensions in `share/libc/`
  (`pthread.h`, `unistd.h`, `errno.h`, `fcntl.h`, `string.h`), since `share/libc/features.h` does
  not define `__USE_GNU` from `_GNU_SOURCE`. Happy to guard under `#ifdef _GNU_SOURCE` if preferred.
- `__fc_cpu_zero_s`: declared only (no C body, like `FD_ZERO` in `share/libc/sys/select.h`), so
  `e-acsl-gcc -L` on a program using `CPU_ZERO_S` with a non-default `setsize` would lack a link
  symbol unless a body is added.

## Testing

Validated on a fresh build of `master` `189053d4a2` (Debian 13, OCaml 5.5 switch, gcc 14.2.0, glibc 2.41):

- **Reproducer from the issue (`46-libc-sched-cpu-set.sh`):** before, all 4 checks fail with
  `syntax error` (`RESULT: bug present`); after installing the patched tree, all 4 checks pass on
  both `gcc_x86_64` and `x86_32` (`RESULT: fixed`).
- **New test on unpatched `master`:** `tests/libc/sched_cpu_set.c` fails with
  `sched_cpu_set.c:16: User Error: syntax error ... before or at token: mask`. With the patch, both
  `x86_32` and `x86_64` pass (`exit=0`).
- **ptests, default configuration:** both suites pass with zero diffs:
  - `tests/libc` (including `fc_libc`, `sched_h`, `check_libc_anonymous_tags`,
    `check_libc_naming_conventions`, `check_assigns`, `check_const`,
    `check_parsing_individual_headers`, `check_full_libc.sh`, and `check_header_guards.sh`);
  - `plugins/e-acsl`.
- **Host glibc check:** `gcc -fsyntax-only -Wall -Wextra -Wpedantic tests/libc/sched_cpu_set.c`
  passes cleanly.
- **WP:** spot-checked `CPU_ZERO`, `CPU_ZERO_S`, `CPU_SET`, `CPU_CLR`, `CPU_ISSET`, `CPU_COUNT`,
  `sched_setaffinity`, and `sched_getaffinity` under `-wp -wp-rte` on both `x86_64` and `x86_32`:
  81 / 81 goals proved on both machdeps with zero incompatible-pointer-cast warnings.
- **`./dev/check-files.sh -p HEAD~1`:** clean (`Lint 4 file(s)`, `exit=0`).
- **Not run:** the default ptests of plugins other than `tests/libc` and `plugins/e-acsl`, E-ACSL's
  `dev` configuration on unrelated tests, and cram tests.

The analysis and fix were prepared with LLM assistance (Antigravity / Gemini); I reviewed them and
ran the reproducer and tests described above.
