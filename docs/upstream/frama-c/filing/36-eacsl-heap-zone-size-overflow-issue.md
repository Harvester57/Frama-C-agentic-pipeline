# [E-ACSL] e-acsl-gcc --zone-sizes heap:2048 or stack:2048 makes every run crash: the size in MB overflows int when converted to bytes

<!-- Everything below this line is the issue description. -->

### Summary

`e-acsl-gcc --zone-sizes` sets the sizes, in MB, of the memory spaces of the segment memory model. The runtime converts them to bytes with `N * MB`, where `MB` is the `int` constant `1024 * 1024`, so from 2048 MB the product overflows `int`. With `heap:2048` to `heap:4095` or `stack:2048`, every run of the monitored program crashes at start-up; from `heap:4096` the heap gets (N mod 4096) MB, so the first large `malloc` aborts with "Exceeded heap allocation limit of 4096MB"; `stack:4096` and above are silently ignored; `thread-stack:2048` makes `pthread_create` fail. Only lower bounds are checked, and the documentation gives no upper bound.

### Steps to reproduce the issue

`big.c`:

```c
#include <stdlib.h>
#include <string.h>

/* Allocates 2 MB on the heap and writes every byte. */
int main(int argc, char **argv) {
  size_t n = 2 * 1024 * 1024;
  char *p = malloc(n);
  if (!p)
    return 2;
  memset(p, 1, n);
  int r = p[n - 1] - 1;
  free(p);
  return r;
}
```

```sh
for z in heap:2047 heap:2048 heap:4096 heap:4097 stack:2048; do
  e-acsl-gcc -c --zone-sizes $z -o big.inst.c -O big big.c > build-$z.log 2>&1
  ./big.e-acsl; echo "$z: exit $?"
done
grep 'integer overflow' build-heap:2048.log
```

### Expected behaviour

Every run exits 0: a 2 GB or 4 GB heap is a valid request on a 64-bit target.

### Actual behaviour

With bash (paths before `segment_model/` shortened to `...`):

```text
heap:2047: exit 0
heap:2048: exit 139
bash: line 6: 71995 Segmentation fault      ./big.e-acsl
.../segment_model/e_acsl_segment_tracking.c:528: Exceeded heap allocation limit of 4096MB -- heap memory space moved. 
heap:4096: exit 134
bash: line 6: 72049 Aborted                 ./big.e-acsl
.../segment_model/e_acsl_segment_tracking.c:528: Exceeded heap allocation limit of 4097MB -- heap memory space moved. 
heap:4097: exit 134
bash: line 6: 72103 Aborted                 ./big.e-acsl
stack:2048: exit 139
bash: line 6: 72157 Segmentation fault      ./big.e-acsl
.../segment_model/e_acsl_shadow_layout.h:59:41: warning: integer overflow in expression of type ‘int’ results in ‘-2147483648’ [-Woverflow]
``` The same with `-G clang`, which prints no warning because `e-acsl-gcc` drops the warning flags there (#2810). heap:4095 crashes like heap:2048; stack:4096, 8192 and 65536 run but leave the stack limit unchanged. With `--concurrency`, `thread-stack:2048` makes `pthread_create` fail and `thread-stack:4096` is ignored.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 95408044f7; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** In `plugins/e-acsl/share/e-acsl/observation_model/segment_model/`:

- `e_acsl_shadow_layout.h:59`: `#define PGM_HEAP_SIZE (E_ACSL_HEAP_SIZE * MB)`, which sizes the heap mspace and its shadows through `get_heap_size()`;
- `e_acsl_segment_observation_model.c:324`: `increase_stack_limit(E_ACSL_STACK_SIZE * MB);`
- `e_acsl_shadow_concurrency.c:337,340`: `E_ACSL_THREAD_STACK_SIZE * MB`.

`MB` is `(1024 * KB)` in `internals/e_acsl_malloc.h`, an `int`. `2048 * MB` is `INT_MIN` once folded (undefined behaviour), and becomes 0xFFFFFFFF80000000 as a `size_t`; larger values wrap modulo 4 GB.

Separately, `--zone-sizes tls:N` has no effect at all: `PGM_TLS_SIZE` (`e_acsl_shadow_layout.h:69`) is never read, `get_tls_size()` returns the TLS size measured at start-up.

**Fix.** Cast the size to `size_t` before the multiplication at these places. With that, heap sizes up to 1048576 MB and stack sizes up to 65536 MB work, with gcc and clang. A merge request with this fix and a regression test follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the reproducer and tests described above.
