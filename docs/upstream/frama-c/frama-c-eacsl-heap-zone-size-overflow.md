# E-ACSL: `e-acsl-gcc --zone-sizes heap:2048` (or `stack:2048`) makes every run of the monitored program crash: the size in MB is converted to bytes in `int`

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Filed on 2026-11-18 as [#2825](https://git.frama-c.com/pub/frama-c/-/work_items/2825), with merge request [!53](https://git.frama-c.com/pub/frama-c/-/merge_requests/53).** Number 36 in this folder's index.

**Filing package (2026-11-17):** issue text
[`./filing/36-eacsl-heap-zone-size-overflow-issue.md`](./filing/36-eacsl-heap-zone-size-overflow-issue.md),
merge request text
[`./filing/36-eacsl-heap-zone-size-overflow-mr.md`](./filing/36-eacsl-heap-zone-size-overflow-mr.md),
patch [`./patches/36-eacsl-heap-zone-size-overflow.patch`](./patches/36-eacsl-heap-zone-size-overflow.patch)
(validated, see "Validation"), reproducer
[`./repro/36-eacsl-heap-zone-size-overflow.sh`](./repro/36-eacsl-heap-zone-size-overflow.sh) with
[`./repro/36-eacsl-heap-zone-size-overflow.c`](./repro/36-eacsl-heap-zone-size-overflow.c).

## Summary

`e-acsl-gcc --zone-sizes heap:N,stack:N,tls:N,thread-stack:N` sets the sizes, in MB, of the memory
spaces of the segment memory model (the default). The script checks only lower bounds
(`MIN_HEAP=64`, `MIN_STACK=16`, `MIN_TLS=1`, `MIN_THREAD_STACK=4`), and the man page and the user manual
say only "set the size (in MB)". The runtime converts the size to bytes with `N * MB`, where `MB` is
the `int` macro `1024 * KB` (`internals/e_acsl_malloc.h`). From N = 2048 the product overflows `int`.

What a user sees, with a program that allocates 2 MB (gcc and clang alike):

| `--zone-sizes` | Result |
| :-- | :-- |
| `heap:1024`, `heap:2047` | runs |
| `heap:2048` to `heap:4095` | segmentation fault at start-up, every run |
| `heap:4096` | heap of 0 MB: the first `malloc` aborts with "Exceeded heap allocation limit of 4096MB -- heap memory space moved." |
| `heap:4097` | heap of 1 MB: same abort for any allocation above 1 MB |
| `heap:N`, N ≥ 4096 | heap of (N mod 4096) MB |
| `stack:2048` | segmentation fault at start-up |
| `stack:4096`, `8192`, `65536` | silently no change (the limit wraps to 0) |
| `thread-stack:2048` (`--concurrency`) | `pthread_create` fails (the program sees the error) |
| `thread-stack:4096` | silently no change |

gcc warns at compile time, in the runtime source, `integer overflow in expression of type 'int'
results in '-2147483648' [-Woverflow]`, but `e-acsl-gcc` shows it among the runtime's build output;
with `-G clang` there is no warning at all, because `e-acsl-gcc` drops the warning flags (#2810).

Asking for a 2 GB or larger heap is a normal request: the default is 128 MB
(`E_ACSL_HEAP_SIZE`), and programs that allocate more abort with "Exceeded heap allocation limit".

## Versions

- Reproduced on `35.0~~dev (Bromine)`, `master` at `95408044f7` (image `framac-master-audit:9540804`,
  gcc 14.2.0, clang 19.1.7) and on `34.0~beta (Selenium)` (image `framac-analysis:latest`). Same
  output, line for line.
- The `int` arithmetic is in the segment model since the sizes were made configurable; not bisected.

## Reproduction

[`./repro/36-eacsl-heap-zone-size-overflow.sh`](./repro/36-eacsl-heap-zone-size-overflow.sh) builds the
2 MB program with gcc and clang for each size and prints the exit code and the runtime message. Its
header holds the output before and after the fix. Short form:

```sh
e-acsl-gcc -c --zone-sizes heap:2048 -o i.c -O t 36-eacsl-heap-zone-size-overflow.c
./t.e-acsl; echo "exit $?"     # Segmentation fault, exit 139
```

## Cause

`plugins/e-acsl/share/e-acsl/observation_model/segment_model/`:

- `e_acsl_shadow_layout.h:59`: `#define PGM_HEAP_SIZE (E_ACSL_HEAP_SIZE * MB)`, used by
  `get_heap_size()` (`e_acsl_shadow_layout.c:509-511`), which sizes the heap mspace
  (`eacsl_make_memory_spaces(64 * MB, get_heap_size())`, `e_acsl_segment_observation_model.c:302`)
  and the heap shadow.
- `e_acsl_segment_observation_model.c:324`: `increase_stack_limit(E_ACSL_STACK_SIZE * MB);`
- `e_acsl_shadow_concurrency.c:337,340`: `E_ACSL_THREAD_STACK_SIZE * MB`.
- `e_acsl_shadow_layout.h:69`: `PGM_TLS_SIZE (E_ACSL_TLS_SIZE * MB)`, which is never used (see below).

`2048 * 1048576` is 2^31: in `int` it is `INT_MIN` (undefined behaviour; gcc folds it to
-2147483648), and once converted to `size_t` it becomes 0xFFFFFFFF80000000. The heap and its shadows are laid out from that
value, and the program crashes at start-up (the exact faulting access was not traced). From 4096 on, the product wraps modulo 2^32
to (N mod 4096) MB.

## Proposed fix

Convert to `size_t` before the multiplication, at the four places:

```diff
-#define PGM_HEAP_SIZE (E_ACSL_HEAP_SIZE * MB)
+#define PGM_HEAP_SIZE ((size_t)(E_ACSL_HEAP_SIZE) * MB)
```

and the same for `PGM_TLS_SIZE`, `E_ACSL_STACK_SIZE * MB` and the two `E_ACSL_THREAD_STACK_SIZE * MB`.

With the fix, every size tried works, gcc and clang: heap up to 1048576 MB (1 TiB: the shadow is
reserved, not committed) and stack up to 65536 MB. No upper limit was found. A large heap reserves
address space (heap plus its shadows), not memory.

### Patch proposed (2026-11-17; updated 2026-11-18)

[`./patches/36-eacsl-heap-zone-size-overflow.patch`](./patches/36-eacsl-heap-zone-size-overflow.patch),
one commit on `b80fcac74f`, "[e-acsl] compute the zone sizes of --zone-sizes in size_t":

- the three runtime files above (5 lines; `PGM_HEAP_SIZE` and `PGM_TLS_SIZE` parenthesize the macro
  operands `((size_t)(E_ACSL_HEAP_SIZE) * MB)` and `((size_t)(E_ACSL_TLS_SIZE) * MB)`);
- new test `special/e-acsl-zone-sizes.c`: `malloc(16)`, a `\valid` check, `free`, run in the `dev`
  configuration with `--zone-sizes heap:2048,stack:2048`; default-configuration oracles
  `oracle/e-acsl-zone-sizes.0.res.oracle` and `oracle/gen_e-acsl-zone-sizes.0.c`. It reserves about
  2 GB of heap address space (plus shadows) at run time.

## Also seen, not fixed here

- `--zone-sizes tls:N` has no effect: `PGM_TLS_SIZE` is never read. `get_tls_size()` returns the TLS
  size measured at start-up (`actual_tls_size`); the macro only appears in a debug print. The patch
  still makes the macro `size_t`, for consistency.
- `e-acsl-gcc` line 381 spells `OPTIONS_TLS_SIZE` where the other variables are `OPTION_...`; harmless.
- With `-G clang`, the concurrency build fails (`__e_acsl_pthread_create` implicitly declared); known
  from !41 (#2810), so `thread-stack` was checked with gcc only.

## Validation

Originally run in container `framac-master-audit:9540804` (Debian 13, gcc 14.2.0, clang 19.1.7),
`master` at `95408044f7`, and re-validated on 2026-11-18 in a fresh `framac-master-audit:b80fcac`
container (`master` at `b80fcac74f`, commit `29005691a0` with parenthesized macro operands) via
[`../../../tools/upstream_audit/revalidate.sh`](../../../tools/upstream_audit/revalidate.sh)
`package 36`:

| Check | `master` | Patched |
| :-- | :-- | :-- |
| Reproducer (gcc, clang × 8 sizes) | 139 for heap:2048, heap:4095, stack:2048; 134 for heap:4096, heap:4097; gcc `-Woverflow` warning | every line exit 0, no warning (re-checked on `b80fcac74f`) |
| Reproducer on 34.0~beta | same as `master` | not run (no patched 34 image) |
| Larger sizes by hand (gcc and clang, on `95408044f7`) | heap:8192 to 1048576 abort at the first malloc; stack:4096 to 65536 no-op | all exit 0 |
| `thread-stack` by hand (gcc, `--concurrency`, one thread, on `95408044f7`) | 2048: `pthread_create` fails; 4096: no-op | 2048 and 4096 exit 0 |
| New test, `dev` configuration (`special/`) | `e-acsl-zone-sizes.0`: exit 139 (`b80fcac74f`) | passes (`b80fcac74f`) |
| ptests `plugins/e-acsl`, default configuration | — | all pass (`b80fcac74f`, `./dev/test.sh -p plugins/e-acsl`) |
| ptests `special/` and `memory/`, `dev` configuration | — | all pass (on `95408044f7`) |
| `./dev/check-files.sh -p HEAD~1` | — | passes ("Lint 6 file(s)", `b80fcac74f`) |
| `git am --keep-non-patch` alone on `b80fcac74f` | — | applies cleanly, no mode changes |
| `git am --3way` with patches 18, 29, 37, 38 (three orders, on `95408044f7`) | — | applies, no conflict |

Not run: `dev` configuration of the other E-ACSL directories; the change only touches sizes passed by
`--zone-sizes`, which no other test uses. Core dumps: the container has a hard core limit of 0, so
`prlimit --core=1:1` in the reproducer has no effect there (see the report of this package).

## Tracker

Searched on 2026-11-17 with the authenticated API of git.frama-c.com (`pub/frama-c`, issues and merge
requests, all states) for `zone-sizes`, `HEAP_SIZE`, `heap size`, `memory-model`. No duplicate. #2810
(!41) is about the CFLAGS that `-G clang` drops, which explains why clang does not warn.
