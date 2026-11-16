# E-ACSL: when `main` takes `argc` and `argv`, `argv_alloca()` moves the global `environ` to its terminating NULL, and every later `getenv()` returns NULL

**Filed upstream on 2026-11-15:** issue [#2802](https://git.frama-c.com/pub/frama-c/-/work_items/2802), merge request [!33](https://git.frama-c.com/pub/frama-c/-/merge_requests/33).

- **Parent Catalog:** [`./frama-c-e-acsl-issues.md`](./frama-c-e-acsl-issues.md) (Issue 18)

**Filing package:** [issue](./filing/18-eacsl-memory-init-clobbers-environ-issue.md), [MR](./filing/18-eacsl-memory-init-clobbers-environ-mr.md), [reproducer](./repro/18-eacsl-memory-init-clobbers-environ.sh), [patch](./patches/18-eacsl-memory-init-clobbers-environ.patch)

## Summary

When the instrumented `main` takes `argc` and `argv`, `__e_acsl_memory_init` calls the runtime's
`argv_alloca()`, which registers the argument strings and then the environment strings in shadow
memory. It walks the environment with `while (*environ) { ...; environ++; }` on the global
`extern char **environ` itself. When the loop ends, `environ` points to its terminating NULL entry,
so the program and every library it calls see an empty environment: every `getenv(...)` returns
NULL.

No option is needed. Both memory models (segment, the default, and bittree) have the bug, with and
without full memory tracking (`-M`). A `main(void)` is not affected, because `argv_alloca()` is
only called when the references to `argc` and `argv` are non-null. (An earlier version of this
draft said `-M` was required; the runs below show it is not.)

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `3dff90fc70`, image `framac-master-audit:3dff90f` | **bug** (segment and bittree, with and without `-M`) |
| `34.0~beta (Selenium)`, image `framac-analysis:fc34` | **bug** (segment and bittree) |

Debian 13, gcc 14 (the `e-acsl-gcc` default) and clang 19.

## Reproduction

[`./repro/18-eacsl-memory-init-clobbers-environ.c`](./repro/18-eacsl-memory-init-clobbers-environ.c):

```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  const char *v = getenv("EACSL_REPRO_VAR");
  printf("argc=%d EACSL_REPRO_VAR=%s\n", argc, v ? v : "(null)");
  return v ? 0 : 1;
}
```

[`./repro/18-eacsl-memory-init-clobbers-environ.sh`](./repro/18-eacsl-memory-init-clobbers-environ.sh)
builds it with `e-acsl-gcc -c -m <model>` and runs it with `EACSL_REPRO_VAR=hello`. On `master`:

```
== memory model: segment
argc=1 EACSL_REPRO_VAR=hello
prog (not instrumented) exit code: 0
argc=1 EACSL_REPRO_VAR=(null)
prog.e-acsl exit code: 1
== memory model: bittree
argc=1 EACSL_REPRO_VAR=hello
prog (not instrumented) exit code: 0
argc=1 EACSL_REPRO_VAR=(null)
prog.e-acsl exit code: 1
```

The same program with `int main(void)` prints `hello` with the segment model, with and without
`-M`.

## Root cause

On `master` `3dff90fc70`:

1. `plugins/e-acsl/share/e-acsl/observation_model/segment_model/e_acsl_segment_observation_model.c:284-293`:
   ```c
   while (*environ) {
     size_t envlen = strlen(*environ) + 1;
   #ifdef E_ACSL_TEMPORAL
     *environ = shadow_copy(*environ, envlen, 1);
   #else
     shadow_alloca(*environ, envlen);
     initialize_static_region((uintptr_t)*environ, envlen);
   #endif
     environ++;
   }
   ```
2. `plugins/e-acsl/share/e-acsl/observation_model/bittree_model/e_acsl_bittree_observation_model.c:573-578`:
   ```c
   while (*environ) {
     size_t envlen = strlen(*environ) + 1;
     eacsl_store_block(*environ, envlen);
     eacsl_initialize(*environ, envlen);
     environ++;
   }
   ```

`argv_alloca` is called from `eacsl_memory_init` when `argc_ref` (and, for the segment model,
`argv_ref`) is non-null (segment model line 333, bittree model line 590). The argument loop just
above uses a local copy (`char **argv = *argv_ref;`), and `get_stack_start` in
`segment_model/e_acsl_shadow_layout.c:92` already walks the environment with a local
`char **env = environ;`.

The bittree model is still built and selectable on `master`: `e-acsl-gcc -m bittree`
(`plugins/e-acsl/scripts/e-acsl-gcc`, `SUPPORTED_MMODELS="bittree,segment"`), and the `dev` test
`special/e-acsl-bittree-model.c` compiles the runtime with it.

## Fix

Patch: [`./patches/18-eacsl-memory-init-clobbers-environ.patch`](./patches/18-eacsl-memory-init-clobbers-environ.patch)
(subject ``[e-acsl] do not modify `environ` when tracking the environment strings``, branch
`fix/eacsl-environ` from `3dff90fc70`). In both models, the loop walks a local
`char **env = environ;` and leaves `environ` alone. With temporal analysis, the segment model still
replaces each entry by its shadow copy, as before. No `env != NULL` guard is added: the original
loop did not have one and `environ` is not NULL at program start.

Regression test `plugins/e-acsl/tests/libc/getenv.c`: `main(int argc, char **argv)` asserts that
`getenv("PATH")` is not NULL. Default configuration: two runs (default, and
`-e-acsl-full-mtracking`), with oracles. `dev` configuration: segment model, then bittree model
with full memory tracking. The existing `temporal/t_getenv.c` accepts a NULL result, which is why
it never caught the bug.

## Validation

Built from `3dff90fc70` with the patch in a copy of `framac-master-audit:3dff90f`
(`dune build @install --release`, `dune install`).

| Check | `master` | Patched |
|---|---|---|
| Reproducer, segment model | `(null)`, exit 1 | `hello`, exit 0 |
| Reproducer, bittree model | `(null)`, exit 1 | `hello`, exit 0 |
| `libc/getenv.c`, `dev` run 0 (segment) | `Assertion failed` on `path ≢ \null` (`path: (nil)`), exit 134 | pass |
| `libc/getenv.c`, `dev` run 1 (bittree, `--full-mtracking`) | same failure | pass |
| ptests, every suite, default and `dev` configurations (`format`: default only, see below) | all pass | only difference: the new test (oracles added); then all pass |
| `clang-format` 19 (`--dry-run -Werror`) on the two models and the test | | clean |
| `git diff --check` | | clean except the new oracles (trailing space after `Warning:`, trailing blank line: the ptests output format, as in every existing oracle) |
| `git apply --check` on `3dff90fc70` | | clean |

`format`: on `master` (unpatched) in this image, `format/printf.c` in the `dev` configuration stops
making progress after its 28th check and was killed after 90 minutes, so the `dev` configuration of
`format` was not compared; its default configuration matches the oracles on `master` and with the
patch.

## Unrelated observation (bittree model)

On this image, with the bittree model, `int main(void) { return 0; }` crashes with a segmentation
fault without `-M` (gcc and clang), and with `-M` the clang build aborts with no message (exit 134)
while the gcc build runs. `main(int, char **)` runs with gcc and clang without `-M`. This is not the
`environ` bug and the patch does not change it; not investigated further.

## Workaround

Declare `int main(void)` when `argc` and `argv` are not needed. Otherwise none, short of patching
the runtime library.

## Tracker

Not filed at the time of writing (see the filing note at the top). No issue in the 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)) mentions
`environ`, `getenv` or `argv_alloca`.
