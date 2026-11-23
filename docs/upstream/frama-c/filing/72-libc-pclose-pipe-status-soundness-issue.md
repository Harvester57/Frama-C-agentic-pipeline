# [Libc] `pclose` contract proves `\false` under WP (`is_open_pipe` lacks `reads` and `pclose` assigns no memory)

<!-- Everything below this line is the issue description. -->

### Summary

In Frama-C's libc `share/libc/stdio.h`, the `pclose` contract requires `is_open_pipe(stream)` and
ensures `!is_open_pipe(stream)`, while its only `assigns` clause is
`assigns \result \from indirect:*stream;` (no memory location is assigned). In addition, the
predicate `is_open_pipe{L}(FILE *stream)` omits its `reads` clause, so WP interprets it as reading
nothing. As a result, WP derives a logical contradiction at any `pclose()` call and proves `\false`
by Qed for every property that follows it.

### Steps to reproduce the issue

`repro.c`:

```c
#include <stdio.h>

int main(void) {
  FILE *p = popen("ls", "r");
  if (p == NULL)
    return 1;
  pclose(p);
  //@ assert unreachable_false: \false;
  return 0;
}
```

```sh
frama-c repro.c -wp -wp-prover none -wp-print -wp-prop unreachable_false
frama-c repro.c -wp -wp-rte -wp-smoke-tests
```

### Expected behaviour

WP does not emit a `reads nothing` warning for `is_open_pipe`, `-wp-smoke-tests` reports no doomed
`pclose` call, and `assert unreachable_false: \false` is not provable. At the same time, normal
stream operations between `popen` and `pclose` (such as `fread`, `fwrite`, `fgets`, or `fprintf`)
do not invalidate `is_open_pipe(p)`.

### Actual behaviour

```text
[kernel] Parsing repro.c (with preprocessing)
[wp] Running WP plugin...
[kernel:annot:missing-spec] FRAMAC_SHARE/libc/stdio.h:626: Warning: 
  Neither code nor explicit exits and terminates for function popen, generating
  default clauses. See -generated-spec-* options for more info.
[kernel:annot:missing-spec] FRAMAC_SHARE/libc/stdio.h:634: Warning: 
  Neither code nor explicit exits and terminates for function pclose,
  generating default clauses. See -generated-spec-* options for more info.
[wp] Warning: Missing RTE guards
[wp] Warning: No definition for 'is_open_pipe' interpreted as reads nothing
------------------------------------------------------------
  Function main
------------------------------------------------------------

Goal Assertion 'unreachable_false' ("repro.c", line 8):
Prove: true.

------------------------------------------------------------
[wp:pedantic-assigns] repro.c:3: Warning: 
  No 'assigns' specification for function 'main'.
  Callers assumptions might be imprecise.
```

With `-wp -wp-rte -wp-smoke-tests`:

```text
[wp] Warning: No definition for 'is_open_pipe' interpreted as reads nothing
[wp] 10 goals scheduled
[wp] [Failed] (Doomed) typed_pclose_wp_smoke_dead_call_s6 (Qed)
[wp] repro.c:7: Warning: Failed smoke-test
[wp] Proved goals:    9 / 10
  Qed:               4
  Alt-Ergo 2.6.4:    5
  Failed:            1
  Smoke Tests:       2 / 3
```

Exit status: `0`. Both commands produce the same output on `34.0~beta`.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at `189053d4a2`; also 34.0~beta (Selenium), same output
- Plug-in used: WP, kernel (Frama-C libc)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** `share/libc/stdio.h:607-634` on `189053d4a2` has two coupled defects:

1. `predicate is_open_pipe{L}(FILE *stream);` (line 608) has no `reads` clause (unlike the sibling
   state-dependent predicates `is_allocable` in `share/libc/__fc_alloc_axiomatic.h:20-21`, which
   reads `__fc_heap_status`, and `abs_clock_in_range` / `valid_clock_id` in
   `share/libc/time.h:224-228`, which read `__fc_time`). WP therefore treats `is_open_pipe` as
   state-independent.
2. `pclose` (lines 629-633) specifies `requires open_pipe: is_open_pipe(stream);`,
   `assigns \result \from indirect:*stream;`, and `ensures closed_stream: !is_open_pipe(stream);`.
   Because no memory state is assigned, the pre-state and post-state agree on all memory locations,
   so `is_open_pipe(stream) && !is_open_pipe(stream)` is contradictory under ACSL frame semantics
   even once a `reads` clause is added.

Other state-dependent predicates in `share/libc/` (`is_allocable`, `abs_clock_in_range`,
`valid_clock_id`) all declare `reads`, and `closedir` (`share/libc/dirent.h:45-51`) assigns `*dirp`.

**Fix.** Add `/*@ ghost __FC_EXTERN int __fc_pipe_status; */` (following `__fc_heap_status` in
`share/libc/__fc_alloc_axiomatic.h:17`), declare `reads __fc_pipe_status;` on `is_open_pipe`, and
assign `__fc_pipe_status` in `popen` and `pclose`. Using a dedicated ghost state variable rather
than `reads *stream` / `assigns *stream` avoids invalidating `is_open_pipe(p)` across intermediate
`fread`/`fwrite`/`fgetc`/`fprintf` calls on the pipe. A merge request with a regression test
follows.

The analysis and fix were prepared with LLM assistance (Antigravity / Gemini); I reviewed them and
ran the reproducer and tests described above.
