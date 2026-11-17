# [E-ACSL] bittree memory model: stdin, stdout, stderr and errno are not safe locations, so run-time checks on them fail (and -warn-invalid-pointer aborts on the first fputs)

<!-- Everything below this line is the issue description. -->

### Summary

With `e-acsl-gcc -m bittree`, the standard streams and `errno` are unknown to the runtime: `\valid` of a copy of `stdout`, `\object_pointer(stdout)` and `\valid(&errno)` through a pointer are false, and with `-rte -warn-invalid-pointer` the `invalid pointer` guard aborts the program on the first `fputs(..., stdout)`. The bittree `eacsl_memory_init` has the comment "Tracking safe locations" but never calls `collect_safe_locations()`, which the segment model calls at start-up.

### Steps to reproduce the issue

`streams.c`:

```c
#include <stdio.h>

int main(int argc, char **argv) {
  /* \valid(stdout) itself is resolved when instrumenting: use copies */
  FILE *out = stdout, *err = stderr, *in = stdin;
  //@ check OUT: \valid(out);
  //@ check ERR: \valid(err);
  //@ check IN: \valid_read(in);
  //@ check OUT_OBJ: \object_pointer(stdout);
  return 0;
}
```

`rte.c`:

```c
#include <stdio.h>

int main(int argc, char **argv) {
  fputs("to stdout\n", stdout);
  fprintf(stderr, "to stderr %d\n", argc);
  return 0;
}
```

```sh
e-acsl-gcc -q -c -m bittree -o streams.inst.c -O streams streams.c && ./streams.e-acsl; echo "exit $?"
e-acsl-gcc -q -c -m bittree -F "-rte -warn-invalid-pointer" -o rte.inst.c -O rte rte.c && ./rte.e-acsl; echo "exit $?"
```

### Expected behaviour

No failed check and exit 0 for both, as with the default segment model (`-m segment`).

### Actual behaviour

`streams.c` (the `check`s report and continue; `...` marks the same report for `ERR` and `IN`):

```text
streams.c: In function 'main'
streams.c:6: Error: Assertion failed:
	The failing predicate is:
	OUT:
		\valid(out).
	With values at failure point:
	- OUT: \valid(out): 0
	- sizeof(FILE): 216
	- out: 0x73fcf83315c0
...
streams.c: In function 'main'
streams.c:9: Error: Assertion failed:
	The failing predicate is:
	OUT_OBJ:
		\object_pointer(stdout).
	With values at failure point:
	- OUT_OBJ: \object_pointer(stdout): 0
	- sizeof(FILE): 216
	- stdout: 0x73fcf83315c0
exit 0
```

`rte.c`, in bash:

```text
rte.c: In function 'main'
rte.c:4: Error: E-ACSL RTE failed:
	The failing predicate is:
	invalid pointer:
		\null ≡ stdout ∨ \object_pointer(stdout).
	With values at failure point:
	- \object_pointer(stdout): 0
	- sizeof(FILE): 216
	- stdout: 0x79d64027c5c0
bash: line 1: 72281 Aborted                 ./rte.e-acsl
exit 134
```

The same with `-M`. With `-G clang`, `rte.c` aborts the same way and `streams.c` aborts earlier, for an unrelated bittree bug (#<issue-37>). `memory/errno.c` from the test suite also fails with `-m bittree` (`\valid(p)` with `p = &errno`).

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 95408044f7; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`, `--memory-model bittree`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** `plugins/e-acsl/share/e-acsl/observation_model/bittree_model/e_acsl_bittree_observation_model.c:581-593`:

```c
  if (argc_ref)
    argv_alloca(argc_ref, argv_ref);
  /* Tracking safe locations */
  init_infinity_values();
```

`collect_safe_locations()` (`observation_model/internals/e_acsl_safe_locations.c`) registers `errno`, `stdout`, `stderr` and `stdin`; the segment model calls it in `e_acsl_shadow_layout.c:566` and per thread in `e_acsl_shadow_concurrency.c:175`. The validity functions of both models consult the safe locations, so in the bittree model these objects are simply unknown.

Not affected: predicates written on the bare terms (`\valid(stdout)`, `\valid_read(stdin)`, `\initialized(stdout)`...), which E-ACSL resolves when instrumenting.

**Fix.** Call `collect_safe_locations()` there. The bittree model does not support threads (`eacsl_pthread_create` aborts), so one call is enough. A merge request with this fix and a regression test follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the reproducer and tests described above.
