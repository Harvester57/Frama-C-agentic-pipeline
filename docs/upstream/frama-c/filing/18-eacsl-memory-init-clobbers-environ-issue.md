# [E-ACSL] When `main` takes `argc` and `argv`, the runtime initialization empties `environ`: `getenv` always returns NULL

<!-- Everything below this line is the issue description. -->

### Summary

When `main` takes `argc` and `argv`, E-ACSL's runtime initialization walks the environment by incrementing the global `environ` itself, leaving it at the terminating `NULL`. After that, `getenv` returns `NULL` for every variable in the instrumented program. Both the segment and the bittree memory models do this.

### Steps to reproduce the issue

`env.c`:

```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  const char *v = getenv("EACSL_REPRO_VAR");
  printf("argc=%d EACSL_REPRO_VAR=%s\n", argc, v ? v : "(null)");
  return v ? 0 : 1;
}
```

```
$ e-acsl-gcc -c -O prog env.c
$ EACSL_REPRO_VAR=hello ./prog; echo $?
$ EACSL_REPRO_VAR=hello ./prog.e-acsl; echo $?
```

The same with the bittree memory model (`e-acsl-gcc -c -m bittree -O prog env.c`).

### Expected behaviour

The instrumented program sees the same environment as the original one:

```
argc=1 EACSL_REPRO_VAR=hello
0
```

### Actual behaviour

```
$ EACSL_REPRO_VAR=hello ./prog; echo $?
argc=1 EACSL_REPRO_VAR=hello
0
$ EACSL_REPRO_VAR=hello ./prog.e-acsl; echo $?
argc=1 EACSL_REPRO_VAR=(null)
1
```

Same output with `-m bittree`, and with full memory tracking (`-M`). No option is needed: it is
enough that `main` takes `argc` and `argv`. With `int main(void)`, the environment is intact.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`, segment and bittree memory models)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

When `main` takes `argc` and `argv`, `eacsl_memory_init` calls `argv_alloca`, which registers the
argument strings and then the environment strings. Both observation models walk the environment
with the global itself:

- `plugins/e-acsl/share/e-acsl/observation_model/segment_model/e_acsl_segment_observation_model.c:284-293`
- `plugins/e-acsl/share/e-acsl/observation_model/bittree_model/e_acsl_bittree_observation_model.c:573-578`

```c
  while (*environ) {
    ...
    environ++;
  }
```

When the loop ends, `environ` points to its terminating NULL entry, so the program, and every
library it calls, sees an empty environment. The argument loop just above uses a local copy
(`char **argv = *argv_ref;`), and `get_stack_start` in `e_acsl_shadow_layout.c:92` walks the
environment with a local cursor (`char **env = environ;`).

Fix: walk the environment with a local cursor in both models. With this change, both builds of
`env.c` print `EACSL_REPRO_VAR=hello` and exit with 0, and the E-ACSL test suites (default and `dev`
configurations; `format` in the default configuration only, see the merge request) give the same
results as on `master`. A merge request with a fix and a test
follows. The existing test `temporal/t_getenv.c` did not catch the bug because it accepts a NULL
result from `getenv`.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
