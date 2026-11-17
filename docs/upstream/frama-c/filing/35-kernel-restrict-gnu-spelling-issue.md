# [Kernel] `__restrict__` (GNU spelling of `restrict`) is a syntax error unless a Frama-C libc header is included

<!-- Everything below this line is the issue description. -->

### Summary

GCC and Clang accept `restrict`, `__restrict` and `__restrict__` as the same qualifier. Frama-C's lexer knows only the first two, so `__restrict__` is a syntax error in any declaration, and an unnamed parameter `int *__restrict__` silently becomes a parameter named `__restrict__`. Frama-C's `features.h` hides this with `#define __restrict__ __restrict`, so only files that include no Frama-C libc header pulling it in (such as `<stddef.h>`), or that are parsed with `-no-frama-c-stdlib`, are affected.

### Steps to reproduce the issue

`t.c` (no `#include`):

```c
int *__restrict__ gp;

int get(int *__restrict__ p)
{
  int *__restrict__ l = p;
  return *l;
}
```

```
$ gcc -std=c99 -pedantic -Werror -fsyntax-only t.c && echo ok
ok
$ frama-c t.c -print
```

`u.c`:

```c
int get(int *__restrict__) { return *__restrict__; }
```

```
$ gcc -fsyntax-only u.c
$ frama-c u.c -print
```

### Expected behaviour

`t.c` is accepted, with the three pointers `restrict`-qualified, as gcc and clang accept it (gcc
also with `-std=c89 -pedantic -Werror`). `u.c` is rejected, as gcc rejects it (`__restrict__` is a
keyword, not a name: `error: expected expression before '__restrict__'`).

### Actual behaviour

`t.c`:

```
[kernel] t.c:1: User Error:
  syntax error:
  Location: "t.c", line 1, before or at token: gp
[kernel] Frama-C aborted: invalid user input.
```

The same error appears in every position (file scope, struct member, prototype and definition
parameters, block-scope declaration, cast) and with both machdeps I tried (`x86_64`,
`gcc_x86_64`). It goes away when the file includes a Frama-C libc header such as `<stddef.h>`, and
comes back with `-no-frama-c-stdlib`
(for instance `-machdep gcc_x86_64 -no-frama-c-stdlib` and `#include <stddef.h>` from the host).

`u.c` is accepted and printed as:

```c
int get(int *__restrict__)
{
  int __retres;
  __retres = *__restrict__;
  return __retres;
}
```

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 95408044f7; also 34.0~beta (Selenium), same output
- Plug-in used: kernel
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

`src/kernel/internals/parsing/clexer.mll:181-182` registers `__restrict` and `restrict` as
`RESTRICT`, but not `__restrict__`, while the other GNU double-underscore spellings (`__const__`,
`__signed__`, `__inline__`, `__volatile__`, `__typeof__`) are all registered with `valid`.
`share/libc/features.h:94` (`#define __restrict__ __restrict`) covers the gap only when a Frama-C
libc header is included.

Found on MPack, whose `MPACK_RESTRICT` expands to `__restrict__` under `__GNUC__`: parsing
`src/mpack/mpack-writer.c` with `-machdep gcc_x86_64 -no-frama-c-stdlib` (as when instrumenting
against the system headers) stops on `char* __restrict__ p = writer->position;`, while the same
file parses with Frama-C's libc.

A merge request follows: one `valid "__restrict__"` line in the lexer and a new test
`tests/syntax/restrict_gnu_spelling.i`.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
