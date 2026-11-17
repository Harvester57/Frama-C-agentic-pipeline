# Kernel: the GNU spelling `__restrict__` is not a keyword, so it is a syntax error unless a Frama-C libc header was included

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
Not filed yet. Issue 35 of this folder.

**Filing package:** [issue](./filing/35-kernel-restrict-gnu-spelling-issue.md), [MR](./filing/35-kernel-restrict-gnu-spelling-mr.md), [reproducer](./repro/35-kernel-restrict-gnu-spelling.sh), [patch](./patches/35-kernel-restrict-gnu-spelling.patch)

## Summary

GCC and Clang accept three spellings of the `restrict` qualifier: `restrict`, `__restrict` and
`__restrict__` (gcc accepts the two GNU spellings even with `-std=c89 -pedantic -Werror`). Frama-C's
C lexer knows only the first two. `__restrict__` is lexed as an identifier, so:

- every declaration that uses it is a syntax error, in any position (file scope, struct member,
  prototype, definition, block scope, cast) and with both machdeps tried (`x86_64`, `gcc_x86_64`):

  ```
  [kernel] t.c:5: User Error:
    syntax error:
    Location: "t.c", line 5, before or at token: gp
  ```

- an unnamed parameter `int *__restrict__` is accepted silently as a parameter *named*
  `__restrict__`: `int get(int *__restrict__) { return *__restrict__; }`, which gcc rejects, is
  parsed and printed as is.

It does not show in most programs because `share/libc/features.h:94` defines
`#define __restrict__ __restrict`, and most Frama-C libc headers (for instance `<stddef.h>`, the one
the reproducer uses) include `features.h`. A file that includes no such header, or any file parsed
with `-no-frama-c-stdlib` (host headers), keeps the GNU spelling and fails.

Found on mpack (run-3, 2026-11-17): `MPACK_RESTRICT` expands to `__restrict__` under `__GNUC__`
(target mpack, `src/mpack/mpack-platform.h:1327-1332`), and the E-ACSL frontend, which parses
against the host headers (`-machdep gcc_x86_64 -no-frama-c-stdlib`), stopped on
`char* __restrict__ p = writer->position;` in `src/mpack/mpack-writer.c:1274`. The same file parses
with Frama-C's libc because one of its headers pulls in `features.h`. The first diagnosis
("block-scope declarations") was only the first error of that file; the matrix below shows that the
position does not matter (see the `__restrict__` entry of
[`../../troubleshooting/kernel-and-stubs.md`](../../troubleshooting/kernel-and-stubs.md)).

### Cause

`src/kernel/internals/parsing/clexer.mll:181-182` on `95408044f7` registers `__restrict` and
`restrict` as `RESTRICT` tokens, but not `__restrict__`, while the other GNU double-underscore
spellings are all registered unconditionally with `valid`: `__const__` (line 113), `__signed__`,
`__inline__`, `__volatile__`, `__typeof__`. `__restrict__` has only ever been handled by the libc
macro: commit `8835940a43` ("[Kernel] normalize restrict attribute to __restrict", 2018) replaced
the older `features.h` definitions by `#define __restrict__ __restrict`.

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `95408044f7` (image `framac-master-audit:9540804`) | **bug present**: syntax error in all 6 positions, unnamed parameter accepted as a name |
| `34.0~beta (Selenium)`, opam build (image `framac-analysis:latest`) | **bug present**, identical output |

## Reproduction

[`./repro/35-kernel-restrict-gnu-spelling.c`](./repro/35-kernel-restrict-gnu-spelling.c) puts the
spelling `R` in one of six positions selected by `POS`;
[`./repro/35-kernel-restrict-gnu-spelling-unnamed.c`](./repro/35-kernel-restrict-gnu-spelling-unnamed.c)
is the unnamed-parameter case.
[`./repro/35-kernel-restrict-gnu-spelling.sh`](./repro/35-kernel-restrict-gnu-spelling.sh) checks
each spelling and position with gcc (`-std=c99 -pedantic -Werror`), clang and `frama-c -print`
(default machdep), then with a Frama-C libc header force-included, then on the host headers
(`-machdep gcc_x86_64 -no-frama-c-stdlib`, host `<stddef.h>` force-included). On master:

```
--- positions 1-6: file scope, member, prototype, definition, block, cast
gcc   restrict:     ok ok ok ok ok ok
gcc   __restrict:   ok ok ok ok ok ok
gcc   __restrict__: ok ok ok ok ok ok
clang __restrict__: ok ok ok ok ok ok
frama-c restrict:     ok ok ok ok ok ok
frama-c __restrict:   ok ok ok ok ok ok
frama-c __restrict__: ERR ERR ERR ERR ERR ERR
frama-c __restrict__ after a libc #include: ok ok ok ok ok ok
frama-c __restrict__ host headers (gcc_x86_64 -no-frama-c-stdlib): ERR ERR ERR ERR ERR ERR
[kernel] 35-kernel-restrict-gnu-spelling.c:5: User Error:
  syntax error:
  Location: "35-kernel-restrict-gnu-spelling.c", line 5, before or at token: gp
--- unnamed __restrict__ parameter used as a name in the body
gcc: rejected
frama-c: accepted, printed as:
int get(int *__restrict__)
{
  int __retres;
  __retres = *__restrict__;
RESULT: bug present
```

A wider matrix run during the analysis (spellings x 7 positions x machdeps `x86_64` and
`gcc_x86_64`, with and without `-no-frama-c-stdlib`, with and without a libc include) gave the same
picture: `__restrict__` fails everywhere except as an unnamed prototype parameter, and passes only
when a Frama-C libc header is included.

## Fix

[`./patches/35-kernel-restrict-gnu-spelling.patch`](./patches/35-kernel-restrict-gnu-spelling.patch),
one commit `757346fdcc` on `fix/restrict-gnu-spelling` from `95408044f7`, "[kernel] lexer: accept
the GNU spelling `__restrict__` of restrict": one line,
`valid "__restrict__" (fun loc -> RESTRICT loc) ;`, next to `__restrict` and `restrict`. The
`features.h` define is left in place (redundant, harmless). Only `aorai` uses `Clexer.is_c_keyword`
outside the lexer (`get_fresh`, `plugins/aorai/src/data_for_aorai.ml:253`): it renames a generated
name that is a C keyword, so a name `__restrict__` would now be renamed, which is what is wanted;
the aorai ptests do not change.

New test `tests/syntax/restrict_gnu_spelling.i` (a `.i`, so it is not preprocessed and no libc
macro can rewrite the spelling; default configuration of the directory, `-print -machdep x86_32`):
the three spellings at file scope and in struct members, named and unnamed prototype parameters,
definition parameters, block-scope locals with `const` and `volatile`, a pointer to a restrict
pointer, and a cast.

Output with the fix:

```
--- positions 1-6: file scope, member, prototype, definition, block, cast
...
frama-c __restrict__: ok ok ok ok ok ok
frama-c __restrict__ after a libc #include: ok ok ok ok ok ok
frama-c __restrict__ host headers (gcc_x86_64 -no-frama-c-stdlib): ok ok ok ok ok ok
--- unnamed __restrict__ parameter used as a name in the body
gcc: rejected
frama-c: rejected
RESULT: fixed
```

## Validation

Patched `95408044f7`, built (`dune build @install`) and installed (`dune install`) in a container
of `framac-master-audit:9540804` (Debian 13, gcc 14, clang 19).

| Check | `master` | Patched |
|---|---|---|
| Reproducer | `__restrict__` fails in 6/6 positions (also on host headers); unnamed parameter accepted as a name | 6/6 accepted everywhere; unnamed-parameter body rejected, as by gcc |
| New test `tests/syntax/restrict_gnu_spelling.i` (ptests) | fails: `User Error: syntax error ... line 7 ... before or at token: g3` | passes; every spelling printed as `restrict` |
| Printed code of the new test (the oracle) | not reached | compiles with `gcc -std=c99 -pedantic -Wall` and `clang -std=c99 -pedantic -Wall` |
| ptests `@tests/ptests_config` (1217 results: `syntax`, `misc`, `libc`, `pretty_printing`, ...) | — | pass; only the new oracle |
| ptests `@plugins/rte/tests/ptests_config` (87), `@plugins/eva/tests/ptests_config` (794), `@plugins/aorai/tests/ptests_config` (39) | — | pass, no oracle change |
| `dune build @src/kernel/internals/parsing/tests/runtest` (`check_logic_parser`; the Makefile's `@.../parsing/tests/ptests` alias is empty) | — | exit 0 |
| `./dev/check-files.sh -p HEAD~1` (lint and headers, ocp-indent 1.10.0, clang-format, headache) | — | exit 0 (`Lint 3 file(s)`) |
| `git diff --check` | — | only the final blank line of the new oracle (Frama-C output) |

Not run: the other plug-in suites (WP, E-ACSL, slicing and the rest), `make check-lint`/`check-headers` on
the whole tree. The container's core-file limit is 0 (hard), so `ulimit -c 1` could not be set; no
core can be written anyway.

Unrelated, noticed on the way and not changed: `restrict` on an unnamed prototype parameter is not
printed (`int h(int *restrict);` prints `int h(int *);`), for every spelling; and a `restrict` in a
cast is dropped, as the qualifier has no meaning there.

## Workaround

The pipeline force-includes [`../../../templates/fc_stubs/fc_compat_types.h`](../../../templates/fc_stubs/fc_compat_types.h)
on the E-ACSL frontend; its `__FRAMAC_EACSL__` block defines `__restrict__` as `__restrict` before
any include (fixed `f2772cf`, merged as `87841fb`). Before that, the run used
`-D__restrict__=restrict` in the module cppflags. Either way is the same textual rewrite as the
libc's `features.h`.

## Tracker

Not filed at the time of writing. A live search on 2026-11-17 (`__restrict__`, `restrict`,
`restrict qualifier`, `restrict syntax error`, issues and merge requests, all states) found nothing
related.
