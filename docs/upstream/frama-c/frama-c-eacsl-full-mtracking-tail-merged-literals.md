# E-ACSL: with `-e-acsl-full-mtracking` and `-G clang`, a string literal that is the suffix of another one splits its block, so `\valid_read` fails on correct code

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Number 28 in this folder's [index](./README.md).

**Filing package:** [issue](./filing/28-eacsl-full-mtracking-tail-merged-literals-issue.md),
[MR](./filing/28-eacsl-full-mtracking-tail-merged-literals-mr.md),
[reproducer](./repro/28-eacsl-full-mtracking-tail-merged-literals.sh),
[patch](./patches/28-eacsl-full-mtracking-tail-merged-literals.patch)

**Related to [frama-c-eacsl-gcc-clang-cflags.md](./frama-c-eacsl-gcc-clang-cflags.md)** (Issue 10,
[#2810](https://git.frama-c.com/pub/frama-c/-/work_items/2810)), but not the same bug: `-fno-merge-constants`
is in the CFLAGS that `-G clang` overwrites (`scripts/e-acsl-gcc:894` and `:912`), but restoring it
does not help, because clang ignores that flag
(`clang: warning: optimization flag '-fno-merge-constants' is not supported`). See "Tracker" at the
end for the duplicate search.

## Summary

Under `-e-acsl-full-mtracking`, E-ACSL keeps string literals as literals and registers each one as
its own block in `__e_acsl_globals_init`:

```c
__e_acsl_store_block((void *)" ,",3UL);
__e_acsl_full_init((void *)(& " ,"));
__e_acsl_mark_readonly((void *)" ,");
__e_acsl_store_block((void *)",",2UL);
__e_acsl_full_init((void *)(& ","));
__e_acsl_mark_readonly((void *)",");
```

This relies on each literal having its own storage. clang puts literals in a mergeable string
section (`.rodata.str1.1`, flags `AMS`), and GNU ld stores a literal that is the suffix of another one
inside it: `","` lands at `" ," + 1`. The two registered blocks overlap. The second `store_block`
rewrites the shadow of the shared bytes, which now belong to the block of `","`. A loop over
`" ,"` then fails at its second byte: `\valid_read(charset + 1)` checks that `charset + 1` is in
the block of `charset`, and it is not.

```text
suffix.c: In function 'in_charset'
suffix.c:6: Error: Assertion failed:
	The failing predicate is:
	\valid_read(charset + j).
	With values at failure point:
	- \valid_read(charset + j): 0
	- sizeof(char const): 1
	- j: 1
	- charset: 0x646c9aa2c008
Aborted (core dumped)
```

The program is correct. Without `-e-acsl-full-mtracking`, the memory-tracking analysis demotes each
monitored literal to a named array (`__fc_lit_string1`, `__fc_lit_string2`); named arrays are not
merged, and the same program runs clean. With gcc, `e-acsl-gcc` passes `-fno-merge-constants`, gcc
emits literals in plain `.rodata`, and the program runs clean too. Only the combination full tracking
+ clang fails, and clang is what libFuzzer and the sanitizers need. The concurrency support turns full
tracking on, so it is affected too.

Found by fuzzing c-ares 1.34.5 with E-ACSL: `ares_buf_split(buf, (const unsigned char *)" ,", 2, ...)`
reads `" ,"` while `","` is also a literal of the program. The call runs when the library reads
`/etc/resolv.conf` at initialization, so every input of three campaigns stopped there before the
code under test ran.

## Versions

- Frama-C `35.0~~dev (Bromine)`, `master` at `3dff90fc70` (2026-11-13), Debian 13, clang 19.1.7,
  gcc 14.2.0, GNU ld 2.44.
- Same result on `34.0~beta (Selenium)` (opam build, same OS and toolchain), rechecked on
  2026-11-16 with the reproducer below.
- String literals became global variables (`fc_literal` attribute) on the branch
  `feature/typing/string-literal-array`, merged in `3ba6ed0d68` (2025-10-01); the demotion of
  monitored literals came with it (`1dbd6af88b`). `git tag --contains 3ba6ed0d68` lists 32.0
  onwards. I ran only 34.0~beta and `master`; older releases printed literals differently and were
  not checked.

## Reproduction

[`./repro/28-eacsl-full-mtracking-tail-merged-literals.c`](./repro/28-eacsl-full-mtracking-tail-merged-literals.c):

```c
#include <stddef.h>

static int in_charset(const char *charset, size_t len, char c)
{
  for (size_t j = 0; j < len; j++) {
    /*@ assert \valid_read(charset + j); */
    if (charset[j] == c)
      return 1;
  }
  return 0;
}

int main(void)
{
  const char *comma = ","; /* "," is a suffix of " ," */
  return in_charset(" ,", 2, 'x') + (comma[0] == 'y');
}
```

[`./repro/28-eacsl-full-mtracking-tail-merged-literals.sh`](./repro/28-eacsl-full-mtracking-tail-merged-literals.sh)
builds it three ways and prints the literal registrations and the run status. Before the fix
(`master` and `34.0~beta`):

```text
--- e-acsl-gcc -q -G clang -F -e-acsl-full-mtracking 28-eacsl-full-mtracking-tail-merged-literals.c
build: exit 0
    __e_acsl_store_block((void *)" ,",3UL);
    __e_acsl_store_block((void *)",",2UL);
28-eacsl-full-mtracking-tail-merged-literals.c:6: Error: Assertion failed:
	\valid_read(charset + j).
	- \valid_read(charset + j): 0
	- j: 1
run: exit 134
--- e-acsl-gcc -q -G gcc -F -e-acsl-full-mtracking 28-eacsl-full-mtracking-tail-merged-literals.c
build: exit 0
    __e_acsl_store_block((void *)" ,",3UL);
    __e_acsl_store_block((void *)",",2UL);
run: exit 0
--- e-acsl-gcc -q -G clang 28-eacsl-full-mtracking-tail-merged-literals.c
build: exit 0
    __e_acsl_store_block((void *)(__fc_lit_string2),3UL);
run: exit 0
```

Where the strings are, in a full-tracking clang build of the same two literals (`34.0~beta`, with
`-rte` instead of the assertion, `-e -O1`):

```text
$ objdump -s -j .rodata base.e-acsl | grep ' 202c'
 14000 01000200 202c0026 72007369 7a656f66  .... ,.&r.sizeof
```

`" ,"` is at `0x14004`, and no separate `","` follows it. `clang -c` emits the strings in
`.rodata.str1.1` with flags `AMS` with or without `-fno-merge-constants`. Without E-ACSL, a program
that prints both addresses (`printf("%p %p", " ,", ",")`) shows the same layout:

```text
clang -O0: " ,"=0x58a376d0b004 ","=0x58a376d0b005 diff=1
clang -O1: " ,"=0x63e22a209004 ","=0x63e22a209005 diff=1
gcc -O0 -fno-merge-constants: " ,"=0x635c2f461004 ","=0x635c2f461007 diff=3
```

Control: moving the `","` group before the `" ,"` group in `__e_acsl_globals_init` of `full.inst.c`
and rebuilding with `e-acsl-gcc -C -G clang` gives exit 0. The longer block, registered last, covers
the shared bytes again. The registration order is the order of the variables in E-ACSL's table, not
the source order: a global initializer `const char *tbl[] = {" ,", ",", "x"};` registers `" ,"` last
and runs clean on `master` with clang and full tracking.

The same happens with long blocks (over 64 bytes, kept in the secondary shadow); there the first
failing check can be `\initialized(charset + j)` at `j == 0`.

## Cause

`plugins/e-acsl/src/analyses/memory_tracking.ml`: literals are demoted to plain arrays
(`Demote_string_literal.demote`) only in `Varinfos.add` and in the libc-replacement case of the
dataflow, that is, only when the backward analysis decides that a literal must be monitored. With
`-e-acsl-full-mtracking`, the public `must_monitor_vi`/`must_monitor_lval`/`must_monitor_exp` return
`true` without consulting the analysis, so no literal is ever demoted, while `Global_observer.add`
registers every global, literals included. The printer then prints each literal varinfo as the
literal text (`printer.ml`, the `is_string_literal` cases), both in the registration and at the use
site, and the program's correctness now depends on how the compiler and linker lay out string
literals.

History (`git log -S Demote_string_literal`, `-S Full_mtracking.get`, `--no-textconv`, in a clone of
`3dff90fc70`):

- `347c233b59` (2013-04-12, J. Signoles), "new option -e-acsl-full-mmodel to monitor all pointers":
  the full-tracking shortcut of the public `must_monitor_*`. It predates the representation of
  literals as variables by twelve years.
- `2b383af98a` (2025-07-29, V. Prevosto), "new AST transf to demote a string literal var from its
  special status", and `1dbd6af88b` (same day), "[e-acsl] first step to handle new representation of
  string literal": `demote` is called in the dataflow analysis only (the `extend_to_expr` and
  `register_term_lval` cases).
- `c7652ae418` (2025-08-05), "always monitor str lit used as argument of libc functions with builtin
  instru": the libc-replacement case.
- `9e28a826d0` (2026-03-18, J. Rochel), "Memory_tracking: demote all tracked strings", moves the call
  into `Varinfos.add`. Its message gives the reason a monitored literal must not stay a literal: the
  generated code would print `"abcd"` four times (`store_block`, `full_init`, `mark_readonly`,
  `delete_block`), "4 (potentially) different strings".

I found no stated reason to leave full tracking out; the demotion was added inside the analysis, which
the 2013 shortcut bypasses.

## Fix (patch 28)

[`./patches/28-eacsl-full-mtracking-tail-merged-literals.patch`](./patches/28-eacsl-full-mtracking-tail-merged-literals.patch),
one commit on `3dff90fc70`, "[e-acsl] demote the string literals registered under full memory
tracking":

- `plugins/e-acsl/src/code_generator/injector.ml`: `demote_monitored_string_literals`, called at the
  start of `inject_in_file`. Under full tracking only, it demotes every `GVar` that is a string literal
  and that `Memory_tracking.must_monitor_vi` accepts, which is exactly the set `Global_observer.add`
  registers. Without full tracking nothing changes.
- `src/kernel/services/ast_transformations/demote_string_literal.ml(i)`: new
  `demote_list : varinfo list -> unit`, one traversal of the AST for all the literals and one
  `Ast.mark_as_changed`; `demote vi` is `demote_list [vi]`. Only for cost (below).
- New test `plugins/e-acsl/tests/full-mtracking/literal_strings.c` and its oracles; the two
  concurrency oracles `gen_parallel_threads.0.c` and `gen_threads_debug.0.c` updated (14 `perror`
  messages become `__fc_lit_stringN` arrays).

Semantics, the same as without full tracking: one `char const __fc_lit_stringN[]` per literal
occurrence (two `","` give two arrays), registered once in `__e_acsl_globals_init` (so no repeat of
the closed #633, where a literal was registered at every loop iteration), marked read-only
(`\valid_read` true, `\valid` false). A local `char buf[] = "ab";` becomes
`char buf[3UL] = {'a', 'b', '\000'};`. E-ACSL's own literals (`"Assertion"`, file names) are created
during the injection, are not registered, and stay literals.

**Alternatives considered.**

- Demote in `Global_observer.add`, one literal at a time (first version, one line): correct and the
  same oracles, but one traversal of the AST per literal. On a generated file with 400 functions and
  4,000 literals: 98 s (`const char *p = "..."`) and 117 s (`char a[] = "..."`) instead of 2.0 and
  1.9 s on `master`. With `demote_list`: 2.4 and 2.1 s. One traversal but `Ast.mark_as_changed` per
  rewritten `Local_init` (as `demote` does) still took 12 to 13 s on the array case.
- Demote in the full-tracking branch of the public `must_monitor_vi`: called from many places during
  the injection, so the `Local_init` rewrite could come after the function was already instrumented.
  Rejected.
- Register literals by ascending size in `__e_acsl_globals_init`: a merged suffix then lies inside the
  enclosing block, registered last. Reads past its end are still caught, but a read before its start,
  and `\base_addr`/`\offset`/`\block_length` of the suffix, report the enclosing literal, and the
  result still depends on the toolchain. Kept as the fallback in the issue text.

The default mode has the same per-literal cost today (not changed by the patch): on `master`, the same
file with `/*@ assert \valid_read(p); */` on each literal and without full tracking takes 76 s for
2,000 literals and 217 s for 4,000, because `Varinfos.add` calls `demote` once per monitored literal.

## Validation

`master` at `3dff90fc70` in `framac-master-audit:3dff90f`, then the same tree with the patch
(`dune build @install --release -j 8 && dune install`), committed as the image
`framac-master-audit:3dff90f-p28`. Debian 13, gcc 14.2.0, clang 19.1.7, GNU ld 2.44.

| Check | `master` (and `34.0~beta`) | Patched |
|---|---|---|
| Reproducer, clang + full tracking | `" ,"` and `","` registered as literals; `\valid_read(charset + j)` fails, `j: 1`, exit 134 | `__fc_lit_string2`, `__fc_lit_string1` registered; exit 0 |
| Reproducer, gcc + full tracking | exit 0 | exit 0, named arrays |
| Reproducer, clang, default tracking | exit 0, `__fc_lit_string2` | unchanged |
| Global initializer `const char *tbl[] = {" ,", ",", "x"};`, clang and gcc + full tracking | exit 0 (literals, `" ,"` registered last) | exit 0, `tbl` initialized with the named arrays |
| New test `full-mtracking/literal_strings.c` | oracle difference: literals printed and registered as literals, `char buf[3UL] = "ab";` | passes, default and `dev` configurations |
| New test built with `e-acsl-gcc -G clang -F -e-acsl-full-mtracking` and run | `literal_strings.c:19`, `\valid_read(s + j) && !\valid(s + j)` fails, `j: 1`, exit 134 | exit 0 |
| ptests `plugins/e-acsl/tests`, default configuration (198 results) | — | first run: differences only in the new oracles and the two concurrency oracles, promoted; final run: exit 0, every test matches |
| ptests, `dev` configuration (compiled and run) of `full-mtracking`, `concurrency`, `builtin`, `special`, `bts`, `memory` | — | every test matches `oracle_dev` |
| ptests, `dev` configuration of `format` (runs with full tracking) | `printf.0` still running after 1,000 s, stopped | **incomplete**: no difference in the tests that finished; `printf.0` still running after 1,000 s and stopped, its error output byte-identical to `master` up to that point |
| Kernel test `tests/misc/string_literal.ml` (`dune build @tests/misc/runtest --force`) | — | passes; negative control (extra line in `.expected`) fails |
| Instrumentation time, 4,000 literals, full tracking | 2.0 s / 1.9 s | 2.4 s / 2.1 s (98 s / 117 s with `demote` per literal) |
| `./dev/check-files.sh -p HEAD~1` in `framac-lint:3dff90f` | — | exit 0, "Lint 8 file(s)"; negative control (a changed line with wrong leading indentation) fails with "Bad indentation" |
| `git am --keep-non-patch` on `3dff90fc70` | — | exit 0 (git notes trailing whitespace in the generated oracles, as in the existing ones) |
| `git am --3way` after the 22 existing patches (24 commits) | — | exit 0; three-way merge of `injector.ml` and of the two concurrency oracles, which patch 13 also changes |

The E-ACSL ptests compile with gcc and `-fno-merge-constants`, so the run-time failure cannot show
there. The regression test is the generated-code oracle `gen_literal_strings.0.c`; compiled with
clang and full tracking, the same test fails at run time on `master` and passes with the patch.

The stacked application merges the concurrency oracles textually; they were not regenerated on top
of patch 13. Whichever of patch 13 (!28) and this patch lands second should regenerate them, and the
same holds for `libc/oracle/gen_getenv.1.c` of patch 18 (!33), which registers `"PATH"` as a
literal under full tracking.

## Workaround

Post-process the instrumented source to reorder the literal registrations in
`__e_acsl_globals_init` by ascending block size (the cheaper fix above), or build with `-G gcc`
where libFuzzer is not needed.

The pipeline does the first: `order_literal_registrations` (`scripts/eacsl_toolchain.py`), applied
by `scripts/run_eacsl_fuzz.py`, commit `078e336` on branch `sup/c-ares-eacsl-literal-charset`
(not merged as of 2026-11-16).

## Tracker

Searched on 2026-11-16 with the authenticated API of git.frama-c.com (`pub/frama-c`, issues and merge
requests, all states) for `merge-constants`, `tail merg`, `suffix literal`, `full-mtracking` and
`string literal`, and in the 2026-11-09 export for "merge", "suffix" and "literal". No duplicate.

- The 2026 hits are this folder's own reports (#2794, #2810, !26, !33, !35, !41).
- #633 (2014, closed, fixed in Sodium), "Literal strings can be added multiple times in memory", is
  related history: the same literal was registered again at every loop iteration. It is about one
  literal, not two literals sharing storage.
- #2122, #2347, #2672 and the other `string literal` hits are about Eva, parsing or wide strings.
