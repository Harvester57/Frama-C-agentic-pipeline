# E-ACSL: with `-e-acsl-full-mtracking` and `-G clang`, a string literal that is the suffix of another one splits its block, so `\valid_read` fails on correct code

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues). Not filed yet.

**Related to [frama-c-eacsl-gcc-clang-cflags.md](./frama-c-eacsl-gcc-clang-cflags.md)** (Issue 10), but
not the same bug: fixing the CFLAGS overwrite restores `-fno-merge-constants` under clang, and clang
ignores that flag (`clang: warning: optimization flag '-fno-merge-constants' is not supported`).
No duplicate in the 2026-11-09 work-items snapshot (searched for "merge", "suffix" and "literal").

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
	- j: 1
```

The program is correct. Without `-e-acsl-full-mtracking`, the memory-tracking analysis demotes each
monitored literal to a named array (`__fc_lit_string1`, `__fc_lit_string2`); named arrays are not
merged, and the same program runs clean. With gcc, `e-acsl-gcc` passes `-fno-merge-constants`, gcc
emits literals in plain `.rodata`, and the program runs clean too. Only the combination full tracking
+ clang fails, and clang is what libFuzzer and the sanitizers need.

Found by fuzzing c-ares 1.34 with E-ACSL: `ares_buf_split(buf, (const unsigned char *)" ,", 2, ...)`
reads `" ,"` while `","` is also a literal of the program. The call runs when the library reads
`/etc/resolv.conf` at initialization, so every input of three campaigns stopped there before the
code under test ran.

## Versions

- Frama-C `35.0~~dev (Bromine)`, `master` at `3dff90f`, Debian 13, clang 19.1.7, GNU ld 2.44.
- Same result on `34.0~beta (Selenium)` (opam build, same OS and toolchain).

## Reproduction

`suffix.c`:

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

```text
$ e-acsl-gcc -G clang -F -e-acsl-full-mtracking -o full.inst.c -O full suffix.c && ./full.e-acsl
suffix.c:6: Error: Assertion failed: ... \valid_read(charset + j) ... - j: 1
Aborted                                     (exit 134)
$ e-acsl-gcc -G gcc -F -e-acsl-full-mtracking -o gfull.inst.c -O gfull suffix.c && ./gfull.e-acsl
                                            (exit 0)
$ e-acsl-gcc -G clang -o plain.inst.c -O plain suffix.c && ./plain.e-acsl
                                            (exit 0)
```

Where the strings are, in a full-tracking clang build of the same two literals (`34.0~beta`, with
`-rte` instead of the assertion, `-e -O1`):

```text
$ objdump -s -j .rodata base.e-acsl | grep ' 202c'
 14000 01000200 202c0026 72007369 7a656f66  .... ,.&r.sizeof
```

`" ,"` is at `0x14004`; `","` was given `0x14005`, inside it. `clang -c` emits the strings in
`.rodata.str1.1` with flags `AMS` with or without `-fno-merge-constants`.

Control: moving the `","` group before the `" ,"` group in `__e_acsl_globals_init` of `full.inst.c`
and rebuilding with `e-acsl-gcc -C -G clang` gives exit 0. The longer block, registered last, covers
the shared bytes again.

The same happens with long blocks (over 64 bytes, kept in the secondary shadow); there the first
failing check can be `\initialized(charset + j)` at `j == 0`.

## Cause

`plugins/e-acsl/src/analyses/memory_tracking.ml`: literals are demoted to plain arrays
(`Demote_string_literal.demote`) only in `Varinfos.add` and in the libc-replacement case of the
dataflow, that is, only when the backward analysis decides that a literal must be monitored. With
`-e-acsl-full-mtracking`, the public `must_monitor_vi`/`must_monitor_lval`/`must_monitor_exp` return
`true` without consulting the analysis, so no literal is ever demoted. The printer then prints each
literal varinfo as the literal text (`printer.ml`, the `is_string_literal` cases), both in the
registration and at the use site, and the program's correctness now depends on how the compiler and
linker lay out string literals.

## Proposed fix (not validated)

Under `-e-acsl-full-mtracking`, demote every string literal that is registered, as the analysis does
for monitored literals without full tracking. For example, demote in the full-tracking branch of
the public `must_monitor_vi`, or demote every `fc_literal` global once before the global observer
runs. The registered object is then a named array: the linker does not merge it, its bounds are
exact, and the output no longer depends on the toolchain.

A cheaper partial fix: register literals by ascending size in `__e_acsl_globals_init`. A merged
suffix then lies inside the enclosing block, which is registered last. Reads past its end are still
caught (the two literals share their terminator). A read before the start of the suffix, or its
`\base_addr`/`\offset`/`\block_length`, then reports the enclosing literal.

## Workaround

Post-process the instrumented source to reorder the literal registrations in
`__e_acsl_globals_init` by ascending block size (the cheaper fix above), or build with `-G gcc`
where libFuzzer is not needed.
