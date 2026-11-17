# [E-ACSL] -e-acsl-full-mtracking registers string literals as literals: with clang, a literal stored inside another one makes \valid_read fail on correct code

<!-- Everything below this line is the issue description. -->

### Summary

With `-e-acsl-full-mtracking`, E-ACSL registers every string literal of the program as a block of its own and prints it as a literal, both in `__e_acsl_globals_init` and where it is used. clang puts literals in a mergeable section, and GNU ld stores a literal that is the suffix of another one inside it: `","` lands at `" ," + 1`. The two registered blocks overlap, and a correct loop over `" ,"` fails at its second byte with `\valid_read(charset + j)`. With gcc (`e-acsl-gcc` passes `-fno-merge-constants`), or without full tracking, the same program runs clean.

### Steps to reproduce the issue

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

```sh
e-acsl-gcc -q -G clang -F -e-acsl-full-mtracking -o a.inst.c -O a suffix.c && ./a.e-acsl
e-acsl-gcc -q -G gcc -F -e-acsl-full-mtracking -o b.inst.c -O b suffix.c && ./b.e-acsl
e-acsl-gcc -q -G clang -o c.inst.c -O c suffix.c && ./c.e-acsl
```

### Expected behaviour

The three programs exit 0: the program is correct.

### Actual behaviour

The first one (clang, full tracking) aborts:

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

(exit status 134)

The second (gcc, full tracking) and the third (clang, default tracking) exit 0.

With full tracking, `__e_acsl_globals_init` registers both literals as literals:

```c
    __e_acsl_store_block((void *)" ,",3UL);
    __e_acsl_full_init((void *)(& " ,"));
    __e_acsl_mark_readonly((void *)" ,");
    __e_acsl_store_block((void *)",",2UL);
    __e_acsl_full_init((void *)(& ","));
    __e_acsl_mark_readonly((void *)",");
```

Without full tracking, the monitored literal is a named array (`char const __fc_lit_string2[3UL] = " ,";`, registered as `__fc_lit_string2`), which the linker does not merge.

Where the strings are, without E-ACSL, in a program that prints the addresses of `" ,"` and `","`:

```text
clang -O0: " ,"=0x58a376d0b004 ","=0x58a376d0b005 diff=1
clang -O1: " ,"=0x63e22a209004 ","=0x63e22a209005 diff=1
gcc -O0 -fno-merge-constants: " ,"=0x635c2f461004 ","=0x635c2f461007 diff=3
```

`clang -c` emits the strings in `.rodata.str1.1` (flags `AMS`) with or without `-fno-merge-constants`, which clang ignores ("optimization flag '-fno-merge-constants' is not supported"). So restoring the CFLAGS that `-G clang` overwrites (#2810) does not help here.

The `,` block, registered second, takes over the shadow of the bytes it shares with `" ,"`, so `" ," + 1` is no longer in the block of `" ,"`. Moving the `","` registration before the `" ,"` one in the instrumented file makes the program pass. With longer literals (over 64 bytes), the first failing check can also be `\initialized(charset + j)` at `j == 0`.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 95408044f7 (and 3dff90fc70); also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie), clang 19.1.7, gcc 14.2.0, GNU ld 2.44

### Additional information (optional)

**Cause.** String literals are global variables with the `fc_literal` attribute, printed as the literal text. `plugins/e-acsl/src/analyses/memory_tracking.ml` demotes a literal to a plain array (`Demote_string_literal.demote`) only when the backward analysis decides to monitor it (`Varinfos.add`, and the libc-replacement case of `do_call`). With `-e-acsl-full-mtracking`, the public `must_monitor_vi`/`must_monitor_lval`/`must_monitor_exp` return `true` without running the analysis, so no literal is demoted, while `Global_observer` registers every one of them. The message of `9e28a826d0` ("Memory_tracking: demote all tracked strings") gives the reason a monitored literal must not be printed as a literal: the four printed copies are potentially different strings. The full-tracking shortcut dates from 2013 (`347c233b59`, `-e-acsl-full-mmodel`), and the demotion from 2025 (`1dbd6af88b`); I found no stated reason to leave full tracking out.

**Fix.** Under full tracking, demote every string literal that is registered, before the injection. The registered object is then a named array, which the linker does not merge, and the result no longer depends on the toolchain. Demoting the literals one by one costs one traversal of the AST per literal (instrumenting a file with 4,000 literals took 98 s instead of 2 s), so the merge request adds `Demote_string_literal.demote_list`, which demotes a list of literals in one traversal. A cheaper alternative would be to register the literals by increasing size in `__e_acsl_globals_init`, so that the enclosing literal is registered last; it fixes this case but `\base_addr`, `\offset` and `\block_length` of the suffix would then report the enclosing literal. A merge request with the first fix follows.

Related: #633 (closed), where one literal was registered again at every loop iteration; here the registration happens once, in `__e_acsl_globals_init`, and the problem is two literals sharing storage.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the reproducer and tests described above.
