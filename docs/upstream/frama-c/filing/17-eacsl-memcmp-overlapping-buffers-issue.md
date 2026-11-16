# [E-ACSL] With `--libc-replacements`, `memcmp` on overlapping or identical buffers aborts with "memcpy: overlapping memory areas"

<!-- Everything below this line is the issue description. -->

### Summary

With `--libc-replacements`, E-ACSL's `memcmp` replacement checks that its two buffers do not overlap, a check copied from `memcpy`. It aborts with "memcpy: overlapping memory areas" on valid calls, such as comparing a buffer with itself or two slices of one buffer.

### Steps to reproduce the issue

`memcmp.c`:

```c
#include <string.h>

int main(void) {
  char buf[8] = "abababa";
  int same = memcmp(buf, buf, 4);        /* identical ranges */
  int overlap = memcmp(buf, buf + 2, 4); /* overlapping ranges */
  return (same == 0 && overlap == 0) ? 0 : 1;
}
```

```
$ e-acsl-gcc --libc-replacements -c -O prog memcmp.c
$ ./prog; echo $?
$ ./prog.e-acsl; echo $?
```

### Expected behaviour

`memcmp` only reads its arguments and has no `restrict` parameter (C17 7.24.4.1), so comparing
identical or overlapping ranges is valid. `prog.e-acsl` exits with 0, like `prog`.

### Actual behaviour

```
$ ./prog; echo $?
0
$ ./prog.e-acsl; echo $?
memcpy: overlapping memory areas
Aborted (core dumped)
134
```

Each of the two calls aborts on its own. `memcmp(buf, buf + 4, 3)` (disjoint ranges) and
`memcmp(buf, buf, 0)` do not.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc --libc-replacements`, that is `-e-acsl-replace-libc-functions`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

`eacsl_builtin_memcmp` in `plugins/e-acsl/share/e-acsl/libc_replacements/e_acsl_string.c:237-242`
checks that both ranges are allocated, then calls
`validate_overlapping_spaces((uintptr_t)s1, n, (uintptr_t)s2, n, "memcpy")` (line 240). The line was
copied from `eacsl_builtin_memcpy`, function name included. The replacements of `strcmp` and
`strncmp` in the same file check only that their arguments are allocated.

Fix: remove the overlap check from `eacsl_builtin_memcmp`; the allocation checks stay. With this
change, `prog.e-acsl` exits with 0, and the E-ACSL test suites (default and `dev` configurations;
`format` in the default configuration only, see the merge request) give the same results as on
`master`. A merge request with a fix and a test follows.

Unrelated to the abort, a few diagnostics in the same file name the wrong function:
`eacsl_builtin_memmove` passes `"memcmp"` to `validate_allocated_space` and
`validate_writeable_space` (lines 245-246), `eacsl_builtin_strcpy` passes `"strlen"` (lines 142 and
145), and `eacsl_builtin_strncat` passes `"strcat"` (lines 201 and 210). For instance, a `memmove`
into a freed buffer reports `memcmp: destination space  space unallocated or cannot be written`.
The merge request does not change them.

Workaround: do not use `--libc-replacements`.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
