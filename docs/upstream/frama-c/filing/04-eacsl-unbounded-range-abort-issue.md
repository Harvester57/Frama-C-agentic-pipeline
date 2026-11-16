# [E-ACSL] An unbounded range (`p + (0..)`) in any annotation, including the libc contracts used with `-L`, aborts the whole instrumentation

<!-- Everything below this line is the issue description. -->

### Summary

E-ACSL aborts the whole instrumentation as soon as one annotation contains an unbounded range such as `p + (0..)`, instead of ignoring that annotation with a warning as it does for other unsupported constructs. Frama-C's own libc uses such ranges, so `e-acsl-gcc -L` cannot instrument any program that calls `strtok_r`, `getsockopt`, `wcschr`, `wcspbrk`, `wcsrchr` or `wcsstr`.

### Steps to reproduce the issue

`u.c`:

```c
/*@ requires \valid_read(p + (0..));
    requires n >= 0; */
int first(const char *p, int n) { return n > 0 ? p[0] : 0; }

int main(void) {
  char b[2] = "a";
  return first(b, -1);
}
```

`s.c`, with no annotation at all:

```c
#include <string.h>

int main(void) {
  char buf[] = "a:b";
  char *save = 0;
  char *tok = strtok_r(buf, ":", &save);
  return tok == 0;
}
```

```sh
e-acsl-gcc -o u.inst.c -O u u.c
e-acsl-gcc -L -e -D_DEFAULT_SOURCE -o s.inst.c -O s s.c
```

(`-e -D_DEFAULT_SOURCE` only makes `strtok_r` visible to the compiler; it is not related to this
issue.)

### Expected behaviour

E-ACSL cannot check an unbounded range at runtime, so it should ignore the annotation that contains
it, with a warning, and instrument the rest of the program, as it does for every other construct it
cannot translate (`Error.not_yet` / `Error.untypable`: "... Ignoring annotation."). In `u.c`, the
valid clause `requires n >= 0` should still be checked.

### Actual behaviour

The whole run aborts and nothing is instrumented:

```text
[e-acsl] u.c:3: User Error:
  unbounded ranges are not part of E-ACSl
[kernel] Plug-in e-acsl aborted: invalid user input.
e-acsl-gcc: fatal error: aborted by Frama-C
```

```text
[e-acsl] FRAMAC_SHARE/libc/string.h:352: User Error:
  unbounded ranges are not part of E-ACSl
[kernel] Plug-in e-acsl aborted: invalid user input.
e-acsl-gcc: fatal error: aborted by Frama-C
```

With `-L` (Frama-C's libc), E-ACSL instruments the libc contracts of the called functions, and
several of them use unbounded ranges. A program that calls any of these six functions cannot be
instrumented at all with `-L` (each one checked on `master`):

| Function | Contract on `3dff90fc70` |
|---|---|
| `strtok_r` | `share/libc/string.h:354-355`: `requires separation: \separated(..., *saveptr+(0..))` |
| `getsockopt` | `share/libc/sys/socket.h:397-398`: `requires optval_null_or_valid: optval == \null \|\| \valid(((char*)optval)+(0..))` |
| `wcschr` | `share/libc/wchar.h:109-110`: `ensures result_null_or_inside_wcs: \result == \null \|\| \subset(\result, wcs+(0..))` |
| `wcspbrk` | `share/libc/wchar.h:200-201`: the same `ensures` on `wcs+(0 .. )` |
| `wcsrchr` | `share/libc/wchar.h:208-209`: the same `ensures` on `wcs+(0 .. )` |
| `wcsstr` | `share/libc/wchar.h:225-226`: `ensures result_null_or_inside_haystack: \result == \null \|\| \subset (\result, haystack+(0 .. ))` |

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`, gcc 14.2.0)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** Four places in E-ACSL react to `Trange(None, _) | Trange(_, None)` with
`Options.abort`, which stops the whole run instead of dropping the annotation:

- `plugins/e-acsl/src/analyses/interval.ml:519-520`
- `plugins/e-acsl/src/analyses/typing.ml:665-666`
- `plugins/e-acsl/src/analyses/memory_tracking.ml:389-390`
- `plugins/e-acsl/src/code_generator/memory_translate.ml:179-180`

(The recent interval changes for semi-bounded intervals in `interval_utils.ml` do not touch these
sites; the abort is unchanged on `3dff90fc70`.)

**Fix.** Raise `Error.untypable "unbounded range"` at the four sites, like the other constructs
outside the E-ACSL subset. The annotation is ignored with
``invalid E-ACSL construct `unbounded range'. Ignoring annotation.`` and the rest is instrumented.
With that change `u.c` builds and the remaining clause is checked:

```text
[e-acsl] u.c:1: Warning:
  invalid E-ACSL construct `unbounded range'. Ignoring annotation.
u.c:2: Error: Precondition failed:
	The failing predicate is:
	n ≥ 0.
```

and `s.c` builds and runs (exit 0) with `-L`. Callers of the five other functions build and run
too, each exiting with the value its `main` returns. The fix
also removes the "E-ACSl" typo of two of the messages.

The `getsockopt` contract is also wrong on its own (unsatisfiable for Eva, rejected by WP); that is
reported separately, and fixing it does not fix this issue.

Workaround: do not use `-L` for programs that call these functions, or override the contracts with
bounded ones.

A merge request with a fix follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
