# [Kernel] Feature request: support `offsetof(T, m[i])` with a non-constant index (GCC/Clang extension)

<!-- Everything below this line is the issue description. -->

### Summary

Frama-C rejects `offsetof(T, m[i])` when `i` is not a constant, with "Unable to compute offset ... Index is not constant". C17 requires a constant designator, but GCC and Clang accept this as an extension and glibc-based code (for instance libseccomp) uses it. This is a feature request, with a proposed implementation.

### Steps to reproduce the issue

`t.c`:

```c
#include <stddef.h>

struct s {
  int hdr;
  struct { char c; long v[4]; } inner[3];
  unsigned long long args[6];
};

/*@ requires 0 <= i < 6;
    assigns \nothing;
    ensures \result == 128 + 8 * i; */
size_t arg_offset(int i)
{
  return offsetof(struct s, args[i]);
}

/*@ requires 0 <= i < 3 && 0 <= j < 4;
    assigns \nothing;
    ensures \result == 16 + 40 * i + 8 * j; */
size_t inner_offset(int i, int j)
{
  return offsetof(struct s, inner[i].v[j]);
}

int main(void)
{
  return (int)(arg_offset(2) + inner_offset(1, 3)) - 224;
}
```

```
$ gcc -Wall -Wextra -pedantic -o t t.c && ./t; echo $?
0
$ frama-c t.c -print
```

### Expected behaviour

Frama-C accepts the program, as GCC and Clang do (both compile it without a warning, even with
`-pedantic`, and it returns 0), and gives `offsetof(struct s, args[i])` its run-time value
`128 + 8 * i` (x86_64).

### Actual behaviour

```
[kernel] t.c:14: User Error:
  Unable to compute offset .args[i] in type struct s: Index is not constant
[kernel] t.c:22: User Error:
  Unable to compute offset .inner[i].v[j] in type struct s: Index is not constant
[kernel] User Error: stopping on file "t.c" that has errors.
[kernel] Frama-C aborted: invalid user input.
```

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium), same output
- Plug-in used: kernel
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

This is a feature request rather than a bug: C17 7.19p3 requires the member designator of `offsetof`
to give an address constant, so a non-constant index is outside ISO C. GCC documents
`__builtin_offsetof` with a `[ expr ]` designator and computes it at run time; Clang does the same.
Real code relies on it. For instance libseccomp's `src/arch.c` computes
`offsetof(struct seccomp_data, args[x])` with a variable `x` (its `default_arg_offset` macro), so
that file cannot be parsed by Frama-C.

Frama-C's grammar already accepts such designators (`offsetof_member_designator`, "GCC extension
for __builtin_offsetof", `src/kernel/internals/parsing/cparser.mly:586-591`). The typer then folds
the whole designator with `Cil.bitsOffset` (`src/kernel/internals/typing/cabs2cil.ml:6962-6986` on
`3dff90fc70`), which raises `SizeOfError "Index is not constant"`
(`src/kernel/services/ast_queries/cil.ml:3645`), and the error stops the parsing.

Defining `offsetof` as `((size_t)&((T *)0)->m)` instead is not a good workaround (observed on
35.0~~dev): the kernel no longer folds it, Eva with `-warn-invalid-pointer` reports `\object_pointer(&((struct s *)0)->arr)`
as invalid, WP cannot prove offsets, and `_Static_assert` on an offset stops the parsing.

Proposed implementation (merge request follows): in the `__builtin_offsetof` case of the typer,
replace each non-constant index of the designator by 0, fold the resulting constant offset with
`Cil.bitsOffset` as today, and add `(size_t)i * sizeof(element)` for each such index:

```c
size_t arg_offset(int i)
{
  size_t __retres;
  __retres = 128UL + (unsigned long)i * 8UL;
  return __retres;
}
size_t inner_offset(int i, int j)
{
  size_t __retres;
  __retres = (16UL + (unsigned long)i * 40UL) + (unsigned long)j * 8UL;
  return __retres;
}
```

Designators with constant indexes are folded to the same constant as before (so they stay integer
constant expressions, and `_Static_assert` on them still works). With it, Eva
(`-warn-invalid-pointer`) reports 0 alarms on the example and WP (`-wp-rte`, Alt-Ergo) proves all 13
goals, including both `ensures`.

Questions for the maintainers:

- Should this be accepted silently, as GCC and Clang do, or with a warning (it is not ISO C)?
- Should it be limited to GCC-like machdeps? The grammar accepts these designators for all
  machdeps today.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
