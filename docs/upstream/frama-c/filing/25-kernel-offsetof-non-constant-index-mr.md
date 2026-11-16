# [kernel] offsetof: accept non-constant array indexes (GCC extension)

- Source branch: `fix/offsetof-non-constant-index` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/25-kernel-offsetof-non-constant-index.patch`](../patches/25-kernel-offsetof-non-constant-index.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2813.

## Problem

GCC and Clang accept `__builtin_offsetof(T, m[i])` with a non-constant index `i` and compute it at
run time (libseccomp's `offsetof(struct seccomp_data, args[x])`, for instance). Frama-C's grammar
accepts the designator, but the typer folds it with `Cil.bitsOffset`, which raises
`SizeOfError "Index is not constant"`, and the parsing stops with
`Unable to compute offset .args[i] in type struct s: Index is not constant`.

## Change

`src/kernel/internals/typing/cabs2cil.ml`, `__builtin_offsetof` case: each non-constant index of
the designator is replaced by 0, the resulting offset is folded with `Cil.bitsOffset` as before, and
`(size_t)i * sizeof(element)` is added for each replaced index:

```c
offsetof(struct s, inner[i].v[j])
  ~> (16UL + (unsigned long)i * 40UL) + (unsigned long)j * 8UL
```

Designators whose indexes are all constant go through the same path as before and give the same
constant (so `_Static_assert` on them still works); the error for bit-fields and other
`SizeOfError`s is unchanged. The non-constant case is accepted silently, as GCC and Clang do; a
warning, or restricting it to GCC-like machdeps, would be easy to add if you prefer (the grammar
accepts these designators for every machdep today).

New test `tests/syntax/offsetof_non_constant_index.c` (x86_32, `-print`): one index, two nested
indexes, a mix of constant and variable indexes, and a `_Static_assert` on a constant index.

## Testing

On a build of `3dff90fc70` with the patch (Debian 13, OCaml 5.5 switch):

- Reproducer from the issue (x86_64): before, two `User Error`s and the parsing stops; after, the
  offsets print as `128UL + (unsigned long)i * 8UL` and
  `(16UL + (unsigned long)i * 40UL) + (unsigned long)j * 8UL`, Eva with `-warn-invalid-pointer`
  reports 0 alarms, and WP (`-wp-rte`, Alt-Ergo 2.4.3) proves 13/13 goals, including
  `ensures \result == 128 + 8 * i` and `ensures \result == 16 + 40 * i + 8 * j`. The program
  compiled by gcc returns 0, matching these values.
- ptests, default configuration: `dune build @tests/ptests_config` (1217 results) passes; the only
  change is the new oracle.
- A non-constant index in a constant context is still rejected, as by gcc: file-scope initializer
  (`n is not a compile-time constant`), global array size (`Global arrays cannot have variable
  size`), `_Static_assert` (`failed to evaluate constant expression in static assertion`), `case`
  label (`Case statement with a non-constant`). As a local array size it gives a VLA, as with gcc.
- `dune build --profile dev @src/kernel/check`: exit 0, no output.
- `git diff --check`: only the final blank line of the new oracle (Frama-C output).
- `./dev/check-files.sh -p` (that is, `make check-lint` and `make check-headers` on the changed
  files) with ocp-indent 1.10.0 and clang-format 19.1.7: clean.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
