# [kernel] Variadic: print original callee for calls in local initializers

- Source branch: `fix/variadic-local-init-printer` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/03-variadic-fallback-local-init.patch`](../patches/03-variadic-fallback-local-init.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2796.

## Problem

The Variadic translation replaces a call to a variadic function with a call to a generated
fixed-arity prototype (`__va_open_void`, `open_fallback_1`, `printf_va_1`, ...). These prototypes
are never defined, so `change_printer` prints the original callee with the generated name in a
comment. It only matched `Call` instructions: a call that initializes a local variable is a
`Local_init(v, ConsInit(f, args, kind), loc)` and was printed with the generated name
(`int fd = open_fallback_1(...);`). The printed program then does not link, and `e-acsl-gcc`
fails with `fail to compile/link instrumented code` on such programs.

## Change

`src/kernel/services/ast_transformations/variadic/variadic.ml`: handle
`Local_init(v, ConsInit(vi, args, kind), loc)` with `Replacements.mem vi` the same way as `Call`,
i.e. print it with the original function and the generated name in a comment:

```c
  int fd = open((char const *)file,flag); /* __va_open_void */
```

Four oracles of `tests/variadic/known` change accordingly; they are the regression test (each
`Local_init` line now prints like the `Call` lines next to it):

- `open.0.res.oracle`: 3 lines (`__va_open_mode_t`, `__va_open_void`, `open_fallback_1`)
- `ioctl.0.res.oracle`: 2 lines (`__va_ioctl_void`, `__va_ioctl_ptr`)
- `fcntl.0.res.oracle`: 1 line (`__va_fcntl_void`)
- `printf_garbled_mix.0.res.oracle`: 1 line (`printf_va_1`)

## Testing

On `3dff90fc70` (Debian 13, OCaml 5.5 switch, gcc 14.2), with the patch built and installed:

- Reproducer of the issue (`frama-c -no-frama-c-stdlib v.c -print`, then `gcc`): before,
  `int fd = open_fallback_1(...)` and the link fails on `open_fallback_1`/`fcntl_fallback_1`;
  after, `int fd = open((char const *)*(argv + 0),00); /* open_fallback_1 */` and it links.
- `e-acsl-gcc v.c`: before, `fail to compile/link instrumented code`; after, builds and runs
  (exit 0).
- ptests `tests/variadic`, `tests/libc`, `tests/pretty_printing` (398 test results): the four
  oracle changes above, promoted; the rerun after promotion passes with no difference. Other
  suites were not run, but a `git grep` of all oracles on `3dff90fc70` for a local initialized by
  a call to a translated variadic function (`__va_*`, `*_va_<n>`, `*_fallback_<n>`) finds only the
  lines changed here.
- `make check-lint` on the changed files (`LINTCK_FILES_INPUT`, ocp-indent 1.10.0): clean.
- `git diff --check`: clean.
- `make check-headers`: not run (no new file).

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
