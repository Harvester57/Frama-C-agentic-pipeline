# [Kernel] Variadic: a variadic call in a local initializer is printed with the generated name (`int fd = open_fallback_1(...)`), so the printed program does not link

<!-- Everything below this line is the issue description. -->

### Summary

When Variadic translates a variadic call in the initializer of a local variable (`int fd = open(path, O_RDONLY);`), `-print` and `-ocode` output the generated name (`open_fallback_1`) instead of `open`, so the printed program does not link. Calls in plain statements are printed correctly.

### Steps to reproduce the issue

`v.c`:

```c
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
  (void)argc;
  int fd = open(argv[0], O_RDONLY);
  int fl = fcntl(fd, F_GETFL);
  close(fd);
  return fl < 0;
}
```

```sh
frama-c -no-frama-c-stdlib v.c -print -ocode printed.c
sed -n '/^int main/,/^}/p' printed.c | grep -E 'open|fcntl'
gcc -w printed.c -o printed
```

### Expected behaviour

The printed program links, as it does when the call is a separate assignment (`int fd; fd = open(...);`),
which prints as

```c
  fd = open((char const *)*(argv + 0),00); /* open_fallback_1 */
```

### Actual behaviour

```text
  int fd = open_fallback_1((char const *)*(argv + 0),00);
  int fl = fcntl_fallback_1(fd,3);
undefined reference to `fcntl_fallback_1'
undefined reference to `open_fallback_1'
```

`open_fallback_1` and `fcntl_fallback_1` are only declared, so the link fails. With Frama-C's libc,
the same lines print as `int fd = __va_open_void(...)`, which is not defined either. `e-acsl-gcc`
runs Frama-C in host-header mode and compiles the printed code, so it stops with
`fail to compile/link instrumented code` on any program that initializes a local with `open`,
`fcntl`, `ioctl`, `printf`, ...

The repository's own oracles show both forms side by side, e.g.
`tests/variadic/known/oracle/ioctl.0.res.oracle`:

```c
  int r2 = __va_ioctl_ptr(fd1,request1,(void *)(& arg));
  ioctl(fd1,request1,(void *)p); /* __va_ioctl_ptr */
```

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: kernel (Variadic translation); seen through E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** The Variadic translation replaces a call to a variadic function with a call to a
generated fixed-arity prototype. Since that prototype is never defined, `change_printer`
(`src/kernel/services/ast_transformations/variadic/variadic.ml:17-42`) installs a printer extension
that prints the original callee, with the generated name in a comment. Its `instr` method matches
only `Call(res, Var vi, args, loc)` (line 30). A call that initializes a local variable is a
`Local_init(v, ConsInit(vi, args, kind), loc)`, which falls into the default case and is printed
with the generated name.

**Fix.** Handle `Local_init(_, ConsInit(vi, _, _), _)` with `Replacements.mem vi` the same way as
`Call`: print the instruction with the original function's name, followed by the generated name
in a comment. The printed line becomes `int fd = open((char const *)*(argv + 0),00); /*
open_fallback_1 */`, and the program links. Four oracles of `tests/variadic/known` change
accordingly (`open`, `ioctl`, `fcntl`, `printf_garbled_mix`); nothing else in `tests/variadic`,
`tests/libc` or `tests/pretty_printing` changes.

Workaround: `-no-variadic-translation`, or write the call as a separate assignment.

A merge request with a fix follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
