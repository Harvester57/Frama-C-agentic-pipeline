# Variadic: calls in declaration initializers are printed with the generated name (`int fd = open_fallback_1(...)`), so printed code does not link

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

## Summary

The Variadic translation replaces calls to variadic functions with calls to generated fixed-arity
functions (`__va_open_void`, `__va_fcntl_int`, `open_fallback_1`, `printf_va_1`, ...). Because those
functions exist only as prototypes, `variadic.ml` installs a printer extension (`change_printer`)
that prints the **original** callee, with the generated name in a comment:

```c
fd = open("/dev/null",00,0); /* open_fallback_1 */
```

The extension matches only `Call` instructions. When the call initializes a local variable, the
instruction is `Local_init(v, ConsInit(f, args, kind), loc)`, and the generated name is printed as
the callee:

```c
int fd = open_fallback_1((char const *)*(argv + 0),00);
int fl = fcntl_fallback_1(fd,3);
```

With Frama-C's libc, `__va_*` is declared in the printed code but not defined. In host-header mode
(`-no-frama-c-stdlib`), `<fn>_fallback_<N>` is declared but defined nowhere. Either way the printed
program does not link. `int fd = open(path, O_RDONLY);` is one of the most common lines in C code.

This hits E-ACSL users first, because `e-acsl-gcc` runs Frama-C in host-header mode by default
and compiles its printed output. But it is a kernel bug: plain `frama-c -print -ocode` shows it.

## Versions

- Reproduced with Frama-C `35.0~~dev (Bromine)`, built from `master` at `ad24dca` (2026-11-02),
  Debian 13, gcc 14.2.0.
- Also present in `34.0~~dev (Selenium)`, and first seen with 33.0.

## Reproduction

`v3.c`:

```c
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  int fd = open(argv[0], O_RDONLY);
  int fl = fcntl(fd, F_GETFL);
  close(fd);
  return fl < 0;
}
```

```text
$ frama-c -no-frama-c-stdlib v3.c -print -ocode v3p.c
$ grep -n fallback v3p.c
11:int open_fallback_1(char const *__file, int __oflag);
15:int fcntl_fallback_1(int __fd, int __cmd);
20:  int fd = open_fallback_1((char const *)*(argv + 0),00);
21:  int fl = fcntl_fallback_1(fd,3);
$ gcc -w v3p.c -o v3p
undefined reference to `open_fallback_1'
undefined reference to `fcntl_fallback_1'

$ e-acsl-gcc -o v.instrumented.c -O v v3.c
v.instrumented.c:(.text+0x2c): undefined reference to `open_fallback_1'
e-acsl-gcc: fatal error: fail to compile/link instrumented code
```

The same call written as an assignment (`int fd; fd = open(...);`) prints as
`fd = open(...); /* open_fallback_1 */` and links.

The repository's own oracles show both forms side by side. In
`tests/variadic/known/oracle/ioctl.0.res.oracle`:

```c
  int r2 = __va_ioctl_ptr(fd1,request1,(void *)(& arg));    /* Local_init */
  ioctl(fd1,request1,(void *)p); /* __va_ioctl_ptr */        /* Call */
```

## Proposed fix

Give `Local_init` / `ConsInit` the same treatment as `Call`:

```diff
--- a/src/kernel/services/ast_transformations/variadic/variadic.ml
+++ b/src/kernel/services/ast_transformations/variadic/variadic.ml
@@ -35,6 +35,15 @@ let change_printer =
                 Call(res, Var old_vi, args, loc)
               in
               Format.fprintf fmt "%a /* %s */" super#instr old_instr vi.vname
+            (* Same for a call initializing a local variable. *)
+            | Local_init(v, ConsInit(vi, args, kind), loc)
+              when Replacements.mem vi ->
+              let old_vi = Replacements.find vi in
+              let old_vi = { vi with vname = old_vi.vname } in
+              let old_instr =
+                Local_init(v, ConsInit(old_vi, args, kind), loc)
+              in
+              Format.fprintf fmt "%a /* %s */" super#instr old_instr vi.vname
             (* Otherwise keep the instruction. *)
             | _ ->
               super#instr fmt i
```

## Validation of the proposed fix

Built from `ad24dca` with the patch:

| Check | `master` | Patched |
|---|---|---|
| `frama-c -no-frama-c-stdlib v3.c -print`, then `gcc` | `int fd = open_fallback_1(…)`; link fails | `int fd = open(…); /* open_fallback_1 */`; links |
| `e-acsl-gcc v.c` (`int fd = open("/dev/null", O_RDONLY, 0);`) | link fails | builds; runs, exit 0 |
| Assignment form (`fd = open(…);`) | `/* open_fallback_1 */` comment | unchanged |
| ptests `tests/variadic`, `tests/libc`, `tests/pretty_printing` | — | 4 oracle changes, all intended (below) |

The four oracles that change are each a `Local_init` line that now prints like the `Call` lines next
to it:

```diff
# tests/variadic/known/oracle/open.0.res.oracle
-  int fd1 = __va_open_mode_t((char const *)file,flag,(mode_t)mode);
-  int fd2 = __va_open_void((char const *)file,flag);
-  int fd3 = open_fallback_1((char const *)file,flag,mode,3,"arg4",5);
+  int fd1 = open((char const *)file,flag,(mode_t)mode); /* __va_open_mode_t */
+  int fd2 = open((char const *)file,flag); /* __va_open_void */
+  int fd3 = open((char const *)file,flag,mode,3,"arg4",5); /* open_fallback_1 */
# tests/variadic/known/oracle/ioctl.0.res.oracle
-  int r1 = __va_ioctl_void(fd1,request1);
+  int r1 = ioctl(fd1,request1); /* __va_ioctl_void */
-  int r2 = __va_ioctl_ptr(fd1,request1,(void *)(& arg));
+  int r2 = ioctl(fd1,request1,(void *)(& arg)); /* __va_ioctl_ptr */
# tests/variadic/known/oracle/fcntl.0.res.oracle
-  int flags = __va_fcntl_void(0,1);
+  int flags = fcntl(0,1); /* __va_fcntl_void */
# tests/variadic/known/oracle/printf_garbled_mix.0.res.oracle
-  int nb_printed = printf_va_1("%d",(int)b);
+  int nb_printed = printf("%d",(int)b); /* printf_va_1 */
```

## Workaround

`-no-variadic-translation` (verified: the instrumented `v3.c` links and runs). Alternatively, write
the call as a separate assignment, or provide link-time definitions of `<fn>_fallback_<N>` that
forward to the real function.
