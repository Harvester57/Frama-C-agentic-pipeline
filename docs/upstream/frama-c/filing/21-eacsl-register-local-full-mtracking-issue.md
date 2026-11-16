# [E-ACSL] A `register` local makes E-ACSL abort with "Taking the address of a register variable" under -e-acsl-full-mtracking

<!-- Everything below this line is the issue description. -->

### Summary

Under `-e-acsl-full-mtracking`, E-ACSL aborts with "Taking the address of a register variable" on any function with a `register` local, because it observes every local through its address. A plain `register unsigned i` loop counter is enough.

### Steps to reproduce the issue

`r.c`:

```c
int main(void)
{
  register unsigned i;
  unsigned sum = 0;
  for (i = 0; i < 4; i++)
    sum += i;
  return sum != 6;
}
```

`a.c`:

```c
int main(void)
{
  register int i = 1;
  /*@ assert \initialized(&i); */
  return i - 1;
}
```

```sh
e-acsl-gcc -q -X -o r.inst.c -O r r.c       # fine
e-acsl-gcc -q -X -M -o r.inst.c -O r r.c    # full memory tracking
e-acsl-gcc -q -X -o a.inst.c -O a a.c
```

### Expected behaviour

Both programs are instrumented, compile and exit 0.

### Actual behaviour

`r.c` instruments and runs without `-M`. With `-M`, and for `a.c` without `-M`, Frama-C aborts:

```text
[kernel] Failure: Taking the address of a register variable with &[ i ]
[kernel] Frama-C aborted: internal error (Taking the address of a register variable with &[ i ]).
  Please report as 'crash' at https://git.frama-c.com/pub/frama-c/issues
e-acsl-gcc: fatal error: aborted by Frama-C
```

The backtrace for `r.c` with `-M`:

```text
  Called from Frama_c_kernel_base__Cil.mkAddrOf.fatal in file "src/kernel/services/ast_queries/cil.ml", line 4871, characters 4-81
  Called from E_ACSL__Smart_stmt.initialize in file "plugins/e-acsl/src/code_generator/smart_stmt.ml", line 151, characters 32-52
  Called from E_ACSL__Injector.add_initializer in file "plugins/e-acsl/src/code_generator/injector.ml", line 173, characters 13-42
  Called from E_ACSL__Injector.inject_in_instr in file "plugins/e-acsl/src/code_generator/injector.ml", line 190, characters 14-48
```

Any program with a `register` local loses E-ACSL under full memory tracking.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** E-ACSL observes a monitored variable through its address: `__e_acsl_store_block(&i, ...)`,
`__e_acsl_full_init(&i)` (`Smart_stmt.initialize`, `plugins/e-acsl/src/code_generator/smart_stmt.ml:151`),
`__e_acsl_delete_block(&i)`, `\initialized(&i)`. They are built with `Cil.mkAddrOf` or
`Cil.mkAddrOfVi`, which abort on a variable whose storage is `Register`
(`src/kernel/services/ast_queries/cil.ml:4875`). Under `-e-acsl-full-mtracking` every local is
monitored. Without it, a memory predicate on the local is enough.

**Fix.** `register` is only a hint whose one constraint is that the program cannot take the variable's
address (C11 6.7.1p6), and the original program does not (the kernel rejects `&i`). E-ACSL can drop the
storage class from the locals and formals of the functions it instruments, in `Injector.inject_in_fundec`,
next to where it already rewrites them (ghost status). The instrumented program then declares
`unsigned int i;`. A merge request with a fix follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
