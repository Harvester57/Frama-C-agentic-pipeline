# [E-ACSL] A monitored const union global makes E-ACSL fail with "implicit cast: cast from union u to void *"

<!-- Everything below this line is the issue description. -->

### Summary

A monitored `const` union global makes E-ACSL fail with "implicit cast: cast from union u to void *", so the program cannot be instrumented. It has the same root cause, and the same fix, as the read-only marking bug of `const` scalar globals reported in #2794.

### Steps to reproduce the issue

`u.c`:

```c
union u { unsigned char b[16]; unsigned long w[2]; };

static const union u zero_block;

int main(void) { return zero_block.b[0]; }
```

```sh
e-acsl-gcc -q -X -M -o u.inst.c -O u u.c
```

(`-M` is `-e-acsl-full-mtracking`. Without it, the global is not monitored in this program and it
instruments and runs.)

### Expected behaviour

The program is instrumented, compiles and exits 0, with `zero_block` marked read-only.

### Actual behaviour

```text
[kernel] u.c:3: User Error: 
  implicit cast: cast from union u to void *
[kernel] Frama-C aborted: invalid user input.
e-acsl-gcc: fatal error: aborted by Frama-C
```

- `static` does not matter: a non-static `const union u zero_block;` and a `static const` union local to
  a function fail the same way.
- An initializer (`= { { 0 } }`) does not matter.
- A `static const` struct with the same members, and a non-const `static` union, instrument and run.
- `frama-c -print u.c` is clean: the cast is in the code E-ACSL generates.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** Same as #2794. `Global_observer.mk_init_function`
(`plugins/e-acsl/src/code_generator/global_observer.ml:130`) marks a const global read-only with
`__e_acsl_mark_readonly((void *)g)`, passing the value of the global (`Cil.evar ~loc vi`) for every type
but structs. For a union, the conversion to `void *` is not a valid cast and the kernel rejects
E-ACSL's code. Structs are spared because they have their own branch (one call per field address,
e-acsl#223).

**Fix.** Pass the address of the global (`Cil.mkAddrOfVi vi`) for every type but arrays. The merge
request for #2794 does this and adds a const union to its regression test.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
