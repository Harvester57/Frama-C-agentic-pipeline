# [E-ACSL] Unexpected error Rtl.Symbols.Unregistered("__gmpz_clear") when the program uses GMP and an annotation needs GMP

<!-- Everything below this line is the issue description. -->

### Summary

E-ACSL stops with `Unexpected error (Rtl.Symbols.Unregistered("__gmpz_clear"))` when the program itself declares GMP functions (by including `<gmp.h>` and calling them) and an annotation needs E-ACSL's own GMP code. Either condition alone works.

### Steps to reproduce the issue

`g.c` declares two GMP functions itself, as `<gmp.h>` does, so it needs no GMP headers:

```c
/* The program declares and calls two GMP functions itself (as <gmp.h> would
   make it do), and the assertion needs GMP: a * b can exceed 64 bits. */
struct my_mpz { int alloc; int size; unsigned long *d; };
void __gmpz_init(struct my_mpz *z);
void __gmpz_clear(struct my_mpz *z);

int f(unsigned long a, unsigned long b)
{
  struct my_mpz z;
  __gmpz_init(&z);
  __gmpz_clear(&z);
  /*@ assert a * b + 1 > 0; */
  return 0;
}

int main(void)
{
  return f(3, 4);
}
```

```sh
e-acsl-gcc -q -X -o g.inst.c -O g g.c
```

The same happens with `#include <gmp.h>`, `mpz_t z; mpz_init(z); mpz_clear(z);` and
`e-acsl-gcc -q -X -l -lgmp ...`.

### Expected behaviour

The program is instrumented, compiles and exits 0. The generated GMP code for the assertion calls the
GMP functions the program also uses.

### Actual behaviour

```text
[kernel] Unexpected error (E_ACSL__Rtl.Symbols.Unregistered("__gmpz_clear")).
  Please report as 'crash' at https://git.frama-c.com/pub/frama-c/issues
e-acsl-gcc: fatal error: aborted by Frama-C
```

Either condition alone is fine: without the assertion, or without the program's GMP declarations and
calls, the program instruments and runs.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** `lookup_rtl_globals` (`plugins/e-acsl/src/project_initializer/rtl.ml:210-220`) sorts the
runtime library's functions when linking it with the user's AST. A function the user's AST does not
have is registered in `Rtl.Symbols` (`add`). A function it already has is only recorded in `Assocs`
(`assoc`), to merge the RTL contract into the user's function, and never enters `Rtl.Symbols`. The RTL
declares the GMP functions under their real names (`__gmpz_clear`,
`plugins/e-acsl/share/e-acsl/numerical_model/e_acsl_gmp_api.h:198`), so when the program declares them too,
`Smart_stmt.rtl_call` (`plugins/e-acsl/src/code_generator/smart_stmt.ml:130-139`) later fails to find
them and raises `Unregistered`.

**Scope (hypothesis).** Nothing in this code path is specific to GMP: any RTL function that
`Smart_stmt.rtl_call` uses and that the program also declares should hit the same error. I only
reproduced it with the GMP functions, the ones a program is most likely to declare itself.

**Possible fixes.** I am not opening a merge request yet, because the choice between these is yours:

1. **Register the user's function under the RTL name.** In the `assoc` branch for functions, also
   call `Symbols.add_vi vi.vname (Kernel_function.get_vi kf)`. The generated code then calls the
   program's declaration of the same function; `Smart_stmt.do_call` already casts the arguments to its
   parameter types (for the reproducer, `__gmpz_clear((struct my_mpz *)(__gen_e_acsl_mul));`).
   I tested this one-line change on `master`: both reproducers (header-free and `<gmp.h>` with
   `-lgmp`) build and run with exit 0, a new `bts/` test with this program fails before and passes
   after (default and `dev` configurations), and the default and `dev` ptests of every E-ACSL test
   directory except `libc/` show no other oracle change. **Side effect:** `Rtl.Symbols.mem_vi` becomes
   true for these names too. Its only user, `Memory_tracking.must_never_monitor`, tests variables by
   name, so a local variable named like one of these functions would no longer be monitored.
2. **Keep a separate table** for RTL functions linked to a user function, and make `rtl_call` look
   there when `Rtl.Symbols` has no entry. This avoids the side effect above, at the cost of a second
   lookup. I have not implemented it.
3. **Keep the RTL's own declaration** instead of linking it with the user's. I do not think this
   works: the two declarations have different parameter types (the RTL's `eacsl_mpz_t` against the
   program's `struct my_mpz *`, or `__mpz_struct *` with `<gmp.h>`), so the generated C file would
   contain conflicting declarations of the same function. Not tried.

**Question for the maintainers.** Is the side effect of option 1 acceptable (a local variable that
shares its name with an RTL function the program declares stops being monitored), or do you prefer
option 2, or another approach? I can open a merge request for the one you choose, with the
regression test above.

The closed #197 ("Plug-in crash with Unregistered_library_function error", 2015, fixed in Silicon)
had a similar message for `__store_block`, raised as `Misc.Unregistered_library_function`, which no
longer exists in the sources.
It does not involve GMP or a function the program declares, so I do not think it is the same bug.

The analysis and the tested fix were prepared with LLM assistance (Claude Code); I reviewed them and
ran the reproducer and tests described above.
