# [E-ACSL] Non-finite suffixed floating-point constants (`1e40f`, `1e400d`) emit undeclared `inf` and `__gmpq_set_d(..., inf)`

<!-- Everything below this line is the issue description. -->

### Summary

When an ACSL annotation contains a suffixed floating-point literal that overflows its target format
(such as `1e40f`, `1e400d`, or `0x1p2000d`), the kernel parses it as an exact `LReal` with
`r_lower = r_upper = r_nearest = infinity`. E-ACSL's `Interval.infer_term` and
`Translate_terms.constant_to_exp_old` check only `lr.r_lower = lr.r_upper` without checking whether
`lr.r_nearest` is finite. As a result, E-ACSL emits `CReal(infinity, FDouble, None)`, which:

1. prints as bare `inf` in the generated C code (even without `-constfold` and even with
   `-float-print hex`), causing `e-acsl-gcc` compilation to fail with `error: 'inf' undeclared`;
2. in rational contexts (such as `assert 0.1 < 1e40f;`), emits
   `__gmpq_set_d(__gen_e_acsl__3, (double)((float)inf));`, where passing an IEEE infinity to GMP's
   `mpq_set_d` raises `SIGFPE` (exit 136) at run time even if the kernel printer is fixed to emit a
   valid C infinity expression.

### Steps to reproduce the issue

`non_finite.c`:

```c
int main(void) {
  double x = 0.5;
  /*@ assert x < 1e40f; */
  return 0;
}
```

```sh
e-acsl-gcc -c -o non_finite.gen.c -O non_finite non_finite.c
```

With `-float-print hex`:

```sh
e-acsl-gcc -c -F "-float-print hex" -o non_finite.gen.c -O non_finite non_finite.c
```

Rational-context variant (`non_finite_gmp.c`):

```c
int main(void) {
  /*@ assert 0.1 < 1e40f; */
  return 0;
}
```

```sh
frama-c non_finite_gmp.c -e-acsl -then-last -print
```

### Expected behaviour

E-ACSL should not emit uncompilable C (`inf`) or pass a non-finite `double` to `__gmpq_set_d`. Since
GMP rationals cannot represent infinity, E-ACSL should report the non-finite floating-point constant
as not yet supported and ignore the annotation cleanly so compilation succeeds and remaining
annotations continue to be checked.

### Actual behaviour

`e-acsl-gcc -c` fails to compile the generated code (exit status 1), both by default and with
`-F "-float-print hex"`:

```text
non_finite.gen.c: In function ‘main’:
non_finite.gen.c:251:25: error: ‘inf’ undeclared (first use in this function); did you mean ‘int’?
  251 |     __e_acsl_assert(x < inf,& __gen_e_acsl_assert_data);
      |                         ^~~
      |                         int
non_finite.gen.c:251:25: note: each undeclared identifier is reported only once for each function it appears in
e-acsl-gcc: fatal error: fail to compile/link instrumented code
```

The same error occurs for `1e400d` and `0x1p2000d`. On `non_finite_gmp.c`, `frama-c -e-acsl` emits:

```c
    __gmpq_init(__gen_e_acsl__3);
    __gmpq_set_d(__gen_e_acsl__3,(double)((float)inf));
```

Calling `mpq_set_d(q, (double)((float)INFINITY))` in a standalone C program against GMP 6 on this
system terminates with `Floating point exception` (`SIGFPE`, exit status 136).

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at `189053d4a2`; also 34.0~beta (Selenium), identical behaviour
- Plug-in used: E-ACSL (`e-acsl-gcc` and `frama-c -e-acsl`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** `Logic_utils.parse_float` (`src/kernel/services/ast_queries/logic_utils.ml`, lines
294-308 on `189053d4a2`) constructs `real_of_float literal nearest` for suffixed literals (`f`, `d`,
`f32`, `f64`), setting `r_lower = r_upper = r_nearest = infinity` on overflow (consistent with ACSL
Section 2.2.5). While the kernel's `Cil.isExactFloat` (`src/kernel/services/ast_queries/cil.ml`,
lines 2494-2495) checks `r.r_upper = r.r_lower && isFiniteFloat fk r.r_nearest`, E-ACSL checks only
`lr.r_lower = lr.r_upper` in two places:

- `plugins/e-acsl/src/analyses/interval.ml`, lines 530-532;
- `plugins/e-acsl/src/code_generator/translate_terms.ml`, lines 128-131.

Because `infinity = infinity` in OCaml, E-ACSL treats the constant as a regular `FDouble` without
source text (`Cil.kfloat ~loc FDouble infinity`), bypassing the `Rational` branch and passing
`infinity` both to `cil_printer.ml` and (when promoted in a mixed rational predicate) to
`__gmpq_set_d`. Note that unsuffixed overflowing real constants such as `1e400` have
`r_lower = max_float <> infinity = r_upper` and are unaffected.

**Fix.** Guard both `LReal` branches in `interval.ml` and `translate_terms.ml` with
`Floating_point.is_finite lr.r_nearest`, calling `Error.not_yet "non-finite floating-point constant"`
when `lr.r_lower = lr.r_upper` and `lr.r_nearest` is non-finite. This is complementary to fixing
non-finite `CReal` printing in `cil_printer.ml` for plain C code. A merge request with this fix and
a regression test (`plugins/e-acsl/tests/arith/non_finite_real.c`) is ready.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
