# [E-ACSL] Rational casts to `double` and `float` truncate toward zero via `__gmpq_get_d` (true assertions abort, false assertions pass)

<!-- Everything below this line is the issue description. -->

### Summary

When translating an ACSL cast from a mathematical real/rational (`\real`, represented at run time as
a GMP `mpq_t`) to `double` or `float`, E-ACSL generates a call to `__gmpq_get_d` (and casts the
`double` result to `float` for `(float)`). GMP's `mpq_get_d` rounds **toward zero** (truncation),
whereas ACSL Section 2.2.5 specifies IEEE 754 **round-to-nearest-even** (and casting through `double`
additionally introduces double rounding for `float`). As a consequence, roughly half of all
non-representable rational constants (every value whose nearest floating-point number is further from
zero than the exact rational) produce the wrong value: valid assertions abort at run time and false
assertions pass silently without warning.

### Steps to reproduce the issue

`rational_cast.c`:

```c
int main(void) {
  double d = 0.1;
  double d_below = 0x1.9999999999999p-4;
  /*@ assert true_eq: d == (double)0.1; */
  /*@ assert false_eq: d_below == (double)0.1; */
  /*@ assert false_lt: (double)0.1 < 0.1; */
  float f = 16777218.0f;
  /*@ assert true_f_dr: f == (float)16777217.0000000001; */
  return 0;
}
```

```sh
e-acsl-gcc --keep-going -c -o rational_cast.gen.c -O rational_cast rational_cast.c
./rational_cast.e-acsl
```

### Expected behaviour

In IEEE 754 round-to-nearest-even (ACSL Section 2.2.5):

- `(double)0.1` is `0x1.999999999999ap-4` (strictly greater than `1/10`), so `true_eq` holds while
  both `false_eq` and `false_lt` fail;
- `(float)16777217.0000000001` is strictly above the midpoint `16777217.0` between `16777216.0f` and
  `16777218.0f`, so single rounding to `float` yields `16777218.0f` and `true_f_dr` holds.

Running `./rational_cast.e-acsl` with `--keep-going` should report failures for `false_eq` and
`false_lt`, and zero failures for `true_eq` and `true_f_dr`.

### Actual behaviour

During instrumentation, E-ACSL emits no warning for `(double)` (only a double-rounding warning for
`R to float`):

```text
[e-acsl] Warning: R to float: double rounding might cause unsoundness
[e-acsl] translation done in project "e-acsl".
```

Running `./rational_cast.e-acsl` reports the two **true** assertions as failed, and lets both
**false** assertions (`false_eq` and `false_lt`) pass silently:

```text
rational_cast.c: In function 'main'
rational_cast.c:4: Error: Assertion failed:
	The failing predicate is:
	true_eq:
		d ≡ (double)0.1.
	With values at failure point:
	- d: 1.000000e-01
rational_cast.c: In function 'main'
rational_cast.c:8: Error: Assertion failed:
	The failing predicate is:
	true_f_dr:
		f ≡ (float)16777217.0000000001.
	With values at failure point:
	- f: 1.677722e+07
```

Without `--keep-going`, `true_eq` aborts immediately (exit status 134), and a program containing only
`false_eq` and `false_lt` exits 0 with no diagnostic.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at `189053d4a2`; also 34.0~beta (Selenium), identical behaviour
- Plug-in used: E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** In `plugins/e-acsl/src/code_generator/gmp.ml` (`Gmp.Q.add_cast`, lines 339-376 on
`189053d4a2`):

- `TFloat FDouble` emits a call to `__gmpq_get_d`. As documented in the GMP manual, `mpq_get_d`
  truncates toward zero regardless of the active FPU rounding mode, and its behaviour on exponent
  overflow/underflow is system-dependent.
- `TFloat FFloat` calls `get_double` (suffering from the same truncation) and then casts the
  resulting `double` to `float` (introducing double rounding as well), emitting only a warning.

Note that the existing `TODO` comment at `gmp.ml:340-342` already anticipates implementing dedicated
C runtime builtins for these conversions.

**Fix.** Add exact IEEE 754 round-to-nearest-even conversion builtins `__e_acsl_mpq_get_d` and
`__e_acsl_mpq_get_f` in the E-ACSL numerical runtime (`e_acsl_gmp_api.h` and
`e_acsl_floating_point.c`) using exact `mpz_t` arithmetic (handling ties-to-even, subnormals, signs,
zero, underflow, and overflow to `+-INFINITY` without double rounding), call them from
`Gmp.Q.add_cast`, and remove the obsolete `R to float: double rounding` warning. A merge request
with this fix and a regression test (`plugins/e-acsl/tests/arith/rational_cast.c`) is ready.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
