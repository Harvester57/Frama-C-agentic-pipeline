# [E-ACSL] With initialization checks, a postcondition reading a field of a struct `\result` fails on every call (false `\initialized(&\result.a)`)

<!-- Everything below this line is the issue description. -->

### Summary

With initialization checks on, a postcondition that reads a field of a struct `\result` fails on every call with a false `\initialized(&\result.a)`: the wrapper E-ACSL generates stores the result without marking it initialized. The program is correct; the failure comes from the instrumentation.

### Steps to reproduce the issue

`r.c`:

```c
struct S { int a; };

/*@ requires x >= 0;
    ensures \result.a == x; */
struct S make_s(int x) {
  struct S s = { x };
  return s;
}

int main(void) {
  struct S s = make_s(0);
  return s.a;
}
```

```sh
e-acsl-gcc -F "-rte -rte-initialized @all" -o r.inst.c -O r r.c && ./r.e-acsl
```

(`-F "-e-acsl-rte-initialized"` gives the same result.)

### Expected behaviour

The function returns a fully initialized struct, so the program runs and exits 0, as it does
without initialization checks (`e-acsl-gcc -o r.inst.c -O r r.c`).

### Actual behaviour

```text
r.c: In function 'make_s'
r.c:4: Error: E-ACSL RTE failed:
	The failing predicate is:
	uninitialized:
		\initialized(&\result.a).
	With values at failure point:
	- uninitialized: \initialized(&\result.a): 0
```

(exit status 134, `abort`.)

The check is blocking and fails on every call, whatever the function returns, so nothing after it
is checked. Under a fuzzer, every input that reaches such a function is reported as a crash.

This issue and the one about formal parameters ("formal parameters are never marked initialized",
#2797, a regression of #177) are the same family: a variable that E-ACSL registers in shadow memory but
never marks initialized. They are independent; the two fixes apply and work together.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`, gcc 14.2.0), RTE
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** The generated wrapper `__gen_e_acsl_make_s` stores the result in `__retres`, which is
registered with `__e_acsl_store_block` but never marked initialized after
`__retres = make_s(x);`. The postcondition then gets an initialization guard on `\result.a`, which
reads that shadow memory.

`needs_guard` (`plugins/e-acsl/src/analyses/rte_analysis.ml:493-502`) already skips the guard for
`\result` ("Frama-C kernel ensures that '__retres' is always initialized"), but only with
`TNoOffset` (line 500). `\result.a` is a `TResult` with a field offset, so it falls into the last
case, and the field is an `int`, so a guard is added. A scalar result (`ensures \result >= 0;`)
does not fail.

**Fix.** Extend the existing `__retres` exemption to its fields: `| TResult _, _ -> false`. This
matches what E-ACSL does for any other struct copy: the caller's `struct S s = make_s(0);` is
followed by `__e_acsl_full_init(&s)`, so its fields are not checked either. `\result` cannot be
used in a user-written `\initialized(&\result.a)` (the kernel rejects it: `not an addressable left
value: \result.a`), so the guard is the only reader of `__retres`'s shadow memory. With the fix,
the program runs and exits 0; a genuinely uninitialized local (`int y; /*@ assert y == 0; */`) is still reported.

Cost: a field of the returned struct that the function left uninitialized is no longer reported
when the postcondition reads it (it is compared as is). Today that check fails on correct
functions too, so it cannot tell the two cases apart. An alternative that keeps the guard is to
emit `__e_acsl_full_init(&__retres)` after `__retres = f(...)` in the wrapper; it has the same cost.

A merge request with a fix follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
