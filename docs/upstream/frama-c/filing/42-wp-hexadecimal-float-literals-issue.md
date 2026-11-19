# [WP] Hexadecimal floating-point literals are not read: a hypothesis using `DBL_MAX` is dropped, and with `-wp-model +real` a suffixed one is read as 0 (wrong proof)

<!-- Everything below this line is the issue description. -->

### Summary

WP reads only decimal floating-point literals. A hexadecimal one, in a specification or (with `-wp-model +real`) in the code, gives one of three results:

1. **Without suffix** (`0x1.8p1`, and so `DBL_MAX`, `FLT_MAX`, `DBL_MIN`, `DBL_EPSILON`... from Frama-C's own `<float.h>`): `Unexpected constant literal`. In a contract this is a warning and the term becomes an unknown value, so a hypothesis that uses it is lost. In a lemma it is a `User Error` and WP stops.
2. **With a suffix, under `-wp-model +real`** (`0x1.8p1f`): the literal is read as 0, with no message. `0x1.8p1f == 0.0` is proved by Qed. This one is a wrong proof.
3. **The `f32` and `f64` suffixes**, which the kernel accepts since 33.0, are rejected the same way on decimal literals too (`1.5f32`).

Callers of `exp` and `expf` get the warnings of case 1 without writing any such literal, because the contracts of these functions in `share/libc/math.h` use hexadecimal bounds.

Case 1 was first reported by Linglong Meng on the `frama-c-discuss` list, with Frama-C 33.0: https://groupes.renater.fr/sympa/arc/frama-c-discuss/2026-10/msg00002.html. Their contract was `requires x+1 <= DBL_MAX; ensures \result == x + 1;` on `double f(double x) { return x + 1.0; }`, and `frama-c -wp` answered with the warning below and a `Timeout` tagged `(Stronger)` on the postcondition. Cases 2 and 3 came out of reading the function behind that warning.

### Steps to reproduce the issue

`max.c`:

```c
#include <float.h>

/*@ requires x <= DBL_MAX;
    ensures x <= DBL_MAX;
*/
void contract(double x) { (void)x; }
```

`lemma.c`:

```c
/*@ lemma hexa: 0x1.8p1 == 3.0; */
```

`suffix.c`:

```c
/*@ lemma f32: 1.5f32 == 1.5; */
```

`real.c`:

```c
/*@ lemma three_is_zero: 0x1.8p1f == 0.0; */

/*@ ensures \result == 0.0; */
float three(void) { return 0x1.8p1f; }
```

```
$ frama-c -wp -wp-prover none -wp-print max.c
$ frama-c -wp -wp-prover none -wp-print lemma.c
$ frama-c -wp -wp-prover none -wp-print suffix.c
$ frama-c -wp -wp-prover none -wp-print -wp-model +real real.c
```

### Expected behaviour

A hexadecimal literal denotes an exact real number, and WP should use it: `0x1.8p1` is 3, and `DBL_MAX` is 2^1024 - 2^971. The postcondition of `max.c` repeats its precondition, so it should be `Prove: true.`; `hexa` and `f32` should be `Prove: true.`; and both goals of `real.c` should be `Prove: false.`, since 3 is not 0.

### Actual behaviour

`max.c`: each use of the literal becomes a different unknown value (`w`, `w_1`, `w_2`), so the precondition says nothing and the goal cannot be proved.

```
[wp] max.c:4: Warning: Unexpected constant literal "0x1.fffffffffffffp+1023"
[wp] max.c:3: Warning: Unexpected constant literal "0x1.fffffffffffffp+1023"
[...]
Goal Post-condition ("max.c", line 4) in 'contract':
[...]
Let r = of_f64(x).
Assume {
  Warning[wp]: Unexpected constant literal "0x1.fffffffffffffp+1023"
  (Hide sub-term definition).
  (* Pre-condition *)
  Have: r <= w_1.
  Warning[wp]: Unexpected constant literal "0x1.fffffffffffffp+1023"
  (Hide sub-term definition).
  (* Pre-condition *)
  Have: r <= w_2.
}
Prove: r <= w.
```

`lemma.c` and `suffix.c`: WP stops.

```
[wp] lemma.c:1: User Error: Unexpected constant literal "0x1.8p1"
[kernel] Plug-in wp aborted: invalid user input.
```

```
[wp] suffix.c:1: User Error: Unexpected constant literal "1.5f32"
[kernel] Plug-in wp aborted: invalid user input.
```

`real.c`: both false goals are proved, with no warning about the literal.

```
Goal Lemma 'three_is_zero':
Prove: true.
[...]
Goal Post-condition ("real.c", line 3) in 'three':
Prove: true.
```

Without `-wp-prover none`, the run ends with `Proved goals:    4 / 4` (`Qed: 2`).

A function that calls `exp` gets the first symptom from the libc contract (`-wp` on `double e(double x) { return exp(x); }` with a precondition bounding `x`):

```
[wp] FRAMAC_SHARE/libc/math.h:789: Warning: 
  Unexpected constant literal "0x1.62e42fefa39efp+9"
[wp] FRAMAC_SHARE/libc/math.h:783: Warning: 
  Unexpected constant literal "0x1.62e42fefa39efp+9"
[wp] FRAMAC_SHARE/libc/math.h:783: Warning: 
  Unexpected constant literal "0x1.74910d52d3051p9"
[wp] FRAMAC_SHARE/libc/math.h:798: Warning: 
  Unexpected constant literal "0x1.74910d52d3051p9"
```

A caller of `expf` gets the same four warnings, for `0x1.62e42ep+6` and `0x1.9fe368p6`.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at b80fcac74f; also 34.0~beta (Selenium), where the four commands and the `exp` caller give the same output. 33.0 is the version of the mailing-list report; I did not run it myself, but `parse_literal` and the definition of `DBL_MAX` are identical at the tag (`src/plugins/wp/Cfloat.ml` there)
- Plug-in used: WP (no prover is needed, Qed decides)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

Cause, on `b80fcac74f`, `plugins/wp/src/Cfloat.ml`, `parse_literal` (lines 138-175):

- It matches `[-+]?[0-9]*`, then an optional `.digits`, then an optional `e` exponent, and accepts the literal if what is left matches `.*[fldFLD]$`.
- On `0x1.8p1` the digits stop after `0`, the rest (`x1.8p1`) does not end with a suffix letter, and the literal is rejected.
- On `0x1.8p1f` the rest (`x1.8p1f`) does end with `f`, so the literal is accepted with the digits read so far: `0`. The default model does not show it, because there a literal that ends with a suffix letter is taken from the value computed by the kernel, before any parsing.
- `1.5f32` ends with `2`, so it is rejected in both models.

Fix: remove the suffix with the kernel's `Floating_point.extract_suffix`, require the rest to be read entirely, and convert a hexadecimal literal to its exact rational value. A merge request follows.

Not covered: `NAN` and `INFINITY` in a specification (`Builtin \NaN not defined`) are a different limitation.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the reproducer and tests described above.
