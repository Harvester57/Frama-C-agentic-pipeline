# [WP] Converting rational or integer constants to `float` double-rounds through `double` in `Cfloat.qmake`

<!-- Everything below this line is the issue description. -->

### Summary

`Cfloat.qmake` rounds exact rational values `Q.t` to single-precision IEEE 754 `float` (`Float32`) by calling `Q.to_float q` (rounding to binary64 `double`) and then `Floating_point.round_to_single_precision` (rounding a second time to binary32 `float`). Constants lying close to a binary32 midpoint — including integer-to-`float` casts, ACSL `(float)` casts of real literals, subnormal midpoints, and values just below the `FLT_MAX` overflow threshold — suffer from double rounding, causing Qed to prove false equalities and refute true ones.

### Steps to reproduce the issue

`double_round.c`:

```c
/*@ check lemma dr_acsl:
      (float)1.0000000596046447753906250000000000000001 == 1.0;
    check lemma dr_fltmax_true:
      (float)340282356779733661637539395458142568447.0
      == 340282346638528859811704183484516925440.0; */

/* x = 2^60 + 2^36 + 1; nearest float is 2^60 + 2^37 = 1152921642045800448 */
/*@ ensures \result == 1152921504606846976.0; */
float to_float(void) {
  long long x = 1152921573326323713LL;
  return (float)x;
}
```

```sh
frama-c -wp -wp-prover none -wp-print double_round.c
```

### Expected behaviour

- `1.0000000596046447753906250000000000000001` is `1 + 2^-24 + 10^-40`, strictly above the midpoint between `1.0f` and `1.0f + 2^-23`. In ACSL, `(float)` rounds a real directly to binary32 with round-to-nearest-even, giving `1 + 2^-23`, so `dr_acsl` should be `Prove: false.`.
- `340282356779733661637539395458142568447.0` is `2^128 - 2^103 - 1`, strictly below the binary32 overflow midpoint `2^128 - 2^103`, so its nearest `float` is `FLT_MAX` (`340282346638528859811704183484516925440.0`). `dr_fltmax_true` is true and should be `Prove: true.`.
- In `to_float`, `x = 2^60 + 2^36 + 1` is strictly above the midpoint between `2^60` and `2^60 + 2^37`. Under IEC 60559 (modeled by WP's default `Float` model and implemented by `gcc 14.2.0`, which computes `1152921642045800448.0 = 0x1.000002p+60`), `(float)x` is `2^60 + 2^37`, so the postcondition `== 2^60` should be `Prove: false.`. (ISO C17 6.3.1.4p2 alone allows an implementation to choose either neighbor for an inexact integer-to-float conversion, whereas IEC 60559 and ACSL `(float)` require single round-to-nearest-even.)

### Actual behaviour

```text
[kernel] Parsing double_round.c (with preprocessing)
[wp] Running WP plugin...
[wp] Warning: Missing RTE guards
------------------------------------------------------------
  Global
------------------------------------------------------------

Goal Check Lemma 'dr_acsl':
Prove: true.

Goal Check Lemma 'dr_fltmax_true':
Prove: false.

------------------------------------------------------------
  Function to_float
------------------------------------------------------------

Goal Post-condition ("double_round.c", line 8) in 'to_float':
Prove: true.
```

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at `189053d4a2`; also 34.0~beta (Selenium), with identical output
- Plug-in used: WP (default `Float` model)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** `plugins/wp/src/Cfloat.ml`, lines 127-131 (commit `189053d4a2`):

```ocaml
let fmake ulp value = match ulp with
  | Float32 -> F.e_fun !@fq32 [F.e_float (rfloat value)]
  | Float64 -> F.e_fun !@fq64 [F.e_float value]

let qmake ulp q = fmake ulp (Q.to_float q)
```

For `Float32`, `Q.to_float q` first rounds `q` to binary64 `double` (rounding `2^60 + 2^36 + 1` down to the exact binary32 tie `2^60 + 2^36`, and rounding `2^128 - 2^103 - 1` up to `2^128 - 2^103`), and `rfloat` then rounds a second time to binary32 (rounding ties to even `2^60`, and overflowing `2^128 - 2^103` to `+infinity`).

This is distinct from `#2831` (parsing hexadecimal literals and `f32`/`f64` suffixes in `Cfloat.parse_literal`), although it touches adjacent lines in `plugins/wp/src/Cfloat.ml`.

**Fix.** Round `Q.t` directly to IEEE 754 binary32 (exact single round-to-nearest-even in Zarith, handling normals, subnormals, zero, and overflow) in `Cfloat.qmake` when `ulp = Float32`. A merge request follows.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and tests described above.
