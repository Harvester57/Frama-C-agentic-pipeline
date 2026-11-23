# [WP] Overflowed and non-finite float constants become infinite `Kreal` constants in Qed (wrong proofs) and crash Why3 export (`Wp.Cfloat.const_float`)

<!-- Everything below this line is the issue description. -->

### Summary

In `plugins/wp/src/Cfloat.ml`, `fmake`, `code_lit`, and `parse_literal` pass non-finite OCaml `float` values (`+infinity`, `-infinity`, `nan`) directly into `F.e_float` and `Q.of_float`, creating non-finite `Kreal` constants (`Q.inf`, `Q.minus_inf`, `Q.undef`) inside Qed's real arithmetic. This causes two defects:

1. **Wrong real proofs by Qed:** because `Q.add Q.inf Q.one = Q.inf` and `Q.sub Q.inf Q.inf = Q.undef`, Qed proves impossible real equalities such as `y + 1.0 == z` (after `y = 1e308 * 10.0; z = 1e308 * 20.0;`), `(float)1e39 + 1.0 == (float)1e39`, and `1e40f + 1.0 == 1e40f`, while refuting the true real identity `(float)1e39 - (float)1e39 == 0.0`.
2. **Why3 export crash:** any goal still containing a non-finite `to_fq32`/`to_fq64` term — including the RTE overflow guard `is_nan_or_infinite` itself, as well as C literals like `float f = 1e40f;` or `-constfold` `1.0 / 0.0` — fails Why3 export with `[Why3 Error] anomaly: Invalid_argument("Wp.Cfloat.const_float")`, so the overflow is reported as a prover failure rather than an unproved goal.

### Steps to reproduce the issue

`non_finite.c`:

```c
/*@ check lemma ovf_f32_plus1: (float)1e39 + 1.0 == (float)1e39;
    check lemma ovf_f32_sub:   (float)1e39 - (float)1e39 == 0.0;
    check lemma acsl_1e40f:    1e40f + 1.0 == 1e40f; */

double ovf2(void) {
  double x = 1e308;
  double y = x * 10.0;
  double z = x * 20.0;
  //@ check f_c_plus1: y + 1.0 == z;
  //@ check f_c_twice: y + y == z + 5.0;
  return y;
}

float ovf_lit(void) {
  float f = 1e40f;
  //@ check f_lit: f + 1.0 == f;
  return f;
}
```

```sh
frama-c -wp -wp-prover none -wp-print non_finite.c
frama-c -wp -wp-rte -wp-prover alt-ergo -wp-fct ovf2,ovf_lit non_finite.c
OCAMLRUNPARAM=b frama-c -wp -wp-rte -wp-prover alt-ergo -wp-msg-key prover -wp-fct ovf2 non_finite.c
```

### Expected behaviour

- In ACSL, `==` on floating-point terms compares mathematical real numbers: `r + 1.0 == r` is unsatisfiable (`Prove: false.`) and `r - r == 0.0` is valid (`Prove: true.`). None of `ovf_f32_plus1`, `acsl_1e40f`, `f_c_plus1`, `f_c_twice`, or `f_lit` should be proved.
- With `-wp-rte -wp-prover alt-ergo`, goals involving overflowed floats (including the RTE `is_nan_or_infinite` assertions) should export cleanly to Why3 without raising `Invalid_argument("Wp.Cfloat.const_float")`, leaving unprovable overflow guards `Timeout`/`Unknown` rather than `[Failure]`.

### Actual behaviour

With `-wp -wp-prover none -wp-print`:

```text
Goal Check Lemma 'acsl_1e40f':
Prove: true.

Goal Check Lemma 'ovf_f32_plus1':
Prove: true.

Goal Check Lemma 'ovf_f32_sub':
Prove: false.

Goal Check 'f_c_plus1' ("non_finite.c", line 9):
Prove: true.

Goal Check 'f_c_twice' ("non_finite.c", line 10):
Prove: true.
```

With `-wp -wp-rte -wp-prover alt-ergo -wp-fct ovf2,ovf_lit`:

```text
[wp] Warning: Goal Property:
    running prover Alt-Ergo:2.6.4 failed ([Why3 Error] anomaly: Invalid_argument("Wp.Cfloat.const_float"))
[wp] [Failure] typed_ovf2_assert_rte_is_nan_or_infinite (Alt-Ergo) (No Cache)
[wp] [Failure] typed_ovf_lit_check_f_lit (Alt-Ergo) (No Cache)
[wp] [Failure] typed_ovf_lit_assert_rte_is_nan_or_infinite (Alt-Ergo) (No Cache)
```

(The same `const_float` anomaly also occurs on `double y = 1.0 / 0.0;` when `-constfold` is passed.)

<details>
<summary>Full backtrace (via OCAMLRUNPARAM=b -wp-msg-key prover)</summary>

```text
[wp] Failure: [Why3 Error] anomaly: Invalid_argument("Wp.Cfloat.const_float")
               Raised at Stdlib.invalid_arg in file "stdlib.ml", line 30, characters 20-45
  Called from Wp__ExportWhy3.cc_any in file "plugins/wp/src/ExportWhy3.ml", line 305, characters 8-20
  Called from Wp__ExportWhy3.cc_term in file "plugins/wp/src/ExportWhy3.ml", line 340, characters 34-42
  Called from Stdlib__List.map in file "list.ml", line 85, characters 15-19
  Called from Wp__ExportWhy3.cc_any in file "plugins/wp/src/ExportWhy3.ml", line 307, characters 17-42
  Called from Wp__ExportWhy3.cc_prop in file "plugins/wp/src/ExportWhy3.ml" (inlined), line 339, characters 34-42
  Called from Wp__ExportWhy3.compile in file "plugins/wp/src/ExportWhy3.ml", line 411, characters 14-30
  Called from Wp__ExportWhy3.cc_goal in file "plugins/wp/src/ExportWhy3.ml", line 732, characters 13-34
  Called from Wp__ProverWhy3.task_of_wpo in file "plugins/wp/src/ProverWhy3.ml", line 17, characters 2-55
  Called from Wp__WpContext.on_context in file "plugins/wp/src/wpContext.ml", line 125, characters 17-20
  Re-raised at Wp__WpContext.on_context in file "plugins/wp/src/wpContext.ml", line 132, characters 4-13
  Called from Wp__ProverWhy3.build_proof_task in file "plugins/wp/src/ProverWhy3.ml", line 391, characters 22-72
[wp] Warning: Goal Property: running prover Alt-Ergo:2.6.4 failed (Fclib.Log.AbortFatal(_))
[wp] [Failure] typed_ovf2_assert_rte_is_nan_or_infinite (Alt-Ergo) (No Cache)
```

</details>

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at `189053d4a2`; also 34.0~beta (Selenium), with identical output
- Plug-in used: WP (and RTE via `-wp-rte`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** In `plugins/wp/src/Cfloat.ml` (commit `189053d4a2`):

- `fmake` (lines 127-130) passes the rounded OCaml float directly to `F.e_float` without checking `Float.is_finite` (unlike `compute_float DIV` at lines 328-332, which checks `Q.classify x = Q.NZERO` and raises `Not_found` so Why3 handles division by zero symbolically).
- `parse_literal` (line 140) calls `Q.of_float v` on suffixed ACSL literals like `1e40f` even when `v` is non-finite.
- `code_lit` (lines 181-186) passes non-finite C constant values (such as `1e40f` or `-constfold` `1.0 / 0.0`) directly to `F.e_float`.
- `const_float` (lines 242-264) formats `q` via `Floating_point.pretty_normal ~use_hex`, producing `"inf"`/`"nan"`, which fails `re_float` and raises `invalid_arg "Wp.Cfloat.const_float"`.

**Fix.** Raise `Not_found` in `fmake` when the rounded float is not finite (letting Why3 handle overflow symbolically via `to_f32`/`to_f64`/`mul_f64`/etc., which `cfloat.mlw` already axiomatizes), check `Q.is_real q` in `acsl_lit` before calling `F.e_real`, and emit `Warning.error "Non-finite floating-point constant"` in `code_lit` when `value` is not finite. Note that `Cfloat.ml` is also touched by `#2831` (`!59`), and placing the `Q.is_real` check in `acsl_lit` avoids any merge conflict with `!59`. A merge request follows.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and tests described above.
