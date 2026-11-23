# [WP] `\floor`, `\ceil`, `\truncate`, and C float-to-integer casts of constants prove false facts via `int_of_float (Q.to_float r)`

<!-- Everything below this line is the issue description. -->

### Summary

`Cmath.builtin_truncate` evaluates `\floor`, `\ceil`, `\truncate`, `(integer)` casts, and C float-to-integer casts (`Cint.of_real`) on constant rationals by computing `int_of_float (Q.to_float r)`. This loses precision when converting an exact rational `Q.t` through IEEE 754 `double` and wraps or yields unspecified results when converting through OCaml's 63-bit `int`. As a result, Qed proves false lemmas (including cases where `\floor(x) > x`) and false C postconditions on valid `long long` and `unsigned long long` casts.

### Steps to reproduce the issue

`trunc_repro.c`:

```c
/*@ check lemma floor_near:    \floor(0.99999999999999999999) == 1;
    check lemma ceil_near:     \ceil(0.99999999999999999999) == 2;
    check lemma trunc_near:    \truncate(-0.99999999999999999999) == -1;
    check lemma floor_gt_arg:  \floor(9007199254740993.5) == 9007199254740994;
    check lemma cast_int_near: (integer)0.99999999999999999999 == 1;
    check lemma floor_huge:    \floor(1e30) == 0; */

/*@ ensures \result == -4223372036854775808; */
long long trunc_big(void) {
  double d = 5e18;
  return (long long)d;
}

/*@ ensures \result == 13835058055282163712ULL; */
unsigned long long trunc_ull(void) {
  float f = 4611686018427387904.0f;
  return (unsigned long long)f;
}
```

```sh
frama-c -wp -wp-prover none -wp-print trunc_repro.c
```

### Expected behaviour

All eight goals are mathematically false and should simplify to `Prove: false.`:

- `\floor(1 - 10^-20) == 0`, `\ceil(1 - 10^-20) == 1`, `\truncate(-(1 - 10^-20)) == 0`, `(integer)(1 - 10^-20) == 0`.
- `\floor(9007199254740993.5) == 9007199254740993` (cannot exceed its argument).
- `\floor(1e30) == 1000000000000000000000000000000`.
- In C (ISO C11 6.3.1.4p1, verified with `gcc 14.2.0`), `5e18` is an exact `double` below `LLONG_MAX` (`(long long)5e18 == 5000000000000000000`), and `4611686018427387904.0f` (`2^62`) is an exact `float` (`(unsigned long long)f == 4611686018427387904ULL`).

### Actual behaviour

All eight false goals are proved by Qed:

```text
[kernel] Parsing trunc_repro.c (with preprocessing)
[wp] Running WP plugin...
[wp] Warning: Missing RTE guards
------------------------------------------------------------
  Global
------------------------------------------------------------

Goal Check Lemma 'cast_int_near':
Prove: true.

Goal Check Lemma 'ceil_near':
Prove: true.

Goal Check Lemma 'floor_gt_arg':
Prove: true.

Goal Check Lemma 'floor_huge':
Prove: true.

Goal Check Lemma 'floor_near':
Prove: true.

Goal Check Lemma 'trunc_near':
Prove: true.

------------------------------------------------------------
  Function trunc_big
------------------------------------------------------------

Goal Post-condition ("trunc_repro.c", line 8) in 'trunc_big':
Prove: true.

------------------------------------------------------------
  Function trunc_ull
------------------------------------------------------------

Goal Post-condition ("trunc_repro.c", line 14) in 'trunc_ull':
Prove: true.
```

(The `floor_huge` result `0` depends on hardware behavior because OCaml leaves `int_of_float` unspecified for magnitudes at or above `2^63`; in `[2^62, 2^63)` it wraps modulo `2^63` without raising.)

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at `189053d4a2`; also 34.0~beta (Selenium), with identical output
- Plug-in used: WP (Qed simplifier; reproduces under default, `real`, `nat`, and `nat+real` models)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** `plugins/wp/src/Cmath.ml`, `builtin_truncate` (lines 42-61 on `189053d4a2`):

```ocaml
      try
        (* Waiting for Z-Arith to have truncation to big-int *)
        let truncated = int_of_float (Q.to_float r) in
```

- `Q.to_float r` rounds arbitrary-precision rationals to binary64 `double`, turning `0.99999999999999999999` into `1.0` and `9007199254740993.5` into `9007199254740994.0`.
- `int_of_float` wraps silently for magnitudes in `[2^62, 2^63)` and is unspecified at or above `2^63` without raising, so the `with _` handler does not catch overflow.
- C float-to-integer casts reach `builtin_truncate` through `Cint.of_real` (`plugins/wp/src/Cint.ml:379`) -> `Cmath.int_of_real`.
- The WP manual (`plugins/wp/doc/manual/wp_builtins.tex:76-77`) states: "Constants (rationals) are truncated towards the expected direction" with no documented limitation.

**Fix.** Guard on `Q.is_real r` and compute the exact `Z.t` directly with Zarith (`Z.fdiv r.Q.num r.Q.den` for `\floor`, `Z.cdiv r.Q.num r.Q.den` for `\ceil`, `Q.to_bigint r` for `\truncate`), returning `F.e_zint`. A merge request follows.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and tests described above.
