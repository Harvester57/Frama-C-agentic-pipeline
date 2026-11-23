# [Kernel] `Cil.fitsInInt` and `Cil.truncateInteger64` treat `_Bool` (`IBool`) as an 8-bit unsigned integer, dropping `(_Bool)` casts on literals `2..255` in ACSL logic

<!-- Everything below this line is the issue description. -->

### Summary

In ACSL annotations, an explicit `(_Bool)` cast on an integer or enumeration literal in the range
`2..255` is silently dropped during typing. As a result, WP proves false equalities such as
`(_Bool)2 == 2` and `(_Bool)255 == 255`, while Eva marks true checks such as `(_Bool)2 == 1` and
`(_Bool)TWO == 1` invalid. Worse, with `int x = 2;`, Eva and WP validate both `(_Bool)x == 1` and
`(_Bool)x == (_Bool)2` alongside `(_Bool)2 == 2`, unsoundly entailing `1 == 2`.

### Steps to reproduce the issue

`bool_cast_literal.c`:

```c
/*@ check lemma bool_zero: (_Bool)0 == 0;
    check lemma bool_one: (_Bool)1 == 1;
    check lemma bool_two: (_Bool)2 == 1;
    check lemma bool_two_bad: (_Bool)2 == 2; */

enum { TWO = 2 };

int main(void) {
  int x = 2;
  //@ check c1: (_Bool)2 == 1;
  //@ check c2: (_Bool)2 == 2;
  //@ check c3: (_Bool)x == 1;
  //@ check c4: (_Bool)x == (_Bool)2;
  //@ check c5: (_Bool)TWO == 1;
  //@ check c6: (_Bool)TWO == 2;
  //@ check c7: (_Bool)256 == 1;
  return 0;
}
```

```sh
frama-c -print bool_cast_literal.c
frama-c -eva bool_cast_literal.c
frama-c -wp -wp-prover none -wp-print bool_cast_literal.c
```

### Expected behaviour

By ISO C11 6.3.1.2p1, converting any non-zero scalar to `_Bool` yields `1` (and `0` yields `0`).
Therefore:

- `-print` keeps `(_Bool)2` and `(_Bool)TWO` (while still simplifying exact `(_Bool)0` and
  `(_Bool)1`);
- `-eva` validates `c1`, `c3`, `c4`, `c5`, and `c7`, and marks only the false checks `c2` and `c6`
  invalid;
- `-wp -wp-prover none -wp-print` proves `bool_two` and refutes `bool_two_bad` (`Prove: false.`).

### Actual behaviour

`-print` drops `(_Bool)` on `2` and `TWO` (while keeping `(_Bool)256`):

```c
/*@ check lemma bool_two: 2 ≡ 1;
 */
/*@ check lemma bool_two_bad: 2 ≡ 2;
 */
  /*@ check c1: 2 ≡ 1; */ ;
  /*@ check c2: 2 ≡ 2; */ ;
  /*@ check c5: TWO ≡ 1; */ ;
  /*@ check c6: TWO ≡ 2; */ ;
  /*@ check c7: (_Bool)256 ≡ 1; */ ;
```

`-eva` marks true checks `c1` and `c5` invalid and false checks `c2` and `c6` valid:

```text
[eva:alarm] bool_cast_literal.c:10: Warning: check 'c1' got status invalid.
[eva:alarm] bool_cast_literal.c:14: Warning: check 'c5' got status invalid.
    Assertions        5 valid     0 unknown     2 invalid      7 total
```

`-wp -wp-prover none -wp-print` proves `bool_two_bad` (`Prove: true.`) and refutes `bool_two`
(`Prove: false.`).

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 189053d4a2; also 34.0~beta (Selenium), same output
- Plug-in used: Kernel (`Cil.fitsInInt`, `Cil.truncateInteger64`, `Logic_utils.numeric_coerce`), observed in Eva and WP
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** `Logic_utils.numeric_coerce` (`src/kernel/services/ast_queries/logic_utils.ml:330-337`)
drops a cast `(TInt ik)` on an integer or enum literal whenever `Cil.fitsInInt ik v` holds. In
`src/kernel/services/ast_queries/cil.ml:2419-2438`, `Cil.fitsInInt` computes
`nrBits = 8 * bytesSizeOfInt k = 8` for `IBool` (with `isSigned IBool = false`), checking
`0 <= i < 256` instead of `i = 0 || i = 1`.

In the same module (`cil.ml:2443-2470`), `Cil.truncateInteger64` delegates to `fitsInInt` and
otherwise reduces modulo `2^8`, returning `2` for `IBool` on `2` and `0` on `256` instead of `1`
(affecting `Logic_utils.constFoldCastToInt` at `logic_utils.ml:2351` as well).

**Fix.** Handle `IBool` explicitly in `Cil.fitsInInt` (`Z.(equal zero i || equal one i)`) and in
`Cil.truncateInteger64` (returning `Z.one, true` for any non-zero value outside `{0, 1}`). A merge
request with this fix and a regression test (`tests/spec/bool_cast_literal.c`) is ready.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
