# [Kernel] `Cil.interpret_character_constant` types multi-character constants as `unsigned long` / `unsigned long long` instead of `int`

<!-- Everything below this line is the issue description. -->

### Summary

Multi-character integer character constants (such as `'ab'` or `'\377\377\377\377'`) are given type
`unsigned long` (when the value is `>= 256` and `<= INT32_MAX`) or `unsigned long long` (when
`> INT32_MAX`), instead of `int` as mandated by ISO C11 6.4.4.4p10. As a result, `sizeof('ab')` is
`8` instead of `sizeof(int)` on `x86_64`, `_Generic('ab', int: 1, unsigned long: 2, ...)` selects
`unsigned long`, signed subtraction `('ab' - 30000) < 0` wraps unsigned to `0`, and
`'\377\377\377\377'` evaluates to `4294967295ULL` instead of `-1`.

### Steps to reproduce the issue

`multichar_const_type.c`:

```c
int main(void) {
  int lt = ('ab' - 30000) < 0;
  int sz = sizeof('ab');
  int cmp4 = ('\377\377\377\377' < 0);
  long long hi4 = '\377\377\377\377';
  int gen = _Generic('ab', int: 1, unsigned long: 2, default: 0);
  int c0 = '\0\200';
  //@ check t1: lt == 1;
  //@ check t2: sz == sizeof(int);
  //@ check t3: cmp4 == 1;
  //@ check t4: hi4 == -1;
  //@ check t5: gen == 1;
  //@ check t6: c0 == 128;
  return 0;
}
```

```sh
frama-c -print multichar_const_type.c
frama-c -eva multichar_const_type.c
```

### Expected behaviour

ISO C11 6.4.4.4p10 states: "An integer character constant has type `int`." Only the *value* of a
multi-character constant is implementation-defined; its type is always `int`. `gcc 14.2.0`
evaluates `lt=1`, `sz=4`, `cmp4=1`, `hi4=-1`, `gen=1`, and `c0=128`; all six checks (`t1` through
`t6`) should be valid in Eva.

### Actual behaviour

`-print` emits `unsigned long` and `unsigned long long` constants and resolves `_Generic` to
`unsigned long` (`2`):

```c
  int lt = 24930UL - (unsigned long)30000 < (unsigned long)0;
  int sz = (int)sizeof(24930UL);
  int cmp4 = 4294967295ULL < (unsigned long long)0;
  long long hi4 = 4294967295LL;
  int gen = 2;
```

Eva marks all six checks invalid:

```text
[eva:alarm] multichar_const_type.c:8: Warning: check 't1' got status invalid.
[eva:alarm] multichar_const_type.c:9: Warning: check 't2' got status invalid.
[eva:alarm] multichar_const_type.c:10: Warning: check 't3' got status invalid.
[eva:alarm] multichar_const_type.c:11: Warning: check 't4' got status invalid.
[eva:alarm] multichar_const_type.c:12: Warning: check 't5' got status invalid.
[eva:alarm] multichar_const_type.c:13: Warning: check 't6' got status invalid.
    Assertions        0 valid     0 unknown     6 invalid      6 total
```

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 189053d4a2; also 34.0~beta (Selenium), same output
- Plug-in used: Kernel (`Cil.interpret_character_constant`), observed in Eva and WP
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** In `src/kernel/services/ast_queries/cil.ml:4150-4161`:

```ocaml
let interpret_character_constant char_list =
  let value = reduce_multichar Cil_const.charType char_list in
  if value < (Int64.of_int 256) then
    (* ISO C 6.4.4.4.10: single-character constants have type int *)
    (CChr(Char.chr (Int64.to_int value))), Cil_const.intType
  else begin
    let orig_rep = None (* Some("'" ^ (String.escaped str) ^ "'") *) in
    if value <= (Int64.of_int32 Int32.max_int) then
      (CInt64(Z.of_int64 value,IULong,orig_rep)), Cil_const.ulongType
    else
      (CInt64(Z.of_int64 value,IULongLong,orig_rep)), Cil_const.ulongLongType
  end
```

The `else` branch creates `IULong` / `IULongLong` constants instead of `IInt`. Moreover, checking
only `value < 256` treats a 2-character constant like `'\0\200'` as a single-character `CChr`
(sign-extending to `-128` on signed-`char` machdeps instead of `128`).

**Fix.** Keep `CChr` for single-element lists `[ _ ]` with `0 <= value < 256`, and otherwise wrap
`value` to `IInt` via `truncateInteger64 IInt (Z.of_int64 value)` and return
`(CInt64 (v, IInt, None), Cil_const.intType)`. A merge request with this fix and a regression test
(`tests/syntax/multichar_const_type.c`) is ready.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
