# [WP] A `void` object is sized as `int` (`sizeof(int)`), giving wrong proofs for `\block_length(void *)` and `void *` pointer arithmetic

<!-- Everything below this line is the issue description. -->

### Summary

`Ctypes.object_of` maps `TPtr TVoid` (`void *`) to `C_pointer Cil_const.charType` (1-byte `char *`), but maps `TVoid` itself to `C_int (c_int IInt)` (`sizeof(int)` bytes: 4 on 32/64-bit targets, 2 on `x86_16`). Whenever WP constructs the pointed-to object of a `void *` pointer directly from `TVoid`, the resulting size is `sizeof(int)` instead of 1 byte:

1. **Default `Typed` model:** `\block_length(p)` on a `void *` pointing to `char buf[8]` is scaled by `sizeof(int)`, so WP proves the false property `\block_length(p) == 32` while leaving the true property `\block_length(p) == 8` unproved (`Malloc_0[G_buf_22] = 2`).
2. **`Bytes` model:** pointer shifts (`p + 4`) and pointer differences (`q - p`) on `void *` step by `sizeof(int)` instead of 1 byte, so WP proves `(char *)(p + 4) == buf + 16` and `q - p == 1` while refuting `(char *)(p + 4) == buf + 4` and `q - p == 4`.
3. **Frama-C's own libc:** the contract of `mempcpy` in `share/libc/string.h` states `ensures \result == dest + n;` on `void *dest`. Under `-wp-model Bytes`, WP proves the false assertion `(char *)r == d + 8` after `mempcpy(d, s, 2)`.

Although WP prints `[wp] Warning: void object`, the false goals are reported as proved without any soundness flag or weakening marker.

### Steps to reproduce the issue

`void_obj.c`:

```c
char buf[8];

void bl_8(void) {
  void *p = buf;
  //@ check bl_true: \block_length(p) == 8;
}

void bl_32(void) {
  void *p = buf;
  //@ check bl_false: \block_length(p) == 32;
}

void shift_4(void) {
  void *p = buf;
  //@ check sh_true: (char *)(p + 4) == buf + 4;
}

void shift_16(void) {
  void *p = buf;
  //@ check sh_false: (char *)(p + 4) == buf + 16;
}

void diff_test(void) {
  void *p = buf;
  void *q = buf + 4;
  //@ check diff_true: q - p == 4;
  //@ check diff_false: q - p == 1;
}
```

`mempcpy_repro.c`:

```c
#define _GNU_SOURCE
#include <string.h>

/*@ requires \valid(d + (0 .. 7)) && \valid_read(s + (0 .. 1));
    requires \separated(d + (0 .. 7), s + (0 .. 1)); */
void f(char *d, const char *s) {
  void *r = mempcpy(d, s, 2);
  //@ assert wrong: (char *)r == d + 8;
}
```

```sh
frama-c -wp -wp-prover alt-ergo -wp-fct bl_8,bl_32 void_obj.c
frama-c -wp -wp-model Bytes -wp-prover none -wp-print -wp-fct shift_4,shift_16,diff_test void_obj.c
frama-c -machdep x86_16 -wp -wp-prover none -wp-print -wp-fct bl_8 void_obj.c
frama-c -wp -wp-model Bytes mempcpy_repro.c
```

### Expected behaviour

- In ACSL, `\block_length` has signature `void* -> size_t` and returns the allocated size in bytes (`8` for `char buf[8]`). `bl_true` should be provable (`Malloc_0[G_buf_22] = 8` on both `x86_64` and `x86_16`) and `bl_false` (`== 32`) should remain unproved.
- Under `-wp-model Bytes` (matching GNU C `sizeof(void) == 1`, verified with `gcc -std=gnu11`), `sh_true` and `diff_true` should simplify to `Prove: true.`, while `sh_false` and `diff_false` should simplify to `Prove: false.`.
- In `mempcpy_repro.c`, `assert wrong: (char *)r == d + 8;` is false (`mempcpy(d, s, 2)` returns `d + 2`) and must not be proved.

### Actual behaviour

Default `Typed` model (`bl_8` and `bl_32` — `bl_false` is proved by Alt-Ergo while `bl_true` is `Unknown`):

```text
[kernel] Parsing void_obj.c (with preprocessing)
[wp] Running WP plugin...
[wp] Warning: Missing RTE guards
[wp] void_obj.c:5: Warning: void object
[wp] void_obj.c:10: Warning: void object
[wp] 2 goals scheduled
[wp] [Unknown] typed_bl_8_check_bl_true (Alt-Ergo) (Cached)
[wp] Proved goals:    5 / 6
  Terminating:       2
  Unreachable:       2
  Qed:               0
  Alt-Ergo 2.6.4:    1 (7ms)
  Unknown:           1
```

`Bytes` model (`shift_4`, `shift_16`, `diff_test`):

```text
[wp] void_obj.c:15: Warning: void object
[wp] void_obj.c:20: Warning: void object
[wp] void_obj.c:27: Warning: void object
[wp] void_obj.c:26: Warning: void object

Goal Check 'sh_true' ("void_obj.c", line 15):
Prove: false.

Goal Check 'sh_false' ("void_obj.c", line 20):
Prove: true.

Goal Check 'diff_true' ("void_obj.c", line 26):
Prove: false.

Goal Check 'diff_false' ("void_obj.c", line 27):
Prove: true.
```

Under `-machdep x86_16` (`bl_8`, showing the scaling factor is `sizeof(int)` = 2):

```text
[wp] void_obj.c:5: Warning: void object

Goal Check 'bl_true' ("void_obj.c", line 5):
Assume { (* Heap *) Type: linked(Malloc_0). }
Prove: Malloc_0[G_buf_22] = 4.
```

`mempcpy_repro.c` under `-wp-model Bytes`:

```text
[wp] FRAMAC_SHARE/libc/string.h:148: Warning: void object
[wp] 6 goals scheduled
[wp] Proved goals:    6 / 6
  Qed:               3 (0.68ms-0.35ms-0.71ms)
  Alt-Ergo 2.6.4:    3 (15ms-23ms)
```

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at `189053d4a2`; also 34.0~beta (Selenium), with identical output
- Plug-in used: WP (default `Typed` and `Bytes` memory models)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** In `plugins/wp/src/ctypes.ml` (commit `189053d4a2`), `object_of` maps `TPtr TVoid` to `C_pointer Cil_const.charType` (lines 285-289), so `MemTyped` already treats `void *` as `sint8*` (and already hides incompatible `int * -> void *` casts). However, lines 316-318 map `TVoid` directly to `C_int (c_int IInt)`:

```ocaml
  | TVoid ->
    WpLog.warning ~current:true "void object" ;
    C_int (c_int IInt)
```

Both `MemTyped.block_length` (`plugins/wp/src/MemTyped.ml:631-637`), `MemBytes.Shift.generate` (`plugins/wp/src/MemBytes.ml:303`), and `MemBytes.loc_diff` (`plugins/wp/src/MemBytes.ml:142-144`) use `Ctypes.sizeof_object obj`, multiplying/dividing by `sizeof(int)` instead of `1`.

**Fix.** Return `C_int (c_char ())` in the `TVoid` branch of `Ctypes.object_of` (`plugins/wp/src/ctypes.ml:318`), matching line 287 and GNU C `sizeof(void) == 1`. A merge request follows.

**Workaround.** Cast `void *` pointers explicitly to `char *` before applying `\block_length`, pointer shifts, or pointer differences in annotations (this does not fix Frama-C libc contracts such as `mempcpy`).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and tests described above.
