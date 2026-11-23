# WP sizes a `void` object as `int` (`sizeof(int)`)

- **Parent index:** [`./README.md`](./README.md)
- **Package:** `64` (`L1` from [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md))
- **Issue text:** [`./filing/64-wp-void-object-size-issue.md`](./filing/64-wp-void-object-size-issue.md)
- **Merge request text:** [`./filing/64-wp-void-object-size-mr.md`](./filing/64-wp-void-object-size-mr.md)
- **Reproducer:** [`./repro/64-wp-void-object-size.sh`](./repro/64-wp-void-object-size.sh) + [`./repro/64-wp-void-object-size.c`](./repro/64-wp-void-object-size.c)
- **Patch:** [`./patches/64-wp-void-object-size.patch`](./patches/64-wp-void-object-size.patch)
- **Local `opam/` patch queue recommendation:** **YES (soundness)** — affects both the default `Typed` model (`\block_length` on `void *` buffers) and the `Bytes` model (`void *` pointer shifts/differences and libc `mempcpy`).

## Summary

`Ctypes.object_of` (`plugins/wp/src/ctypes.ml:285-289`) already maps `TPtr TVoid` (`void *`) to `C_pointer Cil_const.charType` (1-byte `char *`), so `MemTyped` already treats `void *` as `sint8*` and hides incompatible `int * -> void *` casts. However, lines 316-318 map `TVoid` directly to `C_int (c_int IInt)` (`sizeof(int)` bytes: 4 on 32/64-bit targets, 2 on `x86_16`).

Whenever WP constructs the pointed-to object from `TVoid`:

1. **Default `Typed` model (`MemTyped.block_length`, `MemTyped.ml:631-637`):** `\block_length(p)` on `void *p = buf` (`char buf[8]`) emits `Malloc_0[G_buf_22] = 8` for the false goal `\block_length(p) == 32` (proved by Alt-Ergo) and `Malloc_0[G_buf_22] = 2` for the true goal `\block_length(p) == 8` (`Unknown`). Under `-machdep x86_16`, `\block_length(p) == 8` emits `Malloc_0[G_buf_22] = 4`.
2. **`Bytes` model (`MemBytes.Shift.generate`, `MemBytes.ml:303`; `MemBytes.loc_diff`, `MemBytes.ml:142-144`):** `(char *)(p + 4) == buf + 16` and `q - p == 1` (for `q = buf + 4`) get `Prove: true.`, while `(char *)(p + 4) == buf + 4` and `q - p == 4` get `Prove: false.`.
3. **Frama-C libc (`share/libc/string.h:148`, `mempcpy`):** `ensures \result == dest + n;` on `void *dest` lets WP under `-wp-model Bytes` prove the false assertion `(char *)r == d + 8` after `mempcpy(d, s, 2)` (`Proved goals: 6 / 6`).

## Standards and ground truth

- ACSL Reference Manual: `\block_length` has signature `void* -> size_t` and returns the allocated block size in bytes.
- GNU C (`gcc 14.2.0 -std=gnu11` on Debian 13): `sizeof(void) == 1`, `(char *)(p + 4) == buf + 4`, `q - p == 4`.
- Frama-C's kernel and libc (`mempcpy`, `rawmemchr`, `pthread_exit`) rely on byte-sized `void *` shifts and `\block_length(void *)`.

## Duplicate search

Live read-only `glab api` search across `pub/frama-c` (project `780`, issues and MRs, all states) for `void object`, `block_length void`, `TVoid`, `mempcpy`, `shift void`, plus [`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv) and packages `01`-`50`: **0 duplicates** (only overview `#2832`).

## Fix and validation

- **Source change (`plugins/wp/src/ctypes.ml:318`):** change `C_int (c_int IInt)` to `C_int (c_char ())`, consistent with `TPtr TVoid` at line 287.
- **Regression test:** `plugins/wp/tests/wp_acsl/void_object.i` (3 runs: `Typed`, `Bytes`, `x86_16` `Typed`; 3 oracles). Fails on unpatched `master` `189053d4a2`, passes patched.
- **Full WP suite:** `./dev/test.sh -p plugins/wp` passes with zero existing oracle changes.
- **Lint/headers:** `./dev/check-files.sh -p HEAD~1` passes; zero mode changes.
- **Reproducer:** exits `1` on stock `master` `189053d4a2` and stock `34.0~beta`, exits `0` (`RESULT: fixed`) after applying the patch.
