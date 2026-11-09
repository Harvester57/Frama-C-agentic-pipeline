# `UsefulOutBuf_Compare()` reads outside the buffer for large offsets, despite its documentation

Draft issue for https://github.com/laurencelundblade/QCBOR/issues. Not filed yet.
Patch: [`patches/public/0004-Make-UsefulOutBuf_Compare-safe-for-any-offset-and-le.patch`](patches/public/0004-Make-UsefulOutBuf_Compare-safe-for-any-offset-and-le.patch).

## Summary

`UsefulBuf.h` says of `UsefulOutBuf_Compare()`: *"No data will ever be read beyond the buffer's
end, making the function safe regardless of the provided offsets."* The implementation adds the
offsets and lengths to the buffer pointer **before** clamping them to the data length. So:

- **Reads before the buffer.** An offset near `SIZE_MAX` wraps the pointer to just before the
  buffer, and the loop reads there. `Compare(SIZE_MAX, 2, 0, 2)` reads 1 byte before the buffer:
  ASan reports a heap-buffer-overflow.
- **Wrong result.** A length near `SIZE_MAX` wraps the end pointer. `Compare(0, SIZE_MAX, 0, 10)`
  on 10 bytes of data returns −1 instead of 0.
- **Undefined behavior even without wrapping.** Any offset more than one past the end forms an
  out-of-object pointer, which is undefined (C11 6.5.6p8).

The documentation is also wrong in two smaller ways:
- The `@return` line has the sign backwards relative to the code and to the paragraph below it.
- *"If either starting offset is beyond the end of the output buffer, the function returns zero"*
  is not what the code does, nor what the existing tests expect. A string that starts past the end
  is treated as empty, so `Compare(10, 1, 0, 1)` on 4 bytes returns 1.

| | |
| :--- | :--- |
| **Affected** | `dev` at 9bd0845 and v2.0-alpha-6, since 534112f (2025-02-26). 1.x has no `UsefulOutBuf_Compare()`. |
| **Severity** | Low. This is API hardening plus a documentation fix. |
| **Reachability** | Public `UsefulBuf` API only. QCBOR's own caller, map sorting in `qcbor_main_encode.c`, passes offsets taken from its own output and cannot produce such values. |

## Reproducer

[`repro/outbuf_compare.c`](repro/outbuf_compare.c):

```c
uint8_t *pStorage = malloc(16);
UsefulOutBuf_Init(&OB, (UsefulBuf){pStorage, 16});
UsefulOutBuf_AppendData(&OB, "abcd", 4);
UsefulOutBuf_Compare(&OB, 10, 1, 0, 1);          /* 1, documented as 0 */
UsefulOutBuf_Compare(&OB, SIZE_MAX, 2, 0, 2);    /* reads pStorage[-1] */
```

```text
$ clang -g -O1 -fsanitize=address -Iinc -Isrc outbuf_compare.c src/*.c -lm && ./a.out
Compare(10,1, 0,1)       = 1 (doc says 0)
==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
    #0 in UsefulOutBuf_Compare src/UsefulBuf.c:753:27
0x50200000000f is located 1 bytes before 16-byte region [0x502000000010,0x502000000020)

$ clang -g -O1 -fsanitize=undefined ...
src/UsefulBuf.c:744:20: runtime error: addition of unsigned offset to 0x502000000010 overflowed to 0x50200000000f
```

## Root cause

[`src/UsefulBuf.c:726-783`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/UsefulBuf.c#L726-L783):

```c
p1Start = pBase + uStart1;
p2Start = pBase + uStart2;
p1End   = p1Start + uLen1;
p2End   = p2Start + uLen2;
for(p1 = p1Start, p2 = p2Start;
    p1 < pEnd && p2 < pEnd && p1 < p1End && p2 < p2End;
    p1++, p2++) {
   uComparison = *p2 - *p1;
```

The checks `p1 < pEnd` and `p1 < p1End` compare pointers that may already have wrapped.

## Fix

Work on offsets, not pointers. Clamp each string to the data in the buffer first; a string that
starts at or past the end is empty. Then index from the start of the buffer:

```c
uComparedLen1 = 0;
if(uStart1 < uDataLen) {
   uComparedLen1 = uDataLen - uStart1;
   if(uLen1 < uComparedLen1) {
      uComparedLen1 = uLen1;
   }
}
/* same for string 2 */
for(uIndex = 0; uIndex < uComparedLen1 && uIndex < uComparedLen2; uIndex++) {
   uComparison = pBase[uStart2 + uIndex] - pBase[uStart1 + uIndex];
   ...
```

The tie-break on length is unchanged. The result is the same as before for every in-range call,
and all existing tests pass. The patch also:
- corrects the `@return` sign in `UsefulBuf.h`;
- replaces "returns zero" with "a string starting past the end is empty";
- adds three cases to `UOBExtraTests`: `Compare(SIZE_MAX,2,0,2) == 1`, `Compare(0,2,SIZE_MAX,2) == -1`
  and `Compare(0,SIZE_MAX,0,10) == 0`.

## Validation

Validated with clang 19.1.7 on Linux x86_64:
- The reproducer is clean under ASan and UBSan with the patch.
- The test suite passes (89/89) in plain, ASan + recoverable UBSan, and MSan builds.
- On the sources before this patch, the new test fails:
  `UOBExtraTests FAILED (returned Comparison with wrapping offset)`.
