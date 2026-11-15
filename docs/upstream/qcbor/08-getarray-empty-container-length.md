# `QCBORDecode_GetArray()` / `GetMap()` return an uninitialized length for an empty array or map

Private report for the QCBOR maintainer. Attached with it:
- `0002-Fix-GetArray-GetMap-length-for-empty-definite-length.patch`, the fix with tests, for
  `dev` at `19c3367`;
- `getarray_empty.c`, the reproducer.

Line numbers below are for `dev` at `19c3367`.

## Summary

`QCBORDecode_GetArray()` and `QCBORDecode_GetMap()` return the encoded CBOR of the array or map in
`pEncodedCBOR`. For an **empty definite-length** array or map, `pEncodedCBOR->len` is computed from
an uninitialized stack variable:

| Input | Calls | `pEncodedCBOR->len` (expected 1) |
| :--- | :--- | :--- |
| `80` | `GetArray` | 4702111234474983745 (stack garbage, here `0x4141…` from earlier use) |
| `a0` | `GetMap` | same |
| `82 80 01` | `EnterArray`, `GetArray` | indeterminate (0 in this run) |
| `9f 80 ff` | `EnterArray`, `GetArray` | indeterminate (0 in this run) |

No error is set, and `pEncodedCBOR->ptr` is a valid pointer into the input. A caller that hashes,
copies, verifies or forwards `pEncodedCBOR` reads as many bytes as the garbage length says, far
past the end of the input. That is what these functions are for: for example, hashing a
sub-structure for a signature. The result is a crash, or a disclosure of memory that follows the
input buffer. A small garbage length gives a disclosure; a huge one gives a crash.

| | |
| :--- | :--- |
| **Affected** | `dev` only: introduced by 33cf49e (#431, 2026-11-02, "Fixes for GetArray()/GetMap() …"), still present at `19c3367`. **Not** in v2.0-alpha-6 or any 1.x release. |
| **Severity** | High for code built from `dev`. An attacker needs one byte of CBOR to trigger it. The out-of-bounds read happens in the caller's use of the returned length. |
| **Reachability** | Untrusted decode input, through the documented public API. |

## Reproducer

`getarray_empty.c` (attached). It takes the case to run as its argument: `top` (the default),
`map`, `nested` or `indef`, in the order of the table above. Its `Scribble()` fills the stack with `0x41` first, so a plain build shows a
recognizable value:

```c
static const uint8_t aTop[] = {0x80};              /* [] */
QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aTop), QCBOR_DECODE_MODE_NORMAL);
QCBORDecode_GetArray(&D, &Item, &Enc);
printf("error=%d len=%zu\n", QCBORDecode_GetError(&D), Enc.len);
```

Build it from the top of a QCBOR checkout:

```text
$ clang -g -O0 -Iinc -Isrc getarray_empty.c src/*.c -lm
$ ./a.out top
top    error=0  len=4702111234474983745 (expect 1)
$ ./a.out map
map    error=0  len=4702111234474983745 (expect 1)

$ clang -g -O1 -fsanitize=memory -fsanitize-memory-track-origins=2 -Iinc -Isrc getarray_empty.c src/*.c -lm
$ ./a.out top
WARNING: MemorySanitizer: use-of-uninitialized-value
  Uninitialized value was stored to memory at
    #0 in QCBORDecode_Private_GetArrayOrMap src/qcbor_main_decode.c:2578:22
  Uninitialized value was created by an allocation of 'End' in the stack frame
    #0 in QCBORDecode_Private_GetArrayOrMap src/qcbor_main_decode.c:2515:4
```

MSan reports the same for `nested`, `map` and `indef`.

## Root cause

`QCBORDecode_Private_GetArrayOrMap()` ([`qcbor_main_decode.c:2515-2579`](https://github.com/laurencelundblade/QCBOR/blob/19c3367c0bf7db3ffcc8bc5626d7740dc5b8a76e/src/qcbor_main_decode.c#L2515-L2579))
declares `struct ItemEndTracker End`. It sets only `End.uTargetLevel`, then reads `End.uEndOffset`
at the end:

```c
uEndOfReturned    = End.uEndOffset;
pEncodedCBOR->ptr = UsefulInputBuf_OffsetToPointer(&(pMe->InBuf), uStartOfReturned);
pEncodedCBOR->len = uEndOfReturned - uStartOfReturned;
```

`End.uEndOffset` is written only by `QCBORDecode_Private_NestLevelAscender()`, when the target
level closes. An empty definite-length array or map is never descended into, so its level never
closes and `uEndOffset` is never written.

## Fix

In `QCBORDecode_Private_GetNextMapOrArray()`, record the end right after the head of an empty
definite-length array or map that is at the target level. This must happen before the ascender
runs, because the ascender may consume breaks of enclosing indefinite-length levels:

```c
if(pEnd != NULL &&
   QCBORItem_IsEmptyDefiniteLengthMapOrArray(*pDecodedItem) &&
   pDecodedItem->uNestingLevel + 1 == pEnd->uTargetLevel) {
   pEnd->uEndOffset = UsefulInputBuf_Tell(&(pMe->InBuf));
}
```

The patch adds tests 110–113 to `GetMapAndArrayTest`, one for each input in the table above, each
expecting the one-byte encoding back. Test 113 is skipped under
`QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS`.

A defensive alternative would be to initialize `End.uEndOffset` to an invalid value and fail
with an error if it is still unset. That would stop a wrong length from ever leaving the
function. It could be added on top of this fix.

## Validation

On `dev` at `19c3367`, with gcc 14.2.0 and clang 19.1.7 on Linux x86_64:
- `make warn` builds with no new warning and the test suite passes in all 12 CI configurations
  (no `#define`, and each of the 11 `QCBOR_DISABLE_*` / `USEFULBUF_DISABLE_*` options), with gcc
  and clang.
- The test suite passes (90/90) under ASan + UBSan and under MSan
  (`-fno-sanitize-memory-param-retval`). UBSan reports nothing new.
- On the unpatched sources, the new test fails: `GetMapAndArrayTest FAILED (returned 110)`.
- All four reproducer cases return `len=1` in plain and MSan builds, with no MSan report.

## Credit

Found while reviewing the output of an automated Frama-C/E-ACSL/sanitizer analysis of QCBOR. The
analysis itself missed it; it was found and confirmed by hand with MemorySanitizer.
