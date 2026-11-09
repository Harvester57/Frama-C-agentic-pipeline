# `QCBORDecode_GetArray()` / `GetMap()` return an uninitialized length for an empty array or map

**Report privately.** Send this to lgl@island-resort.com with "QCBOR SECURITY" in the subject, as
QCBOR's `SECURITY.md` asks, or use GitHub private vulnerability reporting on the repository, which
is enabled. Do not open a public issue or push this file before the fix is public.
Patch: [`patches/private/0002-Fix-GetArray-GetMap-length-for-empty-definite-length.patch`](patches/private/0002-Fix-GetArray-GetMap-length-for-empty-definite-length.patch).

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
| **Affected** | `dev` only: introduced by 33cf49e (#431, 2026-11-02, "Fixes for GetArray()/GetMap() …"), present at 9bd0845. **Not** in v2.0-alpha-6 or any 1.x release. |
| **Severity** | High for code built from `dev`. An attacker needs one byte of CBOR to trigger it. The out-of-bounds read happens in the caller's use of the returned length. |
| **Reachability** | Untrusted decode input, through the documented public API. |

## Reproducer

[`repro/getarray_empty.c`](repro/getarray_empty.c). Its `Scribble()` fills the stack with `0x41` first, so a plain
build shows a recognizable value:

```c
static const uint8_t aTop[] = {0x80};              /* [] */
QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aTop), QCBOR_DECODE_MODE_NORMAL);
QCBORDecode_GetArray(&D, &Item, &Enc);
printf("error=%d len=%zu\n", QCBORDecode_GetError(&D), Enc.len);
```

```text
$ clang -g -O0 -Iinc -Isrc getarray_empty.c src/*.c -lm
$ ./a.out top
top    error=0  len=4702111234474983745 (expect 1)
$ ./a.out map
map    error=0  len=4702111234474983745 (expect 1)

$ clang -g -O1 -fsanitize=memory -fsanitize-memory-track-origins=2 ...
$ ./a.out top
WARNING: MemorySanitizer: use-of-uninitialized-value
  Uninitialized value was stored to memory at
    #0 in QCBORDecode_Private_GetArrayOrMap src/qcbor_main_decode.c:2551:22
  Uninitialized value was created by an allocation of 'End' in the stack frame
    #0 in QCBORDecode_Private_GetArrayOrMap src/qcbor_main_decode.c:2488:4
```

MSan reports the same for `nested`, `map` and `indef`.

## Root cause

`QCBORDecode_Private_GetArrayOrMap()` ([`qcbor_main_decode.c:2488-2552`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_main_decode.c#L2488-L2552))
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
expecting a length of 1.

A defensive alternative would be to initialize `End.uEndOffset` to an invalid value and fail
with an error if it is still unset. That would stop a wrong length from ever leaving the
function. It could be added on top of this fix.

## Validation

Validated with clang 19.1.7 on Linux x86_64:
- All four cases return `len=1` in plain and MSan builds, with no MSan report.
- The test suite passes (89/89) in plain, ASan + recoverable UBSan, and MSan builds.
- On the sources before this patch, the new test fails: `GetMapAndArrayTest FAILED (returned 110)`.

## Credit

Found while reviewing the output of an automated Frama-C/E-ACSL/sanitizer analysis of QCBOR. The
analysis itself missed it; it was found and confirmed by hand with MemorySanitizer.
