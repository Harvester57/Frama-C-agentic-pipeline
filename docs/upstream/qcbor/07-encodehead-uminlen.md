# `QCBOREncode_EncodeHead()` with `uMinLen` > 8 writes before the start of its buffer

Draft issue for https://github.com/laurencelundblade/QCBOR/issues. Not filed yet.
Patches:
- `dev`: [`patches/public/0006-Reject-uMinLen-8-in-QCBOREncode_EncodeHead.patch`](patches/public/0006-Reject-uMinLen-8-in-QCBOREncode_EncodeHead.patch);
- 1.x: [`patches/v1/0002-Reject-uMinLen-8-in-QCBOREncode_EncodeHead.patch`](patches/v1/0002-Reject-uMinLen-8-in-QCBOREncode_EncodeHead.patch), which also applies to v1.6.1.

## Summary

`QCBOREncode_EncodeHead()` is public: it lets applications hash a byte string in chunks. Its
`uMinLen` is documented only as "the minimum number of bytes to encode uNumber". A CBOR head
argument is at most 8 bytes. With `uMinLen` of 9 or more:
- the encoding loop indexes the 4-entry `aIterate[]` past its end;
- it keeps pre-decrementing `pByte`, writing before the start of the caller's `Buffer`.

The function already returns `NULLUsefulBufC` for a too-small buffer, but nothing checks `uMinLen`.

The out-of-bounds read and write are confirmed:

| Build | Result |
| :--- | :--- |
| UBSan | `index 4 out of bounds for type 'const uint8_t[4]'` |
| ASan | `global-buffer-overflow` read, 0 bytes after `QCBOREncode_EncodeHead.aIterate` |
| UBSan, on 1.x | The program then crashed with `SEGV ... pc 0x000000000000`: the writes before the stack buffer had corrupted the frame. |

No caller inside QCBOR passes more than 8, and an application has no reason to.

**Unrelated typo, fixed in the same patch:** the `EXTRA_ENCODE_HEAD_CHECK` sanity check refers to
`buffer.ptr` instead of `Buffer.ptr`, so it does not compile when enabled.

| | |
| :--- | :--- |
| **Affected** | `dev` at 9bd0845 (`src/qcbor_main_encode.c:470`); v2.0-alpha-6; 1.x `master` at 1d06057 and v1.6.1 (`src/qcbor_encode.c:468`). |
| **Severity** | Low. This is API hardening: the trigger is an out-of-range constant passed by the application, not data. |
| **Reachability** | Public encode API only. |

## Reproducer

[`repro/encodehead.c`](repro/encodehead.c):

```c
UsefulBuf_MAKE_STACK_UB(Head, QCBOR_HEAD_BUFFER_SIZE);
UsefulBufC Out = QCBOREncode_EncodeHead(Head, CBOR_MAJOR_TYPE_POSITIVE_INT, 9, 0);
```

```text
$ clang -g -O1 -fsanitize=address -Iinc -Isrc encodehead.c src/*.c -lm && ./a.out
==ERROR: AddressSanitizer: global-buffer-overflow ... READ of size 1
    #0 in QCBOREncode_EncodeHead src/qcbor_main_encode.c:470:39
0x... is located 0 bytes after global variable 'QCBOREncode_EncodeHead.aIterate' defined in 'src/qcbor_main_encode.c:462' of size 4
```

## Root cause

[`src/qcbor_main_encode.c:462-475`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_main_encode.c#L462-L475):

```c
static const uint8_t aIterate[] = {1,1,2,4};
int nMinLen = (int)uMinLen;
for(i = 0; uArgument || nMinLen > 0; i++) {
   const int nIterations = (int)aIterate[i];        /* i == 4 for uMinLen 9 */
   for(int j = 0; j < nIterations; j++) {
      *--pByte = (uint8_t)(uArgument & 0xff);       /* runs past the start of Buffer */
```

## Fix

Reject the value up front, as for a too-small buffer, and document the limit:

```c
if(uMinLen > sizeof(uint64_t)) {
   return NULLUsefulBufC;
}
```

The patch also:
- fixes `buffer.ptr` → `Buffer.ptr`;
- updates the `@param uMinLen` and `@return` documentation;
- extends `QCBORHeadTest` so that `uMinLen` 9 must return NULL. On `dev` the test also checks that
  8 still works.

## Validation

Validated with clang 19.1.7 on Linux x86_64:
- **`dev`:** the reproducer returns `len=0`, clean under ASan and UBSan. The test suite passes
  (89/89). On the sources before this patch, the new test fails: `QCBORHeadTest FAILED (returned -5)`.
- **1.x:** the reproducer returns `len=0`, clean under ASan. The test suite passes (76/76) under
  ASan + UBSan.
