`QCBOREncode_EncodeHead()` is public, for applications that hash a byte string in chunks. Its `uMinLen` is documented only as "the minimum number of bytes to encode uNumber". A CBOR head argument is at most 8 bytes, but nothing checks `uMinLen`. With a value of 9 or more:

- the encoding loop indexes the 4-entry `aIterate[]` past its end;
- it keeps pre-decrementing `pByte`, and writes before the start of the caller's `Buffer`.

The function already returns `NULLUsefulBufC` for a buffer that is too small.

No caller inside QCBOR passes more than 8, so only an application passing an out-of-range constant triggers this. This is on `dev` (`19c3367`, `src/qcbor_main_encode.c:470`) and on 1.x `master` and v1.6.1 (`src/qcbor_encode.c:468`).

There is also an unrelated typo nearby: the `EXTRA_ENCODE_HEAD_CHECK` block refers to `buffer.ptr` instead of `Buffer.ptr`, so it does not compile when enabled.

## Reproducer

```c
#include <stdio.h>
#include "qcbor/qcbor_encode.h"

int main(void)
{
   UsefulBuf_MAKE_STACK_UB(Head, QCBOR_HEAD_BUFFER_SIZE);

   UsefulBufC Out = QCBOREncode_EncodeHead(Head, CBOR_MAJOR_TYPE_POSITIVE_INT, 9, 0);
   if(!UsefulBuf_IsNULLC(Out)) {
      printf("BUG: uMinLen 9 accepted, len %zu\n", Out.len);
      return 1;
   }
   printf("OK\n");
   return 0;
}
```

```text
$ cc -Iinc -Isrc repro.c src/*.c -lm && ./a.out
BUG: uMinLen 9 accepted, len 10

$ cc -g -fsanitize=address,undefined -fno-sanitize-recover=all -Iinc -Isrc repro.c src/*.c -lm && ./a.out
src/qcbor_main_encode.c:470:39: runtime error: index 4 out of bounds for type 'const uint8_t[4]'
```

On 1.x the UBSan build then crashed with a SEGV at `pc 0x000000000000`, because the writes before the stack buffer had corrupted the frame.

## Cause

[`src/qcbor_main_encode.c:462-472`](https://github.com/laurencelundblade/QCBOR/blob/19c3367c0bf7db3ffcc8bc5626d7740dc5b8a76e/src/qcbor_main_encode.c#L462-L472):

```c
static const uint8_t aIterate[] = {1,1,2,4};
int nMinLen = (int)uMinLen;
for(i = 0; uArgument || nMinLen > 0; i++) {
   const int nIterations = (int)aIterate[i];        /* i == 4 for uMinLen 9 */
   for(int j = 0; j < nIterations; j++) {
      *--pByte = (uint8_t)(uArgument & 0xff);       /* runs past the start of Buffer */
```

I have a fix with a test that returns `NULLUsefulBufC` for `uMinLen` > 8, and will open PRs for `dev` and for `master`.
