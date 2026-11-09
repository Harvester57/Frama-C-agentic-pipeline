# `GetTEpochDate()` / `GetTEpochDays()` overwrite the caller's output with an indeterminate value on error

Draft issue for https://github.com/laurencelundblade/QCBOR/issues. Not filed yet.
Patch: [`patches/public/0005-Don-t-write-an-indeterminate-epoch-date-or-days-on-d.patch`](patches/public/0005-Don-t-write-an-indeterminate-epoch-date-or-days-on-d.patch).

## Summary

Six getters copy `Item.val` into the caller's output **unconditionally**:
- `QCBORDecode_GetTEpochDate()`, `GetTEpochDateInMapN()` and `GetTEpochDateInMapSZ()`;
- `QCBORDecode_GetTEpochDays()`, `GetTEpochDaysInMapN()` and `GetTEpochDaysInMapSZ()`.

When decoding fails, that value was never set, for one of two reasons:
- **An error is already latched.** `Item` is a local that is never written.
- **The label is not found.** `Item` is a copy of the map-search template `OneItemSearch[0]`,
  whose `val` was never set.

So the caller's `*pnTime` or `*pnDays` is overwritten with uninitialized stack memory. MemorySanitizer
confirms all six. A caller that pre-sets a default and relies on it after a failed get loses it.

QCBOR's error-latching design tells callers to check `QCBORDecode_GetError()` before using
outputs, so a careful caller is not affected. But:
- **It is a regression from 1.x.** 1.x assigns the output only on success.
- **The other getters don't do it.** Big numbers, MIME and strings in the same file do not write
  garbage on error.
- **It makes MSan unusable for applications.** An application that uses the default-value pattern
  gets MSan reports that point into QCBOR.

| | |
| :--- | :--- |
| **Affected** | `dev` at 9bd0845, and v2.0-alpha-6. Not 1.x. |
| **Severity** | Low. Writing an indeterminate value is not undefined behavior here, because `Item`'s address is taken. |
| **Reachability** | Untrusted decode input triggers the error path; any malformed or unexpected input does. |

## Reproducer

[`repro/epoch_uninit.c`](repro/epoch_uninit.c) has five modes. The caller's own value is `0x1234`:

```c
int64_t nOut = 0x1234;
static const uint8_t aMap[] = {0xa1, 0x01, 0x02};          /* {1: 2} */
QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aMap), QCBOR_DECODE_MODE_NORMAL);
QCBORDecode_EnterMap(&D, NULL);
QCBORDecode_GetTEpochDateInMapN(&D, 5, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &nOut);  /* label 5: not found */
printf("output %s\n", nOut == 0x1234 ? "unchanged" : "overwritten");
```

```text
$ clang -g -O1 -fsanitize=memory -fsanitize-memory-track-origins=2 -Iinc -Isrc epoch_uninit.c src/*.c -lm
$ ./a.out notfound-n
WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 in main epoch_uninit.c:42
  Uninitialized value was stored to memory at
    #0 in QCBORDecode_GetTEpochDateInMapN src/qcbor_tag_decode.c:919:12
  Uninitialized value was stored to memory at
    #0 in __msan_memcpy
    #1 in QCBORDecode_Private_GetItemInMapNoCheck src/qcbor_spiffy_decode.c:497:13
  Uninitialized value was created by an allocation of 'OneItemSearch' in the stack frame
    #0 in QCBORDecode_Private_GetItemInMapNoCheckN src/qcbor_spiffy_decode.c:566:4
```

The modes and what each reports:

| Mode | Function | Store | Origin |
| :--- | :--- | :--- | :--- |
| `latched` | `GetTEpochDate` | `qcbor_tag_decode.c:893` | `Item`, `:882` |
| `days-latched` | `GetTEpochDays` | `:966` | `Item`, `:955` |
| `notfound-n` | `GetTEpochDateInMapN` | `:919` | `OneItemSearch`, `qcbor_spiffy_decode.c:566` |
| `notfound-sz` | `GetTEpochDateInMapSZ` | `:945` | `OneItemSearch`, `qcbor_spiffy_decode.c:624` |
| `days-notfound` | `GetTEpochDaysInMapN` | `:992` | `OneItemSearch`, `qcbor_spiffy_decode.c:566` |

`GetTEpochDaysInMapSZ()` (`:1018`) has the same code as `GetTEpochDateInMapSZ()`.

## Root cause

[`src/qcbor_tag_decode.c:893`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_tag_decode.c#L893),
[`:919`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_tag_decode.c#L919),
[`:945`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_tag_decode.c#L945),
[`:966`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_tag_decode.c#L966),
[`:992`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_tag_decode.c#L992),
[`:1018`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_tag_decode.c#L1018):

```c
QCBORDecode_Private_ProcessTagItem(pMe, &Item, ..., QCBORDecode_DateEpochTagCB, uOffset, &Item);
*pnTime = Item.val.epochDate.nSeconds;          /* also on error */
```

## Fix

In all six functions:

```diff
-   *pnTime = Item.val.epochDate.nSeconds;
+   if(pMe->uLastError == QCBOR_SUCCESS) {
+      *pnTime = Item.val.epochDate.nSeconds;
+   }
```

The patch adds a test to `SpiffyDateDecodeTest`: after a failed `GetTEpochDateInMapN()` and a
failed `GetTEpochDaysInMapSZ()`, an output pre-set to 42 must still be 42. It returns 1081 and
1082 otherwise.

## Validation

Validated with clang 19.1.7 on Linux x86_64:
- With the patch, all five modes print `output unchanged` under MSan, with no report.
- The test suite passes (89/89) in plain, ASan + recoverable UBSan, and MSan builds.
- On the sources before this patch, the new test fails: `SpiffyDateDecodeTest FAILED (returned 1081)`.

## Not a bug: `uOffset` in `QCBORDecode_Private_GetItemInMap()`

A static analyzer may also flag `uOffset` in `QCBORDecode_Private_GetItemInMap()`
([`qcbor_spiffy_decode.c:510-516`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_spiffy_decode.c#L510-L516)).
It is passed uninitialized to `QCBORDecode_Private_GetItemChecks()` when an error is already
latched. That function reads `uOffset` only when the error passed in is `QCBOR_SUCCESS`, in the
unprocessed-tag-number check at `qcbor_main_decode.c:2291-2298`. On this path the latched error is
passed in, so the value is never used. It is also not undefined behavior, because its address is
taken. Initializing it to 0 would only silence the tools.
