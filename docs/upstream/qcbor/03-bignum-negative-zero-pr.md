Fixes #<issue>.

`QCBOREncode_AddTBigNumber()` and `QCBOREncode_AddTBigNumberNoPreferred()` with `bNegative` true and a big number of value zero applied the negative offset to zero. The result was −2^64 or −1, with no error.

## Change

- `src/qcbor_number_encode.c`: `QCBOREncode_Private_AddTBigNumberMain()` computes `bIsNegative`, which is false when the big number is empty or all zero bytes, and uses it everywhere in place of `bNegative`:

  ```c
  bIsNegative = bNegative && UsefulBuf_SkipLeading(BigNumber, 0x00).len > 0;
  ```

- `test/qcbor_encode_tests.c`: in `BigNumEncodeTestCases[]`, the two zero rows now expect zero for the negative side too (`c2 41 00` / `00`), and are renamed "0; negative 0 is 0". A new row covers the empty big number (`c2 40` / `00`).
- `inc/qcbor/qcbor_number_encode.h`: the documentation of `QCBOREncode_AddTBigNumber()` and `QCBOREncode_AddTBigNumberNoPreferred()` says that there is no negative zero: a zero with `bNegative` true is encoded as zero.

If you would rather reject −0 with an error, as the old row names suggest, the same check can set an encoder error instead, and the table rows would expect that error.

One case also needs #445: a negative zero with `QCBOR_ENCODE_AS_BORROWED` and no preferred serialization. With this PR alone it takes the positive path, which still has the swapped arguments that #445 fixes, and comes out as `c3 41 00`. With both PRs it is `41 00`.

## Testing

All on `dev` `19c3367`, with gcc and clang 19.1.7 on Linux x86_64:

- Without the fix in `src/`, the updated table fails: `BigNumEncodeTests FAILED (returned 7003000)`.
- `make warn` with gcc and with clang, for each of the 12 configurations in the CI workflow, builds with no new warning, and all `qcbortest` tests pass.
- The test suite under ASan + UBSan reports nothing new.
- The reproducer in the issue prints `OK`.
- This PR applies on its own to `dev`. Merged with my other open QCBOR PRs, the same checks pass, and the test suite is also clean under MSan.

Suggested `CHANGELOG.md` line under `[Unreleased]` / `### Fixed`:
`- A negative big number of value zero was encoded as -1 or -2^64; it is now encoded as 0 (#<issue>)`

The change and tests were prepared with LLM assistance (Claude Code); I reviewed them and ran the tests above.
