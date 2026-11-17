Fixes #<issue>.

`QCBOREncode_Private_AddTBigNumberMain()` called `QCBOREncode_AddTBigNumberRaw()` with its tag-requirement and sign arguments swapped. A positive big number with `QCBOR_ENCODE_AS_BORROWED` came out as tag 3 (negative), and a positive number of 2^64 or more was rejected under `QCBOR_ENCODE_CONFIG_ONLY_PREFERRED_BIG_NUMBERS`.

## Change

- `src/qcbor_number_encode.c`: the positive path outputs the tag and the byte string itself, with `QCBOREncode_Private_BigNumberTag()` and `QCBOREncode_AddBytes()`, as the negative path already does through `QCBOREncode_Private_AddTNegativeBigNumber()`. A comment says why it does not go through `AddTBigNumberRaw()` and its preferred-only guard.
- `test/qcbor_encode_tests.c`: `BigNumEncodeTests()` checks that +258 with `QCBOR_ENCODE_AS_BORROWED` is `42 01 02` (-5), and that 2^64 encodes as `c2 49 01 00 …` under `QCBOR_ENCODE_CONFIG_ONLY_PREFERRED_BIG_NUMBERS` (-6).

## Testing

All on `dev` `19c3367`, with gcc and clang 19.1.7 on Linux x86_64:

- Without the fix in `src/`, the new test fails: `BigNumEncodeTests FAILED (returned -5)`.
- `make warn` with gcc and with clang, for each of the 12 configurations in the CI workflow, builds with no new warning, and all `qcbortest` tests pass.
- The test suite under ASan + UBSan reports nothing new.
- The reproducer in the issue prints `OK`.
- This PR applies on its own to `dev`. Merged with my other open QCBOR PRs, the same checks pass, and the test suite is also clean under MSan.

Suggested `CHANGELOG.md` line under `[Unreleased]` / `### Fixed`:
`- Positive big numbers encoded with QCBOR_ENCODE_AS_BORROWED were tagged as negative (#<issue>)`

The change and tests were prepared with LLM assistance (Claude Code); I reviewed them and ran the tests above.
