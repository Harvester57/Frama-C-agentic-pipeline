Fixes #<issue>.

The six epoch date and days getters copied `Item.val` into the caller's output even when decoding failed. On that path `Item.val` is uninitialized, either because an error was already latched or because the label was not found.

## Change

- `src/qcbor_tag_decode.c`: `QCBORDecode_GetTEpochDate()`, `GetTEpochDateInMapN()`, `GetTEpochDateInMapSZ()`, `GetTEpochDays()`, `GetTEpochDaysInMapN()` and `GetTEpochDaysInMapSZ()` assign `*pnTime` / `*pnDays` only when `pMe->uLastError` is `QCBOR_SUCCESS`, as 1.x does.
- `test/qcbor_decode_tests.c`: `SpiffyDateDecodeTest()` checks that a failed `GetTEpochDateInMapN()` (1081) and a failed `GetTEpochDaysInMapSZ()` (1082) leave the output unchanged.

## Testing

All on `dev` `19c3367`, with gcc and clang 19.1.7 on Linux x86_64:

- Without the fix in `src/`, the new test fails: `SpiffyDateDecodeTest FAILED (returned 1081)`.
- `make warn` with gcc and with clang, for each of the 12 configurations in the CI workflow, builds with no new warning, and `qcbortest` passes 90/90.
- The test suite under ASan + UBSan reports nothing new, and under MSan it is clean.
- The reproducer in the issue prints `OK`, with and without MSan. The label-not-found case of the four `InMap` getters is clean under MSan. The latched-error case of `GetTEpochDate()` / `GetTEpochDays()` keeps the caller's value, and is clean under MSan built with `-fno-sanitize-memory-param-retval` (see the note below).
- This PR applies on its own to `dev`. Merged with my other open QCBOR PRs, the same checks pass.

**MSan note.** With clang's default eager parameter check, MSan still flags the latched-error case at the call to `QCBORDecode_Private_ProcessTagOne()` (`qcbor_tag_decode.c:886`), because `uOffset` is passed uninitialized. `QCBORDecode_Private_ProcessTagItem()` returns on the latched error before it reads `uOffset`, so the value is never used. I left that alone. Initializing `uOffset` to 0 in the six getters would only silence the tool.

Suggested `CHANGELOG.md` line under `[Unreleased]` / `### Fixed`:
`- The epoch date and days getters no longer overwrite the caller's output with an uninitialized value on error (#<issue>)`

The change and tests were prepared with LLM assistance (Claude Code); I reviewed them and ran the tests above.
