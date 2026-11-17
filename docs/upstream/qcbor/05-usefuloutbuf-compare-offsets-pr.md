Fixes #<issue>.

`UsefulOutBuf_Compare()` added its offsets and lengths to the buffer pointer before checking them, so wrapping values read before the buffer or gave a wrong result. That contradicts the header, which says the function is safe for any offsets.

## Change

- `src/UsefulBuf.c`: `UsefulOutBuf_Compare()` works on offsets and lengths, not pointers. Each string is first cut to the output data, and a string that starts at or past the end is empty. The bytes are then read as `pBase[uStart + uIndex]`, with indexes that are always inside the data. Results for in-range arguments are unchanged.
- `inc/qcbor/UsefulBuf.h`: the `@return` line now has the right sign, and the paragraph on out-of-range offsets says what the function does: such a string is empty, and nothing outside the output data is read, whatever the offsets and lengths.
- `test/UsefulBuf_Tests.c`: `UOBExtraTests()` checks `Compare(SIZE_MAX, 2, 0, 2) == 1`, `Compare(0, 2, SIZE_MAX, 2) == -1` and `Compare(0, SIZE_MAX, 0, 10) == 0`.

## Testing

All on `dev` `19c3367`, with gcc and clang 19.1.7 on Linux x86_64:

- Without the fix in `src/`, the new tests fail: `UOBExtraTests FAILED (returned Comparison with wrapping offset)`.
- `make warn` with gcc and with clang, for each of the 12 configurations in the CI workflow, builds with no new warning, and all `qcbortest` tests pass.
- The test suite under ASan + UBSan reports nothing new. The only line change in its output is the existing NULL `memcpy` report at `UsefulBuf.h:2195`, which moves down a few lines because the header comment is longer.
- The reproducer in the issue prints `OK` in plain, ASan and UBSan builds.
- This PR applies on its own to `dev`. Merged with my other open QCBOR PRs, the same checks pass, and the test suite is also clean under MSan.

Suggested `CHANGELOG.md` line under `[Unreleased]` / `### Fixed`:
`- UsefulOutBuf_Compare() could read outside the buffer for offsets or lengths near SIZE_MAX (#<issue>)`

The change and tests were prepared with LLM assistance (Claude Code); I reviewed them and ran the tests above.
