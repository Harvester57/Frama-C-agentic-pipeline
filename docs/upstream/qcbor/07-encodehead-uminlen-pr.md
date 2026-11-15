Two PRs with the same change: one against `dev` (patch [`0006`](./patches/public/0006-Reject-uMinLen-8-in-QCBOREncode_EncodeHead.patch)) and one against `master` for 1.x (patch [`v1/0002`](./patches/v1/0002-Reject-uMinLen-8-in-QCBOREncode_EncodeHead.patch)). Each body is between the markers below.

---

**PR for `dev`.** Title: "Reject uMinLen > 8 in QCBOREncode_EncodeHead()".

Fixes #<issue>.

`QCBOREncode_EncodeHead()` with `uMinLen` of 9 or more indexed `aIterate[]` past its end and wrote before the start of the caller's buffer.

## Change

- `src/qcbor_main_encode.c`: `QCBOREncode_EncodeHead()` returns `NULLUsefulBufC` when `uMinLen` is more than 8, as it already does for a buffer that is too small. The `EXTRA_ENCODE_HEAD_CHECK` block now says `Buffer.ptr` instead of `buffer.ptr`, so it compiles when enabled.
- `inc/qcbor/qcbor_main_encode.h`: the `@param uMinLen` and `@return` documentation state the limit.
- `test/qcbor_encode_tests.c`: `QCBORHeadTest()` checks that `uMinLen` 8 still gives `1b 00 00 00 00 00 00 00 00` (-4), and that 9 returns NULL (-5).

## Testing

All on `dev` `19c3367`, with gcc and clang 19.1.7 on Linux x86_64:

- Without the fix in `src/`, the new test crashes the test binary with a segmentation fault: the writes before `RightSize` corrupt the stack.
- `make warn` with gcc and with clang, for each of the 12 configurations in the CI workflow, builds with no new warning, and `qcbortest` passes 90/90.
- The test suite under ASan + UBSan reports nothing new.
- The reproducer in the issue prints `OK`, also under ASan + UBSan.
- This PR applies on its own to `dev`. Merged with my other open QCBOR PRs, the same checks pass, and the test suite is also clean under MSan.

Suggested `CHANGELOG.md` line under `[Unreleased]` / `### Fixed`:
`- QCBOREncode_EncodeHead() wrote before its buffer when uMinLen was more than 8; it now returns NULLUsefulBufC (#<issue>)`

The change and tests were prepared with LLM assistance (Claude Code); I reviewed them and ran the tests above.

---

**PR for `master` (1.x).** Title: "Reject uMinLen > 8 in QCBOREncode_EncodeHead() (1.x)".

Fixes #<issue> for 1.x. This is the same change as #<dev PR> on `dev`.

## Change

- `src/qcbor_encode.c`: `QCBOREncode_EncodeHead()` returns `NULLUsefulBufC` when `uMinLen` is more than 8, and the `EXTRA_ENCODE_HEAD_CHECK` block says `Buffer.ptr`.
- `inc/qcbor/qcbor_encode.h`: the `@param uMinLen` and `@return` documentation state the limit.
- `test/qcbor_encode_tests.c`: `QCBORHeadTest()` checks that `uMinLen` 9 returns NULL.

## Testing

All on `master` `1d06057`, with gcc and clang 19.1.7 on Linux x86_64:

- Without the fix in `src/`, the new test crashes the test binary with a segmentation fault.
- `make warn` with gcc and with clang, for each of the 10 configurations in the CI workflow, builds with no warning, and `qcbortest` passes 76/76.
- The test suite under ASan + UBSan reports nothing new.
- The reproducer in the issue prints `OK`. Without the fix, the plain build crashes with a segmentation fault.

The change and tests were prepared with LLM assistance (Claude Code); I reviewed them and ran the tests above.
