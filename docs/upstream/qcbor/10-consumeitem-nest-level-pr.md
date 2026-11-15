Two PRs: one against `dev` (patch [`0008`](./patches/public/0008-Don-t-set-uNextNestLevel-when-consuming-an-array-or-.patch)) and one against `master` for 1.x (patch [`v1/0003`](./patches/v1/0003-Don-t-set-uNextNestLevel-when-consuming-an-array-or-.patch)). Each body is between the markers below.

---

**PR for `dev`.** Title: "Don't set uNextNestLevel when consuming an array or map stops early".

Fixes #<issue>.

`QCBORDecode_Private_ConsumeItem()` copied `Item.uNextNestLevel` into its output after the traversal loop stopped on an error, when `Item` had not been written. Through `QCBORDecode_VGetNextConsume()`, this replaced the caller's `uNextNestLevel` with an uninitialized byte for truncated input such as `81`.

## Change

- `src/qcbor_main_decode.c`: on a halting error and on `QCBOR_ERR_NO_MORE_ITEMS`, the loop returns directly instead of breaking. `*puNextNestLevel` is left unset, as the function's documentation already says. The "Should never occur" comment on `NO_MORE_ITEMS` now says when it does occur: the input ends before the array or map does.
- `test/qcbor_decode_tests.c`: new input `spBadConsumeInput6` (`81`). `EnterMapTest()` checks that `QCBORDecode_VGetNextConsume()` sets `QCBOR_ERR_NO_MORE_ITEMS` (3001), and that the item still has type array and `uNextNestLevel` 1 (3002).

## Testing

All on `dev` `19c3367`, with gcc and clang 19.1.7 on Linux x86_64:

- Without the fix in `src/`, the new test fails: `EnterMapTest FAILED (returned 3002)`. That check reads a stack byte, so it could pass by chance on another platform. MSan always reports it.
- `make warn` with gcc and with clang, for each of the 12 configurations in the CI workflow, builds with no new warning, and `qcbortest` passes 90/90.
- The test suite under ASan + UBSan reports nothing new, and under MSan it is clean.
- The reproducer in the issue prints `OK`, with and without MSan. A truncated map (`b7` with nothing after it) is clean under MSan too.
- This PR applies on its own to `dev`. Merged with my other open QCBOR PRs, the same checks pass.

Suggested `CHANGELOG.md` line under `[Unreleased]` / `### Fixed`:
`- QCBORDecode_VGetNextConsume() set an uninitialized uNextNestLevel when an array or map was truncated (#<issue>)`

The change and tests were prepared with LLM assistance (Claude Code); I reviewed them and ran the tests above.

---

**PR for `master` (1.x).** Title: "Don't set uNextNestLevel when consuming an array or map stops early (1.x)".

Fixes #<issue> for 1.x. This is the same fix as #<dev PR> on `dev`.

## Change

- `src/qcbor_decode.c`: `QCBORDecode_Private_ConsumeItem()` sets `*puNextNestLevel` only when the traversal loop ended with `QCBOR_SUCCESS`. Its `@param puNextNestLevel` documentation says "Not set on error".
- `test/qcbor_decode_tests.c`: the same `spBadConsumeInput6` (`81`) test as on `dev`, in `EnterMapTest()` (3001, 3002).

## Testing

All on `master` `1d06057`, with gcc and clang 19.1.7 on Linux x86_64:

- Without the fix in `src/`, the new test fails: `EnterMapTest FAILED (returned 3002)`.
- `make warn` with gcc and with clang, for each of the 10 configurations in the CI workflow, builds with no warning, and `qcbortest` passes 76/76.
- The test suite under ASan + UBSan reports nothing new, and under MSan it is clean.
- The reproducer in the issue prints `OK`, with and without MSan.

The change and tests were prepared with LLM assistance (Claude Code); I reviewed them and ran the tests above.
