# Frama-C patches

- **Parent index, coverage table and filing order:** [`../README.md`](../README.md)

Each file, `NN-<slug>.patch`, is one `git format-patch` commit on upstream `master` `3dff90fc70`
(2026-11-13). It holds the fix, a regression test and the test's oracles. 13's also carries 57
promoted oracles, and some others update existing oracles; each MR text lists them.

- **Applies on its own** to pristine `3dff90fc70` (`git apply --check`, rechecked 2026-11-15): every
  patch except `10-*`, which applies on top of `12-*`.
- **Apply with `git am --keep-non-patch`**, so the subject keeps its `[e-acsl]` / `[kernel]` /
  `[wp]` / `[libc]` prefix.
- **Validated** on a build of `3dff90fc70` with the patch: reproducer before and after, the new test
  failing without the fix, and ptests of the touched suites. Details are in each long draft and MR
  text.
- **Not run:** `make check-lint` and `make check-headers`.

No patch for 15 (a design choice for the maintainers); 23 is fixed by `27-*`.

**28 to 31 (2026-11-16, not filed):** same standard, and in addition each was checked with
`git am --3way` after the 22 earlier patches, and with upstream's `./dev/check-files.sh -p HEAD~1`
in `framac-lint:3dff90f`. `28-*` also touches the kernel (`Demote_string_literal.demote_list`).
`30-*` and `31-*` change the same runtime function and apply together in either order. The commits
are authored with the GitLab noreply address, not the personal one of the earlier patch files.
