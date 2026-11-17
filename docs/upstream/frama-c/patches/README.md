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

No patch for 15 (a design choice for the maintainers), 34 or 40 (issues only); 23 is fixed by
`27-*`.

**28 to 31 (2026-11-16, not filed):** same standard, and in addition each was checked with
`git am --3way` after the 22 earlier patches, and with upstream's `./dev/check-files.sh -p HEAD~1`
in `framac-lint:3dff90f`. `28-*` also touches the kernel (`Demote_string_literal.demote_list`).
`30-*` and `31-*` change the same runtime function and apply together in either order. The commits
are authored with the GitLab noreply address, not the personal one of the earlier patch files.

**2026-11-17, upstream `master` at `95408044f7`:** 28 to 31 were re-validated on the new base, and
`32-*`, `33-*`, `35-*` to `39-*` were written on it (not filed). Each of these eleven was run with
[`../../../../tools/upstream_audit/revalidate.sh`](../../../../tools/upstream_audit/revalidate.sh)
in the image `framac-master-audit:9540804`: `git am --keep-non-patch`, the new test against
`master`'s sources (fails) and against the patch (passes), the default configuration of the whole
E-ACSL suite, any other touched test directory, `./dev/check-files.sh -p HEAD~1`, and the
reproducer before and after.

- `30-*`, `31-*` and `32-*` change the same runtime file and apply as a stack in any order.
- `33-*` regenerates three existing `format/` oracles; with 30 to 32, the `gen_*.0.c` oracles of
  their tests need regenerating.
- `37-*` and `38-*` apply in either order; 38's fix is complete under `-G clang` only with 37.
- `35-*` and `39-*` touch the kernel and the libc (`tests/syntax` and `tests/libc` were run).
- A patch must not change the mode of a file or create an executable one: a file copied into the
  container with `docker cp` from Windows has mode 755. `revalidate.sh` reports both.
