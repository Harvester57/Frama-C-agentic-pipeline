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

No patch for 15 (a design choice for the maintainers) or 34 (issue only); 23 is fixed by `27-*`.
`40-*` changes two sentences of the WP manual and nothing else (no test; the manual was not built):
the feature request of its issue has no patch.

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

**2026-11-18:** 28 to 33 and 35 to 40 are filed as merge requests !46 to !57, one branch per patch
from `95408044f7`. The branches were built with `git am --keep-non-patch` inside the audit
container and pushed from a bundle, because the host clone converts line endings.

**`41-*` (2026-11-18, filed as merge request !58)** is one commit on upstream `master` `b80fcac74f`, the head since
2026-11-17 (it also applies on `95408044f7`: the two differ only under `plugins/wp`). It adds
eleven macros to `share/libc/sys/ioctl.h` and a `tests/libc` test with its oracle, and changes no
existing oracle. It was run with `revalidate.sh package 41` in a container of
`framac-master-audit:9540804` whose tree had been fast-forwarded to `b80fcac74f` and rebuilt;
`tests/variadic` was run by hand in addition.

**`42-*` (2026-11-18, filed as !59)** is one commit on `b80fcac74f`, authored and committed with the
GitLab noreply address. It changes `Cfloat.parse_literal` in `plugins/wp/src/Cfloat.ml` (21 lines
added, 4 removed) and adds `plugins/wp/tests/wp_acsl/float_literals.i` with four oracles (default
and `qualif`, Float and Real model). No existing oracle changes. `revalidate.sh package` is shaped
for E-ACSL patches (`-c dev`, the E-ACSL suite), so the steps were run by hand in a container of
the audit image moved to `b80fcac74f`; the long draft lists them.

**`43-*` (2026-11-18, not filed)** is one commit on `b80fcac74f`, authored and committed with the
GitLab noreply address. It changes `Gmp.Q.normalize_str` in
`plugins/e-acsl/src/code_generator/gmp.ml` (12 lines added, 20 removed) and one sentence of
`gmp.mli`, and adds `plugins/e-acsl/tests/arith/real_constants.c` with two oracles. No existing
oracle changes. It was run with `revalidate.sh package 43` in a container of the audit image moved
to `b80fcac74f`; the `dev` configuration of `plugins/e-acsl/tests/arith` was run by hand in
addition.

**`44-*` (2026-11-18, not filed)** is one commit on `b80fcac74f`, authored and committed with the
GitLab noreply address. It rewrites four clauses of the contract of `strlcat` in
`share/libc/string.h` (6 lines added, 4 removed; the fourth, the `separation` precondition, came
with the second version of the patch), adds `tests/libc/strlcat.c` with its oracle, and
updates `tests/libc/oracle/string_h.0.res.oracle` (an unknown check and two unknown preconditions
become valid; two line numbers move). `fc_libc.0.res.oracle` does not change. It was run with
`revalidate.sh package 44` in a container of `framac-master-audit:b80fcac`.

**`47-*`, `48-*` and `49-*` (2026-11-20, not filed)** are patches for MetAcsl (`pub/meta`), not
`pub/frama-c`, one commit each on `pub/meta` `master` `4f43801390`, authored with the GitLab
noreply address. Apply them to a clone of `pub/meta` with `git am --keep-non-patch` (subjects
`[meta]` and `[fold]`). 47 maps the callee's `Old`/`Pre` labels to MetAcsl's `Before` in
`meta_annotate.ml` and adds `tests/meta/callee_labels.c` with four oracles; 48 passes the
property's location to folded calls and to the `external_assigns`/`passthrough_from` wrappers and
updates `tests/meta-wp/oracle_fold/typing.0.res.oracle`; 49 adds a `no-footprint` warning with a
test. 47 and 48 apply stacked (checked); 49 conflicts with them on one `CHANGELOG.md` line. They
were built and their suites run in throwaway containers of `framac-analysis:latest` (34.0~beta),
with `meta_parse.ml`'s `PLpointer_comparable` line removed because 34.0~beta lacks it; that
removal is not in the patches. Lint, the header check and the `meta-deduce` deduction checks
(SWI-Prolog absent) were not run. The oracles of 47 and 49 contain lines ending in spaces, as
Frama-C prints them; `git am` warns about them.
