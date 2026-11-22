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

**`45-*`, `47-*`, `48-*` and `49-*` (2026-11-20, not filed)** are patches for MetAcsl (`pub/meta`),
not `pub/frama-c`, one commit each on `pub/meta` `master` `4f43801390`, authored with the GitLab
noreply address. Apply them to a clone of `pub/meta` with `git am --keep-non-patch` (subjects
`[meta]` and `[fold]`):

- **45:** threads `?(with_result=false)` from `process_property` (true only for `Postcond`) to
  `process_meta_termassoc` in `meta_parse.ml`, adding `\result` via `Logic_typing.add_result` with
  `Kernel_function.get_return_type` (plus `Ast_types.C.add_ghost` for ghost functions, guarded on
  `Ast_types.C.is_fun` for `Meta_deduce.dummy_unpack`), documents `\result` in `README.md` and
  `CHANGELOG.md`, and adds `tests/meta/postcond_result.c` with ten oracles (`oracle/` and
  `oracle_fold/`, `.0` through `.4`).
- **47:** maps the callee's `Old`/`Pre`/`Here` labels to MetAcsl's `Before` in `meta_annotate.ml`
  and adds `tests/meta/callee_labels.c` with four oracles.
- **48:** passes the property's location to folded calls and to the
  `external_assigns`/`passthrough_from` wrappers, adds a `CHANGELOG.md` entry and
  `tests/meta/fold_location.c` (two oracles), and updates
  `tests/meta-wp/oracle_fold/typing.0.res.oracle`.
- **49:** puts all three missing-footprint warnings (unspecified callee, `WritesAny` and
  `\reading`'s `FromAny`) under warning category `no-footprint` with call-site locations (`~loc`),
  documents it in `README.md` and `CHANGELOG.md`, and adds `tests/meta/no_footprint.i` covering
  `\writing` and `\reading` (four oracles).

Stacked with `git am --keep-non-patch --3way` (tested both `45, 47, 48, 49` and `47, 48, 49, 45`),
`meta_parse.ml`, `meta_annotate.ml`, `README.md` and all tests merge cleanly (only the
`# Version dev` line of `CHANGELOG.md` conflicts), all four reproducers exit 0, and all 31 + 31
`tests/meta` and 12 + 12 `tests/meta-wp` runs match their oracles byte-for-byte. They were built
and both `tests/meta` and `tests/meta-wp` (default and `fold` configurations) were run in throwaway
containers of `framac-analysis:latest` (34.0~beta), with `meta_parse.ml`'s `PLpointer_comparable`
line removed because 34.0~beta lacks it; that removal is not in the patches. Lint, the header
check and the `meta-deduce` Prolog proofs (SWI-Prolog absent) were not run. The oracles of 45, 47
and 49 contain trailing spaces or blank lines at EOF as Frama-C prints them; `git am` warns about
them.

**`50-*` (2026-11-22, not filed)** is one commit (`53ebd5fc4a`) on upstream `master` `189053d4a2`,
authored with the GitLab noreply address. It updates `Functions.Libc.get_printf_argument_str` in
`plugins/e-acsl/src/libraries/functions.ml` (4 lines added, 2 changed: maps `TEnum { ekind }` via
`get_ikind_str ekind` and recurses in `get_pkind_str` on `Cil_const.mk_tint ekind`) and adds
`plugins/e-acsl/tests/format/printf_enum.c` (14 sub-tests) with its three oracles
(`oracle/gen_printf_enum.0.c`, `oracle/printf_enum.0.res.oracle`,
`oracle_dev/printf_enum.0.e-acsl.err.log`). No existing oracle changes. Validated in fresh
containers of `framac-master-audit:189053d` with `revalidate.sh package 50` (fail-before /
pass-after in default and `dev`, full `plugins/e-acsl` default suite, `./dev/check-files.sh -p
HEAD~1`, and installed 12-case reproducer), plus the full `plugins/e-acsl/tests/format` `dev` suite
and `revalidate.sh combined 30 50` / `combined 50 30` (auto-merges `functions.ml` cleanly with `!48`
in either order and passes both `printf_promoted.c` and `printf_enum.c` in `dev`).
