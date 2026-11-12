# Upstream Frama-C & E-ACSL Bug Reports

- **Upstream Directory Index:** [`../README.md`](../README.md)
- **Master Issue Catalog & Validation Summary:** [`./frama-c-e-acsl-issues.md`](./frama-c-e-acsl-issues.md)

This folder contains minimal standalone bug reports, root-cause analyses against Frama-C `master` (`35.0~~dev` Bromine), and validated patches prepared for [`pub/frama-c`](https://git.frama-c.com/pub/frama-c/-/issues), alongside a snapshot of upstream work items (`./pub-frama-c_work_items_2026-11-09.csv`) used for deduplication.

---

## Standalone Issue Drafts

Start with [`./frama-c-e-acsl-issues.md`](./frama-c-e-acsl-issues.md) for the consolidated status table across Frama-C 33.0, 34.0~~dev, and 35.0~~dev. Individual filing-ready drafts:

| Issue # | Draft File | Component & Summary |
| :---: | :--- | :--- |
| 1 | [`./frama-c-eacsl-gcc-option-arguments-reparsed.md`](./frama-c-eacsl-gcc-option-arguments-reparsed.md) | `e-acsl-gcc.sh`: re-parses `-e`/`-E`/`-l`/`-F` values as script options |
| 3 | [`./frama-c-variadic-fallback-local-init.md`](./frama-c-variadic-fallback-local-init.md) | Kernel / Variadic: fallback names printed in local declaration initializers fail to link |
| 4 | [`./frama-c-eacsl-unbounded-range-abort.md`](./frama-c-eacsl-unbounded-range-abort.md) | E-ACSL: unbounded ranges in `__fc_libc` (`strtok_r`, `getsockopt`, `wcschr`) abort translation |
| 4b | [`./frama-c-getsockopt-unbounded-range.md`](./frama-c-getsockopt-unbounded-range.md) | `__fc_libc` (`sys/socket.h`): `getsockopt` contract uses unbounded `0..` range instead of `*optlen` |
| 5 | [`./frama-c-eacsl-incomplete-type-sizeof.md`](./frama-c-eacsl-incomplete-type-sizeof.md) | E-ACSL: emits `sizeof` / `_Alignof` on incomplete (opaque) struct types |
| 8 | [`./frama-c-eacsl-struct-result-initialized.md`](./frama-c-eacsl-struct-result-initialized.md) | E-ACSL: wrapper `__retres` left uninitialized in shadow memory (`\result.f` false positive) |
| 9 | [`./frama-c-eacsl-assert-print-data-alias.md`](./frama-c-eacsl-assert-print-data-alias.md) | E-ACSL: `-e-acsl-assert-print-data` mistakenly aliased to `-e-acsl-O-valid` in `options.ml` |
| 10 | [`./frama-c-eacsl-gcc-clang-cflags.md`](./frama-c-eacsl-gcc-clang-cflags.md) | `e-acsl-gcc.sh`: `-G clang` overwrites `CFLAGS` |
| 12 | [`./frama-c-eacsl-gcc-default-source.md`](./frama-c-eacsl-gcc-default-source.md) | `e-acsl-gcc.sh`: compiles with `-std=c99` without `-D_DEFAULT_SOURCE` used during preprocessing |
| 13 | [`./frama-c-eacsl-formal-params-initialized.md`](./frama-c-eacsl-formal-params-initialized.md) | E-ACSL: formal parameters registered with `__e_acsl_store_block` but never marked initialized (regression of #177) |
| 14 | [`./frama-c-eacsl-iff-labelled-term.md`](./frama-c-eacsl-iff-labelled-term.md) | E-ACSL (35.0~~dev regression): `<==>` over a labelled term aborts with `labels pre-analysis was not performed` |
