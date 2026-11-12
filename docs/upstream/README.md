# Upstream Issue Drafts, Disclosure Packages & Vendored Sources

- **Documentation Hub:** [`../README.md`](../README.md)
- **Confirmed Target Advisories:** [`../bugs-found/README.md`](../bugs-found/README.md)

This directory organizes artifacts prepared for or extracted from upstream projects into three distinct subdirectories:

| Subdirectory | Purpose | Entry Point |
| :--- | :--- | :--- |
| [`./frama-c/`](./frama-c/README.md) | Bug reports, minimal standalone C reproducers, validated OCaml/shell patches, and issue-tracker exports for **upstream Frama-C 33.0 - 35.0~~dev** (`e-acsl`, `e-acsl-gcc`, kernel variadic printing, and `__fc_libc` specifications). | [`./frama-c/README.md`](./frama-c/README.md) & [`./frama-c/frama-c-e-acsl-issues.md`](./frama-c/frama-c-e-acsl-issues.md) |
| [`./qcbor/`](./qcbor/README.md) | Staged upstream disclosure bundle (9 bug reports, `public`/`private`/`v1` patch series, standalone C reproducers, and sanitizer test logs) from the QCBOR `run-5` assessment ([`../runs/2026-11-09-qcbor-run5-assessment.md`](../runs/2026-11-09-qcbor-run5-assessment.md)). | [`./qcbor/README.md`](./qcbor/README.md) |
| [`./sources/`](./sources/README.md) | Verbatim reference C/ACSL snippets and notes vendored from the upstream Frama-C master archive (`share/libc/eva_stubs.c`, Eva taint/partitioning tests, WP gallery examples, `make-wrapper` repair patterns), referenced by pipeline scripts and skills. | [`./sources/README.md`](./sources/README.md) |
