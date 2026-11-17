# Upstream Issue Drafts, Disclosure Packages & Vendored Sources

- **Documentation Hub:** [`../README.md`](../README.md)
- **Confirmed Target Advisories:** [`../bugs-found/README.md`](../bugs-found/README.md)

This directory organizes artifacts prepared for or extracted from upstream projects into four subdirectories:

| Subdirectory | Purpose | Entry Point |
| :--- | :--- | :--- |
| [`./frama-c/`](./frama-c/README.md) | Filing packages for 37 **upstream Frama-C** bugs and requests (E-ACSL, `e-acsl-gcc`, kernel, WP, libc), all filed. 24 were filed on 2026-11-15 as pub/frama-c#2793 to #2816, with merge requests !25 to !45 (15 and 22 are issues only, pending the maintainers' design choice). Thirteen more, 28 to 40, were filed on 2026-11-18 as #2817 to #2829, with merge requests !46 to !57 (34 is an issue only; 40's merge request corrects the manual only). Each has a long draft, paste-ready issue and merge-request texts (`filing/`), a standalone reproducer (`repro/`) and a `git format-patch` file (`patches/`). The 24 filed ones were re-checked on 2026-11-15 against `master` `3dff90fc70` and `34.0~beta`, with 22 validated patches; the eleven patches of 28 to 39 are validated on `master` `95408044f7`. | [`./frama-c/README.md`](./frama-c/README.md) & [`./frama-c/frama-c-e-acsl-issues.md`](./frama-c/frama-c-e-acsl-issues.md) |
| [`./qcbor/`](./qcbor/README.md) | Upstream disclosure bundle (10 bug reports, issue and PR texts for the public ones, filed on 2026-11-15 as laurencelundblade/QCBOR#439 to #452, a private follow-up email, `public`/`private`/`v1` patches, minimal C reproducers, and sanitizer test logs) from the QCBOR `run-5` and `run-6` assessments ([`../runs/2026-11-09-qcbor-run5-assessment.md`](../runs/2026-11-09-qcbor-run5-assessment.md), [`../runs/2026-11-15-qcbor-run6-findings-assessment.md`](../runs/2026-11-15-qcbor-run6-findings-assessment.md)). | [`./qcbor/README.md`](./qcbor/README.md) |
| [`./minmea/`](./minmea/README.md) | Issue and pull request drafts for `kosma/minmea` (`MINMEA-01`, unvalidated month and day in `minmea_getdatetime`; `MINMEA-04`, comment for the open `minmea_rescale` pull request), drafted 2026-11-14. | [`./minmea/README.md`](./minmea/README.md) |
| [`./sources/`](./sources/README.md) | Verbatim reference C/ACSL snippets and notes vendored from the upstream Frama-C master archive (`share/libc/eva_stubs.c`, Eva taint/partitioning tests, WP gallery examples, `make-wrapper` repair patterns), referenced by pipeline scripts and skills. | [`./sources/README.md`](./sources/README.md) |
