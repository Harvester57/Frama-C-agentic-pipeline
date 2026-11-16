# Frama-C filing texts

- **Parent index, coverage table and filing order:** [`../README.md`](../README.md)

Paste-ready texts for [`pub/frama-c`](https://git.frama-c.com/pub/frama-c):

- **`NN-<slug>-issue.md`:** the issue. The first line is the title, prefixed by the plug-in tag
  upstream asks for (`[E-ACSL]`, `[Kernel]`, `[WP]`, `[Libc]`, `[e-acsl-gcc]`). Everything below the
  HTML comment is the description, laid out like upstream's `bug_report.md` template.
- **`NN-<slug>-mr.md`:** the merge request.
  - The first line is the MR title, which is also the patch subject.
  - The two lines above the comment give the source branch, the base commit and the patch file.
  - Below the comment is the description, starting with upstream's `external_contribution.md`
    checkboxes, left unticked for the owner.

There is no MR text for 15 (no patch) or 23 (fixed by 27's MR). The texts of 30 and 31 cite each
other (`#ISSUE-30`, `#ISSUE-31`): file both issues first. Replace `#<issue>`, `#ISSUE-NN` and
`!<MR>` with the real numbers when filing. The texts are self-contained: they quote the reproducer
and its output, and they link nothing in this repository.
