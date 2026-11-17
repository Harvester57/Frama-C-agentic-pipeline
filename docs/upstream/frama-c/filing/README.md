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

There is no MR text for 15 or 34 (no patch) or 23 (fixed by 27's MR). 40's MR text corrects two
sentences of the WP manual only: it says "Related to", not "Closes", because the feature request of
its issue stays open. The texts are self-contained: they quote the reproducer and its output, and
they link nothing in this repository.

Every text of this folder is filed (01 to 27 on 2026-11-15, 28 to 40 on 2026-11-18), and the
placeholders now hold the real numbers. For a new package, write `#<issue>` for its own issue and
`#ISSUE-NN` for another package's, file the issues in an order that lets each text cite the ones it
needs, and replace the placeholders before sending: 30 to 33 cite each other, and 38 cites 37.
