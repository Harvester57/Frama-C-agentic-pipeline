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

[`./00-reports-overview-issue.md`](./00-reports-overview-issue.md) is not a bug report: it is an
overview of the 39 filed issues for the maintainers (where they come from, the five that
matter, an index by component, the findings of the hunt of 2026-11-18 that are not filed, three
questions and the CLA status). It is filed as
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832) (2026-11-18). If the issue is
edited on the tracker, edit this file the same way.

The texts of 43 (E-ACSL real constants, drafted on 2026-11-18) are **not filed** either: the MR
text still holds `#<issue>`. The same goes for the texts of 44 (the contract of `strlcat`,
drafted the same day).

45 (MetAcsl refuses `\result` in a `\postcond` property; issue drafted on 2026-11-18, MR text
added on 2026-11-20) is **not filed**. Like 47, 48 and 49, it is written for the MetAcsl tracker,
[`pub/meta`](https://git.frama-c.com/pub/meta/-/issues), so its issue title carries no plug-in tag,
and its MR text has no CONTRIBUTING/CLA checkboxes (`pub/meta` has no merge-request template) and
holds `#<issue>`.

47, 48 and 49 (MetAcsl: callee labels in `\written`/`\read` instances, folded instances without
location, no instance and no warning for a call to a function without specification; drafted on
2026-11-20) are **not filed**. They are written for `pub/meta` too, so like 45 and the existing
`pub/meta` issues their issue titles carry no plug-in tag. Each has an issue and an MR text.
`pub/meta` has no merge-request template, so their MR texts have no CONTRIBUTING/CLA checkboxes.
49 cites 47 and 48 as `#ISSUE-47` and `#ISSUE-48`.

Every other text of this folder is filed (01 to 27 on 2026-11-15, 28 to 42 on 2026-11-18), and
their placeholders now hold the real numbers. For a new package, write `#<issue>` for its own issue and
`#ISSUE-NN` for another package's, file the issues in an order that lets each text cite the ones it
needs, and replace the placeholders before sending: 30 to 33 cite each other, and 38 cites 37.
