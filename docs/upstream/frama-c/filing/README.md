# Frama-C filing texts

- **Parent index, coverage table and filing order:** [`../README.md`](../README.md)
- **Dedicated reporting & filing skill:** [`../../../../skills/upstream-bug-report/SKILL.md`](../../../../skills/upstream-bug-report/SKILL.md) (`/upstream-bug-report`)
- **Upstream reporting guidelines:** [Guidelines for reporting bugs](https://git.frama-c.com/pub/frama-c/-/wikis/Guidelines-for-reporting-bugs)
- **Automated validator & filer:** [`../../../../tools/upstream_audit/file_upstream.py`](../../../../tools/upstream_audit/file_upstream.py)

Invoke `/upstream-bug-report` whenever drafting, auditing, updating, or filing any text in this folder.

## Mandatory reporting guidelines & enforcement

Every `NN-<slug>-issue.md` (other than the `00` overview discussion) must follow upstream's [Guidelines for reporting bugs](https://git.frama-c.com/pub/frama-c/-/wikis/Guidelines-for-reporting-bugs) and `bug_report.md` template:

- **English only**, LF line endings, balanced Markdown code fences, title <= 255 characters, and a single `<!-- Everything below this line... -->` description marker.
- **Category:** start the H1 title with a bracketed component tag (`[E-ACSL]`, `[e-acsl-gcc]`, `[Kernel]`, `[Libc]`, `[WP]`, `[Eva]`, `[RTE]`, `[Installation]`, `[GUI]`, `[Documentation]`) on `pub/frama-c`, and populate `Plug-in used:` in `### Contextual information` (note `kernel (Frama-C libc)` for libc issues). On `pub/meta`, omit the title tag and put `Tracker: pub/meta (MetAcsl), not pub/frama-c.` in the HTML marker.
- **Self-contained minimal reproducer (`### Steps to reproduce the issue`):** inline every minimal input file and exact command line; inline file line numbers must match every `file.c:N:` diagnostic quoted in `### Actual behaviour`. Never link into this repository (`](../`, `](./`) or refer to an unattached file. When using `-no-frama-c-stdlib` or `e-acsl-gcc` with non-freestanding host headers, state the host libc/compiler version (or provide a preprocessed `.i` file).
- **Obtained and expected behavior:** separate `### Expected behaviour` and `### Actual behaviour` sections with verbatim output and exit status. Place `Cause`, `Fix`, and workarounds under `### Additional information (optional)`.
- **Crashes, backtraces, and journals:** on any Frama-C OCaml crash (`Unexpected error`, `aborted: internal error`, `Please report as 'crash'`), include the verbatim backtrace (`-debug 1` / `OCAMLRUNPARAM=b`, collapsed in `<details>` if long) rather than stripping it. Record a `-journal-enable` journal (`frama_c_journal.ml`) when reproduction is stateful or GUI-driven.
- **Contextual information (`### Contextual information`):** include `Frama-C installation mode`, `Frama-C version`, `Plug-in used`, `OS name`, and `OS version`.

Validate every draft before handoff or filing:

```powershell
$env:PYTHONIOENCODING="utf-8"
python tools/upstream_audit/file_upstream.py check            # validate all issue drafts
python tools/upstream_audit/file_upstream.py check NN         # validate one package
```

`file_upstream.py show`, `issue`, and `mr` also run this check automatically and refuse to post any non-compliant draft or any `Tracker: pub/meta` text onto `pub/frama-c`. All issue drafts in this folder (01 through 87) pass `file_upstream.py check`.

---

Paste-ready texts for [`pub/frama-c`](https://git.frama-c.com/pub/frama-c):

- **`NN-<slug>-issue.md`:** the issue. The first line is the title, prefixed by the plug-in tag
  upstream asks for (`[E-ACSL]`, `[Kernel]`, `[WP]`, `[Libc]`, `[e-acsl-gcc]`). Everything below the
  HTML comment is the description, laid out like upstream's `bug_report.md` template.
- **`NN-<slug>-mr.md`:** the merge request.
  - The first line is the MR title, which is also the patch subject.
  - The two lines above the comment give the source branch, the base commit and the patch file.
  - Below the comment is the description, starting with upstream's `external_contribution.md`
    checkboxes, left unticked for the owner.

There is no MR text for 15, 34, or 63 (no patch) or 23 (fixed by 27's MR). 40's MR text corrects two
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
drafted the same day) and 46 (`<sched.h>` `cpu_set_t`, `CPU_*`, and `sched_{set,get}affinity`,
rewritten with an MR text and validated patch on 2026-11-22).

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

50 (E-ACSL `--validate-format-strings` crashing with `Assertion failed` in `functions.ml:156` on
`enum` arguments and `Options.fatal` on `enum *` pointers; drafted on 2026-11-22) is **not filed**
either: its MR text holds `#<issue>` and keeps the CONTRIBUTING/CLA checkboxes unticked.

51 to 87 (37 packages from the 2026-11-18 Frama-C hunt: 36 with validated patches + MR texts and
1 issue-only report, 63 for enumeration constant typing `N1`; drafted and validated on 2026-11-23
against stock `master` `189053d4a2` and stock `34.0~beta`) are **not filed** (filing remains paused
pending `#2832`): every MR text holds `#<issue>` and leaves the CONTRIBUTING/CLA checkboxes
unticked. Candidate `H13` (compilation-database shell quoting) has an internal analysis draft only
and deliberately has no file in this folder pending an owner disclosure-channel decision.

Every other text of this folder is filed (01 to 27 on 2026-11-15, 28 to 42 on 2026-11-18), and
their placeholders now hold the real numbers. For a new package, write `#<issue>` for its own issue and
`#ISSUE-NN` for another package's, file the issues in an order that lets each text cite the ones it
needs, and replace the placeholders before sending: 30 to 33 cite each other, and 38 cites 37.
