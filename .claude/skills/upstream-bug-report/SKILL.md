---
name: upstream-bug-report
description: >-
  Drafts, audits, packages, validates, and files upstream bug reports, feature
  requests, reproducers, patches, and merge requests for Frama-C (pub/frama-c)
  and MetAcsl (pub/meta). Invoke whenever an agent is preparing, reviewing,
  re-validating, or filing an upstream Frama-C, E-ACSL, e-acsl-gcc, WP, Eva,
  Kernel, Libc, or MetAcsl defect under docs/upstream/frama-c/. Enforces
  upstream's Guidelines for Reporting Bugs, the bug_report.md and
  external_contribution.md templates, deduplication, container reproduction on
  34.0~beta and master, mechanical checks via file_upstream.py check and
  revalidate.sh, and explicit owner go-ahead before any network write.
argument-hint: "<symptom | package NN> [--tracker pub/frama-c|pub/meta] [--patch] [--file]"
---

# Upstream Frama-C & MetAcsl Bug Reporting

You prepare, validate, and (only on explicit owner go-ahead) file upstream bug reports, feature requests, standalone reproducers, and merge requests for [`pub/frama-c`](https://git.frama-c.com/pub/frama-c/-/issues) and [`pub/meta`](https://git.frama-c.com/pub/meta/-/issues).

Every issue draft MUST follow Frama-C's official [Guidelines for reporting bugs](https://git.frama-c.com/pub/frama-c/-/wikis/Guidelines-for-reporting-bugs) and upstream's `bug_report.md` template, and pass [`../../tools/upstream_audit/file_upstream.py`](../../tools/upstream_audit/file_upstream.py) `check` before filing or handoff.

## Parameters

| Parameter | Default |
| :--- | :--- |
| `TARGET_DEFECT` | required: a symptom/log excerpt, an analysis draft under [`../../docs/upstream/frama-c/`](../../docs/upstream/frama-c/README.md), or a package number `NN` |
| `TRACKER` | `pub/frama-c` (project `780`). Use `pub/meta` (project `869`) for MetAcsl plug-in defects |
| `MODE` | `draft` (reproduce, deduplicate, write package, validate locally). Pass `--patch` to also build and validate a `git format-patch` and MR draft; pass `--file` only after explicit owner go-ahead |

## Hard rules

- **Never file, edit, comment, or push upstream without explicit owner go-ahead.** Check [`../../docs/upstream/frama-c/README.md`](../../docs/upstream/frama-c/README.md) for any active filing pause (such as waiting on maintainers in `#2832`) before proposing to file.
- **Never run `file_upstream.py issue` or `mr` on a `pub/meta` package.** `file_upstream.py` posts to `pub/frama-c` only and refuses filing texts whose marker names `Tracker: pub/meta`.
- **Self-contained filing texts only.** Paste-ready files under [`../../docs/upstream/frama-c/filing/`](../../docs/upstream/frama-c/filing/README.md) must never contain confidential target source code, internal repository links (`](../`, `](./`), local paths, or references to unattached files ("in the attached file").
- **Real container execution only.** Never invent command outputs, version strings, or test results. Run every reproducer in the real container (`framac-analysis:latest` for `34.0~beta` / MetAcsl, `framac-master-audit:*` for upstream `master`) and quote verbatim output.
- **File-writing discipline.** Use direct file-writing/editing tools only (never shell heredocs or PowerShell here-strings), keep LF line endings, never use emojis, and follow [`../../docs/AGENTS.md`](../../docs/AGENTS.md).

## 1. Confirm, minimize, and deduplicate

1. **Build a minimal synthetic reproducer (MRE):**
   - Strip all target-specific code and identifiers down to a tiny, self-contained C file (typically 5–30 lines). Use C-Reduce if minimizing from confidential or large code.
   - Avoid third-party headers whenever the defect reproduces without them (for example, declare only the minimal prototypes needed, as in package `22`).
2. **Reproduce on both versions:**
   - Run on `34.0~beta` (`framac-analysis:latest`) and on upstream `master` (`framac-master-audit:*`, fast-forwarding `master` if stale). For MetAcsl, reproduce on `framac-analysis:latest` and against `pub/meta` `master`.
   - When C semantics are at issue, also run `gcc` / `clang` on the same snippet to prove the expected C behavior.
3. **Rule out documented limits:**
   - Search [`../../docs/references/`](../../docs/references/README.md) and upstream's `.tex` manuals/changelogs to confirm the behavior is a defect (or explicitly label the report as a feature request).
4. **Check for duplicates:**
   - Check [`../../docs/upstream/frama-c/README.md`](../../docs/upstream/frama-c/README.md), [`../../docs/upstream/frama-c/frama-c-e-acsl-issues.md`](../../docs/upstream/frama-c/frama-c-e-acsl-issues.md), and [`../../docs/upstream/frama-c/pub-frama-c_work_items_2026-11-09.csv`](../../docs/upstream/frama-c/pub-frama-c_work_items_2026-11-09.csv).
   - Search the live upstream tracker (issues and merge requests, all states) via read-only `glab api` when credentials are available, and note any close neighbour issues in `Additional information`.

## 2. Frama-C Guidelines for Reporting Bugs (mandatory contract)

Every issue text under `docs/upstream/frama-c/filing/NN-<slug>-issue.md` must satisfy every requirement of [Guidelines for reporting bugs](https://git.frama-c.com/pub/frama-c/-/wikis/Guidelines-for-reporting-bugs) and upstream's `bug_report.md`:

| Upstream guideline | Requirement in `filing/NN-<slug>-issue.md` | Enforced by `file_upstream.py check` |
| :--- | :--- | :--- |
| **Language** | Write in English. | Manual review |
| **Category** (`Installation`, `Kernel (parsing, command line, libc)`, `GUI`, `<Plug-in>`, `Documentation`) | For `pub/frama-c`: start the H1 title with a bracketed component tag (`[E-ACSL]`, `[e-acsl-gcc]`, `[Kernel]`, `[Libc]`, `[WP]`, `[Eva]`, `[RTE]`, `[Installation]`, `[GUI]`, `[Documentation]`) and fill `Plug-in used:` in `### Contextual information` (for libc issues, note `kernel (Frama-C libc)`). For `pub/meta`: omit the title tag, put `Tracker: pub/meta (MetAcsl), not pub/frama-c.` in the HTML marker, and state `Plug-in used: MetAcsl ...`. | Error if missing on `pub/frama-c`; warning if `Plug-in used:` omitted on `pub/meta` |
| **How to reproduce** | Under `### Steps to reproduce the issue`: include every minimal input file inline, exact command line(s), and sequence of actions. Inline file line numbers MUST match every `file.c:N:` diagnostic quoted in the output. Never reference an "attached file". | Error on missing section, missing code/command, phantom attachment, or inline line-number mismatch |
| **System headers** | If the reproducer invokes `-no-frama-c-stdlib` or `e-acsl-gcc` and `#include`s non-freestanding host headers (`<stdio.h>`, `<string.h>`, `<fcntl.h>`, `<sys/...>`, etc.), either remove the host header, provide a preprocessed `.i` file, or explicitly record the host libc and compiler versions (`glibc X.Y, gcc Z`). | Warning if host headers are included without stating libc version or `.i` |
| **Obtained behavior** | Under `### Actual behaviour`: quote verbatim output, exit code, and/or generated C excerpt with enough detail for another engineer to verify reproduction. Keep `Cause`, `Fix`, and workarounds under `### Additional information (optional)`. | Error if missing/empty; warning if `**Cause`/`**Fix` sits in `Actual behaviour` |
| **Expected behavior** | Under `### Expected behaviour`: state the expected result clearly (required by upstream for every non-crash report, included on all reports for `bug_report.md` parity). | Error if missing/empty |
| **Crashes, backtraces, and journals** | On any Frama-C OCaml crash (`Unexpected error`, `aborted: internal error`, `Please report as 'crash'`), capture and include the verbatim backtrace (`-debug 1` or `OCAMLRUNPARAM=b`; wrap long traces in `<details><summary>Full backtrace</summary>...</details>` rather than stripping them with `[...]`). When reproduction is stateful or multi-step (e.g., GUI or session sequence), also record a `-journal-enable` journal (`frama_c_journal.ml`), noting that neither a journal nor a backtrace replaces the input files. | Warning if a crash report omits or strips the OCaml backtrace |
| **Contextual information** | Under `### Contextual information`: include all five `bug_report.md` bullets (`Frama-C installation mode`, `Frama-C version` from `frama-c -version` plus `master` commit SHA, `Plug-in used`, `OS name`, `OS version`). | Error if any required bullet is missing |
| **Formatting & hygiene** | LF line endings, title <= 255 chars, balanced Markdown code fences, single HTML description marker, no relative repository links, no unresolved placeholders when filing, and an accurate LLM-assistance disclosure line when an LLM assisted. | Error on CRLF, long title, unclosed fence, marker error, repo links, or placeholders on `show`/`issue`/`mr` |

## 3. Package layout and canonical templates

A complete package `NN` under [`../../docs/upstream/frama-c/`](../../docs/upstream/frama-c/README.md) holds:

1. **Long analysis draft:** `docs/upstream/frama-c/frama-c-<slug>.md` (internal notes, full diagnosis, duplicate search, test runs, pipeline workaround).
2. **Standalone reproducer:** `docs/upstream/frama-c/repro/NN-<slug>.sh` (+ `NN-<slug>.c` / helper files; POSIX `sh`, LF endings, exits `1` before the fix and `0` after, header documents before/after outputs).
3. **Paste-ready issue text:** `docs/upstream/frama-c/filing/NN-<slug>-issue.md`:

````markdown
# [<Component>] Short, concrete summary of the defect

<!-- Everything below this line is the issue description. -->

### Summary

One concise paragraph explaining the defect and its user impact.

### Steps to reproduce the issue

`repro.c`:

```c
/* Minimal self-contained C reproducer; line numbers match Actual behaviour. */
```

```sh
frama-c -machdep gcc_x86_64 repro.c
```

### Expected behaviour

Concrete expected output / exit status.

### Actual behaviour

```text
Verbatim tool output (and exit status).
```

<details>
<summary>Full backtrace (include verbatim for crashes / internal errors)</summary>

```text
...
```

</details>

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at `<commit>`; also 34.0~beta (Selenium)
- Plug-in used: <plug-in or kernel (Frama-C libc)>
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc X.Y, gcc Z)

### Additional information (optional)

**Cause.** Source file, function, and line numbers on `<commit>`.

**Fix.** Proposed change (or design options for the maintainers). A merge request follows.

**Workaround.** If known.

The analysis and fix were prepared with LLM assistance (<tool>); I reviewed them and ran the reproducer and tests described above.
````

For `pub/meta`, omit `[<Component>]` from line 1 and change the marker to `<!-- Everything below this line is the issue description. Tracker: pub/meta (MetAcsl), not pub/frama-c. -->`.

4. **Optional patch and MR text (when `--patch`):**
   - `docs/upstream/frama-c/patches/NN-<slug>.patch`: exported via `git format-patch` from a commit on upstream `master` authored and committed with the GitLab noreply address, containing the fix, a regression test (and its oracles) that fails on unpatched `master` and passes with the patch, and zero file-mode changes (`mode change` / `create mode 100755`).
   - `docs/upstream/frama-c/filing/NN-<slug>-mr.md`: H1 title matching the single-commit subject, metadata lines (`- Source branch: ...`, `- Patch: [NN-<slug>.patch](../patches/NN-<slug>.patch)`), HTML marker, `external_contribution.md` checkboxes left unticked for the owner (omitted for `pub/meta`), `Closes #<issue>` (or `Related to #<issue>` for partial/doc-only fixes), summary of changes, and exact tests run / not run.
5. **Update indexes:** [`../../docs/upstream/frama-c/README.md`](../../docs/upstream/frama-c/README.md), [`../../docs/upstream/frama-c/filing/README.md`](../../docs/upstream/frama-c/filing/README.md), [`../../docs/upstream/frama-c/repro/README.md`](../../docs/upstream/frama-c/repro/README.md), [`../../docs/upstream/frama-c/patches/README.md`](../../docs/upstream/frama-c/patches/README.md), and [`../../docs/upstream/frama-c/frama-c-e-acsl-issues.md`](../../docs/upstream/frama-c/frama-c-e-acsl-issues.md).

## 4. Mandatory validation gates

Run all applicable checks before handing the package to the owner:

```powershell
$env:PYTHONIOENCODING="utf-8"
python tools/upstream_audit/file_upstream.py check NN
python tools/check_generated_text.py
python -m pytest tests/test_upstream_filing.py tests/test_docs_structure.py -n auto
```

When a patch is included for `pub/frama-c`, also run [`../../tools/upstream_audit/revalidate.sh`](../../tools/upstream_audit/revalidate.sh) inside the audit container (`before`, `package NN`, and `combined` when overlapping open MRs), verifying:

- `git am --keep-non-patch` applies cleanly with zero `mode change` or `create mode 100755`;
- the new test fails on unpatched `master` and passes with the patch;
- the default configuration of the touched test suites passes;
- `./dev/check-files.sh -p HEAD~N` passes;
- the standalone reproducer transitions from failing ("before") to passing ("after").

Resolve every `ERROR` from `file_upstream.py check`, and address every `WARN` (or document explicitly why a warning does not apply) before asking the owner to file.

## 5. Filing upstream (explicit owner go-ahead only)

1. Confirm filing is unpaused and the owner explicitly authorized which `NN` item(s) to post.
2. For `pub/frama-c` patches, build and bundle branches inside the audit container via [`../../tools/upstream_audit/make_branches.sh`](../../tools/upstream_audit/make_branches.sh) (never apply patches on a Windows checkout with `core.autocrlf=true`), then fetch the bundle and push explicit refspecs to the fork.
3. Dry-run with `python tools/upstream_audit/file_upstream.py show issue NN` (and `show mr NN` after the issue number is recorded).
4. File issues in dependency order with `python tools/upstream_audit/file_upstream.py issue NN`, run `python tools/upstream_audit/file_upstream.py subst` to replace `#<issue>` / `#ISSUE-NN` placeholders, then file MRs with `python tools/upstream_audit/file_upstream.py mr NN`. Never retry blindly on error: inspect the tracker first.
5. Verify read-back identity, GitLab Markdown rendering (no unintended `@mention`, no `~~` strikethrough, balanced fences, valid `#N`/`!N` links), commit/file counts, and leave CONTRIBUTING/CLA checkboxes for the owner to tick. Record the assigned numbers in [`../../docs/upstream/frama-c/README.md`](../../docs/upstream/frama-c/README.md) and [`../../tools/upstream_audit/ledger.json`](../../tools/upstream_audit/ledger.json).
