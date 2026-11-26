# Agent Instructions for Updating `docs/`

Read this file before creating, moving, or updating any document under [`./`](./README.md). These rules keep `docs/` consistent, navigable, and passing the repository's automated tests ([`../tests/test_docs_structure.py`](../tests/test_docs_structure.py) and [`../tools/check_generated_text.py`](../tools/check_generated_text.py)).

---

## 1. Directory Taxonomy & Root Invariant

**Never place loose Markdown files directly in `docs/` root.** The root of `docs/` holds only [`./README.md`](./README.md), [`./AGENTS.md`](./AGENTS.md), and the category directories below:

| Directory | What Belongs Here | Index / Specific Rules |
| :--- | :--- | :--- |
| [`./guides/`](./guides/README.md) | Canonical, living documentation of how the pipeline works **today** (architecture, phases, security layers, swarm, resources/caching, benchmarking). Update guides in the same change as behavior changes. | [`./guides/README.md`](./guides/README.md) |
| [`./troubleshooting/`](./troubleshooting/README.md) | Thematic `### Symptom:` / **Cause:** / **Fix:** entries for open pipeline bugs, Frama-C/E-ACSL quirks, and target onboarding workarounds that still apply. Entries with nothing left to act on move to `./troubleshooting/resolved.md`. | Read [`./troubleshooting/AGENTS.md`](./troubleshooting/AGENTS.md) before editing. |
| [`./plans/`](./plans/README.md) | Living [`./plans/backlog.md`](./plans/backlog.md) and **active** engineering/remediation plans. Completed historical plans move to `./plans/archive/`. | [`./plans/README.md`](./plans/README.md) |
| [`./runs/`](./runs/README.md) | Chronological run logs, benchmark validation reports, target verdict assessments, and pipeline-blocker postmortems. Named `YYYY-MM-DD-<target-or-topic>.md`. | [`./runs/README.md`](./runs/README.md) |
| [`./bugs-found/`](./bugs-found/README.md) | **Confirmed target vulnerabilities only** (defects in evaluated C targets that passed the Crash Verification Gate), organized as `./bugs-found/<target>/README.md`. Never put pipeline blockers here. | [`./bugs-found/README.md`](./bugs-found/README.md) (checked by `tests/test_benchmark.py`) |
| [`./upstream/`](./upstream/README.md) | Upstream Frama-C/E-ACSL bug drafts (`./upstream/frama-c/`), staged target disclosure bundles (`./upstream/<target>/`), and vendored Frama-C master reference examples (`./upstream/sources/`). | [`./upstream/README.md`](./upstream/README.md) |
| [`./references/`](./references/README.md) | Container-mounted Frama-C PDF manuals, generated greppable `.md` conversions, [`./references/INDEX.md`](./references/INDEX.md), and [`./references/e-acsl-quickref.md`](./references/e-acsl-quickref.md). **Never move this folder** (`Dockerfile` and wrappers mount `docs/references`). | [`./references/README.md`](./references/README.md) |

Local scratch folders `docs/papers/` and `docs/lessons/` are gitignored in [`../.gitignore`](../.gitignore); do not link to individual gitignored PDFs as required files.

---

## 2. Lifecycle Maintenance

1. **Behavior changes update `guides/` immediately:** When changing CLI flags, environment variables, schema fields, Make targets, or phase gates, update the corresponding guide in [`./guides/`](./guides/README.md) in the same commit. Note that [`../tests/test_remediation_p2_container.py`](../tests/test_remediation_p2_container.py) verifies that every forwarded `FRAMAC_*` host knob is documented in [`./guides/resources-and-caching.md`](./guides/resources-and-caching.md).
2. **Archiving finished plans:** Once every step of an active plan in `./plans/` is either landed or tracked in [`./plans/backlog.md`](./plans/backlog.md), move the plan to `./plans/archive/`, fix its relative link depth (`../` -> `../../`), and move its row in [`./plans/README.md`](./plans/README.md) to the Archive table.
3. **Updating folder indexes:** Every directory under `docs/` has a `README.md`. Whenever you add, rename, or move a file, update that folder's `README.md` in the same session.
4. **Recording pipeline defects:** Follow [`./troubleshooting/AGENTS.md`](./troubleshooting/AGENTS.md) to log every pipeline bug or workaround in `./troubleshooting/` during the session that discovers it.

---

## 3. Link, Formatting & Text Guardrails

- **Explicit relative links only:** Every Markdown link within `README.md` and `docs/**/*.md` referencing another repository file **must** start with `./` or `../` (for example, `[v2-design.md](./v2-design.md)` or `[ledger.py](../../scripts/ledger.py)`), never bare filenames (`(v2-design.md)`) or bare repo-root paths (`(scripts/ledger.py)`).
- **No emojis:** Never use emojis anywhere in documentation, tables, headings, or commit messages.
- **File-writing tools only (never shell heredocs):** Always write and edit files with direct file-writing/editing tools, never via Bash heredocs or PowerShell here-strings, which corrupt ACSL backslashes (`\result`, `\valid_read`, `\forall`, `\false`) and line endings.
- **LF line endings:** Keep all Markdown files LF-terminated (`\n`).
- **Generated manuals:** Never hand-edit generated `<tool>/<name>.md` files or `INDEX.md` inside `./references/`; regenerate them via `python scripts/extract_references.py`.
- **Skill mirror synchronization:** If a documentation change updates paths inside [`../skills/`](../skills/), run `python tools/sync_skill_mirrors.py` afterwards. `skills/` is the only place skills are edited; `.agents/skills/` and `.claude/skills/` are plain tracked copies, and the pre-commit hook and CI fail when they differ (`python tools/sync_skill_mirrors.py --check`).

---

## 4. Verification Before Finishing

Run these checks from the repository root after editing documentation:

```powershell
$env:PYTHONIOENCODING="utf-8"
python tools/check_generated_text.py
python -m pytest tests/test_docs_structure.py tests/test_extract_references.py -n auto
```
