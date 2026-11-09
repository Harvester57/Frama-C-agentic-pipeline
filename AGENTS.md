# Agent instructions

## Running the tests

Always run the Python tests in parallel with pytest-xdist, from the repository root:

```powershell
# Windows (PowerShell)
$env:PYTHONIOENCODING="utf-8"
python -m pytest tests -n auto
```

```bash
# Linux / macOS
python3 -m pytest tests -n auto
```

- Add `-n auto` to every run of more than a single test, including runs filtered by file, `-k` or `-m`.
- Use `-n 0` only to debug one failing test, or to check whether a failure appears only in parallel.
- With `FRAMAC_DOCKER_TESTS=1`, cap the workers (`-n 4`): each worker starts its own containers.
- Tests write only under `tmp_path`, never into the repository, so they stay safe to run in parallel.

See `tests/README.md` for the other variants and `skills/python-testing/SKILL.md` for test conventions.

## Recording pipeline bugs in `docs/troubleshooting.md`

Whenever you hit a bug, gap or workaround in the pipeline itself while running or developing it (a script, a generator, a gate, the wrapper, a skill or brief that is wrong or incomplete), write it into `docs/troubleshooting.md` **in the same session**, so the maintainers can inspect and correct it later. This applies to every agent: the parent, forks, subagents and anyone working a target run. Do not leave it only in chat or in a progress report.

- **Where:** the section for the phase it appeared in (Phase 0 is Section 1), as a `### Symptom: ...` entry with **Cause:** and **Fix:** bullets, in the format of the neighbouring entries. Update an existing entry instead of adding a duplicate.
- **What to include:** the exact error text or gate message, the target and run that showed it, the root cause once you have diagnosed it (open the logs first; do not guess), and the workaround you used.
- **Status:** say whether the pipeline bug is **fixed** (name the file and the change; mention it is uncommitted if it is) or **open** (mark it `**Open pipeline bug:**` so it is easy to find). A target-side issue (for example a CRLF checkout) is a troubleshooting entry too, but say it is not a pipeline defect.
- **Do not silently work around it:** if you change pipeline code to get past it, say so in the entry and in your report to the user. If you only worked around it in the run directory, the entry must say the pipeline still has the defect.
- Subagents that cannot edit shared documents (a scratch overlay) put the entry in their result instead, and the parent adds it before the run ends.
