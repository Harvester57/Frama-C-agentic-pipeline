This codebase is yours: what it's for and how it's built are your call, and you'll keep building on it.

## Windows shell & file-writing rules
- Never write code, tests, or docs containing backslashes (ACSL `\valid_read`, `\result`, regex, `\n`) through shell heredocs. Use the Write/Edit tools instead.
- Write files with LF line endings. In Python scripts, open files with `newline='\n'`.
- Pass git commit messages through a file (`git commit -F msg.txt`), not through a PowerShell pipe.
- If Git Bash hits fork errors under load, switch to PowerShell instead of retrying.

## Generated-text guardrails
- Write and change files with the Write/Edit tools only. A PreToolUse hook (`tools/block_heredoc_writes.py`) blocks Bash/PowerShell commands that write a file through a heredoc or here-string.
- Run Docker from PowerShell on Windows when Git Bash hits fork errors.
- Pass commit messages via a file: Write `msg.txt`, then `git commit -F msg.txt`.
- A PostToolUse hook runs `tools/check_generated_text.py` on the files each Write/Edit/Bash/PowerShell call touched and reports control characters, CRLF in `.sh`/`.py`, literal `\n` in `.sh`, mangled ACSL (`\result`, `\valid_read`, `\old` corrupted or missing their backslash) and test constants redefined from an imported module. Fix the hit; if it is intended, add it to `tools/check_generated_text.allow` with a justification. Run `python tools/check_generated_text.py` for the whole repo.

## Worktrees & parallel agents
- Cut agent worktrees from the current integration branch (e.g. phase1-remediation), never from an old main commit. Confirm with `git merge-base` before dispatching.
- When a live pipeline run is in progress, make code changes in an isolated worktree. Don't touch the run's working tree or containers.
- Before merging, dry-run in a scratch worktree. After merging, delete only branches that are fully merged.
- Commit only your own changes. Other sessions may have uncommitted work in the same tree.

## Long-running pipeline runs (Frama-C / fuzz / Eva / Docker)
- Set an explicit timeout on every fuzz, Eva or prover step. While a background run is going, check its progress every ~10 minutes and report stalls without waiting to be asked.
- If a run makes no progress for more than 15 minutes, stop it, explain why, and clean up any containers it started (`docker ps --filter label=...`).
- Before blaming a slow phase, check what is actually running (leases, locks, container state).
- Record every pipeline bug you hit in the troubleshooting docs.

## Testing
- Run the Python suite in parallel: `pytest -n auto`. Then run `ruff check` and `mypy` before committing.
- New test modules must not redefine shared module-level constants (e.g. TREE). Check for name collisions first.
- Known flaky tests: the concurrency/run-lock tests. Rerun once before investigating.

## Recording pipeline bugs in `docs/troubleshooting/`

Whenever you hit a bug, gap or workaround in the pipeline itself while running or developing it (a script, a generator, a gate, the wrapper, a skill or brief that is wrong or incomplete), write it into the thematic sub-documents under [`./docs/troubleshooting/`](./docs/troubleshooting/README.md) **in the same session**, so the maintainers can inspect and correct it later. Read [`./docs/troubleshooting/AGENTS.md`](./docs/troubleshooting/AGENTS.md) for how to update the folder. This applies to every agent: the parent, forks, subagents and anyone working a target run. Do not leave it only in chat or in a progress report.

- **Where:** the thematic sub-document matching the component or phase (see the routing table in [`./docs/troubleshooting/AGENTS.md`](./docs/troubleshooting/AGENTS.md)), as a `### Symptom: ...` entry with **Cause:** and **Fix:** bullets, in the format of the neighbouring entries. Update an existing entry instead of adding a duplicate.
- **What to include:** the exact error text or gate message, the target and run that showed it, the root cause once you have diagnosed it (open the logs first; do not guess), and the workaround you used.
- **Status:** say whether the pipeline bug is **fixed** (name the file and the change; mention it is uncommitted if it is) or **open** (mark it `**Open pipeline bug:**` so it is easy to find). A target-side issue (for example a CRLF checkout) is a troubleshooting entry too, but say it is not a pipeline defect.
- **Do not silently work around it:** if you change pipeline code to get past it, say so in the entry and in your report to the user. If you only worked around it in the run directory, the entry must say the pipeline still has the defect.
- Subagents that cannot edit shared documents (a scratch overlay) put the entry in their result instead, and the parent adds it before the run ends.