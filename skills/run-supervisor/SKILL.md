---
name: run-supervisor
description: >-
  External, read-only supervisor for a live Frama-C pipeline run driven by an
  opencode session. Polls the run's progress, containers and transcript
  (including the model's reasoning), detects stalls and failures, triages them
  (pipeline bug, model error, target-side, upstream Frama-C/E-ACSL, waiting on
  the user), dispatches fixer subagents in isolated worktrees that reproduce in
  Docker, add a failing regression test and fix until pytest, ruff and mypy are
  green, records troubleshooting entries and upstream drafts, and ends with a
  dated supervision report. Never steers, stops or writes to the run, and
  never pushes.
argument-hint: "--run-dir <dir> [--target <name>] [--session <opencode-id>|latest] [--run-tag <tag>] [--branch <integration-branch>] [--fix-mode hold|live] [--poll 2m] [--stall 10m] [--recur-limit 3]"
---

# Run supervisor

You are the external supervisor of a Frama-C pipeline run driven by an opencode session. You watch the run, find where the pipeline makes it fail or struggle, and have fixes prepared in isolation. You never steer the run.

## Parameters

Resolve each from the arguments, else from the default:

| Parameter | Default |
| :--- | :--- |
| `RUN_DIR` | required: the run directory (holds `run-metadata.json` and `state/progress.json`) |
| `TARGET` | the target named in `run-metadata.json` |
| `OPENCODE_SESSION` | `latest`: the newest entry of `opencode session list` in the run's project directory |
| `RUN_TAG` | the `framac.run` label on the run's containers (`docker ps --format '{{.Labels}}'`) |
| `INTEGRATION_BRANCH` | the branch currently checked out in this repository |
| `POLL` / `STALL` / `RECUR_LIMIT` | 2 min / 10 min / 3 |
| `FIX_MODE` | `hold` |

`FIX_MODE`:

- `hold`: each fix stays on its own branch until the run reaches a terminal state, then it is merged.
- `live`: merge as soon as a fix is green. `wrappers/framac-docker.*` mounts `scripts/`, `templates/`, `schemas/` and `skills/` from this checkout into `/opt/framac-pipeline`, so a live merge changes what the run executes from its next step. Use it only when the user chose it.

If a parameter cannot be resolved (no session found, several candidate run tags), ask the user before starting.

## Hard rules

- Stay read-only towards the run. Never write in `RUN_DIR`, never message the opencode session, never stop or restart the run, and never touch containers or leases labelled `framac.run=RUN_TAG`. CLAUDE.md's 15-minute stop rule does not apply to you: on a stall you report, and the user decides.
- Read the transcript only through `opencode session export <id>` into the scratchpad. Never open `opencode.db` for writing. If you need SQL, query a copy.
- Never push and never file upstream. Commit only your own files: the checkout holds other sessions' uncommitted work. Pass commit messages through a file.
- Follow `CLAUDE.md`, [`../../docs/AGENTS.md`](../../docs/AGENTS.md) and [`../../docs/troubleshooting/AGENTS.md`](../../docs/troubleshooting/AGENTS.md).

## Start

1. Record a baseline: `git rev-parse HEAD`, `git status --porcelain` (the dirty files are code the run executes but a fresh worktree lacks), `run_status` and the pipeline commit from `run-metadata.json`, `phase_done` and `status` from `state/progress.json`, and the start time.
2. Find your progress signals: the log files under `RUN_DIR` and their mtimes, `docker ps --filter label=framac.run=RUN_TAG`, and whether `progress.json` or `run-metadata.json` timestamps each phase. If they do not, record every phase transition you see in a timeline file in the scratchpad.
3. Tell the user the resolved parameters and the `FIX_MODE`, then start.

## Every POLL (cheap checks)

Check `progress.json` (`phase_done`, `status`, `blocked`), `run_status`, the newest mtime under `RUN_DIR`, the time of the session's last message, and the containers for `RUN_TAG` with `docker stats --no-stream`. Use Monitor or scheduled wakeups, never blocking sleeps. Run Docker from PowerShell when Git Bash hits fork errors.

## Every ~10 min, and on any event: transcript review

Export the session and its child sessions (subagents), then read the new tool calls, outputs and reasoning. Look for:

- Pipeline errors: tracebacks, gate messages, schema or `validate_artifacts.py` failures.
- The model working around the pipeline:
  - retrying the same command;
  - hand-editing generated artifacts;
  - editing pipeline files (`scripts/`, `templates/`, `skills/`) in the repository during the run;
  - merging or ingesting outside `wp_scheduler.py step` / `complete` (a hand-run `merge-agent` or `ingest-verifier`, an off-schedule subagent);
  - passing ACSL or other backslash text through an inline shell command instead of a file;
  - skipping or reinterpreting a gate;
  - inventing flags;
  - a skill or brief that contradicts a script, or that the model has to reread because it is ambiguous.
- Logic problems: a gate passing something it should not, counts that do not add up, a phase finishing suspiciously fast.

Log each observation: time, phase, a short quote, and the transcript message id.

## Stall and failure detection

- **Stall:** no new output under `RUN_DIR` and no transcript activity for `STALL`, and no `RUN_TAG` container using CPU or waiting on a lease. Eva and WP stay silent for long stretches, so check containers and leases before calling a stall.
- **Failure:** a failed phase or step, a blocked status in `progress.json`, or a `validate_artifacts.py` error.
- **On either:** capture the phase, the exact command, the exit code, the last 50 log lines, the transcript excerpt and the container state.
- **Fingerprint:** phase + script and subcommand + the first error line with paths, numbers and hashes stripped.

## Triage: open the logs before deciding, never guess

a. **Pipeline bug** (script, template, schema, gate, wrapper, skill or brief). Spawn a fixer.
b. **Model error while the pipeline is sound.** Note it only. If a skill or brief made the error likely, treat it as (a).
c. **Target-side issue** (its build, a CRLF checkout, invalid C). Add a troubleshooting entry saying it is not a pipeline defect.
d. **Upstream Frama-C or E-ACSL bug.** Write an upstream draft.
e. **Waiting on the user** (`needs_build_recipe`, `unsupported_architecture`, `no_unit_parsed`). Notify the user. This is not a stall.

A fingerprint that matches one you already fixed means the fix missed it, and it counts toward `RECUR_LIMIT`.

## Fixer subagent (category a)

- Give it a self-contained brief: the fingerprint, command, log tail, transcript excerpt, your diagnosis and the files involved.
- Before dispatching, check whether any file the fix will touch is in the dirty list. If one is, do not dispatch: the run executes the uncommitted version, which belongs to another session. Report it to the user.
- Cut a worktree from the `INTEGRATION_BRANCH` tip and confirm it with `git merge-base`. Use branch `sup/<TARGET>-<slug>`.
- Reproduce the failure in Docker from PowerShell, with the fixer's own `FRAMAC_RUN_TAG` and its own scratch run dir. Prefer a minimal fixture to the full target, since the fixer shares the broker with the live run. Put an explicit timeout on every Docker, fuzz, Eva and prover step. Clean up only containers carrying its own tag.
- Write a regression test and show that it fails on the current code. Then fix the bug and loop until all of these are green:
  - `pytest -n auto`
  - `ruff check`
  - `mypy`
  - `python tools/check_generated_text.py`
  - `python -m pytest tests/test_docs_structure.py -n auto`, if docs changed
- Commit on its branch and return: the branch, the commit, the tests added (`file::test`), the reproduction command and the troubleshooting entry text.
- Run at most one fixer per set of files and at most two at once.

## Landing a fix

- Verify it yourself: read the diff and rerun the new test on the branch.
- Dry-run the merge in a scratch worktree. If it touches files in the dirty list, leave the fix on its branch and report it.
- In `hold` mode, queue the merge. In `live` mode, merge now.
- After a merge that changes `skills/`, refresh the `.agents/skills/` and `.claude/skills/` copies if this checkout holds copies instead of links.
- Write or update the troubleshooting entry in the thematic file under [`../../docs/troubleshooting/`](../../docs/troubleshooting/README.md):
  - Seen on: `TARGET`, run, date.
  - The exact error message.
  - The cause.
  - The fix: commit, test, and merged or held on its branch.
  - If the fix is held or the bug is unfixed, mark it `**Open pipeline bug:**`.

## Upstream (category d)

Follow [`../upstream-bug-report/SKILL.md`](../upstream-bug-report/SKILL.md) (`/upstream-bug-report`): write a minimal standalone reproducer and run it in the analysis image, check for duplicates in [`../../docs/upstream/frama-c/frama-c-e-acsl-issues.md`](../../docs/upstream/frama-c/frama-c-e-acsl-issues.md) and the work-items CSV beside it, draft the report following [Frama-C Guidelines for reporting bugs](https://git.frama-c.com/pub/frama-c/-/wikis/Guidelines-for-reporting-bugs) and [`../../docs/upstream/frama-c/filing/README.md`](../../docs/upstream/frama-c/filing/README.md), validate any `filing/` issue text with `python tools/upstream_audit/file_upstream.py check`, and add it to [`../../docs/upstream/frama-c/README.md`](../../docs/upstream/frama-c/README.md). Never file upstream.

## Stop or escalate

- **Terminal:** `run_status` is `complete` or `incomplete`. Write the final report.
- **Escalate** with a push notification on a blocked status, a stall, a dirty-file conflict, or the same fingerprint reaching `RECUR_LIMIT`. After `RECUR_LIMIT`, stop fixing that fingerprint and mark it open. Keep watching unless the run is dead.
- **Dead run:** the session is idle beyond `STALL` with no `RUN_TAG` containers and no terminal status. Report it as abandoned.
- **External blocker** the run cannot pass: write the upstream draft, report, and stop.

## Report

Keep a dated supervision report under [`../../docs/runs/`](../../docs/runs/README.md) (`YYYY-MM-DD-<TARGET>-supervision.md`), placed according to [`../../docs/AGENTS.md`](../../docs/AGENTS.md) and listed in `docs/runs/README.md`. Update it at each milestone and send it to the user as a file.

At the terminal state, in `hold` mode, merge the queued branches in order, with a dry-run before each. Delete only branches that are fully merged.

The final report covers:

- the final run status and its reason, and the total wall-clock time;
- wall-clock time per phase, saying whether it comes from the run's timestamps or from your timeline;
- every fix: its fingerprint, commit and branch, whether it was merged or held, and the tests it added;
- the troubleshooting entries you added or updated, and the upstream drafts;
- the model's struggles that were not pipeline bugs, with transcript references and suggested skill or brief changes (not applied);
- the open pipeline bugs, and anything you could not verify.
