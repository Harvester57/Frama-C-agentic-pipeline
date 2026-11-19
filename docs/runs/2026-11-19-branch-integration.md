# Branch Integration, Night of 2026-11-19

Goal set by the owner: merge the recent branches cleanly on `phase1-remediation`, then on `main` if that is clean. Work happens on `integ/merge-2026-11-19` in the worktree `.claude/worktrees/merge-all`.

## Status

**In progress.** Nothing has landed on `phase1-remediation` or `main` yet. Nothing is pushed.

## Merged on the integration branch

| Source | Commit | Notes |
| --- | --- | --- |
| `integ/vb-wave1` | base of the integration branch | |
| `integ/brief-gaps` | `dfbcd23` | |
| `metacsl-integ` | `da63ab1` | Main conflict: L5 wrapper placement. An explicit `checked_at` takes precedence over inferred forwarding. |
| `feat/threat-model-skill` | `549a67a` | Clean merge. |
| Merge repairs | `23e74e6` | Places where the merged branches disagreed. |
| `fix/sanitizer-fixtures` | `ed851d1` | Three failure fixture programs, wrong since the test was added. |

## Test results

| Commit | Suite | Result |
| --- | --- | --- |
| `23e74e6` | Full suite with `FRAMAC_DOCKER_TESTS=1` | 7503 passed, 5 failed, 64 skipped |

The five failures:

- Three in `tests/test_failure_fixtures_docker.py`: fixed by `3579d8e`. They failed on every branch before the merge.
- `test_markdown_links_are_explicit_relative_and_resolve`: fixed by `8e87f95`. It failed before the merge.
- `test_the_callers_goal_is_false_before_and_gone_after_in_the_image` in `tests/test_security_props_wrapper.py`: being diagnosed.

`python -m mypy scripts tests`, which CI runs, reports 105 errors in tests that came in with the merged branches. A fix is in progress.

## Pipeline bugs found

- **Open:** every double free or bad free gets the fingerprint `unknown#free::freeable::<hash>`, so different sites collapse into one candidate. See [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md).

## Not merged

These need the owner's decision:

- `feat/caller-sufficient-contracts`: conflicts in `scripts/generate_report.py` and `scripts/workspace_overlay.py`.
- `trial/fuzz-gap-inputs` and `trial/rocq-step0`: trial branches with documentation conflicts.
- `phase1-s1` and `backup/run6-hotpatches`: look superseded or are backups.

## Uncommitted work in the main checkout

The main checkout holds 80 modified and 25 untracked files from earlier sessions. This integration does not commit, stash or edit them.
