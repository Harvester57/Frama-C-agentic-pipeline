# Branch Integration, Night of 2026-11-19

Goal set by the owner: merge the recent branches cleanly on `phase1-remediation`, then on `main` if that is clean. The work was done on `integ/merge-2026-11-19` in the worktree `.claude/worktrees/merge-all`.

## Status

**Landed locally on `phase1-remediation` and `main`, by fast-forward. Nothing is pushed.** The owner asked for a merge, not a push.

## Merged

| Source | Commit | Notes |
| --- | --- | --- |
| `integ/vb-wave1` | base of the integration branch | |
| `integ/brief-gaps` | `dfbcd23` | |
| `metacsl-integ` | `da63ab1` | Main conflict: L5 wrapper placement. An explicit `checked_at` takes precedence over inferred forwarding. |
| `feat/threat-model-skill` | `549a67a` | Clean merge. |
| Merge repairs | `23e74e6` | Places where the merged branches disagreed. |
| `fix/sanitizer-fixtures` | `ed851d1` | Three failure fixture programs, wrong since the test was added. |
| `fix/wrapper-in-image` | `8dca9c2` | An image test still stated the placement from before the merge. |
| `fix/mypy-tests` | `18cf81d` | 101 type errors in tests. Four more fixed in `af167b0`. No assertion weakened, no suppression added. |

## Test results

| Commit | Check | Result |
| --- | --- | --- |
| `23e74e6` | Full suite with `FRAMAC_DOCKER_TESTS=1` | 7503 passed, 5 failed, 64 skipped |
| `18cf81d` | Full suite with `FRAMAC_DOCKER_TESTS=1` | **7509 passed, 0 failed, 65 skipped** |
| `18cf81d` | `python -m mypy scripts tests` | No issues in 323 files (105 errors before) |
| `18cf81d` | `ruff check`, skill mirror check, `tools/check_generated_text.py` | Pass |

The skipped tests need tools this Windows host lacks outside the image (GNU make, gcc, clang, symlinks). No real target was run through the pipeline.

## Pipeline bugs and limits found

- **Fixed after this integration, on the owner's request:** a failure inside a libc call got the fingerprint `unknown#<call>::<alarm>::<hash>`, so different sites collapsed into one candidate. See [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md).
- **Limit:** a forwarding wrapper without a `calls` annotation gets no L5 goal from WP. The run is flagged unsound and earns no credit, but a real violation is not reported as an L5 failure either. See [`../troubleshooting/security-properties.md`](../troubleshooting/security-properties.md).

## Decision taken for the owner: the main checkout changed branch

The main checkout held 80 modified and 25 untracked files from earlier sessions, all idle since 01:27. Git cannot move a checked-out branch under such a tree, and replaying the work would have meant resolving conflicts in it unattended. So the main checkout was switched to a new branch, `wip/main-checkout-2026-11-19`, at the old commit `5cbf8c2`. **No file there was changed, committed or stashed.**

To bring that work onto the merged code, review it, commit it on that branch, then merge:

```bash
git switch phase1-remediation
```

```bash
git merge wip/main-checkout-2026-11-19
```

A trial replay on the merged code merged 76 files cleanly and left conflicts in 4 documents: `README.md`, `docs/troubleshooting/eacsl-and-fuzzing.md`, `docs/troubleshooting/eva.md` and `docs/troubleshooting/security-properties.md`.

After that merge, revert `c74ae27` and run `python tools/sync_skill_mirrors.py`. That commit held back three edits only because of this uncommitted work. The two links removed in `8e87f95` can also come back once their target files are committed.

## Not merged

These need the owner's decision:

- `feat/caller-sufficient-contracts`: conflicts in `scripts/generate_report.py` and `scripts/workspace_overlay.py`.
- `trial/fuzz-gap-inputs` and `trial/rocq-step0`: trial branches with documentation conflicts.
- `phase1-s1` and `backup/run6-hotpatches`: look superseded or are backups.
