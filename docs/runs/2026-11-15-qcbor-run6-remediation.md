# QCBOR run-6 remediation (2026-11-15)

Fixes for the pipeline problems that the [`run-6` supervision report](./2026-11-14-qcbor-run6-supervision.md) and its review found. The details of every item are in the `### Symptom:` entries under [`../troubleshooting/`](../troubleshooting/README.md), each with a status bullet dated 2026-11-15.

## State

- Landed locally on `phase1-remediation` as merge commit `0b2e048` (`integ/run6-remediation`, tip `62c12cb`). Nothing is pushed.
- The run agent's uncommitted hot patches in the main checkout (12 files) were replaced by these fixes. They are kept on the branch `backup/run6-hotpatches`.
- The troubleshooting updates and this report are committed as `f9c5d12`, with the six troubleshooting files taken whole. Those files link to upstream drafts under `docs/upstream/frama-c/` that are still uncommitted in the main checkout.
- Work was done by nine agents in separate worktrees (six fixers, then skills, harness and guides), each reviewed and merged with `--no-ff`. The fixer worktrees and branches are deleted. The agents' commits carry a `Claude Opus 5.5` trailer; the merges and follow-ups a `Claude Fable 5.2` one.

## What was fixed

| Area | Change |
| :--- | :--- |
| Merge gate | A header function declared twice (prototype and `static inline` definition) takes its contract on either declaration; the trust-boundary check reads each. A `requires` that an agent adds with `\aligned(` is refused. `merge-agent --module` takes its build inputs from the sidecar and fails instead of merging without the guardrail. |
| WP runner | Only `Typed` and `Bytes` (with `nocast`, `raw`, `ref`, `int`, `float`) count as evidence. A `Typed` run held back by a union warning or byte-wise casts is retried once under `Bytes`. `--waive-signed-downcast` covers a narrowing on a declared wrap line. A run with the cache off passes `-wp-cache none`. No counter-example pass on an exhausted budget, and the verdict is written first. An unterminated annotation comment is an ACSL syntax error. Mutation checks replay the proof's model and checks. |
| Scheduler | A quarter of the dispatch slots (at least one) goes to ready breakers. `refresh` closes a repair only when the module's fuzz and Eva reports rest on the repaired harness. A caller of a callee without a visible contract waits on a negotiation that the scheduler files itself, or is dispatched last with a "Calls Without a Contract" brief section. |
| Ledger | A `Bytes` proof is recorded as an assumption. Opposite verdicts at one sink are recorded on both findings, the rejection is verified again once, and the reports list unresolved pairs. Keep-going rounds that stopped early leave evidence. `validate_artifacts.py run-dir` fails on libFuzzer files in the run-dir root. |
| Eva and facts | The frame skeleton projects `assigns \nothing` only when the function and everything it calls write nothing (facts schema 4). Eva reports carry `harness_digest`; the shard merge refuses shards of different harnesses. Large flows are spilled by every writer, and a missing side file fails the facts visibly. |
| Fuzzing and reach | Fuzz reports and crash files carry the harness identity. A crash credits an entry point only under the current harness and on direct evidence. The dispatch selector is the case index itself (at most 256 cases), so adding a case no longer remaps existing inputs. The keep-going skip falls back to a rebuild when the build has no runtime skip. Replays write libFuzzer's copies under their scratch directory. |
| Harness generation | `--record-repair` rolls the sidecar back on any failure. `--api` cases pass callback stubs and zero-terminate byte arrays. |
| Tooling | The text-checker hook follows `cd` and matches a worktree file against the allowlist by its own checkout path. `pipeline_make.py run` refuses targets after Phase 0 when the DAG has no module or no sidecar matches one. |
| Skills, briefs, guides | Updated to describe all of the above, including conduct rules for the orchestrating model (no hand merges, no pipeline edits during a run, backslash text through files). |

## Verification

- Full suite with the Docker-backed tests (`FRAMAC_DOCKER_TESTS=1`) at `f1e9ce3`, the last commit that changed code: 5386 passed, 53 skipped, 1 failed. The failure is `tests/test_docs_structure.py::test_markdown_links_are_explicit_relative_and_resolve`, on links to files that were untracked in the main checkout; it passes in the main checkout after the landing. `ruff check`, `mypy` (229 files), the text checker and the skill-mirror check are clean. Only guides changed after that commit, and the documentation tests were run again.
- In `framac-analysis:latest`, through the real writers:
  - `Bytes` chain: a prover run keeps the `Bytes` retry (4 goals unproven under `Typed`, 0 under `Bytes`), the parent replays `--wp-model Bytes`, and the ledger records the assumption. A `Hoare` run is never credited.
  - Harness chain on a 3-case module in a run-directory layout: only first bytes 0 to 2 reach a target; the fuzz and Eva reports carry the digest the gate computes; keep-going rounds crash in case 0, then 1, then run clean; crash credit goes to the two crashing entries and is withdrawn after a harness edit; Eva reaches all three cases; no stray file in the run-dir root.
- On run-6's own data (read-only): the crash-credit rules keep 32 credits, all on a stack frame or a direct failure with a stack; exactly the known pair of opposite verdicts is flagged; the frame skeleton keeps `\nothing` for 92 functions and makes 475 `partial`.

## Decisions taken without asking

- A `Bytes` proof counts as proven under an assumption, not unconditionally.
- A contract is accepted on both declarations of a header function; provers are told to write one.
- A `checked` rejection is verified again when a sibling at the same sink is `confirmed`. The run-6 pair would otherwise only have been flagged.
- Crash credit was tightened beyond the plan: no credit for a crash at an unknown location, nor for an E-ACSL failure under the entry's name without any stack frame.
- A report rebuilt from unstamped Eva runs that predate the harness carries `harness_digest: "unknown"`, so `refresh` treats it as stale.
- More than 256 dispatch cases is refused, not split automatically.
- The repository was not run through `ruff format`.

## Not verified, and open

- No full pipeline run of the landed tree. The scheduler changes were not run on a live schedule, and the keep-going fallback was not run on QCBOR's 182-case harness.
- The `Bytes` retry runs on each prover invocation that meets its trigger, and is not charged to the prover budget. On run-6's stored reports it would have fired on 34 of 163 unproven `Typed` runs (9 functions). The reports carry no timing, so no throughput gain is claimed.
- `refresh` with sub-module harness names was checked by reading only.
- Sharded Eva on an identity-selector harness was not run. Shards are cut by per-case guards, not by the selector, and no code outside the harness scripts decodes the selector.
- The harness agent's final report was lost when the session restarted. Its five commits were verified by the suite and the Docker chain instead; a pipeline bug it may have hit on the way is not recorded.
- Open pipeline bugs, recorded in troubleshooting: the API merge callers skip the guardrail when the sidecar has no sources; the indirect-call WP hint is always present; `wp_scheduler.py status` has side effects; `benchmark.py` reads Eva reports uncapped; an Eva report and its flows side file are two writes; the skip variable is parsed leniently; a zero-terminated array of wider scalars has no known sentinel.

## Before resuming run-6

1. Remove the merged `requires \aligned` contract of `UsefulOutBuf_Reset` and restore its dropped `keep_UB_ptr` postcondition. Until then every merge into that header is refused.
2. Decide whether to regenerate the harness. Regenerating gives the identity selector and the callback stubs, but an input whose first byte is at or above the case count (182) then selects no case. That holds for corpus inputs and for recorded crash files: 5 of run-6's 42 reproducible crash files (first bytes 239, 239, 250, 250, 255) would stop reproducing, and the findings that rest on them would need new reproducers. Keeping the current harness keeps the modulo selector, which is still decoded, and every recorded reproducer; it gives up the stable selector and the stubs for this run. There is no remapping tool. Either way, run `reach-gate`, then `module-libqcbor_a` (fuzz, Eva, facts): the Eva shards are from the 181-case harness. After a regeneration, harvest seeds again first.
3. Run `wp_scheduler.py refresh --module libqcbor_a`; it now refuses until step 2 is done.
4. Merge the two `merge_queued` proofs (`QCBORDecode_Private_MapTagNumber`, `QCBOR_Private_DecodeTagNumber`) through the scheduler.
