# Tier 5: Trivial-Annotation-Aware Candidate Rank

Self-contained implementation plan. Parent document: [`../formal-discovery-plan.md`](../formal-discovery-plan.md) (Section 3, Tier 5). Independent of every other tier (Tier 1 edits a different function of the same module; the two merge cleanly).

## Goal

The per-prover candidate tracker ranks iterations by `(failed, invalid, -proved)` and treats a rise in `proved` as progress. Every added `assert` or `loop invariant` creates goals, so a tautological clause (`\true`, `x == x`, `0 <= 1`) raises `proved`, wins ties and counts as progress. Make the rank and the progress test blind to clauses that hold whatever the code does, using the syntactic detector that already exists (`acsl_ast.is_trivial_predicate`). Byte counts are deliberately **not** used (see the parent document: the paper's shortening rule only applies alongside a strict cost reduction).

New A/B switch: `FRAMAC_CANDIDATE_RANK` (`legacy` restores the current rank; default `trivial_aware`).

Expected effect is modest: a prover stops at its first `all_proven` candidate, so the rank mostly decides among partial candidates and which one `restore_best` brings back. The detector is syntactic, like `trivial_layer_clauses` in the WP report; semantic tautologies still earn credit.

## Facts the implementer must know (verified 2026-11-09)

- `scripts/prover_candidates.py`:
  - `note_oracle(out_json, oracle, report, digest_before)` runs after each oracle on the prover's tracked files; it has `scratch`, `budget` (`.prover_budget.json`: `file`, optional `header`, `function`) and `contents: dict[rel, bytes | None]` (the tracked files' current bytes from `scratch/work/`). `agents/<id>/scratch/base/<rel>` is the pristine snapshot.
  - `_oracle_summary("wp", report)` → `{"status", "failed", "proved" (= proven + proven_under_hyp), "soundness_ok", "invalid"}`; `invalid` counts unproven goals whose `annotation` ends in `_established` or `_preserved`.
  - `_evaluate` builds `rank = {"failed", "proved", "invalid"}`, compares with `_rank_key(rank) = (failed, invalid, -proved)`, and sets `progress = ranks_higher or highest is None or rank["proved"] > highest` with `highest = _highest_proved(state)` (max `proved` over eligible, unrefuted history entries). `all_proven` → `next_action: "finished"`, else `"continue"` if progress else `"restore_best_and_finish"` (`NO_PROGRESS_FOCUS`).
  - `state.json` (`SCHEMA_VERSION = 1`): `candidates[digest] = {"id", "wp", "guardrail", "refuted"}`, `best_rank`, `history[]` entries with `failed`, `proved`.
- `scripts/acsl_ast.py`:
  - `tokenize_c_acsl(source, path)` → tokens with `kind` in `c_token`, `acsl_block`, `acsl_line`, `whitespace`, `pp_directive`, ..., `text`, `line`.
  - `_parse_acsl_inner_segments(inner, base_line) -> list[_AcslSegment]` with fields `kind` (contract keyword such as `ensures`, `assert`, `loop invariant`? — check how multi-word kinds are stored; `_CONTRACT_KWS` lists the recognised keywords), `name`, `raw_text`, `line`.
  - `is_trivial_predicate(text) -> bool`: `\true`, nonzero literal, `x == x`, literal relations, connectives of those; conservative (`False` for predicate calls and quantifiers).
  - `find_named_clause` exists; `run_wp_function.py` uses `is_trivial_predicate` for `trivial_layer_clauses`.
- The prover reads the `candidate` block printed by each oracle (`skills/framac-wp/prover_brief.md`, around line 244) and acts on `next_action` / `next_synthesis_focus`.

## Changes

### 1. Count trivial added clauses (`scripts/prover_candidates.py`)

- New `_added_acsl_texts(base: bytes | None, work: bytes | None) -> list[tuple[str, int]]`: tokenize both; return `(text, line)` of `acsl_block` / `acsl_line` tokens in `work` whose text is not among the base's ACSL token texts (the same baseline idea `verify_acsl_only` uses). Fail-open on tokenizer errors → `[]`.
- New `trivial_added_clauses(scratch: Path, budget: dict, contents: dict[str, bytes | None]) -> list[dict]`: for each tracked rel, read `scratch/base/<rel>`, take the added ACSL texts from `contents[rel]`, parse each with `_parse_acsl_inner_segments`, and for segments whose kind is one of `ensures`, `assert`, `loop invariant`, `check`, `invariant` (statement form is already rejected elsewhere, keep it for completeness) extract the predicate: `raw_text` after the keyword and an optional `name:` label, up to the final `;`. Return `[{"file": rel, "line", "kind", "predicate"}]` for predicates where `is_trivial_predicate` is true. `requires` is excluded (a trivial precondition does not inflate `proved` in a harmful way and dropping it changes nothing).
- In `note_oracle`, when `oracle == "wp"`, compute `trivial = trivial_added_clauses(...)` and set `cand["wp"]["trivial_added"] = len(trivial)` and `cand["wp"]["trivial_clauses"] = trivial[:20]`. Add `"trivial_added": len(trivial)` to the returned block and to the history entry.

### 2. Rank and progress

- `_mode() -> str`: `os.environ.get("FRAMAC_CANDIDATE_RANK", "trivial_aware").lower()`; anything other than `legacy` means trivial-aware.
- `_effective_proved(wp: dict) -> int`: `max(0, wp["proved"] - wp.get("trivial_added", 0))` in trivial-aware mode (one goal per trivial clause is an under-estimate for a `loop invariant`, which yields two; say so in a comment and accept it), else `wp["proved"]`.
- `_rank_key(rank)`: trivial-aware → `(failed, invalid, trivial_added, -effective_proved)`; legacy → unchanged `(failed, invalid, -proved)`. `rank` dicts gain `trivial_added` and `effective_proved`; `_rank_key` reads them with `.get(..., 0)` so `best_rank` values written by older code still compare (treat a missing `effective_proved` as `proved`).
- `_highest_proved(state)` compares `effective_proved` when present in the history entry, else `proved`; `_evaluate` uses `_effective_proved(wp) > highest` for the progress test. A candidate whose only change is adding trivial clauses therefore gets `progress = False` and `restore_best_and_finish`.
- Add `"next_synthesis_focus": "drop_trivial_clauses"` to the block when `trivial_added > 0` and the candidate is not `all_proven`, so the prover is told what to change.

### 3. Brief text (`skills/framac-wp/prover_brief.md`)

In the `candidate` block description (around line 244): "`trivial_added` counts clauses you added that hold whatever the code does (`\true`, `x == x`, literal comparisons); they earn no credit in the rank and `drop_trivial_clauses` asks you to remove them."

### 4. Flag plumbing

`FRAMAC_CANDIDATE_RANK` goes into `wrappers/framac-docker.ps1` (allowlist near line 624), `wrappers/framac-docker.sh` (near line 385), `docker-compose.yml` (near line 69), `tests/test_remediation_p2_container.py` (`AB_SWITCHES`; the `env.update` at line 152 sets it to `legacy`), and the knob list in `docs/resources-and-caching.md` Section 4.

### 5. Docs

- `docs/backlog.md`: the SESpec rank item mentions `(failed, invalid, -proved)`; add the trivial-aware extension and the flag.
- `docs/v2-design.md`: one sentence where the candidate tracker is described.

## Tests (`-n auto`)

- `tests/test_prover_candidates.py`:
  - `trivial_added_clauses`: base without annotations, work adding `//@ assert 1 <= 2;`, `/*@ loop invariant \true; */` and `//@ assert 0 <= i;` → two trivial items (kinds `assert`, `loop invariant`), the real one excluded; an added `requires \true;` is not counted; unchanged ACSL is not counted even if trivial.
  - Rank: two eligible candidates with equal `(failed, invalid)`, A with `proved=10, trivial_added=0`, B with `proved=12, trivial_added=3` → A ranks higher in trivial-aware mode, B in `legacy` (monkeypatch env).
  - Progress: after a best with `proved=10`, a candidate with `proved=12, trivial_added=2` and the same `failed` yields `progress=False`, `next_action="restore_best_and_finish"`, `next_synthesis_focus="drop_trivial_clauses"`; the same candidate with `trivial_added=0` yields `progress=True`.
  - Backward compatibility: a `state.json` whose `best_rank` lacks `trivial_added` / `effective_proved` loads and compares without error.
- `tests/test_remediation_p2_container.py`: the new switch is forwarded.

## Verification

```powershell
$env:PYTHONIOENCODING="utf-8"
python -m pytest tests/test_prover_candidates.py tests/test_remediation_p2_container.py -n auto
python -m pytest tests -n auto
python -m ruff check scripts tests
python -m mypy scripts tests
```

Acceptance: a benchmark run with the default mode versus one with `FRAMAC_CANDIDATE_RANK=legacy` shows no `regression` in `benchmark.py compare`; the per-run count of `trivial_added > 0` history entries (sum over `agents/*/scratch/candidates/state.json`) is reported in the comparison notes.

## Out of scope

Byte- or token-count parsimony; semantic tautology detection (would need a solver call per clause); changing when a prover finishes.
## Implementation notes (2026-11-09)

Facts above that turned out different in the code, and choices made while implementing:

- `_parse_acsl_inner_segments` stores only the **first word** of a clause as `kind`: `loop invariant` arrives as `kind == "loop"` (so does `loop assigns`), and `assert` / `check` arrive as themselves although they are not in `_CONTRACT_KWS`. `trivial_added_clauses` therefore matches the clause head on the segment text (`loop invariant`, `ensures`, `assert`, `check`, `invariant`, optional `name:` labels) instead of trusting `kind`.
- Continuation-line `@` characters are dropped before matching, as `find_named_clause` does. A leading `*` bullet is kept: a clause written across bullet lines then reads as non-trivial, which errs on the conservative side.
- `trivial_added` and `trivial_clauses` are recorded in both modes (so an A/B comparison can count them); only the rank, the progress test and the `drop_trivial_clauses` focus depend on `FRAMAC_CANDIDATE_RANK`. In `legacy` mode no `next_synthesis_focus` is added to the `candidate` block.
- `state.json` keeps `SCHEMA_VERSION = 1`: the new fields are additive. `best_rank` and history entries written before this change lack `trivial_added` / `effective_proved`; `_rank_key` and `_highest_proved` read them as 0 trivial clauses and `effective_proved = proved`.
- The `candidate` block gains a `trivial_added` key (None until a WP report exists for the candidate). The oracle summary's own `next_synthesis_focus` is unchanged; `drop_trivial_clauses` appears only inside the `candidate` block.
- Benchmark acceptance (default vs `legacy`) was not run as part of the implementation.
