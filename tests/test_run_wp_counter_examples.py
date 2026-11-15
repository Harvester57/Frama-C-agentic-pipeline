"""run_wp_function --counter-examples: the proof verdict never comes from a -wp-counter-examples run.

Frama-C 34 WP builds a weaker goal under -wp-counter-examples: on a struct whose pointer field the
function leaves alone, `ensures p->UB.ptr == \\old(p->UB.ptr)` is `Prove: true` normally but
`Prove: Mptr_0[a] = Mptr_1[a]` with no frame hypothesis in counter-example mode (QCBOR run-6,
UsefulOutBuf_Reset). The parent merge check passes --counter-examples, so it refused proven contracts.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import run_wp_function as W

_CE_CSV_HEAD = "directory\tfile\tfunction\tline\tkind\tstatus\tproperty\n"
_CE_FLAG = "-wp-counter-examples"


def _csv_rows(rows: list[tuple[str, str]]) -> str:
    return _CE_CSV_HEAD + "".join(f".\tf.c\tf\t3\tpostcondition\t{status}\t{prop}\n" for prop, status in rows)


def _fake_wp(proof_csv: str, proof_log: str, model_csv: str, model_log: str, calls: list[list[str]]):
    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(list(cmd))
        if "-wp" in cmd and "-report-csv" in cmd:
            csv_path = Path(cmd[cmd.index("-report-csv") + 1])
            model_mode = _CE_FLAG in cmd
            csv_path.write_text(model_csv if model_mode else proof_csv, encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout=model_log if model_mode else proof_log, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    return fake_run


def _c_file(tmp_path: Path) -> Path:
    c_file = tmp_path / "f.c"
    c_file.write_text("struct s { void *ptr; int n; };\nvoid f(struct s *p) { p->n = 0; }\n", encoding="utf-8")
    return c_file


@pytest.mark.unit
def test_counter_examples_never_turn_a_proved_goal_unknown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    proof_csv = _csv_rows([("keep_ptr", "Valid"), ("reset", "Valid")])
    proof_log = "[wp] 2 goals scheduled\n[wp] Proved goals:    2 / 2\n"
    model_csv = _csv_rows([("keep_ptr", "Unknown"), ("reset", "Valid")])
    model_log = (
        "[wp] 2 goals scheduled\n"
        "[wp] [Unknown] typed_f_ensures_keep_ptr (Qed 2ms) (CVC5) (Cached) (Model)\n"
        "[wp] Proved goals:    1 / 2\n"
    )
    monkeypatch.setattr(W.subprocess, "run", _fake_wp(proof_csv, proof_log, model_csv, model_log, calls))

    res = W.run_wp_on_function(
        _c_file(tmp_path), "f", tmp_path / "wp", counter_examples=True, cache_dir="off", sarif=True
    )

    assert res["status"] == "all_proven"
    assert res["counter_examples"] is True
    assert res["counter_example_goals"] == []
    # Nothing failed in the proof pass: no model pass is run at all.
    assert not any(_CE_FLAG in c for c in calls)


@pytest.mark.unit
def test_counter_example_goals_only_list_goals_the_proof_pass_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    out_dir = tmp_path / "wp"
    proof_csv = _csv_rows([("keep_ptr", "Valid"), ("keep_len", "Unknown")])
    proof_log = (
        "[wp] 2 goals scheduled\n"
        "[wp] [Timeout] typed_f_ensures_keep_len (Qed 1ms) (Alt-Ergo) (Cached)\n"
        "[wp] Proved goals:    1 / 2\n"
    )
    model_csv = _csv_rows([("keep_ptr", "Unknown"), ("keep_len", "Unknown")])
    model_log = (
        "[wp] 2 goals scheduled\n"
        "[wp] [Unknown] typed_f_ensures_keep_ptr (Qed 2ms) (CVC5) (Cached) (Model)\n"
        "[wp] [Unknown] typed_f_ensures_keep_len (Qed 1ms) (Z3) (Model)\n"
        "[wp] Proved goals:    0 / 2\n"
    )
    monkeypatch.setattr(W.subprocess, "run", _fake_wp(proof_csv, proof_log, model_csv, model_log, calls))

    shared_cache = tmp_path / "cache"
    res = W.run_wp_on_function(
        _c_file(tmp_path),
        "f",
        out_dir,
        counter_examples=True,
        cache_dir=shared_cache,
        retry_tail=False,
        retry_bitwise=False,
        retry_cast_probe=False,
    )

    assert res["status"] == "unproven_goals_remain"
    assert res["proven_count"] == 1 and res["unproven_count"] == 1
    assert [g["annotation"] for g in res["unproven_goals"]] == ["keep_len"]
    # The witness of a goal the proof pass proved comes from the weaker counter-example goal: dropped.
    assert res["counter_example_goals"] == [{"goal": "typed_f_ensures_keep_len", "prover": "Z3"}]
    # The model pass writes its own artifacts; the proof pass's report and log stay as they were.
    assert "(Model)" not in (out_dir / "wp_f.log").read_text(encoding="utf-8")
    assert "keep_len\n" in (out_dir / "wp_f.csv").read_text(encoding="utf-8")
    assert "Valid\tkeep_ptr" in (out_dir / "wp_f.csv").read_text(encoding="utf-8")
    wp_calls = [c for c in calls if "-wp" in c]
    assert [_CE_FLAG in c for c in wp_calls] == [False, True]
    proof_cmd, model_cmd = wp_calls
    # The proof pass keeps the shared prover cache; the weaker model-pass goals never reach any cache.
    assert proof_cmd[proof_cmd.index("-wp-cache-dir") + 1] == str(shared_cache)
    assert "-wp-cache-dir" not in model_cmd
    assert model_cmd[model_cmd.index("-wp-cache") + 1] == "none"


_FAILING_PROOF_CSV = _csv_rows([("keep_ptr", "Valid"), ("keep_len", "Unknown")])
_FAILING_PROOF_LOG = (
    "[wp] 2 goals scheduled\n"
    "[wp] [Timeout] typed_f_ensures_keep_len (Qed 1ms) (Alt-Ergo)\n"
    "[wp] Proved goals:    1 / 2\n"
)
_FAILING_MODEL_LOG = "[wp] [Unknown] typed_f_ensures_keep_len (Qed 1ms) (Z3) (Model)\n[wp] Proved goals:    1 / 2\n"


@pytest.mark.unit
def test_no_model_pass_when_the_prover_budget_is_exhausted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scratch = tmp_path / "agents" / "prove-f" / "scratch"
    work = scratch / "work"
    work.mkdir(parents=True)
    c_file = _c_file(work)
    (scratch / ".prover_budget.json").write_text(
        '{"max_wp_invocations": 2, "wp_invocations": 2, "first_wp_at": 1}', encoding="utf-8"
    )
    (scratch / "wp_f.json").write_text(
        '{"unproven_goals": [{"annotation": "keep_len", "kind": "postcondition"}], "unproven_count": 1}',
        encoding="utf-8",
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(
        W.subprocess,
        "run",
        _fake_wp(_FAILING_PROOF_CSV, _FAILING_PROOF_LOG, _FAILING_PROOF_CSV, _FAILING_MODEL_LOG, calls),
    )

    res = W.run_wp_on_function(c_file, "f", scratch / "wp", counter_examples=True, cache_dir="off")

    assert res["budget_exhausted"] is True and res["status"] == "unproven_goals_remain"
    # The verdict pass ran no WP; neither may the model pass (it ignores the budget by design).
    assert calls == []
    assert res["counter_example_goals"] == []
    assert res["counter_example_pass"]["status"] == "skipped"
    assert "budget" in res["counter_example_pass"]["reason"]


@pytest.mark.unit
def test_main_writes_the_verdict_before_the_model_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out_json = tmp_path / "wp_f.json"
    seen_during_model_pass: list[dict] = []
    calls: list[list[str]] = []
    inner = _fake_wp(_FAILING_PROOF_CSV, _FAILING_PROOF_LOG, _FAILING_PROOF_CSV, _FAILING_MODEL_LOG, calls)

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if _CE_FLAG in cmd:
            # A kill now must not lose the verdict: it is already on disk.
            seen_during_model_pass.append(json.loads(out_json.read_text(encoding="utf-8")))
        return inner(cmd, **kwargs)

    monkeypatch.setattr(W.subprocess, "run", fake_run)
    argv = [
        "--file",
        str(_c_file(tmp_path)),
        "--function",
        "f",
        "--out-dir",
        str(tmp_path / "wp"),
        "--out-json",
        str(out_json),
        "--cache-dir",
        "off",
        "--no-retry-bitwise",
        "--no-retry-tail",
        "--counter-examples",
    ]
    assert W.main(argv) == 0

    (early,) = seen_during_model_pass
    assert early["status"] == "unproven_goals_remain" and early["unproven_count"] == 1
    assert early["counter_examples"] is True and early["counter_example_pass"]["status"] == "pending"
    final = json.loads(out_json.read_text(encoding="utf-8"))
    assert final["status"] == "unproven_goals_remain"
    assert final["counter_example_goals"] == [{"goal": "typed_f_ensures_keep_len", "prover": "Z3"}]
    assert final["counter_example_pass"]["status"] == "unproven_goals_remain"
    assert [_CE_FLAG in c for c in calls if "-report-csv" in c] == [False, True]


@pytest.mark.unit
def test_model_goal_lines_parse_with_qed_time_and_cache_tags() -> None:
    log = (
        "[wp] [Unknown] typed_UsefulOutBuf_Reset_ensures_keep_UB_ptr (Qed 2ms) (CVC5) (Cached) (Model)\n"
        "[wp] [Unsuccess] typed_check_lemma_wrong (CVC4) (Model)\n"
        "[wp] [Valid] typed_ok (Alt-Ergo)\n"
        "[wp] [Timeout] typed_slow (Qed 1ms) (Alt-Ergo) (Cached)\n"
    )
    assert W.parse_model_goals(log) == [
        {"goal": "typed_UsefulOutBuf_Reset_ensures_keep_UB_ptr", "prover": "CVC5"},
        {"goal": "typed_check_lemma_wrong", "prover": "CVC4"},
    ]
    assert W.parse_failed_wp_goals(log) == {
        "typed_UsefulOutBuf_Reset_ensures_keep_UB_ptr",
        "typed_check_lemma_wrong",
        "typed_slow",
    }
