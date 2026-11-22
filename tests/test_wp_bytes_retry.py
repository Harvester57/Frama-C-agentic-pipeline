"""run_wp_function: the WP memory model allowlist and the automatic `Bytes` retry.

QCBOR run-6: byte-wise `memcpy` type puns (`CopyUint64ToDouble`) stalled under `Typed` with four
`precondition of memcpy` goals and `Cast with incompatible pointers types` warnings, and union-writing
decoders were refused as `unsound_proof` (`[wp:unsupported:union] ... might be unsound`). Both proved
under `--wp-model Bytes`, which provers found only after hours. A local, non-aliased union still warns
`... with Hoare model might be unsound` under `Bytes` (checked in framac-analysis:latest).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import run_wp_function as W
from framac_common import WP_UNSOUND_MODEL_ISSUE, wp_model_problem

_BR_CSV_HEAD = "directory\tfile\tfunction\tline\tkind\tstatus\tproperty\n"
_CAST_WARNINGS = (
    "[wp] f.c:8: Warning: \n  Cast with incompatible pointers types (source: float64*) (target: sint8*)\n"
    "[wp] f.c:8: Warning: \n  Cast with incompatible pointers types (source: uint64*) (target: sint8*)\n"
)
_MEMCPY_UNKNOWN = [
    ("assigns clause", "Unknown", "assigns \\nothing;"),
    (
        "precondition of memcpy",
        "Unknown",
        "separation: \\separated((char *)dest + (0 .. n - 1), (char *)src + (0 .. n - 1))",
    ),
    ("precondition of memcpy", "Unknown", "valid_dest: valid_or_empty(dest, n)"),
    ("precondition of memcpy", "Unknown", "valid_src: valid_read_or_empty(src, n)"),
]
_ALL_VALID = [("postcondition", "Valid", "ok"), ("rte: mem_access", "Valid", "\\valid(p)")]


def _union_warning(model: str) -> str:
    return (
        f"[wp:unsupported:union] f.c:19: Warning: \n  Accessing union fields with {model} model might be unsound.\n"
        "  Please refer to WP manual.\n"
    )


def _rows(rows: list[tuple[str, str, str]]) -> str:
    return _BR_CSV_HEAD + "".join(f".\tf.c\tf\t8\t{kind}\t{status}\t{prop}\n" for kind, status, prop in rows)


def _log(rows: list[tuple[str, str, str]], warnings: str = "") -> str:
    proved = sum(1 for _, status, _ in rows if status == "Valid")
    return f"{warnings}[wp] {len(rows)} goals scheduled\n[wp] Proved goals:    {proved} / {len(rows)}\n"


class _ByModel:
    """A fake Frama-C answering each WP run by its -wp-model: {model: (rows, warnings)}."""

    def __init__(self, answers: dict[str, tuple[list[tuple[str, str, str]], str]]):
        self.answers = answers
        self.models: list[str] = []

    def __call__(self, cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-wp" in cmd and "-report-csv" in cmd:
            model = cmd[cmd.index("-wp-model") + 1]
            self.models.append(model)
            rows, warnings = self.answers.get(model, self.answers["Typed"])
            Path(cmd[cmd.index("-report-csv") + 1]).write_text(_rows(rows), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout=_log(rows, warnings), stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


def _c_file(tmp_path: Path) -> Path:
    c_file = tmp_path / "f.c"
    c_file.write_text("int f(int *p) { return *p; }\n", encoding="utf-8")
    return c_file


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake: _ByModel, **kw: object) -> dict:
    monkeypatch.setattr(W.subprocess, "run", fake)
    options: dict = {"cache_dir": "off", "retry_tail": False, "retry_bitwise": False, "retry_bytes": True}
    options.update(kw)
    return W.run_wp_on_function(_c_file(tmp_path), "f", tmp_path / "wp", **options)


# ---------------------------------------------------------------------------
# (a) a model outside the allowlist never yields all_proven
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("model", ["Hoare", "Region", "Typed+nat", "Typed+cast", "Typed+Bytes"])
def test_a_model_outside_the_allowlist_is_never_all_proven(tmp_path, monkeypatch, model) -> None:
    fake = _ByModel({"Typed": (_ALL_VALID, ""), model: (_ALL_VALID, "")})
    res = _run(tmp_path, monkeypatch, fake, wp_model=model, retry_bytes=False, retry_cast_probe=False)
    problem = wp_model_problem(model)
    assert problem is not None
    assert res["status"] == "unsound_proof" and res["soundness"]["ok"] is False
    assert problem in res["soundness"]["tier_b_unsound"]


@pytest.mark.unit
@pytest.mark.parametrize("model", ["Typed", "Bytes", "Typed+ref+int", "Typed+nocast"])
def test_an_allowed_model_can_be_all_proven(tmp_path, monkeypatch, model) -> None:
    fake = _ByModel({"Typed": (_ALL_VALID, ""), model: (_ALL_VALID, "")})
    res = _run(tmp_path, monkeypatch, fake, wp_model=model, retry_bytes=False)
    assert res["status"] == "all_proven" and res["wp_model"] == model


@pytest.mark.unit
def test_the_cast_probe_still_recognises_its_own_model_issue(tmp_path, monkeypatch) -> None:
    fake = _ByModel({"Typed": (_MEMCPY_UNKNOWN, _CAST_WARNINGS), "Typed+cast": (_ALL_VALID, "")})
    res = _run(tmp_path, monkeypatch, fake, retry_bytes=False)
    assert wp_model_problem("Typed+cast") == WP_UNSOUND_MODEL_ISSUE
    assert res["cast_model_probe"]["proves_all"] is True and res["wp_cast_limitation"] is True


# ---------------------------------------------------------------------------
# (b) the automatic Bytes retry
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_memcpy_type_pun_is_retried_under_bytes_and_credited(tmp_path, monkeypatch) -> None:
    fake = _ByModel(
        {"Typed": (_MEMCPY_UNKNOWN, _CAST_WARNINGS), "Typed+cast": (_MEMCPY_UNKNOWN, ""), "Bytes": (_ALL_VALID, "")}
    )
    res = _run(tmp_path, monkeypatch, fake)
    assert fake.models == ["Typed", "Typed+cast", "Bytes"]
    assert res["status"] == "all_proven" and res["wp_model"] == "Bytes"
    retry = res["bytes_retry"]
    assert retry["triggered"] is True and retry["kept"] is True
    assert retry["typed_status"] == "unproven_goals_remain" and retry["typed_unproven_count"] == 4
    assert retry["trigger"] == "pointer_cast"


@pytest.mark.unit
def test_a_union_through_a_pointer_is_retried_under_bytes(tmp_path, monkeypatch) -> None:
    fake = _ByModel({"Typed": (_ALL_VALID, _union_warning("Typed")), "Bytes": (_ALL_VALID, "")})
    res = _run(tmp_path, monkeypatch, fake)
    assert res["status"] == "all_proven" and res["wp_model"] == "Bytes"
    assert res["bytes_retry"]["kept"] is True and res["bytes_retry"]["trigger"] == "union"
    assert res["bytes_retry"]["typed_status"] == "unsound_proof"


@pytest.mark.unit
def test_a_local_union_that_still_warns_under_bytes_is_not_credited(tmp_path, monkeypatch) -> None:
    fake = _ByModel({"Typed": (_ALL_VALID, _union_warning("Hoare")), "Bytes": (_ALL_VALID, _union_warning("Hoare"))})
    res = _run(tmp_path, monkeypatch, fake)
    assert fake.models == ["Typed", "Bytes"]
    assert res["status"] == "unsound_proof" and res["wp_model"] == "Typed"
    retry = res["bytes_retry"]
    assert retry["triggered"] is True and retry["kept"] is False
    assert "union" in retry["reason"] and retry["bytes_status"] == "unsound_proof"


@pytest.mark.unit
def test_a_bytes_run_that_is_not_better_is_dropped(tmp_path, monkeypatch) -> None:
    fake = _ByModel(
        {
            "Typed": (_MEMCPY_UNKNOWN, _CAST_WARNINGS),
            "Typed+cast": (_MEMCPY_UNKNOWN, ""),
            "Bytes": (_MEMCPY_UNKNOWN, ""),
        }
    )
    res = _run(tmp_path, monkeypatch, fake)
    assert res["wp_model"] == "Typed" and res["unproven_count"] == 4
    assert res["bytes_retry"]["kept"] is False and res["bytes_retry"]["bytes_unproven_count"] == 4


@pytest.mark.unit
def test_other_unproven_goals_do_not_trigger_the_retry(tmp_path, monkeypatch) -> None:
    rows = [("postcondition", "Unknown", "\\result == 0"), ("rte: mem_access", "Valid", "\\valid(p)")]
    fake = _ByModel({"Typed": (rows, ""), "Bytes": (_ALL_VALID, "")})
    res = _run(tmp_path, monkeypatch, fake)
    assert fake.models == ["Typed"] and "bytes_retry" not in res


@pytest.mark.unit
def test_other_soundness_issues_do_not_trigger_the_retry(tmp_path, monkeypatch) -> None:
    warnings = _union_warning("Typed") + "[wp] f.c:3: Warning: Missing assigns clause (assigns 'everything' instead)\n"
    fake = _ByModel({"Typed": (_ALL_VALID, warnings), "Bytes": (_ALL_VALID, "")})
    res = _run(tmp_path, monkeypatch, fake)
    assert fake.models == ["Typed"] and "bytes_retry" not in res


@pytest.mark.unit
@pytest.mark.parametrize(
    "kw",
    [
        {"retry_bytes": False},  # the library default; the CLI turns it on only without --wp-model
        {"wp_model": "Typed+ref"},  # a model the caller chose
        {"prop": "x"},  # a partial run
    ],
)
def test_no_retry_when_not_asked_or_on_a_chosen_model_or_a_partial_run(tmp_path, monkeypatch, kw) -> None:
    fake = _ByModel({"Typed": (_ALL_VALID, _union_warning("Typed")), "Bytes": (_ALL_VALID, "")})
    res = _run(tmp_path, monkeypatch, fake, retry_cast_probe=False, **kw)
    assert "Bytes" not in fake.models and "bytes_retry" not in res


@pytest.mark.unit
def test_no_retry_when_the_prover_budget_is_exhausted(tmp_path, monkeypatch) -> None:
    scratch = tmp_path / "agents" / "prove-f" / "scratch"
    (scratch / "work").mkdir(parents=True)
    (scratch / ".prover_budget.json").write_text('{"max_wp_invocations": 1, "wp_invocations": 1}', encoding="utf-8")
    fake = _ByModel({"Typed": (_ALL_VALID, _union_warning("Typed")), "Bytes": (_ALL_VALID, "")})
    monkeypatch.setattr(W.subprocess, "run", fake)
    res = W.run_wp_on_function(_c_file(scratch / "work"), "f", scratch / "wp", cache_dir="off", retry_bytes=True)
    assert res["budget_exhausted"] is True and fake.models == [] and "bytes_retry" not in res


@pytest.mark.unit
@pytest.mark.parametrize(
    "extra,retried", [((), True), (("--wp-model", "Typed"), False), (("--no-retry-bytes",), False)]
)
def test_cli_retries_only_without_an_explicit_model(tmp_path, monkeypatch, extra, retried) -> None:
    fake = _ByModel({"Typed": (_ALL_VALID, _union_warning("Typed")), "Bytes": (_ALL_VALID, "")})
    monkeypatch.setattr(W.subprocess, "run", fake)
    out = tmp_path / "r.json"
    argv = [
        "--file",
        str(_c_file(tmp_path)),
        "--function",
        "f",
        "--out-dir",
        str(tmp_path / "wp"),
        "--out-json",
        str(out),
        "--cache-dir",
        "off",
        "--security-props",
        "none",
        *extra,
    ]
    assert W.main(argv) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert ("Bytes" in fake.models) is retried
    assert report["wp_model"] == ("Bytes" if retried else "Typed")
    assert report["status"] == ("all_proven" if retried else "unsound_proof")


# ---------------------------------------------------------------------------
# The real tools (inside framac-analysis:latest)
# ---------------------------------------------------------------------------

needs_framac = pytest.mark.skipif(shutil.which("frama-c") is None, reason="needs Frama-C (inside the image)")

PUN = r"""#include <stdint.h>
#include <string.h>

/*@ assigns \nothing; */
double to_double(uint64_t u)
{
   double d;
   memcpy(&d, &u, sizeof d);
   return d;
}

union val { int64_t i; double d; };

/*@ assigns \nothing; */
int64_t union_local(double x)
{
   union val v;
   v.d = x;
   return v.i;
}
"""


def _real_main(tmp_path: Path, fn: str) -> dict:
    (tmp_path / "pun.c").write_text(PUN, encoding="utf-8")
    out = tmp_path / f"{fn}.json"
    W.main(
        [
            "--file",
            str(tmp_path / "pun.c"),
            "--function",
            fn,
            "--out-dir",
            str(tmp_path / "wp"),
            "--out-json",
            str(out),
            "--cache-dir",
            "off",
            "--security-props",
            "none",
            "--timeout",
            "5",
        ]
    )
    return json.loads(out.read_text(encoding="utf-8"))


@needs_framac
def test_real_memcpy_type_pun_proves_under_bytes(tmp_path: Path) -> None:
    report = _real_main(tmp_path, "to_double")
    assert report["status"] == "all_proven", report.get("bytes_retry")
    assert report["wp_model"] == "Bytes" and report["bytes_retry"]["kept"] is True


@needs_framac
def test_real_local_union_is_not_credited(tmp_path: Path) -> None:
    report = _real_main(tmp_path, "union_local")
    assert report["status"] != "all_proven"
    assert report["bytes_retry"]["kept"] is False and report["wp_model"] == "Typed"
