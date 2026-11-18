r"""run_wp_function: WP's `Warning: void object` is recorded in the report, with the lines WP names.

WP gives a `void` object the size of an `int` (plugins/wp/src/ctypes.ml) and prints `Warning: void object` where a
term needs that size. A goal that depends on it can be proved although it is false: `\block_length(p) == 32` for
`char buf[8]; void *p = buf;` under `Typed`, `(char *)(p + 4) == big + 16` under `Bytes`. The warning is not a sign
of a false proof by itself: WP prints it as well for the `pointer_value` alarm on a loaded `void *` and at the libc
declaration of a callee with a `void *` formal (`send`), on correct code with a correct contract. So the report
lists the warned lines and gives a hint, and the status stays what the goals say.

The logs and CSVs under tests/fixtures/wp_void_object/ are Frama-C's own output (34.0~beta, in
framac-analysis:latest) for the command line of run_wp_function.py with `--timeout 5 --cache-dir off
--security-props none`, one run per function of tests/fixtures/wp_void_object/src/voidobj.c
(`mempcpy_false_bytes_model`: with `--wp-model Bytes`; `shift_false_castprobe` and `shift_false_bytes`: the cast
probe and the automatic `Bytes` retry of the `shift_false` run). Each is cut to the function under proof: the log
keeps everything up to `[report] Computing properties status...`, the function's own section of the `-report`
output and the `Status Report Summary`; the CSV keeps the header, the function's rows and the rows at a file:line
that a `void object` warning of the log names.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import run_wp_function as W

VOID_FIXTURES = Path(__file__).parent / "fixtures" / "wp_void_object"
VOID_SOURCE = VOID_FIXTURES / "src" / "voidobj.c"
VOID_C = "/target/wp_void_object/src/voidobj.c"
_SUFFIX_BY_MODEL = {"Typed": "", "Typed+cast": "_castprobe", "Bytes": "_bytes"}


class _RecordedByModel:
    """A fake Frama-C answering each WP run of `name` with the recorded log and CSV of its `-wp-model`."""

    def __init__(self, name: str, suffixes: dict[str, str] | None = None):
        self.name = name
        self.suffixes = suffixes or _SUFFIX_BY_MODEL
        self.models: list[str] = []

    def __call__(self, cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-wp" in cmd and "-report-csv" in cmd:
            model = cmd[cmd.index("-wp-model") + 1]
            self.models.append(model)
            stem = self.name + self.suffixes[model]
            shutil.copyfile(VOID_FIXTURES / f"{stem}.csv", cmd[cmd.index("-report-csv") + 1])
            log = (VOID_FIXTURES / f"{stem}.log").read_text(encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout=log, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


def _report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake: _RecordedByModel, **kw: object) -> dict:
    monkeypatch.setattr(W.subprocess, "run", fake)
    options: dict = {
        "cache_dir": "off",
        "retry_tail": False,
        "retry_bitwise": False,
        "retry_bytes": False,
        "retry_cast_probe": False,
    }
    options.update(kw)
    return W.run_wp_on_function(VOID_SOURCE, fake.name, tmp_path / "wp", **options)


def _void_hints(res: dict) -> list[str]:
    return [hint for hint in res["diagnostic_hints"] if "void object" in hint]


# ---------------------------------------------------------------------------
# The false proofs: the report now names the line and says to cast first
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_false_block_length_proof_names_the_assertion_wp_warned_on(tmp_path, monkeypatch) -> None:
    res = _report(tmp_path, monkeypatch, _RecordedByModel("bl_false"))
    assert res["void_object_warnings"] == [
        {
            "file": VOID_C,
            "line": 18,
            "properties": [
                {
                    "function": "bl_false",
                    "kind": "user assertion",
                    "status": "Valid",
                    "annotation": "\\block_length(p) == 32",
                }
            ],
        }
    ]
    hints = _void_hints(res)
    assert len(hints) == 1 and f"{VOID_C}:18" in hints[0] and "(char *)p" in hints[0]
    # Recorded, not downgraded: the warning alone cannot tell this proof from the correct ones below.
    assert res["status"] == "all_proven" and res["wp_model"] == "Typed" and res["soundness"]["ok"] is True


@pytest.mark.unit
def test_the_bytes_retry_that_proves_a_false_shift_carries_the_warning(tmp_path, monkeypatch) -> None:
    """`Typed` leaves `(char *)(p + 4) == big + 16` unproven; the automatic `Bytes` retry proves it and is kept."""
    fake = _RecordedByModel("shift_false")
    res = _report(tmp_path, monkeypatch, fake, retry_bytes=True, retry_cast_probe=True)
    assert fake.models == ["Typed", "Typed+cast", "Bytes"]
    assert res["status"] == "all_proven" and res["wp_model"] == "Bytes" and res["bytes_retry"]["kept"] is True
    assert [(w["file"], w["line"]) for w in res["void_object_warnings"]] == [(VOID_C, 34)]
    assert res["void_object_warnings"][0]["properties"] == [
        {
            "function": "shift_false",
            "kind": "user assertion",
            "status": "Valid",
            "annotation": "(char *)(p + 4) == &big[16]",
        }
    ]
    assert len(_void_hints(res)) == 1


@pytest.mark.unit
def test_a_warning_in_a_libc_contract_names_the_clause_not_the_false_assertion(tmp_path, monkeypatch) -> None:
    """Under `Bytes`, `(char *)r == d + 8` after `mempcpy(d, s, 2)` is proved; WP warns at mempcpy's `ensures`."""
    fake = _RecordedByModel("mempcpy_false", {"Bytes": "_bytes_model"})
    res = _report(tmp_path, monkeypatch, fake, wp_model="Bytes")
    assert res["status"] == "all_proven" and res["wp_model"] == "Bytes"
    assert res["void_object_warnings"] == [
        {
            "file": "FRAMAC_SHARE/libc/string.h",
            "line": 148,
            "properties": [
                {
                    "function": "mempcpy",
                    "kind": "postcondition",
                    "status": "Considered valid",
                    "annotation": "result_next_byte: \\result == \\old(dest) + \\old(n)",
                }
            ],
        }
    ]
    assert {g["annotation"] for g in res["unproven_goals"]} == set()
    assert len(_void_hints(res)) == 1


# ---------------------------------------------------------------------------
# Controls: correct code that makes WP print the warning keeps its verdict
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_correct_caller_of_send_stays_all_proven(tmp_path, monkeypatch) -> None:
    """WP warns at the libc declaration of `send`, on its own separation hypothesis over the `void *` buffer."""
    res = _report(tmp_path, monkeypatch, _RecordedByModel("calls_send"))
    assert res["status"] == "all_proven" and res["soundness"]["ok"] is True
    assert res["soundness"]["tier_b_unsound"] == []
    (site,) = res["void_object_warnings"]
    assert (site["file"], site["line"]) == ("FRAMAC_SHARE/libc/sys/socket.h", 513)
    assert {p["function"] for p in site["properties"]} == {"send"}
    assert "\\separated(buf + (..), &__fc_errno)" in {p["annotation"] for p in site["properties"]}


@pytest.mark.unit
def test_loading_a_void_pointer_keeps_its_verdict(tmp_path, monkeypatch) -> None:
    """The warning sits on the `pointer_value` alarm of `return h->ctx;` (-warn-invalid-pointer)."""
    res = _report(tmp_path, monkeypatch, _RecordedByModel("load_void"))
    assert res["status"] == "unproven_goals_remain" and res["soundness"]["ok"] is True
    (site,) = res["void_object_warnings"]
    assert (site["file"], site["line"]) == (VOID_C, 56)
    assert [p["kind"] for p in site["properties"]] == ["mem_access", "pointer_value"]
    assert [g["kind"] for g in res["unproven_goals"]] == ["pointer_value"]


@pytest.mark.unit
@pytest.mark.parametrize("fn", ["bl_cast", "stores_void", "fill_void"])
def test_void_pointers_that_are_cast_stored_or_passed_give_no_warning(tmp_path, monkeypatch, fn) -> None:
    res = _report(tmp_path, monkeypatch, _RecordedByModel(fn))
    assert res["status"] == "all_proven"
    assert res["void_object_warnings"] == [] and res["diagnostic_hints"] == []


# ---------------------------------------------------------------------------
# The parser
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_each_warned_line_is_listed_once_in_log_order() -> None:
    log = (VOID_FIXTURES / "shift_false.log").read_text(encoding="utf-8")
    assert log.count("Warning: void object") == 2
    assert W.void_object_sites(log) == [(VOID_C, 34)]
    assert W.void_object_sites("[wp] 2 goals scheduled\n[wp] Proved goals:    2 / 2\n") == []
    assert W.void_object_sites("[wp] Warning: void object\n[kernel] a.c:3: Warning: void object\n") == [("", 0)]
