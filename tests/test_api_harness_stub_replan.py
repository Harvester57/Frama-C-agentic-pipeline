"""
The re-plan `api_harness.generate` does when a callback stub does not compile (NULL callbacks instead)
keeps the module's variadic call sites: without them every variadic entry point went to `api_skipped`
as having no call site, although the first plan had cases for it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
from test_api_harness_capture_headers import _setup

pytestmark = pytest.mark.unit


def test_the_stub_replan_plans_with_the_variadic_call_sites(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out, _ = _setup(tmp_path, monkeypatch, None)
    variadic: dict[str, Any] = {"sites": {}}
    plans: list[dict[str, Any]] = []
    real_plan = ah.plan

    def spy(*args: Any, **kw: Any) -> dict:
        plans.append(kw)
        return real_plan(*args, **kw)

    # First probe: an error outside the cases, on a stub's line. Second probe: clean.
    results: list[tuple[dict[int, str], list[str]]] = [
        ({}, ["harness_lib.c:1:1: error: unknown type name 'cb_t'"]),
        ({}, []),
    ]
    probes = iter(results)
    monkeypatch.setattr(ah, "plan", spy)
    monkeypatch.setattr(ah, "probe_layouts", lambda *a, **k: ({}, set()))
    monkeypatch.setattr(ah, "probe_cases", lambda *a, **k: next(probes))
    monkeypatch.setattr(ah, "_stub_errors_only", lambda *a, **k: True)

    ah.generate(
        "lib",
        "none",
        64,
        "",
        out,
        unit="lib",
        dag_path=Path("dag.json"),
        model_path=Path("model.json"),
        traces_path=Path("none/traces.jsonl"),
        variadic=variadic,
    )

    stub_replans = [kw for kw in plans if kw.get("callback_stubs") is False]
    assert len(stub_replans) == 1, plans
    assert len(plans) == 3, plans  # the first plan, the one with the probed layouts, the stub re-plan
    assert all(kw.get("variadic") is variadic for kw in plans), plans
