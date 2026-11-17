"""
The dispatch selector (generate_harness._build_dispatch_invocation): the first input byte is the case
index, a byte at or above the case count runs no case, at most 256 cases (above that, two bytes:
test_dispatch_selector_wide.py). A harness generated before
(sidecar without `dispatch_selector`) is still decoded modulo its case count by every decoder.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

import generate_harness as G
import harness_reach
import run_eacsl_fuzz as R
import seed_harvest
from test_harness_reach import _coverage, _run_dir, _write_fuzz_report, _write_harness

pytestmark = pytest.mark.unit


def _gen(tmp_path: Path, n: int, out: str = "harnesses") -> Path:
    src = tmp_path / "mod.c"
    src.write_text("int hit_case(unsigned int c) { return (int)c; }\n", encoding="utf-8")
    (tmp_path / "mod.h").write_text("int hit_case(unsigned int c);\n", encoding="utf-8")
    res = G.generate_module_harness(
        module_name="mod",
        sources=[str(src)],
        header_include="mod.h",
        entry_fn="hit_case",
        max_input_size=64,
        cppflags=f"-I{tmp_path.as_posix()}",
        out_dir=tmp_path / out,
        entry_style="dispatch",
        dispatch_cases=[f"(void)hit_case({i}U);" for i in range(n)],
        auto_prelude=False,
    )
    return Path(res["harness_file"])


def _byte_to_stmt(harness_c: Path) -> dict[int, str]:
    """What each first byte runs, decoded as every decoder does (sidecar encoding, case list)."""
    sidecar = json.loads(harness_c.with_suffix(".json").read_text(encoding="utf-8"))
    sel = G.dispatch_selector_of(sidecar)
    n = sidecar["dispatch_case_count"]
    cases = dict(seed_harvest.harness_cases(harness_c.read_text(encoding="utf-8")))
    out: dict[int, str] = {}
    for b in range(256):
        c = G.dispatch_case_of(b, n, sel)
        if c is not None:
            out[b] = cases[c].strip()
    return out


def test_generated_harness_selects_by_identity_and_rejects_the_rest(tmp_path):
    harness = _gen(tmp_path, 3)
    text = harness.read_text(encoding="utf-8")
    assert "switch (harness_selector) { /* dispatch selector: identity, 3 cases */" in text
    assert "% 3U" not in text
    assert "default: FRAMAC_FUZZ_REJECT(); break;" in text
    sidecar = json.loads(harness.with_suffix(".json").read_text(encoding="utf-8"))
    assert sidecar["dispatch_selector"] == "identity" and sidecar["dispatch_case_count"] == 3
    assert "warnings" not in sidecar, sidecar.get("warnings")
    assert G.dispatch_selector_of_text(text) == ("identity", 3)
    assert _byte_to_stmt(harness) == {0: "(void)hit_case(0U);", 1: "(void)hit_case(1U);", 2: "(void)hit_case(2U);"}


def test_appending_a_case_keeps_the_case_of_every_old_byte(tmp_path):
    old = _byte_to_stmt(_gen(tmp_path, 181, "h181"))
    new = _byte_to_stmt(_gen(tmp_path, 182, "h182"))
    assert len(old) == 181 and len(new) == 182
    assert all(new[b] == stmt for b, stmt in old.items())
    assert new[181] == "(void)hit_case(181U);"


def test_more_than_4096_cases_is_refused_and_leaves_no_harness(tmp_path):
    # Above 256 cases the selector is two bytes (test_dispatch_selector_wide.py), up to 4096 cases.
    with pytest.raises(ValueError, match=r"at most 4096 cases; this one has 4097\. Split the module"):
        _gen(tmp_path, 4097)
    assert not (tmp_path / "harnesses" / "harness_mod.c").exists()
    assert not (tmp_path / "harnesses" / "harness_mod.json").exists()


def test_legacy_text_and_sidecar_decode_modulo():
    legacy = "#ifdef FRAMAC_FUZZ_SKIP_CASES\n#endif\n    switch (harness_selector % 3U) {\n"
    assert G.dispatch_selector_of_text(legacy) == ("modulo", 3)
    assert G.dispatch_selector_of({"dispatch_case_count": 3}) == "modulo"
    assert G.dispatch_selector_of({"dispatch_case_count": 3, "dispatch_selector": "identity"}) == "identity"
    assert G.dispatch_selector_of(None, legacy) == "modulo"
    assert G.dispatch_case_of(5, 3, "modulo") == 2
    assert G.dispatch_case_of(5, 3, "identity") is None
    assert G.dispatch_case_of(2, 3, "identity") == 2


def _fuzz_sources(tmp_path: Path, *, identity: bool) -> Path:
    """A harness on disk as run_eacsl_fuzz finds it: the .c with the skip macro, its sidecar."""
    harness = _gen(tmp_path, 3)
    if not identity:
        text = harness.read_text(encoding="utf-8").replace(
            "switch (harness_selector) { /* dispatch selector: identity, 3 cases */", "switch (harness_selector % 3U) {"
        )
        harness.write_text(text, encoding="utf-8")
        sc = json.loads(harness.with_suffix(".json").read_text(encoding="utf-8"))
        sc.pop("dispatch_selector")
        harness.with_suffix(".json").write_text(json.dumps(sc), encoding="utf-8")
    return harness


@pytest.mark.parametrize("identity", [True, False])
def test_run_eacsl_fuzz_reads_the_encoding(tmp_path, identity):
    harness = _fuzz_sources(tmp_path, identity=identity)
    want = "identity" if identity else "modulo"
    assert R.dispatch_case_count([str(harness)]) == 3
    assert R.dispatch_selector([str(harness)]) == want
    assert R.harness_supports_runtime_skip_cases([str(harness)]) is True
    assert R.dispatch_skippable_cases([str(harness)], 3) == 3
    # Without the sidecar, the harness text decides, and still gives the count.
    harness.with_suffix(".json").unlink()
    assert R.dispatch_selector([str(harness)]) == want
    assert R.dispatch_case_count([str(harness)]) == 3
    ident = R.campaign_harness_identity("", [harness])
    assert ident["dispatch_selector"] == want and ident["dispatch_case_count"] == 3


def test_artifact_dispatch_case_by_encoding(tmp_path):
    p = tmp_path / "crash-5"
    p.write_bytes(b"\x05rest")
    art = {"artifact": str(p)}
    assert R.artifact_dispatch_case(art, 3) == 2  # legacy default
    assert R.artifact_dispatch_case(art, 3, "modulo") == 2
    assert R.artifact_dispatch_case(art, 3, "identity") is None
    assert R.artifact_dispatch_case(art, 6, "identity") == 5


def test_keep_going_rounds_decode_with_the_harness_selector(tmp_path):
    crash = tmp_path / "crash-a"
    crash.write_bytes(b"\x04\x00")
    calls: list[int] = []

    def campaign(binary, seconds, fork, *, extra_env=None):
        calls.append(seconds)
        arts = (
            [{"artifact": str(crash), "kind": "crash", "sha256": "a", "fingerprint": "fp"}] if len(calls) == 1 else []
        )
        return {"status": "crash_found" if arts else "clean", "returncode": 1 if arts else 0, "artifacts": arts}

    res = R.run_campaign_rounds(
        Path("bin"), 600, campaign=campaign, rebuild=lambda m: (Path("bin2"), {}), n_cases=6, selector="identity"
    )
    kg: dict = res["keep_going"]
    assert kg["rounds"][0]["crashed_cases"] == [4] and kg["skipped_cases"] == [4]
    assert kg["dispatch_selector"] == "identity"
    calls.clear()
    res = R.run_campaign_rounds(
        Path("bin"), 600, campaign=campaign, rebuild=lambda m: (Path("bin2"), {}), n_cases=3, selector="modulo"
    )
    assert res["keep_going"]["rounds"][0]["crashed_cases"] == [1]


def test_stamp_carries_the_selector_but_absence_still_means_modulo():
    report: dict[str, Any] = {"artifacts": [{"sha256": "x"}, {"sha256": "y", "pre_existing": True}]}
    prior = {"artifacts": [{"sha256": "y", "harness_digest": "d", "dispatch_case_count": 3}]}
    ident = {"harness_digest": "e", "dispatch_case_count": 4, "dispatch_selector": "identity"}
    R.stamp_harness_identity(report, ident, prior)
    assert report["dispatch_selector"] == "identity"
    assert report["artifacts"][0]["dispatch_selector"] == "identity"
    # The carried-over artifact keeps what the prior report recorded: no selector, i.e. modulo.
    assert report["artifacts"][1] == {"sha256": "y", "pre_existing": True, "harness_digest": "d", "dispatch_case_count": 3}


# --- harness_reach --------------------------------------------------------------------------------

THREE = [
    {"selector": 0, "kind": "single", "entry": "rec_put", "calls": ["rec_put"], "inits": []},
    {"selector": 1, "kind": "single", "entry": "rec_put", "calls": ["rec_put"], "inits": []},
    {"selector": 2, "kind": "single", "entry": "rec_parse", "calls": ["rec_parse"], "inits": []},
]


def _reach_run(tmp_path, monkeypatch, **sidecar):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(
        run,
        "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 1);",
        reach_exempt={"rec_print": "debug output"},
        entry_style="dispatch",
        dispatch_case_count=3,
        api_cases=THREE,
        **sidecar,
    )
    harness_reach.record_exempt(hdir, "tools", None, "examples")
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 0
    _coverage(run, {"rec_parse": 0, "rec_put": 10})
    return run, hdir


def _reach_row(run: Path, hdir: Path, fdir: Path) -> dict:
    dag = json.loads((run / "workspace/reports/callgraph_dag.json").read_text(encoding="utf-8"))
    mm = harness_reach.ModuleMap(dag, harness_reach.load_sidecars(hdir))
    cov = json.loads((run / "workspace/reports/coverage/api.json").read_text(encoding="utf-8"))
    return harness_reach.check_dynamic("api", dag, mm, cov, fuzz_dir=fdir, harnesses_dir=hdir)


def _art(run: Path, data: bytes, function: str = "rec_check", **extra) -> dict:
    p = run / "workspace" / "crashes" / "api" / "crash-x"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    failure = {"function": function, "file": "workspace/work/src/api.c", "line": 4}
    return {"artifact": "workspace/crashes/api/crash-x", "reproducible": True, "kind": "crash", "failure": failure, **extra}


@pytest.mark.parametrize(("selector", "credited"), [("identity", []), (None, ["rec_parse"])])
def test_reach_decodes_a_byte_above_the_count_by_the_sidecar_encoding(tmp_path, monkeypatch, selector, credited):
    # Byte 5: modulo 3 selects case 2 (rec_parse, whose callee rec_check failed); identity rejects it.
    extra = {"dispatch_selector": selector} if selector else {}
    run, hdir = _reach_run(tmp_path, monkeypatch, **extra)
    fdir = _write_fuzz_report(run, "api", [_art(run, b"\x05\x00")])
    assert _reach_row(run, hdir, fdir)["crashed_entry_points"] == credited


def test_reach_refuses_an_artifact_found_under_the_other_encoding(tmp_path, monkeypatch):
    # Same digest and count, but found under the modulo selector: byte 5 meant case 2 then, nothing now.
    run, hdir = _reach_run(tmp_path, monkeypatch, dispatch_selector="identity")
    fdir = _write_fuzz_report(run, "api", [_art(run, b"\x02\x00", dispatch_selector="modulo")])
    row = _reach_row(run, hdir, fdir)
    assert row["crashed_entry_points"] == []
    note = " ".join(row["crash_notes"])
    assert "(modulo selector), case 2" in note and "(identity selector), case 2" in note, note
    # The same file stamped under the identity selector counts.
    fdir = _write_fuzz_report(run, "api", [_art(run, b"\x02\x00")])
    assert _reach_row(run, hdir, fdir)["crashed_entry_points"] == ["rec_parse"]


def test_seeds_lead_with_the_byte_that_selects_their_case(tmp_path):
    src = tmp_path / "buf.c"
    src.write_text("void take(const unsigned char *p, unsigned long n) { (void)p; (void)n; }\n", encoding="utf-8")
    names = ["take_a", "take_b", "take_c"]
    res = G.generate_module_harness(
        module_name="buf",
        sources=[str(src)],
        header_include=None,
        entry_fn="take",
        max_input_size=64,
        cppflags="",
        out_dir=tmp_path / "harnesses",
        entry_style="dispatch",
        dispatch_cases=[f"(void){fn}(fuzz_buf, fuzz_len);" for fn in names],
        auto_prelude=False,
    )
    harness = Path(res["harness_file"])
    sidecar = json.loads(harness.with_suffix(".json").read_text(encoding="utf-8"))
    cases = seed_harvest.harness_cases(harness.read_text(encoding="utf-8"))
    assert [sel for sel, _ in cases] == [0, 1, 2]
    for sel, stmt in cases:
        assert sel is not None
        binding = seed_harvest.case_bindings(stmt, set(names))
        calls = [{"fn": fn, "args": {"0": [["b", 0, "c0ffee"]]}} for fn in names]
        seeds = seed_harvest.seeds_for_case(sel, binding, calls)
        assert seeds == [bytes([sel]) + bytes.fromhex("c0ffee")], (sel, stmt, binding)
        case = G.dispatch_case_of(seeds[0][0], sidecar["dispatch_case_count"], G.dispatch_selector_of(sidecar))
        assert case == sel and names[sel] in stmt


def test_generated_dispatch_harness_runs_case_k_for_byte_k(tmp_path):
    """Compiled and run: byte k < N runs case k (rc 0); byte >= N runs nothing (rc -1). Host cc, else Docker."""
    import os

    _gen(tmp_path, 3)
    driver = tmp_path / "driver.c"
    driver.write_text(
        '#include "harnesses/harness_mod.c"\n'
        "#include <stdio.h>\n"
        "static int last_hit = -1;\n"
        "int hit_case(unsigned int c) { last_hit = (int)c; return (int)c; }\n"
        "int main(void) {\n"
        "    for (unsigned int c = 0; c < 256U; c++) {\n"
        "        uint8_t in[2] = {(uint8_t)c, 0x42U};\n"
        "        last_hit = -1;\n"
        "        int rc = LLVMFuzzerTestOneInput(in, 2U);\n"
        '        printf("case:%u:%d:%d\\n", c, rc, last_hit);\n'
        "    }\n"
        "    return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    cc = shutil.which("clang") or shutil.which("gcc")
    if cc:
        exe = tmp_path / "sel_driver.exe"
        proc = subprocess.run(
            [cc, "-Wall", "-Werror", f"-I{tmp_path.as_posix()}", str(driver), "-o", str(exe)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        stdout = subprocess.run([str(exe)], env=dict(os.environ), capture_output=True, text=True, check=True).stdout
    else:
        from conftest import ANALYSIS_IMAGE, require_docker_images

        require_docker_images(ANALYSIS_IMAGE)  # skips without FRAMAC_DOCKER_TESTS=1
        script = "cd /tmp && clang -Wall -Werror -I/fixture /fixture/driver.c -o drv && timeout 60 ./drv"
        argv = ["docker", "run", "--rm", "--network", "none", "-v", f"{tmp_path}:/fixture:ro", ANALYSIS_IMAGE, script]
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
        assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
        stdout = proc.stdout
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip().startswith("case:")]
    assert len(lines) == 256, stdout[-2000:]
    for ln in lines:
        _, c_s, rc_s, hit_s = ln.split(":")
        c_i, rc_i, hit_i = int(c_s), int(rc_s), int(hit_s)
        if c_i < 3:
            assert (rc_i, hit_i) == (0, c_i), ln
        else:
            assert (rc_i, hit_i) == (-1, -1), ln
