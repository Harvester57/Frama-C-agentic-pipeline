"""
In-image driver of tests/test_metacsl_eacsl_wiring.py (plan package C2): the fixture of
tests/fixtures/metacsl_eacsl through `run_eacsl_fuzz.py`, as Make runs it, in a run-directory layout
(cwd). It prints one `RESULT <json>` line and copies the reports and crash inputs to OUT_DIR.

usage: drive.py C_FIXTURE_DIR WIRING_FIXTURE_DIR INPUT_DIR OUT_DIR MAKEFILE
INPUT_DIR holds on.json (the `eacsl` engine on), changed.json (the same with one property's text
changed), off.json (the engine off), and the Make run directories mk_off and mk_on with `before/`, the
templates without this package's change. MAKEFILE is the generated makefile's run-relative path.

Every step has a timeout; the campaigns stop at their first crash, on a corpus that holds one input.
"""

from __future__ import annotations

import difflib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPTS = "/opt/framac-pipeline/scripts"
VIOLATIONS = "-DVIOLATE_WRITE -DVIOLATE_PRECOND -DVIOLATE_INIT -DVIOLATE_WIPE -DVIOLATE_TEXT -DVIOLATE_LEAK"
INPUTS = {
    "backdoor": b"B",
    "admin": b"A",
    "emit": b"Eabc",
    "close": b"Cabcdefghijklmnopqrstuvwxyz",
    "text": b"Ta\nb",
    "leak": b"S",
}
HARNESS = "workspace/harnesses/harness_prog.c"
SOURCE = "workspace/work/src/prog.c"
OUT_BIN = "workspace/harnesses/fuzz_prog"
PROPS = "workspace/reports/security_props.json"
BUILD_TIMEOUT_S = 900
CAMPAIGN_TIMEOUT_S = 300


def tool(args: list[str], *, cwd: str | None = None, timeout: int = BUILD_TIMEOUT_S) -> dict:
    """One run_eacsl_fuzz.py call: exit code, the stderr lines about the properties, the report it wrote."""
    out_json = Path(cwd or ".") / args[args.index("--out-json") + 1]
    out_json.unlink(missing_ok=True)
    try:
        proc = subprocess.run(
            ["python3", f"{SCRIPTS}/run_eacsl_fuzz.py", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        rc, err = proc.returncode, proc.stderr
    except subprocess.TimeoutExpired:
        rc, err = 124, "timeout"
    try:
        report = json.loads(out_json.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        report = None
    return {
        "rc": rc,
        "stderr_props": [ln for ln in err.splitlines() if ln.startswith("security props")],
        "stderr_tail": err[-3000:] if report is None else "",
        "report": report,
    }


def build_args(out_json: str, props: str | None, *, defs: str = VIOLATIONS, engine: str = "eacsl") -> list[str]:
    args = [
        "build", "--module", "prog", "--sources", HARNESS, SOURCE, "--out-bin", OUT_BIN,
        f"--cppflags=-Iworkspace/work/src {defs}".rstrip(), "--ldflags=", f"--engine={engine}",
    ]  # fmt: skip
    if props is not None:
        args.append(f"--security-props={props}")
    return [*args, "--out-json", out_json]


def without_cache_fields(report: dict | None) -> str | None:
    """A build report as text, without `cache` (hit or miss) at its top and in its `compile`."""
    if not isinstance(report, dict):
        return None
    doc = {k: v for k, v in report.items() if k != "cache"}
    if isinstance(doc.get("compile"), dict):
        doc["compile"] = {k: v for k, v in doc["compile"].items() if k != "cache"}
    return json.dumps(doc, indent=2)


def brief(step: dict) -> dict:
    """A build step without the report text and the compiler output."""
    report = step["report"] or {}
    comp = report.get("compile") or {}
    return {
        "rc": step["rc"],
        "status": report.get("status"),
        "cache": report.get("cache"),
        "command": comp.get("command"),
        "security_props": report.get("security_props"),
        "warnings": report.get("security_props_warnings"),
        "stderr_props": step["stderr_props"],
        "stderr_tail": step["stderr_tail"],
        "top_keys": sorted(report),
    }


def campaign(name: str, data: bytes, *, module: str, harness: str, out_bin: str, defs: str) -> dict:
    corpus = Path("workspace/corpus") / name
    crashes = Path("workspace/crashes") / name
    for d in (corpus, crashes):
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True)
    (corpus / "seed").write_bytes(data)
    out_json = f"workspace/reports/fuzz/{name}.json"
    step = tool(
        [
            "campaign", "--module", module, "--sources", harness, SOURCE, "--out-bin", out_bin,
            "--corpus-dir", corpus.as_posix(), "--artifacts-dir", crashes.as_posix(),
            "--workers", "1", "--max-time", "30", "--stop-on-first-crash", "--no-auto-dict", "--no-attribution-replay",
            "--engine=eacsl", f"--cppflags=-Iworkspace/work/src {defs}".rstrip(), "--ldflags=",
            f"--security-props={PROPS}", "--out-json", out_json,
        ],
        timeout=BUILD_TIMEOUT_S + CAMPAIGN_TIMEOUT_S,
    )  # fmt: skip
    report = step["report"] or {}
    return {
        "rc": step["rc"],
        "report": out_json,
        "status": report.get("status"),
        "cache": (report.get("compile") or {}).get("cache"),
        "artifacts": [
            {
                "artifact": a.get("artifact"),
                "fingerprint": a.get("fingerprint"),
                "reproducible": a.get("reproducible"),
                "failure": a.get("failure"),
            }
            for a in report.get("artifacts") or []
        ],
        "harness_induced": report.get("security_props_harness_induced"),
        "stderr_props": step["stderr_props"],
        "stderr_tail": step["stderr_tail"],
    }


def make_dry_run(run: Path, makefile: str, scripts: str = SCRIPTS) -> dict:
    """`make -n build-prog fuzz-prog` in a generated run directory, the script directory normalized."""
    proc = subprocess.run(
        ["make", "-f", makefile, f"S={scripts}", "-n", "build-prog", "fuzz-prog"],
        cwd=run,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return {"rc": proc.returncode, "stdout": proc.stdout.replace(scripts, SCRIPTS), "stderr": proc.stderr[-2000:]}


def main() -> int:
    c_fixture, w_fixture, inputs, out_dir = (Path(a) for a in sys.argv[1:5])
    makefile = sys.argv[5]
    os.environ["FRAMAC_CACHE"] = "on"
    os.environ.pop("FRAMAC_SECURITY_PROPS", None)
    for sub in ("workspace/work/src", "workspace/harnesses", "workspace/reports/fuzz", "workspace/build"):
        Path(sub).mkdir(parents=True, exist_ok=True)
    for name in ("prog.c", "prog.h"):
        shutil.copy(c_fixture / name, Path("workspace/work/src") / name)
    shutil.copy(c_fixture / "harness_prog.c", HARNESS)
    shutil.copy(w_fixture / "harness_indirect.c", "workspace/harnesses/harness_indirect.c")
    shutil.copy(inputs / "on.json", PROPS)
    out: dict = {"builds": {}, "campaigns": {}, "replays": {}, "make": {}}
    builds = out["builds"]
    meta_file = Path(OUT_BIN + ".security_meta.c")
    sidecar = Path(OUT_BIN + ".security_meta.json")

    # 1. The cache: a first build, the same build again without its meta file and sidecar, a changed
    #    property text, then the builds without the engine.
    builds["first"] = brief(tool(build_args("workspace/build/first.json", PROPS)))
    if builds["first"]["status"] != "built":
        print("RESULT " + json.dumps(out))
        return 0
    kept = {p.name: p.read_text(encoding="utf-8") for p in (meta_file, sidecar) if p.is_file()}
    for p in (meta_file, sidecar):
        p.unlink(missing_ok=True)
    builds["again"] = brief(tool(build_args("workspace/build/again.json", PROPS)))
    restored = {p.name: p.read_text(encoding="utf-8") for p in (meta_file, sidecar) if p.is_file()}
    out["sidecar"] = {"written": sorted(kept), "restored": sorted(restored), "identical": kept == restored}
    # The default file of the run, not named: the same properties, the same entry.
    builds["by_default"] = brief(tool(build_args("workspace/build/by_default.json", None)))
    builds["changed"] = brief(tool(build_args("workspace/build/changed.json", str(inputs / "changed.json"))))
    off = tool(build_args("workspace/build/off.json", str(inputs / "off.json")))
    none = tool(build_args("workspace/build/none.json", "none"))
    builds["off"], builds["none"] = brief(off), brief(none)
    shutil.copy(inputs / "off.json", PROPS)
    plain = tool(build_args("workspace/build/plain.json", None))
    builds["plain"] = brief(plain)
    shutil.copy(inputs / "on.json", PROPS)
    # The engine off in the file, `none`, and no file with the engine: one entry, and the reports of its
    # hits are one text (a hit's report differs from its build's by itself: the restored record).
    off_again = tool(build_args("workspace/build/off_again.json", str(inputs / "off.json")))
    builds["off_again"] = brief(off_again)
    texts = [without_cache_fields(step["report"]) for step in (off_again, none, plain)]
    out["engine_off_reports_identical"] = texts[0] is not None and texts[0] == texts[1] == texts[2]
    out["engine_off_report_differences"] = sorted(
        {
            line
            for text in texts[1:]
            for line in difflib.unified_diff((texts[0] or "").splitlines(), (text or "").splitlines(), lineterm="", n=0)
            if line[:1] in "+-" and line[:3] not in ("+++", "---")
        }
    )
    # The entry of the first build is still there after the others used the same output path.
    builds["back"] = brief(tool(build_args("workspace/build/back.json", PROPS)))

    # 2. One campaign per planted violation, on the binary of the first build (a cache hit each time).
    for name, data in INPUTS.items():
        out["campaigns"][name] = campaign(name, data, module="prog", harness=HARNESS, out_bin=OUT_BIN, defs=VIOLATIONS)
    # 3. A harness that calls the protected function itself, unseen by the build, on the correct target.
    out["campaigns"]["indirect"] = campaign(
        "indirect",
        b"H",
        module="prog_indirect",
        harness="workspace/harnesses/harness_indirect.c",
        out_bin="workspace/harnesses/fuzz_prog_indirect",
        defs="-DCALL_GATE=admin",
    )

    # 4. Replays from another directory: a build made there, then the campaign's binary as it is.
    run = Path.cwd()
    there = Path("/tmp/elsewhere")
    there.mkdir(parents=True, exist_ok=True)
    crash = [a["artifact"] for a in out["campaigns"]["backdoor"]["artifacts"] if a.get("artifact")]
    if crash:
        crash_input = str(run / crash[0])
        base = ["replay", "--module", "prog", "--inputs", crash_input, "--no-attribution-replay"]
        built_there = tool(
            [
                *base, "--sources", str(run / HARNESS), str(run / SOURCE), "--out-bin", "out/fuzz_prog",
                "--engine=eacsl", f"--cppflags=-I{run / 'workspace/work/src'} {VIOLATIONS}", "--ldflags=",
                f"--security-props={run / PROPS}", "--out-json", "replay_built.json",
            ],
            cwd=str(there),
        )  # fmt: skip
        given = tool(
            [*base, "--binary", str(run / (OUT_BIN + ".e-acsl")), "--out-json", "replay_binary.json"], cwd=str(there)
        )
        here = tool([*base, "--binary", OUT_BIN + ".e-acsl", "--out-json", "workspace/reports/replay_here.json"])
        for tag, step in (("built_elsewhere", built_there), ("binary_elsewhere", given), ("binary_here", here)):
            report = step["report"] or {}
            out["replays"][tag] = {
                "rc": step["rc"],
                "status": report.get("status"),
                "cache": report.get("cache"),
                "has_security_props": "security_props" in report,
                "fingerprints": [a.get("fingerprint") for a in report.get("artifacts") or []],
                "files": [(a.get("failure") or {}).get("file") for a in report.get("artifacts") or []],
                "stderr_tail": step["stderr_tail"],
            }

    # 5. Make: the recipes with the engine off are the ones of the template before this package.
    for tag in ("mk_off", "mk_on"):
        shutil.copytree(inputs / tag, Path("/tmp") / tag, dirs_exist_ok=True)
    out["make"]["off"] = make_dry_run(Path("/tmp/mk_off"), makefile)
    out["make"]["off_before"] = make_dry_run(Path("/tmp/mk_off"), makefile, str(inputs / "before" / "scripts"))
    out["make"]["on"] = make_dry_run(Path("/tmp/mk_on"), makefile)
    (Path("/tmp/mk_on") / PROPS).unlink()
    out["make"]["on_without_the_file"] = make_dry_run(Path("/tmp/mk_on"), makefile)

    for sub in ("workspace/reports/fuzz", "workspace/crashes"):
        shutil.copytree(sub, out_dir / sub, dirs_exist_ok=True)
    print("RESULT " + json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
