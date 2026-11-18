"""
In-image driver of tests/test_metacsl_eacsl.py: builds the fixture through fuzz_build.build_module_binary
in a run-directory layout (cwd), runs the binaries on fixed inputs, and prints one `RESULT <json>` line.

usage: drive.py FIXTURE_DIR PROPS_ON PROPS_OFF
PROPS_ON turns the `eacsl` engine on (`meta_engines`), PROPS_OFF is the same document with it off.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, "/opt/framac-pipeline/scripts")

import failure_identity  # noqa: E402
import fingerprint  # noqa: E402
import fuzz_build  # noqa: E402
from run_wp_function import goal_obligation_class  # noqa: E402

VIOLATIONS = "-DVIOLATE_WRITE -DVIOLATE_PRECOND -DVIOLATE_INIT -DVIOLATE_WIPE -DVIOLATE_TEXT -DVIOLATE_LEAK -DRTE_BUG"
INPUTS = {
    "login": b"Lok",
    "admin": b"A",
    "backdoor": b"B",
    "emit": b"Eabc",
    "close": b"Cabcdefghijklmnopqrstuvwxyz",
    "text": b"Ta\nb",
    "key": b"Kabc",
    "leak": b"S",
    "direct": b"H",
    "other": b"Z",
    "long": b"M" * 80,
}
ASSERT_TOKEN_RE = re.compile(
    r"(?P<var>\w+)\.(?P<field>kind|pred_txt|fct|name) = (?P<val>[^;\n]*);"
    r"|__e_acsl_assert\s*\((?P<args>[^;]*?)&\s*(?P<call>\w+)\s*\)\s*;",
    re.DOTALL,
)


def assertions(instrumented: str) -> Counter:
    """Every run-time assertion call of an instrumented file as (kind, name, function, predicate)."""
    text = Path(instrumented).read_text(encoding="utf-8", errors="replace")
    out: Counter = Counter()
    data: dict[str, dict[str, str]] = {}
    for m in ASSERT_TOKEN_RE.finditer(text):
        if m.group("var"):
            data.setdefault(m.group("var"), {})[m.group("field")] = m.group("val").strip().strip('"')
            continue
        d = data.pop(m.group("call"), {})
        out[tuple(d.get(k, "") for k in ("kind", "name", "fct", "pred_txt"))] += 1
    return out


def build(tag: str, harness: str, defs: str, spec: str | None) -> dict:
    out_bin = Path("workspace/work/out") / tag / "fuzz_prog"
    built = fuzz_build.build_module_binary(
        [f"workspace/harnesses/{harness}", "workspace/work/src/prog.c"],
        out_bin,
        engine="eacsl",
        cppflags=f"-Iworkspace/work/src {defs}".strip(),
        warn_unsigned_downcast=True,
        use_cache=False,
        security_props=spec,
    )
    comp = built["compile"]
    keep = ("returncode", "reason", "command", "binary", "instrumented_source", "security_props", "cache")
    res = {k: comp.get(k) for k in keep}
    res["sources"] = built["sources"]
    if comp["returncode"] != 0:
        res["log_tail"] = Path(comp["compile_log"]).read_text(encoding="utf-8", errors="replace")[-6000:]
    return res


def run(binary: str, name: str) -> dict:
    """One input through one binary: exit code, parsed failure, fingerprint and what the ledger would read."""
    inp = Path("workspace/work/out/inputs") / name
    inp.parent.mkdir(parents=True, exist_ok=True)
    inp.write_bytes(INPUTS[name])
    try:
        proc = subprocess.run([binary, str(inp)], capture_output=True, timeout=120, check=False)
        rc, out = proc.returncode, (proc.stdout + proc.stderr).decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        rc, out = 124, ""
    failure = failure_identity.parse_runtime_failure(out)
    fp = failure_identity.failure_fingerprint(failure)
    res: dict = {"rc": rc, "error_lines": [ln.strip() for ln in out.splitlines() if "Error:" in ln][:4]}
    if failure:
        res.update(
            failure=failure,
            fingerprint=fp,
            fingerprint_valid=fingerprint.is_valid_fingerprint(fp or ""),
            needs_attribution=failure_identity.needs_attribution(failure),
            ledger_class=goal_obligation_class(
                {"kind": failure.get("kind", ""), "annotation": failure.get("predicate", "")}
            ),
        )
    return res


def campaign(binary: str, tag: str) -> dict:
    """A libFuzzer run over a corpus holding the violating input: it must stop on it and keep it."""
    corpus = Path("workspace/work/out") / tag / "corpus"
    crashes = Path("workspace/work/out") / tag / "crashes"
    for d in (corpus, crashes):
        d.mkdir(parents=True, exist_ok=True)
    (corpus / "seed").write_bytes(INPUTS["backdoor"])
    cmd = [binary, "-runs=200", "-seed=7", f"-artifact_prefix={crashes.as_posix()}/", corpus.as_posix()]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=120, check=False)
        rc, out = proc.returncode, (proc.stdout + proc.stderr).decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        rc, out = 124, ""
    kept = sorted(crashes.iterdir())
    failure = failure_identity.parse_runtime_failure(out)
    return {
        "rc": rc,
        "artifacts": [p.name for p in kept],
        "artifact_bytes": [p.read_bytes().decode("latin-1") for p in kept][:3],
        "fingerprint": failure_identity.failure_fingerprint(failure),
    }


def main() -> int:
    fixture, props_on, props_off = (Path(a) for a in sys.argv[1:4])
    for sub in ("workspace/work/src", "workspace/harnesses", "workspace/reports"):
        Path(sub).mkdir(parents=True, exist_ok=True)
    for name in ("prog.c", "prog.h"):
        shutil.copy(fixture / name, Path("workspace/work/src") / name)
    for name in ("harness_prog.c", "harness_direct.c"):
        shutil.copy(fixture / name, Path("workspace/harnesses") / name)
    default_props = Path("workspace/reports/security_props.json")
    out: dict = {"builds": {}, "runs": {}}

    # The run's file is there with the engine off: nothing may change.
    shutil.copy(props_off, default_props)
    out["builds"]["off"] = build("off", "harness_prog.c", "", None)
    # The same file with the engine on, found at its default place.
    shutil.copy(props_on, default_props)
    out["builds"]["ok"] = build("ok", "harness_prog.c", "", None)
    # `none` wins over the file; then the file named by the environment, then by the option.
    out["builds"]["viol_plain"] = build("viol_plain", "harness_prog.c", VIOLATIONS, "none")
    default_props.unlink()
    os.environ[fuzz_build.SECURITY_PROPS_ENV] = str(props_on)
    out["builds"]["viol"] = build("viol", "harness_prog.c", VIOLATIONS, None)
    del os.environ[fuzz_build.SECURITY_PROPS_ENV]
    out["builds"]["direct"] = build("direct", "harness_direct.c", "", str(props_on))

    builds = out["builds"]
    if any(b["returncode"] != 0 for b in builds.values()):
        print("RESULT " + json.dumps(out))
        return 0
    for base, with_props in (("off", "ok"), ("viol_plain", "viol"), ("off", "direct")):
        before = assertions(builds[base]["instrumented_source"])
        after = assertions(builds[with_props]["instrumented_source"])
        out.setdefault("assertions", {})[with_props] = {
            "base": sum(before.values()),
            "with_properties": sum(after.values()),
            "lost": [list(k) for k in (before - after)],
            "added_names": sorted({k[1] for k in (after - before)}),
        }
    for tag, names in (
        ("ok", ("login", "admin", "backdoor", "emit", "close", "text", "key", "leak", "other", "long")),
        ("viol", ("backdoor", "admin", "emit", "close", "text", "leak", "long", "login", "other")),
        ("viol_plain", ("long", "backdoor")),
        ("direct", ("direct", "admin", "other")),
    ):
        out["runs"][tag] = {name: run(builds[tag]["binary"], name) for name in names}
    out["campaign"] = campaign(builds["viol"]["binary"], "viol")
    print("RESULT " + json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
