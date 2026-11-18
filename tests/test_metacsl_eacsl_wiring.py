"""
MetAcsl properties in the fuzz build, wired through the pipeline (docs/plans/metacsl-exploitation-plan.md,
package C2): the build cache, `run_eacsl_fuzz.py --security-props` and the replays, the Make variable,
what the reports show, and how `ledger.py ingest-fuzz` files a violated property.

The unit tests run the real functions on the fake toolchain of tests/test_metacsl_eacsl.py. The
acceptance test drives tests/fixtures/metacsl_eacsl through run_eacsl_fuzz.py in the analysis image
(tests/fixtures/metacsl_eacsl_wiring/drive.py, FRAMAC_DOCKER_TESTS=1) and ingests its reports here.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from subprocess import CompletedProcess

import pytest

import crash_replay
import eacsl_toolchain
import failure_identity
import fuzz_build
import ledger as L
import pipeline_make as pm
import run_eacsl_fuzz as R
from conftest import ANALYSIS_IMAGE, ROOT, metadata, require_docker_images, write_json
from test_metacsl_eacsl import (
    ALL_PROPERTY_NAMES,
    DEFAULT_PROPS,
    HARNESS_CALL_FRAMES,
    META_EACSL_FIXTURE,
    META_INSTRUMENTED,
    MODULE_FUNCTIONS,
    OUT_BIN,
    PLAIN_INSTRUMENTED,
    SOURCES,
    TARGET_CALL_FRAMES,
    WRITE_FRAMES,
    FakeToolchain,
    eacsl_report,
    fixture_props,
    run_dir,  # noqa: F401  (fixture)
    write_props,
)
from test_metacsl_eacsl import build as fake_build

WIRING_FIXTURE = ROOT / "tests" / "fixtures" / "metacsl_eacsl_wiring"
WIRING_TEMPLATES = "/opt/framac-pipeline/templates"
WIRING_FILE = "src/prog.c"
WIRING_MODULE = "prog"
META_SUFFIX = failure_identity.SECURITY_META_SUFFIX
# What this package appended to the build and fuzz recipes of templates/pipeline.mk.
MK_OPTION = "$(if $(FUZZ_SECURITY_PROPS_$*), --security-props=$(FUZZ_SECURITY_PROPS_$*))"
MK_PREREQUISITE = (
    "$(foreach m,$(FUZZ_MODULES),$(if $(FUZZ_SECURITY_PROPS_$(m)),$(eval build-$(m): $(FUZZ_SECURITY_PROPS_$(m)))))\n"
)
MK_COMMENT = (
    "# FUZZ_SECURITY_PROPS_<mod> is set when security_props.json turns MetAcsl on for E-ACSL (`meta_engines`):\n"
    "# the build and the campaign then name the file (run_eacsl_fuzz.py --security-props), and the build\n"
    "# depends on it. Without the variable both recipes expand to the text they always had.\n"
)


def wiring_props(engines: list[str] | None = None, *, backdoor: bool = False) -> dict:
    """
    The fixture's properties (test_metacsl_eacsl.fixture_props). With `backdoor`, the -DVIOLATE_WRITE
    build's function is an instance of the authentication-state property, as security_props.py lists it
    for a model that holds the function.
    """
    doc = fixture_props(engines)
    if backdoor:
        fid = f"{WIRING_FILE}#backdoor"
        prop = next(p for p in doc["properties"] if p["name"] == "L4_auth_state_login")
        prop["instances"].append(fid)
        doc["obligations"][fid] = [{"class": "l4_auth_state", "property": prop["name"], "reason": "fixture"}]
    return doc


class CachingToolchain(FakeToolchain):
    """The fake toolchain, which also answers the dependency scan of a cached build (`-M`)."""

    def __call__(self, cmd, **kwargs):
        cmd = [str(c) for c in cmd]
        if "-M" in cmd:
            sources = [c for c in cmd if c.endswith(".c")]
            return CompletedProcess(cmd, 0, "".join(f"{Path(s).stem}.o: {s}\n" for s in sources), "")
        return super().__call__(cmd, **kwargs)


@pytest.fixture
def cached_run(run_dir, monkeypatch):  # noqa: F811
    """The fixture's run directory with the build cache on and a fixed toolchain identity."""
    monkeypatch.setenv("FRAMAC_CACHE", "on")
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:wiring-test-image")
    monkeypatch.delenv("FRAMAC_CACHE_MODE", raising=False)
    monkeypatch.delenv("FRAMAC_SHARED_CACHE_DIR", raising=False)
    return run_dir


def cached_build(monkeypatch, fake: FakeToolchain, **kwargs) -> dict:
    return fake_build(monkeypatch, fake, use_cache=True, **kwargs)["compile"]


def meta_outputs() -> dict[str, str]:
    meta_file = OUT_BIN.with_suffix(META_SUFFIX)
    return {
        p.name: p.read_text(encoding="utf-8")
        for p in (meta_file, failure_identity.meta_sidecar_path(meta_file))
        if p.is_file()
    }


# ---------------------------------------------------------------------------------------------------
# The build cache
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_a_build_with_properties_is_cached_and_a_hit_restores_the_meta_file_and_the_sidecar(cached_run, monkeypatch):
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    fake = CachingToolchain()
    first = cached_build(monkeypatch, fake)
    assert first["returncode"] == 0 and first["cache"]["hit"] is False and first["cache"]["key"]
    assert first["security_props"]["status"] == "loaded"
    written = meta_outputs()
    assert sorted(written) == ["fuzz_prog.security_meta.c", "fuzz_prog.security_meta.json"]
    stage1 = len(fake.stage1_cmds)

    # A restored binary without its sidecar would report a violation without its file: both come back.
    for name in written:
        (OUT_BIN.parent / name).unlink()
    Path(first["binary"]).unlink()
    failure_identity._META_SIDECARS.clear()
    again = cached_build(monkeypatch, fake)
    assert again["cache"] == {"hit": True, "key": first["cache"]["key"]}
    assert len(fake.stage1_cmds) == stage1  # nothing was built
    assert meta_outputs() == written and Path(again["binary"]).is_file()
    assert again["security_props"] == first["security_props"]
    assert {k: v for k, v in again.items() if k != "cache"} == {k: v for k, v in first.items() if k != "cache"}
    # The restored sidecar still gives a violation its file and its class.
    report = eacsl_report(
        str(OUT_BIN.with_suffix(META_SUFFIX)).replace("\\", "/"),
        "mix",
        9,
        "Assertion",
        "L4_auth_state_login/meta",
        r"\separated(dst + i, &auth_ok)",
        "",
    )
    failure = failure_identity.parse_runtime_failure(report)
    assert (failure["file"], failure["obligation_class"]) == (WIRING_FILE, "l4_auth_state")


@pytest.mark.unit
def test_the_same_properties_named_another_way_are_the_same_entry(cached_run, monkeypatch):
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    fake = CachingToolchain()
    first = cached_build(monkeypatch, fake)
    named = cached_build(monkeypatch, fake, security_props=str(cached_run / DEFAULT_PROPS))
    assert named["cache"] == {"hit": True, "key": first["cache"]["key"]}
    # The record names the file this build was given, whoever published the entry.
    assert Path(first["security_props"]["props"]) == DEFAULT_PROPS
    assert Path(named["security_props"]["props"]) == cached_run / DEFAULT_PROPS
    # A file written again with the same properties (a new date, a warning) is the same entry too.
    doc = fixture_props(["eacsl"])
    doc["generated_at"], doc["warnings"] = "2027-01-01T00:00:00Z", ["a note"]
    write_props(DEFAULT_PROPS, doc)
    assert cached_build(monkeypatch, fake)["cache"]["hit"] is True


@pytest.mark.unit
def test_a_changed_property_text_or_changed_meta_flags_miss(cached_run, monkeypatch):
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    fake = CachingToolchain()
    first = cached_build(monkeypatch, fake)
    keys = {first["cache"]["key"]}

    def miss(label: str) -> None:
        built = cached_build(monkeypatch, fake)
        assert built["cache"]["hit"] is False and built["cache"]["key"] not in keys, label
        keys.add(built["cache"]["key"])

    doc = fixture_props(["eacsl"])
    wiped = next(p for p in doc["properties"] if p["name"] == "L6_wiped_session_key")
    wiped["acsl"] = wiped["acsl"].replace("i < 16", "i < 15")
    write_props(DEFAULT_PROPS, doc)
    miss("property text")
    assert "i < 15" in OUT_BIN.with_suffix(META_SUFFIX).read_text(encoding="utf-8")

    doc = fixture_props(["eacsl"])
    doc["preamble"] += "\n/*@ predicate another_one(integer x) = x == 0; */"
    write_props(DEFAULT_PROPS, doc)
    miss("preamble")

    doc = fixture_props(["eacsl"])
    doc["properties"][2]["instances"].append(f"{WIRING_FILE}#mix")  # the sidecar's instances
    write_props(DEFAULT_PROPS, doc)
    miss("instances")

    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    flags, options = eacsl_toolchain.EACSL_META_FLAGS, eacsl_toolchain.EACSL_META_STAGE_OPTIONS
    monkeypatch.setattr(eacsl_toolchain, "EACSL_META_FLAGS", ("-meta", "-meta-warn-key unknown-func=active"))
    miss("MetAcsl flags")
    monkeypatch.setattr(eacsl_toolchain, "EACSL_META_FLAGS", flags)
    monkeypatch.setattr(eacsl_toolchain, "EACSL_META_STAGE_OPTIONS", ("--then", "--e-acsl-extra"))
    miss("stage options")
    monkeypatch.setattr(eacsl_toolchain, "EACSL_META_STAGE_OPTIONS", options)
    # Everything back as it was: the first entry is still there.
    assert cached_build(monkeypatch, fake)["cache"] == {"hit": True, "key": first["cache"]["key"]}


@pytest.mark.unit
def test_builds_with_and_without_the_properties_never_share_an_entry(cached_run, monkeypatch):
    fake = CachingToolchain()
    plain = cached_build(monkeypatch, fake)  # no file at all
    write_props(DEFAULT_PROPS, fixture_props([]))
    off = cached_build(monkeypatch, fake)
    assert off["cache"] == {"hit": True, "key": plain["cache"]["key"]} and "security_props" not in off
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    with_props = cached_build(monkeypatch, fake)
    assert with_props["cache"]["hit"] is False and with_props["cache"]["key"] != plain["cache"]["key"]
    assert "-meta" in with_props["command"]
    none = cached_build(monkeypatch, fake, security_props="none")
    assert none["cache"] == {"hit": True, "key": plain["cache"]["key"]}
    assert "-meta" not in none["command"] and "security_props" not in none
    # The key material of a build without properties is the one it always had.
    args = (SOURCES, OUT_BIN, "gcc_x86_64", "-I.", "all", True, MODULE_FUNCTIONS, "", True, False, True)
    assert "security_meta" not in fuzz_build._eacsl_cache_material(*args)
    plan = fuzz_build.resolve_security_meta(None, SOURCES, OUT_BIN)
    material = fuzz_build._eacsl_cache_material(*args, security_meta=plan)
    assert sorted(material["security_meta"]) == [
        "functions",
        "harness_functions",
        "left_out",
        "max_rejected",
        "properties",
        "stage",
        "text",
    ]
    assert str(DEFAULT_PROPS) not in json.dumps(material) and DEFAULT_PROPS.as_posix() not in json.dumps(material)


@pytest.mark.unit
def test_a_rejected_property_is_part_of_the_cached_outcome(cached_run, monkeypatch):
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))

    def stage1(cmd, n):
        if "L5_sanitized_logmsg" in Path(cmd[-1]).read_text(encoding="utf-8"):
            log = "[meta] User Error: Error during the typing of a HILARE!\n"
            log += f"  What: the HILARE named 'L5_sanitized_logmsg' ({cmd[-1]}:18)\n  Why: unbound logic function\n"
            return 1, log, "", ""
        return 0, "", "", META_INSTRUMENTED

    fake = CachingToolchain(stage1)
    first = cached_build(monkeypatch, fake)
    assert first["cache"]["hit"] is False and len(fake.stage1_cmds) == 2
    rejected = [{"property": "L5_sanitized_logmsg", "reason": "unbound logic function"}]
    assert first["security_props"]["rejected"] == rejected
    reduced = meta_outputs()
    for name in reduced:
        (OUT_BIN.parent / name).unlink()
    again = cached_build(monkeypatch, fake)
    assert again["cache"]["hit"] is True and len(fake.stage1_cmds) == 2
    assert again["security_props"]["rejected"] == rejected and meta_outputs() == reduced
    assert "L5_sanitized_logmsg" not in json.loads(reduced["fuzz_prog.security_meta.json"])["properties"]


@pytest.mark.unit
def test_a_build_the_properties_break_is_never_published(cached_run, monkeypatch):
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))

    def stage1(cmd, n):
        if cmd[-1].endswith(META_SUFFIX):
            return 1, "", "[e-acsl] internal error", ""
        return 0, "", "", PLAIN_INSTRUMENTED

    fake = CachingToolchain(stage1)
    first = cached_build(monkeypatch, fake)
    assert first["returncode"] == 0 and first["security_props"]["status"] == "dropped"
    assert "-meta" not in first["command"] and first["cache"]["hit"] is False
    with_meta = [c for c in fake.stage1_cmds if c[-1].endswith(META_SUFFIX)]
    assert len(with_meta) == 1
    # The next build tries the properties again (the plain build under it is a hit).
    again = cached_build(monkeypatch, fake)
    assert again["security_props"]["status"] == "dropped" and again["cache"]["hit"] is True
    assert len([c for c in fake.stage1_cmds if c[-1].endswith(META_SUFFIX)]) == 2
    # Once the toolchain takes them, the build with them is made and cached.
    fixed = CachingToolchain()
    built = cached_build(monkeypatch, fixed)
    assert built["security_props"]["status"] == "loaded" and built["cache"]["hit"] is False
    assert cached_build(monkeypatch, fixed)["cache"]["hit"] is True


@pytest.mark.unit
def test_without_the_cache_a_build_with_properties_is_as_before(run_dir, monkeypatch):  # noqa: F811
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    comp = fake_build(monkeypatch, FakeToolchain())["compile"]
    assert comp["cache"] == {"hit": False, "key": None} and comp["security_props"]["status"] == "loaded"


# ---------------------------------------------------------------------------------------------------
# run_eacsl_fuzz.py: the option, the reports, the warnings
# ---------------------------------------------------------------------------------------------------


def run_build_mode(monkeypatch, fake: FakeToolchain, out_json: str, *extra: str) -> tuple[int, bytes]:
    """`run_eacsl_fuzz.py build` on the fake toolchain: its exit code and the report it wrote."""
    real = fuzz_build.compile_eacsl_binary
    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", lambda *a, **k: real(*a, **{"runner": fake, **k}))
    argv = [
        "build", "--module", WIRING_MODULE, "--sources", *SOURCES, "--out-bin", str(OUT_BIN), "--engine", "eacsl",
        "--functions", *MODULE_FUNCTIONS, "--no-cache", *extra, "--out-json", out_json,
    ]  # fmt: skip
    try:
        rc = R.main(argv)
    finally:
        monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", real)
    return rc, Path(out_json).read_bytes()


@pytest.mark.unit
def test_engine_off_the_build_call_the_report_and_the_output_are_todays(run_dir, monkeypatch, capsys):  # noqa: F811
    fake = FakeToolchain()
    reports: dict[str, bytes] = {}
    outputs: dict[str, tuple[str, str]] = {}

    def one(label: str, *extra: str) -> None:
        rc, reports[label] = run_build_mode(monkeypatch, fake, "build.json", *extra)
        captured = capsys.readouterr()
        outputs[label] = (captured.out, captured.err)
        assert rc == 0, label

    one("no file")
    write_props(DEFAULT_PROPS, fixture_props([]))
    one("engine off")
    write_props(DEFAULT_PROPS, fixture_props(["eva"]))
    one("eva only")
    one("eva only, named", f"--security-props={DEFAULT_PROPS.as_posix()}")
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    one("none", "--security-props=none")
    for label, data in reports.items():
        assert data == reports["no file"], label
        assert outputs[label] == outputs["no file"], label
    assert b"security_props" not in reports["no file"] and "security props" not in outputs["no file"][1]
    assert all(cmd == fake.stage1_cmds[0] for cmd in fake.stage1_cmds) and len(fake.stage1_cmds) == 5

    # The keyword reaches the build only when the option is given.
    parser_args = type("Args", (), {})()
    for name, value in (
        ("engine", "auto"), ("selftest_json", None), ("machdep", "m"), ("cppflags", ""), ("ldflags", ""),
        ("rte", "all"), ("functions", None), ("no_variadic_translation", False), ("warn_unsigned_downcast", False),
        ("no_rte_initialized", False), ("no_libc_checks", False), ("dag", None), ("module", ""),
    ):  # fmt: skip
        setattr(parser_args, name, value)
    assert "security_props" not in R._build_options(parser_args)
    parser_args.security_props = None
    assert "security_props" not in R._build_options(parser_args)
    parser_args.security_props = "p.json"
    assert R._build_options(parser_args)["security_props"] == "p.json"


@pytest.mark.unit
def test_engine_on_the_build_report_shows_the_properties_and_warns(run_dir, monkeypatch, capsys):  # noqa: F811
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    rc, data = run_build_mode(monkeypatch, FakeToolchain(), "build.json")
    captured = capsys.readouterr()
    report = json.loads(data)
    assert rc == 0 and report["security_props"]["status"] == "loaded"
    assert report["security_props"] == report["compile"]["security_props"]
    # The fake's instrumented file checks the write property in `backdoor`, which the plan does not list.
    assert report["security_props"]["unplanned_instances"] == {"L4_auth_state_login": ["backdoor"]}
    warnings = report["security_props_warnings"]
    assert any(w.startswith("unplanned instances: L4_auth_state_login is also checked in backdoor") for w in warnings)
    assert any(w.startswith("not translated: no run-time check for ") for w in warnings)
    for line in warnings:
        assert f"security props [{WIRING_MODULE}]: {line}" in captured.err
    # What is printed carries them too (the summary drops `compile`).
    printed = json.loads(captured.out)
    assert "compile" not in printed and printed["security_props_warnings"] == warnings


@pytest.mark.unit
def test_a_dropped_build_is_a_visible_warning(run_dir, monkeypatch, capsys):  # noqa: F811
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))

    def stage1(cmd, n):
        if cmd[-1].endswith(META_SUFFIX):
            return 1, "", "[e-acsl] internal error", ""
        return 0, "", "", PLAIN_INSTRUMENTED

    rc, data = run_build_mode(monkeypatch, FakeToolchain(stage1), "build.json")
    captured = capsys.readouterr()
    report = json.loads(data)
    assert rc == 0 and report["status"] == "built" and report["security_props"]["status"] == "dropped"
    (warning,) = report["security_props_warnings"]
    assert warning.startswith("dropped: this binary checks NO MetAcsl property at run time (")
    assert all(name in warning for name in ALL_PROPERTY_NAMES) and ".security_meta.log" in warning
    assert f"security props [{WIRING_MODULE}]: dropped: " in captured.err


@pytest.mark.unit
def test_what_the_warnings_say_for_each_outcome():
    assert R.security_props_warnings(None) == []
    loaded = {"status": "loaded", "props": "p.json", "left_out": [], "not_translated": [], "unplanned_instances": {}}
    assert R.security_props_warnings(loaded) == []
    # A module the properties do not speak of is no warning (fuzz_build.resolve_security_meta's reason).
    no_instance = {"status": "skipped", "props": "p.json", "left_out": [], "reason": R._SECURITY_PROPS_NO_INSTANCE}
    assert R.security_props_warnings(no_instance) == []
    toolchain = {"status": "skipped", "props": "p.json", "reason": "no target function is listed"}
    assert R.security_props_warnings(toolchain) == [
        "skipped: this binary checks no MetAcsl property at run time (no target function is listed)"
    ]
    error = {"status": "error", "props": "gone.json", "reason": "security properties file not found"}
    (line,) = R.security_props_warnings(error)
    assert line.startswith("error: gone.json could not be loaded (security properties file not found)")
    full = {
        **loaded,
        "rejected": [{"property": "L4_a", "reason": "unbound logic variable g"}],
        "left_out": [{"property": "L4_b", "reason": "the harness names its target admin"}],
        "not_translated": ["L6_c"],
        "unplanned_instances": {"L4_d": ["f", "g"]},
    }
    lines = R.security_props_warnings(full)
    assert [ln.split(":")[0] for ln in lines] == ["rejected", "left out", "not translated", "unplanned instances"]
    assert "L4_a" in lines[0] and "unbound logic variable g" in lines[0]
    assert "L4_b" in lines[1] and "L6_c" in lines[2] and "L4_d is also checked in f, g" in lines[3]


@pytest.mark.unit
def test_the_reason_of_a_module_without_instances_is_the_one_the_build_gives(run_dir):  # noqa: F811
    doc = fixture_props(["eacsl"])
    for prop in doc["properties"]:
        prop["instances"] = ["lib/other.c#f"]
    doc["obligations"] = {}
    write_props(DEFAULT_PROPS, doc)
    found = fuzz_build.resolve_security_meta(None, SOURCES, OUT_BIN)
    assert found["status"] == "skipped" and found["reason"] == R._SECURITY_PROPS_NO_INSTANCE
    assert L._fuzz_security_props_lost({"security_props": found}) is None


@pytest.mark.unit
def test_build_security_props_reads_the_eacsl_attempt_the_sanitizers_replaced():
    record = {"status": "dropped", "reason": "x; the build without them fails too"}
    build = {"compile": {"engine": "sanitizers"}, "eacsl_compile_attempt": {"security_props": record}}
    assert R.build_security_props(build) == record
    assert R.build_security_props({"compile": {"engine": "eacsl"}, "eacsl_compile_attempt": None}) is None
    res: dict = {"module": "m"}
    R.note_security_props(res, None)
    assert res == {"module": "m"}


@pytest.mark.unit
def test_harness_induced_failures_are_listed_from_the_artifacts():
    induced = {"meta_property": "L4_auth_required_login", "function": "admin", "caller": "LLVMFuzzerTestOneInput"}
    artifacts = [
        {"artifact": "c/crash-1", "fingerprint": "fp1", "failure": {**induced, "harness_induced": True}},
        {"artifact": "c/crash-2", "fingerprint": "fp2", "failure": {**induced, "caller": "process", "harness_induced": False}},
        {"artifact": "c/crash-3", "fingerprint": "fp3", "failure": {"function": "mix", "kind": "assertion"}},
        {"artifact": "c/crash-4", "fingerprint": None, "failure": None},
    ]  # fmt: skip
    assert R.harness_induced_failures(artifacts) == [
        {
            "artifact": "c/crash-1",
            "property": "L4_auth_required_login",
            "function": "admin",
            "caller": "LLVMFuzzerTestOneInput",
            "fingerprint": "fp1",
        }
    ]
    assert R.harness_induced_failures(None) == []


@pytest.mark.unit
@pytest.mark.parametrize("mode", ["replay-candidates", "minimize-candidates"])
def test_the_candidate_subcommands_take_the_option(monkeypatch, tmp_path, capsys, mode):
    seen: list[dict] = []
    name = "replay_candidates" if mode == "replay-candidates" else "minimize_candidates"

    def fake(*args, **kwargs):
        seen.append(kwargs)
        return {"status": "ok"}

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(crash_replay, name, fake)
    assert R.main([mode]) == 0
    assert R.main([mode, "--security-props", "run/props.json"]) == 0
    assert R.main([mode, "--security-props=none"]) == 0
    capsys.readouterr()
    assert "security_props" not in seen[0]
    assert [k.get("security_props") for k in seen[1:]] == ["run/props.json", "none"]


@pytest.mark.unit
def test_the_guardrail_does_not_take_the_option(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    argv = ["guardrail", "--sources", "a.c", "--out-bin", "g", "--corpus-dir", "c", "--out-json", "g.json"]
    with pytest.raises(SystemExit):
        R.main([*argv, "--security-props", "p.json"])
    assert "--security-props" in capsys.readouterr().err


@pytest.mark.unit
def test_a_direct_eacsl_build_is_plain_with_the_engine_on(run_dir, monkeypatch):  # noqa: F811
    # The guardrail, the loop-seed check and the selftest call compile_eacsl_binary themselves: neither
    # the run's default file nor $FRAMAC_SECURITY_PROPS reaches them (only build_module_binary reads them).
    write_props(DEFAULT_PROPS, wiring_props(["eacsl"]))
    monkeypatch.setenv(fuzz_build.SECURITY_PROPS_ENV, str(DEFAULT_PROPS))
    fake = FakeToolchain()
    comp = fuzz_build.compile_eacsl_binary(
        SOURCES, OUT_BIN, cppflags="", functions=list(MODULE_FUNCTIONS), ldflags_extra="", use_cache=False, runner=fake
    )
    assert comp["returncode"] == 0 and "security_props" not in comp
    assert len(fake.stage1_cmds) == 1 and "-meta" not in " ".join(fake.stage1_cmds[0])
    assert "--then-last" not in fake.stage1_cmds[0]
    assert not OUT_BIN.with_suffix(failure_identity.SECURITY_META_SUFFIX).exists()


# ---------------------------------------------------------------------------------------------------
# crash_replay.py
# ---------------------------------------------------------------------------------------------------

REPLAY_SPEC = {"sources": ["a.c", "workspace/harnesses/harness_m.c"], "cppflags": "-I.", "ldflags": ""}
TODAYS_REPLAY_KEYWORDS = {
    "attribution",
    "engine",
    "selftest_json",
    "machdep",
    "cppflags",
    "ldflags",
    "rte_initialized",
    "libc_checks",
}


@pytest.mark.unit
def test_a_candidate_replay_names_the_file_make_names_unless_told_otherwise(monkeypatch):
    seen: list[dict] = []

    def fake(module, sources, out_bin, **kwargs):
        seen.append(kwargs)
        return {"binary": None, "reason": "test"}

    monkeypatch.setattr(crash_replay, "prepare_replay_binary", fake)
    make_file = pm.SECURITY_PROPS_JSON

    def prepared(spec_props: str | None, option: str | None, cross: bool = False) -> dict:
        spec = {**REPLAY_SPEC, **({"security_props": spec_props} if spec_props else {})}
        common = {"attribution": False, "selftest_json": None, "machdep": "gcc_x86_64"}
        extra = {"security_props": option} if option is not None else {}
        if cross:
            crash_replay._cross_engine_replay(
                module="m", harness_module="m", spec=spec, reproducers=[], other="eacsl", bin_dir=Path("b"),
                scratch=Path("s"), per_input_timeout=5, prepared_cache={}, **common, **extra,
            )  # fmt: skip
        else:
            crash_replay._prepared_replay(
                "m", spec, "eacsl", own_engine="eacsl", bin_dir=Path("b"), prepared_by_key={}, **common, **extra
            )
        return seen[-1]

    for cross in (False, True):
        # No engine in the run, no option: the keywords of every replay build before this option existed.
        assert set(prepared(None, None, cross)) == TODAYS_REPLAY_KEYWORDS
        assert prepared(make_file, None, cross)["security_props"] == make_file
        assert prepared(make_file, "none", cross)["security_props"] == "none"
        assert prepared(None, "/elsewhere/props.json", cross)["security_props"] == "/elsewhere/props.json"


@pytest.mark.unit
def test_a_replay_build_passes_the_option_on_and_reports_the_properties(run_dir, monkeypatch):  # noqa: F811
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    seen: list[dict] = []
    real = fuzz_build.build_module_binary

    def spy(sources, out_bin, **kwargs):
        seen.append(kwargs)
        compile_real = fuzz_build.compile_eacsl_binary
        monkeypatch.setattr(
            fuzz_build, "compile_eacsl_binary", lambda *a, **k: compile_real(*a, **{"runner": FakeToolchain(), **k})
        )
        try:
            return real(sources, out_bin, **kwargs)
        finally:
            monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", compile_real)

    monkeypatch.setattr(fuzz_build, "build_module_binary", spy)
    options = {"engine": "eacsl", "functions": list(MODULE_FUNCTIONS), "use_cache": False, "attribution": False}
    elsewhere = Path("agents/v1/scratch/out/fuzz_prog")
    prepared = crash_replay.prepare_replay_binary(
        WIRING_MODULE, SOURCES, elsewhere, security_props=str(run_dir / DEFAULT_PROPS), **options
    )
    assert seen[-1]["security_props"] == str(run_dir / DEFAULT_PROPS)
    assert prepared["security_props"]["status"] == "loaded"
    assert elsewhere.with_suffix(META_SUFFIX).is_file()
    report = crash_replay.replay_report(WIRING_MODULE, [], Path("scratch"), prepared=prepared)
    assert report["security_props"] == prepared["security_props"] and report["reason"] == "no_inputs"

    off = crash_replay.prepare_replay_binary(WIRING_MODULE, SOURCES, elsewhere, security_props="none", **options)
    plain = crash_replay.replay_report(WIRING_MODULE, [], Path("scratch"), prepared=off)
    assert "security_props" not in off and "security_props" not in plain


# ---------------------------------------------------------------------------------------------------
# Make: the variable, the recipes, the build spec of the replays
# ---------------------------------------------------------------------------------------------------


def plan_run(run: Path, doc: dict | None) -> Path:
    """A run directory pipeline_make.py can plan: one module that is fuzzed, with the fixture as its target."""
    write_json(run / "run-metadata.json", {**metadata(), "profile": "quick"})
    module = {
        "tier": "Tier 1A (Untrusted Binary / Network Parser)",
        "run_eacsl_fuzz": True,
        "run_eva": True,
        "required_sources": ["src/prog.c"],
        "cppflags": [],
    }
    write_json(run / pm.DAG_JSON, {"modules": {WIRING_MODULE: module}})
    sidecar = {"module": WIRING_MODULE, "sources": ["workspace/work/src/prog.c"], "cppflags": "-Iworkspace/work/src"}
    write_json(run / pm.HARNESS_DIR / "harness_prog.json", {**sidecar, "include_source": False, "entry_fn": "process"})
    shutil.copy(META_EACSL_FIXTURE / "harness_prog.c", run / pm.HARNESS_DIR / "harness_prog.c")
    (run / "workspace/work/src").mkdir(parents=True, exist_ok=True)
    for name in ("prog.c", "prog.h"):
        shutil.copy(META_EACSL_FIXTURE / name, run / "workspace/work/src" / name)
    props = run / pm.SECURITY_PROPS_JSON
    if doc is None:
        props.unlink(missing_ok=True)
    else:
        write_json(props, doc)
    return run


@pytest.mark.unit
def test_modules_mk_names_the_file_for_the_fuzz_build_only_with_the_engine_on(tmp_path):
    run = plan_run(tmp_path, None)
    assert pm.fuzz_security_props(run) is None
    pm.generate(run, templates_dir=WIRING_TEMPLATES)
    without = (run / pm.MODULES_MK).read_bytes()
    spec_without = pm.module_build_spec(WIRING_MODULE, run)
    json_without = pm.build_plan(run, templates_dir=WIRING_TEMPLATES).modules[WIRING_MODULE].to_json()
    assert b"FUZZ_SECURITY_PROPS" not in without and "security_props" not in spec_without

    # The file is there and E-ACSL is not among its engines: modules.mk does not move, byte for byte.
    for doc in (fixture_props(None), fixture_props([])):
        plan_run(run, doc)
        assert pm.fuzz_security_props(run) is None
        assert pm.generate(run, templates_dir=WIRING_TEMPLATES)["changed"] is False
        assert (run / pm.MODULES_MK).read_bytes() == without
        assert pm.module_build_spec(WIRING_MODULE, run) == spec_without
        assert pm.build_plan(run, templates_dir=WIRING_TEMPLATES).modules[WIRING_MODULE].to_json() == json_without
    # Eva alone turns its own variable on, not this one.
    plan_run(run, fixture_props(["eva"]))
    pm.generate(run, templates_dir=WIRING_TEMPLATES)
    eva_only = (run / pm.MODULES_MK).read_text(encoding="utf-8")
    assert "EVA_SECURITY_PROPS_prog" in eva_only and "FUZZ_SECURITY_PROPS" not in eva_only
    assert "security_props" not in pm.module_build_spec(WIRING_MODULE, run)
    (run / pm.SECURITY_PROPS_JSON).write_text("{not json", encoding="utf-8")
    assert pm.fuzz_security_props(run) is None

    plan_run(run, fixture_props(["eacsl"]))
    assert pm.fuzz_security_props(run) == pm.SECURITY_PROPS_JSON
    pm.generate(run, templates_dir=WIRING_TEMPLATES)
    with_props = (run / pm.MODULES_MK).read_text(encoding="utf-8")
    line = f"FUZZ_SECURITY_PROPS_prog := {pm.SECURITY_PROPS_JSON}\n"
    # One line more, after the module's other fuzz variables, and nothing else moves.
    assert with_props.replace(line, "").encode() == without
    assert with_props.index(line) > with_props.index("FUZZ_ENGINE_prog := ")
    spec = pm.module_build_spec(WIRING_MODULE, run)
    assert spec == {**spec_without, "security_props": pm.SECURITY_PROPS_JSON}
    plan = pm.build_plan(run, templates_dir=WIRING_TEMPLATES)
    assert plan.modules[WIRING_MODULE].to_json() == {**json_without, "fuzz_security_props": pm.SECURITY_PROPS_JSON}
    # The replays take it from the same place.
    assert crash_replay._security_props_option(spec, None) == {"security_props": pm.SECURITY_PROPS_JSON}
    assert crash_replay._security_props_option(spec_without, None) == {}


def pipeline_mk_before(text: str) -> str:
    """templates/pipeline.mk without what this package added to its fuzz rules."""
    assert text.count(MK_COMMENT) == 1
    return text.replace(MK_COMMENT, "").replace(MK_OPTION, "").replace(MK_PREREQUISITE, "")


@pytest.mark.unit
def test_the_fuzz_rules_get_the_option_without_moving_a_byte_of_the_recipe():
    text = (ROOT / "templates" / "pipeline.mk").read_text(encoding="utf-8")
    # Attached to the last word before it, inside one $(if): an unset variable expands to nothing at all.
    assert text.count("--engine=$(FUZZ_ENGINE_$*)" + MK_OPTION + " \\\n") == 2
    assert text.count("FUZZ_SECURITY_PROPS_$*") == 4 and text.count(MK_PREREQUISITE) == 1
    build_rule = text.split("$(BUILD_TARGETS): build-%:", 1)[1].split("\n\n", 1)[0]
    fuzz_rule = text.split("$(FUZZ_TARGETS): fuzz-%:", 1)[1].split("\n\n", 1)[0]
    assert MK_OPTION in build_rule and MK_OPTION in fuzz_rule
    assert build_rule.rstrip("\n").endswith(MK_PREREQUISITE.rstrip("\n"))
    before = pipeline_mk_before(text)
    assert "FUZZ_SECURITY_PROPS" not in before
    # The recipes as they were before this package.
    assert (
        "\t\t$(if $(FUZZ_NO_RTE_INIT_$*),--no-rte-initialized) $(if $(FUZZ_NO_LIBC_CHECKS_$*),--no-libc-checks) \\\n"
        "\t\t--engine=$(FUZZ_ENGINE_$*) \\\n"
        "\t\t--out-json workspace/build/$*.build.json\n"
        "\n"
    ) in before
    assert (
        "\t\t--engine=$(FUZZ_ENGINE_$*) \\\n"
        "\t\t--cppflags=$(CPPFLAGS_$*) --ldflags=$(LDFLAGS_$*) \\\n"
        "\t\t--selftest-json $(SELFTEST_JSON) --out-json workspace/reports/fuzz/$*.json\n"
    ) in before
    # The candidate replays read the file from the module's build spec, not from a recipe.
    replay_rule = text.split("\nreplay: ingest\n", 1)[1].split("\n\n", 1)[0]
    assert "--security-props" not in replay_rule


# ---------------------------------------------------------------------------------------------------
# ledger.py ingest-fuzz
# ---------------------------------------------------------------------------------------------------

WIRING_FUNCTIONS = (*MODULE_FUNCTIONS, "backdoor")
FUZZ_REPORT = "workspace/reports/fuzz/prog.json"


def unit_id(function: str, cls: str) -> str:
    return f"{WIRING_FILE}#{function}::{cls}"


def seed_ledger(run: Path, doc: dict) -> None:
    dag = {
        "callgraph_source": "frama_c",
        "modules": {WIRING_MODULE: {"tier": "Tier 1A (Untrusted Binary / Network Parser)"}},
        "functions": {
            name: {"name": name, "file": WIRING_FILE, "module": WIRING_MODULE, "wave": 0, "has_loops": False}
            for name in WIRING_FUNCTIONS
        },
    }
    write_json(run / pm.SECURITY_PROPS_JSON, doc)
    write_json(run / pm.DAG_JSON, dag)
    L.cmd_seed(run / pm.DAG_JSON, [], "frama_c")


def ledger_state() -> tuple[dict, dict]:
    return L.load_state()


def artifact(index: int, failure: dict | None) -> dict:
    return {
        "artifact": f"workspace/crashes/prog/crash-{index:040x}",
        "kind": "crash",
        "sha256": f"{index:064x}",
        "reproducible": True,
        "failure": failure,
        "fingerprint": failure_identity.failure_fingerprint(failure) if failure else None,
        "engine": "eacsl",
    }


def ingest(failures: list[dict], path: str = FUZZ_REPORT, **extra) -> dict:
    report = {
        "mode": "campaign",
        "module": WIRING_MODULE,
        "status": "crash_found" if failures else "clean",
        "engine_used": "eacsl",
        "artifacts": [artifact(i, f) for i, f in enumerate(failures)],
        **extra,
    }
    write_json(Path(path), report)
    return L.cmd_ingest_fuzz([Path(path)])


@pytest.fixture
def wired(run_dir):  # noqa: F811
    """The run directory with a seeded ledger and a built meta file: (meta file, its line of each property)."""
    doc = wiring_props(["eacsl"], backdoor=True)
    seed_ledger(run_dir, doc)
    plan = fuzz_build.resolve_security_meta(None, SOURCES, OUT_BIN)
    written = fuzz_build.write_security_meta(plan, OUT_BIN)
    lines = {name: int(line) for line, name in written["line_names"].items()}
    return written["meta_file"], lines


def violation(wired, function: str, prop: str, kind: str = "Assertion", frames: str = "") -> dict:  # noqa: F811
    meta_file, lines = wired
    failure = failure_identity.parse_runtime_failure(
        eacsl_report(meta_file, function, lines[prop], kind, f"{prop}/meta", "P(x)", frames)
    )
    assert failure["meta_property"] == prop and failure["file"] == WIRING_FILE
    return failure


def touched(units: dict) -> dict[str, str]:
    """The status of every unit a detection reached."""
    return {cid: u["status"] for cid, u in units.items() if u["result_fingerprints"] or u["status"] != "planned"}


@pytest.mark.unit
def test_the_fixture_seeds_a_unit_per_instance_and_class(wired):
    units, _ = ledger_state()
    meta_units = sorted(cid for cid, u in units.items() if u["obligation_class"] in L.METACSL_CLASSES)
    assert meta_units == sorted(
        [
            unit_id("backdoor", "l4_auth_state"),
            unit_id("mix", "l4_auth_state"),
            unit_id("process", "l4_auth_state"),
            unit_id("process", "l4_auth_required"),
            unit_id("process", "l5_sanitized"),
            unit_id("process", "l6_no_leak"),
            unit_id("session_close", "l6_wiped"),
        ]
    )
    assert touched(units) == {}


@pytest.mark.unit
def test_each_violation_is_a_candidate_on_the_unit_of_its_class(wired):
    failures = [
        violation(wired, "backdoor", "L4_auth_state_login", frames=WRITE_FRAMES),
        violation(wired, "process", "L5_sanitized_emit"),
        violation(wired, "process", "L5_sanitized_logmsg"),
        violation(wired, "process", "L6_no_leak_session_key"),
        violation(wired, "session_close", "L6_wiped_session_key", kind="Postcondition"),
    ]
    stats = ingest(failures)
    units, candidates = ledger_state()
    assert stats["candidates"] == 5 and len(candidates) == 5  # three properties in `process`: three candidates
    linked = {c["property"]["predicate"].split(":")[0]: c["linked_units"] for c in candidates.values()}
    assert linked == {
        "L4_auth_state_login": [unit_id("backdoor", "l4_auth_state")],
        "L5_sanitized_emit": [unit_id("process", "l5_sanitized")],
        "L5_sanitized_logmsg": [unit_id("process", "l5_sanitized")],
        "L6_no_leak_session_key": [unit_id("process", "l6_no_leak")],
        "L6_wiped_session_key": [unit_id("session_close", "l6_wiped")],
    }
    assert touched(units) == {
        unit_id("backdoor", "l4_auth_state"): "candidate",
        unit_id("process", "l5_sanitized"): "candidate",
        unit_id("process", "l6_no_leak"): "candidate",
        unit_id("session_close", "l6_wiped"): "candidate",
    }
    assert len(units[unit_id("process", "l5_sanitized")]["result_fingerprints"]) == 2
    evidence = units[unit_id("session_close", "l6_wiped")]["evidence"][-1]
    assert evidence["result"] == "fuzz_failure" and "meta_L6_wiped_session_key" in evidence["summary"]
    assert not L.validate_ledger(list(units.values()))


@pytest.mark.unit
def test_a_failed_precondition_is_the_callers_unit(wired):
    failure = violation(wired, "admin", "L4_auth_required_login", "Precondition", TARGET_CALL_FRAMES)
    assert (failure["function"], failure["caller"], failure["harness_induced"]) == ("admin", "process", False)
    ingest([failure])
    units, candidates = ledger_state()
    (cand,) = candidates.values()
    # The identity stays the protected function's; the obligation is its caller's.
    assert cand["location"]["function"] == "admin" and cand["fingerprint"].startswith(f"{WIRING_FILE}#admin::")
    assert cand["linked_units"] == [unit_id("process", "l4_auth_required")]
    assert touched(units) == {unit_id("process", "l4_auth_required"): "candidate"}
    assert "at its call in process: the unit is the caller's" in cand["notes"][0]

    # Without a caller in the report (no stack), nothing is guessed.
    no_stack = violation(wired, "admin", "L4_auth_required_login", "Precondition")
    assert "caller" not in no_stack
    route = L._fuzz_meta_route(units, no_stack, WIRING_FILE, "admin", {})
    assert route["linked"] == [] and "names no caller" in route["notes"][0]


@pytest.mark.unit
def test_a_harness_induced_failure_is_no_candidate_and_touches_no_unit(wired):
    failure = violation(wired, "admin", "L4_auth_required_login", "Precondition", HARNESS_CALL_FRAMES)
    assert failure["harness_induced"] is True and failure["caller"] == "LLVMFuzzerTestOneInput"
    before = json.dumps(ledger_state()[0], sort_keys=True)
    stats = ingest([failure])
    units, candidates = ledger_state()
    assert candidates == {} and stats["candidates"] == 0
    assert json.dumps(units, sort_keys=True) == before
    assert stats["meta_harness_induced"] == [
        {
            "module": WIRING_MODULE,
            "property": "L4_auth_required_login",
            "function": "admin",
            "caller": "LLVMFuzzerTestOneInput",
            "artifact": f"workspace/crashes/prog/crash-{0:040x}",
            "fingerprint": failure_identity.failure_fingerprint(failure),
        }
    ]
    # The same failure from a caller in the target is a candidate: `harness_induced` alone decides.
    ingest([violation(wired, "admin", "L4_auth_required_login", "Precondition", TARGET_CALL_FRAMES)])
    assert len(ledger_state()[1]) == 1


@pytest.mark.unit
def test_an_unplanned_instance_links_no_unit(wired):
    # `mix` has a unit of the class, for its own instance: the report says where MetAcsl went past the plan.
    failure = violation(wired, "mix", "L4_auth_state_login")
    section = {"status": "loaded", "unplanned_instances": {"L4_auth_state_login": ["mix"]}}
    ingest([failure], security_props=section)
    units, candidates = ledger_state()
    (cand,) = candidates.values()
    assert cand["linked_units"] == [] and touched(units) == {}
    assert "mix is not an instance of L4_auth_state_login" in cand["notes"][0]
    # A function without any unit of the class, and no word of it in the report: no unit either.
    route = L._fuzz_meta_route(units, violation(wired, "login", "L4_auth_state_login"), WIRING_FILE, "login", {})
    assert route["cls"] == "l4_auth_state" and route["linked"] == []
    assert "no ledger unit for login::l4_auth_state" in route["notes"][0]


@pytest.mark.unit
def test_a_failed_guard_is_an_rte_candidate_at_the_function_not_a_violation(wired):
    meta_file, lines = wired
    text = eacsl_report(
        meta_file, "process", lines["L5_sanitized_logmsg"], "E-ACSL RTE", "memory access", r"\valid_read(s + i)", ""
    )
    failure = failure_identity.parse_runtime_failure(text)
    assert failure["meta_guard"] == "memory access" and failure["obligation_class"] == "l5_sanitized"
    ingest([failure])
    units, candidates = ledger_state()
    (cand,) = candidates.values()
    assert cand["linked_units"] == [unit_id("process", "rte")]
    assert touched(units) == {unit_id("process", "rte"): "candidate"}
    assert "not a violation of the property" in cand["notes"][0]
    assert units[unit_id("process", "l5_sanitized")]["status"] == "planned"


@pytest.mark.unit
def test_the_class_is_the_failures_when_the_ledger_knows_it(wired, monkeypatch):
    units, _ = ledger_state()
    failure = violation(wired, "process", "L5_sanitized_emit")
    # A class another package adds to the shared constant flows through, whatever the name spells.
    monkeypatch.setattr(L, "METACSL_CLASSES", (*L.METACSL_CLASSES, "l3_isolation"))
    units[unit_id("process", "l3_isolation")] = {
        **units[unit_id("process", "l5_sanitized")],
        "coverage_id": unit_id("process", "l3_isolation"),
        "obligation_class": "l3_isolation",
    }
    route = L._fuzz_meta_route(units, {**failure, "obligation_class": "l3_isolation"}, WIRING_FILE, "process", {})
    assert (route["cls"], route["linked"]) == ("l3_isolation", [unit_id("process", "l3_isolation")])
    # A class the ledger does not know: the one the predicate's name spells, as for any failure.
    route = L._fuzz_meta_route(units, {**failure, "obligation_class": "not_a_class"}, WIRING_FILE, "process", {})
    assert (route["cls"], route["linked"]) == ("l5_sanitized", [unit_id("process", "l5_sanitized")])
    assert L._fuzz_meta_route(units, {"function": "mix", "kind": "assertion"}, WIRING_FILE, "mix", {}) is None


@pytest.mark.unit
def test_other_failures_are_filed_as_before(wired):
    rte = {
        "file": WIRING_FILE,
        "line": 0,
        "function": "mix",
        "kind": "assertion",
        "alarm_kind": "mem_access",
        "is_rte": True,
        "label": "rte/mem_access",
        "predicate": "\\valid(dst + i)",
    }
    stats = ingest([rte])
    units, candidates = ledger_state()
    (cand,) = candidates.values()
    assert cand["linked_units"] == [unit_id("mix", "rte")] and "notes" not in cand
    assert "meta_harness_induced" not in stats and "security_props_warnings" not in stats


@pytest.mark.unit
@pytest.mark.parametrize(
    "section, lost",
    [
        ({"status": "dropped", "reason": "the E-ACSL build failed with the properties (1)"}, True),
        ({"status": "error", "reason": "security properties file not found"}, True),
        ({"status": "skipped", "reason": "no target function is listed"}, True),
        ({"status": "skipped", "reason": "no property has an instance in a function of these sources"}, False),
        ({"status": "loaded"}, False),
        (None, False),
    ],
)
def test_a_campaign_that_lost_the_properties_says_so_on_their_units(wired, section, lost):
    extra = {"security_props": section} if section else {}
    if lost:
        extra["security_props_warnings"] = [f"{section['status']}: no property checked"]
    stats = ingest([], **extra)
    units, _ = ledger_state()
    marked = sorted(
        cid for cid, u in units.items() if any(e["result"] == "fuzz_meta_not_checked" for e in u["evidence"])
    )
    expected = sorted(cid for cid, u in units.items() if u["obligation_class"] in L.METACSL_CLASSES) if lost else []
    assert marked == expected
    assert ("security_props_warnings" in stats) is lost
    if lost:
        assert stats["security_props_warnings"] == {WIRING_MODULE: [f"{section['status']}: no property checked"]}
        summary = units[expected[0]]["evidence"][-2]["summary"]
        assert "checked no MetAcsl property at run time" in summary and section["reason"] in summary
    assert not L.validate_ledger(list(units.values()))


# ---------------------------------------------------------------------------------------------------
# Acceptance, in the image: run_eacsl_fuzz.py on the fixture, then ingest-fuzz on its reports
# ---------------------------------------------------------------------------------------------------

ACCEPTANCE_UNITS = {
    "backdoor": ("L4_auth_state_login", unit_id("backdoor", "l4_auth_state")),
    "admin": ("L4_auth_required_login", unit_id("process", "l4_auth_required")),
    "emit": ("L5_sanitized_emit", unit_id("process", "l5_sanitized")),
    "text": ("L5_sanitized_logmsg", unit_id("process", "l5_sanitized")),
    "close": ("L6_wiped_session_key", unit_id("session_close", "l6_wiped")),
    "leak": ("L6_no_leak_session_key", unit_id("process", "l6_no_leak")),
}


@pytest.fixture(scope="module")
def wiring_result(tmp_path_factory):
    """drive.py in the analysis image: (its RESULT document, the directory holding the reports it wrote)."""
    require_docker_images(ANALYSIS_IMAGE)
    inputs = tmp_path_factory.mktemp("metacsl_wiring_inputs")
    out = tmp_path_factory.mktemp("metacsl_wiring_out")
    write_props(inputs / "on.json", wiring_props(["eacsl"], backdoor=True))
    write_props(inputs / "off.json", wiring_props([], backdoor=True))
    changed = wiring_props(["eacsl"], backdoor=True)
    wiped = next(p for p in changed["properties"] if p["name"] == "L6_wiped_session_key")
    wiped["acsl"] = wiped["acsl"].replace("i < 16", "i < 15")
    write_props(inputs / "changed.json", changed)
    for tag, doc in (("mk_off", wiring_props([], backdoor=True)), ("mk_on", wiring_props(["eacsl"], backdoor=True))):
        plan_run(inputs / tag, doc)
        assert pm.generate(inputs / tag, templates_dir=WIRING_TEMPLATES)["ok"]
    before = inputs / "before"
    (before / "scripts").mkdir(parents=True)
    (before / "scripts" / ".keep").write_text("", encoding="utf-8")
    (before / "templates").mkdir()
    template = (ROOT / "templates" / "pipeline.mk").read_text(encoding="utf-8")
    (before / "templates" / "pipeline.mk").write_text(pipeline_mk_before(template), encoding="utf-8", newline="\n")
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
        "-v", f"{META_EACSL_FIXTURE.resolve()}:/fixture:ro",
        "-v", f"{WIRING_FIXTURE.resolve()}:/wiring:ro",
        "-v", f"{inputs.resolve()}:/inputs:ro",
        "-v", f"{out.resolve()}:/out",
        "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
        "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro",
        "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
        ANALYSIS_IMAGE, "-c",
        "mkdir -p /tmp/run && cd /tmp/run && "
        f"timeout 3300 python3 /wiring/drive.py /fixture /wiring /inputs /out {pm.MAKEFILE}",
    ]  # fmt: skip
    res = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=3600, check=False
    )
    lines = [ln for ln in res.stdout.splitlines() if ln.startswith("RESULT ")]
    assert res.returncode == 0 and lines, res.stdout[-4000:] + res.stderr[-4000:]
    result = json.loads(lines[-1][len("RESULT ") :])
    (out / "result.json").write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8", newline="\n")
    assert result["builds"]["first"]["status"] == "built", json.dumps(result["builds"]["first"], indent=1)[-6000:]
    return result, out


@pytest.mark.integration
@pytest.mark.slow
def test_in_the_image_an_identical_build_is_a_hit_and_a_changed_property_a_miss(wiring_result):
    builds = wiring_result[0]["builds"]
    first = builds["first"]
    assert first["cache"]["hit"] is False and first["cache"]["key"], first
    assert first["security_props"]["status"] == "loaded" and "--then-last --e-acsl-extra -rte" in first["command"]
    assert first["security_props"]["properties"] == ALL_PROPERTY_NAMES
    assert first["security_props"]["unplanned_instances"] == {}
    for tag in ("again", "by_default", "back"):
        assert builds[tag]["cache"] == {"hit": True, "key": first["cache"]["key"]}, (tag, builds[tag])
        assert builds[tag]["security_props"]["status"] == "loaded", tag
    # The hit put the meta file and its sidecar back, as the build had written them.
    assert wiring_result[0]["sidecar"] == {
        "written": ["fuzz_prog.security_meta.c", "fuzz_prog.security_meta.json"],
        "restored": ["fuzz_prog.security_meta.c", "fuzz_prog.security_meta.json"],
        "identical": True,
    }
    changed = builds["changed"]
    assert changed["status"] == "built" and changed["cache"]["hit"] is False, changed
    assert changed["cache"]["key"] != first["cache"]["key"]


@pytest.mark.integration
@pytest.mark.slow
def test_in_the_image_engine_off_builds_are_the_plain_build(wiring_result):
    result = wiring_result[0]
    builds = result["builds"]
    off, none, plain = builds["off"], builds["none"], builds["plain"]
    assert off["status"] == "built" and off["cache"]["hit"] is False
    assert off["cache"]["key"] not in (builds["first"]["cache"]["key"], builds["changed"]["cache"]["key"])
    for tag, build in (("off_again", builds["off_again"]), ("none", none), ("plain", plain)):
        assert build["cache"] == {"hit": True, "key": off["cache"]["key"]}, tag
    for tag, build in (("off", off), ("none", none), ("plain", plain)):
        assert build["security_props"] is None and build["warnings"] is None and build["stderr_props"] == [], tag
        assert "-meta" not in build["command"] and "--then-last" not in build["command"], tag
        assert "security_props" not in build["top_keys"] and "security_props_warnings" not in build["top_keys"], tag
    assert result["engine_off_report_differences"] == []
    assert result["engine_off_reports_identical"] is True


@pytest.mark.integration
@pytest.mark.slow
def test_in_the_image_the_planted_violations_become_candidates_on_their_units(wiring_result, monkeypatch):
    result, out = wiring_result
    campaigns = result["campaigns"]
    first_key = result["builds"]["first"]["cache"]["key"]
    for name, (prop, _) in ACCEPTANCE_UNITS.items():
        got = campaigns[name]
        assert got["status"] == "crash_found" and got["artifacts"], (name, got)
        assert got["cache"] == {"hit": True, "key": first_key}, (name, got["cache"])
        failure = got["artifacts"][0]["failure"]
        assert failure["meta_property"] == prop and failure["file"] == WIRING_FILE, (name, failure)
        assert got["artifacts"][0]["reproducible"] is True and not got["harness_induced"], (name, got)
    induced = campaigns["indirect"]
    assert induced["status"] == "crash_found", induced
    assert [(i["property"], i["function"], i["caller"]) for i in induced["harness_induced"]] == [
        ("L4_auth_required_login", "admin", "LLVMFuzzerTestOneInput")
    ]
    assert any("harness-induced: L4_auth_required_login" in line for line in induced["stderr_props"]), induced

    monkeypatch.chdir(out)
    seed_ledger(out, wiring_props(["eacsl"], backdoor=True))
    reports = [out / "workspace/reports/fuzz" / f"{name}.json" for name in (*ACCEPTANCE_UNITS, "indirect")]
    stats = L.cmd_ingest_fuzz(reports)
    units, candidates = ledger_state()
    detail = json.dumps({"stats": stats, "candidates": candidates}, indent=1)[-8000:]
    linked = {c["property"]["predicate"].split(":")[0]: c["linked_units"] for c in candidates.values()}
    assert linked == {prop: [unit] for prop, unit in ACCEPTANCE_UNITS.values()}, detail
    assert touched(units) == {unit: "candidate" for _, unit in ACCEPTANCE_UNITS.values()}, detail
    # The harness-induced failure: listed, no candidate, no unit.
    assert [(i["property"], i["caller"]) for i in stats["meta_harness_induced"]] == [
        ("L4_auth_required_login", "LLVMFuzzerTestOneInput")
    ], detail
    assert stats["candidates"] == len(ACCEPTANCE_UNITS) == len(candidates), detail
    assert not L.validate_ledger(list(units.values()))


@pytest.mark.integration
@pytest.mark.slow
def test_in_the_image_a_replay_from_another_directory_reproduces(wiring_result):
    result = wiring_result[0]
    found = result["campaigns"]["backdoor"]["artifacts"][0]["fingerprint"]
    built = result["replays"]["built_elsewhere"]
    assert built["status"] == "reproduced" and built["has_security_props"], built
    assert built["fingerprints"] == [found] and built["files"] == [WIRING_FILE], built
    # Another directory is another key: that build was made there, with the properties named by their path.
    assert built["cache"]["hit"] is False
    here = result["replays"]["binary_here"]
    assert here["status"] == "reproduced" and here["fingerprints"] == [found], here
    # The campaign's binary by its absolute path, from the other directory: the sidecar is next to it
    # (package F; before it the file part of the fingerprint was `unknown`).
    given = result["replays"]["binary_elsewhere"]
    assert given["status"] == "reproduced" and given["fingerprints"] == [found], given
    assert given["files"] == [WIRING_FILE] and found.startswith(f"{WIRING_FILE}#backdoor::"), given


@pytest.mark.integration
@pytest.mark.slow
def test_in_the_image_make_passes_the_option_only_with_the_engine_on(wiring_result):
    make = wiring_result[0]["make"]
    off, before, on = make["off"], make["off_before"], make["on"]
    assert off["rc"] == 0 and before["rc"] == 0 and on["rc"] == 0, make
    assert "run_eacsl_fuzz.py build" in off["stdout"] and "run_eacsl_fuzz.py campaign" in off["stdout"]
    # Engine off: what Make runs is what the template before this package ran, byte for byte.
    assert off["stdout"] == before["stdout"] and "--security-props" not in off["stdout"]
    option = f" --security-props={pm.SECURITY_PROPS_JSON}"
    assert on["stdout"].count(option) == 2 and on["stdout"].replace(option, "") == off["stdout"]
    missing = make["on_without_the_file"]
    assert missing["rc"] != 0 and "No rule to make target" in missing["stderr"], missing
    assert pm.SECURITY_PROPS_JSON in missing["stderr"]


@pytest.mark.unit
def test_the_wiring_fixture_harness_never_names_the_protected_function():
    text = (WIRING_FIXTURE / "harness_indirect.c").read_text(encoding="utf-8")
    words = set(fuzz_build._C_IDENT_RE.findall(fuzz_build._C_COMMENT_RE.sub(" ", text)))
    assert "CALL_GATE" in words and "admin" not in words
