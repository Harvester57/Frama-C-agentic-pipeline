"""`run_eacsl_fuzz.py coverage`: per-function reach of a module's corpus, and where it is wired in."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import pipeline_make as pm
import resources
import run_eacsl_fuzz as R
from generate_report import fuzz_reach_lines, load_coverage_reports
from sandbox_exec import SandboxResult, SandboxUnavailable
from test_pipeline_make import ACSL, FakeMake, _make_run

CODE, GAP = 0, 3


def _region(line_start, line_end, count, file_id=0, kind=CODE, col_start=1, col_end=2):
    return [line_start, col_start, line_end, col_end, count, file_id, 0, kind]


def _fn(name, filename, count, regions, extra_files=()):
    return {"name": name, "count": count, "filenames": [filename, *extra_files], "regions": regions}


def _export(*functions):
    return {"data": [{"functions": list(functions)}]}


# ---------------------------------------------------------------------------
# summarize_coverage_export
# ---------------------------------------------------------------------------


def test_summary_counts_reach_and_keeps_only_the_targets_functions():
    summary = R.summarize_coverage_export(
        _export(
            _fn("parse", "/framac-run/workspace/work/src/p.c", 5, [_region(10, 20, 5), _region(12, 13, 0)]),
            _fn("p.c:unused", "/framac-run/workspace/work/src/p.c", 0, [_region(30, 40, 0)]),
            _fn("LLVMFuzzerTestOneInput", "/framac-run/workspace/harnesses/harness_m.c", 5, [_region(1, 2, 5)]),
            _fn("inline_helper", "/usr/include/x86_64-linux-gnu/bits/stdio.h", 3, [_region(1, 2, 3)]),
            _fn("stub", "/opt/framac-pipeline/templates/fc_stubs/s.h", 3, [_region(1, 2, 3)]),
        )
    )
    assert summary["totals"] == {
        "functions": {"total": 2, "reached": 1},
        "regions": {"total": 3, "covered": 1},
    }
    assert summary["excluded_functions"] == {"external": 2, "harness": 1}
    parse, unused = summary["functions"]
    assert (parse["function"], parse["file"], parse["line"]) == ("parse", "src/p.c", 10)
    assert parse["uncovered_lines"] == [[12, 13]]
    # The file prefix of a static's symbol is dropped, and an unreached function lists no ranges.
    assert (unused["function"], unused["executions"]) == ("unused", 0)
    assert "uncovered_lines" not in unused


def test_summary_counts_only_code_regions():
    summary = R.summarize_coverage_export(
        _export(_fn("f", "/r/workspace/work/a.c", 1, [_region(1, 9, 1), _region(4, 5, 0, kind=GAP)]))
    )
    assert summary["functions"][0]["regions"] == {"total": 1, "covered": 1}
    assert summary["functions"][0]["uncovered_lines"] == []


def test_summary_counts_each_macro_expansion_as_its_own_region():
    """llvm-cov gives each expansion a file id of its own, with the macro's file and span repeated."""
    macro = "/r/workspace/work/macro.h"
    summary = R.summarize_coverage_export(
        _export(
            _fn(
                "f",
                "/r/workspace/work/a.c",
                1,
                [_region(10, 20, 1), _region(3, 3, 1, file_id=1), _region(3, 3, 0, file_id=2)],
                extra_files=[macro, macro],
            )
        )
    )
    assert summary["functions"][0]["regions"] == {"total": 3, "covered": 2}


def test_summary_counts_zero_width_regions_at_one_point_separately():
    """llvm-cov repeats a point for a short-circuit operand, sometimes with different counts."""
    summary = R.summarize_coverage_export(
        _export(
            _fn(
                "f",
                "/r/workspace/work/a.c",
                1,
                [_region(1, 9, 1), _region(5, 5, 3, col_start=7, col_end=7), _region(5, 5, 0, col_start=7, col_end=7)],
            )
        )
    )
    fn = summary["functions"][0]
    assert fn["regions"] == {"total": 3, "covered": 2}
    assert fn["uncovered_lines"] == [[5, 5]]


def test_summary_merges_a_headers_static_across_translation_units():
    header = "/r/workspace/work/inc/h.h"
    summary = R.summarize_coverage_export(
        _export(
            _fn("a.c:helper", header, 2, [_region(3, 8, 2), _region(5, 6, 0)]),
            _fn("b.c:helper", header, 0, [_region(3, 8, 0), _region(5, 6, 0)]),
            _fn("c.c:helper", header, 1, [_region(3, 8, 1), _region(5, 6, 1)]),
        )
    )
    assert len(summary["functions"]) == 1
    helper = summary["functions"][0]
    assert helper["executions"] == 3
    assert helper["regions"] == {"total": 2, "covered": 2}
    assert helper["uncovered_lines"] == []


def test_summary_keeps_same_named_statics_in_different_files_apart():
    summary = R.summarize_coverage_export(
        _export(
            _fn("a.c:init", "/r/workspace/work/a.c", 1, [_region(3, 4, 1)]),
            _fn("b.c:init", "/r/workspace/work/b.c", 0, [_region(3, 4, 0)]),
        )
    )
    assert [(f["file"], f["executions"]) for f in summary["functions"]] == [("a.c", 1), ("b.c", 0)]
    assert summary["totals"]["functions"] == {"total": 2, "reached": 1}


def test_summary_classifies_a_harness_that_includes_the_target_by_the_targets_file():
    summary = R.summarize_coverage_export(
        _export(_fn("f", "/r/workspace/harnesses/../work/a.c", 1, [_region(1, 2, 1)]))
    )
    assert summary["functions"][0]["file"] == "a.c"
    assert summary["excluded_functions"] == {}


def test_summary_lists_uncovered_lines_of_the_functions_own_file_only():
    summary = R.summarize_coverage_export(
        _export(
            _fn(
                "f",
                "/r/workspace/work/a.c",
                1,
                [
                    _region(10, 40, 1),
                    _region(12, 13, 0),
                    _region(14, 15, 0),
                    _region(30, 31, 0),
                    _region(2, 3, 0, file_id=1),
                ],
                extra_files=["/r/workspace/work/macro.h"],
            )
        )
    )
    fn = summary["functions"][0]
    assert fn["uncovered_lines"] == [[12, 15], [30, 31]]
    assert fn["regions"] == {"total": 5, "covered": 1}


# ---------------------------------------------------------------------------
# replay_for_coverage
# ---------------------------------------------------------------------------


class CoverageSandbox:
    """Inputs replay in batches: CRASH dies with no profile, EXIT returns 0 and leaves it empty."""

    def __init__(self):
        self.batches: list[list[str]] = []
        self.envs: list[dict] = []

    def __call__(self, cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        inputs = [a for a in cmd[1:] if not a.startswith("-")]
        self.batches.append([Path(a).name for a in inputs])
        self.envs.append(dict(extra_env or {}))
        contents = [Path(a).read_bytes() for a in inputs]
        profile = Path((extra_env or {})["LLVM_PROFILE_FILE"].replace("%p", "1"))
        profile.parent.mkdir(parents=True, exist_ok=True)
        profile.write_bytes(b"")
        if any(c.startswith(b"CRASH") for c in contents):
            return SandboxResult(77, "", "deadly signal", False, "rlimits", list(cmd))
        if not any(c.startswith(b"EXIT") for c in contents):
            profile.write_bytes(b"profile")
        return SandboxResult(0, "", "", False, "rlimits", list(cmd))


def _corpus(tmp_path: Path, *contents: bytes) -> list[Path]:
    corpus = tmp_path / "corpus"
    corpus.mkdir(exist_ok=True)
    files = []
    for i, data in enumerate(contents):
        path = corpus / f"input-{i:03}"
        path.write_bytes(data)
        files.append(path)
    return files


def _replay(tmp_path, files, **kwargs):
    profiles = tmp_path / "profiles"
    profiles.mkdir(exist_ok=True)
    return R.replay_for_coverage(tmp_path / "bin", files, profiles, tmp_path / "scratch", **kwargs), profiles


def test_replay_runs_each_input_once_in_batches(tmp_path, monkeypatch):
    fake = CoverageSandbox()
    monkeypatch.setattr(R, "run_sandboxed", fake)
    files = _corpus(tmp_path, *[b"x"] * 5)
    res, profiles = _replay(tmp_path, files, batch_size=2)
    assert [len(b) for b in fake.batches] == [2, 2, 1]
    assert res["replayed"] == 5
    assert res["failed_inputs"] == []
    assert res["not_replayed"] == 0
    assert len(R._written_profiles(profiles)) == 3
    assert all(e["LLVM_PROFILE_FILE"].endswith("%p.profraw") for e in fake.envs)


def test_replay_isolates_a_crash_and_keeps_every_other_inputs_profile(tmp_path, monkeypatch):
    fake = CoverageSandbox()
    monkeypatch.setattr(R, "run_sandboxed", fake)
    files = _corpus(tmp_path, b"ok", b"ok", b"CRASH", b"ok", b"ok")
    res, profiles = _replay(tmp_path, files)
    assert res["replayed"] == 4
    assert res["not_replayed"] == 0
    assert [f["input"] for f in res["failed_inputs"]] == [files[2].as_posix()]
    assert res["failed_inputs"][0]["returncode"] == 77
    assert len(res["failed_inputs"][0]["sha256"]) == 64
    assert fake.batches[0] == [f.name for f in files]
    assert all(p.endswith(".profraw") for p in R._written_profiles(profiles))


def test_replay_treats_an_empty_profile_as_a_failed_input(tmp_path, monkeypatch):
    """A target's `_exit(0)` returns 0 and leaves the empty file the profile runtime created at start."""
    monkeypatch.setattr(R, "run_sandboxed", CoverageSandbox())
    files = _corpus(tmp_path, b"ok", b"EXIT")
    res, _ = _replay(tmp_path, files)
    assert res["replayed"] == 1
    assert [f["input"] for f in res["failed_inputs"]] == [files[1].as_posix()]
    assert res["failed_inputs"][0]["returncode"] == 0


def test_replay_stops_after_too_many_failures_and_reports_the_rest(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "run_sandboxed", CoverageSandbox())
    files = _corpus(tmp_path, *[b"CRASH"] * 8)
    res, _ = _replay(tmp_path, files, max_failed=2)
    assert len(res["failed_inputs"]) == 2
    assert res["replayed"] == 0
    assert res["not_replayed"] == 6


def test_replay_stops_at_the_deadline_and_reports_the_rest(tmp_path, monkeypatch):
    fake = CoverageSandbox()
    monkeypatch.setattr(R, "run_sandboxed", fake)
    files = _corpus(tmp_path, *[b"x"] * 4)
    res, _ = _replay(tmp_path, files, batch_size=1, max_time=0)
    assert fake.batches == []
    assert (res["replayed"], res["not_replayed"]) == (0, 4)


def test_replay_treats_a_killed_batch_like_a_crash(tmp_path, monkeypatch):
    def hang(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        return SandboxResult(-9, "", "", True, "rlimits", list(cmd))

    monkeypatch.setattr(R, "run_sandboxed", hang)
    files = _corpus(tmp_path, b"x")
    res, _ = _replay(tmp_path, files)
    assert res["failed_inputs"][0]["timed_out"] is True
    assert res["replayed"] == 0


# ---------------------------------------------------------------------------
# coverage_report
# ---------------------------------------------------------------------------


def _compile_ok(binary: Path):
    def fake(sources, out_bin, cppflags="-I.", ldflags_extra="", runner=None, use_cache=True):
        return {"engine": "coverage", "returncode": 0, "binary": str(binary), "cache": {"hit": False, "key": None}}

    return fake


def _no_compile(*a, **k):
    raise AssertionError("nothing to measure: no build")


def _report(tmp_path, **kwargs):
    return R.coverage_report("m", ["a.c"], tmp_path / "cov_m", [tmp_path / "corpus"], tmp_path / "scratch", **kwargs)


def test_report_without_inputs_measures_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "compile_coverage_binary", _no_compile)
    report = _report(tmp_path)
    assert report["status"] == "no_inputs"
    assert "functions" not in report
    assert "totals" not in report


def test_report_compile_error_claims_no_coverage(tmp_path, monkeypatch):
    _corpus(tmp_path, b"x")
    monkeypatch.setattr(
        R, "compile_coverage_binary", lambda *a, **k: {"engine": "coverage", "returncode": 1, "binary": "b"}
    )
    report = _report(tmp_path)
    assert report["status"] == "compile_error"
    assert "totals" not in report


def _measured(tmp_path, monkeypatch, *contents, export=None, export_error=None):
    _corpus(tmp_path, *contents)
    monkeypatch.setattr(R, "compile_coverage_binary", _compile_ok(tmp_path / "cov_m"))
    monkeypatch.setattr(R, "run_sandboxed", CoverageSandbox())
    default = _export(_fn("f", "/r/workspace/work/a.c", 1, [_region(1, 2, 1)]))
    monkeypatch.setattr(
        R, "_export_coverage", lambda *a: (export or default, None) if not export_error else (None, export_error)
    )
    return _report(tmp_path)


def test_report_ok_has_per_function_records_and_input_counts(tmp_path, monkeypatch):
    report = _measured(tmp_path, monkeypatch, b"a", b"b")
    assert report["status"] == "ok"
    assert report["inputs"] == {"total": 2, "replayed": 2, "failed": 0, "not_replayed": 0}
    assert report["totals"]["functions"] == {"total": 1, "reached": 1}
    assert report["functions"][0]["function"] == "f"


def test_report_is_partial_when_an_input_failed(tmp_path, monkeypatch):
    report = _measured(tmp_path, monkeypatch, b"a", b"CRASH")
    assert report["status"] == "partial"
    assert report["inputs"] == {"total": 2, "replayed": 1, "failed": 1, "not_replayed": 0}
    assert report["totals"]["functions"]["reached"] == 1


def test_report_without_any_profile_claims_no_coverage(tmp_path, monkeypatch):
    report = _measured(tmp_path, monkeypatch, b"CRASH")
    assert report["status"] == "coverage_error"
    assert "totals" not in report


def test_report_surfaces_export_failures(tmp_path, monkeypatch):
    report = _measured(tmp_path, monkeypatch, b"a", export_error="llvm-cov export failed (1): boom")
    assert report["status"] == "coverage_error"
    assert "boom" in report["reason"]


def _truncated_then_ok(tmp_path, monkeypatch, pre_included: list[str]):
    """A first export LLVM cannot read (cryptolib r2v), then a readable one; records the build flags."""
    _corpus(tmp_path, b"a")
    flags: list[str] = []

    def compile_(sources, out_bin, cppflags="-I.", ldflags_extra="", runner=None, use_cache=True):
        flags.append(cppflags)
        return {"engine": "coverage", "returncode": 0, "binary": str(tmp_path / "cov_m"), "cache": {"hit": False}}

    good = _export(_fn("f", "/r/workspace/work/a.c", 1, [_region(1, 2, 1)]))
    results = iter([(None, f"llvm-cov export failed (1): error: {R.COVERAGE_TRUNCATED_MAPPING}"), (good, None)])
    monkeypatch.setattr(R, "compile_coverage_binary", compile_)
    monkeypatch.setattr(R, "run_sandboxed", CoverageSandbox())
    monkeypatch.setattr(R, "_export_coverage", lambda *a: next(results))
    monkeypatch.setattr(R, "in_function_includes", lambda sources, cppflags="": pre_included)
    return _report(tmp_path, cppflags="-Iinc"), flags


def test_report_rebuilds_with_in_function_headers_included_first_when_llvm_cov_cannot_read_the_mapping(
    tmp_path, monkeypatch
):
    report, flags = _truncated_then_ok(tmp_path, monkeypatch, ["malloc.h"])
    assert flags == ["-Iinc", "-Iinc -include malloc.h"]
    assert report["status"] == "ok" and report["pre_included"] == ["malloc.h"]
    assert "reason" not in report


def test_report_keeps_the_export_error_when_no_header_is_included_inside_a_function(tmp_path, monkeypatch):
    report, flags = _truncated_then_ok(tmp_path, monkeypatch, [])
    assert flags == ["-Iinc"]
    assert report["status"] == "coverage_error" and R.COVERAGE_TRUNCATED_MAPPING in report["reason"]


def test_includes_inside_braces_skip_file_scope_comments_and_literals():
    text = "\n".join(
        [
            '#include "crypto.h"',
            "/* { */ int x = '{'; const char *s = \"{\";",
            "int f(void) {",
            "#if defined(__linux__)",
            "#include <malloc.h>",
            "#elif defined(__APPLE__)",
            "  #  include <malloc/malloc.h>",
            "#endif",
            '#include "local.h"',
            "  return 0; // }",
            "}",
            "#include <string.h>",
        ]
    )
    assert R._includes_inside_braces(text) == [("<", "malloc.h"), ("<", "malloc/malloc.h"), ('"', "local.h")]


def test_in_function_includes_keeps_only_headers_that_preprocess(tmp_path, monkeypatch):
    src = tmp_path / "crypto.c"
    src.write_text(
        'int f(void) {\n#include <malloc.h>\n#include <malloc/malloc.h>\n#include "local.h"\nreturn 0; }\n',
        encoding="utf-8",
    )
    (tmp_path / "local.h").write_text("", encoding="utf-8")
    probed: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        probed.append(cmd)
        return R.subprocess.CompletedProcess(cmd, 1 if "malloc/malloc.h" in cmd else 0, "", "")

    monkeypatch.setattr(R.subprocess, "run", fake_run)
    got = R.in_function_includes([str(src), str(src)], "-Iinc")
    assert got == ["malloc.h", (tmp_path / "local.h").as_posix()]
    assert all(cmd[:4] == ["clang", "-E", "-x", "c"] and "-Iinc" in cmd for cmd in probed)
    assert len(probed) == 3  # the second copy of the source probes nothing new


def test_report_rejects_an_export_without_target_functions(tmp_path, monkeypatch):
    harness_only = _export(_fn("h", "/r/workspace/harnesses/harness_m.c", 1, [_region(1, 2, 1)]))
    report = _measured(tmp_path, monkeypatch, b"a", export=harness_only)
    assert report["status"] == "coverage_error"
    assert "totals" not in report


def test_report_rejects_a_malformed_export(tmp_path, monkeypatch):
    report = _measured(tmp_path, monkeypatch, b"a", export={"data": []})
    assert report["status"] == "coverage_error"
    assert "unexpected llvm-cov export shape" in report["reason"]


def test_report_drops_profiles_of_an_earlier_measurement(tmp_path, monkeypatch):
    stale = tmp_path / "scratch/profiles/batch-99/9.profraw"
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"stale")
    _measured(tmp_path, monkeypatch, b"a")
    assert not stale.exists()


# ---------------------------------------------------------------------------
# Build and CLI
# ---------------------------------------------------------------------------


def test_coverage_build_has_no_checks_and_keeps_the_module_flags(tmp_path):
    seen = {}

    def runner(cmd, **kwargs):
        seen["cmd"] = cmd
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    comp = R.compile_coverage_binary(["a.c"], tmp_path / "cov_m", "-Iinc -DX=1", "-lm", runner=runner, use_cache=False)
    cmd = seen["cmd"]
    assert comp["engine"] == "coverage"
    assert {"-fprofile-instr-generate", "-fcoverage-mapping", "-fsanitize=fuzzer", "-Iinc", "-DX=1", "-lm"} <= set(cmd)
    assert not any("address" in a or "undefined" in a for a in cmd)
    assert (tmp_path / "cov_m.coverage_compile.log").is_file()


def test_sanitizer_build_keeps_its_command_after_sharing_the_clang_builder(tmp_path):
    seen = {}

    def runner(cmd, **kwargs):
        seen["cmd"] = cmd
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    out = tmp_path / "bin"
    comp = R.compile_sanitizer_binary(["a.c"], out, "-I.", True, "-lm", runner=runner, use_cache=False)
    assert seen["cmd"] == [
        "clang",
        "-g",
        "-O1",
        "-fcommon",
        "-fsanitize=fuzzer,address,undefined",
        "-fno-sanitize-recover=all",
        "-I.",
        "a.c",
        "-o",
        str(out),
        "-lm",
    ]
    assert comp["engine"] == "sanitizers"
    assert (tmp_path / "bin.sanitizer_compile.log").is_file()


def _cli(tmp_path, *extra):
    return R.main(
        [
            "coverage",
            "--module",
            "m",
            "--sources",
            "a.c",
            "--out-bin",
            str(tmp_path / "cov_m"),
            "--corpus-dir",
            str(tmp_path / "corpus"),
            "--scratch-dir",
            str(tmp_path / "scratch"),
            "--out-json",
            str(tmp_path / "out.json"),
            *extra,
        ]
    )


def test_cli_writes_the_full_report_and_prints_a_summary(tmp_path, monkeypatch, capsys):
    _corpus(tmp_path, b"a")
    monkeypatch.setattr(R, "compile_coverage_binary", _compile_ok(tmp_path / "cov_m"))
    monkeypatch.setattr(R, "run_sandboxed", CoverageSandbox())
    export = _export(_fn("f", "/r/workspace/work/a.c", 1, [_region(1, 2, 1)]))
    monkeypatch.setattr(R, "_export_coverage", lambda *a: (export, None))
    assert _cli(tmp_path) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["status"] == "ok"
    assert "functions" not in printed
    assert json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))["functions"][0]["function"] == "f"


def test_cli_exits_3_without_the_sandbox(tmp_path, monkeypatch, capsys):
    _corpus(tmp_path, b"a")
    monkeypatch.setattr(R, "compile_coverage_binary", _compile_ok(tmp_path / "cov_m"))

    def unavailable(*a, **k):
        raise SandboxUnavailable("no sandbox")

    monkeypatch.setattr(R, "run_sandboxed", unavailable)
    assert _cli(tmp_path) == 3
    assert json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))["status"] == "sandbox_unavailable"


# ---------------------------------------------------------------------------
# Make, broker and report wiring
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cmd",
    [
        "python3 $S/run_eacsl_fuzz.py coverage --module m",
        "python3 $S/run_eacsl_fuzz.py coverage --module build",
        "python3 $S/pipeline_make.py run coverage",
        "python3 $S/pipeline_make.py run coverage-m",
    ],
)
def test_coverage_runs_target_code_so_it_is_never_static(cmd):
    assert resources.is_known_static_command(cmd) is False


def test_coverage_commands_are_leased_as_target_code():
    assert resources.infer_class("python3 $S/run_eacsl_fuzz.py coverage --module build") == "replay"
    assert resources.CLASSES["replay"].runs_target_code is True
    assert resources.infer_class("python3 $S/pipeline_make.py run coverage") == "phase-dynamic"
    assert resources.infer_class("python3 $S/pipeline_make.py run coverage-m") == "phase-dynamic"


def test_coverage_runs_after_the_campaigns():
    assert pm.STAGE_OF_TARGET["coverage"] > pm.STAGE_OF_TARGET["fuzz"]
    assert pm._stage("coverage-m") == pm.STAGE_OF_TARGET["coverage"]
    assert pm._stage("fuzz-m") == pm.STAGE_OF_TARGET["fuzz"]


def test_run_expands_coverage_per_fuzz_module_and_refuses_excluded_modules(tmp_path):
    run = _make_run(tmp_path)
    pm.generate(run, templates_dir=ACSL)
    fake = FakeMake(writes={"workspace/reports/coverage/snmp.json": json.dumps({"status": "partial"})})

    rc, out = pm.run_targets(["coverage", "coverage-evil"], run, jobs=2, make_runner=fake, templates_dir=ACSL)

    assert rc == 1
    assert out["targets"]["coverage-evil"]["status"] == "refused"
    assert fake.calls[0][7:] == ["coverage"]
    nodes = out["targets"]["coverage"]["nodes"]
    assert set(nodes) == {"coverage-cfg", "coverage-log", "coverage-snmp"}
    assert nodes["coverage-snmp"]["output"] == "workspace/reports/coverage/snmp.json"
    assert nodes["coverage-snmp"]["report_status"] == "partial"
    assert nodes["coverage-log"]["status"] == "no_output"


def test_run_orders_coverage_after_fuzz(tmp_path):
    run = _make_run(tmp_path)
    pm.generate(run, templates_dir=ACSL)
    fake = FakeMake()
    pm.run_targets(["coverage", "fuzz"], run, jobs=2, make_runner=fake, templates_dir=ACSL)
    assert [c[7:] for c in fake.calls] == [["fuzz"], ["coverage"]]


def test_makefile_coverage_recipe_replays_the_corpus_without_a_new_campaign():
    text = (Path(R.__file__).resolve().parent.parent / "templates/pipeline.mk").read_text(encoding="utf-8")
    assert "$(COVERAGE_TARGETS): coverage-%:\n" in text
    recipe = text.split("$(COVERAGE_TARGETS): coverage-%:\n", 1)[1].split("\n\n", 1)[0]
    assert "--class replay" in recipe
    assert "--corpus-dir workspace/corpus/$*" in recipe
    assert "--output workspace/reports/coverage/$*.json" in recipe


def test_report_says_when_reach_was_not_measured():
    assert "not measured" in "\n".join(fuzz_reach_lines([]))


def test_report_tables_reach_and_lists_unreached_functions():
    report = {
        "module": "parser",
        "status": "partial",
        "inputs": {"total": 3, "replayed": 2},
        "totals": {"functions": {"total": 2, "reached": 1}, "regions": {"total": 9, "covered": 4}},
        "functions": [
            {"function": "reached", "file": "a.c", "line": 1, "executions": 2},
            {"function": "never", "file": "a.c", "line": 9, "executions": 0},
        ],
    }
    text = "\n".join(fuzz_reach_lines([report]))
    assert "| `parser` | `partial` | 2 / 3 | 1 / 2 | 4 / 9 |" in text
    assert "`never` at `a.c:9` (parser)" in text
    assert "`reached`" not in text
    assert "not evidence of safety" in text


def test_report_caps_the_unreached_list():
    functions = [{"function": f"f{i}", "file": "a.c", "line": i, "executions": 0} for i in range(60)]
    text = "\n".join(fuzz_reach_lines([{"module": "m", "status": "ok", "functions": functions}]))
    assert "(60)" in text
    assert "... and 10 more" in text


def test_report_keeps_a_module_whose_coverage_failed_or_is_unreadable(tmp_path):
    reports = tmp_path / "workspace/reports/coverage"
    reports.mkdir(parents=True)
    (reports / "good.json").write_text('{"module": "good", "status": "compile_error"}', encoding="utf-8")
    (reports / "bad.json").write_text("{not json", encoding="utf-8")
    loaded = load_coverage_reports(tmp_path)
    assert [(r["module"], r["status"]) for r in loaded] == [("bad", "unreadable"), ("good", "compile_error")]
    text = "\n".join(fuzz_reach_lines(loaded))
    assert "| `bad` | `unreadable` | 0 / 0 | 0 / 0 | 0 / 0 |" in text
    assert "| `good` | `compile_error` |" in text
