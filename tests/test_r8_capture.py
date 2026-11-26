"""
Remediation plan step R8 (capture, images and tooling), unit side: the capture retries a timed-out build
serially, the build's generated headers reach the analyses' include path, the Phase 0 steps that run
target code infer their resource class, the wrappers no longer chmod the scratch volume, and every
script module is first-party for Ruff.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest

import build_capture as bc
import framac_common
import resources
import target_env
from conftest import ROOT, dockerfile_command_args, dockerfile_commands, dockerfile_stages

FIXTURE = ROOT / "tests" / "fixtures" / "r8_generated_header"


# ------------------------------------------------------------------------------ capture timeout


def _capture_args(tmp_path: Path) -> argparse.Namespace:
    target = tmp_path / "target"
    target.mkdir()
    (target / "Makefile").write_text("all:\n\ttrue\n", encoding="utf-8")
    return argparse.Namespace(target=str(target), scratch=str(tmp_path / "scratch"), timeout=30)


def _recorded_build(monkeypatch, tmp_path, results: list[dict], jobs: int = 4, env: dict | None = None) -> list[dict]:
    """Replace the sandboxed build with `results` in order; returns the recorded calls."""
    calls: list[dict] = []
    copies: list[int] = []
    real_copy = bc.copy_target

    def copy_target(target, tree):
        copies.append(1)
        return real_copy(target, tree)

    def run_sandboxed_shell(command, cwd, scratch, timeout, env_, wrap):
        res = results[len(calls)]
        # A fresh copy: nothing the previous attempt left in the tree survives.
        calls.append({"env": dict(env_), "fresh": not (Path(cwd) / "stale").exists(), "copies": len(copies)})
        (Path(cwd) / "stale").write_text("x", encoding="utf-8")
        return SimpleNamespace(stdout="", stderr="", **res)

    recipe: dict = {
        "command": "make",
        "workdir": ".",
        "packages": [],
        "env": env or {},
        "test_command": None,
        "install_command": None,
        "snapshot_extra": [],
        "origin": "user",
    }
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(bc, "load_recipe", lambda args: dict(recipe))
    monkeypatch.setattr(bc, "packages_missing", lambda pkgs: [])
    monkeypatch.setattr(bc, "job_count", lambda: jobs)
    monkeypatch.setattr(bc, "copy_target", copy_target)
    monkeypatch.setattr(bc, "run_sandboxed_shell", run_sandboxed_shell)
    return calls


@pytest.mark.unit
def test_a_timed_out_parallel_build_is_retried_once_serially_on_a_fresh_copy(monkeypatch, tmp_path):
    calls = _recorded_build(
        monkeypatch, tmp_path, [{"returncode": -9, "timed_out": True}, {"returncode": 0, "timed_out": False}]
    )
    report, _ = bc.capture(_capture_args(tmp_path))
    assert [c["env"]["MAKEFLAGS"] for c in calls] == ["-j4", "-j1"]
    assert all(c["fresh"] for c in calls) and calls[1]["copies"] == 2
    build = report["build"]
    assert [(a["jobs"], a["timed_out"]) for a in build["attempts"]] == [(4, True), (1, False)]
    assert build["jobs"] == 1 and build["timed_out"] is False
    assert any("timed out with 4 jobs and succeeded with one" in w for w in report["warnings"])
    assert (tmp_path / "workspace/reports/build_capture/build-parallel.log").is_file()


@pytest.mark.unit
def test_a_build_that_times_out_serially_too_stops_with_the_timeout(monkeypatch, tmp_path):
    _recorded_build(monkeypatch, tmp_path, [{"returncode": -9, "timed_out": True}] * 2)
    report, code = bc.capture(_capture_args(tmp_path))
    assert code == bc.EXIT_NEEDS_RECIPE and len(report["build"]["attempts"]) == 2
    assert report["diagnostics"]["first_error"] == "build timed out after 30 s"
    assert not bc.validate_report({**report, "status": bc.STATUS_NEEDS_RECIPE})


@pytest.mark.unit
@pytest.mark.parametrize(("jobs", "env"), [(1, None), (4, {"MAKEFLAGS": "-j8"})])
def test_no_serial_retry_when_already_serial_or_the_recipe_sets_the_jobs(monkeypatch, tmp_path, jobs, env):
    calls = _recorded_build(monkeypatch, tmp_path, [{"returncode": -9, "timed_out": True}], jobs=jobs, env=env)
    report, code = bc.capture(_capture_args(tmp_path))
    assert len(calls) == 1 and code == bc.EXIT_NEEDS_RECIPE and report["build"]["timed_out"] is True


# ------------------------------------------------------------------------------ generated headers


COMPILES = [
    {
        "source": "demo.c",
        "flags": ["-I", "build", "-I", "include", "-DX=1"],
        "headers": ["build/config.h", "build/gen/version.h", "include/api.h"],
    },
    {"source": "lib/a.c", "flags": ["-I", "/usr/include/mysql"], "headers": ["/usr/include/mysql/mysql.h"]},
]


def _target_without_generated(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    (target / "include").mkdir(parents=True)
    (target / "include/api.h").write_text("int api(void);\n", encoding="utf-8")
    return target


@pytest.mark.unit
def test_generated_headers_are_those_the_target_does_not_have(tmp_path):
    target = _target_without_generated(tmp_path)
    headers = bc.generated_headers(COMPILES, target)
    assert headers == ["build/config.h", "build/gen/version.h"]
    # Each header's own directory, then a project include directory holding one below it.
    assert bc.generated_include_dirs(headers, COMPILES) == ["build", "build/gen"]
    assert bc.generated_include_dirs(["config.h"], [{"flags": ["-I", "."]}]) == ["."]
    assert bc.generated_headers(COMPILES[1:], target) == []


def _export(tmp_path: Path, generated: dict[str, Path] | None, dirs: list[str] | None) -> tuple[Path, dict]:
    lib = tmp_path / "sys" / "libz.so"
    lib.parent.mkdir(parents=True, exist_ok=True)
    lib.write_bytes(b"lib")
    snap = tmp_path / "run" / "workspace" / "snapshot"
    return snap, bc.export_snapshot(snap, {lib.as_posix(): {}}, generated, dirs)


@pytest.mark.unit
def test_a_snapshot_without_generated_headers_keeps_its_digest_and_manifest(tmp_path):
    snap, summary = _export(tmp_path, None, None)
    lib = (tmp_path / "sys" / "libz.so").as_posix()
    want = hashlib.sha256(f"{lib}\0{hashlib.sha256(b'lib').hexdigest()}\n".encode()).hexdigest()
    assert summary == {"digest": want, "files": 1, "generated": 0}
    manifest = target_env._manifest(snap)
    assert set(manifest) == {"digest", "files"}


@pytest.mark.unit
def test_a_generated_header_is_on_the_analysis_include_path(tmp_path, monkeypatch):
    tree = tmp_path / "tree"
    (tree / "build/gen").mkdir(parents=True)
    (tree / "build/config.h").write_text('#define GREETING "hello"\n', encoding="utf-8")
    (tree / "build/gen/version.h").write_text("#define V 1\n", encoding="utf-8")
    headers = ["build/config.h", "build/gen/version.h"]
    snap, summary = _export(tmp_path, {h: tree / h for h in headers}, ["build", "build/gen"])
    assert summary["files"] == 3 and summary["generated"] == 2
    assert (snap / "generated/build/config.h").read_text(encoding="utf-8").startswith("#define GREETING")
    _, plain = _export(tmp_path / "other", None, None)
    assert summary["digest"] != plain["digest"]

    monkeypatch.setenv("FRAMAC_SNAPSHOT_DIR", str(snap))
    gen = [(snap / "generated/build").as_posix(), (snap / "generated/build/gen").as_posix()]
    assert target_env.generated_include_flags() == ["-idirafter", gen[0], "-idirafter", gen[1]]
    flags = shlex.split(target_env.with_include_flags("-Iworkspace/work/build -DX=1"))
    assert flags[:2] == ["-Iworkspace/work/build", "-DX=1"]
    # Generated headers come before the target's system headers, each once.
    after = flags[flags.index("-idirafter") :]
    assert after[1] == gen[0] and after[3] == gen[1]
    again = shlex.split(target_env.with_include_flags(shlex.join(flags)))
    assert again.count(gen[0]) == 1
    # Every Frama-C run (Eva, WP, the kernel AST, the slices) goes through augment_framac_cppflags.
    assert gen[0] in shlex.split(framac_common.augment_framac_cppflags("-I."))


@pytest.mark.unit
def test_generated_dirs_never_leave_the_snapshot(tmp_path, monkeypatch):
    snap = tmp_path / "snapshot"
    (snap / "generated/build").mkdir(parents=True)
    (snap / "manifest.json").write_text(
        '{"digest": "d", "files": {}, "generated": {}, "generated_dirs": ["../..", "/etc", "build", 3]}',
        encoding="utf-8",
    )
    assert target_env.generated_include_flags(snap) == ["-idirafter", (snap / "generated/build").as_posix()]


@pytest.mark.unit
def test_the_fixture_generates_its_header_in_the_build_tree():
    assert not (FIXTURE / "build").exists()
    makefile = (FIXTURE / "Makefile").read_text(encoding="utf-8")
    assert "build/config.h:" in makefile and "-lz" in makefile
    assert '#include "config.h"' in (FIXTURE / "demo.c").read_text(encoding="utf-8")


# ------------------------------------------------------------------------------ resource classes


@pytest.mark.unit
@pytest.mark.parametrize(
    "cmd",
    [
        "python3 /opt/framac-pipeline/scripts/build_capture.py run",
        "python3 $S/build_capture.py run --recipe-file bench/spec.json",
        "python3 /opt/framac-pipeline/scripts/seed_harvest.py record",
        "python3 $S/seed_harvest.py record --recipe-file bench/spec.json --timeout 600",
        "python3 /opt/framac-pipeline/scripts/codeql_trust.py run && python3 /opt/framac-pipeline/scripts/trust.py run",
        "bash -lc 'python3 /opt/framac-pipeline/scripts/build_capture.py run'",
    ],
)
def test_phase0_steps_that_run_target_code_infer_phase_dynamic(cmd):
    assert resources.infer_class(cmd) == "phase-dynamic"
    assert resources.CLASSES["phase-dynamic"].runs_target_code
    assert not resources.is_known_static_command(cmd)


@pytest.mark.unit
@pytest.mark.parametrize(
    "cmd",
    [
        "python3 $S/build_capture.py propose",
        "python3 $S/seed_harvest.py write --module m",
        "python3 $S/seed_harvest.py write && echo record",
        "python3 $S/trust.py run",
    ],
)
def test_other_subcommands_keep_their_class(cmd):
    assert resources.infer_class(cmd) == "light"


# ------------------------------------------------------------------------------ wrappers, compose, images


@pytest.mark.unit
def test_wrappers_no_longer_chmod_the_scratch_volume():
    sh = (ROOT / "wrappers" / "framac-docker.sh").read_text(encoding="utf-8")
    ps1 = (ROOT / "wrappers" / "framac-docker.ps1").read_text(encoding="utf-8")
    for text in (sh, ps1):
        assert "volume create" in text and "/framac-scratch" in text
        assert not re.search(r"entrypoint\W+(/bin/)?chmod", text)
        assert "Failed to initialize scratch volume" not in text


@pytest.mark.unit
def test_both_images_create_the_scratch_directory_world_writable():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    stages = dockerfile_stages(text)
    assert [s.name for s in stages] == ["framac-build", "framac-opam", "framac-analysis"]
    # framac-opam only builds the switch the analysis image copies; no job runs in it.
    for stage in (s for s in stages if s.name != "framac-opam"):
        assert "/framac-scratch" in dockerfile_command_args(stage.text, "mkdir", "-p"), stage.name
        assert "/framac-scratch" in dockerfile_command_args(stage.text, "chmod", "1777"), stage.name
    # The two Debian bases stay aligned by pinned digests (decision D9).
    assert _unpinned_bases(text) == []
    assert "pinned digests" in text
    # The image build runs only the model selftest; the canaries run in CI.
    assert _image_script_runs(text) == [("phase0_model", "selftest")]


def _unpinned_bases(text: str) -> list[str]:
    """The base-image arguments of a Dockerfile that are not set, on a line of their own, to a full digest."""
    return [
        name
        for name in ("OPAM_BASE", "DEBIAN_BASE")
        if len(re.findall(rf"^ARG {name}=\S+@sha256:[0-9a-f]{{64}}$", text, re.MULTILINE)) != 1
        or len(re.findall(rf"^\s*ARG\s+{name}=", text, re.MULTILINE)) != 1
    ]


def _image_script_runs(text: str) -> list[tuple[str, str]]:
    """
    (script, subcommand) of every `python3 <script>.py <subcommand>` an image build runs, wherever it sits
    in a RUN instruction. Inline code (`python3 -c`) may patch a file of the image, never run the pipeline.
    """
    runs = []
    for argv in dockerfile_commands(text):
        if Path(argv[0]).name != "python3":
            continue
        if argv[1:2] == ["-c"]:
            assert "framac-pipeline" not in argv[2] and "selftest" not in argv[2], argv
            continue
        assert len(argv) > 1 and argv[1].endswith(".py"), f"python3 runs something other than a script: {argv}"
        runs.append((Path(argv[1]).stem, argv[2] if len(argv) > 2 else ""))
    return runs


DOCKERFILE_SAMPLE = """\
ARG OPAM_BASE=ocaml/opam:debian-13-ocaml-5.5@sha256:{digest}
ARG DEBIAN_BASE=debian:trixie-slim@sha256:{digest}
FROM ${{DEBIAN_BASE}} AS framac-build
RUN apt-get install -y python3 \\
    # a comment inside a continued instruction
    && mkdir -p /home/framac/.cache /framac-scratch /framac-cache \\
    && chmod 1777 /framac-cache /framac-scratch
FROM ${{DEBIAN_BASE}} AS framac-analysis
RUN chmod a+rx /home/opam /root && python3 -c "print('a; b && c')" \\
    && chmod 1777 /home/opam /framac-scratch
RUN python3 /opt/framac-pipeline/scripts/phase0_model.py selftest
""".format(digest="0123456789abcdef" * 4)


@pytest.mark.unit
def test_dockerfile_helpers_read_whole_commands():
    text = DOCKERFILE_SAMPLE
    build, analysis = dockerfile_stages(text)
    assert (build.base, build.name) == ("${DEBIAN_BASE}", "framac-build")
    # Arguments are a set per command and mode: order and line do not matter, a path of another mode is out.
    assert dockerfile_command_args(build.text, "chmod", "1777") == {"/framac-cache", "/framac-scratch"}
    assert dockerfile_command_args(build.text, "mkdir", "-p") >= {"/framac-scratch", "/framac-cache"}
    assert dockerfile_command_args(analysis.text, "chmod", "1777") == {"/home/opam", "/framac-scratch"}
    assert "/root" not in dockerfile_command_args(analysis.text, "chmod", "1777")
    # A quoted argument stays one word, operators inside it included; the apt package is not a command.
    assert ["python3", "-c", "print('a; b && c')"] in dockerfile_commands(text)
    assert _image_script_runs(text) == [("phase0_model", "selftest")]
    assert _unpinned_bases(text) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    ("old", "new"),
    [
        # A longer name is another directory (the old `chmod 1777 [^\n]*/framac-scratch` took it).
        ("&& chmod 1777 /framac-cache /framac-scratch\n", "&& chmod 1777 /framac-cache /framac-scratch-old\n"),
        ("/framac-scratch /framac-cache \\", "/framac-scratch-old /framac-cache \\"),
    ],
)
def test_a_scratch_directory_of_another_name_is_not_the_scratch_directory(old, new):
    assert old in DOCKERFILE_SAMPLE
    build = dockerfile_stages(DOCKERFILE_SAMPLE.replace(old, new))[0]
    created = dockerfile_command_args(build.text, "mkdir", "-p") & dockerfile_command_args(build.text, "chmod", "1777")
    assert "/framac-scratch" not in created


@pytest.mark.unit
@pytest.mark.parametrize(
    ("old", "new"),
    [
        # Commented out, with the pattern still on the line.
        ("ARG OPAM_BASE=", "ARG OPAM_BASE=ocaml/opam:debian-13-ocaml-5.5\n# ARG OPAM_BASE="),
        ("ARG DEBIAN_BASE=", "# ARG DEBIAN_BASE="),
        # 65 hexadecimal digits are not a digest.
        ("\nARG DEBIAN_BASE", "f\nARG DEBIAN_BASE"),
        ("@sha256:", ":"),
    ],
)
def test_a_base_image_without_a_full_digest_is_reported(old, new):
    assert old in DOCKERFILE_SAMPLE
    assert _unpinned_bases(DOCKERFILE_SAMPLE.replace(old, new, 1))


@pytest.mark.unit
@pytest.mark.parametrize(
    "extra",
    [
        # Chained on a continuation line of another RUN (the old `^RUN python3 ...` saw only the line start).
        "RUN echo ok \\\n    && python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py selftest\n",
        "RUN true; python3 /opt/framac-pipeline/scripts/stub_check.py run\n",
        "RUN  python3  /opt/framac-pipeline/scripts/run_eacsl_fuzz.py selftest\n",
    ],
)
def test_a_second_script_run_in_the_image_build_is_seen(extra):
    assert len(_image_script_runs(DOCKERFILE_SAMPLE + extra)) == 2


@pytest.mark.unit
def test_ci_checks_both_images():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "target: framac-build" in ci and "target: framac-analysis" in ci
    assert "image_toolchain.py compare" in ci
    assert "run_eacsl_fuzz.py selftest" in ci
    assert "tests/test_r8_images.py" in ci and "FRAMAC_DOCKER_TESTS" in ci


# ------------------------------------------------------------------------------ pyproject


@pytest.mark.unit
def test_every_script_module_is_first_party():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    block = re.search(r"^known-first-party = \[(.*?)^\]", text, re.MULTILINE | re.DOTALL)
    assert block
    first_party = re.findall(r'"([^"]+)"', block.group(1))
    modules = {p.stem for p in (ROOT / "scripts").glob("*.py")}
    assert modules <= set(first_party), sorted(modules - set(first_party))
    assert first_party == sorted(first_party)
