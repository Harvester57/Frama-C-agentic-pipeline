"""image_toolchain.py: the build and analysis images must agree on Debian, gcc and glibc."""

import json
import re

import pytest

import image_toolchain
from conftest import ROOT, dockerfile_stages

BUILD = {"debian": "13.7", "gcc": "14.2.0", "glibc": "2.41-12+deb13u4", "clang": "Debian clang version 19.1.7"}


@pytest.mark.unit
def test_identical_shared_fields_compare_clean():
    assert image_toolchain.compare(BUILD, {**BUILD, "clang": "other"}) == []


@pytest.mark.unit
@pytest.mark.parametrize("field", image_toolchain.SHARED)
def test_a_different_or_missing_shared_field_is_reported(field):
    assert image_toolchain.compare(BUILD, {**BUILD, field: "x"})
    assert image_toolchain.compare(BUILD, {k: v for k, v in BUILD.items() if k != field})


@pytest.mark.unit
def test_compare_cli_exit_code(tmp_path, capsys):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(BUILD), encoding="utf-8")
    b.write_text(json.dumps({**BUILD, "glibc": "2.40"}), encoding="utf-8")
    assert image_toolchain.main(["compare", str(a), str(a)]) == 0
    assert image_toolchain.main(["compare", str(a), str(b)]) == 1
    assert "glibc" in capsys.readouterr().out


@pytest.mark.unit
def test_dockerfile_defines_the_build_and_analysis_images_with_the_analysis_image_last():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    # Every FROM counts, named or not: a trailing unnamed stage would be the image a plain build produces.
    assert [(s.base, s.name) for s in dockerfile_stages(text)] == [
        ("${DEBIAN_BASE}", "framac-build"),
        ("${FRAMAC_BASE}", "framac-analysis"),
    ]
    # The analysis image carries no build system or target library; the build image no Frama-C.
    analysis = text.split("AS framac-analysis", 1)[1]
    for absent in ("cmake", "bear", "ninja-build", "libssl-dev", "TARGET_APT_PACKAGES"):
        assert absent not in analysis, absent
    assert re.search(r"^FROM \$\{DEBIAN_BASE\} AS framac-build$", text, re.MULTILINE)
    build = text.split("AS framac-build", 1)[1].split("AS framac-analysis", 1)[0]
    assert "opam" not in build and "METACSL" not in build


@pytest.mark.unit
def test_codeql_image_builds_from_the_build_image_with_a_pinned_digest():
    text = (ROOT / "Dockerfile.codeql").read_text(encoding="utf-8")
    assert "ARG BUILD_IMAGE=framac-build" in text
    assert [(s.base, s.name) for s in dockerfile_stages(text)] == [("${BUILD_IMAGE}", "")]
    assert len(re.findall(r"^ARG CODEQL_SHA256=[0-9a-f]{64}$", text, re.MULTILINE)) == 1
    assert "sha256sum -c" in text
    assert "codeql" not in (ROOT / "Dockerfile").read_text(encoding="utf-8").lower()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("extra", "stage"),
    [
        ("FROM debian:trixie-slim\n", ("debian:trixie-slim", "")),  # the old `^FROM \S+ AS (\S+)$` skipped it
        ("FROM --platform=linux/amd64 debian:trixie-slim AS last\n", ("debian:trixie-slim", "last")),
        ("from scratch as tail\n", ("scratch", "tail")),
    ],
)
def test_every_from_is_a_stage_named_or_not(extra, stage):
    text = "ARG B=debian\nFROM ${B} AS framac-build\nRUN true\n# FROM commented AS out\nFROM x AS framac-analysis\n"
    assert [s.name for s in dockerfile_stages(text)] == ["framac-build", "framac-analysis"]
    stages = dockerfile_stages(text + extra)
    assert len(stages) == 3 and (stages[-1].base, stages[-1].name) == stage
