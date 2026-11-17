"""
Open topic O7, Docker-backed (FRAMAC_DOCKER_TESTS=1): a capture in the build image exports the build
image's `<elf.h>` and `<linux/audit.h>` (libc headers Frama-C's libc lacks) to the run's snapshot, and a
Frama-C parse in the analysis image reads those copies, before the image's own system directories.
"""

from __future__ import annotations

import json

import pytest

from conftest import ANALYSIS_IMAGE, BUILD_IMAGE, ROOT, require_docker_images
from test_r8_images import PY, _job_user, docker, volume  # noqa: F401  (volume is a fixture)

O7_FIXTURE = ROOT / "tests" / "fixtures" / "o7_libc_gaps"
SNAPSHOT_LIBC = "/framac-run/workspace/snapshot/libc"

pytestmark = [pytest.mark.integration, pytest.mark.slow]


def test_frama_c_reads_the_build_image_s_libc_gaps_from_the_snapshot(volume, tmp_path):  # noqa: F811
    require_docker_images(BUILD_IMAGE, ANALYSIS_IMAGE)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    user = _job_user(run_dir)
    common = [
        "run", "--rm", "--network", "none", "--user", user,
        "-v", f"{O7_FIXTURE.resolve()}:/target:ro", "-v", f"{run_dir.resolve()}:/framac-run",
        "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
        "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro", "-w", "/framac-run",
    ]  # fmt: skip
    cap = docker(
        [*common, "-v", f"{volume}:/framac-scratch", BUILD_IMAGE,
         f"{PY}/build_capture.py run --scratch /framac-scratch --recipe-file '' --command make"]
    )  # fmt: skip
    assert cap.returncode == 0, cap.stdout + cap.stderr
    report = json.loads((run_dir / "workspace/reports/build_capture.json").read_text(encoding="utf-8"))
    gaps = {g["path"]: g["package"] for g in report["snapshot"]["framac_libc_gaps"]}
    assert gaps["/usr/include/elf.h"] == "libc6-dev"
    assert gaps["/usr/include/linux/audit.h"] == "linux-libc-dev"
    assert "/usr/include/stdio.h" not in gaps
    manifest = json.loads((run_dir / "workspace/snapshot/manifest.json").read_text(encoding="utf-8"))
    assert set(gaps) == set(manifest["libc"])

    # The analysis image: the flags every Frama-C parse gets; its preprocessor writes the headers it read.
    check = (
        "set -e; "
        'A=$(python3 -c \'import sys; sys.path.insert(0, "/opt/framac-pipeline/scripts"); '
        'import framac_common; print(framac_common.augment_framac_cppflags("-I/target"))\'); '
        'echo "flags: $A"; '
        'frama-c -no-unicode -cpp-extra-args="$A -MD -MF /tmp/demo.d" /target/demo.c >/tmp/fc.log 2>&1 '
        "|| { cat /tmp/fc.log; exit 1; }; "
        "echo parsed; tr ' \\\\' '\\n\\n' < /tmp/demo.d | grep '^/' | sed 's/^/dep: /'"
    )
    ana = docker([*common, "--entrypoint", "bash", ANALYSIS_IMAGE, "-lc", check])
    assert ana.returncode == 0, ana.stdout + ana.stderr
    lines = ana.stdout.splitlines()
    flags = next(line for line in lines if line.startswith("flags: ")).split()
    after = [flags[i + 1] for i, w in enumerate(flags[:-1]) if w == "-idirafter"]
    assert after.index(f"{SNAPSHOT_LIBC}/usr/include") < after.index("/usr/include"), after
    deps = {line.removeprefix("dep: ") for line in lines if line.startswith("dep: ")}
    assert f"{SNAPSHOT_LIBC}/usr/include/elf.h" in deps, ana.stdout
    assert f"{SNAPSHOT_LIBC}/usr/include/linux/audit.h" in deps, ana.stdout
    # linux/types.h -> asm/types.h, through the build image's x86_64-linux-gnu/asm link (Debian keeps the
    # real files under /usr/lib/linux/uapi): exported where the #include finds it.
    assert f"{SNAPSHOT_LIBC}/usr/include/x86_64-linux-gnu/asm/types.h" in deps, ana.stdout
    image_copies = ("/usr/include/linux/", "/usr/include/asm", "/usr/include/x86_64-linux-gnu/asm/", "/usr/lib/linux/")
    assert not {d for d in deps if d.startswith(image_copies) or d == "/usr/include/elf.h"}, ana.stdout
    assert "parsed" in lines, ana.stdout
