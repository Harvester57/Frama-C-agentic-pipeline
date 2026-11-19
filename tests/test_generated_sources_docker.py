"""
A source the build generates, end to end in the images (FRAMAC_DOCKER_TESTS=1).

nginx 1.31.9 run-3: link repair added `workspace/work/objs/ngx_modules.c`, which nginx's configure
generates in the scratch build tree; once Phase 0 removed the scratch volume no copy was left, and the
E-ACSL build failed with `source file '...' does not exist`. The fixture (tests/fixtures/generated_source)
does the same in miniature: gen_modules.sh writes gen/modules.c, which defines `gen_module_count`.

Steps, each in its own container with an explicit timeout: overlay init (analysis image), build capture
on a new scratch volume (build image), the volume removed, then `run_eacsl_fuzz.py build` of a harness
that calls `gen_module_count`, with a DAG that places it in gen/modules.c, so link repair has to add the
generated file (analysis image, no scratch volume, the target read-only).
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from conftest import ANALYSIS_IMAGE, BUILD_IMAGE, ROOT, require_docker_images

pytestmark = [pytest.mark.integration, pytest.mark.slow]

_FIXTURE = ROOT / "tests" / "fixtures" / "generated_source"
_PY = "python3 /opt/framac-pipeline/scripts"
_RECIPE = (
    "sh gen_modules.sh && cc -I. -c main.c -o main.o && cc -I. -c gen/modules.c -o gen/modules.o"
    " && cc -o app main.o gen/modules.o"
)
_HARNESS = """#include <stddef.h>
#include <stdint.h>
#include "modules.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    volatile int n = gen_module_count();
    (void)data;
    (void)size;
    (void)n;
    return 0;
}
"""
_NON_ROOT = "12345:12345"


def _docker(args: list[str], timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, check=False,
    )  # fmt: skip


@pytest.fixture
def run_tag() -> Iterator[str]:
    """This test's own label value; every container it starts carries it, and only those are cleaned up."""
    tag = f"generated-sources-{uuid.uuid4().hex[:12]}"
    yield tag
    ids = _docker(["ps", "-aq", "--filter", f"label=framac.test={tag}"]).stdout.split()
    if ids:
        _docker(["rm", "-f", *ids])


@pytest.fixture
def scratch_volume(run_tag: str) -> Iterator[str]:
    name = f"framac-scratch-{run_tag}"
    created = _docker(["volume", "create", "--label", "framac.scratch=1", "--label", f"framac.test={run_tag}", name])
    assert created.returncode == 0, created.stderr
    yield name
    _docker(["volume", "rm", "-f", name])


def _job_user(run_dir: Path) -> str:
    getuid, getgid = getattr(os, "getuid", None), getattr(os, "getgid", None)
    if getuid is not None and getgid is not None and getuid() != 0:
        return f"{getuid()}:{getgid()}"
    run_dir.chmod(0o777)
    return _NON_ROOT


@pytest.mark.parametrize("engine", ["eacsl", "sanitizers"])
def test_a_generated_source_survives_the_scratch_volume(engine, run_tag, scratch_volume, tmp_path):
    require_docker_images(BUILD_IMAGE, ANALYSIS_IMAGE)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    user = _job_user(run_dir)
    common = [
        "run", "--rm", "--network", "none", "--user", user, "--label", f"framac.test={run_tag}",
        "-v", f"{_FIXTURE.resolve()}:/target:ro", "-v", f"{run_dir.resolve()}:/framac-run",
        "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
        "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro",
        "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro", "-w", "/framac-run",
    ]  # fmt: skip

    def analysis(command: str, timeout: int) -> subprocess.CompletedProcess:
        return _docker([*common, "--entrypoint", "bash", ANALYSIS_IMAGE, "-lc", command], timeout=timeout)

    init = analysis(f"{_PY}/workspace_overlay.py init --target /target --overlay workspace", 300)
    assert init.returncode == 0, init.stdout + init.stderr

    cap = _docker(
        [*common, "-v", f"{scratch_volume}:/framac-scratch", BUILD_IMAGE,
         f"{_PY}/build_capture.py run --scratch /framac-scratch --recipe-file '' --command '{_RECIPE}'"],
        timeout=600,
    )  # fmt: skip
    assert cap.returncode == 0, cap.stdout + cap.stderr
    removed = _docker(["volume", "rm", "-f", scratch_volume])
    assert removed.returncode == 0, removed.stderr

    reports = run_dir / "workspace/reports"
    dag = {
        "functions": {
            "main.c#main": {"name": "main", "file": "main.c"},
            "gen/modules.c#gen_module_count": {"name": "gen_module_count", "file": "gen/modules.c"},
        }
    }
    (reports / "callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")
    harnesses = run_dir / "workspace/harnesses"
    harnesses.mkdir(parents=True, exist_ok=True)
    (harnesses / "harness_gen.c").write_bytes(_HARNESS.encode())
    out_json = f"workspace/reports/build_{engine}.json"
    build = analysis(
        f"timeout 900 {_PY}/run_eacsl_fuzz.py build --engine {engine} --no-cache --module gen"
        " --sources workspace/harnesses/harness_gen.c --cppflags '-Iworkspace/work'"
        f" --dag workspace/reports/callgraph_dag.json --out-bin workspace/harnesses/fuzz_gen_{engine}"
        f" --out-json {out_json}",
        1000,
    )
    res = json.loads((run_dir / out_json).read_text(encoding="utf-8"))
    logs = "".join(
        p.read_text(encoding="utf-8", errors="replace")[-2000:] for p in sorted(harnesses.glob("fuzz_gen_*.log"))
    )
    assert res["status"] == "built", (build.stdout + build.stderr)[-3000:] + logs
    assert res["engine_used"] == engine
    assert res["link_repair"]["added_sources"] == ["workspace/work/gen/modules.c"]
    assert "missing_sources" not in res["link_repair"]

    # Where it came from: the capture's snapshot (digest and manifest), installed in work/ and baseline/.
    report = json.loads((reports / "build_capture.json").read_text(encoding="utf-8"))
    assert report["snapshot"]["generated"]["sources"] == ["gen/modules.c"]
    manifest = json.loads((run_dir / "workspace/snapshot/manifest.json").read_text(encoding="utf-8"))
    assert "gen/modules.c" in manifest["generated_sources"]
    assert (run_dir / "workspace/snapshot/generated/gen/modules.c").is_file()
    for side in ("work", "baseline"):
        assert (run_dir / "workspace" / side / "gen/modules.c").is_file(), side
    assert not (_FIXTURE / "gen").exists()
