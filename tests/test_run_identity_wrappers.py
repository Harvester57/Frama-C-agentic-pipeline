"""Run identity in the wrappers: repo key, run tag, container and volume labels, derived tags, atomic --new-run."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import ROOT
from test_sandbox_and_overlay import DOCKER_INFO

SH = ROOT / "wrappers" / "framac-docker.sh"
PS1 = ROOT / "wrappers" / "framac-docker.ps1"
HEX12 = "[0-9a-f]{12}"
IDENTITY = re.compile(r"^\[framac-docker\] run identity: (\S+) / (\S+)$", re.M)
RUN_DIR_LINE = re.compile(r"^\[framac-docker\] run dir: (.+)$", re.M)

# A `docker` that logs every call (one JSON argv per line), answers info/images/image/--version, and reports
# every volume as missing so the wrapper creates it.
FAKE_ENGINE = """\
import json, pathlib, sys
here = pathlib.Path(__file__).parent
args = sys.argv[1:]
with open(here / "calls.jsonl", "a", encoding="utf-8") as f:
    f.write(json.dumps(args) + "\\n")
cmd = args[0] if args else ""
if cmd == "info":
    print((here / "info.json").read_text())
elif cmd == "images":
    print("sha256:deadbeef")
elif cmd == "image":
    print("sha256:feedface")
elif cmd == "--version":
    print("Docker version 28.0.0")
elif cmd == "volume" and args[1:2] == ["inspect"]:
    sys.exit(1)
"""


def _short_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def _fake_engine(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "info.json").write_text(json.dumps(DOCKER_INFO), encoding="utf-8")
    script = bin_dir / "fake_engine.py"
    script.write_text(FAKE_ENGINE, encoding="utf-8")
    if os.name == "nt":
        (bin_dir / "docker.cmd").write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
    else:
        shim = bin_dir / "docker"
        shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
        shim.chmod(0o700)
    (tmp_path / "target_repo").mkdir()
    (tmp_path / "run_1").mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("FRAMAC_")}
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
    env.update(
        FRAMAC_PYTHON=sys.executable,
        FRAMAC_BROKER_DIR=str(tmp_path / "broker"),
        FRAMAC_CACHE_DIR=str(tmp_path / "cache"),
        FRAMAC_POOL_CPUS="2",
        FRAMAC_POOL_MEMORY="4g",
        PYTHONDONTWRITEBYTECODE="1",
    )
    return bin_dir / "calls.jsonl", env


def _calls(log: Path) -> list[list[str]]:
    calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    log.unlink()
    return calls


def _labels(args: list[str]) -> dict[str, str]:
    return dict(b.split("=", 1) for a, b in zip(args, args[1:], strict=False) if a == "--label")


def _envs(args: list[str]) -> dict[str, str]:
    return dict(b.split("=", 1) for a, b in zip(args, args[1:], strict=False) if a == "-e" and "=" in b)


def _identity(stderr: str) -> tuple[str, str, str]:
    m = IDENTITY.search(stderr)
    d = RUN_DIR_LINE.search(stderr)
    assert m and d, stderr
    return m.group(1), m.group(2), d.group(1).strip()


def _pwsh() -> str:
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:
        pytest.skip("pwsh/powershell not available")
    return pwsh


def _ps1(pwsh: str, *args: str) -> list[str]:
    return [pwsh, "-NoProfile", "-File", str(PS1), *args]


# ------------------------------------------------------------------------------------------- static checks


@pytest.mark.unit
def test_both_wrappers_define_the_run_identity_and_forward_it():
    sh = SH.read_text(encoding="utf-8")
    ps1 = PS1.read_text(encoding="utf-8")
    # repo key = name (cut to fit a 128-char tag) + 12 hex of the target path; run tag = run id + 12 hex of the run dir
    assert 'REPO_KEY="${REPO:0:115}-$(short_hash "${RESOLVED_TARGET}")"' in sh
    assert 'RUN_TAG="${RUN_ID}-${RUN_HASH}"' in sh and 'RUN_HASH="$(short_hash "${RESOLVED_RUN}")"' in sh
    assert "$RepoName.Substring(0, 115)" in ps1 and '$RepoKey = "$repoPart-$(Get-ShortHash $ResolvedTarget)"' in ps1
    assert '$RunTag = "$RunId-$runHash"' in ps1 and "$runHash = Get-ShortHash $ResolvedRun" in ps1
    # forwarded to the container and exported to the host broker
    assert '-e "FRAMAC_REPO_KEY=${REPO_KEY}" -e "FRAMAC_RUN_TAG=${RUN_TAG}"' in sh
    assert 'export FRAMAC_REPO_KEY="${REPO_KEY}"' in sh and 'export FRAMAC_RUN_TAG="${RUN_TAG}"' in sh
    assert '"-e", "FRAMAC_REPO_KEY=$RepoKey"' in ps1 and '"-e", "FRAMAC_RUN_TAG=$RunTag"' in ps1
    assert "$env:FRAMAC_REPO_KEY = $RepoKey" in ps1 and "$env:FRAMAC_RUN_TAG = $RunTag" in ps1
    # labels on both container paths
    assert 'LABEL_ARGS=(--label "framac.repo=${REPO_KEY}" --label "framac.run=${RUN_TAG}")' in sh
    assert sh.count('"${ENGINE}" run "${HARDENING[@]}" "${LABEL_ARGS[@]}"') == 2
    assert '$labelArgs = @("--label", "framac.repo=$RepoKey", "--label", "framac.run=$RunTag")' in ps1
    assert "$hardeningArgs + $labelArgs + $selinuxArgs" in ps1 and '@("run") + $hardeningArgs + $labelArgs' in ps1
    # derived images and the scratch volume
    assert 'DERIVED_IMAGE="framac-build:${REPO_KEY}"' in sh and 'CODEQL_IMAGE="framac-codeql:${REPO_KEY}"' in sh
    assert '$DerivedImage = "framac-build:$RepoKey"' in ps1 and '$codeqlImage = "framac-codeql:$RepoKey"' in ps1
    assert not re.search(r"framac-(build|codeql):(\$\{REPO\}|\$RepoName)", sh + ps1)
    assert 'volume create --label framac.scratch=1 --label "framac.repo=${REPO_KEY}"' in sh
    assert '"--label" "framac.scratch=1" "--label" "framac.repo=$RepoKey"' in ps1
    assert 'SCRATCH_VOLUME="framac-scratch-${REPO}-${RUN_ID}-${RUN_HASH}"' in sh  # existing volumes still found
    assert '$ScratchVolume = "framac-scratch-$RepoName-$RunId-$runHash"' in ps1


@pytest.mark.unit
def test_new_run_claims_the_directory_with_a_create_that_fails_when_it_exists():
    sh = SH.read_text(encoding="utf-8")
    block = sh.split("# new-run allocation:", 1)[1].split("# end new-run allocation", 1)[0]
    assert 'until mkdir "${BASE}/run-${N}" 2>/dev/null; do' in block and "N=$((N + 1))" in block
    assert "mkdir -p" not in block and "ATTEMPTS >= 1000" in block
    ps1 = PS1.read_text(encoding="utf-8")
    block = ps1.split("# new-run allocation:", 1)[1].split("# end new-run allocation", 1)[0]
    assert "New-Item -ItemType Directory -Path $candidate -ErrorAction Stop" in block
    assert not any("-Force" in line for line in block.splitlines() if not line.lstrip().startswith("#"))
    assert "[System.IO.FileShare]::None" in block and "$lock.Dispose()" in block and "$n++" in block


@pytest.mark.unit
def test_both_images_create_the_cache_directory_world_writable():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    build, analysis = text.split("AS framac-build", 1)[1].split("AS framac-analysis", 1)
    for stage in (build, analysis):
        assert re.search(r"mkdir -p [^\n]*/framac-scratch /framac-cache", stage)
        assert re.search(r"chmod 1777 [^\n]*/framac-scratch /framac-cache", stage)


@pytest.mark.unit
def test_compose_labels_both_services():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert compose.count("      framac.repo: ${FRAMAC_REPO_KEY:-manual}\n") == 2
    assert compose.count("      framac.run: ${FRAMAC_RUN_ID:-run-1}\n") == 2


# ------------------------------------------------------------------------------------- PowerShell wrapper


@pytest.mark.integration
def test_ps1_labels_and_forwards_the_run_identity_on_both_paths(tmp_path):
    pwsh = _pwsh()
    log, env = _fake_engine(tmp_path)
    base = _ps1(pwsh, "-TargetDir", str(tmp_path / "target_repo"), "-RunDir", str(tmp_path / "run_1"))
    keys = set()
    for extra in (["-NoBroker"], []):
        proc = subprocess.run([*base, *extra, "true"], env=env, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr or proc.stdout
        repo_key, run_tag, run_dir = _identity(proc.stderr)
        assert re.fullmatch(f"target_repo-{HEX12}", repo_key), repo_key
        assert run_tag == f"run_1-{_short_hash(run_dir)}"
        run = [c for c in _calls(log) if c[:1] == ["run"]]  # the broker may probe first: the job runs last
        labels = _labels(run[-1])
        assert labels["framac.repo"] == repo_key and labels["framac.run"] == run_tag, (extra, labels)
        env_in = _envs(run[-1])
        assert env_in["FRAMAC_REPO_KEY"] == repo_key and env_in["FRAMAC_RUN_TAG"] == run_tag
        assert env_in["FRAMAC_REPO"] == "target_repo"
        keys.add(repo_key)
    assert len(keys) == 1  # stable for the same target

    # Same folder name, another path: another repo key.
    other = tmp_path / "elsewhere" / "target_repo"
    other.mkdir(parents=True)
    proc = subprocess.run(
        [*_ps1(pwsh, "-TargetDir", str(other), "-RunDir", str(tmp_path / "run_1")), "-NoBroker", "true"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert _identity(proc.stderr)[0] not in keys


@pytest.mark.integration
def test_ps1_tags_derived_images_and_labels_the_scratch_volume_with_the_repo_key(tmp_path):
    pwsh = _pwsh()
    log, env = _fake_engine(tmp_path)
    base = _ps1(pwsh, "-TargetDir", str(tmp_path / "target_repo"), "-RunDir", str(tmp_path / "run_1"), "-NoBroker")

    proc = subprocess.run(
        [*base, "-BuildImage", "-Scratch", "-TargetPackages", "check", "true"], env=env, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    repo_key, run_tag, _ = _identity(proc.stderr)
    calls = _calls(log)
    builds = [c for c in calls if c[:1] == ["build"]]
    assert any(("-t", f"framac-build:{repo_key}") in set(zip(c, c[1:], strict=False)) for c in builds), builds
    create = [c for c in calls if c[:2] == ["volume", "create"]]
    assert len(create) == 1
    assert _labels(create[0]) == {"framac.scratch": "1", "framac.repo": repo_key, "framac.run": run_tag}
    volume = create[0][-1]
    assert volume == f"framac-scratch-target_repo-{run_tag}"  # the name keeps its old form: <repo>-<run id>-<hash>
    run = next(c for c in calls if c[:1] == ["run"])
    assert f"framac-build:{repo_key}" in run and f"{volume}:/framac-scratch" in run

    proc = subprocess.run(
        [*base, "-CodeQL", "-TargetPackages", "check", "true"], env=env, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    calls = _calls(log)
    run = next(c for c in calls if c[:1] == ["run"])
    assert f"framac-codeql:{repo_key}" in run
    assert any(f"framac-codeql:{repo_key}" in c for c in calls if c[:1] == ["build"])


@pytest.mark.integration
def test_ps1_cuts_a_long_repo_name_to_fit_a_docker_tag(tmp_path):
    pwsh = _pwsh()
    _log, env = _fake_engine(tmp_path)
    name = "r" * 140
    proc = subprocess.run(
        [
            *_ps1(pwsh, "-TargetDir", str(tmp_path / "target_repo"), "-RunDir", str(tmp_path / "run_1")),
            "-RepoName",
            name,
            "-NoBroker",
            "true",
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    repo_key = _identity(proc.stderr)[0]
    assert len(repo_key) == 128 and re.fullmatch("r{115}-" + HEX12, repo_key)


@pytest.mark.integration
@pytest.mark.slow
def test_ps1_concurrent_new_runs_get_distinct_directories(tmp_path):
    pwsh = _pwsh()
    _log, env = _fake_engine(tmp_path)
    home = tmp_path / "home"
    (home / "framac-pipeline" / "target_repo" / "run-2").mkdir(parents=True)
    env.update(HOME=str(home), USERPROFILE=str(home))
    argv = [*_ps1(pwsh, "-TargetDir", str(tmp_path / "target_repo"), "-NewRun", "-NoBroker"), "true"]

    def one(_: int) -> str:
        proc = subprocess.run(argv, env=env, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
        return _identity(proc.stderr)[2]

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        run_dirs = list(pool.map(one, range(6)))
    names = sorted(Path(d).name for d in run_dirs)
    assert len(set(names)) == 6, names
    assert names == sorted(f"run-{n}" for n in range(3, 9))


# ------------------------------------------------------------------------------------------- bash wrapper


def _bash() -> str:
    """bash on PATH; on Windows Git for Windows' bash (System32's bash.exe is WSL and does not see these paths)."""
    bash = shutil.which("bash")
    if os.name == "nt":
        git = shutil.which("git")
        cand = Path(git).resolve().parents[1] / "bin" / "bash.exe" if git else None
        bash = str(cand) if cand and cand.is_file() else None
    if not bash:
        pytest.skip("bash not available")
    return bash


@pytest.mark.integration
def test_sh_new_run_allocation_is_atomic_under_concurrency(tmp_path):
    """Run the wrapper's own allocation block in many bash processes at once: every run-<N> is claimed once."""
    bash = _bash()
    sh = SH.read_text(encoding="utf-8")
    block = sh.split("# new-run allocation:", 1)[1].split("# end new-run allocation", 1)[0]
    script = tmp_path / "alloc.sh"
    script.write_text(
        'set -euo pipefail\nBASE="$1"\nmkdir -p "${BASE}"\n# new-run allocation:' + block + 'echo "${RUN_DIR}"\n',
        encoding="utf-8",
        newline="\n",
    )
    base = (tmp_path / "base").as_posix()
    (tmp_path / "base" / "run-1").mkdir(parents=True)

    def one(_: int) -> str:
        proc = subprocess.run([bash, script.as_posix(), base], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
        return proc.stdout.strip().rsplit("/", 1)[-1]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        names = list(pool.map(one, range(8)))
    assert sorted(names, key=lambda n: int(n[4:])) == [f"run-{n}" for n in range(2, 10)], names


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="the bash wrapper targets POSIX hosts (Windows uses framac-docker.ps1)")
def test_sh_labels_and_forwards_the_run_identity(tmp_path):
    bash = _bash()
    log, env = _fake_engine(tmp_path)
    base = [bash, str(SH), "--target", str(tmp_path / "target_repo"), "--run-dir", str(tmp_path / "run_1")]
    for extra in (["--no-broker"], []):
        proc = subprocess.run([*base, *extra, "--", "true"], env=env, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
        repo_key, run_tag, run_dir = _identity(proc.stderr)
        # The wrapper resolves both paths the same way (cd && pwd): the target sits next to run_1.
        assert repo_key == f"target_repo-{_short_hash(str(Path(run_dir).parent / 'target_repo'))}"
        assert run_tag == f"run_1-{_short_hash(run_dir)}"
        run = [c for c in _calls(log) if c[:1] == ["run"]][-1]
        assert _labels(run)["framac.repo"] == repo_key and _labels(run)["framac.run"] == run_tag
        assert _envs(run)["FRAMAC_REPO_KEY"] == repo_key and _envs(run)["FRAMAC_RUN_TAG"] == run_tag

    proc = subprocess.run(
        [*base, "--no-broker", "--build-image", "--scratch", "--target-packages", "check", "--", "true"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    repo_key, run_tag, _ = _identity(proc.stderr)
    calls = _calls(log)
    create = next(c for c in calls if c[:2] == ["volume", "create"])
    assert _labels(create) == {"framac.scratch": "1", "framac.repo": repo_key, "framac.run": run_tag}
    assert create[-1] == f"framac-scratch-target_repo-{run_tag}"
    assert f"framac-build:{repo_key}" in next(c for c in calls if c[:1] == ["run"])

    home = tmp_path / "home"
    env["HOME"] = str(home)
    new = [bash, str(SH), "--target", str(tmp_path / "target_repo"), "--new-run", "--no-broker", "--", "true"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        procs = list(pool.map(lambda _: subprocess.run(new, env=env, capture_output=True, text=True), range(4)))
    assert all(p.returncode == 0 for p in procs), [p.stderr for p in procs]
    assert sorted(Path(_identity(p.stderr)[2]).name for p in procs) == [f"run-{n}" for n in range(1, 5)]
