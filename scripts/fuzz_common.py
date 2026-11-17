"""
Constants and small helpers that more than one of the fuzz modules needs (D13): the fuzz build and run
timeouts and the sanitizer environment, the artifact kinds, sha256 and seed derivation, and the input
collection. Imported by fuzz_build and run_eacsl_fuzz; it imports no module of those.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from resources import CLASSES

# Wall-clock limit of each compile stage (e-acsl-gcc, clang); a hung toolchain must not hold a lease forever.
BUILD_TIMEOUT_S = CLASSES["build"].wall_timeout_s or 3600


# Per-input LibFuzzer -timeout: campaigns and replays (the campaign default), guardrails (contract
# checks add overhead). Fixed values, never derived from the machine.
DEFAULT_PER_INPUT_TIMEOUT_S = 10


# engine_used of a campaign that fuzzed with ASan+UBSan and then E-ACSL (`--engine auto`).
DUAL_ENGINE = "eacsl+sanitizers"


SANITIZER_RUNTIME_ENV = {
    "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
    "ASAN_OPTIONS": "abort_on_error=1",
}


ARTIFACT_KINDS = (
    ("crash-", "crash"),
    ("oom-", "oom"),
    ("timeout-", "timeout"),
    ("leak-", "leak"),
    ("slow-unit-", "slow_unit"),
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def derive_seed(binary: Path | str, module: str = "") -> int:
    """
    Deterministic LibFuzzer `-seed` for guardrail and replay runs: the first 32 bits of
    sha256("<resolved binary path>\\0<module>"), in 1..2^31-1 (libFuzzer reads 0 as "pick a
    random seed"). The same build at the same path mutates and replays identically on any machine.
    """
    digest = hashlib.sha256(f"{Path(binary).resolve().as_posix()}\0{module}".encode()).digest()
    return int.from_bytes(digest[:4], "big") % 2147483646 + 1


def _in_agent_scratch(path: Path | str) -> bool:
    """True under agents/<id>/scratch/: agent builds are never cached (they are scoped instead)."""
    parts = Path(os.path.abspath(path)).parts
    return any(parts[i] == "agents" and parts[i + 2] == "scratch" for i in range(len(parts) - 2))


def _artifact_kind(name: str) -> str | None:
    for prefix, kind in ARTIFACT_KINDS:
        if name.startswith(prefix):
            return kind
    return None


def replay_artifact_dir(scratch: Path) -> Path:
    """
    Where a replay's libFuzzer writes the `crash-<sha1>` (or leak-, timeout-, oom-) copy of a failing
    input: a directory of its own under the replay's writable `scratch`, never the working directory
    (without -artifact_prefix libFuzzer writes there, the run-dir root: QCBOR run-6, issue #15).
    """
    out = (Path(scratch) / "replay_artifacts").resolve()
    out.mkdir(parents=True, exist_ok=True)
    return out


DEFAULT_SELFTEST_JSON = Path("workspace/reports/eacsl_selftest.json")


def _collect_inputs(inputs: list[Path]) -> tuple[list[Path], list[str]]:
    """Files given directly or found (non-recursively) in given directories; missing paths separately."""
    files: list[Path] = []
    missing: list[str] = []
    seen: set[str] = set()
    for raw in inputs:
        path = Path(raw)
        if path.is_dir():
            found = sorted(c for c in path.iterdir() if c.is_file() and not c.name.startswith("."))
        elif path.is_file():
            found = [path]
        else:
            missing.append(str(raw))
            continue
        for f in found:
            key = os.path.abspath(f)
            if key not in seen:
                seen.add(key)
                files.append(f)
    return files, missing
