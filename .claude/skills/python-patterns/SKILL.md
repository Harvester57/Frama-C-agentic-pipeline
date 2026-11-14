---
name: python-patterns
description: Python 3.10+ conventions, type annotations, stdlib-only design, atomic file I/O, locking, and Ruff/mypy standards for the Frama-C verification pipeline (`scripts/` and `tests/`).
---

# Python Patterns (`frama-c` Pipeline)

Conventions and idioms enforced across `scripts/` and `tests/` in this repository.

## 1. Runtime & Dependency Rules

- **Target version:** Python **3.10+** (`target-version = "py310"` in `pyproject.toml`).
- **Stdlib-only in `scripts/`:** All pipeline helper scripts under `scripts/` execute both on the host (for the resource broker) and inside the hardened pipeline containers without third-party PyPI dependencies. Use only the Python standard library (`pathlib`, `json`, `subprocess`, `hashlib`, `argparse`, `dataclasses`, `shlex`, `tempfile`, `os`, `sys`, `typing`).
  - Only `scripts/extract_references.py` (a host-only PDF-to-Markdown maintainer utility) may optionally import `pymupdf` / `pypdf`.
  - Schema validation uses the stdlib-only validator in `scripts/minischema.py` (`validate(instance, schema)`).
- **UTF-8 everywhere:** Always pass `encoding="utf-8"` (and `errors="replace"` when decoding untrusted tool/compiler logs) to `Path.read_text`, `Path.write_text`, `open`, and `subprocess.run`. Set `$env:PYTHONIOENCODING="utf-8"` when invoking Python from PowerShell.

## 2. Type Annotations & Ruff / Mypy Standards

- **Modern PEP 585 / PEP 604 syntax (enforced by Ruff `UP`):**
  - Use built-in generics `list[str]`, `dict[str, Any]`, `tuple[int, ...]`, `set[str]` instead of `typing.List`, `Dict`, `Tuple`, `Set`.
  - Use union syntax `str | None` instead of `Optional[str]` or `Union[str, None]`.
- **Configuration (`pyproject.toml`):**
  - Line length: `120` (`E501` ignored; formatted via `ruff format`).
  - Enabled lint rules: `select = ["E", "F", "I", "UP", "B"]`.
  - First-party modules in `scripts/` and `tests/` are listed in `[tool.ruff.lint.isort] known-first-party`. Whenever you add a new `.py` module under `scripts/`, add its stem to `known-first-party` in `pyproject.toml`.
  - Mypy runs with `python_version = "3.10"`, `check_untyped_defs = true`, and `no_implicit_optional = true`.

```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SliceConfig:
    module: str
    sources: list[Path]
    max_size: int = 1500
    extra_cppflags: str | None = None
```

## 3. Shared Helpers (`scripts/framac_common.py`)

Prefer existing helpers in `scripts/framac_common.py` over re-implementing file I/O, locking, or path resolution:

- **Atomic JSON / file writes (`atomic_write_text`, `atomic_write_json`, `load_json`):**
  Never write directly to shared state files (`coverage-ledger.json`, `candidates.json`, `findings.json`, `run-metadata.json`, checkpoints, or scheduler state). Write to a temporary sibling file and `os.replace` atomically via `atomic_write_json(path, data)`.
- **Cross-container locks (`run_lock`):**
  Shared run-directory state is guarded by directory-based heartbeat locks (`with run_lock(run_dir, "ledger"):` or `"merge"`). Respect lock ordering and never hold a lock across an unbounded external subagent invocation.
- **Schema validation (`scripts/minischema.py` & `scripts/validate_artifacts.py`):**
  Every shared JSON artifact written to the run directory must conform to its schema in `schemas/*.schema.json`.
- **Argv flag normalization (`normalize_flag_args`):**
  Use `normalize_flag_args` when accepting pass-through compiler/Frama-C flags (`--cppflags`, `--ldflags`) on CLI entry points.

## 4. Subprocess & Sandbox Discipline

- **List-form `subprocess.run`:** Always pass argument lists (`["frama-c", "-wp", ...]`), never `shell=True`, when invoking tools from Python.
- **Target-controlled binaries:** Any binary compiled from target C code (LibFuzzer campaigns, E-ACSL guardrail replays, crash reproducers, or native target builds) must be executed through `scripts/sandbox_exec.py` (which enforces rlimits, environment allowlisting, and process-group timeouts) inside the hardened container.
- **No silent errors:** Distinguish tool outcomes (`all_proven`, `unproven_goals_remain`, `analysis_error`, `insufficient_memory`) explicitly in structured JSON reports rather than swallowing non-zero exit codes.

## 5. Verification Commands

Run these checks from PowerShell before finishing any Python change:

```powershell
$env:PYTHONIOENCODING="utf-8"
python -m ruff check scripts tests
python -m ruff format --check scripts tests
python -m mypy scripts tests
```
