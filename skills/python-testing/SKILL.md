---
name: python-testing
description: Pytest testing conventions, fixtures, mocking, schema validation checks, and marker usage (`unit`, `integration`, `slow`) for the Frama-C verification pipeline (`tests/`).
---

# Python Testing (`frama-c` Pipeline)

Testing conventions for the `tests/` suite in this repository.

## 1. Running the Test Suite

From PowerShell on Windows (always set `PYTHONIOENCODING="utf-8"` and double-quote flags containing `=` or `.`):

```powershell
$env:PYTHONIOENCODING="utf-8"
python -m pytest tests
python -m pytest tests/test_validators.py -k "test_name"
python -m pytest "-m" "not slow" tests
```

`pyproject.toml` configures `pythonpath = ["scripts", "tests"]` and `--strict-markers`, so tests import pipeline modules directly by name (e.g., `import ledger`, `import resources`, `import workspace_overlay`).

## 2. Pytest Markers

Only the markers registered in `pyproject.toml` are allowed (`--strict-markers` is active):
- `@pytest.mark.unit`: fast, self-contained unit tests using `tmp_path` and mocks.
- `@pytest.mark.integration`: tests exercising multi-script workflows or container/toolchain interactions.
- `@pytest.mark.slow`: long-running tests.

## 3. Core Testing Conventions

- **Filesystem isolation with `tmp_path`:**
  Build synthetic run directories, `workspace/work/` trees, or broker state directories inside pytest's `tmp_path` fixture. Never mutate repository files or the user's `~/framac-pipeline` / `~/.cache/framac-pipeline` directories during tests (`monkeypatch.setenv("FRAMAC_CACHE_DIR", str(tmp_path / "cache"))` and `monkeypatch.setenv("FRAMAC_BROKER_DIR", str(tmp_path / "broker"))`).
- **Schema & artifact validation:**
  When testing scripts that emit or mutate `coverage-ledger.json`, `candidates.json`, `findings.json`, `run-metadata.json`, or `agent-result` JSONs, assert that `validate_artifacts.py` accepts the produced artifacts (and rejects intentionally malformed ones).
- **Cross-platform paths & line endings:**
  Tests run on Windows host Python as well as Linux inside the container.
  - Use `Path` methods and `.as_posix()` when comparing relative paths stored in JSON artifacts (`<rel-file>#<function>::<class>`).
  - Always specify `encoding="utf-8"` when reading or writing test files.
  - Remember that ACSL strings contain backslashes (`\valid`, `\forall`, `\false`, `\result`, `\at`); use raw strings (`r"/*@ requires \valid(p); */"`) or `json.dumps` when constructing test fixtures.
- **Mocking external tools (`monkeypatch`):**
  When unit-testing wrappers around `frama-c`, `e-acsl-gcc`, `clang`, `docker`, or `podman` on a host where the container toolchain is not installed natively, use `monkeypatch.setattr` on `subprocess.run` or the module's runner helper to simulate stdout/stderr, exit codes, and generated report files deterministically.
- **Skill mirror invariant:**
  The skill directories `skills/framac-*` and `.agents/skills/framac-*` must remain byte-for-byte identical. Tests in `tests/test_extract_references.py` enforce this invariant automatically.
