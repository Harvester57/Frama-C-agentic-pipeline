# Running the tests in parallel

The suite runs in parallel with [pytest-xdist](https://pypi.org/project/pytest-xdist/). Run every command from the repository root, where `pyproject.toml` sets the test paths and markers.

## Setup (once)

```bash
python -m pip install pytest pytest-xdist
```

## Run

```powershell
# Windows (PowerShell)
$env:PYTHONIOENCODING="utf-8"
python -m pytest tests -n auto
```

```bash
# Linux / macOS
python3 -m pytest tests -n auto
```

`-n auto` starts one worker per CPU core. The full unit suite takes about a minute in parallel on a typical workstation, against several minutes serially.

## Useful variants

| Goal | Command |
| --- | --- |
| Fixed worker count (shared or small machine) | `python -m pytest tests -n 4` |
| Keep each test file on one worker | `python -m pytest tests -n auto --dist loadfile` |
| One marker only | `python -m pytest tests -n auto -m unit` |
| One file or test | `python -m pytest tests/test_ledger.py -n auto` |
| Stop at the first failure | `python -m pytest tests -n auto -x` |
| Serial (debugging, `pdb`, clean output) | `python -m pytest tests -n 0` |

## Docker-backed tests

Tests that start containers are skipped unless `FRAMAC_DOCKER_TESTS=1` is set and both images are built. They can run in parallel too, but each worker starts its own containers, so cap the workers to what the machine can hold:

```powershell
$env:FRAMAC_DOCKER_TESTS="1"
python -m pytest tests -n 4
```

```bash
FRAMAC_DOCKER_TESTS=1 python3 -m pytest tests -n 4
```

## Notes

- Tests must not share state across workers: write only under `tmp_path` (or the `run_dir` fixture), never into the repository.
- Session-scoped fixtures run once per worker, not once per run.
- If a test fails only in parallel, rerun it with `-n 0` to tell an ordering or shared-state bug from a real failure.
