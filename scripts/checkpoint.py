#!/usr/bin/env python3
"""
Atomic JSON state and wave/shard checkpointing for Frama-C agentic skills.
Stores state in <state-dir>/progress.json and phase/wave payload files.

`status` is running | complete, or a blocking status a step records when the run must stop and wait
for the user, with the details under `blocked`:
  - `needs_build_recipe`: build_capture.py, when the target does not build (report path, first error);
  - `no_unit_parsed`: phase0_model.py, when Frama-C parses none of the units (report path, and each
    unit's first Frama-C error under `units`).
`blocked.resume_at` names the step a resumed run restarts at. `phase_done` is not advanced by a blocked
step, so a resumed run starts again at that step; the step clears the status when it succeeds.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import atomic_write_json, load_json_optional, utc_now  # noqa: E402


def load_json(path: Path) -> dict:
    return load_json_optional(path, {})


def cmd_init(state_dir: Path, target_dir: str, mode: str, force: bool = False) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    progress_path = state_dir / "progress.json"
    existing = load_json(progress_path) if progress_path.exists() else {}
    if existing and not force:
        # Re-running Phase 0 on a resumed run must never rewind the recorded progress.
        print(json.dumps({**existing, "init": "kept_existing"}))
        return
    progress = {
        "status": "running",
        "mode": mode,
        "target_dir": target_dir,
        "phase_done": -1,
        "current_wave": 0,
        "waves_done": [],
        "shards_done": {},
        "updated_at": utc_now(),
    }
    atomic_write_json(progress_path, progress)
    print(json.dumps(progress))


def cmd_load(state_dir: Path) -> None:
    progress_path = state_dir / "progress.json"
    if not progress_path.exists():
        print(json.dumps({"status": "absent"}))
        return
    data = load_json(progress_path)
    print(json.dumps(data))
    for line in blocked_lines(data):
        print(line, file=sys.stderr)


def blocked_lines(progress: dict) -> list[str]:
    """What a resume shows for a blocked run: the status, the step it restarts at, each unit's error."""
    blocked = progress.get("blocked") if isinstance(progress.get("blocked"), dict) else None
    if not blocked or progress.get("status") != blocked.get("status"):
        return []
    lines = [f"blocked: {blocked.get('status')}; a resumed run restarts at {blocked.get('resume_at') or 'that step'}"]
    for key in ("error", "first_error"):
        if blocked.get(key):
            lines.append(f"  {blocked[key]}")
    for unit, err in sorted((blocked.get("units") or {}).items()):
        lines.append(f"  {unit}: {err}")
    return lines


def cmd_save_phase(state_dir: Path, phase: int, from_file: Path | None) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    progress_path = state_dir / "progress.json"
    progress = load_json(progress_path)
    if not progress:
        progress = {
            "status": "running",
            "phase_done": -1,
            "current_wave": 0,
            "waves_done": [],
            "shards_done": {},
        }

    payload = load_json(from_file) if from_file is not None else {}
    phase_file = state_dir / f"phase{phase}.json"
    atomic_write_json(phase_file, payload)

    progress["phase_done"] = max(progress.get("phase_done", -1), phase)
    progress["updated_at"] = utc_now()
    atomic_write_json(progress_path, progress)
    print(json.dumps({"saved": str(phase_file), "phase_done": progress["phase_done"]}))


def cmd_save_shard(state_dir: Path, phase: int, shard_id: str, from_file: Path) -> None:
    progress_path = state_dir / "progress.json"
    progress = load_json(progress_path)
    if not progress:
        raise RuntimeError(f"State directory {state_dir} is not initialized.")

    payload = load_json(from_file)
    shard_dir = state_dir / f"phase{phase}_shards"
    shard_file = shard_dir / f"{shard_id}.json"
    atomic_write_json(shard_file, payload)

    shards_done = progress.setdefault("shards_done", {})
    phase_key = f"phase{phase}"
    phase_shards = shards_done.setdefault(phase_key, [])
    if shard_id not in phase_shards:
        phase_shards.append(shard_id)

    progress["updated_at"] = utc_now()
    atomic_write_json(progress_path, progress)
    print(json.dumps({"shard": shard_id, "file": str(shard_file)}))


def _new_progress(target_dir: str = "/target", mode: str = "verify") -> dict:
    return {
        "status": "running",
        "mode": mode,
        "target_dir": target_dir,
        "phase_done": -1,
        "current_wave": 0,
        "waves_done": [],
        "shards_done": {},
    }


# Blocking statuses -> the step (and its command) a resumed run restarts at.
BLOCKING_STEPS = {
    "needs_build_recipe": "build_capture.py run",
    "no_unit_parsed": "phase0_model.py run",
}


def mark_blocked(state_dir: Path, status: str, detail: dict) -> dict:
    """
    Record that the run stopped and waits for the user (`needs_build_recipe` from the build capture,
    `no_unit_parsed` from the model). `phase_done` is unchanged, so a resumed run starts again at the
    step that stopped (`blocked.resume_at`).
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    progress_path = state_dir / "progress.json"
    progress = load_json(progress_path) or _new_progress()
    progress["status"] = status
    resume = {"resume_at": BLOCKING_STEPS[status]} if status in BLOCKING_STEPS else {}
    progress["blocked"] = {"status": status, **resume, **detail, "at": utc_now()}
    progress["updated_at"] = utc_now()
    atomic_write_json(progress_path, progress)
    return progress


def clear_blocked(state_dir: Path, status: str) -> dict | None:
    """Clear a `mark_blocked` status once the step that stopped succeeds (no-op otherwise)."""
    progress_path = state_dir / "progress.json"
    progress = load_json(progress_path)
    if not progress or progress.get("status") != status:
        return None
    progress["status"] = "running"
    progress.pop("blocked", None)
    progress["updated_at"] = utc_now()
    atomic_write_json(progress_path, progress)
    return progress


def cmd_complete(state_dir: Path) -> None:
    progress_path = state_dir / "progress.json"
    progress = load_json(progress_path)
    progress["status"] = "complete"
    progress["updated_at"] = utc_now()
    atomic_write_json(progress_path, progress)
    print(json.dumps(progress))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Atomic checkpoint manager for Frama-C pipeline skills.")
    sub = parser.add_subparsers(dest="action", required=True)

    p_init = sub.add_parser("init")
    p_init.add_argument("state_dir", type=Path)
    p_init.add_argument("--target", default=".")
    p_init.add_argument("--mode", default="verify")
    p_init.add_argument("--force", action="store_true", help="Reset an existing progress file")

    p_load = sub.add_parser("load")
    p_load.add_argument("state_dir", type=Path)

    for save_cmd in ("save-phase", "save"):
        p_save = sub.add_parser(save_cmd)
        p_save.add_argument("state_dir", type=Path)
        p_save.add_argument("--phase", "--phase-done", dest="phase", type=int, required=True)
        p_save.add_argument("--from-file", type=Path, default=None)

    p_shard = sub.add_parser("save-shard")
    p_shard.add_argument("state_dir", type=Path)
    p_shard.add_argument("--phase", "--phase-done", dest="phase", type=int, required=True)
    p_shard.add_argument("--shard-id", required=True)
    p_shard.add_argument("--from-file", type=Path, required=True)

    p_comp = sub.add_parser("complete")
    p_comp.add_argument("state_dir", type=Path)

    args = parser.parse_args(argv)
    if args.action == "init":
        cmd_init(args.state_dir, args.target, args.mode, force=args.force)
    elif args.action == "load":
        cmd_load(args.state_dir)
    elif args.action in ("save-phase", "save"):
        cmd_save_phase(args.state_dir, args.phase, args.from_file)
    elif args.action == "save-shard":
        cmd_save_shard(args.state_dir, args.phase, args.shard_id, args.from_file)
    elif args.action == "complete":
        cmd_complete(args.state_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
