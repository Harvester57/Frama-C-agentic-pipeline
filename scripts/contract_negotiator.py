#!/usr/bin/env python3
"""
Manages Caller-Callee ACSL Contract Strengthening Requests across Topological Waves.

When a Caller Subagent in Wave W fails a WP proof because a Callee function in Wave W-1
has a weak postcondition (`ensures`) or overly broad `assigns` clause in its `.h` header,
the Caller Subagent returns a strengthening request in its structured result instead of
editing the Callee's contract. The parent (the only writer of this ledger) records it here.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import atomic_write_json, load_json_optional, utc_now  # noqa: E402


def load_ledger(path: Path) -> dict:
    return load_json_optional(path, {"requests": []})


def save_ledger(path: Path, data: dict) -> None:
    atomic_write_json(path, data)


def cmd_request(
    ledger_path: Path,
    caller_fn: str,
    callee_fn: str,
    callee_file: str,
    header_file: str,
    needed_clause: str,
    reason: str,
) -> dict:
    ledger = load_ledger(ledger_path)
    # IDs derive from the highest existing sequence number, never from len(), so a
    # resolved or removed entry cannot cause a collision. The parent is the only writer.
    seqs = [int(r["id"].split("_")[1]) for r in ledger["requests"] if r.get("id", "").startswith("req_") and r["id"].split("_")[1].isdigit()]
    req_id = f"req_{(max(seqs) if seqs else 0) + 1:04d}_{caller_fn}_to_{callee_fn}"
    entry = {
        "id": req_id,
        "status": "pending",
        "caller_function": caller_fn,
        "callee_function": callee_fn,
        "callee_file": callee_file,
        "header_file": header_file,
        "needed_clause": needed_clause,
        "reason": reason,
        "resolution_note": "",
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    ledger["requests"].append(entry)
    save_ledger(ledger_path, ledger)
    return entry


def cmd_list(ledger_path: Path, status_filter: str | None = None, callee_filter: str | None = None) -> dict:
    ledger = load_ledger(ledger_path)
    reqs = ledger.get("requests", [])
    if status_filter:
        reqs = [r for r in reqs if r.get("status") == status_filter]
    if callee_filter:
        reqs = [r for r in reqs if r.get("callee_function") == callee_filter]
    return {"count": len(reqs), "requests": reqs}


def cmd_resolve(ledger_path: Path, req_id: str, new_status: str, note: str) -> dict:
    ledger = load_ledger(ledger_path)
    for r in ledger.get("requests", []):
        if r.get("id") == req_id:
            r["status"] = new_status
            r["resolution_note"] = note
            r["updated_at"] = utc_now()
            save_ledger(ledger_path, ledger)
            return r
    raise KeyError(f"Request ID '{req_id}' not found in {ledger_path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Caller-Callee ACSL Contract Strengthening Negotiator.")
    parser.add_argument(
        "--ledger",
        type=Path,
        default=Path("workspace/reports/strengthen_requests.json"),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_req = sub.add_parser("request")
    p_req.add_argument("--caller", required=True)
    p_req.add_argument("--callee", required=True)
    p_req.add_argument("--callee-file", required=True)
    p_req.add_argument("--header-file", required=True)
    p_req.add_argument("--needed-clause", required=True, help="e.g. 'ensures \\result <= max_len;'")
    p_req.add_argument("--reason", required=True)

    p_list = sub.add_parser("list")
    p_list.add_argument("--status", default=None, choices=["pending", "verified_and_applied", "rejected_by_callee"])
    p_list.add_argument("--callee", default=None)

    p_res = sub.add_parser("resolve")
    p_res.add_argument("--id", required=True)
    p_res.add_argument("--status", required=True, choices=["verified_and_applied", "rejected_by_callee"])
    p_res.add_argument("--note", required=True)

    args = parser.parse_args(argv)
    if args.cmd == "request":
        res = cmd_request(
            args.ledger,
            args.caller,
            args.callee,
            args.callee_file,
            args.header_file,
            args.needed_clause,
            args.reason,
        )
    elif args.cmd == "list":
        res = cmd_list(args.ledger, args.status, args.callee)
    elif args.cmd == "resolve":
        res = cmd_resolve(args.ledger, args.id, args.status, args.note)
    else:
        return 1

    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
