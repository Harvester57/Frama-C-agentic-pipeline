#!/usr/bin/env python3
"""
Manages Caller-Callee ACSL Contract Strengthening Requests across Topological Waves.

When a Caller Subagent in Wave W fails a WP proof because a Callee function in Wave W-1
has a weak postcondition (`ensures`) or overly broad `assigns` clause in its `.h` header,
the Caller Subagent returns a strengthening request in its structured result instead of
editing the Callee's contract. The parent (the only writer of this ledger) records it here,
under the run-wide `ledger` lock (framac_common.run_lock).
"""

from __future__ import annotations

import argparse
import functools
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import atomic_write_json, load_agent_result_json, load_json_optional, run_lock, utc_now  # noqa: E402


def _locked(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        with run_lock("ledger"):
            return fn(*args, **kwargs)

    return wrapper


def load_ledger(path: Path) -> dict:
    return load_json_optional(path, {"requests": []})


def save_ledger(path: Path, data: dict) -> None:
    atomic_write_json(path, data)


@_locked
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


def _infer_callee_file(
    callee_fn: str,
    header_file: str,
    coverage_ledger_path: Path,
    dag_path: Path,
) -> str:
    cov = load_json_optional(coverage_ledger_path, [])
    if isinstance(cov, list):
        for u in cov:
            if isinstance(u, dict) and u.get("function") == callee_fn and u.get("file"):
                return str(u["file"])
    dag = load_json_optional(dag_path, {})
    if isinstance(dag, dict):
        fmeta = (dag.get("functions") or {}).get(callee_fn)
        if isinstance(fmeta, dict) and fmeta.get("file"):
            return str(fmeta["file"])
    return Path(header_file).with_suffix(".c").as_posix()


@_locked
def cmd_ingest_prover(
    ledger_path: Path,
    result_path: Path,
    coverage_ledger_path: Path = Path("coverage-ledger.json"),
    dag_path: Path = Path("workspace/reports/callgraph_dag.json"),
) -> dict:
    """
    Ingest `strengthening_requests` from a prover's `result.json`, inferring `callee_file`
    from `coverage-ledger.json` or `callgraph_dag.json` when omitted, and deduplicating
    identical `(caller_function, callee_function, needed_clause)` requests.
    """
    res = load_agent_result_json(result_path)
    caller_fn = str(res.get("function") or "")
    raw_reqs = res.get("strengthening_requests") or []
    ledger = load_ledger(ledger_path)
    existing_keys = {
        (r.get("caller_function"), r.get("callee_function"), r.get("needed_clause"))
        for r in ledger.get("requests", [])
    }

    added: list[dict] = []
    skipped = 0
    for item in raw_reqs:
        callee_fn = str(item.get("callee") or "")
        header_file = str(item.get("header_file") or "")
        needed_clause = str(item.get("needed_clause") or "")
        reason = str(item.get("reason") or "")
        if not (caller_fn and callee_fn and header_file and needed_clause):
            continue
        key = (caller_fn, callee_fn, needed_clause)
        if key in existing_keys:
            skipped += 1
            continue
        callee_file = item.get("callee_file") or _infer_callee_file(
            callee_fn, header_file, coverage_ledger_path, dag_path
        )
        entry = cmd_request(
            ledger_path=ledger_path,
            caller_fn=caller_fn,
            callee_fn=callee_fn,
            callee_file=str(callee_file),
            header_file=header_file,
            needed_clause=needed_clause,
            reason=reason,
        )
        existing_keys.add(key)
        added.append(entry)

    return {
        "caller_function": caller_fn,
        "added_count": len(added),
        "added_requests": added,
        "skipped_duplicates": skipped,
    }


def cmd_list(ledger_path: Path, status_filter: str | None = None, callee_filter: str | None = None) -> dict:
    ledger = load_ledger(ledger_path)
    reqs = ledger.get("requests", [])
    if status_filter:
        reqs = [r for r in reqs if r.get("status") == status_filter]
    if callee_filter:
        reqs = [r for r in reqs if r.get("callee_function") == callee_filter]
    return {"count": len(reqs), "requests": reqs}


@_locked
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

    p_ing = sub.add_parser("ingest-prover")
    p_ing.add_argument("result", type=Path)
    p_ing.add_argument("--coverage-ledger", type=Path, default=Path("coverage-ledger.json"))
    p_ing.add_argument("--dag", type=Path, default=Path("workspace/reports/callgraph_dag.json"))

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
    elif args.cmd == "ingest-prover":
        res = cmd_ingest_prover(args.ledger, args.result, args.coverage_ledger, args.dag)
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

