#!/usr/bin/env python3
"""
Cross-run proof carry-forward (stdlib only): the `proofs` namespace of cache.py.

Publishing. `pipeline_make.py sweep` (the trusted end-of-run re-proof, no WP cache) calls
`publish_proof` for every function it re-proved `all_proven`. The entry holds the function's
annotated definition span, its header prototype span, the top-level ACSL declarations its
annotations name, and the swept WP report. It goes to the run store, and to the shared store only
with FRAMAC_CACHE_MODE=rw.

Replay. `pipeline_make.py wp-replay` (Make target `wp-replay`, after the Phase 3 gate and before
`wp_scheduler.py init`) calls `replay`: for each function with `planned` ledger units, callees
first, a hit is spliced into a parent-owned scratch agent and merged through the ordinary
`workspace_overlay.merge_agent_overlay` path (ACSL-only and scope checks, guardrail, parent WP on
the merged tree). Only a merge whose parent WP re-check is `all_proven` credits units, through
`ledger.py ingest-wp` of that new report; `ledger.py mark-carried` then records the evidence as
`carried_forward_reproven`. Anything else rolls back and leaves the units `planned`, so the prover
runs as before. A cached proof never changes a verdict on its own.

Key (what the proof depends on, computable on a fresh tree before Phase 3): the C tokens of the
function's file and of its header (every ACSL annotation and comment stripped, so the contract
being carried does not key itself), the contracts of its direct callees on the current tree, the
module's WP cppflags and extra sources, and the machdep; `cache.make_key` adds the toolchain and
the scripts/templates digest.

FRAMAC_PROOF_CARRY=off disables both publishing and replay (A/B switch; default on).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cache  # noqa: E402
from acsl_ast import (  # noqa: E402
    AcslError,
    AcslSyntaxError,
    check_frame_preserved,
    extract_top_level_acsl_declarations,
    function_contract_text,
    locate_function_span,
    tokenize_c_acsl,
)
from framac_common import ArtifactError, atomic_write_json, load_json_optional, utc_now  # noqa: E402

NS = "proofs"
KEY_VERSION = 1
MACHDEP = "gcc_x86_64"  # run_wp_function.py's default; never overridden by the pipeline
SUMMARY_REL = "workspace/reports/proof-carry/summary.json"
STATE_REL = "state/proof-carry"
LEDGER_JSON = "coverage-ledger.json"
DAG_JSON = "workspace/reports/callgraph_dag.json"
CARRIED_RESULT = "carried_forward_reproven"
_OFF = ("off", "0", "false", "no", "disabled")
_LINE_DIRECTIVE_RE = re.compile(r"^\s*#\s*(?:line\s+)?\d+")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_SLUG_RE = re.compile(r"[^A-Za-z0-9_.-]+")

# merge_agent_overlay's signature (see workspace_overlay.py); injectable for tests.
MergeFn = Callable[..., dict]
# (report run-relative path) -> (ok, detail)
IngestFn = Callable[[str], tuple[bool, str]]
# (report, entry, key) -> credited coverage ids
MarkFn = Callable[[str, str, str], list[str]]


def flag_enabled() -> bool:
    """FRAMAC_PROOF_CARRY: anything but an explicit off value keeps carry-forward on."""
    return (os.environ.get("FRAMAC_PROOF_CARRY") or "").strip().lower() not in _OFF


def _slug(file: str, function: str) -> str:
    return f"{_SLUG_RE.sub('_', file)}__{function}"


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogateescape")).hexdigest()


def _norm_ws(text: str) -> str:
    return " ".join(text.split())


def c_tokens_digest(text: str, path: str = "<input>") -> str | None:
    """Digest of the C tokens of `text`: every ACSL annotation, comment, blank and `#line` dropped."""
    try:
        tokens = tokenize_c_acsl(text, path=path)
    except AcslSyntaxError:
        return None
    parts = []
    for tok in tokens:
        if tok.kind in ("c_token", "string", "char"):
            parts.append(tok.text)
        elif tok.kind == "pp_directive" and not _LINE_DIRECTIVE_RE.match(tok.text):
            parts.append(_norm_ws(tok.text))
    return _sha("\n".join(parts))


# ---------------------------------------------------------------------------
# DAG and header resolution
# ---------------------------------------------------------------------------


def load_dag_functions(run_dir: Path) -> dict:
    dag = load_json_optional(run_dir / DAG_JSON, {})
    fns = dag.get("functions") if isinstance(dag, dict) else None
    return fns if isinstance(fns, dict) else {}


def _dag_ref(dag_fns: dict, key: str) -> tuple[str, str]:
    """A DAG callee key (`name`, or `file#name` when the name collides) as (file, name)."""
    meta = dag_fns.get(key)
    if isinstance(meta, dict) and meta.get("name"):
        return str(meta.get("file") or ""), str(meta["name"])
    return (key.split("#", 1)[0], key.split("#", 1)[1]) if "#" in key else ("", key)


def direct_callees(dag_fns: dict, file: str, function: str) -> list[tuple[str, str]]:
    """Direct callees of `file#function` in the DAG, as sorted (file, name) pairs ('' when unknown)."""
    record = None
    for key, meta in dag_fns.items():
        if not isinstance(meta, dict):
            continue
        name = str(meta.get("name") or (key.split("#", 1)[-1] if "#" in str(key) else key))
        mfile = str(meta.get("file") or (key.split("#", 1)[0] if "#" in str(key) else ""))
        if name == function and (mfile == file or not mfile):
            record = meta
            if mfile == file:
                break
    if record is None:
        return []
    raw = record.get("internal_callees") or record.get("direct_callees") or record.get("callees") or []
    out = {_dag_ref(dag_fns, str(c)) for c in raw if isinstance(c, str) and c}
    return sorted(out)


def resolve_header(run_dir: Path, overlay: Path, file: str, function: str, module: str | None) -> str | None:
    """The header holding `function`'s prototype, as the prover merge resolves it (None: no prototype)."""
    import workspace_overlay  # lazily: it is heavy and imports pipeline_make on demand

    work = overlay / "work"
    header: str | None = None
    try:
        side = workspace_overlay.merged_sidecar(workspace_overlay.module_map_for(overlay), module)
        flags = workspace_overlay._module_header_flags(overlay, module, side.get("cppflags"))
        header = workspace_overlay._prover_header(run_dir, work, file, function, side.get("header"), flags)
    except Exception:
        header = None
    if not header:
        sibling = Path(file).with_suffix(".h").as_posix()
        header = sibling if (work / sibling).is_file() else None
    if not header:
        return None
    text = _read(work / header)
    if text is None or not workspace_overlay._declares_function(text, function):
        return None
    return header


def _callee_contract_digest(work: Path, callee_file: str, name: str, extra_headers: list[str]) -> str:
    """Digest of `name`'s contracts on the current tree: definition, sibling header, the caller's header."""
    parts: list[str] = []
    if callee_file:
        text = _read(work / callee_file)
        if text is not None:
            with contextlib.suppress(AcslError):
                parts.append("c:" + _norm_ws(function_contract_text(text, name, False, callee_file)))
    headers = [Path(callee_file).with_suffix(".h").as_posix()] if callee_file else []
    for h in [*headers, *extra_headers]:
        text = _read(work / h) if h else None
        if text is None:
            continue
        with contextlib.suppress(AcslError):
            if locate_function_span(text, name, is_header=True, path=h) is not None:
                parts.append(f"h:{h}:" + _norm_ws(function_contract_text(text, name, True, h)))
    return _sha("\n".join(parts))


def proof_key_material(
    run_dir: Path,
    overlay: Path,
    file: str,
    function: str,
    module: str | None,
    cppflags: list[str],
    dag_fns: dict,
    wp_extra_sources: list[str] | None = None,
    header: str | None = None,
) -> dict | None:
    """What the proof of `file#function` depends on, or None when any input is missing."""
    work = overlay / "work"
    c_text = _read(work / file)
    if c_text is None:
        return None
    try:
        if locate_function_span(c_text, function, is_header=False, path=file) is None:
            return None
    except AcslError:
        return None
    code = c_tokens_digest(c_text, file)
    if code is None:
        return None
    header_code = None
    if header:
        h_text = _read(work / header)
        header_code = c_tokens_digest(h_text, header) if h_text is not None else None
        if header_code is None:
            return None
    callees = [
        [f"{cf}#{cn}" if cf else cn, _callee_contract_digest(work, cf, cn, [header] if header else [])]
        for cf, cn in direct_callees(dag_fns, file, function)
        if (cf, cn) != (file, function)
    ]
    extra = []
    for src in wp_extra_sources or []:
        text = _read(run_dir / src) if not Path(src).is_absolute() else None
        extra.append([src, c_tokens_digest(text, src) if text is not None else "unreadable"])
    return {
        "version": KEY_VERSION,
        "file": file,
        "function": function,
        "code": code,
        "header": header,
        "header_code": header_code,
        "callees": callees,
        "cppflags": list(cppflags),
        "wp_extra_sources": extra,
        "machdep": MACHDEP,
    }


# ---------------------------------------------------------------------------
# Publishing (wp-sweep only)
# ---------------------------------------------------------------------------


def _acsl_names(span_text: str, path: str) -> set[str]:
    names: set[str] = set()
    try:
        tokens = tokenize_c_acsl(span_text, path=path)
    except AcslSyntaxError:
        return names
    for tok in tokens:
        if tok.kind in ("acsl_block", "acsl_line"):
            names.update(_IDENT_RE.findall(tok.text))
    return names


def _acsl_of(span_text: str, path: str) -> str:
    try:
        tokens = tokenize_c_acsl(span_text, path=path)
    except AcslSyntaxError:
        return ""
    return "\n".join(t.text for t in tokens if t.kind in ("acsl_block", "acsl_line"))


def frame_gate_errors(
    overlay: Path, module: str | None, file: str, function: str, spans: list[tuple[str, str]]
) -> list[str]:
    """
    The merge gate's frame-preservation errors for this contract (workspace_overlay applies the same check when
    the replay merges it): a contract the gate always rejects is not worth publishing. Fail-open without facts.
    """
    import workspace_overlay

    skel = workspace_overlay._function_frame_skeleton(overlay, module, file, function)
    if skel is None:
        return []
    return check_frame_preserved(skel, "\n".join(_acsl_of(text, path) for path, text in spans), path=file)


def _referenced_decls(sources: list[tuple[str, str]], names: set[str]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for rel, text in sources:
        try:
            decls = extract_top_level_acsl_declarations(text, path=rel)
        except AcslError:
            continue
        for d in decls:
            if d["name"] in names and d["name"] not in seen:
                seen.add(d["name"])
                out.append({"name": d["name"], "kind": d["kind"], "text": d["text"], "source": rel})
    return out


def publish_proof(
    run_dir: Path,
    overlay: Path,
    entry: dict,
    sweep_report: Path,
    cppflags: list[str],
    dag_fns: dict | None = None,
    wp_extra_sources: list[str] | None = None,
    wp_extra_flags: list[str] | None = None,
) -> tuple[bool, str]:
    """Publish one swept function's proof; (published, reason when not)."""
    if not flag_enabled():
        return False, "FRAMAC_PROOF_CARRY=off"
    if not cache.enabled(run_dir):
        return False, "cache disabled"
    if entry.get("eva_only"):
        return False, "Eva-covered callee: no merged contract"
    report = load_json_optional(sweep_report, {})
    if not isinstance(report, dict) or report.get("status") != "all_proven":
        return False, "sweep report is not all_proven"
    file, function, module = entry["file"], entry["function"], entry.get("module")
    dag_fns = load_dag_functions(run_dir) if dag_fns is None else dag_fns
    header = resolve_header(run_dir, overlay, file, function, module)
    material = proof_key_material(run_dir, overlay, file, function, module, cppflags, dag_fns, wp_extra_sources, header)
    if material is None:
        return False, "no key: the function or one of its inputs is missing"
    work = overlay / "work"
    c_text = _read(work / file) or ""
    span_c = locate_function_span(c_text, function, is_header=False, path=file)
    if span_c is None:
        return False, "definition not found"
    sources = [(file, c_text)]
    span_h_text = contract_h = None
    if header:
        h_text = _read(work / header) or ""
        span_h = locate_function_span(h_text, function, is_header=True, path=header)
        if span_h is not None:
            span_h_text = span_h.text
            contract_h = function_contract_text(h_text, function, True, header)
        sources.append((header, h_text))
    spans = [(file, span_c.text)] + ([(header or "", span_h_text)] if span_h_text else [])
    frame_errs = frame_gate_errors(overlay, module, file, function, spans)
    if frame_errs:
        return False, "the replay merge gate would reject it: " + "; ".join(frame_errs)[:300]
    names = _acsl_names(span_c.text, file) | (_acsl_names(span_h_text, header or "") if span_h_text else set())
    names.discard(function)
    doc = {
        "file": file,
        "function": function,
        "module": module,
        "header_file": header,
        "span_c": span_c.text,
        "span_h": span_h_text,
        "contract_c": function_contract_text(c_text, function, False, file),
        "contract_h": contract_h,
        "top_level_decls": _referenced_decls(sources, names),
        "wp_extra_flags": list(wp_extra_flags or []),
        "wp_report_status": "all_proven",
        "swept_at": utc_now(),
        "run_id": _run_id(run_dir),
    }
    key = cache.make_key(NS, material)
    staging = run_dir / STATE_REL / "publish" / _slug(file, function)
    staging.mkdir(parents=True, exist_ok=True)
    contract_json = staging / "contract.json"
    atomic_write_json(contract_json, doc)
    ok = cache.publish(
        NS,
        key,
        {"contract.json": contract_json, "wp_report.json": Path(sweep_report)},
        data={"function": function, "file": file, "module": module},
        key_material=material,
        cwd=run_dir,
    )
    return (True, key) if ok else (False, "cache publish failed")


def _run_id(run_dir: Path) -> str | None:
    meta = load_json_optional(run_dir / "run-metadata.json", {})
    return str(meta.get("run_id")) if isinstance(meta, dict) and meta.get("run_id") else None


def lookup_proof(
    run_dir: Path,
    overlay: Path,
    file: str,
    function: str,
    module: str | None,
    cppflags: list[str],
    dag_fns: dict,
    wp_extra_sources: list[str] | None = None,
    header: str | None = None,
) -> tuple[cache.Entry | None, str | None]:
    """(entry or None, key or None when the function cannot be keyed)."""
    material = proof_key_material(run_dir, overlay, file, function, module, cppflags, dag_fns, wp_extra_sources, header)
    if material is None:
        return None, None
    key = cache.make_key(NS, material)
    return cache.lookup(NS, key, run_dir), key


# ---------------------------------------------------------------------------
# Replay (before wp_scheduler.py init)
# ---------------------------------------------------------------------------


def planned_functions(run_dir: Path) -> list[dict]:
    """Every (file, function) with a `planned` ledger unit, as the scheduler selects prove tasks."""
    ledger = load_json_optional(run_dir / LEDGER_JSON, [])
    if not isinstance(ledger, list):
        raise ArtifactError(f"{LEDGER_JSON} is not a list")
    out: dict[tuple[str, str], dict] = {}
    for u in ledger:
        if not isinstance(u, dict) or u.get("status") != "planned":
            continue
        file, fn = str(u.get("file") or "").replace("\\", "/"), str(u.get("function") or "")
        if not file or not fn:
            continue
        rec = out.setdefault((file, fn), {"file": file, "function": fn, "module": u.get("module"), "units": []})
        rec["units"].append(u.get("coverage_id"))
    return [out[k] for k in sorted(out)]


def callee_first(items: list[dict], dag_fns: dict) -> list[dict]:
    """Order so that a function comes after its planned callees (cycles: in name order)."""
    by_key = {(i["file"], i["function"]): i for i in items}
    deps: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for k in by_key:
        found = []
        for cf, cn in direct_callees(dag_fns, *k):
            match = [o for o in by_key if o[1] == cn and (not cf or o[0] == cf) and o != k]
            found.extend(match)
        deps[k] = sorted(set(found))
    order: list[dict] = []
    state: dict[tuple[str, str], int] = {}

    def visit(k: tuple[str, str]) -> None:
        if state.get(k):
            return  # done, or on the stack (a cycle)
        state[k] = 1
        for d in deps[k]:
            visit(d)
        state[k] = 2
        order.append(by_key[k])

    for k in sorted(by_key):
        visit(k)
    return order


def _replace_span(text: str, function: str, new_span: str, is_header: bool, path: str) -> str | None:
    span = locate_function_span(text, function, is_header=is_header, path=path)
    if span is None:
        return None
    return text[: span.start_byte] + new_span + text[span.end_byte :]


def _existing_decls(work: Path, rels: list[str]) -> dict[str, str]:
    """Top-level ACSL declaration texts by name in `rels` and every other header of the tree."""
    out: dict[str, str] = {}
    paths = [work / r for r in rels] + sorted(p for p in work.rglob("*.h") if p.is_file())
    seen: set[Path] = set()
    for p in paths:
        if p in seen or not p.is_file():
            continue
        seen.add(p)
        text = _read(p)
        if text is None:
            continue
        with contextlib.suppress(AcslError):
            for d in extract_top_level_acsl_declarations(text, path=p.name):
                out.setdefault(d["name"], d["text"])
    return out


def _insert_decls(header_text: str, function: str, decls: list[dict], header: str) -> str | None:
    """Put `decls` as one ACSL block right before `function`'s prototype (outside its span)."""
    span = locate_function_span(header_text, function, is_header=True, path=header)
    if span is None:
        return None
    block = "/*@\n" + "\n".join(f"  {d['text']}" for d in decls) + "\n*/\n"
    return header_text[: span.start_byte] + block + header_text[span.start_byte :]


def _remove_agent(run_dir: Path, agent_id: str) -> None:
    shutil.rmtree(run_dir / "agents" / agent_id, ignore_errors=True)


# Source trees of an agent (scratch/work, scratch/base, candidates/*/work): large, and the
# rejected contract is already in the restored cache entry next to the kept evidence.
_EVIDENCE_SKIP_DIRS = frozenset({"work", "base"})


def _keep_evidence(run_dir: Path, agent_id: str, dest: Path) -> bool:
    """Copy an agent's reports and logs (not its source trees) to `dest` before it is removed."""
    src = run_dir / "agents" / agent_id
    if not src.is_dir():
        return False

    def ignore(directory: str, names: list[str]) -> set[str]:
        return {n for n in names if n in _EVIDENCE_SKIP_DIRS and (Path(directory) / n).is_dir()}

    shutil.rmtree(dest, ignore_errors=True)
    try:
        shutil.copytree(src, dest, ignore=ignore)
    except OSError:
        return False
    return True


def _snapshot_files(work: Path, wp_report: Path, rels: list[str | None]) -> dict[Path, bytes | None]:
    """Bytes of the tree files a replay may change (None: absent), for _restore_files."""
    paths = [work / r for r in rels if r] + [wp_report]
    return {p: (p.read_bytes() if p.is_file() else None) for p in paths}


def _restore_files(snapshot: dict[Path, bytes | None]) -> None:
    """Put back every snapshotted file that changed; remove one that did not exist."""
    for path, raw in snapshot.items():
        current = path.read_bytes() if path.is_file() else None
        if current == raw:
            continue
        if raw is None:
            path.unlink(missing_ok=True)
            continue
        tmp = path.with_name(f".tmp_restore_{path.name}")
        tmp.write_bytes(raw)
        os.replace(tmp, path)


def _default_merge() -> MergeFn:
    import workspace_overlay

    return workspace_overlay.merge_agent_overlay


def _default_init_agent() -> Callable[..., dict]:
    import workspace_overlay

    return workspace_overlay.init_agent_overlay


def _sidecar(overlay: Path, module: str | None) -> dict:
    import workspace_overlay

    try:
        return workspace_overlay.merged_sidecar(workspace_overlay.module_map_for(overlay), module)
    except Exception:
        return {}


def _next_agent_id(run_dir: Path, start: int) -> tuple[str, int]:
    n = start
    while (run_dir / "agents" / f"carry-{n}").exists():
        n += 1
    return f"carry-{n}", n + 1


def replay(
    run_dir: Path,
    plan: Any,
    overlay: Path | None = None,
    *,
    merge: MergeFn | None = None,
    init_agent: Callable[..., dict] | None = None,
    ingest: IngestFn | None = None,
    mark: MarkFn | None = None,
) -> dict:
    """
    Re-apply and re-prove cached proofs of planned functions; writes SUMMARY_REL. `plan` is a
    pipeline_make.Plan (wp_cppflags_for / wp_extra_sources_for). `ingest` and `mark` run
    `ledger.py ingest-wp` and `ledger.py mark-carried` (the parent is the only ledger writer).
    """
    run_dir = Path(run_dir).resolve()
    overlay = (overlay or run_dir / "workspace").resolve()
    summary: dict[str, Any] = {
        "ok": True,
        "skipped": False,
        "planned_functions": 0,
        "hits": 0,
        "reproven": 0,
        "misses": 0,
        "unkeyed": [],
        "rejected": [],
        "carried": [],
        "generated_at": utc_now(),
    }
    reason = None
    if not flag_enabled():
        reason = "FRAMAC_PROOF_CARRY=off"
    elif not cache.enabled(run_dir):
        reason = "cache disabled (FRAMAC_CACHE=off or not a run directory)"
    if reason:
        summary.update(skipped=True, reason=reason)
        atomic_write_json(run_dir / SUMMARY_REL, summary)
        return summary
    if ingest is None or mark is None:
        raise ValueError("replay needs the ledger ingest and mark callables")
    merge = merge or _default_merge()
    init_agent = init_agent or _default_init_agent()
    dag_fns = load_dag_functions(run_dir)
    items = callee_first(planned_functions(run_dir), dag_fns)
    summary["planned_functions"] = len(items)
    work = overlay / "work"
    next_n = 1

    def reject(item: dict, why: str, agents: list[str] | None = None) -> None:
        row = {"file": item["file"], "function": item["function"], "reason": why[:400]}
        if agents:
            # Keep the guardrail and WP reports and the logs: the summary's reason is cut at 400 characters.
            dest = run_dir / STATE_REL / _slug(item["file"], item["function"]) / "rejected"
            kept = [aid for aid in agents if _keep_evidence(run_dir, aid, dest / aid)]
            if kept:
                dest.mkdir(parents=True, exist_ok=True)
                (dest / "reason.txt").write_text(why + "\n", encoding="utf-8")
                row["evidence"] = (dest.relative_to(run_dir)).as_posix()
        for aid in agents or []:
            _remove_agent(run_dir, aid)
        summary["rejected"].append(row)

    for item in items:
        file, fn, module = item["file"], item["function"], item.get("module")
        flags, why = plan.wp_cppflags_for(module)
        if flags is None:
            summary["unkeyed"].append({"file": file, "function": fn, "reason": why})
            continue
        extra_sources = plan.wp_extra_sources_for(module)
        header = resolve_header(run_dir, overlay, file, fn, module)
        entry, key = lookup_proof(run_dir, overlay, file, fn, module, flags, dag_fns, extra_sources, header)
        if key is None:
            summary["unkeyed"].append({"file": file, "function": fn, "reason": "function or input missing"})
            continue
        if entry is None:
            summary["misses"] += 1
            continue
        summary["hits"] += 1
        dest = run_dir / STATE_REL / _slug(file, fn)
        contract_path, report_path = dest / "contract.json", dest / "wp_report.json"
        if not cache.restore(entry, {"contract.json": contract_path, "wp_report.json": report_path}):
            reject(item, "cache entry failed its digest check on restore")
            continue
        doc = load_json_optional(contract_path, {})
        if not isinstance(doc, dict) or doc.get("file") != file or doc.get("function") != fn or not doc.get("span_c"):
            reject(item, "cache entry does not describe this function")
            continue
        if (doc.get("header_file") or None) != header:
            reject(item, f"header changed: cached {doc.get('header_file')!r}, now {header!r}")
            continue

        existing = _existing_decls(work, [file])
        missing: list[dict] = []
        conflict = None
        for d in doc.get("top_level_decls") or []:
            have = existing.get(d.get("name"))
            if have is None:
                missing.append(d)
            elif _norm_ws(have) != _norm_ws(str(d.get("text") or "")):
                conflict = d.get("name")
                break
        if conflict:
            reject(item, f"declaration conflict: {conflict}")
            continue
        side = _sidecar(overlay, module)
        merge_kw = {
            "module": module,
            "sources": side.get("sources") or None,
            "cppflags": side.get("cppflags") or "-I.",
            "ldflags": side.get("ldflags") or "",
        }
        agents: list[str] = []
        # merge_agent_overlay undoes its own failed merge, but not one that succeeded before a later step of this
        # item failed (the header declarations before the prover merge, or the ingest after it): restore those.
        snapshot = _snapshot_files(work, overlay / "reports" / "wp" / f"{fn}.json", [file, header])

        def undo(item: dict, why: str, agents: list[str] | None = None, *, _snap=snapshot) -> None:
            _restore_files(_snap)
            reject(item, why, agents)

        try:
            if missing:
                bad = [d["name"] for d in missing if d.get("source") != header]
                if bad or not header:
                    undo(
                        item,
                        f"missing declarations outside the header: {', '.join(bad or [d['name'] for d in missing])}",
                    )
                    continue
                arch_id, next_n = _next_agent_id(run_dir, next_n)
                agents.append(arch_id)
                init_agent(run_dir, arch_id, overlay)
                h_path = run_dir / "agents" / arch_id / "scratch" / "work" / header
                new_h = _insert_decls(_read(h_path) or "", fn, missing, header)
                if new_h is None:
                    undo(item, "prototype not found for the declarations", agents)
                    continue
                h_path.write_text(new_h, encoding="utf-8", newline="")
                res = merge(run_dir, arch_id, "architect", overlay, header_file=header, **merge_kw)
                if not res.get("ok"):
                    undo(item, f"declarations not merged: {res.get('reason')}", agents)
                    continue

            aid, next_n = _next_agent_id(run_dir, next_n)
            agents.append(aid)
            init_agent(run_dir, aid, overlay)
            scratch = run_dir / "agents" / aid / "scratch"
            c_path = scratch / "work" / file
            new_c = _replace_span(_read(c_path) or "", fn, doc["span_c"], False, file)
            if new_c is None:
                undo(item, "definition not found in the agent copy", agents)
                continue
            c_path.write_text(new_c, encoding="utf-8", newline="")
            if header and doc.get("span_h"):
                h_path = scratch / "work" / header
                new_h2 = _replace_span(_read(h_path) or "", fn, doc["span_h"], True, header)
                if new_h2 is None:
                    undo(item, "prototype not found in the agent copy", agents)
                    continue
                h_path.write_text(new_h2, encoding="utf-8", newline="")
            # The parent WP re-check takes its reduced checks and model from here (infer_prover_wp_flags).
            shutil.copy2(report_path, scratch / f"wp_{fn}.json")
            res = merge(
                run_dir,
                aid,
                "prover",
                overlay,
                c_file=file,
                function=fn,
                header_file=header,
                contract_only=False,
                wp_extra_sources=extra_sources or None,
                **merge_kw,
            )
        except Exception as exc:  # ScopeViolationError, AcslError, ArtifactError, OverlayMergeError, ...
            undo(item, f"{type(exc).__name__}: {exc}", agents)
            continue
        if not res.get("ok"):
            undo(item, str(res.get("reason") or "merge failed"), agents)
            continue
        rep = res.get("parent_wp_report")
        if not rep:
            undo(item, "merged without a parent WP report", agents)
            continue
        ok, detail = ingest(rep)
        if not ok:
            summary["ok"] = False
            undo(item, f"ledger ingest-wp failed: {detail}", agents)
            continue
        entry_rel = contract_path.relative_to(run_dir).as_posix()
        credited = mark(rep, entry_rel, key)
        if not credited:
            # ingest-wp already credited the units with the fresh all_proven report, so the merge stays: only the
            # carried_forward_reproven label is missing. Not rolled back, or the ledger would point at a contract
            # that is no longer in the tree.
            reject(item, "re-proven and ingested, but mark-carried labelled no unit")
            continue
        summary["reproven"] += 1
        summary["carried"].append(
            {"file": file, "function": fn, "agent_id": aid, "key": key, "store": entry.store.scope, "units": credited}
        )
    atomic_write_json(run_dir / SUMMARY_REL, summary)
    return summary


def ledger_runner(script_runner: Callable[[str, list[str]], tuple[int, str]]) -> tuple[IngestFn, MarkFn]:
    """`ingest` and `mark` callables over `ledger.py ingest-wp` / `ledger.py mark-carried`."""

    def ingest(rep: str) -> tuple[bool, str]:
        rc, out = script_runner("ledger.py", ["ingest-wp", rep])
        return rc == 0, out.strip()[-400:]

    def mark(rep: str, entry: str, key: str) -> list[str]:
        rc, out = script_runner("ledger.py", ["mark-carried", "--report", rep, "--entry", entry, "--key", key])
        if rc != 0:
            return []
        try:
            data = json.loads(out)
        except ValueError:
            return []
        return [str(c) for c in data.get("marked") or []] if isinstance(data, dict) else []

    return ingest, mark
