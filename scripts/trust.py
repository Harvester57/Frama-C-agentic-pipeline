#!/usr/bin/env python3
"""
Trust boundary (docs/phase0-implementation-plan.md step I7): which functions take attacker-controlled
data, decided by a stated rule, the target's threat model and, optionally, CodeQL. Stdlib only.

    trust.py run [--model workspace/reports/phase0_model.json] [--threat-model PATH]
                 [--codeql workspace/reports/codeql_trust.json] [--metadata run-metadata.json]
    trust.py check-threat-model [PATH] [--model workspace/reports/phase0_model.json]

`run` annotates the Phase 0 model in place (phase0_model.py already does it once when it writes the
model; run it again after a CodeQL run, then rebuild the DAG). It takes the threat model the model
recorded (path and sha256) and stops when that file changed, went missing or appeared since: re-run
the model, or give `--threat-model PATH` to annotate it with that file, which the model then records.
It validates the model it rewrites; schema problems become the model's `schema:` warning. The rules,
in this order:

  1. library API: every API function of a library unit (its exports) and an executable's embedded
     API is untrusted (`default`);
  2. input path: a function that calls an input reader (INPUT_READERS: read, recv, recvfrom, fread,
     fgets, getline, getenv and their close relatives), `main` with parameters (argv), and the threat
     model's `input_sources` are input roots. Every function they reach in the call graph (direct and
     indirect edges, test units excluded) is untrusted (`call_graph`). An `entry` input source is
     itself untrusted (`threat_model`); a `reader` input source makes its callers input roots;
  3. CodeQL (optional, opt-in per run, scripts/codeql_trust.py): a function a source-to-sink taint
     flow reaches is untrusted (`codeql`). CodeQL only adds untrusted marks: it never makes a function
     trusted and never overrides a threat-model decision;
  4. any other function is trusted (`default`): only project code calls it.

The threat model's `trusted_callers` (a unit's API, or named functions, called only by trusted code)
wins over rules 1-3: such a function is trusted (`threat_model`) and the rules it overrides are kept
under `overridden` (attacker data does reach it, through callers that check it).

Per function (`functions.<id>.trust` in the model):
  value     untrusted | trusted
  source    the deciding rule: threat_model, default, call_graph or codeql
  sources   every rule that marked it untrusted (a function can be API and on an input path)
  boundary  attacker data reaches its parameters directly: an untrusted API function, `main` with
            argv, an `entry` input source. The harness sidecar's `reachability` defaults to
            untrusted_surface there (generate_harness.py), and the contract trust-boundary check
            (acsl_ast.py) applies to its `requires`.
  reasons   why, in a few words each

Per unit (`units.<name>.trust`): the threat-model status (`ok`, `no_threat_model` when THREAT_MODEL.md
or its structured block is missing, `invalid_threat_model`) and counts. The model's top-level `trust`
block holds the threat model's path, digest, errors and warnings, the CodeQL status and the counts per
source.

The threat model is the fenced block `framac-threat-model` of THREAT_MODEL.md, validated against
schemas/threat_model.schema.json. The model's first annotation looks for it, in order: --threat-model,
workspace/THREAT_MODEL.md (supplied with the run, e.g. a benchmark asset), the target's own
THREAT_MODEL.md (the model's scratch tree, workspace/work/, /target). The model records the file's
path and sha256 (`trust.threat_model`); `trust.py run` and security_props.py read that file, never
search again, and refuse it once its sha256 differs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import atomic_write_json, load_json_optional, utc_now  # noqa: E402
from phase0_model import model_features, validate_model  # noqa: E402

SCHEMA_VERSION = 1
DEFAULT_MODEL = Path("workspace/reports/phase0_model.json")
DEFAULT_CODEQL = Path("workspace/reports/codeql_trust.json")
DEFAULT_METADATA = Path("run-metadata.json")
THREAT_MODEL_NAME = "THREAT_MODEL.md"
BLOCK_INFO = "framac-threat-model"

# The plan's input readers, and the libc calls that do the same job.
INPUT_READERS = frozenset(
    {
        "read",
        "pread",
        "readv",
        "recv",
        "recvfrom",
        "recvmsg",
        "fread",
        "fgets",
        "fgetc",
        "getc",
        "getchar",
        "getline",
        "getdelim",
        "scanf",
        "fscanf",
        "getenv",
        "secure_getenv",
    }
)
LIBRARY_KINDS = frozenset({"static_lib", "shared_lib"})
# The deciding source of an untrusted function, most specific first.
SOURCE_ORDER = ("threat_model", "default", "call_graph", "codeql")
UNTRUSTED, TRUSTED = "untrusted", "trusted"
STATUS_OK, STATUS_NONE, STATUS_INVALID = "ok", "no_threat_model", "invalid_threat_model"
MAX_REASONS = 6

_FENCE_RE = re.compile(
    r"^(?P<fence>`{3,}|~{3,})[ \t]*(?P<info>[^\n`]*)\n(?P<body>.*?)^(?P=fence)[ \t]*$", re.MULTILINE | re.DOTALL
)
_FID_RE = re.compile(r"^(?:(?P<file>[A-Za-z0-9_./+-]+\.[A-Za-z0-9]+)#)?(?P<name>[A-Za-z_]\w*)$")


# ---------------------------------------------------------------------------------------------------
# Threat model
# ---------------------------------------------------------------------------------------------------


def _schema_path() -> Path | None:
    here = Path(__file__).resolve().parent
    for cand in (here.parent / "schemas", Path("/opt/framac-pipeline/schemas")):
        path = cand / "threat_model.schema.json"
        if path.is_file():
            return path
    return None


def extract_block(text: str) -> tuple[dict | None, list[str]]:
    """The structured block of THREAT_MODEL.md: (object or None, errors). No block is (None, [])."""
    blocks = [m for m in _FENCE_RE.finditer(text) if BLOCK_INFO in m.group("info").split()]
    if not blocks:
        return None, []
    if len(blocks) > 1:
        return None, [f"{len(blocks)} `{BLOCK_INFO}` blocks: keep exactly one"]
    try:
        data = json.loads(blocks[0].group("body"))
    except ValueError as exc:
        return None, [f"the `{BLOCK_INFO}` block is not JSON: {exc}"]
    if not isinstance(data, dict):
        return None, [f"the `{BLOCK_INFO}` block must hold one JSON object"]
    return data, []


def validate_block(block: dict) -> list[str]:
    """Schema and structural errors of a threat-model block (references are checked against the model)."""
    from minischema import Validator, load_schema

    path = _schema_path()
    if path is None:
        return ["schemas/threat_model.schema.json not found"]
    errors = list(Validator(load_schema(path)).errors(block))
    for i, item in enumerate(block.get("trusted_callers") or []):
        if not isinstance(item, dict):
            continue
        has_unit, has_fns = "unit" in item, "functions" in item
        if has_unit == has_fns:
            errors.append(f"trusted_callers[{i}]: give either `unit` or `functions`")
        if "except" in item and not has_unit:
            errors.append(f"trusted_callers[{i}]: `except` goes with `unit`")
    return errors


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_threat_model(path: Path | None) -> dict:
    """
    {status, path, sha256, reason, errors, warnings, block}: `ok` with a valid block, `no_threat_model`
    without the file or without a structured block, `invalid_threat_model` with errors.
    """
    out: dict[str, Any] = {"status": STATUS_NONE, "path": None, "sha256": None, "reason": None, "errors": []}
    out["warnings"] = []
    out["block"] = None
    if path is None or not path.is_file():
        out["reason"] = f"no {THREAT_MODEL_NAME}"
        return out
    raw = path.read_bytes()
    out.update(path=str(path), sha256=_sha256(raw))
    block, errors = extract_block(raw.decode("utf-8", errors="replace"))
    if block is None and not errors:
        out["reason"] = f"{THREAT_MODEL_NAME} has no structured `{BLOCK_INFO}` block"
        return out
    errors = errors or validate_block(block or {})
    if errors:
        out.update(status=STATUS_INVALID, reason="the structured block does not validate", errors=errors)
        return out
    out.update(status=STATUS_OK, block=block)
    return out


def find_threat_model(explicit: Path | None, model: dict | None = None) -> Path | None:
    """
    The threat model file: explicit, else run-supplied, else the target's own. Only the first
    annotation of a model searches: later readers take the file the model recorded
    (`recorded_threat_model`).
    """
    if explicit is not None:
        return explicit
    cands = [Path("workspace") / THREAT_MODEL_NAME]
    tree = (model or {}).get("tree")
    if tree:
        cands.append(Path(tree) / THREAT_MODEL_NAME)
    cands += [Path("workspace/work") / THREAT_MODEL_NAME, Path("/target") / THREAT_MODEL_NAME]
    return next((c for c in cands if c.is_file()), None)


RERUN_MODEL = (
    "re-run the model (phase0_model.py run, or trust.py run --threat-model PATH to annotate it with this "
    "file), then build_callgraph_dag.py and security_props.py run"
)


def recorded_threat_model(model: dict) -> tuple[dict | None, str | None]:
    """
    The threat model the model's trust annotation used, so trust, the DAG and the security properties
    share one: (load_threat_model's result for the path and sha256 in `model.trust.threat_model`, None),
    or (None, why) when the model has no trust annotation, or when that file is gone, changed since the
    model was built, or appeared where the model recorded none.
    """
    trust_block = model.get("trust")
    rec = trust_block.get("threat_model") if isinstance(trust_block, dict) else None
    if not isinstance(rec, dict):
        return None, "the model has no trust annotation (`trust.threat_model`): run trust.py run"
    path = rec.get("path")
    if not path:
        found = find_threat_model(None, model)
        if found is not None:
            return None, f"{found} appeared after the model was built without a threat model: {RERUN_MODEL}"
        out = load_threat_model(None)
        out.update(status=rec.get("status") or STATUS_NONE, reason=rec.get("reason") or out["reason"])
        return out, None
    file = Path(str(path))
    if not file.is_file():
        return None, f"threat model {path}, which the model recorded, is missing: {RERUN_MODEL}"
    threat = load_threat_model(file)
    if threat.get("sha256") != rec.get("sha256"):
        return None, (
            f"threat model {path} changed since the model was built (sha256 {str(rec.get('sha256'))[:12]} -> "
            f"{str(threat.get('sha256'))[:12]}): {RERUN_MODEL}"
        )
    return threat, None


# ---------------------------------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------------------------------


def has_parameters(signature: str | None) -> bool:
    """`int(int,char **)` has parameters; `int(void)` and `int()` do not. No signature (GCC fallback): assume so."""
    if not signature:
        return True
    start = signature.find("(")
    end = signature.rfind(")")
    if start < 0 or end <= start:
        return True
    inner = signature[start + 1 : end].strip()
    return inner not in ("", "void")


class _Index:
    """Name and unit lookups over a model."""

    def __init__(self, model: dict):
        self.functions: dict[str, dict] = model.get("functions") or {}
        self.units: dict[str, dict] = {n: u for n, u in (model.get("units") or {}).items() if not u.get("test")}
        self.by_name: dict[str, list[str]] = defaultdict(list)
        for fid, f in sorted(self.functions.items()):
            self.by_name[str(f.get("name") or fid.split("#")[-1])].append(fid)
        for alias, rec in (model.get("macro_aliases") or {}).items():
            for fid in rec.get("ids") or []:
                if fid in self.functions and fid not in self.by_name[alias]:
                    self.by_name[alias].append(fid)
        self.externals = set(model.get("externals") or [])
        self.succ: dict[str, set[str]] = defaultdict(set)
        self.callers: dict[str, set[str]] = defaultdict(set)
        for e in model.get("edges") or []:
            a, b = e.get("caller"), e.get("callee")
            if a in self.functions and b in self.functions:
                self.succ[a].add(b)
                self.callers[b].add(a)

    def resolve(self, ref: str) -> list[str]:
        m = _FID_RE.match(ref or "")
        if not m:
            return []
        if m.group("file"):
            return [ref] if ref in self.functions else []
        return list(self.by_name.get(m.group("name"), []))

    def unit(self, ref: str) -> str | None:
        if ref in self.units:
            return ref
        hits = [n for n in self.units if Path(n).name == ref]
        return hits[0] if len(hits) == 1 else None

    def api(self, unit: str) -> list[str]:
        u = self.units.get(unit) or {}
        api = list(u.get("entry_points") or []) if u.get("kind") in LIBRARY_KINDS else []
        api += list(u.get("embedded_api") or [])
        return [f for f in dict.fromkeys(api) if f in self.functions]


class _Marks:
    def __init__(self) -> None:
        self.untrusted: dict[str, dict[str, list[str]]] = defaultdict(dict)
        self.boundary: set[str] = set()

    def add(self, fid: str, source: str, reason: str, boundary: bool = False) -> None:
        reasons = self.untrusted[fid].setdefault(source, [])
        if reason not in reasons and len(reasons) < MAX_REASONS:
            reasons.append(reason)
        if boundary:
            self.boundary.add(fid)


def _threat_rules(idx: _Index, block: dict, marks: _Marks, roots: dict[str, str], warnings: list[str]) -> dict:
    """Input sources (marks and roots) and trusted callers (returned: id -> reason)."""
    for item in block.get("input_sources") or []:
        ref, role = str(item.get("function") or ""), item.get("role")
        fids = idx.resolve(ref)
        name = ref.split("#")[-1]
        if role == "entry":
            if not fids:
                warnings.append(f"threat model: input source {ref} is not a function of the build")
            for fid in fids:
                marks.add(fid, "threat_model", "threat-model input source (entry)", boundary=True)
                roots.setdefault(fid, "threat-model input source")
            continue
        # A reader: its callers get its data. A project reader also handles the raw data itself.
        for fid in fids:
            marks.add(fid, "threat_model", "threat-model input source (reader)")
            roots.setdefault(fid, "threat-model reader")
            for caller in sorted(idx.callers.get(fid, ())):
                roots.setdefault(caller, f"calls {idx.functions[fid].get('name')} (threat-model reader)")
        external_callers = [f for f, rec in idx.functions.items() if name in (rec.get("external_calls") or [])]
        for caller in external_callers:
            roots.setdefault(caller, f"calls {name} (threat-model reader)")
        if not fids and not external_callers and name not in idx.externals:
            warnings.append(f"threat model: reader {ref} is neither a function of the build nor called by one")
    trusted: dict[str, str] = {}
    for item in block.get("trusted_callers") or []:
        reason = f"threat model: trusted callers only ({item.get('reason')})"
        if "unit" in item:
            unit = idx.unit(str(item["unit"]))
            if unit is None:
                warnings.append(f"threat model: trusted_callers unit {item['unit']} is not a non-test link unit")
                continue
            keep = {f for ref in item.get("except") or [] for f in idx.resolve(str(ref))}
            for ref in item.get("except") or []:
                if not idx.resolve(str(ref)):
                    warnings.append(f"threat model: trusted_callers except {ref} is not a function of the build")
            for fid in idx.api(unit):
                if fid not in keep:
                    trusted.setdefault(fid, reason)
        for ref in item.get("functions") or []:
            fids = idx.resolve(str(ref))
            if not fids:
                warnings.append(f"threat model: trusted_callers function {ref} is not a function of the build")
            for fid in fids:
                trusted.setdefault(fid, reason)
    for kind in ("secrets", "auth_gates", "output_sinks"):
        for item in block.get(kind) or []:
            refs = [item.get("function")] + list(item.get("protects") or [])
            for ref in refs:
                if ref and not idx.resolve(str(ref)) and str(ref).split("#")[-1] not in idx.externals:
                    warnings.append(f"threat model: {kind} names {ref}, which is not a function of the build")
    return trusted


def _codeql_marks(idx: _Index, codeql: dict, marks: _Marks, warnings: list[str]) -> tuple[int, list[str]]:
    """CodeQL facts as `codeql` marks: (facts used, function ids CodeQL named that the model lacks)."""
    used, unmatched = 0, []
    for fact in codeql.get("facts") or []:
        fid = str(fact.get("function") or "")
        if fid not in idx.functions:
            if fid not in unmatched:
                unmatched.append(fid)
            continue
        src = fact.get("source") or {}
        where = f"{src.get('file')}:{src.get('line')}" if src.get("file") else "a source"
        what = f"parameter {fact['parameter']}" if fact.get("parameter") else "its body"
        marks.add(fid, "codeql", f"codeql: {src.get('type') or 'untrusted data'} at {where} reaches {what}")
        used += 1
    if unmatched:
        warnings.append(f"codeql: {len(unmatched)} function(s) not in the model, e.g. {unmatched[:3]}")
    return used, unmatched


def compute_trust(model: dict, threat: dict | None = None, codeql: dict | None = None) -> dict:
    """The trust annotation of a model: {functions, units, summary, warnings} (see the module doc)."""
    idx = _Index(model)
    marks = _Marks()
    warnings: list[str] = []
    threat = threat or {"status": STATUS_NONE}
    # Rule 1: library API.
    for unit in sorted(idx.units):
        u = idx.units[unit]
        exported = set(u.get("entry_points") or []) if u.get("kind") in LIBRARY_KINDS else set()
        for fid in idx.api(unit):
            what = "API" if fid in exported else "embedded API"
            marks.add(fid, "default", f"{what} of {unit}", boundary=True)
    # Rule 2: input roots, then the call graph.
    roots: dict[str, str] = {}
    if idx.functions and not model_features(model)["external_calls"]:
        warnings.append("the model records no external calls (made before step I7): input readers are not seen")
    for fid, f in sorted(idx.functions.items()):
        readers = sorted(set(f.get("external_calls") or []) & INPUT_READERS)
        if readers:
            roots[fid] = f"calls {', '.join(readers)}"
        if f.get("name") == "main" and not f.get("static") and has_parameters(f.get("signature")):
            roots[fid] = "; ".join(filter(None, ["main with argv", roots.get(fid)]))
            marks.boundary.add(fid)
    trusted: dict[str, str] = {}
    if threat.get("status") == STATUS_OK and threat.get("block"):
        trusted = _threat_rules(idx, threat["block"], marks, roots, warnings)
    for root, why in sorted(roots.items()):
        marks.add(root, "call_graph", why)
    # Breadth first from every root in turn: a function is visited once, named after the first root.
    seen: set[str] = set()
    for root, why in sorted(roots.items()):
        queue: deque[str] = deque([root])
        while queue:
            cur = queue.popleft()
            if cur in seen:
                continue
            seen.add(cur)
            if cur not in roots:
                marks.add(cur, "call_graph", f"on the input path from {root} ({why})")
            queue.extend(n for n in sorted(idx.succ.get(cur, ())) if n not in seen)
    # Rule 3: CodeQL.
    codeql_info: dict[str, Any] = {"status": "off"}
    if codeql is not None:
        codeql_info = {k: codeql.get(k) for k in ("status", "path", "codeql_version") if codeql.get(k) is not None}
        if codeql.get("status") == "ok":
            used, unmatched = _codeql_marks(idx, codeql, marks, warnings)
            codeql_info.update(facts=used, unmatched=len(unmatched))
        else:
            warnings.append(f"codeql: status {codeql.get('status')}, its facts are not used")
    # Decide.
    functions: dict[str, dict] = {}
    for fid in sorted(idx.functions):
        found = marks.untrusted.get(fid) or {}
        sources = [s for s in SOURCE_ORDER if s in found]
        reasons = [r for s in sources for r in found[s]][:MAX_REASONS]
        if fid in trusted:
            rec: dict[str, Any] = {
                "value": TRUSTED,
                "source": "threat_model",
                "sources": [],
                "boundary": False,
                "reasons": [trusted[fid]],
            }
            if sources:
                # Expected: attacker data reaches it, and its trusted callers check it on the way.
                rec["overridden"] = sources
        elif sources:
            rec = {
                "value": UNTRUSTED,
                "source": sources[0],
                "sources": sources,
                "boundary": fid in marks.boundary,
                "reasons": reasons,
            }
        else:
            rec = {
                "value": TRUSTED,
                "source": "default",
                "sources": [],
                "boundary": False,
                "reasons": ["not API and not on an input path"],
            }
        functions[fid] = rec
    units: dict[str, dict] = {}
    for unit in sorted(idx.units):
        fids = [f for f, rec in idx.functions.items() if unit in (rec.get("units") or [])]
        units[unit] = {
            "threat_model": threat.get("status") or STATUS_NONE,
            "functions": len(fids),
            "untrusted": sum(1 for f in fids if functions[f]["value"] == UNTRUSTED),
            "boundary": sum(1 for f in fids if functions[f]["boundary"]),
            "api": len(idx.api(unit)),
        }
    by_source: dict[str, int] = defaultdict(int)
    for rec in functions.values():
        by_source[f"{rec['value']}:{rec['source']}"] += 1
    summary = {
        "untrusted": sum(1 for r in functions.values() if r["value"] == UNTRUSTED),
        "trusted": sum(1 for r in functions.values() if r["value"] == TRUSTED),
        "boundary": sum(1 for r in functions.values() if r["boundary"]),
        "by_source": dict(sorted(by_source.items())),
        "with_codeql": sum(1 for r in functions.values() if "codeql" in [*r["sources"], *r.get("overridden", [])]),
        "overridden": sum(1 for r in functions.values() if r.get("overridden")),
    }
    return {
        "functions": functions,
        "units": units,
        "summary": summary,
        "codeql": codeql_info,
        "input_readers": sorted(INPUT_READERS),
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------------------------------
# Model annotation, lookups for consumers
# ---------------------------------------------------------------------------------------------------


def codeql_enabled(metadata: dict | None) -> bool:
    block = (metadata or {}).get("codeql") or {}
    return bool(block.get("enabled")) and bool(block.get("open_source"))


def annotate_model(
    model: dict,
    threat_path: Path | None = None,
    codeql_path: Path | None = None,
    metadata: dict | None = None,
    threat: dict | None = None,
) -> dict:
    """
    Add `trust` to the model's functions and units and a top-level `trust` block; returns the block.
    The threat model is `threat` (load_threat_model's result) when given, else the file
    find_threat_model gives for `threat_path`. The block records its path and sha256: every later
    reader takes that file (`recorded_threat_model`).
    """
    if threat is None:
        threat = load_threat_model(find_threat_model(threat_path, model))
    codeql = None
    codeql_state: dict[str, Any] = {"status": "off"}
    if codeql_enabled(metadata):
        path = codeql_path or DEFAULT_CODEQL
        data = load_json_optional(path, None)
        if isinstance(data, dict):
            codeql = {**data, "path": str(path)}
        else:
            codeql_state = {"status": "not_run", "path": str(path)}
    elif codeql_path is not None and codeql_path.is_file():
        codeql_state = {"status": "off", "ignored": str(codeql_path)}
    result = compute_trust(model, threat, codeql)
    for fid, rec in result["functions"].items():
        model["functions"][fid]["trust"] = rec
    for unit, rec in result["units"].items():
        model["units"][unit]["trust"] = rec
    for u in (model.get("units") or {}).values():
        if u.get("test"):
            u["trust"] = {"threat_model": threat["status"], "functions": 0, "untrusted": 0, "boundary": 0, "api": 0}
    block = {
        "generated_at": utc_now(),
        "threat_model": {k: threat.get(k) for k in ("status", "path", "sha256", "reason", "errors")},
        "codeql": result["codeql"] if codeql is not None else codeql_state,
        "input_readers": result["input_readers"],
        "summary": result["summary"],
        "warnings": result["warnings"],
    }
    model["trust"] = block
    return block


def function_trust(records: dict, function: str, file: str | None = None) -> dict | None:
    """
    The trust record of `function` in a DAG's or a model's `functions` (keyed by name, `file#name`, or
    both): the record of that key, else of the functions of that name (in `file` when given). Several
    same-named records merge: untrusted wins, `boundary` when any is.
    """
    if not isinstance(records, dict):
        return None
    rec = records.get(function)
    if isinstance(rec, dict) and isinstance(rec.get("trust"), dict) and (file is None or rec.get("file") == file):
        return rec["trust"]
    name = function.split("#")[-1]
    hits = [
        r["trust"]
        for r in records.values()
        if isinstance(r, dict)
        and r.get("name") == name
        and isinstance(r.get("trust"), dict)
        and (file is None or r.get("file") == file)
    ]
    if not hits:
        return None
    if len(hits) == 1:
        return hits[0]
    untrusted = [h for h in hits if h.get("value") == UNTRUSTED]
    best = dict(untrusted[0] if untrusted else hits[0])
    best["boundary"] = any(h.get("boundary") for h in hits)
    return best


def reachability_of(trust: dict | None) -> str | None:
    """The harness reachability a trust record implies: untrusted_surface at a boundary, else internal_api."""
    if not isinstance(trust, dict) or trust.get("value") not in (UNTRUSTED, TRUSTED):
        return None
    return "untrusted_surface" if trust.get("value") == UNTRUSTED and trust.get("boundary") else "internal_api"


# ---------------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------------


def cmd_run(args: argparse.Namespace) -> int:
    model = load_json_optional(args.model, None)
    if not isinstance(model, dict) or model.get("status") != "ok":
        print(json.dumps({"ok": False, "error": f"{args.model}: no model with status ok (run phase0_model.py)"}))
        return 1
    # The threat model: --threat-model when given (a new choice, recorded in the model), else the one the
    # model recorded, unchanged; a model never annotated searches as phase0_model.py does.
    threat: dict | None = None
    recorded = model["trust"].get("threat_model") if isinstance(model.get("trust"), dict) else None
    if args.threat_model is None and isinstance(recorded, dict):
        threat, why = recorded_threat_model(model)
        if threat is None:
            print(json.dumps({"ok": False, "error": f"{args.model}: {why}"}))
            return 1
    metadata = load_json_optional(args.metadata, None)
    block = annotate_model(
        model, args.threat_model, args.codeql, metadata if isinstance(metadata, dict) else None, threat=threat
    )
    # The model's own schema problems are warnings (validate_artifacts.py run-dir fails on them).
    problems = list(validate_model(model))
    model["warnings"] = [w for w in model.get("warnings") or [] if not str(w).startswith("schema: ")]
    if problems:
        model["warnings"].append(f"schema: {problems[:5]}")
    atomic_write_json(args.model, model)
    out = {
        "ok": True,
        "threat_model": block["threat_model"],
        "codeql": block["codeql"],
        "summary": block["summary"],
        "warnings": block["warnings"][:10],
    }
    if problems:
        out["schema"] = problems[:5]
    print(json.dumps(out, indent=1))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    path = args.path or find_threat_model(None, None)
    threat = load_threat_model(path)
    out: dict[str, Any] = {k: threat.get(k) for k in ("status", "path", "reason", "errors")}
    model = load_json_optional(args.model, None)
    if threat["status"] == STATUS_OK and isinstance(model, dict) and model.get("status") == "ok":
        warnings: list[str] = []
        _threat_rules(_Index(model), threat["block"], _Marks(), {}, warnings)
        out["warnings"] = warnings
    print(json.dumps(out, indent=1))
    return 0 if threat["status"] == STATUS_OK else (2 if threat["status"] == STATUS_INVALID else 1)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Trust boundary: untrusted functions from rules, threat model, CodeQL")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="Annotate the Phase 0 model with each function's trust")
    r.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    r.add_argument("--threat-model", type=Path, default=None)
    r.add_argument("--codeql", type=Path, default=None, help=f"CodeQL facts (default {DEFAULT_CODEQL} when enabled)")
    r.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    c = sub.add_parser("check-threat-model", help="Validate THREAT_MODEL.md's structured block")
    c.add_argument("path", type=Path, nargs="?", default=None)
    c.add_argument("--model", type=Path, default=DEFAULT_MODEL, help="checks the block's references when present")
    a = p.parse_args(argv)
    return cmd_run(a) if a.cmd == "run" else cmd_check(a)


if __name__ == "__main__":
    sys.exit(main())
