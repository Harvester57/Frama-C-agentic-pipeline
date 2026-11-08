#!/usr/bin/env python3
"""
A harness for a module's whole API, built from the Phase 0 model (scripts/generate_harness.py --api).

A pinned or hand-written harness drives the entry points someone chose; the rest of the API is never
fuzzed. This one gives every API entry point of the module's scope a dispatch case (the first input
byte selects it), with arguments built from the model's signature of each function:

  - a scalar or a struct by value: read from the input (`memcpy(&a, fuzz_buf + fuzz_off, sizeof a)`);
  - a byte pointer followed by an integer (a `(buf, len)` pair): the first input pair gets the rest of
    the input itself, so a read past it is caught; an output pair gets a spare buffer and a length read
    from the input, clamped to the buffer;
  - a byte pointer with a size the call sites in the code base agree on (`param_sizes` in the model,
    step "call-site sizes"): a buffer of exactly that size, read from the input when it is an input
    (a `const` pointee), else zeroed;
  - a byte pointer without a known size: a zeroed spare buffer (`2 * MAX_INPUT_SIZE + 1024` bytes), so
    an unknown contract does not read as a target bug; a `const char *` alone takes the rest of the
    input as a NUL-terminated string;
  - a pointer to a scalar or struct: one object (an output, or read from the input when `const`);
  - a function pointer: NULL.

Recorded call sequences (seed_harvest.py traces) add sequence cases: the calls of one traced chain in
order, the buffers they share passed between them, so a later call sees what an earlier one produced
(a key pair before the box that uses it).

The layout of every case (which input bytes feed which argument) goes to the sidecar as `api_cases`,
which seed_harvest.py write reads to turn recorded calls into seeds for each case. Functions the
generator cannot call (static, variadic, an anonymous struct by value, a case the compiler refuses)
go to `api_skipped` with the reason; the reach gate then reports them as gaps.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import atomic_write_json, load_json_optional  # noqa: E402
from seed_harvest import _CHAR_POINTEES, _LEN_SCALARS, classify_type, split_signature  # noqa: E402

MODEL_JSON = Path("workspace/reports/phase0_model.json")
TRACES_JSONL = Path("workspace/seed_records/traces.jsonl")
MAX_SEQUENCE_CASES = 16
MAX_CASES = 255  # one selector byte
MAX_PROBE_ROUNDS = 3

# Byte size of the scalars a slot can hold (x86_64): a seed needs it to lay out the input.
SCALAR_BYTES = {
    "_Bool": 1,
    "char": 1,
    "signed char": 1,
    "unsigned char": 1,
    "short": 2,
    "unsigned short": 2,
    "int": 4,
    "unsigned int": 4,
    "long": 8,
    "unsigned long": 8,
    "long long": 8,
    "unsigned long long": 8,
    "float": 4,
    "double": 8,
    "long double": 16,
}


class ApiHarnessError(ValueError):
    pass


def spare_bytes(max_input_size: int) -> int:
    """The size of a buffer whose contract the model does not give: room for any length the input holds."""
    return 2 * max_input_size + 1024


def param_size(rec: dict, index: int) -> int | None:
    """The byte size the call sites agree a pointer parameter points to (largest seen), if the model has one."""
    sizes = (rec.get("param_sizes") or {}).get(str(index))
    if isinstance(sizes, dict):
        try:
            n = int(sizes.get("max") or 0)
        except (TypeError, ValueError):
            return None
        return n if n > 0 else None
    return None


def _storage(size: int | None) -> str:
    """
    Spare buffers (no known size) are `static`, zeroed on every call: a case may hold several and a
    harness many cases. A buffer of a known size stays on the stack, where an overflow is caught exactly.
    """
    return "" if size else "static "


def _is_input(formals: list[dict], index: int) -> bool:
    """A pointer the function only reads (`const` pointee), per the model; unknown counts as input."""
    if index < len(formals) and isinstance(formals[index], dict):
        return formals[index].get("kind") != "pointer"
    return True


class _Case:
    """One dispatch case under construction: its statements, input slots and the rest-of-input binding."""

    def __init__(self, spare: int) -> None:
        self.spare = spare
        self.decls: list[str] = []
        self.post: list[str] = []
        self.slots: list[dict[str, Any]] = []
        self.rest: dict[str, Any] | None = None

    def slot(self, var: str, size: int | None, call: int, param: int, kind: str, addr: bool = True) -> None:
        ref = f"&{var}" if addr else var
        self.decls.append(
            f"if (fuzz_len >= fuzz_off + sizeof({var})) {{ memcpy({ref}, fuzz_buf + fuzz_off, sizeof({var}));"
            f" fuzz_off += sizeof({var}); }}"
        )
        self.slots.append({"call": call, "param": param, "size": size, "kind": kind})

    def statements(self, calls: list[str]) -> str:
        body = ["size_t fuzz_off = 0;", *self.decls, *self.post, *calls, "(void)fuzz_off;"]
        return " ".join(body)


def _bind_call(
    case: _Case,
    call: int,
    name: str,
    params: list[dict],
    formals: list[dict],
    rec: dict,
    shared: dict[int, str] | None = None,
) -> str:
    """The declarations and slots of one call's arguments (added to `case`); returns the call statement."""
    shared = shared or {}
    args: list[str] = []
    i = 0
    n = len(params)
    while i < n:
        p = params[i]
        v = f"c{call}a{i}"
        nxt = params[i + 1] if i + 1 < n else None
        if i in shared:
            args.append(f"({p['type']}){shared[i]}")
            if (
                nxt is not None
                and (i + 1) not in shared
                and (p.get("pointee") in _CHAR_POINTEES or p.get("pointee") == "")
                and nxt["kind"] == "int"
                and nxt["ctype"] in _LEN_SCALARS
            ):
                # The length of a shared buffer: from the input, clamped to that buffer.
                ln = f"c{call}a{i + 1}"
                case.decls.append(f"{nxt['ctype']} {ln}; memset(&{ln}, 0, sizeof({ln}));")
                case.slot(ln, SCALAR_BYTES.get(nxt["ctype"]), call, i + 1, "int")
                case.decls.append(
                    f"if ((unsigned long long){ln} > sizeof({shared[i]})) {{ {ln} = ({nxt['ctype']})sizeof({shared[i]}); }}"
                )
                args.append(ln)
                i += 2
                continue
            i += 1
            continue
        if p["kind"] == "fnptr":
            args.append("0")
            i += 1
            continue
        if p["kind"] == "ptr":
            pointee = p.get("pointee") or "void"
            is_input = _is_input(formals, i)
            size = param_size(rec, i)
            charlike = pointee in _CHAR_POINTEES or pointee == ""
            pair = charlike and nxt is not None and nxt["kind"] == "int" and nxt["ctype"] in _LEN_SCALARS
            if pair and nxt is not None and (i + 1) not in shared:
                if is_input and case.rest is None and size is None:
                    case.rest = {"call": call, "param": i, "kind": "bytes"}
                    args.append(f"({p['type']})(fuzz_buf + fuzz_off)")
                    args.append(f"({nxt['type']})(fuzz_len - fuzz_off)")
                else:
                    buf = size or case.spare
                    case.decls.append(f"{_storage(size)}unsigned char {v}[{buf}]; memset({v}, 0, sizeof({v}));")
                    if size and is_input:
                        case.slot(v, size, call, i, "bytes", addr=False)
                    ln = f"c{call}a{i + 1}"
                    case.decls.append(f"{nxt['ctype']} {ln}; memset(&{ln}, 0, sizeof({ln}));")
                    case.slot(ln, SCALAR_BYTES.get(nxt["ctype"]), call, i + 1, "int")
                    case.decls.append(f"if ((unsigned long long){ln} > {buf}ULL) {{ {ln} = ({nxt['ctype']}){buf}; }}")
                    args.append(f"({p['type']}){v}")
                    args.append(ln)
                i += 2
                continue
            if charlike:
                buf = size or case.spare
                case.decls.append(f"{_storage(size)}unsigned char {v}[{buf}]; memset({v}, 0, sizeof({v}));")
                if size and is_input:
                    case.slot(v, size, call, i, "bytes", addr=False)
                elif size is None and is_input and pointee in ("char", "signed char") and case.rest is None:
                    case.rest = {"call": call, "param": i, "kind": "string"}
                    case.post.append(
                        f"{{ size_t rest_n = fuzz_len - fuzz_off; if (rest_n > sizeof({v}) - 1) "
                        f"{{ rest_n = sizeof({v}) - 1; }} memcpy({v}, fuzz_buf + fuzz_off, rest_n); {v}[rest_n] = 0; }}"
                    )
                args.append(f"({p['type']}){v}")
                i += 1
                continue
            # A pointer to a scalar or a struct: an array of the known size, else one object.
            if size:
                case.decls.append(
                    f"{pointee} {v}[({size} + sizeof({pointee}) - 1) / sizeof({pointee})]; memset({v}, 0, sizeof({v}));"
                )
                if is_input:
                    case.slot(v, size, call, i, "bytes", addr=False)
                args.append(f"({p['type']}){v}")
            else:
                case.decls.append(f"{pointee} {v}; memset(&{v}, 0, sizeof({v}));")
                if is_input:
                    case.slot(v, SCALAR_BYTES.get(pointee), call, i, "pointee")
                args.append(f"&{v}")
            i += 1
            continue
        # A scalar, an enum or a struct by value.
        case.decls.append(f"{p['ctype']} {v}; memset(&{v}, 0, sizeof({v}));")
        case.slot(v, SCALAR_BYTES.get(p["ctype"]), call, i, "struct" if p["kind"] == "struct" else "int")
        args.append(v)
        i += 1
    return f"(void){name}({', '.join(args)});"


def plan_params(signature: str) -> tuple[list[dict] | None, str | None]:
    """The parameters of a model signature as the generator spells them, or why it cannot call it."""
    parts = split_signature(signature)
    if parts is None:
        return None, f"signature {signature!r} not understood"
    _, params_s, variadic = parts
    if variadic:
        return None, "variadic"
    params: list[dict] = []
    for t in params_s:
        c = classify_type(t)
        if c["kind"] in ("unsupported", "void"):
            return None, c.get("why") or "void parameter"
        if c["kind"] == "struct" and str(c.get("tag", "")).startswith("__anon"):
            return None, "anonymous struct by value"
        if c["kind"] == "ptr" and "__anon" in str(c.get("pointee") or ""):
            return None, "pointer to an anonymous struct"
        # An array parameter is a pointer: cast to `void *`, which converts to it.
        c["type"] = "void *" if "[" in t else " ".join(t.split())
        params.append(c)
    return params, None


def _model_record(model: dict, dag_rec: dict, key: str) -> dict:
    functions = model.get("functions") or {}
    name = str(dag_rec.get("name") or key.split("#")[-1])
    for cand in (f"{dag_rec.get('file')}#{name}", key):
        if isinstance(functions.get(cand), dict):
            return functions[cand]
    return {}


def single_case(name: str, model_rec: dict, spare: int) -> tuple[str | None, dict | None, str | None]:
    """(statements, layout, why not) of the case that calls one API function."""
    params, why = plan_params(str(model_rec.get("signature") or ""))
    if params is None:
        return None, None, why
    case = _Case(spare)
    call = _bind_call(case, 0, name, params, list(model_rec.get("formals") or []), model_rec)
    layout = {"kind": "single", "calls": [name], "slots": case.slots, "rest": case.rest}
    return case.statements([call]), layout, None


def load_traces(path: Path = TRACES_JSONL) -> list[list[dict]]:
    """Recorded call sequences (seed_harvest.py record) of more than one call: one list per traced process."""
    from seed_harvest import load_traces as load_recorded

    traces = [[c for c in t if isinstance(c.get("fn"), str)] for t in load_recorded(path.parent)]
    return [t for t in traces if len(t) > 1]


def chains(trace: list[dict]) -> list[list[int]]:
    """
    The calls of one trace grouped by data flow: two calls are in one chain when they pass the same
    pointer (by address). Chains of one call are left out; the single cases cover them.
    """
    parent = list(range(len(trace)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    first_by_addr: dict[str, int] = {}
    for k, call in enumerate(trace):
        for addr in (call.get("addrs") or {}).values():
            if not isinstance(addr, str) or addr in ("0", "-"):
                continue
            if addr in first_by_addr:
                parent[find(k)] = find(first_by_addr[addr])
            else:
                first_by_addr[addr] = k
    groups: dict[int, list[int]] = {}
    for k in range(len(trace)):
        groups.setdefault(find(k), []).append(k)
    return [g for g in groups.values() if len(g) > 1]


def sequence_case(
    trace: list[dict], chain: list[int], records: dict[str, dict], spare: int
) -> tuple[str | None, dict | None, str | None]:
    """
    The case that replays one chain of a trace: one buffer per shared address (the largest size the
    model or the trace gives it), passed to every call that used that address; every other argument
    as in a single case. The layout's slots name the trace call (`call`, its position in the chain).
    """
    case = _Case(spare)
    buffers: dict[str, str] = {}
    calls: list[str] = []
    names: list[str] = []
    seen_addr: dict[str, int] = {}
    for call in (trace[k] for k in chain):
        for addr in (call.get("addrs") or {}).values():
            if isinstance(addr, str) and addr not in ("0", "-"):
                seen_addr[addr] = seen_addr.get(addr, 0) + 1
    shared_addrs = {a for a, c in seen_addr.items() if c > 1}
    for pos, k in enumerate(chain):
        call = trace[k]
        name = call["fn"]
        rec = records.get(name)
        if rec is None:
            return None, None, f"{name} is not an API function of this module"
        params, why = plan_params(str(rec.get("signature") or ""))
        if params is None:
            return None, None, f"{name}: {why}"
        shared: dict[int, str] = {}
        for idx_s, addr in (call.get("addrs") or {}).items():
            if addr not in shared_addrs:
                continue
            idx = int(idx_s)
            if idx >= len(params) or params[idx]["kind"] != "ptr":
                continue
            if addr not in buffers:
                var = f"s{len(buffers)}"
                # The largest size the model gives any use of this address, or the trace recorded.
                size = max(
                    [
                        param_size(records.get(trace[j]["fn"]) or {}, int(i)) or 0
                        for j in chain
                        for i, a in (trace[j].get("addrs") or {}).items()
                        if a == addr
                    ]
                    + [int((call.get("sizes") or {}).get(idx_s) or 0)]
                )
                case.decls.append(
                    f"{_storage(size or None)}unsigned char {var}[{size or spare}]; memset({var}, 0, sizeof({var}));"
                )
                # Filled from the input when its first use reads it and its size is known.
                if size and _is_input(list(rec.get("formals") or []), idx):
                    case.slot(var, size, pos, idx, "bytes", addr=False)
                buffers[addr] = var
            shared[idx] = buffers[addr]
        calls.append(_bind_call(case, pos, name, params, list(rec.get("formals") or []), rec, shared))
        names.append(name)
    layout = {"kind": "sequence", "calls": names, "slots": case.slots, "rest": case.rest}
    return case.statements(calls), layout, None


def plan(
    dag: dict,
    model: dict,
    module: str,
    unit: str | None,
    max_input_size: int,
    traces: list[list[dict]] | None = None,
) -> dict[str, Any]:
    """The cases of a module's API harness: {entries, cases, layouts, skipped}."""
    from module_map import ModuleMap

    mm = ModuleMap(dag, {module: {"unit": unit}} if unit else {})
    entries = mm.scope_entry_points(module)
    if not entries:
        info = (dag.get("modules") or {}).get(module) or {}
        entries = [e for e in info.get("candidate_entry_points") or [] if isinstance(e, str)]
    functions = dag.get("functions") or {}
    spare = spare_bytes(max_input_size)
    cases: list[str] = []
    layouts: list[dict] = []
    skipped: dict[str, str] = {}
    records: dict[str, dict] = {}
    names: list[str] = []
    for key in entries:
        drec = functions.get(key) or {}
        name = str(drec.get("name") or key.split("#")[-1])
        if name == "main":
            continue
        if drec.get("is_static"):
            skipped[key] = "static: not callable from the harness"
            continue
        mrec = _model_record(model, drec, key)
        if not mrec:
            skipped[key] = "not in the Phase 0 model"
            continue
        stmt, layout, why = single_case(name, mrec, spare)
        if stmt is None or layout is None:
            skipped[key] = str(why)
            continue
        records[name] = mrec
        names.append(key)
        cases.append(stmt)
        layouts.append({**layout, "entry": key})
    seq_seen: set[tuple[str, ...]] = set()
    for trace in traces or []:
        for chain in chains(trace):
            sig = tuple(trace[k]["fn"] for k in chain)
            if sig in seq_seen or len(seq_seen) >= MAX_SEQUENCE_CASES:
                continue
            stmt, layout, why = sequence_case(trace, chain, records, spare)
            if stmt is None or layout is None:
                continue
            seq_seen.add(sig)
            cases.append(stmt)
            layouts.append(layout)
    if len(cases) > MAX_CASES:
        for lay in layouts[MAX_CASES:]:
            if lay.get("entry"):
                skipped[lay["entry"]] = f"more than {MAX_CASES} cases"
        cases, layouts = cases[:MAX_CASES], layouts[:MAX_CASES]
    for sel, lay in enumerate(layouts):
        lay["selector"] = sel
    return {"entries": names, "cases": cases, "layouts": layouts, "skipped": skipped}


_ERR_LINE_RE = re.compile(r"^(?P<file>[^:\n]+):(?P<line>\d+):\d+:\s+(?:fatal\s+)?error:", re.MULTILINE)


def failing_cases(harness_c: Path, cppflags: str, clang: str | None = None) -> set[int] | None:
    """
    Selectors of the dispatch cases the compiler refuses (each case is one line of the harness), or
    None when no compiler ran. A case the target's headers cannot spell (an incomplete struct) is
    dropped instead of failing the whole harness.
    """
    import shlex

    exe = clang or shutil.which("clang") or shutil.which("gcc")
    if not exe:
        return None
    argv = [exe, "-fsyntax-only", "-w", "-x", "c", *shlex.split(cppflags), str(harness_c)]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode == 0:
        return set()
    lines = harness_c.read_text(encoding="utf-8", errors="replace").splitlines()
    case_of_line = {}
    for no, text in enumerate(lines, start=1):
        m = re.match(r"\s*case (\d+)U: \{", text)
        if m:
            case_of_line[no] = int(m.group(1))
    bad: set[int] = set()
    for m in _ERR_LINE_RE.finditer((proc.stdout or "") + (proc.stderr or "")):
        if Path(m.group("file")).name == harness_c.name and int(m.group("line")) in case_of_line:
            bad.add(case_of_line[int(m.group("line"))])
    return bad if bad else None


def generate(
    module: str,
    header: str | None,
    max_input_size: int,
    cppflags: str,
    out_dir: Path,
    unit: str | None = None,
    ldflags: str = "",
    extra_includes: list[str] | None = None,
    reachability: str | None = None,
    auto_prelude: bool = True,
    probe: bool = True,
    dag_path: Path | None = None,
    model_path: Path = MODEL_JSON,
    traces_path: Path = TRACES_JSONL,
) -> dict[str, Any]:
    """Write harness_<module>.{c,json} for the module's whole API; the generate_harness result plus counts."""
    from generate_harness import generate_module_harness

    dag_file = dag_path or (out_dir.parent / "reports" / "callgraph_dag.json")
    dag = load_json_optional(dag_file, None)
    if not isinstance(dag, dict):
        raise ApiHarnessError(f"--api needs the DAG ({dag_file})")
    model = load_json_optional(model_path, None)
    if not isinstance(model, dict) or model.get("status") != "ok":
        raise ApiHarnessError(f"--api needs the Phase 0 model ({model_path})")
    p = plan(dag, model, module, unit, max_input_size, load_traces(traces_path))
    if not p["cases"]:
        raise ApiHarnessError(f"module {module!r}: no API entry point the generator can call: {p['skipped']}")
    functions = dag.get("functions") or {}
    sources = sorted(
        {str((functions.get(k) or {}).get("file")) for k in p["entries"] if (functions.get(k) or {}).get("file")}
    )
    first = str((functions.get(p["entries"][0]) or {}).get("name") or p["entries"][0].split("#")[-1])
    cases, layouts, skipped = list(p["cases"]), list(p["layouts"]), dict(p["skipped"])
    result: dict[str, Any] = {}
    for _ in range(MAX_PROBE_ROUNDS):
        result = generate_module_harness(
            module_name=module,
            sources=sources,
            header_include=header,
            entry_fn=first,
            max_input_size=max_input_size,
            cppflags=cppflags,
            out_dir=out_dir,
            reachability=reachability,
            entry_style="dispatch",
            dispatch_cases=cases,
            unit=unit,
            ldflags=ldflags,
            extra_includes=extra_includes,
            auto_prelude=auto_prelude,
        )
        if not probe:
            break
        bad = failing_cases(Path(result["harness_file"]), result["cppflags"])
        if not bad:
            break
        keep = [i for i in range(len(cases)) if i not in bad]
        for i in sorted(bad):
            if layouts[i].get("entry"):
                skipped[layouts[i]["entry"]] = "the case does not compile with the target's headers"
        if not keep:
            raise ApiHarnessError(f"module {module!r}: no API case compiles: {sorted(skipped.items())}")
        cases = [cases[i] for i in keep]
        layouts = [layouts[i] for i in keep]
        for sel, lay in enumerate(layouts):
            lay["selector"] = sel
    sidecar_path = Path(result["harness_meta"])
    sidecar = load_json_optional(sidecar_path, {}) or {}
    sidecar["api_harness"] = True
    sidecar["api_cases"] = layouts
    sidecar["api_skipped"] = skipped
    atomic_write_json(sidecar_path, sidecar)
    result.update(
        api_cases=len(layouts),
        api_entries=sum(1 for lay in layouts if lay.get("entry")),
        api_sequences=sum(1 for lay in layouts if lay["kind"] == "sequence"),
        api_skipped=skipped,
    )
    return result
