#!/usr/bin/env python3
"""
A harness for a module's whole API, built from the Phase 0 model (scripts/generate_harness.py --api).

A pinned or hand-written harness drives the entry points someone chose; the rest of the API is never
fuzzed. This one gives every API entry point of the module's scope a dispatch case (the first input
byte selects it), with arguments built from the model's signature of each function:

  - a scalar, an enum, or a struct by value without pointers: read from the input
    (`memcpy(&a, fuzz_buf + fuzz_off, sizeof a)`);
  - a struct by value with pointers (a `{ptr, len}` slice such as QCBOR's `UsefulBufC`): never read
    from the input as a whole, so no input byte becomes a pointer. Its layout comes from the target's
    headers (`probe_layouts`: clang's AST of the harness). Each (pointer, length) field pair gets
    generator-owned storage: an input pair (`const` pointee) takes the rest of the input when it is
    still free, else a `PAIR_BYTES` buffer read from the input; an output pair a zeroed spare buffer;
    the length is read from the input and clamped to that storage. Another pointer field points to a
    zeroed spare buffer, a function pointer stays NULL, every other field is read from the input. A
    struct whose layout is unknown is zeroed, and the case's `notes` say why;
  - a byte pointer followed by a length (a `(buf, len)` pair: an unsigned integer, or a signed one
    whose formal name says length, never an enum): the first input pair gets the rest of the input
    itself, so a read past it is caught; an output pair gets a spare buffer and a length read from
    the input, clamped to the buffer;
  - a byte pointer with a size the call sites in the code base agree on (`param_sizes` in the model,
    step "call-site sizes"): a buffer of exactly that size, read from the input when it is an input
    (a `const` pointee), else zeroed;
  - a byte pointer without a known size: a zeroed spare buffer (`2 * MAX_INPUT_SIZE + 1024` bytes), so
    an unknown contract does not read as a target bug; a `const char *` alone takes the rest of the
    input as a NUL-terminated string;
  - a pointer to a struct the API has an initializer for (a function named like `*_Init`, `*_init`,
    `*Init*`, `*_new`, `*_create` whose first parameter is a non-const pointer to that struct; the one
    the recorded traces call first, else the plainest): one object, initialized by that call before
    the call under test (its own arguments built by the same rules; the case's `inits` name it). The
    initializer's own case does not call it first;
  - a pointer to another scalar or struct: one object (an output, or read from the input when `const`
    and the struct has no pointers; zeroed otherwise);
  - a function pointer: NULL.

Recorded call sequences (seed_harvest.py traces) add sequence cases: the calls of one traced chain in
order, the buffers they share passed between them, so a later call sees what an earlier one produced
(a key pair before the box that uses it).

The layout of every case (which input bytes feed which argument) goes to the sidecar as `api_cases`,
which seed_harvest.py write reads to turn recorded calls into seeds for each case. Functions the
generator cannot call (static, variadic, an anonymous struct by value, a case the compiler refuses,
with the compiler's first error) go to `api_skipped` with the reason; the reach gate then reports
them as gaps.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import load_json_optional  # noqa: E402
from seed_harvest import _CHAR_POINTEES, _QUALIFIERS_RE, classify_type, is_length, split_signature  # noqa: E402

MODEL_JSON = Path("workspace/reports/phase0_model.json")
TRACES_JSONL = Path("workspace/seed_records/traces.jsonl")
MAX_SEQUENCE_CASES = 16
MAX_CASES = 255  # one selector byte
PAIR_BYTES = 256  # an input (pointer, length) field pair that does not get the rest of the input
MAX_DIAGNOSTIC_CHARS = 300
POINTER_BYTES = 8  # x86_64, as SCALAR_BYTES
# Initializer names: QCBORDecode_Init, UsefulOutBuf_Init, ctx_init, foo_new, bar_create.
_INIT_NAME_RE = re.compile(r"Init|(?:^|_)init(?:$|_)|_new$|_create$")

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


@dataclass
class ApiInfo:
    """
    What the generator knows of the module's API beyond each signature: the layouts of the structs the
    target's headers define (`probe_layouts`; `probed` says whether a probe ran), and per struct type
    (`struct tag`) the initializer to call on a pointer to it and every initializer candidate.
    """

    structs: dict[str, dict] = field(default_factory=dict)
    probed: bool = False
    inits: dict[str, str] = field(default_factory=dict)
    candidates: dict[str, set[str]] = field(default_factory=dict)
    records: dict[str, dict] = field(default_factory=dict)


class _Case:
    """One dispatch case under construction: its statements, input slots and the rest-of-input binding."""

    def __init__(self, spare: int, api: ApiInfo | None = None, calls: int = 1) -> None:
        self.spare = spare
        self.api = api or ApiInfo()
        self.ncalls = calls
        self.decls: list[str] = []
        self.post: list[str] = []
        self.slots: list[dict[str, Any]] = []
        self.rest: dict[str, Any] | None = None
        self.inits: list[dict[str, Any]] = []
        self.notes: list[str] = []

    def slot(
        self, var: str, size: int | None, call: int, param: int, kind: str, addr: bool = True, **extra: Any
    ) -> None:
        ref = f"&{var}" if addr else var
        self.decls.append(
            f"if (fuzz_len >= fuzz_off + sizeof({var})) {{ memcpy({ref}, fuzz_buf + fuzz_off, sizeof({var}));"
            f" fuzz_off += sizeof({var}); }}"
        )
        self.slots.append({"call": call, "param": param, "size": size, "kind": kind, **extra})

    def bool_slot(self, var: str, call: int, param: int, kind: str, **extra: Any) -> None:
        """
        A `_Bool` read from the input: only 0 and 1 are values of the type (any other byte is undefined
        behavior in the harness itself, which UBSan reports at the first load), so the byte's low bit.
        """
        self.slot(var, 1, call, param, kind, **extra)
        self.decls.append(f"{{ unsigned char fc_b; memcpy(&fc_b, &{var}, 1); {var} = (fc_b & 1U) != 0; }}")

    def note(self, call: int, param: int, why: str) -> None:
        self.notes.append(f"call {call} argument {param}: {why}")

    def layout(self, kind: str, calls: list[str]) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": kind, "calls": calls, "slots": self.slots, "rest": self.rest}
        if self.inits:
            out["inits"] = self.inits
        if self.notes:
            out["notes"] = self.notes
        return out

    def statements(self, calls: list[str]) -> str:
        body = ["size_t fuzz_off = 0;", *self.decls, *self.post, *calls, "(void)fuzz_off;"]
        return " ".join(body)


def _name(formals: list[dict], i: int) -> str | None:
    if i < len(formals) and isinstance(formals[i], dict) and isinstance(formals[i].get("name"), str):
        return formals[i]["name"]
    return None


def _charlike(p: dict) -> bool:
    return p.get("pointee") in _CHAR_POINTEES or p.get("pointee") == ""


def _is_pair(params: list[dict], i: int, formals: list[dict] | None = None) -> bool:
    """A byte pointer followed by a length (never an enum): a (buffer, length) pair."""
    p = params[i]
    nxt = params[i + 1] if i + 1 < len(params) else None
    return p["kind"] == "ptr" and _charlike(p) and nxt is not None and is_length(nxt, _name(formals or [], i + 1))


def _variable_length(params: list[dict], formals: list[dict], rec: dict, shared: dict[int, str]) -> bool:
    """
    Whether the call reads an input pair of no known size, so its length comes from the fuzz input. A
    lone output pointer of such a call (crypto_box's `c`, sized by `mlen`) may receive that many bytes,
    whatever size its call sites showed: it gets a spare buffer.
    """
    return any(
        _is_pair(params, i, formals) and i not in shared and _is_input(formals, i) and param_size(rec, i) is None
        for i in range(len(params))
    )


def _lone_output(params: list[dict], formals: list[dict], i: int) -> bool:
    return params[i]["kind"] == "ptr" and not _is_pair(params, i, formals) and not _is_input(formals, i)


def _is_record(t: str) -> bool:
    return t.startswith(("struct ", "union "))


def _layout_why(api: ApiInfo, ctype: str) -> str:
    if not api.probed:
        return f"{ctype}: no struct layout (the layout probe did not run)"
    return f"{ctype}: layout not known (not defined in the headers, a bit-field, packed, or an anonymous member)"


def _raw_ok(lay: dict | None) -> bool:
    """Whether a struct, union or member may be copied from input bytes: no pointer and no `_Bool` in it."""
    return lay is not None and not lay.get("pointers") and not lay.get("bools")


def _len_field(f: dict) -> bool:
    return f.get("kind") == "int" and is_length({"kind": "int", "ctype": f.get("ctype")}, f.get("name"))


def _fill_fields(case: _Case, call: int, param: int, expr: str, lay: dict, base: int) -> None:
    """
    Fill the fields of a struct with pointers (`expr`, already zeroed) without putting an input byte
    into a pointer: (pointer, length) pairs get generator-owned storage, other pointers a zeroed spare
    buffer, function pointers stay NULL, scalars and pointer-free members come from the input.
    """
    fields = list(lay.get("fields") or [])
    i = 0
    while i < len(fields):
        f = fields[i]
        fx = f"{expr}.{f['name']}"
        off = base + int(f["off"])
        nxt = fields[i + 1] if i + 1 < len(fields) else None
        tag = f"{expr.replace('.', '_')}f{i}"
        if f["kind"] == "ptr" and nxt is not None and _len_field(nxt):
            lx = f"{expr}.{nxt['name']}"
            if f.get("const") and case.rest is None:
                case.rest = {"call": call, "param": param, "kind": "bytes", "off": off}
                case.post.append(f"{fx} = (void *)(fuzz_buf + fuzz_off); {lx} = ({nxt['ctype']})(fuzz_len - fuzz_off);")
            else:
                size = PAIR_BYTES if f.get("const") else case.spare
                case.decls.append(f"{_storage(None)}unsigned char {tag}[{size}]; memset({tag}, 0, sizeof({tag}));")
                if f.get("const"):
                    case.slot(tag, size, call, param, "field_bytes", addr=False, off=off)
                case.slot(lx, int(nxt["size"]), call, param, "field_len", off=off, max=size)
                case.decls.append(
                    f"if ((unsigned long long){lx} > {size}ULL) {{ {lx} = ({nxt['ctype']}){size}; }} {fx} = (void *){tag};"
                )
            i += 2
            continue
        if f["kind"] == "ptr":
            case.decls.append(
                f"static unsigned char {tag}[{case.spare}]; memset({tag}, 0, sizeof({tag})); {fx} = (void *){tag};"
            )
        elif f["kind"] == "int" and f.get("ctype") == "_Bool":
            case.bool_slot(fx, call, param, "field", off=off)
        elif f["kind"] in ("int", "float", "enum") or (f["kind"] in ("array", "record") and _raw_ok(f)):
            case.slot(fx, int(f["size"]), call, param, "field", addr=f["kind"] != "array", off=off)
        elif f["kind"] == "record" and f.get("what") == "struct" and f.get("ctype") in case.api.structs:
            _fill_fields(case, call, param, fx, case.api.structs[f["ctype"]], off)
        elif f["kind"] != "fnptr":
            case.note(call, param, f"field {f['name']}: holds pointers or _Bool the generator cannot place: zeroed")
        i += 1


def _struct_value(case: _Case, call: int, param: int, v: str, ctype: str) -> None:
    """A struct (or union) by value: read from the input without pointers, else filled field by field."""
    case.decls.append(f"{ctype} {v}; memset(&{v}, 0, sizeof({v}));")
    lay = case.api.structs.get(ctype)
    if lay is None:
        case.note(call, param, f"{_layout_why(case.api, ctype)}: zeroed, not read from the input")
    elif _raw_ok(lay):
        case.slot(v, int(lay["size"]), call, param, "struct")
    elif lay.get("what") == "struct":
        _fill_fields(case, call, param, v, lay, 0)
    else:
        case.note(call, param, f"{ctype}: a union with pointers or _Bool: zeroed, not read from the input")


def _init_call(case: _Case, pointee: str, target: str, call: int, param: int) -> str:
    """The initializer call of a struct object `target` (an address expression) before call `call`."""
    fn = case.api.inits[pointee]
    rec = case.api.records.get(fn) or {}
    params, _ = plan_params(str(rec.get("signature") or ""))
    k = case.ncalls + len(case.inits)
    case.inits.append({"fn": fn, "call": k, "for": {"call": call, "param": param}})
    return _bind_call(case, k, fn, params or [], list(rec.get("formals") or []), rec, {0: target}, allow_init=False)


def _bind_call(
    case: _Case,
    call: int,
    name: str,
    params: list[dict],
    formals: list[dict],
    rec: dict,
    shared: dict[int, str] | None = None,
    allow_init: bool = True,
) -> str:
    """
    The declarations and slots of one call's arguments (added to `case`); returns the call statement,
    preceded by the initializer calls of its struct objects.
    """
    shared = shared or {}
    varlen = _variable_length(params, formals, rec, shared)
    args: list[str] = []
    before: list[str] = []
    i = 0
    n = len(params)
    while i < n:
        p = params[i]
        v = f"c{call}a{i}"
        nxt = params[i + 1] if i + 1 < n else None
        if i in shared:
            args.append(f"({p['type']}){shared[i]}")
            if nxt is not None and (i + 1) not in shared and _is_pair(params, i, formals):
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
            size = None if varlen and _lone_output(params, formals, i) else param_size(rec, i)
            charlike = _charlike(p)
            pair = _is_pair(params, i, formals)
            own_init = i == 0 and name in case.api.candidates.get(pointee, set())
            if allow_init and pointee in case.api.inits and not own_init:
                # A context object: its initializer runs first, never a zeroed or input-filled object.
                case.decls.append(f"{pointee} {v}; memset(&{v}, 0, sizeof({v}));")
                before.append(_init_call(case, pointee, f"&{v}", call, i))
                args.append(f"&{v}")
                i += 1
                continue
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
            # A pointer to a scalar or a struct: an array of the known size, else one object. A struct
            # with pointers (or of unknown layout) is never read from the input as raw bytes.
            lay = case.api.structs.get(pointee) if _is_record(pointee) else None
            raw_ok = pointee != "_Bool" and (not _is_record(pointee) or _raw_ok(lay))
            if is_input and not raw_ok and lay is None:
                case.note(call, i, f"{_layout_why(case.api, pointee)}: the object is zeroed, not read from the input")
            if size:
                case.decls.append(
                    f"{pointee} {v}[({size} + sizeof({pointee}) - 1) / sizeof({pointee})]; memset({v}, 0, sizeof({v}));"
                )
                if is_input and raw_ok:
                    case.slot(v, size, call, i, "bytes", addr=False)
                elif is_input and lay is not None and lay.get("what") == "struct":
                    _fill_fields(case, call, i, f"{v}[0]", lay, 0)
                args.append(f"({p['type']}){v}")
            elif varlen and _lone_output(params, formals, i):
                case.decls.append(f"static unsigned char {v}[{case.spare}]; memset({v}, 0, sizeof({v}));")
                args.append(f"({p['type']}){v}")
            else:
                case.decls.append(f"{pointee} {v}; memset(&{v}, 0, sizeof({v}));")
                if is_input and pointee == "_Bool":
                    case.bool_slot(v, call, i, "pointee")
                elif is_input and raw_ok:
                    case.slot(v, SCALAR_BYTES.get(pointee) or (lay or {}).get("size"), call, i, "pointee")
                elif is_input and lay is not None and lay.get("what") == "struct":
                    _fill_fields(case, call, i, v, lay, 0)
                args.append(f"&{v}")
            i += 1
            continue
        if p["kind"] == "struct":
            _struct_value(case, call, i, v, p["ctype"])
            args.append(v)
            i += 1
            continue
        # A scalar or an enum.
        case.decls.append(f"{p['ctype']} {v}; memset(&{v}, 0, sizeof({v}));")
        if p["ctype"] == "_Bool":
            case.bool_slot(v, call, i, "int")
        else:
            case.slot(v, SCALAR_BYTES.get(p["ctype"]), call, i, "int")
        args.append(v)
        i += 1
    return " ".join([*before, f"(void){name}({', '.join(args)});"])


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


def single_case(
    name: str, model_rec: dict, spare: int, api: ApiInfo | None = None
) -> tuple[str | None, dict | None, str | None]:
    """(statements, layout, why not) of the case that calls one API function."""
    params, why = plan_params(str(model_rec.get("signature") or ""))
    if params is None:
        return None, None, why
    case = _Case(spare, api, calls=1)
    call = _bind_call(case, 0, name, params, list(model_rec.get("formals") or []), model_rec)
    return case.statements([call]), case.layout("single", [name]), None


def initializers(
    functions: dict[str, dict], traces: list[list[dict]] | None = None, visible: set[str] | None = None
) -> tuple[dict[str, str], dict[str, set[str]], dict[str, dict]]:
    """
    Per struct type, the initializer the harness calls on a pointer to it, and every candidate: a
    function named like an initializer whose first parameter is a non-const pointer to that struct.
    `functions` are the model's records (key -> record); a header `static` function counts only when
    the layout probe saw it declared in the harness (`visible`), every function then must be. The
    recorded traces decide between candidates (the one called first), else the plainest name
    (`*_Init`/`*_init`), the fewest parameters, then the name.
    """
    cands: dict[str, set[str]] = {}
    records: dict[str, dict] = {}
    for key, rec in functions.items():
        if not isinstance(rec, dict):
            continue
        name = str(rec.get("name") or key.split("#")[-1])
        if not _INIT_NAME_RE.search(name):
            continue
        if rec.get("static") and not rec.get("header"):
            continue
        if (rec.get("static") and visible is None) or (visible is not None and name not in visible):
            continue
        params, _ = plan_params(str(rec.get("signature") or ""))
        formals = list(rec.get("formals") or [])
        if not params or params[0]["kind"] != "ptr" or _is_input(formals, 0):
            continue
        pointee = str(params[0].get("pointee") or "")
        if not _is_record(pointee):
            continue
        cands.setdefault(pointee, set()).add(name)
        records[name] = rec
    chosen: dict[str, str] = {}
    for trace in traces or []:
        for c in trace:
            fn = c.get("fn")
            for t, names in cands.items():
                if fn in names and t not in chosen:
                    chosen[t] = str(fn)

    def plainest(n: str) -> tuple[bool, int, str]:
        parts = split_signature(str(records[n].get("signature") or ""))
        return (not re.search(r"_[Ii]nit$", n), len(parts[1]) if parts else 99, n)

    for t, names in cands.items():
        if t not in chosen:
            chosen[t] = min(names, key=plainest)
    return chosen, cands, records


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


def _shared_size(trace: list[dict], chain: list[int], records: dict[str, dict], addr: str) -> int:
    """
    The size of a buffer shared by the calls of a chain: the largest the model gives any of its uses,
    0 (a spare buffer) when no use has one or a use is the lone output of a variable-length call. The
    bytes the trace recorded are not a size: they are what one run passed, often less than the object.
    """
    sizes: list[int] = []
    for j in chain:
        rec = records.get(trace[j]["fn"]) or {}
        params, _ = plan_params(str(rec.get("signature") or ""))
        formals = list(rec.get("formals") or [])
        for i_s, a in (trace[j].get("addrs") or {}).items():
            if a != addr:
                continue
            i = int(i_s)
            if (
                params
                and i < len(params)
                and _lone_output(params, formals, i)
                and _variable_length(params, formals, rec, {})
            ):
                return 0
            sizes.append(param_size(rec, i) or 0)
    return max(sizes, default=0)


def sequence_case(
    trace: list[dict], chain: list[int], records: dict[str, dict], spare: int, api: ApiInfo | None = None
) -> tuple[str | None, dict | None, str | None]:
    """
    The case that replays one chain of a trace: one buffer per shared address (the largest size the
    model or the trace gives it), passed to every call that used that address; every other argument
    as in a single case. The layout's slots name the trace call (`call`, its position in the chain).
    A shared struct object whose first use is not one of its initializers gets the initializer first.
    """
    case = _Case(spare, api, calls=len(chain))
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
        before: list[str] = []
        for idx_s, addr in (call.get("addrs") or {}).items():
            if addr not in shared_addrs:
                continue
            idx = int(idx_s)
            if idx >= len(params) or params[idx]["kind"] != "ptr":
                continue
            if addr not in buffers:
                var = f"s{len(buffers)}"
                size = _shared_size(trace, chain, records, addr)
                pointee = str(params[idx].get("pointee") or "")
                is_record = _is_record(pointee)
                lay = case.api.structs.get(pointee) if is_record else None
                n_bytes = str(size or spare)
                if is_record:
                    # Room for the whole object, whatever size the call sites showed.
                    n_bytes = f"({n_bytes} > sizeof({pointee}) ? {n_bytes} : sizeof({pointee}))"
                case.decls.append(
                    f"{_storage(size or None)}unsigned char {var}[{n_bytes}]; memset({var}, 0, sizeof({var}));"
                )
                # Filled from the input when its first use reads it, its size is known, and it holds
                # no pointer.
                raw_ok = not is_record or _raw_ok(lay)
                if size and _is_input(list(rec.get("formals") or []), idx) and raw_ok:
                    case.slot(var, size, pos, idx, "bytes", addr=False)
                buffers[addr] = var
                own_init = idx == 0 and name in case.api.candidates.get(pointee, set())
                if pointee in case.api.inits and not own_init:
                    before.append(_init_call(case, pointee, var, pos, idx))
            shared[idx] = buffers[addr]
        calls.append(
            " ".join([*before, _bind_call(case, pos, name, params, list(rec.get("formals") or []), rec, shared)])
        )
        names.append(name)
    return case.statements(calls), case.layout("sequence", names), None


def plan(
    dag: dict,
    model: dict,
    module: str,
    unit: str | None,
    max_input_size: int,
    traces: list[list[dict]] | None = None,
    scope_files: list[str] | None = None,
    struct_layouts: dict[str, dict] | None = None,
    visible: set[str] | None = None,
) -> dict[str, Any]:
    """
    The cases of a module's API harness: {entries, cases, layouts, skipped}. `scope_files` (the
    sidecar's) give a sub-module that is neither a lexer module nor a cluster its scope.
    `struct_layouts` and `visible` come from `probe_layouts` (None: no probe ran).
    """
    from module_map import ModuleMap

    sidecar: dict[str, Any] = {
        **({"unit": unit} if unit else {}),
        **({"scope_files": scope_files} if scope_files else {}),
    }
    mm = ModuleMap(dag, {module: sidecar} if sidecar else {})
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
    # Initializers: the module's callable entry points, and header functions the harness sees.
    entry_names = {str((functions.get(k) or {}).get("name") or k.split("#")[-1]) for k in entries}
    init_pool = {
        k: rec
        for k, rec in (model.get("functions") or {}).items()
        if isinstance(rec, dict)
        and (str(rec.get("name") or k.split("#")[-1]) in entry_names or (rec.get("static") and rec.get("header")))
    }
    inits, candidates, init_records = initializers(init_pool, traces, visible)
    api = ApiInfo(
        structs=dict(struct_layouts or {}),
        probed=struct_layouts is not None,
        inits=inits,
        candidates=candidates,
        records=init_records,
    )
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
        stmt, layout, why = single_case(name, mrec, spare, api)
        if stmt is None or layout is None:
            skipped[key] = str(why)
            continue
        records[name] = mrec
        names.append(key)
        cases.append(stmt)
        layouts.append({**layout, "entry": key})
    seq_seen: set[tuple[str, ...]] = set()
    for full in traces or []:
        # Calls into other modules (an entropy source filling a nonce) are not replayed: what they
        # produced comes from the input instead, and the rest of the chain stays.
        trace = [c for c in full if c.get("fn") in records]
        for chain in chains(trace):
            sig = tuple(trace[k]["fn"] for k in chain)
            if sig in seq_seen or len(seq_seen) >= MAX_SEQUENCE_CASES:
                continue
            stmt, layout, why = sequence_case(trace, chain, records, spare, api)
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


# --- struct layouts (clang's AST of the harness) ----------------------------------------------------

_CASE_LINE_RE = re.compile(r"\s*case (\d+)U: \{")
_ARRAY_RE = re.compile(r"^(?P<elem>.*\S)\s*\[(?P<n>\d+)\]$")
_POINTER_RE = re.compile(r"\*\s*(?:const|volatile|restrict|__restrict)?\s*$")
_RECORD_TYPE_RE = re.compile(r"^(struct|union|enum)\s+([A-Za-z_]\w*)$")
_UNSUPPORTED_ATTRS = {"PackedAttr", "AlignedAttr", "MaxFieldAlignmentAttr"}


def _walk_records(tree: dict) -> tuple[dict[str, dict], set[str]]:
    """Complete named struct/union definitions (`struct tag` -> AST node) and the declared function names."""
    records: dict[str, dict] = {}
    functions: set[str] = set()
    stack = [tree]
    while stack:
        node = stack.pop()
        kind = node.get("kind")
        if kind == "FunctionDecl":
            if isinstance(node.get("name"), str):
                functions.add(node["name"])
            continue  # bodies hold no type definitions the API uses
        if kind == "RecordDecl" and node.get("completeDefinition") and node.get("name"):
            records.setdefault(f"{node.get('tagUsed', 'struct')} {node['name']}", node)
        stack.extend(n for n in reversed(node.get("inner") or []) if isinstance(n, dict))
    return records, functions


def record_layouts(tree: dict) -> tuple[dict[str, dict], set[str]]:
    """
    The layouts of every complete named struct and union of a clang JSON AST (x86_64 sizes and
    alignments), and the functions it declares. A layout: {what, size, align, pointers, fields: [{name,
    kind (int, float, enum, ptr, fnptr, array, record), off, size, ctype?, const?, what?, pointers?, bools?}],
    bools?}; `bools` marks a record or member holding a `_Bool`.
    A record with a bit-field, a packed or aligned attribute, an anonymous member or a type the
    generator does not know has no layout.
    """
    raw, functions = _walk_records(tree)
    memo: dict[str, dict | None] = {}

    def type_info(t: str) -> dict | None:
        t = " ".join(t.split())
        if "unnamed" in t or "anonymous" in t:
            return {"kind": "enum", "size": 4, "align": 4, "pointers": False} if t.startswith("enum ") else None
        m = _ARRAY_RE.match(t)
        if m:
            elem = type_info(m.group("elem"))
            if elem is None:
                return None
            return {
                "kind": "array",
                "size": elem["size"] * int(m.group("n")),
                "align": elem["align"],
                "pointers": elem["pointers"],
                **({"bools": True} if elem.get("bools") else {}),
            }
        if "(" in t:
            if "(*)" not in t.replace(" ", ""):
                return None
            return {"kind": "fnptr", "size": POINTER_BYTES, "align": POINTER_BYTES, "pointers": True}
        if _POINTER_RE.search(t):
            base = t[: t.rfind("*")]
            return {
                "kind": "ptr",
                "size": POINTER_BYTES,
                "align": POINTER_BYTES,
                "pointers": True,
                "const": bool(re.search(r"\bconst\b", base)),
            }
        n = " ".join(_QUALIFIERS_RE.sub(" ", t).split())
        if n in SCALAR_BYTES:
            size = SCALAR_BYTES[n]
            kind = "float" if n in ("float", "double", "long double") else "int"
            info = {"kind": kind, "size": size, "align": size, "pointers": False, "ctype": n}
            return {**info, "bools": True} if n == "_Bool" else info
        m = _RECORD_TYPE_RE.match(n)
        if not m:
            return None
        if m.group(1) == "enum":
            return {"kind": "enum", "size": 4, "align": 4, "pointers": False}
        sub = layout(n)
        if sub is None:
            return None
        return {
            "kind": "record",
            "size": sub["size"],
            "align": sub["align"],
            "pointers": sub["pointers"],
            "what": sub["what"],
            "ctype": n,
            **({"bools": True} if sub.get("bools") else {}),
        }

    def layout(key: str) -> dict | None:
        if key in memo:
            return memo[key]
        memo[key] = None  # a record that contains itself by value is not C; no layout
        node = raw.get(key)
        if node is None:
            return None
        inner = [n for n in node.get("inner") or [] if isinstance(n, dict)]
        if any(n.get("kind") in _UNSUPPORTED_ATTRS for n in inner):
            return None
        what = str(node.get("tagUsed") or "struct")
        fields: list[dict] = []
        off = size = 0
        align = 1
        for f in inner:
            if f.get("kind") != "FieldDecl":
                continue
            ftype = f.get("type") or {}
            name = f.get("name")
            if f.get("isBitfield") or not name:
                return None
            info = type_info(str(ftype.get("desugaredQualType") or ftype.get("qualType") or ""))
            if info is None:
                return None
            a = int(info.pop("align"))
            align = max(align, a)
            here = 0 if what == "union" else (off + a - 1) // a * a
            fields.append({"name": name, "off": here, **info})
            off = here + info["size"]
            size = max(size, off)
        out = {
            "what": what,
            "size": (size + align - 1) // align * align,
            "align": align,
            "pointers": any(f["pointers"] for f in fields),
            "fields": fields,
        }
        if any(f.get("bools") for f in fields):
            out["bools"] = True  # a _Bool takes only 0 and 1: such a record is filled field by field
        memo[key] = out
        return out

    layouts = {k: lay for k in raw if (lay := layout(k)) is not None}
    return layouts, functions


def probe_layouts(
    harness_c: Path, cppflags: str, clang: str | None = None, runner: Callable[..., Any] = subprocess.run
) -> tuple[dict[str, dict], set[str]] | None:
    """
    The struct layouts and the functions declared where the harness is compiled: clang's JSON AST of a
    copy of the harness without its cases (they hold no definitions), with the harness's flags. None
    when clang is missing or its AST cannot be read.
    """
    import shlex

    from target_env import with_include_flags

    exe = clang or shutil.which("clang")
    if not exe:
        return None
    lines = harness_c.read_text(encoding="utf-8", errors="replace").splitlines()
    probe = harness_c.with_name(f".{harness_c.stem}.layout_probe.c")
    probe.write_text("\n".join("" if _CASE_LINE_RE.match(t) else t for t in lines) + "\n", encoding="utf-8")
    argv = [
        exe,
        "-fsyntax-only",
        "-w",
        "-x",
        "c",
        *shlex.split(with_include_flags(cppflags)),
        "-Xclang",
        "-ast-dump=json",
        str(probe),
    ]
    try:
        proc = runner(argv, capture_output=True, text=True, timeout=300, check=False)
        tree = json.loads(proc.stdout or "")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    finally:
        probe.unlink(missing_ok=True)
    return record_layouts(tree) if isinstance(tree, dict) else None


# --- the compile probe ------------------------------------------------------------------------------

_ERR_LINE_RE = re.compile(
    r"^(?P<file>[^:\n]+):(?P<line>\d+):(?P<col>\d+):\s+(?:fatal\s+)?error:\s*(?P<msg>[^\n]*)$", re.MULTILINE
)


def _no_error_limit(exe: str) -> str:
    """The option that lifts the compiler's error cap (clang stops at 20 errors, gcc has no cap by default)."""
    return "-ferror-limit=0" if "clang" in Path(exe).name else "-fmax-errors=0"


def probe_cases(harness_c: Path, cppflags: str, clang: str | None = None) -> tuple[dict[int, str], list[str]] | None:
    """
    Compile the harness once: (the dispatch cases the compiler refuses, each with the compiler's first
    error on its line (`file:line: error: message`, trimmed); the errors on no case line), or None when
    no compiler ran. Each case is one line of the harness, so an error maps to its case by line. A case
    the target's headers cannot spell (an incomplete struct, a function the headers do not declare) is
    dropped instead of failing the whole harness. The error cap is lifted: every failing case is found
    in one compile. The compiler gets the run snapshot's include options (scripts/target_env.py), so
    the headers the build generated are found as in every other compile.
    """
    import shlex

    from target_env import with_include_flags

    exe = clang or shutil.which("clang") or shutil.which("gcc")
    if not exe:
        return None
    argv = [
        exe,
        "-fsyntax-only",
        "-w",
        _no_error_limit(exe),
        "-x",
        "c",
        *shlex.split(with_include_flags(cppflags)),
        str(harness_c),
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode == 0:
        return {}, []
    lines = harness_c.read_text(encoding="utf-8", errors="replace").splitlines()
    case_of_line = {}
    for no, text in enumerate(lines, start=1):
        m = _CASE_LINE_RE.match(text)
        if m:
            case_of_line[no] = int(m.group(1))
    output = (proc.stdout or "") + (proc.stderr or "")
    bad: dict[int, str] = {}
    other: list[str] = []
    for m in _ERR_LINE_RE.finditer(output):
        line = int(m.group("line"))
        if Path(m.group("file")).name == harness_c.name and line in case_of_line:
            diag = f"{harness_c.name}:{line}: error: {m.group('msg').strip()}"
            if len(diag) > MAX_DIAGNOSTIC_CHARS:
                diag = diag[: MAX_DIAGNOSTIC_CHARS - 3] + "..."
            bad.setdefault(case_of_line[line], diag)
        else:
            other.append(m.group(0).strip())
    if not bad and not other:
        # A failed compile with no located error (a fatal one, a driver error): not a case's fault.
        other.append(output.strip().splitlines()[0] if output.strip() else f"exit code {proc.returncode}")
    return bad, other


def case_diagnostics(harness_c: Path, cppflags: str, clang: str | None = None) -> dict[int, str] | None:
    """The dispatch cases the compiler refuses with their first error (`probe_cases`), or None when none
    is refused or no compiler ran."""
    probed = probe_cases(harness_c, cppflags, clang)
    return probed[0] or None if probed is not None else None


def failing_cases(harness_c: Path, cppflags: str, clang: str | None = None) -> set[int] | None:
    """Selectors of the dispatch cases the compiler refuses (`case_diagnostics` without the messages)."""
    diags = case_diagnostics(harness_c, cppflags, clang)
    return None if diags is None else set(diags)


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
    scope_files: list[str] | None = None,
    struct_layouts: dict[str, dict] | None = None,
    visible: set[str] | None = None,
) -> dict[str, Any]:
    """
    Write harness_<module>.{c,json} for the module's whole API; the generate_harness result plus counts.
    `scope_files` (`--scope-file`) default to the previous sidecar's, and are kept in the new one.
    `struct_layouts`/`visible` replace the layout probe (`probe_layouts`), which runs with `probe`.
    """
    from generate_harness import (
        _norm_scope_files,
        generate_module_harness,
        harness_files_kept_on_failure,
        previous_scope_files,
        write_sidecar,
    )

    dag_file = dag_path or (out_dir.parent / "reports" / "callgraph_dag.json")
    dag = load_json_optional(dag_file, None)
    if not isinstance(dag, dict):
        raise ApiHarnessError(f"--api needs the DAG ({dag_file})")
    model = load_json_optional(model_path, None)
    if not isinstance(model, dict) or model.get("status") != "ok":
        raise ApiHarnessError(f"--api needs the Phase 0 model ({model_path})")
    previous = load_json_optional(out_dir / f"harness_{module}.json", {})
    scope = (
        _norm_scope_files(scope_files)
        if scope_files is not None
        else previous_scope_files(previous if isinstance(previous, dict) else {})
    )
    traces = load_traces(traces_path)
    p = plan(dag, model, module, unit, max_input_size, traces, scope, struct_layouts, visible)
    if not p["cases"]:
        raise ApiHarnessError(f"module {module!r}: no API entry point the generator can call: {p['skipped']}")
    functions = dag.get("functions") or {}
    dag_mod = (dag.get("modules") or {}).get(module) or {}
    req_sources = dag_mod.get("required_sources") or []
    sources = sorted(
        {str((functions.get(k) or {}).get("file")) for k in p["entries"] if (functions.get(k) or {}).get("file")}
        | {str(s) for s in req_sources if s}
    )
    first = str((functions.get(p["entries"][0]) or {}).get("name") or p["entries"][0].split("#")[-1])
    cases, layouts, skipped = list(p["cases"]), list(p["layouts"]), dict(p["skipped"])
    result: dict[str, Any] = {}
    # Struct layouts come from the first harness written (its headers and prelude): the cases are
    # planned again with them before the compile probe. Each later round drops at least one case, so
    # the loop ends; the harness is written again after every drop, so the one left on disk is the one
    # whose cases the sidecar lists. Failed generation leaves the previous harness files as they were
    # (generate_harness.harness_files_kept_on_failure).
    need_layouts = probe and struct_layouts is None
    with harness_files_kept_on_failure(out_dir, module):
        while True:
            # While the probe drops cases, a compile error is the probe's to judge; without the
            # probe, generate_module_harness fails on it itself.
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
                scope_files=scope,
                fail_on_compile_error=not probe,
            )
            if not probe:
                break
            if need_layouts:
                need_layouts = False
                layouts_probed = probe_layouts(Path(result["harness_file"]), result["cppflags"])
                if layouts_probed is not None:
                    p = plan(dag, model, module, unit, max_input_size, traces, scope, *layouts_probed)
                    if p["cases"]:
                        cases, layouts, skipped = list(p["cases"]), list(p["layouts"]), dict(p["skipped"])
                        continue
            probed = probe_cases(Path(result["harness_file"]), result["cppflags"])
            if probed is None:
                break  # no compiler: the cases stay unchecked
            bad, other = probed
            if other:
                raise ApiHarnessError(
                    f"module {module!r}: the harness does not compile outside its cases: {'; '.join(other[:3])}"
                )
            if not bad:
                break
            keep = [i for i in range(len(cases)) if i not in bad]
            for i, diag in sorted(bad.items()):
                if layouts[i].get("entry"):
                    skipped[layouts[i]["entry"]] = f"the case does not compile with the target's headers: {diag}"
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
        write_sidecar(sidecar_path, sidecar)
    result.update(
        api_cases=len(layouts),
        api_entries=sum(1 for lay in layouts if lay.get("entry")),
        api_sequences=sum(1 for lay in layouts if lay["kind"] == "sequence"),
        api_skipped=skipped,
    )
    return result
