"""Frame skeleton: every clause it requires is one a function contract can state.

The fixtures under tests/fixtures/libmodbus_run1_frame/ are copied from libmodbus run-1 (2026-11-18) by a
script, not retyped: `facts_records.json` holds facts records of that run (each with the skeleton the run
computed), the `.patch` and `.txt` files hold the contracts the provers delivered and the merge refused,
and `kernel_forms/` holds a small C file with one frame clause form per function and the answer of the
Frama-C kernel of the analysis image (`clause_forms.log`).
"""

from __future__ import annotations

import json
import re
import subprocess

import pytest

import frame_skeleton as fs
import function_facts as ff
from acsl_ast import check_frame_preserved, tokenize_c_acsl
from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images
from test_frame_skeleton import _copy_loop_record, _parse_value_record

RUN1_FRAME = ROOT / "tests" / "fixtures" / "libmodbus_run1_frame"
TCP_REQUEST = "src/modbus-tcp.c#_modbus_tcp_build_request_basis"
SET_BITS = "src/modbus-data.c#modbus_set_bits_from_bytes"
SET_BITS_BYTE = "src/modbus-data.c#modbus_set_bits_from_byte"
READ_REGISTERS = "src/modbus.c#read_registers"
RTU_SEND_PRE = "src/modbus-rtu.c#_modbus_rtu_send_msg_pre"
ENABLE_QUIRKS = "src/modbus.h#modbus_enable_quirks"
RAW_REQUEST = "src/modbus.h#modbus_send_raw_request_tid"
RTU_RESPONSE = "src/modbus-rtu.c#_modbus_rtu_build_response_basis"
SET_FLOAT = "src/modbus-data.c#modbus_set_float"
GET_FLOAT_ABCD = "src/modbus-data.c#modbus_get_float_abcd"


def _run1() -> dict:
    return json.loads((RUN1_FRAME / "facts_records.json").read_text(encoding="utf-8"))


def _recorded(key: str) -> dict:
    """The skeleton the run computed (the code before the fix)."""
    return _run1()["functions"][key]["frame_skeleton"]


def _skeleton(key: str) -> dict:
    """The skeleton of a recorded function, computed as function_facts does it for a module."""
    doc = _run1()
    record = {k: v for k, v in doc["functions"][key].items() if k != "frame_skeleton"}
    if record.get("calls"):
        return fs.compute(record, write_free_callees=set(doc["write_free_callees"]))
    return fs.compute(record)


def _acsl(text: str) -> str:
    """The annotation text the merge check reads (workspace_overlay._acsl_text_of_span)."""
    tokens = tokenize_c_acsl(text, path="fixture")
    return "\n".join(t.text for t in tokens if t.kind in ("acsl_block", "acsl_line"))


def _patched(name: str) -> str:
    """The lines a recorded patch leaves in the file (context and added lines)."""
    lines = (RUN1_FRAME / name).read_text(encoding="utf-8").splitlines()
    return "\n".join(line[1:] for line in lines if line[:1] in ("+", " ") and not line.startswith("+++"))


def _text(name: str) -> str:
    return (RUN1_FRAME / name).read_text(encoding="utf-8")


def _without(acsl: str, fragment: str) -> str:
    """`acsl` less the one line holding `fragment`."""
    lines = acsl.splitlines()
    hits = [line for line in lines if fragment in line]
    assert len(hits) == 1, (fragment, hits)
    return "\n".join(line for line in lines if fragment not in line)


def _clauses(skel: dict) -> list[str]:
    return [s["clause"] for s in skel["separated"]] + [a["clause"] for a in skel["assigns"]]


def _by_loc(skel: dict) -> dict[str, dict]:
    return {a["loc"]: a for a in skel["assigns"]}


TCP_CONTRACT = "prove-2_modbus_tcp_build_request_basis.patch"


# ---------------------------------------------------------------------------
# Bug A: a write through a local alias of a formal (`ctx_tcp->t_id`)
# ---------------------------------------------------------------------------


def test_the_recorded_skeleton_refused_the_provers_contract_over_the_local_alias() -> None:
    # What run-1 did: the skeleton names the local `ctx_tcp`, the contract cannot.
    errors = check_frame_preserved(_recorded(TCP_REQUEST), _acsl(_patched(TCP_CONTRACT)), path="src/modbus-tcp.c")
    assert len(errors) == 1
    assert "projected frame clause missing or weakened: 'assigns ctx_tcp->t_id \\\\from \\\\nothing;'" in errors[0]


def test_a_write_through_a_local_alias_is_not_required_but_recorded() -> None:
    skel = _skeleton(TCP_REQUEST)
    assert not any("ctx_tcp" in clause for clause in _clauses(skel))
    assert skel["unprojected"] == [
        {
            "lval": "ctx_tcp->t_id",
            "root": "ctx",
            "line": 114,
            "reason": "`ctx_tcp` is a local pointer derived from `ctx`, and the facts do not record "
            "the expression it holds",
        }
    ]
    assert skel["status"] == "partial"
    hint = [n for n in skel["notes"] if "`ctx_tcp->t_id`" in n]
    assert len(hint) == 1 and hint[0].startswith("not required, so the minimum is incomplete here")


def test_the_provers_contract_for_the_tcp_request_passes_the_merge_check() -> None:
    assert check_frame_preserved(_skeleton(TCP_REQUEST), _acsl(_patched(TCP_CONTRACT))) == []


@pytest.mark.parametrize(
    ("dropped", "named"),
    [
        ("\\separated(ctx, req + (0 .. 11))", "no \\separated clause over roots ['ctx', 'req']"),
        ("assigns *(req + 7) \\from function;", "covering location '*(req + 7)'"),
        ("assigns *(req + 0) \\from \\nothing;", "covering location '*(req + 0)'"),
        ("assigns *(req + 11) \\from nb;", "covering location '*(req + 11)'"),
    ],
)
def test_the_tcp_request_contract_is_still_refused_without_a_projected_clause(dropped: str, named: str) -> None:
    # Control: writes through the formal `req` stay required, with the pair that must be separated.
    errors = check_frame_preserved(_skeleton(TCP_REQUEST), _without(_acsl(_patched(TCP_CONTRACT)), dropped))
    assert len([e for e in errors if "projected frame clause missing or weakened" in e and named in e]) == 1


def test_a_weakened_from_is_still_refused_where_the_facts_give_the_dependency() -> None:
    acsl = _acsl(_patched(TCP_CONTRACT))
    assert "assigns *(req + 7) \\from function;" in acsl
    weakened = acsl.replace("assigns *(req + 7) \\from function;", "assigns *(req + 7) \\from \\nothing;")
    errors = check_frame_preserved(_skeleton(TCP_REQUEST), weakened)
    assert len([e for e in errors if "'assigns *(req + 7) \\\\from function;'" in e]) == 1


def test_no_from_is_projected_for_a_value_read_through_the_alias() -> None:
    # req[0] and req[1] hold bits of ctx_tcp->t_id: run-1 projected `\from \nothing` and the provers
    # copied it. req[2] is a constant and req[7] is `function`: those stay as they were.
    by_loc = _by_loc(_skeleton(TCP_REQUEST))
    for loc in ("*(req + 0)", "*(req + 1)"):
        assert by_loc[loc] == {
            "loc": loc,
            "from": [],
            "clause": f"assigns {loc};",
            "source": "ast",
            "from_unknown": True,
        }
    assert by_loc["*(req + 2)"] == _by_loc(_recorded(TCP_REQUEST))["*(req + 2)"]
    assert by_loc["*(req + 2)"]["clause"] == "assigns *(req + 2) \\from \\nothing;"
    assert by_loc["*(req + 7)"] == _by_loc(_recorded(TCP_REQUEST))["*(req + 7)"]
    assert by_loc["*(req + 7)"]["clause"] == "assigns *(req + 7) \\from function;"


def test_a_clause_without_from_is_covered_by_any_clause_listing_the_location() -> None:
    # How acsl_ast.check_frame_preserved reads `"from": []`: the location is required, a `\from` is not.
    skel = {"status": "partial", "separated": [], "assigns": [_by_loc(_skeleton(TCP_REQUEST))["*(req + 0)"]]}
    assert check_frame_preserved(skel, "assigns *(req + 0);") == []
    assert check_frame_preserved(skel, "assigns *(req + 0) \\from ctx->backend_data;") == []
    assert check_frame_preserved(skel, "assigns *(req + 0) \\from \\nothing;") == []
    assert check_frame_preserved(skel, "assigns *(req + 1);") != []


# ---------------------------------------------------------------------------
# Bug B: a write through a loop index (`*(dest + i)`), with a `\from` the facts do not support
# ---------------------------------------------------------------------------


def _negotiated_set_bits() -> str:
    return (
        _acsl(_text("negotiate_modbus_set_bits_from_bytes.modbus.h.txt"))
        + "\n"
        + _acsl(_text("negotiate_modbus_set_bits_from_bytes.modbus-data.c.txt"))
    )


def test_the_recorded_skeleton_refused_the_negotiated_contract_over_the_loop_index() -> None:
    errors = check_frame_preserved(_recorded(SET_BITS), _negotiated_set_bits(), path="src/modbus-data.c")
    assert len(errors) == 1 and "'assigns *(dest + i) \\\\from idx, nb_bits;'" in errors[0]


def test_a_write_through_an_unbounded_loop_index_is_not_required_but_recorded() -> None:
    skel = _skeleton(SET_BITS)
    # The guard bound `(unsigned int)idx + nb_bits` and the start `i = idx` are not a literal or one
    # name: no range is stated, no clause names `i`, and `tab_byte` is not left out of a `\from`.
    assert skel["assigns"] == []
    assert _clauses(skel) == ["requires \\separated(dest, tab_byte);"]
    assert skel["unprojected"] == [
        {
            "lval": "*(dest + i)",
            "root": "dest",
            "line": 52,
            "reason": "`i` is a loop variable, and the facts give no bounds for it that hold at entry",
            "loop": {
                "line": 51,
                "header": "for (i = idx; i < idx + nb_bits; i++)",
                "guard": "i < (unsigned int)idx + nb_bits",
            },
        }
    ]
    assert skel["status"] == "partial"
    assert any(n.startswith("no `assigns \\nothing` projected: the function writes") for n in skel["notes"])
    assert not any("kept as written" in n for n in skel["notes"])


def test_the_negotiated_contract_for_set_bits_passes_the_merge_check() -> None:
    assert check_frame_preserved(_skeleton(SET_BITS), _negotiated_set_bits()) == []


def test_the_set_bits_contract_is_still_refused_without_the_separation() -> None:
    weakened = _without(_negotiated_set_bits(), "\\separated(dest, tab_byte)")
    errors = check_frame_preserved(_skeleton(SET_BITS), weakened)
    assert len([e for e in errors if "no \\separated clause over roots ['dest', 'tab_byte']" in e]) == 1


def test_an_index_added_to_a_formal_is_not_required_either() -> None:
    # `*(dest + (idx + i))` in `for (i = 0; i < 8; i++)`: the offset is not the index alone.
    skel = _skeleton(SET_BITS_BYTE)
    assert skel["assigns"] == []
    assert [u["lval"] for u in skel["unprojected"]] == ["*(dest + (idx + i))"]


def test_a_range_bounded_by_a_local_is_not_required() -> None:
    # run-1 projected `assigns dest + (0 .. rc - 1)`: `rc` is a local of read_registers.
    assert "assigns dest + (0 .. rc - 1) \\from \\nothing;" in _clauses(_recorded(READ_REGISTERS))
    skel = _skeleton(READ_REGISTERS)
    assert [a["loc"] for a in skel["assigns"]] == ["errno"]
    assert [(u["lval"], u["loop"]["guard"]) for u in skel["unprojected"]] == [("*(dest + i)", "i < rc")]


def test_a_location_the_kernel_names_through_a_temporary_is_not_required() -> None:
    # run-1 projected `assigns req \from \nothing;`: the formal itself, for a write to `req[req_length++]`.
    assert _clauses(_recorded(RTU_SEND_PRE)) == ["assigns req \\from \\nothing;"]
    skel = _skeleton(RTU_SEND_PRE)
    assert skel["assigns"] == []
    assert [(u["lval"], u["root"]) for u in skel["unprojected"]] == [(None, "req")]
    assert "through a temporary" in skel["unprojected"][0]["reason"]


def test_no_from_is_projected_for_a_value_that_reads_the_written_object() -> None:
    # `ctx->quirks |= quirks_mask`: run-1 projected `\from quirks_mask`, without the old value.
    assert "assigns ctx->quirks \\from quirks_mask;" in _clauses(_recorded(ENABLE_QUIRKS))
    entry = _by_loc(_skeleton(ENABLE_QUIRKS))["ctx->quirks"]
    assert entry["clause"] == "assigns ctx->quirks;" and entry["from"] == [] and entry["from_unknown"] is True


def test_a_window_after_from_is_the_cells_not_the_addresses() -> None:
    old = "assigns errno \\from ctx, raw_req + (0 .. 1), raw_req_length;"
    new = "assigns errno \\from *(raw_req + (0 .. 1)), ctx, raw_req_length;"
    assert _clauses(_recorded(RAW_REQUEST)) == [old]
    assert _clauses(_skeleton(RAW_REQUEST)) == [new]


def _locals_of(record: dict) -> set[str]:
    names = set(record.get("derived_pointers") or {})
    for loop in record.get("loops") or []:
        names |= {s["var"] for s in loop.get("scalars") or []}
    return names - {f["name"] for f in record.get("formals") or []}


def test_no_required_clause_of_a_recorded_function_names_a_local() -> None:
    doc = _run1()
    named_by_run1 = []
    for key, record in doc["functions"].items():
        for name in sorted(_locals_of(record) | {"rc"}):
            word = re.compile(rf"(?<![\w>.]){re.escape(name)}\b")
            assert not [c for c in _clauses(_skeleton(key)) if word.search(c)], (key, name)
            named_by_run1 += [c for c in _clauses(record["frame_skeleton"]) if word.search(c)]
    # The same scan on the skeletons the run computed finds the clauses of both bug entries.
    assert "assigns ctx_tcp->t_id \\from \\nothing;" in named_by_run1
    assert "assigns *(dest + i) \\from idx, nb_bits;" in named_by_run1


# ---------------------------------------------------------------------------
# The forms the kernel accepts (tests/fixtures/libmodbus_run1_frame/kernel_forms)
# ---------------------------------------------------------------------------

_REFUSED_RE = re.compile(r"Ignoring logic specification of function (\w+)")
_REFUSED_FORMS = {
    "refused_address_set_in_assigns": "not an assignable left value: dst + (0 .. n - 1)",
    "refused_address_set_after_from": "not a valid dependency: buf + (0 .. 1)",
    "refused_loop_index": "unbound logic variable i",
    "refused_local_alias": "unbound logic variable ctx_tcp",
}


def _contract_of(program: str, function: str) -> str:
    """The contract comment right before `function` in the clause-forms program."""
    head = program[: program.index(f"void {function}(")]
    return " ".join(head[head.rindex("/*@") :].split())


def test_the_kernel_log_refuses_the_old_forms_and_only_those() -> None:
    log = _text("kernel_forms/clause_forms.log")
    assert set(_REFUSED_RE.findall(log)) == set(_REFUSED_FORMS)
    flat = " ".join(log.split())
    for function, message in _REFUSED_FORMS.items():
        assert f"{message}. Ignoring logic specification of function {function}" in flat


def test_the_projected_range_and_window_are_forms_the_kernel_accepted() -> None:
    program = _text("kernel_forms/clause_forms.c")
    copy = fs.compute(_copy_loop_record())
    accepted = _contract_of(program, "accepted_copy_loop")
    assert copy["separated"][0]["clause"] in accepted
    assert _by_loc(copy)["*(dst + (0 .. n - 1))"]["clause"] in accepted
    parse = fs.compute(_parse_value_record())
    accepted = _contract_of(program, "accepted_parse_value")
    assert [c for c in _clauses(parse) if c not in accepted] == []
    # A location-only clause, and the two contracts the provers wrote for the recorded functions.
    assert "assigns *(req + 0);" in _contract_of(program, "accepted_location_without_from")
    assert "accepted_alias_over_the_formal" in program and "accepted_range_over_the_formals" in program


def test_the_kernel_of_the_analysis_image_still_answers_as_recorded() -> None:
    require_docker_images(ANALYSIS_IMAGE)
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none",
         "-v", f"{RUN1_FRAME / 'kernel_forms'}:/probe:ro",
         "--entrypoint", "timeout", ANALYSIS_IMAGE,
         "120", "frama-c", "-kernel-warn-key", "annot-error=active", "/probe/clause_forms.c"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert set(_REFUSED_RE.findall(proc.stdout + proc.stderr)) == set(_REFUSED_FORMS)


# ---------------------------------------------------------------------------
# Controls: where the skeleton was right it is as strict as before
# ---------------------------------------------------------------------------


def _as_recorded(skel: dict) -> dict:
    """The skeleton less the key the fix added, to compare with what the run computed."""
    assert skel.get("unprojected", []) == []
    return {k: v for k, v in skel.items() if k != "unprojected"}


def test_writes_through_a_formal_pointer_are_projected_as_before() -> None:
    skel = _skeleton(RTU_RESPONSE)
    assert _as_recorded(skel) == _recorded(RTU_RESPONSE)
    assert _clauses(skel) == [
        "requires \\separated(rsp + (0 .. 1), sft);",
        "assigns *(rsp + 0) \\from sft;",
        "assigns *(rsp + 1) \\from sft;",
    ]
    merged = _acsl(_text("merged_modbus_rtu_build_response_basis.modbus-rtu.c.txt"))
    assert check_frame_preserved(skel, merged) == []
    for dropped in ("\\separated(rsp + (0 .. 1), sft)", "assigns *(rsp + 1) \\from sft;"):
        assert len(check_frame_preserved(skel, _without(merged, dropped))) == 1


def test_the_aliased_call_case_is_still_refused_at_merge() -> None:
    # parse_value(buf, 2, &buf[1]): a contract without the separation proves under WP and is unsound.
    skel = fs.compute(_parse_value_record())
    assert skel["status"] == "ok" and skel.get("unprojected", []) == []
    verbatim = "\n".join(_clauses(skel))
    assert check_frame_preserved(skel, verbatim) == []
    no_separation = "requires \\valid(eaten);\n" + skel["assigns"][0]["clause"]
    errors = check_frame_preserved(skel, no_separation)
    assert len(errors) == 1 and "no \\separated clause over roots ['buf', 'eaten']" in errors[0]
    assert len(check_frame_preserved(skel, "requires \\separated(buf + (0 .. 1), eaten);")) == 1


@pytest.mark.parametrize(("key", "callee"), [(SET_FLOAT, "modbus_set_float_cdab"), (GET_FLOAT_ABCD, "memcpy")])
def test_a_wrapper_whose_writes_happen_in_callees_gets_no_assigns_nothing(key: str, callee: str) -> None:
    skel = _skeleton(key)
    assert _as_recorded(skel) == _recorded(key)
    assert skel["assigns"] == [] and skel["status"] == "partial"
    assert any(n.startswith("no `assigns \\nothing` projected") and f"`{callee}`" in n for n in skel["notes"])


def test_the_skeleton_keeps_its_keys_and_adds_one() -> None:
    for key in _run1()["functions"]:
        skel = _skeleton(key)
        assert list(skel) == ["status", "separated", "assigns", "unprojected", "notes"]
        for entry in skel["assigns"]:
            assert set(entry) - {"from_unknown"} == {"loc", "from", "clause", "source"}
            if "from_unknown" in entry:
                assert entry["from"] == [] and entry["clause"] == f"assigns {entry['loc']};"
            else:
                assert "\\from" in entry["clause"] or entry["loc"] == "\\nothing"
        for item in skel["unprojected"]:
            assert set(item) - {"loop"} == {"lval", "root", "line", "reason"}


def test_the_brief_shows_an_unprojected_write_as_a_note_not_as_a_clause() -> None:
    record = dict(_run1()["functions"][TCP_REQUEST])
    record["frame_skeleton"] = _skeleton(TCP_REQUEST)
    section = ff.render_section(record, function="_modbus_tcp_build_request_basis")
    assert "`assigns ctx_tcp->t_id" not in section
    assert "- `assigns *(req + 7) \\from function;`" in section
    assert "- `assigns *(req + 0);`" in section
    assert "- note: not required, so the minimum is incomplete here: the write to `ctx_tcp->t_id`" in section
    record = dict(_run1()["functions"][SET_BITS])
    record["frame_skeleton"] = _skeleton(SET_BITS)
    section = ff.render_section(record, function="modbus_set_bits_from_bytes")
    assert "`assigns *(dest + i)" not in section
    assert "- `requires \\separated(dest, tab_byte);`" in section
    assert "- note: not required, so the minimum is incomplete here: the write to `*(dest + i)`" in section


# ---------------------------------------------------------------------------
# The parts: names an expression depends on, loop bounds stated at entry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("expr", "names"),
    [
        # Kernel-printed expressions of the recorded functions.
        ("(uint8_t)((int)ctx_tcp->t_id >> 8)", ["ctx_tcp"]),
        ("(uint16_t)((int)ctx_tcp->t_id + 1)", ["ctx_tcp"]),
        ("(uint8_t)(addr & 0x00ff)", ["addr"]),
        ("(uint8_t)ctx->slave", ["ctx"]),
        ("*(tab_byte + (i - (unsigned int)idx) / (unsigned int)8)", ["tab_byte", "i", "idx"]),
        ("i + 1U", ["i"]),
        ("*(dest + (0 .. n - 1))", ["dest", "n"]),
        ("((modbus_tcp_t *)ctx->backend_data)->t_id", ["ctx"]),
        ("mb_mapping->tab_bits[a.b]", ["mb_mapping", "a"]),
        # Not a cast: a parenthesised operand or an argument list keeps its name.
        ("(a) * b", ["a", "b"]),
        ("f(x)", ["f", "x"]),
        ("sizeof(int)", ["sizeof", "int"]),
    ],
)
def test_the_names_an_expression_depends_on(expr: str, names: list[str]) -> None:
    assert fs._free_names(expr) == names


def _counted_loop(header: str | None, guard: str = "i < n", updates: tuple[str, ...] = ("i + 1",)) -> dict:
    loop = {
        "index": 0,
        "guard": guard,
        "scalars": [{"var": "i", "updates": list(updates)}],
        "memory_writes": [{"lval": "*(a + i)", "root": "a", "root_kind": "formal", "values": ["0"]}],
        "reads": [],
    }
    if header is not None:
        loop["header"] = header
    return {
        "formals": [{"name": "a", "kind": "pointer"}, {"name": "n", "kind": "scalar"}, {"name": "k", "kind": "scalar"}],
        "writes": [{"lval": "*(a + i)", "root": "a", "root_kind": "formal", "through_pointer": True, "line": 3}],
        "reads": [],
        "loops": [loop],
    }


@pytest.mark.parametrize(
    ("record", "loc"),
    [
        (_counted_loop("for (i = 0; i < n; i++)"), "*(a + (0 .. n - 1))"),
        (_counted_loop("for (int i = 2; i < n; i++)"), "*(a + (2 .. n - 1))"),
        (_counted_loop("for (i = 0, j = n; i < 16U; i++)", guard="i < 16U"), "*(a + (0 .. 16U - 1))"),
        (_counted_loop("for (i = 0; i < n; i += 2)", updates=("(uint16_t)((int)i + 2)",)), "*(a + (0 .. n - 1))"),
        # The start is not a literal, is unknown, or the index does not only count up: no range.
        (_counted_loop("for (i = k; i < n; i++)"), None),
        (_counted_loop("while (i < n)"), None),
        (_counted_loop(""), None),
        (_counted_loop(None), None),
        (_counted_loop("for (i = 0; i < n; i++)", updates=("i + 1", "i - 1")), None),
        (_counted_loop("for (i = 0; i < n; i++)", updates=("i * 2",)), None),
        # The bound is a local.
        (_counted_loop("for (i = 0; i < len; i++)", guard="i < len"), None),
    ],
)
def test_a_range_is_projected_only_with_both_bounds_stated_at_entry(record: dict, loc: str | None) -> None:
    skel = fs.compute(record)
    if loc is None:
        assert skel["assigns"] == []
        assert [u["lval"] for u in skel["unprojected"]] == ["*(a + i)"]
    else:
        assert [a["loc"] for a in skel["assigns"]] == [loc] and skel["unprojected"] == []


def test_a_bound_the_loop_changes_is_not_an_entry_bound() -> None:
    record = _counted_loop("for (i = 0; i < n; i++)")
    record["loops"][0]["scalars"].append({"var": "n", "updates": ["n - 1"]})
    skel = fs.compute(record)
    assert skel["assigns"] == [] and [u["lval"] for u in skel["unprojected"]] == ["*(a + i)"]


def test_a_write_through_a_walked_formal_is_not_required() -> None:
    # `while (n--) *p++ = 0;`: `*p` at the write is not `*p` at entry.
    record = {
        "formals": [{"name": "p", "kind": "pointer"}, {"name": "n", "kind": "scalar"}],
        "writes": [{"lval": "*p", "root": "p", "root_kind": "formal", "through_pointer": True, "line": 2}],
        "reads": [],
        "loops": [
            {
                "index": 0,
                "header": "while (n--)",
                "guard": None,
                "scalars": [{"var": "p", "updates": ["p + 1"]}, {"var": "n", "updates": ["n - 1"]}],
                "memory_writes": [{"lval": "*p", "root": "p", "root_kind": "formal", "values": ["(char)0"]}],
                "reads": [],
            }
        ],
    }
    skel = fs.compute(record)
    assert skel["assigns"] == []
    assert skel["unprojected"][0]["reason"] == (
        "`p` is changed by a loop, so it no longer holds its entry value at the write"
    )
