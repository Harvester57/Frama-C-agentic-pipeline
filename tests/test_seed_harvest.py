"""Tests for seed inputs recorded from the target's tests (scripts/seed_harvest.py, step I6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import seed_harvest as sh
from generate_harness import _build_dispatch_invocation

pytestmark = pytest.mark.unit

HARNESS_TEMPLATE = """\
int eva_main(void) {{ /* Invoke target module entry point */ {eva} return 0; }}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    uint8_t *fuzz_buf = bounded_buf;
    size_t fuzz_len = size;
    /* Invoke target module entry point */
    {fuzz}
    free(alloc_ptr);
    return 0;
}}
"""


def _harness(stmt: str) -> str:
    return HARNESS_TEMPLATE.format(eva="(void)0;", fuzz=stmt)


# --- signatures and the recorder -------------------------------------------------------------------


def test_split_signature():
    assert sh.split_signature("int(char *,_Bool)") == ("int", ["char *", "_Bool"], False)
    assert sh.split_signature("void()") == ("void", [], False)
    assert sh.split_signature("int(void)") == ("int", [], False)
    assert sh.split_signature("int(char *, ...)") == ("int", ["char *"], True)
    assert sh.split_signature("int(void (*)(int),int)") == ("int", ["void (*)(int)", "int"], False)
    assert sh.split_signature("void (*(int))(int)") is None


def test_plan_function_kinds():
    p = sh.plan_function("kv", "int(unsigned int,unsigned char *,unsigned long)")
    assert p["supported"]
    assert [x["record"] for x in p["params"]] == ["i", "b", "i"]
    p = sh.plan_function("parse", "_Bool(struct minmea_sentence_rmc *,char *)")
    assert [x["record"] for x in p["params"]] == [None, "s"]
    assert p["ret"]["ctype"] == "_Bool"
    p = sh.plan_function("init", "void(struct ctx *,struct q_useful_buf_c,enum __anonenum_Mode_7)")
    assert [x["record"] for x in p["params"]] == [None, "t", "i"]
    assert p["params"][2]["ctype"] == "int"
    assert p["structs"] == ["struct q_useful_buf_c"]
    p = sh.plan_function("get", "void(long *,double *)")
    assert [x["record"] for x in p["params"]] == ["p", "p"]
    assert not sh.plan_function("v", "int(char *, ...)")["supported"]
    assert not sh.plan_function("a", "void(struct __anonstruct_x_1)")["supported"]
    assert not sh.plan_function("t", "void(myopaque_t)")["supported"]
    assert sh.plan_function("u", "unsigned long(uint8_t *,size_t)")["params"][0]["record"] == "b"


def test_wrapper_source_records_outermost_calls():
    plans = [
        sh.plan_function("kv", "int(unsigned int,unsigned char *,unsigned long)"),
        sh.plan_function("init", "void(struct ctx *,struct buf)"),
    ]
    src = sh.wrapper_source(plans, ["/t/inc/buf.h"])
    assert '#include "/t/inc/buf.h"' in src
    assert "extern int __real_kv(unsigned int a0, void * a1, unsigned long a2);" in src
    assert "fc_mem(1, 'b', a1, (size_t)a2);" in src
    assert "fc_struct(1, &a1, sizeof a1);" in src
    assert "if (fc_enter(1))" in src
    assert "__real_init(a0, a1);\n    fc_leave();" in src
    rt = sh.runtime_source(2)
    assert "FC_OUT_DIR" in rt and "__real_" not in rt


def test_parse_record_line():
    rec = sh.parse_record_line("kv 0i=05000000 1b=6162 2i=0200000000000000 3s=- 4n8=ff")
    assert rec == {
        "fn": "kv",
        "args": {
            "0": [["i", 0, "05000000"]],
            "1": [["b", 0, "6162"]],
            "2": [["i", 0, "0200000000000000"]],
            "4": [["n", 8, "ff"]],
        },
    }
    assert sh.parse_record_line("not a record!") is None
    assert sh.parse_record_line("kv 0q") is None


def test_struct_headers(tmp_path):
    (tmp_path / "inc").mkdir()
    (tmp_path / "inc" / "a.h").write_text("typedef struct q_buf { const void *ptr; size_t len; } QBuf;\n")
    (tmp_path / "inc" / "b.h").write_text("struct other;\n")
    found = sh.struct_headers({"struct q_buf", "struct other"}, sh._header_index(tmp_path))
    assert found == {"struct q_buf": tmp_path / "inc" / "a.h"}


def test_plan_recorder_skips_main_static_and_unsupported():
    model = {
        "entry_points": ["a.c#main", "a.c#ok", "a.c#var", "h.h#inl"],
        "functions": {
            "a.c#main": {"name": "main", "signature": "int()"},
            "a.c#ok": {"name": "ok", "signature": "int(char *)"},
            "a.c#var": {"name": "var", "signature": "int(char *, ...)"},
            "h.h#inl": {"name": "inl", "signature": "int(int)", "inline": True, "header": True},
        },
    }
    plans, skipped = sh.plan_recorder(model)
    assert [p["name"] for p in plans] == ["ok"]
    assert skipped == {"var": "variadic", "inl": "static or header inline: not a linked symbol"}


def test_plan_recorder_records_an_executables_embedded_api():
    # tweetnacl's shape: the library is compiled straight into the executable, whose only export
    # is main; its API is the unit's embedded_api, which the recorder must wrap too.
    model = {
        "entry_points": ["main.c#main"],
        "units": {
            "main": {"kind": "executable", "test": False, "embedded_api": ["nacl.c#crypto_box"]},
            "t": {"kind": "executable", "test": True, "embedded_api": ["t.c#helper"]},
        },
        "functions": {
            "main.c#main": {"name": "main", "signature": "int()"},
            "nacl.c#crypto_box": {"name": "crypto_box", "signature": "int(char *, int)"},
            "t.c#helper": {"name": "helper", "signature": "int(char *)"},
        },
    }
    plans, _ = sh.plan_recorder(model)
    assert [p["name"] for p in plans] == ["crypto_box"]


def test_strace_opened_and_data_files(tmp_path):
    tree = tmp_path / "tree"
    (tree / "tests" / "data").mkdir(parents=True)
    (tree / "tests" / "data" / "frame.bin").write_bytes(b"\x01\x02")
    (tree / "src.c").write_text("int x;")
    (tree / "exe").write_bytes(b"\x7fELF....")
    (tree / "empty.bin").write_bytes(b"")
    log = "\n".join(
        [
            f'12 openat(AT_FDCWD<{tree}>, "tests/data/frame.bin", O_RDONLY) = 3<{tree}/tests/data/frame.bin>',
            f'12 openat(AT_FDCWD<{tree}>, "out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4<{tree}/out.txt>',
            f'12 openat(AT_FDCWD, "{tree}/src.c", O_RDONLY|O_CLOEXEC) = 5<{tree}/src.c>',
            '12 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 6</etc/passwd>',
            f'12 openat(AT_FDCWD, "{tree}/missing", O_RDONLY) = -1 ENOENT (No such file or directory)',
            f'13 openat(AT_FDCWD, "{tree}/exe", O_RDONLY) = 7<{tree}/exe>',
            f'13 openat(AT_FDCWD, "{tree}/tests/data/frame.bin", O_RDONLY) = 3<{tree}/tests/data/frame.bin>',
        ]
    )
    opened = sh.strace_opened(log, tree)
    assert [Path(p).name for p in opened] == ["frame.bin", "src.c", "exe"]
    assert [Path(p).name for p in opened if sh.is_data_file(Path(p), tree)] == ["frame.bin"]


# --- harness case formats ------------------------------------------------------------------------


def test_dispatch_cases_slots_and_data():
    stmt = _build_dispatch_invocation(
        [
            "(void)kv_count();",
            "char s0[1501]; size_t n0 = fuzz_len < 1500 ? fuzz_len : 1500; memcpy(s0, fuzz_buf, n0); s0[n0] = 0; (void)kv_find(s0);",
            "unsigned a0 = 0; if (fuzz_len >= sizeof a0) { memcpy(&a0, fuzz_buf, sizeof a0); fuzz_buf += sizeof a0; "
            "fuzz_len -= sizeof a0; } (void)kv_key_equals(a0, (const uint8_t *)fuzz_buf, (size_t)fuzz_len);",
        ]
    )
    cases = sh.harness_cases(_harness(stmt))
    assert [sel for sel, _ in cases] == [0, 1, 2]
    fns = {"kv_count", "kv_find", "kv_key_equals"}
    b = [sh.case_bindings(s, fns) for _, s in cases]
    assert b[0] == {"slots": [], "calls": []}
    assert b[1]["calls"] == [{"fn": "kv_find", "binds": {0: ("data", "s0")}}]
    assert b[2]["slots"] == ["a0"]
    assert b[2]["calls"] == [{"fn": "kv_key_equals", "binds": {0: ("slot", "a0"), 1: ("data", "fuzz_buf")}}]
    calls = [
        {
            "fn": "kv_key_equals",
            "args": {"0": [["i", 0, "05000000"]], "1": [["b", 0, "6b6579"]], "2": [["i", 0, "03"]]},
        },
        {"fn": "kv_find", "args": {"0": [["s", 0, "6b6579"]]}},
        {"fn": "kv_key_equals", "args": {"1": [["b", 0, "6b6579"]]}},  # slot missing: no seed
    ]
    assert sh.seeds_for_case(2, b[2], calls) == [b"\x02\x05\x00\x00\x00key"]
    assert sh.seeds_for_case(1, b[1], calls) == [b"\x01key"]
    assert sh.seeds_for_case(0, b[0], calls) == []
    assert sh.whole_input_cases(list(zip([0, 1, 2], b, strict=True))) == [1]


def test_custom_struct_and_alias_cases():
    qcbor = (
        "{ QCBORDecodeContext ctx; QCBORItem item; UsefulBufC input; input.ptr = fuzz_buf; input.len = fuzz_len; "
        "QCBORDecode_Init(&ctx, input, QCBOR_DECODE_MODE_NORMAL); while (QCBORDecode_GetNext(&ctx, &item) == 0) { } }"
    )
    [(sel, stmt)] = sh.harness_cases(_harness(qcbor))
    assert sel is None
    b = sh.case_bindings(stmt, {"QCBORDecode_Init", "QCBORDecode_GetNext"})
    assert b["calls"] == [{"fn": "QCBORDecode_Init", "binds": {1: ("struct", "input")}}]
    calls = [
        {
            "fn": "QCBORDecode_Init",
            "args": {"1": [["t", 0, "00" * 16], ["n", 0, "a16161"]], "2": [["i", 0, "00000000"]]},
        }
    ]
    assert sh.seeds_for_case(None, b, calls) == [b"\xa1\x61\x61"]
    minmea = (
        "const char *s; struct minmea_sentence_rmc rmc; s = (const char *)fuzz_buf; (void)minmea_check(s,false); "
        "(void)minmea_parse_rmc(&rmc,s); (void)other(&rmc, (UsefulBufC){fuzz_buf, fuzz_len});"
    )
    b = sh.case_bindings(minmea, {"minmea_check", "minmea_parse_rmc", "other"})
    assert [c["fn"] for c in b["calls"]] == ["minmea_check", "minmea_parse_rmc", "other"]
    assert b["calls"][1]["binds"] == {1: ("data", "s")}
    assert b["calls"][2]["binds"] == {1: ("struct", "{fuzz_buf, fuzz_len}")}
    calls = [
        {"fn": "minmea_parse_rmc", "args": {"1": [["s", 0, "2447505243"]]}},
        {"fn": "minmea_check", "args": {"0": [["s", 0, "2447"]], "1": [["i", 0, "01"]]}},
    ]
    assert sh.seeds_for_case(None, b, calls) == [b"$GPRC", b"$G"]


def test_auto_prototype_layout():
    stmt = (
        "size_t fuzz_off = 0; uint16_t arg_0; memset(&arg_0, 0, sizeof(arg_0)); if (fuzz_len >= fuzz_off + sizeof(arg_0)) "
        "{ memcpy(&arg_0, fuzz_buf + fuzz_off, sizeof(arg_0)); fuzz_off += sizeof(arg_0); } "
        "long arg_2; if (fuzz_len >= fuzz_off + sizeof(arg_2)) { memcpy(&arg_2, fuzz_buf + fuzz_off, sizeof(arg_2)); "
        "fuzz_off += sizeof(arg_2); } f(arg_0, (const uint8_t *)(fuzz_buf + fuzz_off), (size_t)(fuzz_len - fuzz_off), &arg_2);"
    )
    b = sh.case_bindings(stmt, {"f"})
    assert b["slots"] == ["arg_0", "arg_2"]
    assert b["calls"][0]["binds"] == {0: ("slot", "arg_0"), 1: ("data", "fuzz_buf + fuzz_off"), 3: ("pslot", "arg_2")}
    calls = [
        {"fn": "f", "args": {"0": [["i", 0, "0100"]], "1": [["b", 0, "aabb"]], "3": [["p", 0, "0200000000000000"]]}}
    ]
    assert sh.seeds_for_case(None, b, calls) == [b"\x01\x00" + b"\x02" + b"\x00" * 7 + b"\xaa\xbb"]


def test_write_module_and_records(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "calls"
    out_dir.mkdir()
    (out_dir / "calls-7.txt").write_text(
        "kv_load 0b=0102 1i=0200000000000000\nkv_load 0b=0102 1i=0200000000000000\nkv_find 0s=6b\ngarbage line!\n"
    )
    (tmp_path / "tree" / "data").mkdir(parents=True)
    (tmp_path / "tree" / "data" / "x.bin").write_bytes(b"FILE")
    report: dict = {"status": "error"}
    sh._collect(report, out_dir, [str(tmp_path / "tree" / "data" / "x.bin")], tmp_path / "tree", 0.0)
    assert report["status"] == "ok"
    assert (
        report["calls"]["recorded"] == 3 and report["calls"]["unique"] == 2 and report["calls"]["unparsed_lines"] == 1
    )
    assert report["files"]["kept"][0]["path"] == "data/x.bin"
    stmt = _build_dispatch_invocation(
        [
            "(void)kv_load((const uint8_t *)fuzz_buf, (size_t)fuzz_len);",
            "char s0[16]; memcpy(s0, fuzz_buf, 15); (void)kv_find(s0);",
        ]
    )
    hdir = tmp_path / "workspace" / "harnesses"
    hdir.mkdir(parents=True)
    (hdir / "harness_libkv_a.json").write_text(json.dumps({"module": "libkv_a", "max_input_size": 4}))
    (hdir / "harness_libkv_a.c").write_text(_harness(stmt))
    (tmp_path / "workspace" / "seeds" / "libkv_a").mkdir(parents=True)
    (tmp_path / "workspace" / "seeds" / "libkv_a" / "seed-stale").write_bytes(b"old")
    out = sh.write([])
    # max_input_size 4: the two 5-byte seeds built from the data file are dropped
    assert out["modules"]["libkv_a"] == {"seeds": 2, "dropped_too_large": 2}
    seeds = sorted(p.read_bytes() for p in (tmp_path / "workspace" / "seeds" / "libkv_a").iterdir())
    assert seeds == [b"\x00\x01\x02", b"\x01k"]
    summary = json.loads((tmp_path / "workspace" / "reports" / "seeds" / "libkv_a.json").read_text())
    assert summary["dropped_too_large"] == 2 and summary["dispatch"] is True
    assert summary["cases"]["0"]["from_calls"] == 1 and summary["cases"]["1"]["from_files"] == 0


def test_write_without_records_clears_seeds(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    hdir = tmp_path / "workspace" / "harnesses"
    hdir.mkdir(parents=True)
    (hdir / "harness_m.json").write_text(json.dumps({"module": "m"}))
    (hdir / "harness_m.c").write_text(_harness("f(fuzz_buf, fuzz_len);"))
    (tmp_path / "workspace" / "seeds" / "m").mkdir(parents=True)
    (tmp_path / "workspace" / "seeds" / "m" / "seed-old").write_bytes(b"x")
    out = sh.write(["m"])
    assert out["modules"]["m"]["seeds"] == 0
    assert not list((tmp_path / "workspace" / "seeds" / "m").iterdir())


def test_record_without_test_command(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "run-metadata.json").write_text(json.dumps({"build": {"command": "make"}}))
    assert sh.main(["record", "--scratch", str(tmp_path / "scratch")]) == 0
    report = json.loads((tmp_path / "workspace" / "reports" / "seed_harvest.json").read_text())
    assert report["status"] == "no_model" and report["source"] == "executables"


def _record_fixture(tmp_path, monkeypatch, units: dict, recipe: dict) -> list[list[str]]:
    """A model, a capture and a build tree; relinking and running are stubbed and logged."""
    monkeypatch.chdir(tmp_path)
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    tree = tmp_path / "scratch" / "tree"
    tree.mkdir(parents=True)
    for name in units:
        (tree / name).write_bytes(b"\x7fELF")
    (tmp_path / "run-metadata.json").write_text(json.dumps({"build": recipe}))
    model = {
        "status": "ok",
        "entry_points": ["lib#f"],
        "functions": {"lib#f": {"name": "f", "signature": "int (const unsigned char *, unsigned long)"}},
        "units": {},
    }
    (reports / "phase0_model.json").write_text(json.dumps(model))
    capture = {"status": "ok", "scratch": {"tree": str(tree)}, "units": units, "compiles": []}
    (reports / "build_capture.json").write_text(json.dumps(capture))
    ran: list[list[str]] = []

    class Res:
        returncode = 0
        timed_out = False
        stdout = stderr = ""

    def sandboxed(argv, cwd, scratch, timeout, env):
        ran.append([str(a) for a in argv])
        return Res()

    monkeypatch.setattr(sh, "link_commands", lambda ev, t: {n: {"args": ["cc", "-o", n], "cwd": str(t)} for n in units})
    monkeypatch.setattr(sh, "defined_functions", lambda exe: {"f"})
    monkeypatch.setattr(sh, "_run", lambda argv, cwd, timeout: (0, ""))
    monkeypatch.setattr(sh, "_compile_wrappers", lambda cc, fl, plans, where, c, o, w: (True, plans, ""))
    monkeypatch.setattr(sh, "_sandboxed", sandboxed)
    return ran


def test_record_without_test_command_runs_the_non_test_executables(tmp_path, monkeypatch):
    units = {
        "demo": {"kind": "executable", "objects": []},
        "unit_test": {"kind": "executable", "test": True, "objects": []},
        "libx.a": {"kind": "static_lib", "objects": []},
    }
    ran = _record_fixture(tmp_path, monkeypatch, units, {"command": "make"})
    assert sh.main(["record", "--scratch", str(tmp_path / "scratch")]) == 0
    report = json.loads((tmp_path / "workspace" / "reports" / "seed_harvest.json").read_text())
    assert report["source"] == "executables" and report["executables"] == ["demo"]
    assert report["relink"]["demo"]["status"] == "relinked" and "unit_test" not in report["relink"]
    # one relink, then the demo itself with no arguments
    assert ran[0][0] == "cc" and any(a == "-Wl,--wrap=f" for a in ran[0])
    assert ran[1] == [str(tmp_path / "scratch" / "tree" / "demo")]
    assert report["runs"]["demo"]["returncode"] == 0
    assert report["status"] == "no_calls_recorded"


def test_record_with_a_test_command_runs_only_the_tests(tmp_path, monkeypatch):
    units = {
        "demo": {"kind": "executable", "objects": []},
        "unit_test": {"kind": "executable", "test": True, "objects": []},
    }
    ran = _record_fixture(tmp_path, monkeypatch, units, {"command": "make", "test_command": "make check"})
    monkeypatch.setattr(sh.shutil, "which", lambda name: None)
    assert sh.main(["record", "--scratch", str(tmp_path / "scratch")]) == 0
    report = json.loads((tmp_path / "workspace" / "reports" / "seed_harvest.json").read_text())
    assert report["source"] == "test_command" and report["test_units"] == ["unit_test"]
    assert "demo" not in report["relink"] and "runs" not in report
    assert ran[-1] == ["sh", "-c", "make check"]


def test_record_without_test_command_or_executables(tmp_path, monkeypatch):
    units = {"libx.a": {"kind": "static_lib", "objects": []}}
    _record_fixture(tmp_path, monkeypatch, units, {"command": "make"})
    assert sh.main(["record", "--scratch", str(tmp_path / "scratch")]) == 0
    report = json.loads((tmp_path / "workspace" / "reports" / "seed_harvest.json").read_text())
    assert report["status"] == "no_test_command" and report["executables"] == []
