"""
Phase 0 model (plan step I3): scripts/phase0_model.py merges Frama-C dumps (scripts/phase0_dump.ml) of
each link unit into one inventory and call graph. Unit tests feed recorded dumps; the Docker-backed
tests run the build capture and the model on the reproducers and the features fixture.
"""

import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

import phase0_model as pm
import resources
from conftest import ANALYSIS_IMAGE, BUILD_IMAGE, require_docker_images

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "phase0"
TREE = "/framac-scratch/tree"


def _fn(kernel, name, file, line, calls=(), static=False, signature="int(int)", **extra):
    return {
        "kernel_name": kernel,
        "name": name,
        "loc": f"{file}:{line}",
        "first_line": line,
        "last_line": line + 2,
        "static": static,
        "inline": extra.pop("inline", False),
        "signature": signature,
        "loops": extra.pop("loops", 0),
        "cyclomatic": extra.pop("cyclomatic", 1),
        "calls": list(calls),
    }


def _call(kernel, name=None, args=()):
    return {"kernel_name": kernel, "name": name or kernel, "indirect": False, "function_args": list(args), "loc": "x"}


def _indirect(signature="int(int)", expr="f"):
    return {"indirect": True, "expr": expr, "signature": signature, "loc": "x"}


def _builder(units):
    return pm.ModelBuilder({"units": units}, TREE)


LIB_EXE = {
    "libkv.a": {"kind": "static_lib", "files": ["src/lexer.c", "src/emit.c"], "links": []},
    "kvfmt": {"kind": "executable", "files": ["tools/main.c"], "links": ["libkv.a"]},
}


@pytest.mark.unit
def test_same_named_statics_stay_apart_and_calls_resolve_to_the_file_local_one():
    b = _builder(LIB_EXE)
    b.add_dump(
        ["libkv.a"],
        {
            "functions": [
                _fn("skip_ws", "skip_ws", "src/lexer.c", 3, static=True),
                _fn("kv_next", "kv_next", "src/lexer.c", 9, [_call("skip_ws")]),
                _fn("skip_ws_0", "skip_ws", "src/emit.c", 2, static=True),
                _fn("kv_emit", "kv_emit", "src/emit.c", 8, [_call("skip_ws_0", "skip_ws")]),
                _fn("fopen", "fopen", "FRAMAC_SHARE/libc/stdio.h", 40),  # Frama-C's libc: not the project
            ],
            "address_taken": [],
        },
    )
    b.add_dump(
        ["kvfmt"],
        {
            "functions": [
                _fn("main", "main", f"{TREE}/tools/main.c", 5, [_call("kv_next"), _call("kv_emit"), _call("fopen")]),
            ],
            "address_taken": [],
        },
    )
    b.resolve()
    assert set(b.functions) == {"src/lexer.c#skip_ws", "src/lexer.c#kv_next", "src/emit.c#skip_ws",
                                "src/emit.c#kv_emit", "tools/main.c#main"}  # fmt: skip
    assert b.functions["src/emit.c#skip_ws"]["kernel_names"] == {"libkv.a": "skip_ws_0"}
    assert set(b.edges) == {
        ("src/lexer.c#kv_next", "src/lexer.c#skip_ws", "direct"),
        ("src/emit.c#kv_emit", "src/emit.c#skip_ws", "direct"),
        ("tools/main.c#main", "src/lexer.c#kv_next", "direct"),  # resolved in the library main links
        ("tools/main.c#main", "src/emit.c#kv_emit", "direct"),
    }
    assert b.externals == {"fopen"}
    assert b.functions["src/lexer.c#kv_next"]["source"] == "frama-c-kernel"


@pytest.mark.unit
def test_a_library_call_to_a_function_its_consumer_defines_resolves_there():
    b = _builder(LIB_EXE)
    b.add_dump(["libkv.a"], {"functions": [_fn("kv_next", "kv_next", "src/lexer.c", 1, [_call("user_hook")])]})
    b.add_dump(["kvfmt"], {"functions": [_fn("user_hook", "user_hook", "tools/main.c", 1)]})
    b.resolve()
    assert ("src/lexer.c#kv_next", "tools/main.c#user_hook", "direct") in b.edges
    assert not b.externals


@pytest.mark.unit
def test_indirect_sites_match_address_taken_functions_of_the_same_signature_across_the_program():
    b = _builder(LIB_EXE)
    b.add_dump(
        ["libkv.a"],
        {
            "functions": [
                _fn("dispatch", "dispatch", "src/lexer.c", 1, [_indirect("int(int)")]),
                _fn("lib_cb", "lib_cb", "src/lexer.c", 5),
            ],
            "address_taken": ["lib_cb"],
        },
    )
    b.add_dump(
        ["kvfmt"],
        {
            "functions": [
                _fn("on_line", "on_line", "tools/main.c", 1),
                _fn("on_text", "on_text", "tools/main.c", 4, signature="void(char *)"),
                _fn("unused", "unused", "tools/main.c", 8),  # same signature, address never taken
            ],
            "address_taken": ["on_line", "on_text"],
        },
    )
    b.resolve()
    site = b.indirect_sites[0]
    assert site["candidates"] == ["src/lexer.c#lib_cb", "tools/main.c#on_line"]
    assert ("src/lexer.c#dispatch", "tools/main.c#on_line", "indirect") in b.edges
    assert b.edges[("src/lexer.c#dispatch", "tools/main.c#on_line", "indirect")] == {"type-match"}
    assert (
        b.functions["tools/main.c#on_line"]["address_taken"] and not b.functions["tools/main.c#unused"]["address_taken"]
    )


def _alias_report(sites_by_caller, status="ok"):
    return {
        "schema": 1,
        "status": status,
        "error": "" if status == "ok" else "boom",
        "seconds": 0.01,
        "functions": [{"kernel_name": k, "sites": sites} for k, sites in sites_by_caller.items()],
    }


def _alias_site(status, targets=(), expr="f", loc="x"):
    site = {"expr": expr, "loc": loc, "status": status}
    if targets:
        site["targets"] = list(targets)
    return site


ALIAS_UNITS = {"libcb.a": {"kind": "static_lib", "files": ["src/cb.c"], "links": []}}


def _alias_dump():
    """fire: one site; disp: two sites with the same expression at different lines. a, b, c: int(int)."""
    return {
        "functions": [
            _fn("a", "a", "src/cb.c", 1),
            _fn("b", "b", "src/cb.c", 2),
            _fn("c", "c", "src/cb.c", 3),
            _fn("fire", "fire", "src/cb.c", 5, [_indirect(expr="g")]),
            _fn(
                "disp",
                "disp",
                "src/cb.c",
                9,
                [{**_indirect(expr="t.f"), "loc": "l10"}, {**_indirect(expr="t.f"), "loc": "l11"}],
            ),  # fmt: skip
        ],
        "address_taken": ["a", "b", "c"],
    }


def _sites(b):
    return {(s["caller"], s.get("loc")): s for s in b.indirect_sites}


@pytest.mark.unit
def test_alias_narrows_the_type_match_and_records_why_each_site_kept_or_lost_candidates():
    b = _builder(ALIAS_UNITS)
    report = _alias_report(
        {
            "fire": [_alias_site("targets", ["a"], expr="g")],
            # Reported out of order: matched by location and expression, not position.
            "disp": [
                _alias_site("no_targets", expr="t.f", loc="l11"),
                _alias_site("targets", ["b", "c"], expr="t.f", loc="l10"),
            ],  # fmt: skip
        }
    )
    b.add_dump(["libcb.a"], _alias_dump(), report)
    b.resolve()
    s = _sites(b)
    fire = s[("src/cb.c#fire", "x")]
    assert fire["candidates"] == ["src/cb.c#a"] and fire["narrowing"] == "alias"
    assert fire["dropped"] == ["src/cb.c#b", "src/cb.c#c"]
    assert s[("src/cb.c#disp", "l10")]["candidates"] == ["src/cb.c#b", "src/cb.c#c"]
    kept = s[("src/cb.c#disp", "l11")]
    assert kept["narrowing"] == "none" and kept["narrowing_reason"] == "no_targets" and len(kept["candidates"]) == 3
    assert b.edges[("src/cb.c#fire", "src/cb.c#a", "indirect")] == {"type-match", "alias"}
    assert ("src/cb.c#fire", "src/cb.c#b", "indirect") not in b.edges
    # disp's second site keeps a through the type match alone.
    assert b.edges[("src/cb.c#disp", "src/cb.c#a", "indirect")] == {"type-match"}


@pytest.mark.unit
@pytest.mark.parametrize("status", ["failed", "timeout", "crashed", "unavailable"])
def test_alias_failure_keeps_every_type_match_with_the_reason(status):
    b = _builder(ALIAS_UNITS)
    b.add_dump(["libcb.a"], _alias_dump(), {"status": status, "error": "boom"})
    b.resolve()
    for site in b.indirect_sites:
        assert site["narrowing"] == "none" and site["narrowing_reason"] == f"alias_{status}"
        assert len(site["candidates"]) == 3 and site["dropped"] == []


@pytest.mark.unit
def test_alias_sites_that_do_not_match_or_name_no_candidate_keep_the_type_match():
    b = _builder(ALIAS_UNITS)
    report = _alias_report(
        {
            "fire": [_alias_site("targets", ["printf_like"], expr="g")],  # outside the type match: a cast
            "disp": [_alias_site("no_state", expr="t.f", loc="l10")],  # l11 missing from the report
        }
    )
    b.add_dump(["libcb.a"], _alias_dump(), report)
    b.resolve()
    s = _sites(b)
    assert s[("src/cb.c#fire", "x")]["narrowing_reason"] == "disjoint"
    assert s[("src/cb.c#disp", "l10")]["narrowing_reason"] == "no_state"
    assert s[("src/cb.c#disp", "l11")]["narrowing_reason"] == "unmatched"
    assert all(len(site["candidates"]) == 3 for site in b.indirect_sites)


@pytest.mark.unit
def test_alias_targets_defined_in_a_linked_unit_resolve_by_name():
    units = {
        "liblib.a": {"kind": "static_lib", "files": ["src/lib.c"], "links": []},
        "tool": {"kind": "executable", "files": ["tools/main.c"], "links": ["liblib.a"]},
    }
    b = _builder(units)
    b.add_dump(["liblib.a"], {"functions": [_fn("on_a", "on_a", "src/lib.c", 1), _fn("on_b", "on_b", "src/lib.c", 3)],
                              "address_taken": ["on_a", "on_b"]})  # fmt: skip
    b.add_dump(
        ["tool"],
        {"functions": [_fn("main", "main", "tools/main.c", 1, [_indirect()])], "address_taken": []},
        _alias_report({"main": [_alias_site("targets", ["on_b"])]}),
    )
    b.resolve()
    site = b.indirect_sites[0]
    assert site["candidates"] == ["src/lib.c#on_b"] and site["dropped"] == ["src/lib.c#on_a"]


@pytest.mark.unit
def test_without_alias_sites_record_that_no_narrowing_ran():
    b = _builder(ALIAS_UNITS)
    b.add_dump(["libcb.a"], _alias_dump())
    b.resolve()
    assert {(s["narrowing"], s["narrowing_reason"]) for s in b.indirect_sites} == {("none", "disabled")}
    assert all(src == {"type-match"} for (_, _, k), src in b.edges.items() if k == "indirect")


@pytest.mark.unit
def test_alias_report_reading(tmp_path):
    path = tmp_path / "alias.json"
    assert pm.read_alias_report(path, 0, "")["status"] == "crashed"
    crashed = pm.read_alias_report(path, 2, "[alias] failure: Stack overflow\n")
    assert crashed["status"] == "crashed" and "exit 2" in crashed["error"]
    path.write_text(json.dumps(_alias_report({})), encoding="utf-8")
    assert pm.read_alias_report(path, 0, "")["status"] == "ok"


@pytest.mark.unit
def test_framac_parse_loads_the_alias_module_and_keeps_the_dump_when_alias_crashes(tmp_path):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"], seen["env"] = cmd, kw["env"]
        Path(kw["env"][pm.DUMP_OUT_ENV]).write_text(json.dumps({"functions": []}), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 3, "", "[alias] failure: Stack overflow\n")

    job = {"key": "k", "compiles": [{"source": "a.c", "flags": [], "system_flags": []}]}
    res = pm.framac_parse(job, TREE, None, Path("/m/dump.cmxs"), tmp_path, False, fake_run, Path("/m/alias.cmxs"))
    assert seen["cmd"][seen["cmd"].index("-load-module") + 1] == f"{Path('/m/dump.cmxs')},{Path('/m/alias.cmxs')}"
    assert seen["env"][pm.ALIAS_TIMEOUT_ENV] == str(pm.ALIAS_TIMEOUT_S)
    assert res["status"] == "ok" and res["alias"]["status"] == "crashed"
    # Without Alias, a failing run is a failed parse, as before.
    res = pm.framac_parse(job, TREE, None, Path("/m/dump.cmxs"), tmp_path, False, fake_run)
    assert res["status"] == "parse_failed" and "alias" not in res


@pytest.mark.unit
def test_thread_spawns_and_callbacks_passed_to_externals():
    units = {"libpool.a": {"kind": "static_lib", "files": ["src/pool.c"], "links": []}}
    b = _builder(units)
    b.add_dump(
        ["libpool.a"],
        {
            "functions": [
                _fn("worker", "worker", "src/pool.c", 1, signature="void *(void *)"),
                _fn("cmp", "cmp", "src/pool.c", 5),
                _fn(
                    "pool_create",
                    "pool_create",
                    "src/pool.c",
                    9,
                    [_call("pthread_create", args=["worker"]), _call("qsort", args=["cmp"])],
                ),
            ],
            "address_taken": ["worker", "cmp"],
        },
    )
    b.resolve()
    assert b.thread_entries == {"src/pool.c#worker"}
    assert b.concurrent == {"libpool.a"}
    assert b.edges[("src/pool.c#pool_create", "src/pool.c#worker", "indirect")] == {"thread-spawn"}
    assert b.edges[("src/pool.c#pool_create", "src/pool.c#cmp", "indirect")] == {"callback-arg"}
    assert b.externals == {"pthread_create", "qsort"}


@pytest.mark.unit
def test_header_inline_functions_belong_to_every_unit_compiling_them():
    units = {
        "liba.a": {"kind": "static_lib", "files": ["src/a.c"], "links": []},
        "libb.a": {"kind": "static_lib", "files": ["src/b.c"], "links": []},
    }
    b = _builder(units)
    inline = _fn("clamp", "clamp", "include/api.h", 12, static=True, inline=True)
    b.add_dump(["liba.a"], {"functions": [inline, _fn("fa", "fa", "src/a.c", 1, [_call("clamp")])]})
    b.add_dump(["libb.a"], {"functions": [inline, _fn("fb", "fb", "src/b.c", 1, [_call("clamp")])]})
    b.resolve()
    clamp = b.functions["include/api.h#clamp"]
    assert clamp["header"] and clamp["inline"] and sorted(clamp["units"]) == ["liba.a", "libb.a"]
    assert ("src/a.c#fa", "include/api.h#clamp", "direct") in b.edges
    assert ("src/b.c#fb", "include/api.h#clamp", "direct") in b.edges


@pytest.mark.unit
def test_a_c_file_included_by_another_source_is_marked():
    b = _builder({"libu.a": {"kind": "static_lib", "files": ["src/unity.c"], "links": []}})
    b.add_dump(["libu.a"], {"functions": [_fn("impl", "impl", "src/impl.c", 1)]})
    assert b.functions["src/impl.c#impl"]["included"] is True


@pytest.mark.unit
def test_macro_alias_chains_resolve_to_defined_functions():
    b = _builder({"libn.a": {"kind": "static_lib", "files": ["src/hash.c"], "links": []}})
    b.add_dump(
        ["libn.a"], {"functions": [_fn("crypto_hash_sha512_tweet", "crypto_hash_sha512_tweet", "src/hash.c", 3)]}
    )
    text = "\n".join(
        [
            f'# 1 "{TREE}/include/api.h"',
            "#define API_H ",
            "#define crypto_hash crypto_hash_sha512",
            "#define crypto_hash_sha512 crypto_hash_sha512_tweet",
            "#define BUFSZ 64",
            "#define other_name not_a_function",
            '# 1 "/usr/include/stdio.h"',
            "#define fopen my_fopen",
        ]
    )
    defines = pm.parse_defines(text, TREE)
    assert [d["alias"] for d in defines] == ["crypto_hash", "crypto_hash_sha512", "other_name"]
    aliases = b.aliases(defines)
    assert aliases["crypto_hash"] == {
        "function": "crypto_hash_sha512_tweet",
        "ids": ["src/hash.c#crypto_hash_sha512_tweet"],
        "via": ["crypto_hash_sha512"],
        "defined_in": "include/api.h",
        "source": "preprocessor",
    }
    assert set(aliases) == {"crypto_hash", "crypto_hash_sha512"}


@pytest.mark.unit
def test_gcc_fallback_reads_callgraph_info(tmp_path, monkeypatch):
    ci = (
        'graph: { title: "/framac-scratch/tree/src/nest.c"\n'
        'node: { title: "nest_sum" label: "nest_sum\\n/framac-scratch/tree/src/nest.c:4:5" }\n'
        'node: { title: "nest.c:add.0" label: "add\\n/framac-scratch/tree/src/nest.c:6:9" }\n'
        'node: { title: "clamp" label: "clamp\\n/framac-scratch/tree/include/api.h:12:19" }\n'
        'node: { title: "helper" label: "helper" }\n'
        'node: { title: "__indirect_call" label: "Indirect Call Placeholder" }\n'
        'edge: { sourcename: "nest_sum" targetname: "nest.c:add.0" }\n'
        'edge: { sourcename: "nest.c:add.0" targetname: "clamp" }\n'
        'edge: { sourcename: "nest_sum" targetname: "helper" }\n'
        'edge: { sourcename: "nest_sum" targetname: "__indirect_call" }\n'
    )

    def fake_run(cmd, **kw):
        base = cmd[cmd.index("-dumpbase") + 1]
        Path(f"{base}.ci").write_text(ci, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    job = {
        "key": "k",
        "compiles": [{"source": "src/nest.c", "cwd": ".", "arguments": ["cc", "-Iinclude", "-c", "src/nest.c"],
                      "flags": ["-I", "include"], "system_flags": []}],
    }  # fmt: skip
    g = pm.gcc_callgraph(job, TREE, None, tmp_path, runner=fake_run)
    assert g["status"] == "ok"
    assert set(g["functions"]) == {"src/nest.c#nest_sum", "src/nest.c#add", "include/api.h#clamp"}
    assert g["functions"]["src/nest.c#add"]["static"] is True
    assert ("src/nest.c#add", "include/api.h#clamp", "helper") not in g["edges"]
    assert ("src/nest.c#add", "include/api.h#clamp", "clamp") in g["edges"]
    assert ("src/nest.c#nest_sum", None, "helper") in g["edges"]
    assert g["indirect"] == ["src/nest.c#nest_sum"]

    b = _builder({"libnest.a": {"kind": "static_lib", "files": ["src/nest.c"], "links": []},
                  "libh.a": {"kind": "static_lib", "files": ["src/h.c"], "links": []}})  # fmt: skip
    b.add_gcc(["libnest.a"], g)
    b.add_dump(["libh.a"], {"functions": [_fn("helper", "helper", "src/h.c", 1)]})
    b.resolve()
    assert b.functions["src/nest.c#nest_sum"]["source"] == "gcc-callgraph-info"
    assert ("src/nest.c#nest_sum", "src/nest.c#add", "direct") in b.edges
    # helper is defined in no unit libnest.a links, and nothing links libnest.a: an external.
    assert "helper" in b.externals
    assert b.indirect_sites[0]["signature"] is None and b.indirect_sites[0]["candidates"] == []


@pytest.mark.unit
def test_units_with_the_same_sources_and_flags_share_one_parse_and_tests_are_skipped():
    c1 = {"source": "src/a.c", "object": "a.o", "flags": ["-I", "include"], "system_flags": []}
    c1_pic = {**c1, "object": "a.pic.o"}
    c2 = {"source": "src/a.c", "object": "a.test.o", "flags": ["-DTEST"], "system_flags": []}
    capture = {
        "compiles": [c1, c1_pic, c2],
        "units": {
            "liba.a": {"kind": "static_lib", "test": False, "objects": ["a.o"], "files": ["src/a.c"], "links": []},
            "liba.so": {"kind": "shared_lib", "test": False, "objects": ["a.pic.o"], "files": ["src/a.c"], "links": []},
            "test_a": {"kind": "executable", "test": True, "objects": ["a.test.o"], "files": ["src/a.c"], "links": []},
        },
    }
    jobs, unit_job = pm.plan_jobs(capture)
    assert len(jobs) == 1 and jobs[0]["units"] == ["liba.a", "liba.so"]
    assert set(unit_job) == {"liba.a", "liba.so"}


@pytest.mark.unit
def test_snapshot_include_dirs_follow_the_compile_and_gcc_defaults(tmp_path):
    root = tmp_path / "snap"
    for d in ("usr/include", "usr/include/libxml2", "usr/local/include"):
        (root / d).mkdir(parents=True)
    flags = pm.snapshot_dirs(str(root).replace("\\", "/"), ["-I", "/usr/include/libxml2", "-I", "/opt/missing"])
    dirs = flags[1::2]
    assert flags[0::2] == ["-idirafter"] * len(dirs)
    assert [d.split("snap/")[-1] for d in dirs] == ["usr/include/libxml2", "usr/local/include", "usr/include"]
    assert pm.snapshot_dirs(None, ["-I", "/usr/include"]) == []


@pytest.mark.unit
def test_framac_flags_and_errors():
    assert pm.framac_file_flags(["-I", "include", "-DNAME=a b", "-std=c89", "-std=c99"], "/t") == [
        "-I",
        "/t/include",
        "'-DNAME=a b'",
        "-std=c99",
    ]
    log = "[kernel] Parsing src/nest.c\n[kernel] src/nest.c:6: User Error:\n  syntax error:\nmore\n"
    assert pm.first_error(log) == "[kernel] src/nest.c:6: User Error: syntax error:"
    assert pm.tree_rel("FRAMAC_SHARE/libc/stdio.h", TREE) is None
    assert pm.tree_rel("src/a.c", TREE) == "src/a.c"
    assert pm.tree_rel(f"{TREE}/src/a.c", TREE) == "src/a.c"
    assert pm.tree_rel("/usr/include/gcrypt.h", TREE) is None


@pytest.mark.unit
def test_build_model_reports_a_missing_capture_or_tree(tmp_path):
    model, rc = pm.build_model(tmp_path / "none.json", tmp_path / "out.json")
    assert rc == 1 and model["status"] == "error" and "build_capture.py" in model["error"]
    cap = tmp_path / "cap.json"
    cap.write_text(json.dumps({"status": "ok", "scratch": {"tree": str(tmp_path / "gone")}}), encoding="utf-8")
    model, rc = pm.build_model(cap, tmp_path / "out.json")
    assert rc == 1 and "-Scratch" in model["error"]
    assert not pm.validate_model(model)


@pytest.mark.unit
def test_build_model_stops_when_no_unit_parses(tmp_path, monkeypatch):
    """Phase 0 stops when Frama-C parses no unit (defect 6): status no_unit_parsed, exit 4."""
    tree = tmp_path / "tree"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "a.c").write_text("int f(void) { return 0; }\n", encoding="utf-8")
    capture = {
        "status": "ok",
        "scratch": {"tree": str(tree)},
        "compiles": [{"source": "src/a.c", "object": "a.o", "flags": [], "system_flags": []}],
        "units": {
            "liba.a": {"kind": "static_lib", "test": False, "objects": ["a.o"], "files": ["src/a.c"], "links": []}
        },
    }
    cap = tmp_path / "cap.json"
    cap.write_text(json.dumps(capture), encoding="utf-8")
    monkeypatch.setattr(pm, "compile_dump_module", lambda *a, **k: (tmp_path / "dump.cmxs", ""))
    monkeypatch.setattr(pm, "macro_aliases", lambda *a, **k: [])
    monkeypatch.setattr(
        pm,
        "framac_parse",
        lambda *a, **k: {"status": "parse_failed", "error": "src/a.c:1: syntax error", "seconds": 0.1},
    )
    monkeypatch.setattr(
        pm,
        "gcc_callgraph",
        lambda *a, **k: {"status": "ok", "errors": [], "functions": {}, "edges": [], "indirect": []},
    )
    model, rc = pm.build_model(cap, tmp_path / "out.json", broker=False)
    assert rc == pm.NO_UNIT_PARSED_RC == 4
    assert model["status"] == "no_unit_parsed" and "liba.a" in model["error"]
    assert model["units"]["liba.a"]["parse"] == {
        "status": "gcc_fallback",
        "job": model["units"]["liba.a"]["parse"]["job"],
        "seconds": 0.1,
        "error": "src/a.c:1: syntax error",
    }
    assert not pm.validate_model(model)


@pytest.mark.unit
def test_parse_class_and_container_class():
    assert resources.CLASSES["parse"].runs_target_code is False
    assert resources.CLASSES["parse"].max_cpus == 1
    assert resources.infer_class("python3 $S/phase0_model.py run") == "phase-static"
    assert pm.leased(["frama-c", "x.c"], "p0-k", broker=True)[-4:] == ["p0-k", "--", "frama-c", "x.c"]
    assert pm.leased(["frama-c"], "k", broker=False) == ["frama-c"]


# ---------------------------------------------------------------------------------------------------
# Docker-backed: build capture in the build image, then the model in the analysis image
# ---------------------------------------------------------------------------------------------------


@pytest.fixture
def model_run():
    """`run(fixture, run_dir, build_command) -> model`: capture and model on one scratch volume."""
    require_docker_images(ANALYSIS_IMAGE, BUILD_IMAGE)
    volumes: list[str] = []

    def docker(args: list[str], timeout: int = 900) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["docker", *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False,
        )  # fmt: skip

    def run(fixture: Path, run_dir: Path, build: str, model_args: str = "") -> dict:
        run_dir.mkdir(parents=True, exist_ok=True)
        vol = f"p0model-test-{uuid.uuid4().hex[:12]}"
        volumes.append(vol)
        docker(["volume", "create", vol])
        common = [
            "run", "--rm", "--network", "none",
            "-v", f"{fixture.resolve()}:/target:ro", "-v", f"{run_dir.resolve()}:/framac-run",
            "-v", f"{vol}:/framac-scratch",
            "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
            "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro", "-w", "/framac-run",
        ]  # fmt: skip
        docker([*common, "--user", "root", "--entrypoint", "sh", BUILD_IMAGE, "-c", "chmod 1777 /framac-scratch"])
        py = "python3 /opt/framac-pipeline/scripts"
        cap = docker(
            [*common, BUILD_IMAGE,
             f"{py}/build_capture.py run --scratch /framac-scratch --recipe-file '' --command '{build}'"]
        )  # fmt: skip
        assert cap.returncode == 0, cap.stdout + cap.stderr
        mod = docker([*common, "--entrypoint", "sh", ANALYSIS_IMAGE, "-c", f"{py}/phase0_model.py run {model_args}"])
        assert mod.returncode == 0, mod.stdout + mod.stderr
        return json.loads((run_dir / pm.DEFAULT_OUT).read_text(encoding="utf-8"))

    yield run
    for vol in volumes:
        docker(["volume", "rm", "-f", vol])


REPRODUCERS = sorted(p.name for p in (FIXTURES / "reproducers").iterdir() if (p / "truth.json").is_file())


def _pr(pred: set, truth: set) -> tuple[set, set]:
    return pred - truth, truth - pred


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("name", REPRODUCERS)
def test_reproducers_match_their_truth_on_every_class(model_run, tmp_path, name):
    fixture = FIXTURES / "reproducers" / name
    truth = json.loads((fixture / "truth.json").read_text(encoding="utf-8"))
    model = model_run(fixture, tmp_path / "run", truth["build"])
    assert model["status"] == "ok" and not pm.validate_model(model)
    assert all(u["parse"]["status"] == "ok" for u in model["units"].values() if not u["test"])
    assert _pr(set(model["functions"]), set(truth["functions"])) == (set(), set())
    for kind in ("direct", "indirect"):
        got = {(e["caller"], e["callee"]) for e in model["edges"] if e["kind"] == kind}
        want = {(e["caller"], e["callee"]) for e in truth["edges"] if e["kind"] == kind}
        assert _pr(got, want) == (set(), set()), kind
    assert set(model["entry_points"]) == set(truth["entry_points"])
    assert set(model["thread_entries"]) == set(truth.get("thread_entries") or [])
    got_units = {frozenset(u["files"]) for u in model["units"].values()}
    assert all(frozenset(u["files"]) in got_units for u in truth["units"].values())


@pytest.mark.integration
@pytest.mark.slow
def test_gcc_fallback_aliases_and_header_inline_on_the_features_fixture(model_run, tmp_path):
    model = model_run(FIXTURES / "model" / "features", tmp_path / "run", "make")
    assert not pm.validate_model(model)
    nest = model["units"]["libnest.a"]["parse"]
    assert nest["status"] == "gcc_fallback" and "src/nest.c:6" in nest["error"]
    assert model["units"]["libhash.a"]["parse"]["status"] == "ok"
    fns = model["functions"]
    assert fns["src/nest.c#nest_sum"]["source"] == "gcc-callgraph-info"
    assert fns["src/hash.c#crypto_hash_sha512_tweet"]["loops"] == 1
    assert fns["include/api.h#clamp"]["header"] and fns["include/api.h#clamp"]["units"] == ["libhash.a", "libnest.a"]
    edges = {(e["caller"], e["callee"], e["kind"]): e["sources"] for e in model["edges"]}
    assert edges[("src/nest.c#nest_sum", "src/nest.c#add", "direct")] == ["gcc-callgraph-info"]
    assert edges[("src/nest.c#add", "include/api.h#clamp", "direct")] == ["gcc-callgraph-info"]
    assert edges[("src/hash.c#crypto_hash_sha512_tweet", "include/api.h#clamp", "direct")] == ["frama-c-kernel"]
    alias = model["macro_aliases"]["crypto_hash"]
    assert alias["ids"] == ["src/hash.c#crypto_hash_sha512_tweet"] and alias["via"] == ["crypto_hash_sha512"]
    assert any("GCC fallback" in w for w in model["warnings"])


@pytest.mark.integration
@pytest.mark.slow
def test_alias_narrowing_on_the_alias_fixture(model_run, tmp_path):
    model = model_run(FIXTURES / "model" / "alias", tmp_path / "run", "make", "--alias")
    assert not pm.validate_model(model)
    assert model["alias"]["enabled"] and model["alias"]["module"] == "ok"
    assert all(j["alias"]["status"] == "ok" for j in model["parse_jobs"])
    sites = {s["caller"]: s for s in model["indirect_sites"]}
    every = ["src/cb.c#a", "src/cb.c#b", "src/cb.c#c"]
    assert sites["src/cb.c#pick"]["candidates"] == ["src/cb.c#a", "src/cb.c#c"]
    assert sites["src/cb.c#pick"]["narrowing"] == "alias" and sites["src/cb.c#pick"]["dropped"] == ["src/cb.c#b"]
    assert sites["src/cb.c#apply"]["candidates"] == every
    assert sites["src/cb.c#apply"]["narrowing_reason"] == "no_targets"
    # The unsoundness that keeps Alias off by default: set_g makes g point to b.
    assert sites["src/cb.c#fire"]["candidates"] == ["src/cb.c#a"]
    assert sites["src/cb.c#fire"]["dropped"] == ["src/cb.c#b", "src/cb.c#c"]
    off = model_run(FIXTURES / "model" / "alias", tmp_path / "run-off", "make")
    assert {s["narrowing_reason"] for s in off["indirect_sites"]} == {"disabled"}
    assert off["alias"] == {"enabled": False}


@pytest.mark.integration
@pytest.mark.slow
def test_selftest_passes_in_the_image():
    require_docker_images(ANALYSIS_IMAGE)
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none",
         "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro", "--entrypoint", "sh", ANALYSIS_IMAGE,
         "-c", "python3 /opt/framac-pipeline/scripts/phase0_model.py selftest"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(proc.stdout)["ok"] is True


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
