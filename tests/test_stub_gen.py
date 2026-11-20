"""The run's stub overlay, workspace/stubs (docs/plans/templates-and-stubs-improvement-plan.md S2): scripts/stub_gen.py."""

from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path

import pytest

import acsl_ast
import cache
import eacsl_toolchain
import framac_common
import ledger as L
import run_eva_slice
import stub_gen
from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images, write_json
from test_ledger import load, seed, units_by_id
from validate_artifacts import validate_ledger

SNAP = "/framac-run/workspace/snapshot/root"

IMPL_H = """\
int ml_hash(ml_ctx *ctx, const unsigned char *data, size_t len, unsigned char out[32]);
const char *ml_name(const ml_ctx *ctx);
void ml_free(ml_ctx *ctx);
"""
MAIN_H = """\
#include <stddef.h>
typedef struct ml_ctx ml_ctx;
#include "mylib_impl.h"
"""


def _model(**extra) -> dict:
    decl = f"{SNAP}/usr/include/mylib/mylib_impl.h"
    model = {
        "status": "ok",
        "functions": {
            "src/snmp/ber.c#ber_decode_len": {"external_calls": ["ml_hash", "strlen", "ml_name"]},
            "src/a.c#f": {"external_calls": ["undeclared_fn", "proj_fn", "ml_free"]},
        },
        "externals": ["ml_free", "ml_hash", "ml_name", "proj_fn", "strlen", "undeclared_fn", "bsd_fn"],
        "external_formals": {
            "ml_hash": [
                {"name": "ctx", "kind": "pointer"},
                {"name": "data", "kind": "const_pointer"},
                {"name": "len", "kind": "value"},
                {"name": "out", "kind": "pointer"},
            ],
            "ml_name": [{"name": "ctx", "kind": "const_pointer"}],
            "ml_free": [{"name": "ctx", "kind": "pointer"}],
        },
        "external_decls": {
            "ml_hash": {
                "decl": f"{decl}:1",
                "proto": "int ml_hash(ml_ctx *ctx, unsigned char const *data, size_t len, unsigned char out[32])",
            },
            "ml_name": {"decl": f"{decl}:2", "proto": "char const *ml_name(ml_ctx const *ctx)"},
            "ml_free": {"decl": f"{decl}:3", "proto": "void ml_free(ml_ctx *ctx)"},
            "strlen": {"decl": "FRAMAC_SHARE/libc/string.h:178", "proto": "extern size_t strlen(char const *s)"},
            "proj_fn": {"decl": "include/proj.h:4", "proto": "int proj_fn(int x)"},
            "undeclared_fn": {"decl": "src/a.c:3", "proto": "extern int ( /* missing proto */ undeclared_fn)(int x_0)"},
            "bsd_fn": {
                "decl": "/opt/framac-pipeline/templates/fc_stubs/bsd/string.h:9",
                "proto": "size_t bsd_fn(char *d)",
            },
        },
    }
    model.update(extra)
    return model


@pytest.fixture
def stub_run(run_dir, monkeypatch):
    """A run directory with a model, a fake snapshot under `read_root` and the overlay env set."""
    root = run_dir / "fs"
    inc = root / SNAP.lstrip("/") / "usr" / "include" / "mylib"
    inc.mkdir(parents=True)
    (inc / "mylib_impl.h").write_text(IMPL_H, encoding="utf-8")
    (inc / "mylib.h").write_text(MAIN_H, encoding="utf-8")
    write_json(run_dir / stub_gen.DEFAULT_MODEL, _model())
    monkeypatch.setenv("FRAMAC_STUB_OVERLAY_DIR", str(run_dir / "workspace" / "stubs"))

    def run() -> dict:
        rc = stub_gen.cmd_run(
            Path(stub_gen.DEFAULT_MODEL),
            Path(stub_gen.DEFAULT_CAPTURE),
            Path(framac_common.STUB_OVERLAY_REL),
            Path(framac_common.STUB_REPORT_REL),
            read_root=root.as_posix(),
        )
        assert rc == 0
        return json.loads((run_dir / framac_common.STUB_REPORT_REL).read_text(encoding="utf-8"))

    return run


@pytest.mark.unit
def test_classify_sorts_declarations():
    assert stub_gen.classify(None) == ("unknown", "")
    assert stub_gen.classify({"decl": "FRAMAC_SHARE/libc/string.h:1", "proto": "x"})[0] == "libc"
    assert stub_gen.classify({"decl": "/opt/framac-pipeline/templates/fc_stubs/a.h:1", "proto": "x"})[0] == (
        "pipeline_stub"
    )
    assert stub_gen.classify({"decl": "/framac-run/workspace/stubs/a.h:1", "proto": "x"})[0] == "overlay"
    assert stub_gen.classify({"decl": "include/a.h:1", "proto": "x"})[0] == "project_header"
    assert stub_gen.classify({"decl": "/usr/include/z.h:1", "proto": "x"})[0] == "host_header"
    assert stub_gen.classify({"decl": "a.c:3", "proto": "int ( /* missing proto */ f)(int)"})[0] == "undeclared"


@pytest.mark.unit
def test_include_name_uses_the_longest_root():
    capture = {"compiles": [{"system_flags": ["-I/usr/include/mysql", "-isystem/opt/x/include"]}]}
    roots = stub_gen.include_roots(capture)
    assert stub_gen.include_name("/usr/include/mysql/mysql.h", roots) == "mysql.h"
    assert stub_gen.include_name("/usr/include/json-c/json.h", roots) == "json-c/json.h"
    assert stub_gen.include_name("/opt/x/include/a/b.h", roots) == "a/b.h"


@pytest.mark.unit
def test_system_path_maps_both_snapshot_subtrees_back():
    # `libc/` holds the build image's copies of the libc headers Frama-C's libc lacks (O7).
    libc = "/framac-run/workspace/snapshot/libc"
    assert stub_gen.system_path(f"{SNAP}/usr/include/json-c/json.h") == ("/usr/include/json-c/json.h", SNAP)
    assert stub_gen.system_path(f"{libc}/usr/include/linux/netlink.h") == ("/usr/include/linux/netlink.h", libc)
    assert stub_gen.system_path("/usr/include/stdio.h") == ("/usr/include/stdio.h", "")
    generated = "/framac-run/workspace/snapshot/generated/config.h"
    assert stub_gen.system_path(generated) == (generated, "")


@pytest.mark.unit
def test_skeleton_frame_from_the_signature():
    formals = _model()["external_formals"]["ml_hash"]
    lines = stub_gen.skeleton_contract(
        "int ml_hash(ml_ctx *ctx, unsigned char const *data, size_t len, unsigned char out[32])", formals
    )
    text = "\n".join(lines)
    assert r"requires valid_read_data: len > 0 ==> \valid_read(data + (0 .. len - 1));" in text
    assert r"requires valid_out: \valid(out + (0 .. 31));" in text
    assert r"assigns *ctx, out[0 .. 31], \result \from ctx, data, len, out;" in text
    assert "TODO(stub-author): ctx:" in text and "ensures" not in text
    void = stub_gen.skeleton_contract("void ml_free(ml_ctx *ctx)", [{"name": "ctx", "kind": "pointer"}])
    assert r"assigns *ctx \from ctx;" in void
    pure = stub_gen.skeleton_contract("int ml_id(int x)", [{"name": "x", "kind": "value"}])
    assert pure[-1] == r"assigns \result \from x;"


_FROM_PLACEHOLDER_NOTE = "\\from lists every parameter"
# Signatures whose skeleton writes through a pointer, with and without a result and a length.
_WRITING_SIGNATURES = [
    ("int ml_hash(ml_ctx *ctx, unsigned char const *data, size_t len, unsigned char out[32])",
     [{"name": "ctx", "kind": "pointer"}, {"name": "data", "kind": "const_pointer"},
      {"name": "len", "kind": "value"}, {"name": "out", "kind": "pointer"}]),
    ("void ml_free(ml_ctx *ctx)", [{"name": "ctx", "kind": "pointer"}]),
    ("char *ml_fill(char *buf, size_t len, int c)",
     [{"name": "buf", "kind": "pointer"}, {"name": "len", "kind": "value"}, {"name": "c", "kind": "value"}]),
    ("int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)",
     [{"name": "epfd", "kind": "value"}, {"name": "events", "kind": "pointer"},
      {"name": "maxevents", "kind": "value"}, {"name": "timeout", "kind": "value"}]),
]  # fmt: skip


@pytest.mark.unit
@pytest.mark.parametrize("proto, formals", _WRITING_SIGNATURES)
def test_every_skeleton_location_but_result_has_a_from(proto, formals):
    """
    Eva aborts on an `assigns` location other than \\result without `\\from` ([eva:assigns:missing], a
    deferred error: stub_check and Phase 2 Eva). A skeleton filled as written must not hit it.
    """
    contract = "\n".join(line for line in stub_gen.skeleton_contract(proto, formals) if not line.startswith("//"))
    clauses = acsl_ast.extract_frame_clauses(contract)["assigns"]
    assert clauses, contract
    for clause in clauses:
        written = [loc for loc in clause["locs"] if loc not in ("\\result", "\\nothing")]
        assert not written or clause["from"], f"no \\from for {written}: {contract}"
        # Conservative: every named parameter (the inputs the written values may depend on).
        assert not written or set(clause["from"]) == {f["name"] for f in formals}, contract
    # The author learns the \from is a placeholder to complete with what the function reads.
    assert any(_FROM_PLACEHOLDER_NOTE in line for line in stub_gen.skeleton_contract(proto, formals))


@pytest.mark.unit
def test_run_writes_an_inactive_skeleton_in_the_entry_header(stub_run, run_dir):
    report = stub_run()
    assert report["status"] == "ok"
    # mylib_impl.h is reached only through `#include "mylib_impl.h"` in mylib.h: mylib.h is shadowed.
    header = run_dir / "workspace/stubs/mylib/mylib.h"
    text = header.read_text(encoding="utf-8")
    assert "#include_next <mylib/mylib.h>" in text and "#pragma once" in text
    # errno for the contracts: __fc_errno under Eva and WP, __fc_eacsl_errno under E-ACSL (stub_check's errno test).
    assert "#include_next <mylib/mylib.h>\n#include <errno.h>\n" in text
    assert "#include <errno.h>" not in stub_gen.header_preamble("errno.h", "/usr/include/errno.h")
    assert text.count("\n#ifdef FC_STUB_DRAFT\n") == 3
    assert "extern int ml_hash(ml_ctx *ctx, unsigned char const *data, size_t len, unsigned char out[32]);" in text
    rec = report["headers"]["workspace/stubs/mylib/mylib.h"]
    assert rec["include_name"] == "mylib/mylib.h" and rec["real"] == "/usr/include/mylib/mylib.h"
    assert {fn: f["state"] for fn, f in rec["functions"].items()} == {
        "ml_free": "draft",
        "ml_hash": "draft",
        "ml_name": "draft",
    }
    assert rec["functions"]["ml_hash"]["callers"] == ["src/snmp/ber.c#ber_decode_len"]
    assert rec["problems"] == [] and rec["digest"] == stub_gen.sha256_text(text)
    others = report["other_externals"]
    assert [e["function"] for e in others["libc"]] == ["strlen"]
    assert [e["function"] for e in others["project_header"]] == ["proj_fn"]
    assert others["project_header"][0]["declared_in"] == "include/proj.h"
    assert [e["function"] for e in others["undeclared"]] == ["undeclared_fn"]
    assert [e["function"] for e in others["pipeline_stub"]] == ["bsd_fn"]
    assert report["counts"] == {"draft": 3}
    assert report["overlay_digest"] == stub_gen.overlay_digest(run_dir / "workspace/stubs")


@pytest.mark.unit
def test_rerun_keeps_the_authors_contracts_and_appends_new_functions(stub_run, run_dir):
    stub_run()
    header = run_dir / "workspace/stubs/mylib/mylib.h"
    blocks = stub_gen.split_blocks(header.read_text(encoding="utf-8"))
    filled = (
        "/* fc-stub: ml_name */\n/*@\n  requires valid_ctx: \\valid_read(ctx);\n  assigns \\result \\from ctx;\n"
        "  ensures str: \\result == \\null || valid_read_string(\\result);\n*/\n"
        "extern char const *ml_name(ml_ctx const *ctx);\n\n"
    )
    text = header.read_text(encoding="utf-8").replace(blocks["ml_name"], filled)
    text = text.replace(
        blocks["ml_free"], blocks["ml_free"].replace("#ifdef FC_STUB_DRAFT\n", "").replace("#endif\n", "")
    )
    header.write_text(text, encoding="utf-8")
    model = _model()
    model["externals"].append("ml_reset")
    model["external_decls"]["ml_reset"] = {
        "decl": f"{SNAP}/usr/include/mylib/mylib_impl.h:4",
        "proto": "int ml_reset(ml_ctx *ctx)",
    }
    write_json(run_dir / stub_gen.DEFAULT_MODEL, model)
    report = stub_run()
    after = header.read_text(encoding="utf-8")
    assert after.startswith(text.rstrip("\n")) and "/* fc-stub: ml_reset */" in after
    states = {fn: f["state"] for fn, f in report["headers"]["workspace/stubs/mylib/mylib.h"]["functions"].items()}
    assert states == {"ml_free": "incomplete", "ml_hash": "draft", "ml_name": "filled", "ml_reset": "draft"}
    # Nothing new to add: the file is not rewritten.
    stub_run()
    assert header.read_text(encoding="utf-8") == after


@pytest.mark.unit
def test_a_hand_written_header_is_never_touched(stub_run, run_dir):
    header = run_dir / "workspace/stubs/mylib/mylib.h"
    header.parent.mkdir(parents=True)
    own = "/*@ assigns \\result \\from ctx; */\nconst char *ml_name(const ml_ctx *ctx);\nvoid ml_free(ml_ctx *ctx);\n"
    header.write_text(own, encoding="utf-8")
    report = stub_run()
    assert header.read_text(encoding="utf-8") == own
    functions = report["headers"]["workspace/stubs/mylib/mylib.h"]["functions"]
    assert functions == {
        "ml_name": {
            "state": "manual",
            "callers": ["src/snmp/ber.c#ber_decode_len"],
            "declared_in": "/usr/include/mylib/mylib_impl.h",
        }
    }


@pytest.mark.unit
def test_function_bodies_are_reported(stub_run, run_dir):
    stub_run()
    header = run_dir / "workspace/stubs/mylib/mylib.h"
    header.write_text(header.read_text(encoding="utf-8") + "\nint helper(void) { return 0; }\n", encoding="utf-8")
    report = stub_run()
    assert report["headers"]["workspace/stubs/mylib/mylib.h"]["problems"] == [
        "workspace/stubs/mylib/mylib.h: function body for helper: an overlay header holds contracts only"
    ]


@pytest.mark.unit
def test_a_model_without_declarations_writes_no_skeleton(stub_run, run_dir):
    model = _model()
    del model["external_decls"]
    write_json(run_dir / stub_gen.DEFAULT_MODEL, model)
    report = stub_run()
    assert report["status"] == "model_without_declarations" and report["headers"] == {}
    assert len(report["other_externals"]["unknown"]) == len(model["externals"])


@pytest.mark.unit
def test_missing_model_fails(run_dir):
    assert stub_gen.main(["run"]) == 1


@pytest.mark.unit
@pytest.mark.parametrize(
    "block",
    [
        "/* fc-stub: f */\n/*@\n  requires \\valid(p);\n  // assigns *p \\from p;\n*/\nextern void f(int *p);\n",
        "/* fc-stub: f */\n/*@\n  requires \\valid(p);\n  //@ assigns *p \\from p;\n*/\nextern void f(int *p);\n",
        "/* fc-stub: f */\n/*@* assigns \\nothing; */\nextern void f(int *p);\n",
        "/* fc-stub: f */\n/*@{ assigns \\nothing; */\nextern void f(int *p);\n",
        "/* fc-stub: f */\n//@* assigns \\nothing;\nextern void f(int *p);\n",
        "/* fc-stub: f */\n//@ requires \\valid(p); //@ assigns *p \\from p;\nextern void f(int *p);\n",
        '/* fc-stub: f */\n/*@ requires s != "assigns \\nothing;"; */\nextern void f(const char *s);\n',
        "/* fc-stub: f */\n/* assigns \\nothing; */\nextern int f(int assigns);\n",
    ],
)
def test_block_state_ignores_commented_nested_and_doxygen_assigns(block):
    assert stub_gen.block_state(block) == "incomplete"


@pytest.mark.unit
@pytest.mark.parametrize(
    "block",
    [
        "/* fc-stub: f */\n/*@ assigns @ \\result \\from x; */\nextern int f(int x);\n",
        (
            "/* fc-stub: f */\n"
            "/*@ // frame\n"
            "  @ assigns // comment\n"
            "  @   *p \\from p; // note\n"
            "  @*/\n"
            "extern void f(int *p);\n"
        ),
        "/* fc-stub: f */\n//@ assigns \\nothing;\nextern void f(void);\n",
    ],
)
def test_block_state_accepts_real_assigns_with_comments_and_at_signs(block):
    assert stub_gen.block_state(block) == "filled"


@pytest.mark.unit
def test_brief_names_the_header_and_its_open_functions(stub_run, run_dir, capsys):
    stub_run()
    capsys.readouterr()
    assert stub_gen.main(["brief", "--header", "workspace/stubs/mylib/mylib.h"]) == 0
    text = capsys.readouterr().out
    assert "**`workspace/stubs/mylib/mylib.h`**" in text and "`<mylib/mylib.h>`" in text
    assert "ml_free, ml_hash, ml_name" in text and "src/snmp/ber.c#ber_decode_len" in text
    assert "{" + "header}" not in text
    assert stub_gen.main(["brief", "--header", "workspace/stubs/nope.h"]) == 1


@pytest.mark.unit
def test_overlay_is_first_on_the_include_paths(tmp_path, monkeypatch):
    overlay = tmp_path / "stubs"
    monkeypatch.setenv("FRAMAC_STUB_OVERLAY_DIR", str(overlay))
    assert f"-I{overlay.as_posix()}" not in framac_common.augment_framac_cppflags("-Isrc")
    overlay.mkdir()
    words = shlex.split(framac_common.augment_framac_cppflags("-Isrc"))
    flag = f"-I{overlay.as_posix()}"
    assert words[0] == flag and words.count(flag) == 1
    fc_stubs = framac_common.resolve_fc_stubs_dir()
    assert fc_stubs is not None and words.index(flag) < words.index(f"-I{fc_stubs.as_posix()}")
    assert shlex.split(framac_common.augment_framac_cppflags(f"{flag} -Isrc")).count(flag) == 1
    front = shlex.split(eacsl_toolchain.build_eacsl_flag_sets("-Isrc")["frontend"])
    assert flag in front and front.index(flag) < front.index(f"-I{fc_stubs.as_posix()}")


@pytest.mark.unit
def test_hints_name_the_overlay_header(stub_run, run_dir):
    stub_run()
    hints = run_eva_slice.extract_repair_hints("[kernel] Neither code nor specification for function ml_hash,\n")
    assert "workspace/stubs/mylib/mylib.h" in hints[0]["action"]
    assert "stub_gen.py brief --header workspace/stubs/mylib/mylib.h" in hints[0]["action"]
    other = run_eva_slice.extract_repair_hints("[kernel] Neither code nor specification for function zz,\n")
    assert "workspace/stubs/<lib>.h" in other[0]["action"] and "pipeline_make.py run stubs" in other[0]["action"]


@pytest.mark.unit
def test_cache_key_follows_the_overlay(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:test")
    overlay = tmp_path / "stubs"
    monkeypatch.setenv("FRAMAC_STUB_OVERLAY_DIR", str(overlay))
    k0 = cache.make_key("eva", {"a": 1})
    overlay.mkdir()
    assert cache.make_key("eva", {"a": 1}) == k0  # an empty overlay changes nothing
    (overlay / "z.h").write_text("/*@ assigns \\nothing; */ int z(void);\n", encoding="utf-8")
    k1 = cache.make_key("eva", {"a": 1})
    (overlay / "z.h").write_text("/*@ assigns \\result; */ int z(void);\n", encoding="utf-8")
    assert len({k0, k1, cache.make_key("eva", {"a": 1})}) == 3


@pytest.mark.unit
def test_ledger_records_active_stub_contracts(stub_run, run_dir):
    assert L.cmd_record_stub_contracts(Path(framac_common.STUB_REPORT_REL))["skipped_reason"].startswith("no ledger")
    seed(run_dir)
    report = stub_run()
    out = L.cmd_record_stub_contracts(Path(framac_common.STUB_REPORT_REL))
    assert out["recorded"] == 0  # every block is a draft
    header = run_dir / "workspace/stubs/mylib/mylib.h"
    block = stub_gen.split_blocks(header.read_text(encoding="utf-8"))["ml_hash"]
    done = block.replace("#ifdef FC_STUB_DRAFT\n", "").replace("#endif\n", "")
    done = "\n".join(line for line in done.splitlines() if "TODO(stub-author)" not in line) + "\n"
    header.write_text(header.read_text(encoding="utf-8").replace(block, done), encoding="utf-8")
    report = stub_run()
    digest = report["headers"]["workspace/stubs/mylib/mylib.h"]["digest"][:12]
    assert report["headers"]["workspace/stubs/mylib/mylib.h"]["functions"]["ml_hash"]["state"] == "filled"
    assert L.main(["record-stub-contracts"]) == 0
    units = units_by_id(run_dir)
    rte = units["src/snmp/ber.c#ber_decode_len::rte"]
    stub = [a for a in rte["assumptions"] if a["kind"] == "stub_contract"]
    assert [a["description"] for a in stub] == [
        f"Overlay stub contract of ml_hash in workspace/stubs/mylib/mylib.h (sha256 {digest}, filled) is assumed, not proven."
    ]
    assert list(validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []
    # Idempotent; an edit replaces the assumption instead of adding a second one.
    before = load(run_dir / "coverage-ledger.json")
    assert L.cmd_record_stub_contracts(Path(framac_common.STUB_REPORT_REL))["units_changed"] == 0
    assert load(run_dir / "coverage-ledger.json") == before
    header.write_text(header.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    stub_run()
    L.cmd_record_stub_contracts(Path(framac_common.STUB_REPORT_REL))
    rte = units_by_id(run_dir)["src/snmp/ber.c#ber_decode_len::rte"]
    assert len([a for a in rte["assumptions"] if a["kind"] == "stub_contract"]) == 1


@pytest.mark.unit
def test_seed_records_active_stub_contracts(stub_run, run_dir):
    """
    The hand route of Phase 0 Step 5 runs `ledger.py seed` without `record-stub-contracts` (c-ares run-1:
    5 filled contracts, 0 assumptions). The seed records them itself, with the stub-check status, and the
    make route's `record-stub-contracts` after it changes nothing.
    """
    stub_run()
    header = run_dir / "workspace/stubs/mylib/mylib.h"
    block = stub_gen.split_blocks(header.read_text(encoding="utf-8"))["ml_hash"]
    done = block.replace("#ifdef FC_STUB_DRAFT\n", "").replace("#endif\n", "")
    done = "\n".join(line for line in done.splitlines() if "TODO(stub-author)" not in line) + "\n"
    header.write_text(header.read_text(encoding="utf-8").replace(block, done), encoding="utf-8")
    report = stub_run()
    rec = report["headers"]["workspace/stubs/mylib/mylib.h"]
    write_json(
        run_dir / "workspace/reports/stub_check.json",
        {
            "headers": {
                "workspace/stubs/mylib/mylib.h": {
                    "digest": rec["digest"],
                    "status": "passed",
                    "dynamic": {"functions": {"ml_hash": {"status": "passed"}}},
                }
            }
        },
    )
    out = seed(run_dir)
    rte = units_by_id(run_dir)["src/snmp/ber.c#ber_decode_len::rte"]
    assert [a["description"] for a in rte["assumptions"] if a["kind"] == "stub_contract"] == [
        f"Overlay stub contract of ml_hash in workspace/stubs/mylib/mylib.h (sha256 {rec['digest'][:12]}, filled)"
        " is assumed, not proven; stub-check: dynamic passed."
    ]
    assert out["stub_contracts"]["recorded"] >= 1
    assert list(validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []
    before = (run_dir / "coverage-ledger.json").read_bytes()
    assert L.main(["record-stub-contracts"]) == 0
    assert (run_dir / "coverage-ledger.json").read_bytes() == before
    seed(run_dir)
    assert (run_dir / "coverage-ledger.json").read_bytes() == before


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_contract_reaches_eva_in_the_image(tmp_path):
    """
    The plan's "done when": the dump records the declaration, `stub_gen.py run` writes a skeleton that
    Eva ignores (missing spec), and the filled block removes Eva's missing-spec warning.
    """
    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "inc" / "mylib").mkdir(parents=True)
    (tmp_path / "inc" / "mylib" / "mylib.h").write_text(MAIN_H, encoding="utf-8")
    (tmp_path / "inc" / "mylib" / "mylib_impl.h").write_text(IMPL_H, encoding="utf-8")
    (tmp_path / "a.c").write_text(
        "#include <mylib/mylib.h>\n"
        "int main(void) { unsigned char d[4] = {0}, o[32]; return ml_hash((ml_ctx *)0, d, 4, o) + o[0]; }\n",
        encoding="utf-8",
    )
    script = r"""
set -e
cp -r /w /tmp/w && cd /tmp/w
S=/opt/framac-pipeline/scripts
cp $S/phase0_dump.ml . && ocamlfind ocamlopt -shared -w -a -package frama-c.kernel phase0_dump.ml -o d.cmxs
FRAMAC_P0_DUMP_OUT=/tmp/w/dump.json frama-c -no-annot -cpp-extra-args="-I/tmp/w/inc" a.c -load-module ./d.cmxs >/dev/null
python3 - <<'EOF'
import json
d = json.load(open("dump.json"))
decl = {x["name"]: x for x in d["declared"]}["ml_hash"]
formals = {x["name"]: x["formals"] for x in d["declared"]}
model = {"status": "ok", "functions": {"a.c#main": {"external_calls": ["ml_hash"]}}, "externals": ["ml_hash"],
         "external_formals": {"ml_hash": decl["formals"]},
         "external_decls": {"ml_hash": {"decl": "/tmp/w/" + decl["decl"], "proto": decl["proto"]}}}
json.dump(model, open("model.json", "w"))
EOF
cat > cap.json <<'EOF'
{"compiles": [{"system_flags": ["-I/tmp/w/inc"]}]}
EOF
python3 $S/stub_gen.py run --model model.json --capture cap.json --overlay stubs --out stubs.json >/dev/null
test -f stubs/mylib/mylib.h
eva() { frama-c -cpp-extra-args="-I/tmp/w/stubs -I/tmp/w/inc" a.c -eva -eva-no-alloc-returns-null 2>&1; }
eva > draft.log || true
grep -c "Neither code nor specification for function ml_hash" draft.log | sed 's/^/draft_missing=/'
python3 - <<'EOF'
p = "stubs/mylib/mylib.h"
t = open(p).read()
t = "\n".join(l for l in t.splitlines() if "TODO(stub-author)" not in l and "FC_STUB_DRAFT" not in l and l != "#endif") + "\n"
open(p, "w").write(t)
EOF
eva > filled.log || true
echo "filled_missing=$(grep -c 'Neither code nor specification for function ml_hash' filled.log || true)"
python3 $S/stub_gen.py run --model model.json --capture cap.json --overlay stubs --out stubs.json >/dev/null
python3 -c "import json; print('state=' + json.load(open('stubs.json'))['headers']['workspace/stubs/mylib/mylib.h']['functions']['ml_hash']['state'])"
"""
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none",
         "-v", f"{tmp_path}:/w:ro", "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
         "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
         "--entrypoint", "sh", ANALYSIS_IMAGE, "-c", script],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, check=False,
    )  # fmt: skip
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "draft_missing=1" in out, out
    assert "filled_missing=0" in out, out
    assert "state=filled" in out, out


# A library whose functions cover each skeleton shape: a range, a fixed-size array and an object written
# with a result, a void writer, a pointer result, a result alone without parameters, nothing at all.
_SK_FUNCTIONS = {
    "sk_hash": ("int sk_hash(struct sk_ctx *ctx, unsigned char const *data, size_t len, unsigned char out[32])",
                [{"name": "ctx", "kind": "pointer"}, {"name": "data", "kind": "const_pointer"},
                 {"name": "len", "kind": "value"}, {"name": "out", "kind": "pointer"}]),
    "sk_reset": ("void sk_reset(struct sk_ctx *ctx)", [{"name": "ctx", "kind": "pointer"}]),
    "sk_name": ("char *sk_name(struct sk_ctx *ctx, int which)",
                [{"name": "ctx", "kind": "pointer"}, {"name": "which", "kind": "value"}]),
    "sk_fill": ("int sk_fill(char *buf, size_t len, int c)",
                [{"name": "buf", "kind": "pointer"}, {"name": "len", "kind": "value"}, {"name": "c", "kind": "value"}]),
    "sk_count": ("int sk_count(void)", []),
    "sk_tick": ("void sk_tick(void)", []),
}  # fmt: skip


@pytest.mark.integration
@pytest.mark.slow
def test_a_skeleton_filled_as_written_passes_eva_in_the_image(tmp_path):
    """
    c-ares run-1: a skeleton's `assigns *p, \\result;` filled as written aborted Eva
    ([eva:assigns:missing] no \\from part for clause). Guard and TODO lines removed, nothing else
    changed, every skeleton shape must let Eva run to the end (stub_check's Eva, Phase 2 Eva).
    """
    require_docker_images(ANALYSIS_IMAGE)
    real = tmp_path / "inc" / "sk" / "sk.h"
    real.parent.mkdir(parents=True)
    real.write_text(
        "#include <stddef.h>\nstruct sk_ctx { int n; char *p; };\n"
        + "".join(f"{proto};\n" for proto, _ in _SK_FUNCTIONS.values()),
        encoding="utf-8",
        newline="\n",
    )
    blocks = "".join(stub_gen.draft_block(name, proto, formals) for name, (proto, formals) in _SK_FUNCTIONS.items())
    filled = "\n".join(
        line
        for line in (stub_gen.header_preamble("sk/sk.h", "/w/inc/sk/sk.h") + blocks).splitlines()
        if stub_gen.TODO_MARK not in line and stub_gen.DRAFT_GUARD not in line and line != "#endif"
    )
    overlay = tmp_path / "stubs" / "sk" / "sk.h"
    overlay.parent.mkdir(parents=True)
    overlay.write_text(filled + "\n", encoding="utf-8", newline="\n")
    (tmp_path / "a.c").write_text(
        "#include <sk/sk.h>\n"
        "int main(void) {\n"
        "  struct sk_ctx c = {0, 0};\n"
        "  unsigned char d[4] = {0}, o[32];\n"
        "  char b[8];\n"
        "  int r = sk_hash(&c, d, 4, o);\n"
        "  sk_reset(&c);\n"
        "  char *n = sk_name(&c, 1);\n"
        "  r += sk_fill(b, 8, 'a');\n"
        "  r += sk_count();\n"
        "  sk_tick();\n"
        "  return r + o[0] + b[0] + c.n + (n != 0);\n"
        "}\n",
        encoding="utf-8",
        newline="\n",
    )
    script = (
        "cd /w && timeout 300 frama-c -no-unicode -machdep gcc_x86_64 -cpp-extra-args='-I/w/stubs -I/w/inc' a.c "
        "-eva -eva-no-alloc-returns-null; echo \"frama_c_exit=$?\""
    )
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-v", f"{tmp_path}:/w:ro",
         "--entrypoint", "sh", ANALYSIS_IMAGE, "-c", script],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, check=False,
    )  # fmt: skip
    out = proc.stdout + proc.stderr
    # `assigns \\result;` alone (sk_count) is only a warning, [eva:assigns:missing-result].
    assert "[eva:assigns:missing]" not in out and "no \\from part" not in out, out
    assert "frama_c_exit=0" in out, out
    assert "====== VALUES COMPUTED ======" in out or "[eva] done" in out, out
    assert "Neither code nor specification" not in out, out


@pytest.mark.unit
def test_a_stub_edit_invalidates_only_the_keys_that_read_it(tmp_path, monkeypatch):
    """K2: a key with a dependency manifest is keyed on the stub headers it read, not on all of them."""
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:test")
    scripts, templates = tmp_path / "scripts", tmp_path / "templates"
    (templates / "fc_stubs").mkdir(parents=True)
    scripts.mkdir()
    (scripts / "a.py").write_text("x = 1\n", encoding="utf-8")
    (templates / "pipeline.mk").write_text("all:\n", encoding="utf-8")
    stub = templates / "fc_stubs" / "zlib.h"
    stub.write_text("int z(void);\n", encoding="utf-8")
    monkeypatch.setattr(cache, "_SCRIPTS_DIR", scripts)
    monkeypatch.setattr(cache, "_TEMPLATES_DIR", templates)
    monkeypatch.setattr(cache, "_scripts_memo", {})
    overlay = tmp_path / "stubs"
    overlay.mkdir()
    (overlay / "o.h").write_text("int o(void);\n", encoding="utf-8")
    monkeypatch.setenv("FRAMAC_STUB_OVERLAY_DIR", str(overlay))
    reads = {"deps": [["a.c", "1" * 64], [stub.as_posix(), "2" * 64]]}
    other = {"deps": [["b.c", "3" * 64]]}
    plain = {"text": "x"}
    before = [cache.make_key("eva", m) for m in (reads, other, plain)]
    # Edit the shipped stub and the overlay: keys with a manifest change only through their deps.
    stub.write_text("/*@ assigns \\nothing; */ int z(void);\n", encoding="utf-8")
    (overlay / "o.h").write_text("/*@ assigns \\nothing; */ int o(void);\n", encoding="utf-8")
    monkeypatch.setattr(cache, "_scripts_memo", {})
    reads_after = {"deps": [["a.c", "1" * 64], [stub.as_posix(), "4" * 64]]}
    after = [cache.make_key("eva", m) for m in (reads_after, other, plain)]
    assert after[1] == before[1]  # read neither stub
    assert after[0] != before[0]  # its manifest names the edited stub
    assert after[2] != before[2]  # no manifest: every stub counts
    assert cache.make_key("eva", reads) == before[0]
    # Anything else under templates/ still counts for every key.
    (templates / "pipeline.mk").write_text("all: x\n", encoding="utf-8")
    monkeypatch.setattr(cache, "_scripts_memo", {})
    assert cache.make_key("eva", other) != before[1]
