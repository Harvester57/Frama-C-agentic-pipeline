"""Tests for scripts/fuzz_assets.py: the target's own fuzzers and corpora (discover, map, import, write)."""

from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

import pytest

import fuzz_assets as fa
import validate_artifacts
from generate_harness import _build_dispatch_invocation

pytestmark = pytest.mark.unit

PNG_FUZZER = """\
#include <stdint.h>
#include "png.h"
/* LLVMFuzzerTestOneInput(int x) { in a comment } */
static void helper(const uint8_t *Data) { (void)Data; }
int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;   // log("Data(") must not count
    png_parse((const char *)Data, (int)(Size - 1));
    png_reset(0);
    helper(Data + 1);
    return 0;
}
"""

HARNESS_TEMPLATE = """\
int eva_main(void) {{ /* Invoke target module entry point */ (void)0; return 0; }}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    uint8_t *fuzz_buf = bounded_buf;
    size_t fuzz_len = size;
    /* Invoke target module entry point */
    {fuzz}
    free(alloc_ptr);
    return 0;
}}
"""


def _zip(path: Path, entries: list[tuple[zipfile.ZipInfo | str, bytes]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries:
            zf.writestr(name, data)


def _oss_fuzz_target(root: Path) -> Path:
    t = root / "target"
    (t / "fuzz").mkdir(parents=True)
    (t / "src").mkdir()
    (t / "src" / "png.c").write_text("int png_parse(const char *p, int n) { return n; }\n", encoding="utf-8")
    (t / "fuzz" / "png_fuzzer.c").write_text(PNG_FUZZER, encoding="utf-8")
    (t / "fuzz" / "png_fuzzer.dict").write_text(
        '# header\n\n"IHDR"\nkw1="\\x89PNG"\nnot an entry\n"unterminated\n"bad \\q escape"\n', encoding="utf-8"
    )
    (t / "fuzz" / "png_fuzzer.options").write_text("[libfuzzer]\nmax_len = 70000\n", encoding="utf-8")
    _zip(t / "fuzz" / "png_fuzzer_seed_corpus.zip", [("a.png", b"\x89PNG-a"), ("b.png", b"\x89PNG-bb")])
    (t / "fuzz" / "json_fuzzer.cc").write_text(
        'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { json_load(data, size); return 0; }\n',
        encoding="utf-8",
    )
    (t / "corpus" / "json_fuzzer").mkdir(parents=True)
    (t / "corpus" / "json_fuzzer" / "one.json").write_text("{}", encoding="utf-8")
    (t / "corpus" / "json_fuzzer" / "two.json").write_text("[1]", encoding="utf-8")
    _zip(t / ".git" / "objects" / "x_seed_corpus.zip", [("x", b"x")])
    (t / ".git" / "fuzz.c").write_text(PNG_FUZZER, encoding="utf-8")
    return t


def _discover(run: Path, target: Path, capsys) -> dict:
    assert fa.main(["discover", "--target", str(target)]) == 0
    capsys.readouterr()
    return json.loads((run / "workspace" / "reports" / "fuzz_assets.json").read_text(encoding="utf-8"))


def _load(run: Path) -> dict:
    return json.loads((run / "workspace" / "reports" / "fuzz_assets.json").read_text(encoding="utf-8"))


# --- discover -----------------------------------------------------------------------------------------


def test_oss_fuzz_naming_auto_maps(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    target = _oss_fuzz_target(tmp_path)
    doc = _discover(tmp_path, target, capsys)
    fuzzers = {f["id"]: f for f in doc["fuzzers"]}
    assert sorted(fuzzers) == ["json_fuzzer", "png_fuzzer"]  # .git skipped, src/png.c is no fuzzer
    png = fuzzers["png_fuzzer"]
    assert png["path"] == "fuzz/png_fuzzer.c" and png["work_path"] == "workspace/work/fuzz/png_fuzzer.c"
    assert png["language"] == "c" and png["status"] == "usable" and png["reason"] is None
    assert png["defines_initialize"] is True
    assert (png["data_param"], png["size_param"]) == ("Data", "Size")
    assert png["direct_api_calls"] == ["helper", "png_parse"]  # casts and arithmetic; png_reset(0) is not
    assert png["dict"] == "fuzz/png_fuzzer.dict"
    assert png["options"] == {"max_len": 70000, "dict": None}
    assert png["suggested_max_input_size"] == 70000
    js = fuzzers["json_fuzzer"]
    assert (js["language"], js["status"], js["reason"]) == ("cxx", "unsupported", "cxx")
    assert js["direct_api_calls"] == ["json_load"] and js["defines_initialize"] is False
    assert js["suggested_max_input_size"] == 4096
    corpora = {c["id"]: c for c in doc["corpora"]}
    assert corpora["png_fuzzer"] == {
        "id": "png_fuzzer",
        "path": "fuzz/png_fuzzer_seed_corpus.zip",
        "kind": "zip",
        "files": 2,
        "bytes": 13,
        "imported": None,
        "dir": None,
    }
    assert corpora["json_fuzzer"]["kind"] == "dir" and corpora["json_fuzzer"]["files"] == 2
    assert sorted(corpora) == ["json_fuzzer", "png_fuzzer"]
    assert {(m["corpus"], m["fuzzer"], m["source"]) for m in doc["mappings"]} == {
        ("png_fuzzer", "png_fuzzer", "auto"),
        ("json_fuzzer", "json_fuzzer", "auto"),
    }
    # only the valid dictionary entries are kept
    kept = (tmp_path / "workspace" / "fuzz_assets" / "dicts" / "png_fuzzer.dict").read_text(encoding="utf-8")
    assert kept.splitlines() == ['"IHDR"', 'kw1="\\x89PNG"']
    assert not validate_artifacts.validate_fuzz_assets(doc)
    assert not validate_artifacts.validate_phase0_artifacts(tmp_path)


def test_c_ares_layout_stays_unmapped_and_agent_maps_survive(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    t = tmp_path / "target"
    (t / "test" / "fuzzinput").mkdir(parents=True)
    (t / "test" / "fuzznames").mkdir()
    (t / "test" / "ares-test-fuzz.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char *data,\n unsigned long size)\n{\n"
        "  ares_parse_a_reply(data, (int)size, 0, 0, 0);\n  return 0;\n}\n",
        encoding="utf-8",
    )
    (t / "test" / "ares-test-fuzz-name.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return 0; }\n", encoding="utf-8"
    )
    (t / "test" / "ares-test.cc").write_text("int main() { return 0; }\n", encoding="utf-8")
    for i in range(3):
        (t / "test" / "fuzzinput" / f"answer_{i}").write_bytes(bytes([i + 1]) * 5)
    (t / "test" / "fuzznames" / "name1").write_bytes(b"example.com")
    # a fuzz directory of sources is no corpus
    (t / "fuzz").mkdir()
    (t / "fuzz" / "build.sh").write_text("cc x.c\n", encoding="utf-8")
    (t / "fuzz" / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    doc = _discover(tmp_path, t, capsys)
    assert sorted(c["id"] for c in doc["corpora"]) == ["fuzzinput", "fuzznames"]
    assert doc["mappings"] == []
    fz = {f["id"]: f for f in doc["fuzzers"]}
    assert fz["ares-test-fuzz"]["direct_api_calls"] == ["ares_parse_a_reply"]
    assert fz["ares-test-fuzz-name"]["direct_api_calls"] == []
    assert fa.main(["map", "--corpus", "fuzzinput", "--fuzzer", "ares-test-fuzz"]) == 0
    assert fa.main(["map", "--corpus", "fuzznames", "--ignore", "--reason", "names, not answers"]) == 0
    capsys.readouterr()
    assert fa.main(["import"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["imported"] == {"fuzzinput": 3} and out["unmapped"] == []
    doc = _load(tmp_path)
    assert {c["id"]: c["imported"] is not None for c in doc["corpora"]} == {"fuzzinput": True, "fuzznames": False}
    assert doc["fuzzers"][0]["suggested_max_input_size"] == 4096  # 5-byte inputs: clamped up
    # discover again: the agent's mappings and the unchanged corpus's import survive
    doc = _discover(tmp_path, t, capsys)
    rows = {m["corpus"]: m for m in doc["mappings"]}
    assert rows["fuzzinput"]["source"] == "agent" and rows["fuzzinput"]["fuzzer"] == "ares-test-fuzz"
    assert rows["fuzznames"]["ignored"] is True and rows["fuzznames"]["reason"] == "names, not answers"
    assert next(c for c in doc["corpora"] if c["id"] == "fuzzinput")["imported"]["kept"] == 3


def test_run_input_corpus_maps_by_fuzzer_id(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    target = _oss_fuzz_target(tmp_path)
    (tmp_path / "inputs" / "corpora" / "png_fuzzer").mkdir(parents=True)
    (tmp_path / "inputs" / "corpora" / "png_fuzzer" / "c1").write_bytes(b"\x89PNG-ext")
    (tmp_path / "inputs" / "corpora" / "other").mkdir()
    doc = _discover(tmp_path, target, capsys)
    runs = [c for c in doc["corpora"] if c["kind"] == "run_input"]
    assert [(c["id"], c["path"]) for c in runs] == [
        ("other", "inputs/corpora/other"),
        ("png_fuzzer-2", "inputs/corpora/png_fuzzer"),
    ]
    rows = {m["corpus"]: m["fuzzer"] for m in doc["mappings"]}
    assert rows["png_fuzzer-2"] == "png_fuzzer" and "other" not in rows


def test_direct_api_calls_and_ids():
    info = fa.analyse_fuzzer_source(
        "int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {\n"
        "  if (len > 3 && check(buf[0])) { parse_hdr((struct hdr *)(buf + 1), len - 1); }\n"
        '  log_msg("parse(buf, len)");\n'
        "  for (size_t i = 0; i < len; i++) {}\n"
        "  return sizeof(len);\n}\n"
    )
    assert info is not None and info["direct_api_calls"] == ["check", "parse_hdr"]
    assert fa.analyse_fuzzer_source("int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);") is None
    unnamed = fa.analyse_fuzzer_source("int LLVMFuzzerTestOneInput(const uint8_t *, size_t) { f(0); return 0; }")
    assert unnamed is not None and unnamed["data_param"] is None and unnamed["direct_api_calls"] == []
    assert fa.unique_ids(["a b", "a_b", "..", "x/y"], "c") == ["a_b", "a_b-2", "_..", "x_y"]
    assert all(fa._MODULE_RE.match(f"tf_{i}") for i in fa.unique_ids(["x" * 300, "é"], "f"))


def test_dict_entries_filter():
    text = '# c\n"a"\nname="b\\\\c\\"d"\n  "x\\xAF"  \n"\\xZZ"\nraw\n=\n"a"b"\n'
    assert fa.dict_entries(text) == ['"a"', 'name="b\\\\c\\"d"', '"x\\xAF"']


def test_symlinks_are_never_followed(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_bytes(b"SECRET")
    (outside / "x_fuzzer.c").write_text(PNG_FUZZER, encoding="utf-8")
    t = tmp_path / "target"
    (t / "seeds").mkdir(parents=True)
    (t / "seeds" / "good").write_bytes(b"ok")
    try:
        os.symlink(outside / "secret", t / "seeds" / "link")
        os.symlink(outside, t / "fuzz_corpus", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks here")
    doc = _discover(tmp_path, t, capsys)
    assert doc["fuzzers"] == []  # outside/x_fuzzer.c is behind a symlink
    assert [c["id"] for c in doc["corpora"]] == ["seeds"]
    assert doc["corpora"][0]["files"] == 1
    assert fa.main(["map", "--corpus", "seeds", "--function", "parse"]) == 0
    assert fa.main(["import"]) == 0
    imp = _load(tmp_path)["corpora"][0]["imported"]
    assert imp["kept"] == 1 and imp["dropped"]["symlink"] == 1
    stored = [p.read_bytes() for p in (tmp_path / "workspace" / "fuzz_assets" / "corpora" / "seeds").iterdir()]
    assert stored == [b"ok"]


# --- import -------------------------------------------------------------------------------------------


def test_zip_import_is_safe(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(fa, "MAX_INPUT_BYTES", 8)
    t = tmp_path / "target"
    link = zipfile.ZipInfo("link")
    link.create_system = 3
    link.external_attr = 0o120777 << 16
    fifo = zipfile.ZipInfo("fifo")
    fifo.create_system = 3
    fifo.external_attr = 0o010644 << 16
    _zip(
        t / "evil_seed_corpus.zip",
        [
            ("../../evil", b"EVIL"),
            ("/abs/path", b"ABS"),
            ("dir/", b""),
            (link, b"/etc/passwd"),
            (fifo, b"F"),
            ("big", b"B" * 20),
            ("empty", b""),
            ("dup", b"EVIL"),
            ("ok", b"fine"),
        ],
    )
    (t / "bad_seed_corpus.zip").write_bytes(b"PK\x03\x04 not really a zip")
    doc = _discover(tmp_path, t, capsys)
    assert any("bad_seed_corpus.zip: unreadable zip" in w for w in doc["warnings"])
    for cid in ("evil", "bad"):
        assert fa.main(["map", "--corpus", cid, "--function", "parse"]) == 0
    assert fa.main(["import"]) == 0
    doc = _load(tmp_path)
    c = {x["id"]: x for x in doc["corpora"]}
    assert c["evil"]["imported"] == {
        "kept": 3,
        "bytes": 11,
        "max_input_bytes": 4,
        "dropped": {"too_large": 1, "over_cap": 0, "empty": 1, "symlink": 1, "not_regular": 1, "unreadable": 0},
    }
    assert c["evil"]["dir"] == "workspace/fuzz_assets/corpora/evil"
    assert c["bad"]["imported"]["kept"] == 0 and c["bad"]["imported"]["dropped"]["unreadable"] == 1
    assert any(w.startswith("corpus bad: unreadable zip") for w in doc["warnings"])
    out = tmp_path / "workspace" / "fuzz_assets" / "corpora" / "evil"
    assert sorted(p.read_bytes() for p in out.iterdir()) == [b"ABS", b"EVIL", b"fine"]
    assert all(len(p.name) == 16 for p in out.iterdir())
    assert not (tmp_path / "evil").exists() and not (tmp_path / "workspace" / "evil").exists()
    assert not validate_artifacts.validate_fuzz_assets(doc)


def test_import_caps_and_unmapped_warning(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    t = tmp_path / "target"
    (t / "corpus" / "a").mkdir(parents=True)
    (t / "corpus" / "b").mkdir(parents=True)
    for i in range(4):
        (t / "corpus" / "a" / f"in{i}").write_bytes(bytes([65 + i]) * (i + 1))
    (t / "corpus" / "b" / "x").write_bytes(b"x")
    _discover(tmp_path, t, capsys)
    assert fa.main(["map", "--corpus", "a", "--function", "f"]) == 0
    monkeypatch.setattr(fa, "MAX_INPUTS_PER_CORPUS", 2)
    assert fa.main(["import"]) == 0
    doc = _load(tmp_path)
    imp = next(c for c in doc["corpora"] if c["id"] == "a")["imported"]
    assert imp["kept"] == 2 and imp["dropped"]["over_cap"] == 2 and imp["bytes"] == 3
    assert any(w.startswith("unmapped corpora not imported: b") for w in doc["warnings"])
    monkeypatch.setattr(fa, "MAX_INPUTS_PER_CORPUS", 100)
    monkeypatch.setattr(fa, "MAX_CORPUS_BYTES", 6)
    assert fa.main(["import"]) == 0
    imp = next(c for c in _load(tmp_path)["corpora"] if c["id"] == "a")["imported"]
    assert imp["kept"] == 3 and imp["bytes"] == 6 and imp["dropped"]["over_cap"] == 1
    assert len(list((tmp_path / "workspace" / "fuzz_assets" / "corpora" / "a").iterdir())) == 3


def test_map_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert fa.main(["map", "--corpus", "x", "--fuzzer", "y"]) == 2  # no report yet
    target = _oss_fuzz_target(tmp_path)
    _discover(tmp_path, target, capsys)
    assert fa.main(["map", "--corpus", "nope", "--fuzzer", "png_fuzzer"]) == 2
    assert fa.main(["map", "--corpus", "png_fuzzer", "--fuzzer", "nope"]) == 2
    assert fa.main(["map", "--corpus", "png_fuzzer", "--ignore"]) == 2
    assert fa.main(["map", "--corpus", "png_fuzzer", "--function", "not-a-name"]) == 2
    assert '"error": "unknown corpus id' in capsys.readouterr().out
    assert fa.main(["map", "--corpus", "json_fuzzer", "--function", "png_parse", "png_parse"]) == 0
    row = next(m for m in _load(tmp_path)["mappings"] if m["corpus"] == "json_fuzzer")
    assert row == {
        "corpus": "json_fuzzer",
        "fuzzer": None,
        "functions": ["png_parse"],
        "ignored": False,
        "reason": None,
        "source": "agent",
    }


# --- write --------------------------------------------------------------------------------------------


def _write_harness(run: Path, module: str, sidecar: dict, fuzz: str = "") -> None:
    hdir = run / "workspace" / "harnesses"
    hdir.mkdir(parents=True, exist_ok=True)
    (hdir / f"harness_{module}.json").write_text(json.dumps({"module": module, **sidecar}), encoding="utf-8")
    (hdir / f"harness_{module}.c").write_text(HARNESS_TEMPLATE.format(fuzz=fuzz), encoding="utf-8")


def test_write_dispatch_api_and_target_fuzzer_modules(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    target = _oss_fuzz_target(tmp_path)
    _discover(tmp_path, target, capsys)
    assert fa.main(["import"]) == 0
    stmt = _build_dispatch_invocation(
        [
            "(void)png_parse((const char *)fuzz_buf, (int)fuzz_len);",
            "int v; memcpy(&v, fuzz_buf, sizeof v); (void)png_parse((const char *)fuzz_buf + 4, v);",
        ]
    )
    _write_harness(tmp_path, "libpng_a", {"max_input_size": 7}, stmt)
    stale = tmp_path / "workspace" / "imported_corpus" / "libpng_a"
    stale.mkdir(parents=True)
    (stale / "seed-old").write_bytes(b"old")
    _write_harness(
        tmp_path,
        "libpng_api",
        {
            "max_input_size": 100,
            "api_cases": [
                {"selector": 0, "kind": "single", "calls": ["png_parse"], "slots": [], "rest": {"call": 0, "param": 0}},
                {
                    "selector": 1,
                    "kind": "single",
                    "calls": ["png_parse"],
                    "slots": [{"call": 0, "param": 1, "kind": "int", "size": 4}],
                    "rest": {"call": 0, "param": 0},
                },
                {"selector": 2, "kind": "single", "calls": ["other"], "slots": [], "rest": {"call": 0, "param": 0}},
            ],
        },
    )
    _write_harness(
        tmp_path,
        "tf_png_fuzzer",
        {
            "max_input_size": 70000,
            "target_fuzzer": {"id": "png_fuzzer", "source": "fuzz/png_fuzzer.c", "initialize": True},
        },
    )
    _write_harness(tmp_path, "unrelated", {}, "(void)zz(fuzz_buf, fuzz_len);")
    capsys.readouterr()
    assert fa.main(["write"]) == 0
    out = json.loads(capsys.readouterr().out)["modules"]
    imp = tmp_path / "workspace" / "imported_corpus"

    # dispatch harness: case 0 only (case 1 reads a scalar slot first); the 8-byte input is too large
    assert out["libpng_a"] == {"inputs": 1, "dropped_too_large": 1, "dropped_over_cap": 0}
    files = list((imp / "libpng_a").iterdir())
    assert [p.read_bytes() for p in files] == [b"\x00\x89PNG-a"]
    assert all(p.name.startswith("imp-") and len(p.name) == 20 for p in files)
    rep = json.loads((tmp_path / "workspace" / "reports" / "imported_corpus" / "libpng_a.json").read_text())
    assert rep["target_fuzzer"] is None and rep["max_input_size"] == 7
    assert rep["cases"] == {"0": {"corpora": ["png_fuzzer"], "functions": ["helper", "png_parse"], "inputs": 1}}
    assert (tmp_path / "workspace" / "dicts" / "libpng_a.extra.dict").read_text().splitlines() == [
        '"IHDR"',
        'kw1="\\x89PNG"',
    ]

    # API harness: only the slot-free case whose rest feeds png_parse
    assert sorted(p.read_bytes() for p in (imp / "libpng_api").iterdir()) == [b"\x00\x89PNG-a", b"\x00\x89PNG-bb"]

    # target fuzz module: verbatim
    assert sorted(p.read_bytes() for p in (imp / "tf_png_fuzzer").iterdir()) == [b"\x89PNG-a", b"\x89PNG-bb"]
    rep = json.loads((tmp_path / "workspace" / "reports" / "imported_corpus" / "tf_png_fuzzer.json").read_text())
    assert rep["target_fuzzer"] == "png_fuzzer" and rep["cases"]["all"]["corpora"] == ["png_fuzzer"]
    assert (tmp_path / "workspace" / "dicts" / "tf_png_fuzzer.extra.dict").is_file()

    # a module no corpus feeds: nothing, a reason, no extra dictionary
    assert out["unrelated"]["inputs"] == 0 and "reason" in out["unrelated"]
    assert not (tmp_path / "workspace" / "dicts" / "unrelated.extra.dict").exists()
    assert not list(imp.rglob("seed-*"))
    # the json corpus is mapped to the C++ fuzzer: its direct_api_calls (json_load) feed no case here
    assert all("json_fuzzer" not in json.dumps(r) for r in out.values())


def test_write_without_report_records_a_reason(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _write_harness(tmp_path, "m", {}, "(void)f(fuzz_buf, fuzz_len);")
    (tmp_path / "workspace" / "dicts").mkdir(parents=True)
    (tmp_path / "workspace" / "dicts" / "m.extra.dict").write_text('"old"\n')
    assert fa.main(["write", "--module", "m"]) == 0
    rep = json.loads((tmp_path / "workspace" / "reports" / "imported_corpus" / "m.json").read_text())
    assert rep["inputs"] == 0 and "discover has not run" in rep["reason"] and rep["max_input_size"] == 1500
    assert not (tmp_path / "workspace" / "dicts" / "m.extra.dict").exists()
    assert fa.main(["write", "--module", "../x"]) == 2
