"""libc gap report (scripts/libc_gap_report.py, plan step S7), on fixture headers and models."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import libc_gap_report as G

pytestmark = pytest.mark.unit

LIBC_STRING_H = r"""
#ifndef __FC_STRING
#define __FC_STRING
#include "features.h"
__PUSH_FC_STDLIB
__BEGIN_DECLS

/*@ requires valid_string_s: valid_read_string(s);
  @ assigns \result \from indirect:s[0..strlen(s)];
  @*/
extern size_t strlen (const char *s);

/*@ ensures \result == 0; */
extern int no_frame(void);

extern void *memrchr(const void *s, int c, size_t n);

extern int fprintf(FILE * restrict stream, const char * restrict format, ...);

/*@ assigns \nothing; */
#if defined(SOMETHING)
extern int detached(void);
#endif

__END_DECLS
__POP_FC_STDLIB
#endif
"""

STUB_H = r"""
/*@ assigns \result \from number; */
long syscall(long number, ...);
/*@ assigns ((char *)s)[0 .. n - 1] \from indirect:n; */
void explicit_bzero(void *s, size_t n);
int json_object_put(struct json_object *obj);
"""

HOST_H = "extern int deflate (z_streamp strm, int flush) __THROW __nonnull ((1));\nint pipe2(int fd[2], int flags);\n"


def _model(path: Path, externals: list[str], calls: dict[str, list[str]], generated_at: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "schema_version": 2,
        "generated_at": generated_at,
        "externals": externals,
        "functions": {fid: {"external_calls": names} for fid, names in calls.items()},
    }
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


@pytest.fixture
def headers(tmp_path: Path) -> tuple[Path, Path, Path]:
    libc, stubs, host = tmp_path / "libc", tmp_path / "stubs", tmp_path / "host"
    for d, name, text in (
        (libc, "string.h", LIBC_STRING_H),
        (stubs, "fc_compat_types.h", STUB_H),
        (host, "zlib.h", HOST_H),
    ):
        d.mkdir()
        (d / name).write_text(text, encoding="utf-8")
    return libc, stubs, host


def test_prototypes_keep_their_contract_across_standalone_macros() -> None:
    protos = {p.name: p for p in G.parse_prototypes(LIBC_STRING_H)}
    assert set(protos) == {"strlen", "no_frame", "memrchr", "fprintf", "detached"}
    assert G.has_assigns(protos["strlen"].contract)  # after __PUSH_FC_STDLIB / __BEGIN_DECLS
    assert protos["no_frame"].contract and not G.has_assigns(protos["no_frame"].contract)
    assert protos["memrchr"].contract is None
    assert protos["detached"].contract is None  # a preprocessor line detaches it
    assert protos["fprintf"].variadic and not protos["strlen"].variadic
    host = {p.name for p in G.parse_prototypes(HOST_H)}
    assert host == {"deflate", "pipe2"}


def test_report_classifies_every_external_and_orders_gaps_first(tmp_path: Path, headers, capsys) -> None:
    libc, stubs, host = headers
    runs = tmp_path / "runs"
    _model(runs / "a/run-1" / G.MODEL_REL, ["strlen"], {}, "2026-01-01")  # older run of a: ignored
    _model(
        runs / "a/run-2" / G.MODEL_REL,
        ["strlen", "memrchr", "deflate", "syscall", "fprintf", "__FC_assert", "gmp_thing"],
        {"src/a.c#f": ["memrchr", "deflate"], "src/a.c#g": ["memrchr", "fprintf"]},
        "2026-02-01",
    )
    _model(
        runs / "b/run-1" / G.MODEL_REL,
        ["memrchr", "no_frame", "json_object_put", "explicit_bzero"],
        {"src/b.c#h": ["memrchr", "no_frame"]},
        "2026-02-01",
    )
    out = tmp_path / "gap.json"
    rc = G.main(
        [str(runs), "--libc", str(libc), "--stubs", str(stubs), "--host-include", str(host), "--json", str(out)]
    )
    assert rc == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert set(report["targets"]) == {"a", "b"}
    assert report["targets"]["a"]["model"].endswith("a/run-2/workspace/reports/phase0_model.json")
    status = {e["name"]: e["status"] for e in report["functions"]}
    assert status == {
        "memrchr": "no_contract",
        "no_frame": "no_contract",
        "json_object_put": "no_contract",
        "deflate": "undeclared_host",
        "gmp_thing": "undeclared_other",
        "syscall": "stub",
        "explicit_bzero": "stub",
        "strlen": "libc",
        "fprintf": "variadic",
        "__FC_assert": "internal",
    }
    first = report["functions"][0]
    assert (first["name"], first["targets"], first["callers"]) == ("memrchr", ["a", "b"], 3)
    deflate = next(e for e in report["functions"] if e["name"] == "deflate")
    assert deflate["declared_in"] == ["host:zlib.h"]
    assert report["counts"]["no_contract"] == 3 and report["counts"]["internal"] == 1
    text = capsys.readouterr().out
    assert "libc gap report over 2 target(s): a, b" in text
    assert text.index("memrchr") < text.index("gmp_thing")


def test_a_single_run_directory_and_missing_inputs(tmp_path: Path, headers, capsys) -> None:
    libc, stubs, _ = headers
    run = tmp_path / "target" / "run-3"
    _model(run / G.MODEL_REL, ["memrchr"], {}, "2026-02-01")
    assert G.main([str(run), "--libc", str(libc), "--stubs", str(stubs), "--host-include", str(tmp_path / "none")]) == 0
    assert "over 1 target(s): target" in capsys.readouterr().out
    assert G.main([str(tmp_path / "empty"), "--libc", str(libc)]) == 1
    assert G.main([str(run), "--libc", str(tmp_path / "nolibc")]) == 2


def test_the_shipped_stubs_parse() -> None:
    stubs, skipped = G.scan_headers([Path(G.__file__).resolve().parents[1] / "templates" / "fc_stubs"], "fc_stubs")
    assert not skipped
    assert stubs["syscall"].contract and stubs["getsockopt"].contract
