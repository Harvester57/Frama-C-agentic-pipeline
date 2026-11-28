"""
`_Alignof` of a type the instrumented translation unit leaves incomplete (eacsl_toolchain.rewrite_incomplete_alignof).

Frama-C's `-rte` emits `\\aligned(p, alignof(T))` for a pointer to an opaque handle (`typedef struct evp_md_st
EVP_MD;`) and E-ACSL prints it as `_Alignof(T)`, which clang rejects on an incomplete type (sudo run-1, upstream
pub/frama-c#2805). The build makes those checks vacuous and says so in its result (`incomplete_alignof`).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

import eacsl_toolchain as T
import generate_report
import run_eacsl_fuzz as R
from test_eacsl_toolchain import FakeEacslGcc, _src, modern_cli  # noqa: F401 - modern_cli is a fixture

INCALIGN_REPO = Path(__file__).resolve().parent.parent

# Declarations as the Frama-C printer writes them, then one use of each spelling.
INCALIGN_DECLS = """struct evp_md_st;
typedef struct evp_md_st EVP_MD;
typedef EVP_MD MD_ALIAS;
struct ssl_st;
typedef struct ssl_st SSL;
struct engine_st;
union opaque_u;
struct digest_ctx {
   long state ;
   int used ;
};
typedef struct digest_ctx DIGEST_CTX;
typedef struct digest_ctx const CONST_CTX;
"""

INCALIGN_USES = r"""unsigned long uses[] = {
  _Alignof(EVP_MD const),
  _Alignof(SSL),
  _Alignof(struct engine_st volatile),
  _Alignof(MD_ALIAS),
  _Alignof(union opaque_u),
  _Alignof(
      EVP_MD const),
  __alignof__(SSL const),
  _Alignof(DIGEST_CTX),
  _Alignof(struct digest_ctx const),
  _Alignof(CONST_CTX),
  _Alignof(EVP_MD const *),
  _Alignof(char),
  _Alignof(unsigned long const),
  _Alignof(unknown_t)
};
/* _Alignof(EVP_MD const) in a comment */
// _Alignof(SSL) in a line comment
char const *txt = "_Alignof(SSL)";
"""

# One RTE alignment assertion on an opaque handle, as E-ACSL (Frama-C 35~~dev, -G clang) prints it.
INCALIGN_ASSERT_BLOCK = r"""struct evp_md_st;
typedef struct evp_md_st EVP_MD;
EVP_MD const *md_from(void const *p)
{
  EVP_MD const *__retres;
  {
    int __gen_e_acsl_aligned;
    __e_acsl_assert_data_t __gen_e_acsl_assert_data = {.values = (void *)0};
    __gen_e_acsl_aligned = __e_acsl_aligned((void *)p,_Alignof(EVP_MD const));
    __e_acsl_assert_register_ulong(& __gen_e_acsl_assert_data,
                                   "alignof(EVP_MD const)",0,
                                   _Alignof(EVP_MD const));
    __e_acsl_assert_register_ptr(& __gen_e_acsl_assert_data,"p",(void *)p);
    __e_acsl_assert_register_int(& __gen_e_acsl_assert_data,
                                 "rte: pointer_alignment: \\aligned(p,alignof(EVP_MD const))",
                                 0,__gen_e_acsl_aligned);
    __gen_e_acsl_assert_data.blocking = 1;
    __gen_e_acsl_assert_data.kind = "Assertion";
    __gen_e_acsl_assert_data.pred_txt = "\\aligned(p,alignof(EVP_MD const))";
    __gen_e_acsl_assert_data.file = "workspace/work/lib/util/digest_openssl.c";
    __gen_e_acsl_assert_data.fct = "md_from";
    __gen_e_acsl_assert_data.line = 9;
    __gen_e_acsl_assert_data.name = "rte/pointer_alignment";
    __e_acsl_assert(__gen_e_acsl_aligned,& __gen_e_acsl_assert_data);
    __e_acsl_assert_clean(& __gen_e_acsl_assert_data);
  }
  /*@ assert rte: pointer_alignment: \aligned(p,alignof(EVP_MD const)); */
  __retres = (EVP_MD const *)p;
  return __retres;
}
"""


def _uses_after(text: str) -> list[str]:
    """The initializer lines of `uses[]` in `text`, stripped."""
    body = text.split("uses[] = {", 1)[1].split("};", 1)[0]
    return [ln.strip() for ln in body.split("\n") if ln.strip()]


def test_only_alignof_of_incomplete_types_is_rewritten():
    text = INCALIGN_DECLS + INCALIGN_USES
    new, info = T.rewrite_incomplete_alignof(text)
    assert new.count("\n") == text.count("\n")  # the compile log's line numbers stay meaningful
    assert _uses_after(new) == [
        f"{T.INCOMPLETE_ALIGNOF_VALUE},",  # EVP_MD const: typedef of a declared-only struct, qualified
        f"{T.INCOMPLETE_ALIGNOF_VALUE},",  # SSL
        f"{T.INCOMPLETE_ALIGNOF_VALUE},",  # struct engine_st volatile: the tag itself
        f"{T.INCOMPLETE_ALIGNOF_VALUE},",  # a typedef of the typedef
        f"{T.INCOMPLETE_ALIGNOF_VALUE},",  # a union tag
        T.INCOMPLETE_ALIGNOF_VALUE,  # spread over two lines: the newline is kept after the value
        ",",
        f"{T.INCOMPLETE_ALIGNOF_VALUE},",  # GCC's spelling, as E-ACSL prints it without -G clang
        "_Alignof(DIGEST_CTX),",  # complete: its check stays
        "_Alignof(struct digest_ctx const),",
        "_Alignof(CONST_CTX),",
        "_Alignof(EVP_MD const *),",  # a pointer is complete
        "_Alignof(char),",
        "_Alignof(unsigned long const),",
        "_Alignof(unknown_t)",  # a name nothing declares is never taken for incomplete
    ]
    assert "/* _Alignof(EVP_MD const) in a comment */" in new
    assert "// _Alignof(SSL) in a line comment" in new
    assert 'char const *txt = "_Alignof(SSL)";' in new
    assert info["rewrites"] == 7
    assert info["types"] == ["struct evp_md_st", "struct ssl_st", "struct engine_st", "union opaque_u"]


def test_nothing_to_rewrite_leaves_the_text_alone():
    text = INCALIGN_DECLS + "unsigned long a = _Alignof(DIGEST_CTX);\n"
    assert T.rewrite_incomplete_alignof(text) == (text, {"rewrites": 0, "types": [], "checks": []})
    assert T.rewrite_incomplete_alignof("int f(void) { return 0; }\n")[1]["rewrites"] == 0


def test_a_definition_anywhere_in_the_file_makes_the_tag_complete():
    text = (
        "struct late;\ntypedef struct late LATE;\nunsigned long a = _Alignof(LATE);\n"
        "struct late {\n   int x ;\n};\n"
        "struct packed;\nunsigned long b = _Alignof(struct packed);\n"
        "struct __attribute__((__packed__, __aligned__(4))) packed {\n   char c ;\n};\n"
    )
    new, info = T.rewrite_incomplete_alignof(text)
    assert new == text and info["rewrites"] == 0


def test_a_function_returning_a_pointer_to_the_struct_is_no_definition():
    text = (
        "struct engine_st;\n"
        "static struct engine_st volatile *engine_from(void *p)\n{\n"
        "  unsigned long a = _Alignof(struct engine_st volatile);\n  return 0;\n}\n"
        "/* struct engine_st { int in_a_comment; }; */\n"
        'char const *s = "struct engine_st { int in_a_string; }";\n'
    )
    new, info = T.rewrite_incomplete_alignof(text)
    assert f"unsigned long a = {T.INCOMPLETE_ALIGNOF_VALUE};" in new
    assert info["types"] == ["struct engine_st"]


def test_each_weakened_check_is_attributed_to_its_source_assertion():
    new, info = T.rewrite_incomplete_alignof(INCALIGN_ASSERT_BLOCK)
    assert "_Alignof(" not in new.replace("alignof(EVP_MD const)", "")
    assert f"__e_acsl_aligned((void *)p,{T.INCOMPLETE_ALIGNOF_VALUE});" in new
    # The assertion's own text and source location are left as they are.
    assert '"rte: pointer_alignment: \\\\aligned(p,alignof(EVP_MD const))"' in new
    assert info["rewrites"] == 2  # the check and the value it would report
    assert info["checks"] == [
        {
            "type": "EVP_MD const",
            "tag": "struct evp_md_st",
            "function": "md_from",
            "file": "workspace/work/lib/util/digest_openssl.c",
            "line": 9,
            "predicate": "\\aligned(p,alignof(EVP_MD const))",
            "rewrites": 2,
        }
    ]


def test_the_same_assertion_checked_twice_is_one_entry_with_its_count():
    # A macro checks the same predicate twice on one source line (sudo_sendlog: 60 rewrites, 28 entries).
    body = INCALIGN_ASSERT_BLOCK.split("EVP_MD const *md_from", 1)[1]
    text = INCALIGN_ASSERT_BLOCK + "EVP_MD const *md_from_again" + body
    _new, info = T.rewrite_incomplete_alignof(text)
    assert info["rewrites"] == 4
    (check,) = info["checks"]
    assert check["function"] == "md_from" and check["rewrites"] == 4


def test_an_occurrence_without_assert_data_is_still_listed():
    text = "struct ssl_st;\ntypedef struct ssl_st SSL;\nunsigned long a = _Alignof(SSL);\n"
    _new, info = T.rewrite_incomplete_alignof(text)
    (check,) = info["checks"]
    assert check["type"] == "SSL" and check["tag"] == "struct ssl_st"
    assert check["function"] is None and check["instrumented_line"] == 3 and check["rewrites"] == 1


@pytest.mark.usefixtures("modern_cli")
def test_the_build_records_the_weakened_checks_as_an_assumption(tmp_path):
    fake = FakeEacslGcc(instrumented_text=INCALIGN_ASSERT_BLOCK)
    res = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "fuzz_mod", runner=fake, use_cache=False)
    assert res["returncode"] == 0, res
    rec = res["incomplete_alignof"]
    assert rec["rewrites"] == 2 and rec["types"] == ["struct evp_md_st"]
    assert [c["function"] for c in rec["checks"]] == ["md_from"]
    assert rec["assumption"] == T.INCOMPLETE_ALIGNOF_ASSUMPTION
    instrumented = Path(res["instrumented_source"]).read_text(encoding="utf-8")
    assert "_Alignof(EVP_MD const)" not in instrumented
    log = Path(res["compile_log"]).read_text(encoding="utf-8")
    assert "pointer-alignment checks of 1 distinct source assertion(s) vacuous" in log
    assert "struct evp_md_st" in log and "digest_openssl.c:9 in md_from" in log
    plain = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "plain", runner=FakeEacslGcc(), use_cache=False)
    assert "incomplete_alignof" not in plain


def _incalign_build_report(run: Path, mod: str, comp: dict) -> None:
    path = run / "workspace/build" / f"{mod}.build.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mode": "build", "module": mod, "engine_used": comp["engine"], "compile": comp}))


def test_run_report_names_the_modules_with_weakened_alignment_checks(tmp_path):
    assert generate_report.incomplete_alignof_lines(tmp_path) == []
    rec: dict[str, Any] = {"rewrites": 4, "types": ["struct evp_md_st"], "checks": [{}, {}]}
    _incalign_build_report(tmp_path, "sudo", {"engine": "eacsl", "returncode": 0, "incomplete_alignof": rec})
    other = {**rec, "types": ["struct ssl_st"], "checks": [{}]}
    _incalign_build_report(tmp_path, "sendlog", {"engine": "eacsl", "returncode": 0, "incomplete_alignof": other})
    _incalign_build_report(tmp_path, "failed", {"engine": "eacsl", "returncode": 1, "incomplete_alignof": rec})
    _incalign_build_report(tmp_path, "asan", {"engine": "sanitizers", "returncode": 0})
    lines = generate_report.incomplete_alignof_lines(tmp_path)
    assert len([ln for ln in lines if ln]) == 1
    assert "2 module(s)" in lines[0]
    assert lines[0].endswith("`sendlog` (1: struct ssl_st), `sudo` (2: struct evp_md_st).")


# ---------------------------------------------------------------------------
# End to end in the analysis image (FRAMAC_DOCKER_TESTS=1)
# ---------------------------------------------------------------------------

INCALIGN_LIB_H = """/* OpenSSL-style opaque handles: declared, never defined in this translation unit. */
typedef struct evp_md_st EVP_MD;
typedef struct ssl_st SSL;
struct engine_st;

/* A complete type: its alignment check must stay. */
struct digest_ctx {
    long state;
    int used;
};
typedef struct digest_ctx DIGEST_CTX;

const EVP_MD *md_from(const void *p);
int md_size(const EVP_MD *md);
"""

INCALIGN_MOD_C = """#include <stddef.h>
#include <stdint.h>
#include "lib.h"

static unsigned char arena[64] __attribute__((aligned(16)));

const EVP_MD *md_from(const void *p)
{
    return (const EVP_MD *)p;
}

int md_size(const EVP_MD *md)
{
    return md != NULL ? 32 : 0;
}

static SSL *ssl_from(void *p)
{
    return (SSL *)p;
}

static struct engine_st volatile *engine_from(void *p)
{
    return (struct engine_st volatile *)p;
}

static DIGEST_CTX *ctx_from(void *p)
{
    return (DIGEST_CTX *)p;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;
    /* Opaque handles at any byte offset: no access goes through them here. */
    const EVP_MD *md = md_from(arena + data[0] % 8);
    SSL *ssl = ssl_from(arena + 1);
    struct engine_st volatile *eng = engine_from(arena + 3);
    /* The complete type: offset 16 when the first byte is even, 17 (misaligned) when it is odd. */
    DIGEST_CTX *ctx = ctx_from(arena + 16 + (data[0] & 1));
    return md_size(md) + (ssl != NULL) + (eng != NULL) + (ctx != NULL) == 1000;
}
"""

INCALIGN_DRIVE_PY = """import json, shutil, sys
from pathlib import Path
sys.path.insert(0, "/repo/scripts")
import run_eacsl_fuzz as R
work = Path("/tmp/w")
shutil.copytree("/fixture", work)
res = R.compile_eacsl_binary([str(work / "mod.c")], work / "out" / "fuzz_mod", cppflags=f"-I{work}", use_cache=False)
keys = ("returncode", "reason", "binary", "incomplete_alignof")
print("INCALIGN_RESULT " + json.dumps({k: res.get(k) for k in keys}))
"""

# Even first byte: the opaque handles sit at odd offsets and nothing fires. Odd first byte: the complete
# DIGEST_CTX is misaligned and its kept pointer_alignment check must abort the run.
INCALIGN_DOCKER_SCRIPT = """set -e
timeout 900 python3 /fixture/drive.py
bin=/tmp/w/out/fuzz_mod.e-acsl
[ -x "$bin" ] || exit 0
printf '\\002' > /tmp/even && printf '\\003' > /tmp/odd
if timeout 120 "$bin" /tmp/even > /tmp/even.log 2>&1; then echo INCALIGN_EVEN_OK; else tail -5 /tmp/even.log; fi
if timeout 120 "$bin" /tmp/odd > /tmp/odd.log 2>&1; then echo INCALIGN_ODD_PASSED; else
  grep -q 'pointer_alignment' /tmp/odd.log && grep -q 'DIGEST_CTX' /tmp/odd.log && echo INCALIGN_ODD_CAUGHT
fi
"""


@pytest.mark.integration
def test_opaque_handle_alignment_builds_under_eacsl_and_the_complete_check_still_fires(tmp_path):
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    for name, text in (("lib.h", INCALIGN_LIB_H), ("mod.c", INCALIGN_MOD_C), ("drive.py", INCALIGN_DRIVE_PY)):
        (tmp_path / name).write_text(text, encoding="utf-8", newline="\n")
    tag = os.environ.get("FRAMAC_RUN_TAG", "pytest-eacsl-incomplete-alignof")
    name = f"framac-test-incalign-{tmp_path.name}".lower()
    argv = ["docker", "run", "--rm", "--name", name, "--label", f"framac.run={tag}", "--network", "none"]
    argv += ["-v", f"{tmp_path}:/fixture:ro", "-v", f"{INCALIGN_REPO}:/repo:ro", ANALYSIS_IMAGE, INCALIGN_DOCKER_SCRIPT]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        raise
    out = proc.stdout + proc.stderr
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("INCALIGN_RESULT ")]
    assert lines, out[-4000:]
    res = json.loads(lines[-1].split(" ", 1)[1])
    assert res["returncode"] == 0, out[-4000:]
    assert res["binary"].endswith(".e-acsl")
    rec = res["incomplete_alignof"]
    if rec is not None:
        # Stock Frama-C 34.0~beta emits alignof(incomplete struct), so the Python post-pass rewrites it.
        # Patched images (patch 05) avoid emitting it in the first place, leaving incomplete_alignof as None.
        assert rec["types"] == ["struct evp_md_st", "struct ssl_st", "struct engine_st"]
        assert {c["function"] for c in rec["checks"]} == {"md_from", "ssl_from", "engine_from"}
        assert rec["assumption"] == T.INCOMPLETE_ALIGNOF_ASSUMPTION
    assert "INCALIGN_EVEN_OK" in proc.stdout, out[-4000:]
    assert "INCALIGN_ODD_CAUGHT" in proc.stdout, out[-4000:]
