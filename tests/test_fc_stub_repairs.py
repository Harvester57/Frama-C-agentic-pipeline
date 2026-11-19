"""
The repaired shipped stubs (step S4 of docs/plans/templates-and-stubs-improvement-plan.md): <bsd/string.h>
and fc_strlcpy.h, <json-c/json.h>, <netinet/ip_icmp.h> and getopt in fc_compat_types.h.

Text tests pin what each repair must keep. The Docker-backed tests (FRAMAC_DOCKER_TESTS=1) check, per
header, that Frama-C parses it with the pipeline's flags, that Eva gives no alarm on a valid call and an
Invalid precondition on a short buffer, that the E-ACSL version accepts what the real library accepts and
stops a real out-of-bounds access, and that the ABI matches the real header where an image has one.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from acsl_ast import Token, tokenize_c_acsl
from conftest import ANALYSIS_IMAGE, BUILD_IMAGE, ROOT, require_docker_images, wp_proved_goals
from test_fc_stub_contracts import _prototype_name

STUBS = ROOT / "templates" / "fc_stubs"


def _read(rel: str) -> str:
    return (STUBS / rel).read_text(encoding="utf-8")


def _branches(text: str) -> tuple[str, str]:
    """(E-ACSL branch, Eva/WP branch) of a stub split on its `#if defined(__FRAMAC_EACSL__)`."""
    eacsl = text.split("#if defined(__FRAMAC_EACSL__)", 1)[1]
    eacsl, eva = eacsl.split("#else", 1)
    return eacsl, eva.split("#endif /* __FRAMAC_EACSL__ */", 1)[0]


def _contract_of(text: str, name: str) -> str:
    """The ACSL block right before the prototype of `name` (first occurrence in `text`)."""
    match = re.search(r"/\*@((?:(?!\*/).)*)\*/\s*(?:extern\s+)?[^;{}]*\b" + re.escape(name) + r"\s*\(", text, re.S)
    assert match, name
    return match.group(1)


def stub_prototypes(rel: str, names: set[str] | None = None) -> list[str]:
    """Top-level prototype statements of a stub as plain C (comments and ACSL dropped), in order."""
    out: list[str] = []
    stmt: list[str] = []
    stmt_tokens: list[Token] = []
    depth = 0
    for tok in tokenize_c_acsl(_read(rel), path=rel):
        if tok.kind in ("whitespace", "c_comment", "acsl_block", "acsl_line", "pp_directive"):
            continue
        if tok.text == "{":
            depth += 1
        elif tok.text == "}":
            depth -= 1
        if depth or tok.text == "}":
            stmt, stmt_tokens = [], []
            continue
        if tok.text == ";":
            name = _prototype_name(stmt_tokens)
            if name is not None and (names is None or name in names):
                out.append(" ".join(stmt) + ";")
            stmt, stmt_tokens = [], []
            continue
        stmt.append(tok.text)
        stmt_tokens.append(tok)
    return out


def _quantifier_bodies(text: str) -> list[str]:
    r"""Body of every `\exists integer i;` up to the end of its scope (unmatched `)` or `;` at depth 0)."""
    bodies = []
    for match in re.finditer(r"\\exists\s+integer\s+\w+\s*;", text):
        depth, i = 0, match.end()
        while i < len(text):
            ch = text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                if depth == 0:
                    break
                depth -= 1
            elif ch == ";" and depth == 0:
                break
            i += 1
        bodies.append(text[match.end() : i])
    return bodies


def _top_level_conjuncts(body: str) -> list[str]:
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(body):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif body.startswith("&&", i) and depth == 0:
            parts.append(body[start:i])
            start = i + 2
    parts.append(body[start:])
    return [p.strip() for p in parts]


# ---------------------------------------------------------------------------------------------------
# Text: strlcpy, strlcat, strnstr
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_strlcpy_and_strlcat_are_strict_for_eva_and_wp():
    _, eva = _branches(_read("fc_strlcpy.h"))
    cpy, cat = _contract_of(eva, "strlcpy"), _contract_of(eva, "strlcat")
    for contract in (cpy, cat):
        assert "requires valid_src: valid_read_string(src);" in contract
        assert re.search(r"requires valid_dst:[^;]*\\valid\(dst \+ \(0 \.\. size - 1\)\);", contract)
    assert "requires dst_string_within_size: valid_read_string(dst) && strlen(dst) < size;" in cat
    # strlcpy states what it writes: initialized prefix, NUL, length; strlcat the same from \old(strlen(dst)).
    for clause in (
        "ensures result_is_src_length: \\result == strlen(src);",
        "ensures initialized:",
        "ensures nul_terminated:",
    ):
        assert clause in cpy, clause
    assert "ensures result_is_total_length: \\result == \\old(strlen(dst)) + strlen(src);" in cat
    # Eva reduces through a conditional, not through \min (see the comment in the header).
    assert "\\min" not in "".join(re.findall(r"/\*@.*?\*/", eva, re.S))


@pytest.mark.unit
def test_strlcpy_and_strlcat_are_exact_under_eacsl():
    eacsl, _ = _branches(_read("fc_strlcpy.h"))
    cpy, cat = _contract_of(eacsl, "strlcpy"), _contract_of(eacsl, "strlcat")
    # The whole-`size` range is only one way to pass; the other is the bytes actually written.
    assert "\\valid(dst + (0 .. size - 1)) || !\\valid_read(src) ||" in cpy and "__fc_bsd_cpy_fits" in cpy
    assert "__fc_bsd_cat_fits" in cat
    # Untracked sources (memory an uninstrumented library allocated) are not checked.
    for contract in (cpy, cat):
        assert "requires src_string: \\valid_read(src) ==>" in contract
    # Host-header mode has no logic strlen.
    assert "strlen" not in re.sub(r"//[^\n]*", "", eacsl)


@pytest.mark.unit
@pytest.mark.parametrize("rel", ["fc_strlcpy.h", "bsd/string.h", "json-c/json.h"])
def test_eacsl_quantifiers_have_one_conjunct_after_the_guard(rel):
    # E-ACSL 35 drops the first conjunct after the guard of `\exists i; a <= i < b && P && Q`.
    eacsl, _ = _branches(_read(rel))
    bodies = _quantifier_bodies(eacsl)
    assert bodies, rel
    for body in bodies:
        conjuncts = _top_level_conjuncts(body)
        assert len(conjuncts) == 2 and re.fullmatch(r"__fc_\w+\([^;]*\)", conjuncts[1], re.S), body


@pytest.mark.unit
def test_bsd_string_takes_strlcpy_from_the_shared_header_and_specifies_strnstr():
    text = _read("bsd/string.h")
    assert "#include <fc_strlcpy.h>" in text
    assert "strlcpy(" not in re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    eacsl, eva = _branches(text)
    nstr = _contract_of(eva, "strnstr")
    assert "requires valid_little: valid_read_string(little);" in nstr
    assert "requires valid_big: valid_read_nstring((char *)big, len);" in nstr
    assert "requires little_string: \\valid_read(little) ==>" in _contract_of(eacsl, "strnstr")


@pytest.mark.unit
def test_compat_header_renames_the_libc_getopt_and_strlcpy_before_declaring_its_own():
    text = _read("fc_compat_types.h")
    fc_libc = text.split("#else /* Frama-C __fc_libc */", 1)[1].split("#endif /* __FRAMAC_EACSL__ */", 1)[0]
    for name, header in (("getopt", "unistd.h"), ("strlcpy", "string.h"), ("strlcat", "string.h")):
        rename = fc_libc.index(f"#define {name} __fc_libc_")
        assert rename < fc_libc.index(f"#include <{header}>") < fc_libc.index(f"#undef {name}"), name
    assert fc_libc.index("#undef strlcat") < fc_libc.index('#include "fc_strlcpy.h"')
    getopt = _contract_of(fc_libc, "getopt")
    assert "ensures optarg_in_argv: optarg == \\null || \\subset(optarg, argv[0 .. argc - 1] + (0 ..));" in getopt
    assert "ensures optind_range: 1 <= optind <= \\max(argc, 1);" in getopt
    # The libc's spec assigned `*optarg`; this one assigns the pointer itself.
    assert re.search(r"assigns optarg \\from argv\[0 \.\. argc - 1\]", getopt)
    eacsl_branch = text.split("#if defined(__FRAMAC_EACSL__)", 1)[1].split("#else /* Frama-C __fc_libc */", 1)[0]
    assert "getopt" not in eacsl_branch and "strlcpy" not in eacsl_branch


# ---------------------------------------------------------------------------------------------------
# Text: json-c, ip_icmp
# ---------------------------------------------------------------------------------------------------

JSON_ADDED = (
    "json_tokener_new",
    "json_tokener_new_ex",
    "json_tokener_free",
    "json_tokener_reset",
    "json_tokener_parse_ex",
    "json_tokener_parse_verbose",
    "json_tokener_get_error",
    "json_tokener_error_desc",
    "json_tokener_set_flags",
    "json_tokener_get_parse_end",
    "json_object_array_del_idx",
    "json_type_to_name",
)


@pytest.mark.unit
def test_json_stub_has_ghost_pools_nullable_results_and_the_added_api():
    text = _read("json-c/json.h")
    declared = {p.split("(")[0].split()[-1].lstrip("*") for p in stub_prototypes("json-c/json.h")}
    assert set(JSON_ADDED) <= declared
    # Ghost state is never registered by E-ACSL (it is undefined): libc's internal attribute, which
    # only Frama-C knows (gcc -Werror rejects it).
    assert "#ifdef __FRAMAC__\n#define __FC_JSON_GHOST __attribute__((__fc_stdlib_internal))\n#else" in text
    for decl in (
        "struct json_object __fc_json_pool[",
        "struct json_tokener __fc_json_tokener_pool[",
        "char __fc_json_strbuf[",
    ):
        assert f"extern __FC_JSON_GHOST {decl}" in text, decl
    eacsl, eva = _branches(text)
    assert "#define __FC_JSON_HANDLE_RESULT(r) \\\n  ((r) == \\null || \\subset((r), &__fc_json_pool[0 .." in eva
    for macro in ("HANDLE_RESULT(r)", "TOKENER_RESULT(r)", "STRING_RESULT(r)", "STRBUF_NUL"):
        assert f"#define __FC_JSON_{macro} \\true" in eacsl, macro
    # Every handle-returning function says so; every string-returning one keeps the buffer's NUL.
    for proto in stub_prototypes("json-c/json.h"):
        name = proto.split("(")[0].split()[-1].lstrip("*")
        contract = _contract_of(text.split("#endif /* __FRAMAC_EACSL__ */", 1)[1], name)
        if proto.startswith("json_object *"):
            assert "__FC_JSON_HANDLE_RESULT" in contract or "same_handle" in contract, name
        if proto.startswith("const char *"):
            assert "__FC_JSON_STRING_RESULT(\\result)" in contract and "__FC_JSON_STRBUF_NUL" in contract, name


@pytest.mark.unit
def test_icmp_stub_holds_a_struct_ip_and_the_bsd_names():
    text = _read("netinet/ip_icmp.h")
    assert "#include <netinet/ip.h>" in text and "struct ip idi_ip;" in text
    for name in ("ICMP_UNREACH", "ICMP_TIMXCEED", "ICMP_MASKREQ", "ICMP_UNREACH_NEEDFRAG", "ICMP_TIMXCEED_INTRANS"):
        assert re.search(rf"^#define {name}\s", text, re.M), name
    assert "uint8_t reserved[4];" not in text  # glibc's icmphdr has no such member


@pytest.mark.unit
def test_stub_prototype_extraction():
    protos = stub_prototypes("fc_strlcpy.h")
    assert protos.count("size_t strlcpy ( char * dst , const char * src , size_t size );") == 2
    assert stub_prototypes("fc_compat_types.h", {"getopt"}) == [
        "extern int getopt ( int argc , char * const argv [ ] , const char * optstring );"
    ]
    assert stub_prototypes("netinet/ip_icmp.h") == []


# ---------------------------------------------------------------------------------------------------
# Docker: Frama-C, Eva, WP and E-ACSL in the analysis image; json-c in the build image
# ---------------------------------------------------------------------------------------------------

_FLAGS = (
    'py="import sys; sys.path.insert(0, \\"/opt/framac-pipeline/scripts\\"); "; '
    'A=$(python3 -c "$py import framac_common; print(framac_common.augment_framac_cppflags(\\"-I.\\"))"); '
    'F=$(python3 -c "$py import eacsl_toolchain as T; '
    'print(T.build_eacsl_flag_sets(\\"-I.\\", fuzzer=False)[\\"frontend\\"])"); '
)


def _docker(image: str, work: Path, script: str, timeout: int = 900) -> str:
    proc = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{work}:/w",
            "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
            "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
            "--entrypoint", "bash", image, "-c", f"cd /w; {_FLAGS}{script}",
        ],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False,
    )  # fmt: skip
    return proc.stdout + proc.stderr


def _eva_script(source: str, mains: list[str]) -> str:
    """Run Eva from each entry point; print `== main` then the log."""
    return "".join(
        f'echo "@@MAIN {m}"; frama-c -no-unicode {source} -cpp-extra-args="$A" -eva -eva-no-show-progress '
        f"-warn-invalid-pointer -main {m} 2>&1; "
        for m in mains
    )


def _per_main(log: str) -> dict[str, str]:
    return {chunk.split("\n", 1)[0].strip(): chunk for chunk in log.split("@@MAIN ")[1:]}


def _assert_clean(chunk: str) -> None:
    assert "0 alarms generated by the analysis." in chunk, chunk
    assert re.search(r"Preconditions\s+\d+ valid\s+0 unknown\s+0 invalid", chunk), chunk
    assert "found two contracts" not in chunk and "garbled mix" not in chunk, chunk


BSD_EVA = r"""#include <bsd/string.h>
#include <string.h>
int ok(void) {
  char d[8], e[16] = "ab";
  size_t n = strlcpy(d, "hello", sizeof d);
  n += strlen(d);                                    /* NUL-terminated: no alarm */
  n += strlcpy(d, "a much longer string", sizeof d);
  n += strlen(d);
  n += strlcat(e, "cd", sizeof e);
  n += strlen(e);
  char *p = strnstr("haystack", "st", 8);
  return (int)(n + (p != 0));
}
int short_dst(void) { char d[4]; return (int)strlcpy(d, "hi", 8); }
int unterminated_src(void) { char s[4] = {'a', 'b', 'c', 'd'}; char d[8]; return (int)strlcpy(d, s, sizeof d); }
int cat_unterminated_dst(void) { char d[4] = {'a', 'b', 'c', 'd'}; return (int)strlcat(d, "x", sizeof d); }
int cat_short_dst(void) { char d[4] = "ab"; return (int)strlcat(d, "x", 8); }
int strnstr_short(void) { char b[4] = {'a', 'b', 'c', 'd'}; return strnstr(b, "c", 8) != 0; }
int read_past_copy(void) { char d[8]; strlcpy(d, "hi", sizeof d); return d[5]; }
"""

BSD_WP = r"""#include <bsd/string.h>
#include <string.h>
/*@ requires valid_read_string(s) && \valid(d + (0 .. 15));
    requires \separated(d + (0 .. 15), s + (0 .. strlen(s)));
    assigns d[0 .. 15];
    ensures \result == strlen(s); */
size_t copy16(char *d, const char *s) {
  size_t r = strlcpy(d, s, 16);
  //@ assert d[r < 16 ? r : 15] == '\0';
  return r;
}
/*@ requires \valid(d + (0 .. 15)) && valid_read_string(s) && valid_read_string(d) && strlen(d) < 16;
    requires \separated(d + (0 .. 15), s + (0 .. strlen(s)));
    assigns d[0 .. 15]; */
void append16(char *d, const char *s) { (void)strlcat(d, s, 16); }
"""

BSD_EACSL = r"""#include <bsd/string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* libbsd is not in the image: an instrumented local strnstr carries the stub's contract. */
char *strnstr(const char *big, const char *little, size_t len) {
  size_t n = strlen(little);
  if (n == 0) return (char *)big;
  for (size_t i = 0; i + n <= len && big[i]; i++)
    if (strncmp(big + i, little, n) == 0) return (char *)big + i;
  return NULL;
}
int main(int argc, char **argv) {
  const char *c = argc > 1 ? argv[1] : "";
  size_t r = 0;
  char d4[4], d8[8];
  if (!strcmp(c, "cpy_ok")) r = strlcpy(d8, "hello", sizeof d8);
  if (!strcmp(c, "cpy_trunc_ok")) r = strlcpy(d8, "a much longer string", sizeof d8);
  if (!strcmp(c, "cpy_wrong_size_fits")) r = strlcpy(d4, "hi", 8);
  if (!strcmp(c, "cpy_overflow")) r = strlcpy(d4, "hello", 8);
  if (!strcmp(c, "cpy_huge_size")) r = strlcpy(d4, "hello", (size_t)-1);
  if (!strcmp(c, "cpy_untracked_src")) { char *s = strdup("hi"); r = strlcpy(d4, s, 8); free(s); }
  if (!strcmp(c, "cpy_unterminated_src")) { char s[4] = {'a', 'b', 'c', 'd'}; r = strlcpy(d8, s, sizeof d8); }
  if (!strcmp(c, "cat_ok")) { char d[6] = "ab"; r = strlcat(d, "cd", 16); }
  if (!strcmp(c, "cat_overflow")) { char d[4] = "ab"; r = strlcat(d, "cdef", 16); }
  if (!strcmp(c, "cat_unterminated_dst_fits")) { char d[4] = {'a', 'b', 'c', 'd'}; r = strlcat(d, "x", sizeof d); }
  if (!strcmp(c, "nstr_ok")) { char b[4] = {'a', 'b', 'c', 'd'}; r = strnstr(b, "c", sizeof b) != NULL; }
  if (!strcmp(c, "nstr_overread")) { char b[4] = {'a', 'b', 'c', 'd'}; r = strnstr(b, "z", 8) != NULL; }
  printf("%s done %zu\n", c, r);
  return 0;
}
"""

# case -> the precondition E-ACSL must stop it on (None: the call is in bounds and runs).
BSD_EACSL_CASES = {
    "cpy_ok": None,
    "cpy_trunc_ok": None,
    "cpy_wrong_size_fits": None,  # strict for Eva, exact here: 3 bytes into d4
    "cpy_overflow": "dst_holds_copy",
    "cpy_huge_size": "dst_holds_copy",  # SIZE_MAX does not loop
    "cpy_untracked_src": None,  # strdup's block is not tracked: not checked
    "cpy_unterminated_src": "src_string",
    "cat_ok": None,
    "cat_overflow": "dst_holds_append",
    "cat_unterminated_dst_fits": None,
    "nstr_ok": None,
    "nstr_overread": "big_readable",
}

GLIBC_ABI = """#define _DEFAULT_SOURCE
#include <string.h>
#include <unistd.h>
"""


@pytest.mark.integration
@pytest.mark.slow
def test_bsd_string_in_eva_wp_eacsl_and_against_glibc(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "eva.c").write_text(BSD_EVA, encoding="utf-8", newline="\n")
    (tmp_path / "wp.c").write_text(BSD_WP, encoding="utf-8", newline="\n")
    (tmp_path / "e.c").write_text(BSD_EACSL, encoding="utf-8", newline="\n")
    abi = GLIBC_ABI + "\n".join(
        stub_prototypes("fc_strlcpy.h") + stub_prototypes("fc_compat_types.h", {"getopt"})
    )  # fmt: skip
    (tmp_path / "abi.c").write_text(abi + "\n", encoding="utf-8", newline="\n")
    mains = [
        "ok",
        "short_dst",
        "unterminated_src",
        "cat_unterminated_dst",
        "cat_short_dst",
        "strnstr_short",
        "read_past_copy",
    ]
    cases = " ".join(BSD_EACSL_CASES)
    script = (
        _eva_script("eva.c", mains)
        + 'echo "@@MAIN wp"; frama-c -no-unicode wp.c -cpp-extra-args="$A" -wp -wp-rte -wp-timeout 30 2>&1; '
        + 'echo "@@MAIN abi"; gcc -fsyntax-only -Werror abi.c 2>&1 && echo ABI_OK; '
        + 'echo "@@MAIN eacsl"; e-acsl-gcc --full-mtracking -G clang -E "$F" '
        + '-e "-I/opt/framac-pipeline/templates/fc_stubs" -O eb e.c > build.log 2>&1 || cat build.log; '
        + f'for k in {cases}; do timeout 60 ./eb.e-acsl $k > $k.out 2>&1; echo "case $k rc=$?"; done'
    )
    log = _docker(ANALYSIS_IMAGE, tmp_path, script)
    per = _per_main(log)
    _assert_clean(per["ok"])
    for main, failed in (
        ("short_dst", "strlcpy: precondition 'valid_dst'"),
        ("unterminated_src", "strlcpy: precondition 'valid_src'"),
        ("cat_unterminated_dst", "strlcat: precondition 'dst_string_within_size'"),
        ("cat_short_dst", "strlcat: precondition 'valid_dst'"),
        ("strnstr_short", "strnstr: precondition 'valid_big'"),
    ):
        assert f"function {failed} got status invalid" in per[main], per[main]
    # Bytes strlcpy does not write stay uninitialized.
    assert "assert \\initialized(&d[5]);" in per["read_past_copy"], per["read_past_copy"]
    assert all(proved == total for proved, total in wp_proved_goals(per["wp"])), per["wp"]
    assert "ABI_OK" in per["abi"], per["abi"]
    for case, precondition in BSD_EACSL_CASES.items():
        out = (tmp_path / f"{case}.out").read_text(encoding="utf-8", errors="replace")
        if precondition is None:
            assert f"case {case} rc=0" in log and f"{case} done" in out, (case, out, log)
        else:
            assert "Precondition failed" in out and f"{precondition}:" in out, (case, out)


GETOPT_EVA = r"""#include <unistd.h>
#include <string.h>
#include "__fc_builtin.h"
int tool(int argc, char **argv) {
  int opt;
  unsigned r = 0;  /* unsigned: no overflow alarm from the test's own sums */
  while ((opt = getopt(argc, argv, "a:h")) > 0) {
    Frama_C_show_each_go(optarg, optind);
    if (opt == 'a' && optarg) r += strcmp(optarg, "x86_64") == 0;
  }
  if (optind < argc) r += (unsigned)strlen(argv[optind]);
  return (int)(r & 1);
}
int main(void) {
  char a0[] = "prog", a1[] = "-a", a2[] = "x86_64", a3[] = "file";
  char *argv[] = {a0, a1, a2, a3, 0};
  return tool(4, argv);
}
"""


@pytest.mark.integration
@pytest.mark.slow
def test_getopt_keeps_optarg_and_optind_inside_argv(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "go.c").write_text(GETOPT_EVA, encoding="utf-8", newline="\n")
    log = _docker(ANALYSIS_IMAGE, tmp_path, _eva_script("go.c", ["main"]))
    chunk = _per_main(log)["main"]
    # __fc_libc's contract gave a garbled mix and imprecise `argv + optind` (libseccomp cause C).
    # strcmp(optarg, ...) and strlen(argv[optind]) are proven: no alarm at all.
    _assert_clean(chunk)
    shown = re.search(r"Frama_C_show_each_go:(.*?)\n\[", chunk, re.S)
    assert shown, chunk
    values = " ".join(shown.group(1).split())
    assert "garbled" not in values and "&a2 + {0; 1; 2; 3; 4; 5; 6}" in values and "{1; 2; 3; 4}" in values, values


JSON_EVA = r"""#include <json-c/json.h>
#include <string.h>
int ok(void) {
  unsigned r = 0;  /* unsigned: no overflow alarm from the test's own sums */
  json_object *root = json_tokener_parse("{\"a\": [1, 2]}");
  if (!root) return -1;
  json_object *a = NULL;
  if (json_object_object_get_ex(root, "a", &a) && a && json_object_is_type(a, json_type_array)) {
    size_t n = json_object_array_length(a);
    for (size_t i = 0; i < n && i < 4; i++) {
      json_object *e = json_object_array_get_idx(a, i);
      if (e) r += json_object_get_int(e) != 0;
    }
    json_object_array_del_idx(a, 0, 1);
  }
  const char *s = json_object_get_string(json_object_object_get(root, "b"));
  if (s) r += strlen(s) > 3;
  json_tokener *tok = json_tokener_new();
  if (tok) {
    json_object *o = json_tokener_parse_ex(tok, "[1]", 3);
    if (json_tokener_get_error(tok) != json_tokener_success)
      r += strlen(json_tokener_error_desc(json_tokener_get_error(tok))) > 3;
    json_object_put(o);
    json_tokener_free(tok);
  }
  const char *name = json_type_to_name(json_object_get_type(root));
  if (name) r += strlen(name) > 3;
  json_object_put(json_object_new_string_len("abc", 3));
  json_object_put(root);
  return (int)(r & 1);
}
int no_null_check(void) { json_object *root = json_tokener_parse("[]"); return (int)json_object_array_length(root); }
int unterminated_key(void) {
  json_object *o = json_object_new_object();
  char k[2] = {'a', 'b'};
  if (!o) return 0;
  return json_object_object_add(o, k, NULL);
}
int short_string_len(void) { char s[2] = "a"; return json_object_new_string_len(s, 8) != NULL; }
int null_tokener(void) { return json_tokener_parse_ex(NULL, "1", 1) != NULL; }
int long_string(void) {
  char buf[16];
  const char *s = json_object_get_string(json_tokener_parse("\"x\""));
  if (s) strcpy(buf, s);  /* a json string may be longer than buf */
  return buf[0];
}
"""

JSON_EACSL = r"""#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
  const char *c = argc > 1 ? argv[1] : "";
  long r = 0;
  if (!strcmp(c, "ok")) {
    json_object *root = json_tokener_parse("{\"a\": [1, 2], \"s\": \"text\"}");
    json_object *a = NULL, *s = NULL;
    if (root && json_object_object_get_ex(root, "a", &a) && json_object_is_type(a, json_type_array)) {
      for (size_t i = 0; i < json_object_array_length(a); i++) r += json_object_get_int(json_object_array_get_idx(a, i));
      json_object_array_del_idx(a, 0, 1);
    }
    if (json_object_object_get_ex(root, "s", &s)) {
      const char *txt = json_object_get_string(s);    /* json-c's memory: not tracked by E-ACSL */
      json_object *copy = json_object_new_string(txt);
      json_object_object_add(root, txt, copy);
      r += json_object_get_string_len(copy);
    }
    json_object *n = json_object_new_string_len("abcdef", 3);
    r += (long)strlen(json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN));
    r += (long)strlen(json_type_to_name(json_object_get_type(n)));
    json_tokener *tok = json_tokener_new();
    json_object *p = json_tokener_parse_ex(tok, "[1,", 3);
    r += json_tokener_get_error(tok) == json_tokener_continue;
    r += (long)strlen(json_tokener_error_desc(json_tokener_get_error(tok)));
    r += json_type_to_name((enum json_type)42) == NULL;
    enum json_tokener_error e;
    r += json_tokener_parse_verbose("nul", &e) == NULL && e != json_tokener_success;
    json_object_put(p);
    json_tokener_free(tok);
    json_object_put(n);
    json_object_put(root);
  }
  if (!strcmp(c, "null_array")) r = (long)json_object_array_length(NULL);
  if (!strcmp(c, "unterminated_key")) {
    json_object *o = json_object_new_object();
    char k[2] = {'a', 'b'};
    r = json_object_object_add(o, k, NULL);
  }
  if (!strcmp(c, "string_len_overread")) { char s[2] = "a"; r = json_object_new_string_len(s, 8) != NULL; }
  printf("%s done %ld\n", c, r);
  return 0;
}
"""

JSON_EACSL_CASES = {
    "ok": None,
    "null_array": "valid_obj",
    "unterminated_key": "valid_key",
    "string_len_overread": "readable_s",
}

# The json-c names whose values the stub repeats; checked against json-c 0.18 in the build image.
JSON_CONSTANTS = [
    "json_type_null", "json_type_boolean", "json_type_double", "json_type_int", "json_type_object",
    "json_type_array", "json_type_string", "json_tokener_success", "json_tokener_continue",
    "json_tokener_error_depth", "json_tokener_error_parse_eof", "json_tokener_error_parse_unexpected",
    "json_tokener_error_parse_null", "json_tokener_error_parse_boolean", "json_tokener_error_parse_number",
    "json_tokener_error_parse_array", "json_tokener_error_parse_object_key_name",
    "json_tokener_error_parse_object_key_sep", "json_tokener_error_parse_object_value_sep",
    "json_tokener_error_parse_string", "json_tokener_error_parse_comment",
    "json_tokener_error_parse_utf8_string", "json_tokener_error_size", "json_tokener_error_memory",
    "JSON_C_TO_STRING_PLAIN", "JSON_C_TO_STRING_SPACED", "JSON_C_TO_STRING_PRETTY", "JSON_C_TO_STRING_NOZERO",
    "JSON_C_TO_STRING_PRETTY_TAB", "JSON_C_TO_STRING_NOSLASHESCAPE", "JSON_C_TO_STRING_COLOR",
    "JSON_TOKENER_DEFAULT_DEPTH", "JSON_TOKENER_STRICT", "JSON_TOKENER_ALLOW_TRAILING_CHARS",
    "JSON_TOKENER_VALIDATE_UTF8", "sizeof(json_bool)",
]  # fmt: skip


def _static_assert_generator(header: str, exprs: list[str], pre: str = "") -> str:
    """A program that prints, with the real header, one `_Static_assert` per expression."""
    lines = "".join(f"  P({e});\n" for e in exprs)
    return (
        f"#include <stddef.h>\n#include <stdio.h>\n{pre}#include <{header}>\n"
        '#define P(e) printf("_Static_assert((%s) == %lld, \\"%s\\");\\n", #e, (long long)(e), #e)\n'
        f"int main(void) {{\n{lines}  return 0;\n}}\n"
    )


@pytest.mark.integration
@pytest.mark.slow
def test_json_stub_in_eva_and_against_the_real_json_c(tmp_path):
    require_docker_images(ANALYSIS_IMAGE, BUILD_IMAGE)
    (tmp_path / "eva.c").write_text(JSON_EVA, encoding="utf-8", newline="\n")
    (tmp_path / "je.c").write_text(JSON_EACSL, encoding="utf-8", newline="\n")
    (tmp_path / "abi.c").write_text(
        "#include <json-c/json.h>\n" + "\n".join(stub_prototypes("json-c/json.h")) + "\n",
        encoding="utf-8", newline="\n",
    )  # fmt: skip
    (tmp_path / "gen.c").write_text(_static_assert_generator("json-c/json.h", JSON_CONSTANTS), encoding="utf-8")
    mains = ["ok", "no_null_check", "unterminated_key", "short_string_len", "null_tokener", "long_string"]
    # 1. Analysis image: Eva, then the E-ACSL instrumented object (linked against json-c in step 2).
    script = (
        _eva_script("eva.c", mains)
        + 'echo "@@MAIN eacsl"; e-acsl-gcc --full-mtracking -G clang -E "$F" -n -O je je.c > inst.log 2>&1 '
        + "|| cat inst.log; S=$(frama-c -print-share-path)/e-acsl; L=$(dirname $(which frama-c))/../lib/frama-c-e-acsl; "
        + "mkdir -p link && clang -c -w -DE_ACSL_SEGMENT_MMODEL -I$S -o link/je.o a.out.frama.c "
        + "&& clang -c -w -DE_ACSL_SEGMENT_MMODEL -I$S -o link/rtl.o $S/e_acsl_rtl.c "
        + "&& cp $L/libeacsl-dlmalloc.a /usr/lib/x86_64-linux-gnu/libgmp.a link/ && echo OBJECTS_OK; "
        + 'echo "undefined ghost: $(nm link/je.o | grep -c " U __fc_json")"'
    )
    log = _docker(ANALYSIS_IMAGE, tmp_path, script)
    per = _per_main(log)
    _assert_clean(per["ok"])
    for main, failed in (
        ("no_null_check", "json_object_array_length: precondition 'valid_obj' got status unknown"),
        ("unterminated_key", "json_object_object_add: precondition 'valid_key' got status invalid"),
        ("short_string_len", "json_object_new_string_len: precondition 'readable_s' got status invalid"),
        ("null_tokener", "json_tokener_parse_ex: precondition 'valid_tok' got status invalid"),
        ("long_string", "strcpy: precondition 'room_string' got status unknown"),
    ):
        assert f"function {failed}" in per[main], per[main]
    assert "OBJECTS_OK" in per["eacsl"] and "undefined ghost: 0" in per["eacsl"], per["eacsl"]
    # 2. Build image (json-c 0.18): prototypes and constants against the real header; the E-ACSL binary
    #    against the real library.
    cases = " ".join(JSON_EACSL_CASES)
    script = (
        'echo "@@MAIN abi"; gcc -fsyntax-only -Werror abi.c 2>&1 && echo ABI_OK; '
        + "gcc -o gen gen.c && ./gen > asserts.h && gcc -fsyntax-only -Werror "
        + "-I/opt/framac-pipeline/templates/fc_stubs -include json-c/json.h -include stddef.h -x c asserts.h "
        + "2>&1 && echo CONSTANTS_OK; "
        + 'echo "@@MAIN run"; cd link && clang -o je je.o rtl.o libeacsl-dlmalloc.a -ljson-c libgmp.a -lm 2>&1; '
        + f'for k in {cases}; do timeout 60 ./je $k > $k.out 2>&1; echo "case $k rc=$?"; done'
    )
    log = _docker(BUILD_IMAGE, tmp_path, script)
    per = _per_main(log)
    assert "ABI_OK" in per["abi"] and "CONSTANTS_OK" in per["abi"], per["abi"]
    for case, precondition in JSON_EACSL_CASES.items():
        out = (tmp_path / "link" / f"{case}.out").read_text(encoding="utf-8", errors="replace")
        if precondition is None:
            assert f"case {case} rc=0" in log and f"{case} done" in out, (case, out, log)
        else:
            assert "Precondition failed" in out and f"{precondition}:" in out, (case, out)


ICMP_LAYOUT = [
    "sizeof(struct icmphdr)", "offsetof(struct icmphdr, checksum)", "offsetof(struct icmphdr, un.echo.sequence)",
    "offsetof(struct icmphdr, un.frag.mtu)", "sizeof(struct icmp)", "sizeof(struct icmp_ra_addr)",
    "offsetof(struct icmp, icmp_cksum)", "offsetof(struct icmp, icmp_pptr)", "offsetof(struct icmp, icmp_gwaddr)",
    "offsetof(struct icmp, icmp_id)", "offsetof(struct icmp, icmp_seq)", "offsetof(struct icmp, icmp_void)",
    "offsetof(struct icmp, icmp_pmvoid)", "offsetof(struct icmp, icmp_nextmtu)", "offsetof(struct icmp, icmp_num_addrs)",
    "offsetof(struct icmp, icmp_wpa)", "offsetof(struct icmp, icmp_lifetime)", "offsetof(struct icmp, icmp_otime)",
    "offsetof(struct icmp, icmp_rtime)", "offsetof(struct icmp, icmp_ttime)", "offsetof(struct icmp, icmp_ip)",
    "sizeof(((struct icmp *)0)->icmp_ip)", "offsetof(struct icmp, icmp_ip.ip_src)", "offsetof(struct icmp, icmp_radv)",
    "offsetof(struct icmp, icmp_mask)", "offsetof(struct icmp, icmp_data)", "ICMP_TSLEN", "ICMP_ADVLENMIN",
]  # fmt: skip

ICMP_USE = r"""
#include <netinet/ip_icmp.h>
/*@ requires \valid_read(p); assigns \nothing; */
int advlen(const struct icmp *p) { return (int)ICMP_ADVLEN(p) + (p->icmp_type == ICMP_UNREACH); }
"""


def _icmp_constants() -> list[str]:
    return re.findall(r"^#define ((?:NR_)?ICMP_[A-Z0-9_]+)\s+(?!\()", _read("netinet/ip_icmp.h"), re.M)


@pytest.mark.unit
def test_icmp_constant_list_covers_the_bsd_names():
    names = _icmp_constants()
    assert {"ICMP_UNREACH", "ICMP_TIMXCEED", "ICMP_MASKREQ", "ICMP_ECHO", "NR_ICMP_UNREACH"} <= set(names)
    assert "ICMP_ADVLEN" not in names and "ICMP_INFOTYPE" not in names  # function-like


@pytest.mark.integration
@pytest.mark.slow
def test_icmp_stub_matches_glibc_in_gcc_and_in_frama_c(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    exprs = ICMP_LAYOUT + [n for n in _icmp_constants() if n not in ("ICMP_TSLEN", "ICMP_ADVLENMIN")]
    # glibc spells ICMP_TSLEN with n_time, from <netinet/in_systm.h>, which its ip_icmp.h does not include.
    gen = _static_assert_generator("netinet/ip_icmp.h", exprs, pre="#include <netinet/in_systm.h>\n")
    (tmp_path / "gen.c").write_text(gen, encoding="utf-8")
    (tmp_path / "use.c").write_text(ICMP_USE, encoding="utf-8", newline="\n")
    script = (
        "gcc -o gen gen.c && ./gen > asserts.inc && "
        '{ printf "#include <stddef.h>\\n#include <netinet/ip_icmp.h>\\n"; cat asserts.inc; } > check.c && '
        "gcc -fsyntax-only -Werror -I/opt/framac-pipeline/templates/fc_stubs check.c 2>&1 && echo GCC_OK; "
        'frama-c -no-unicode check.c use.c -cpp-extra-args="$A" 2>&1 && echo FRAMAC_OK'
    )
    log = _docker(ANALYSIS_IMAGE, tmp_path, script)
    assert "GCC_OK" in log and "FRAMAC_OK" in log, log
    assert (tmp_path / "asserts.inc").read_text(encoding="utf-8").count("_Static_assert") == len(exprs), log


@pytest.mark.unit
def test_compat_eacsl_string_predicates_have_one_conjunct_after_the_guard():
    # Same E-ACSL 35 defect as above, for the string vocabulary of E-ACSL builds.
    text = _read("fc_compat_types.h")
    vocabulary = text.split("#if defined(__FRAMAC_EACSL__)\n\n/*@", 1)[1].split("@*/", 1)[0]
    bodies = _quantifier_bodies(vocabulary)
    assert bodies
    for body in bodies:
        conjuncts = _top_level_conjuncts(body)
        assert len(conjuncts) == 2 and re.fullmatch(r"__fc_\w+\([^;]*\)", conjuncts[1], re.S), body


# ---------------------------------------------------------------------------------------------------
# <sys/epoll.h> and <sys/inotify.h>: the headers of upstream patch 39, with contracts (c-ares run-1)
# ---------------------------------------------------------------------------------------------------

LINUX_EVENT_HEADERS = {
    "sys/epoll.h": ["epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait"],
    "sys/inotify.h": ["inotify_init", "inotify_init1", "inotify_add_watch", "inotify_rm_watch"],
}
# Lines the pipeline added inside the patch's text, per header; each one is marked `pipeline addition`.
LINUX_EVENT_ADDITIONS = {"sys/epoll.h": 2, "sys/inotify.h": 0}
_EVA_WP_ONLY = "#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)"
_PATCH_39 = ROOT / "docs" / "upstream" / "frama-c" / "patches" / "39-libc-linux-header-gaps.patch"


def _between_decls(lines: list[str]) -> list[str]:
    return lines[lines.index("__BEGIN_DECLS") : lines.index("__END_DECLS") + 1]


@pytest.mark.unit
@pytest.mark.parametrize("rel", sorted(LINUX_EVENT_HEADERS))
def test_linux_event_headers_declare_with_contracts_for_eva_and_wp_only(rel):
    text = _read(rel)
    # Declared here, so stub_gen classifies the functions pipeline_stub and drafts no overlay block for them.
    assert [p.split("(")[0].split()[-1] for p in stub_prototypes(rel)] == LINUX_EVENT_HEADERS[rel]
    eva_wp, rest = text.split(_EVA_WP_ONLY, 1)[1].split("\n#else", 1)
    # Eva and WP never read glibc's header: it needs glibc's <sys/cdefs.h>, which redefines __THROW,
    # __nonnull, ... for every later libc header (c-ares run-1).
    assert "#include_next" not in eva_wp and not re.search(r"#\s*include\s*<sys/cdefs\.h>", text)
    # E-ACSL and plain compiles read glibc's header and nothing else: the contracts name objects of
    # Frama-C's libc (__FC_MAX_OPEN_FILES, Frama_C_entropy_source) that host headers do not have.
    host = rest.split("#endif /* Eva / WP */", 1)[0].strip().splitlines()
    assert host[-1] == f"#include_next <{rel}>" and not any(line.startswith("#") for line in host[:-1]), host
    assert text.count("#include_next") == 1
    # Not a libc file: only libc's own headers sit under the fc_stdlib pragma.
    assert "__PUSH_FC_STDLIB" not in re.sub(r"/\*.*?\*/", "", text, flags=re.S)


@pytest.mark.unit
@pytest.mark.parametrize("rel", sorted(LINUX_EVENT_HEADERS))
def test_linux_event_headers_carry_the_text_of_the_upstream_patch(rel):
    """One text for the pipeline and for pub/frama-c!56: a change to one side is made to both."""
    patch_text = _PATCH_39.read_text(encoding="utf-8")
    section = patch_text.split(f"+++ b/share/libc/{rel}\n", 1)[1].split("\ndiff --git ", 1)[0]
    patch = [line[1:] for line in section.split("\n")[1:] if line.startswith("+")]
    upstream = [re.sub(r'^#include "\.\./([^"]+)"$', r"#include <\1>", line) for line in _between_decls(patch)]
    local = _between_decls(_read(rel).split("\n"))
    added = [line for line in local if "pipeline addition" in line]
    assert len(added) == LINUX_EVENT_ADDITIONS[rel], added
    assert [line for line in local if line not in added] == upstream


def _linux_event_constants() -> list[str]:
    names: list[str] = []
    for rel in sorted(LINUX_EVENT_HEADERS):
        names += re.findall(r"^#define ((?:EPOLL|IN_)[A-Z0-9_]+)\s", _read(rel), re.M)
    return names


@pytest.mark.unit
def test_linux_event_constant_list_covers_both_headers():
    names = _linux_event_constants()
    assert {"EPOLLIN", "EPOLLET", "EPOLL_CLOEXEC", "EPOLL_CTL_MOD", "IN_MODIFY", "IN_ALL_EVENTS", "IN_NONBLOCK"} <= set(
        names
    )
    assert len(names) == len(set(names))


LINUX_EVENT_LAYOUT = [
    "sizeof(struct epoll_event)", "offsetof(struct epoll_event, events)", "offsetof(struct epoll_event, data)",
    "sizeof(epoll_data_t)", "sizeof(struct inotify_event)", "offsetof(struct inotify_event, wd)",
    "offsetof(struct inotify_event, mask)", "offsetof(struct inotify_event, cookie)",
    "offsetof(struct inotify_event, len)", "offsetof(struct inotify_event, name)",
]  # fmt: skip

LINUX_EVENT_EVA = r"""#include <sys/epoll.h>
#include <sys/inotify.h>
#include <signal.h>
#include <unistd.h>

/* An event loop as c-ares writes it: every event the call returned is read. */
int loop(void) {
  struct epoll_event ev[8];
  unsigned seen = 0;
  int fd = epoll_create1(EPOLL_CLOEXEC);
  if (fd < 0) return -1;
  ev[0].events = EPOLLIN | EPOLLRDHUP;
  ev[0].data.fd = 0;
  if (epoll_ctl(fd, EPOLL_CTL_ADD, 0, &ev[0]) != 0) return -1;
  int n = epoll_wait(fd, ev, 8, 1000);
  for (int i = 0; i < n; i++)
    seen += (ev[i].events & (EPOLLIN | EPOLLHUP | EPOLLERR)) != 0;
  (void)epoll_ctl(fd, EPOLL_CTL_DEL, 0, 0);
  return (int)(seen & 1);
}
int pwait(void) {
  struct epoll_event ev[4];
  sigset_t mask;
  int fd = epoll_create(1);
  if (fd < 0) return -1;
  sigemptyset(&mask);
  return epoll_pwait(fd, ev, 4, 0, &mask) + epoll_pwait(fd, ev, 4, 0, 0);
}
int watch(void) {
  int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  if (fd < 0) return -1;
  int wd = inotify_add_watch(fd, "/etc", IN_MODIFY | IN_CREATE | IN_MOVED_TO | IN_ONLYDIR);
  if (wd < 0) return -1;
  return inotify_rm_watch(fd, wd);
}
int short_events(void) {
  struct epoll_event ev[2];
  int fd = epoll_create1(0);
  if (fd < 0) return -1;
  return epoll_wait(fd, ev, 4, 0);
}
int unchecked_fd(void) { struct epoll_event ev[2]; return epoll_wait(epoll_create1(0), ev, 2, 0); }
int add_without_event(void) {
  int fd = epoll_create1(0);
  if (fd < 0) return -1;
  return epoll_ctl(fd, EPOLL_CTL_ADD, 0, 0);
}
int unterminated_path(void) {
  char p[2] = {'/', 'x'};
  int fd = inotify_init();
  if (fd < 0) return -1;
  return inotify_add_watch(fd, p, IN_MODIFY);
}
"""

# Frama-C's <signal.h>, <time.h> and <sys/select.h> before the two headers.
LINUX_EVENT_LATE = "#include <signal.h>\n#include <time.h>\n#include <sys/select.h>\n" + LINUX_EVENT_EVA

LINUX_EVENT_WP = r"""#include <sys/epoll.h>
#include <sys/inotify.h>
#include <signal.h>

/*@ requires 0 <= epfd < __FC_MAX_OPEN_FILES;
    assigns \nothing; */
unsigned count_ready(int epfd) {
  struct epoll_event ev[8];
  unsigned seen = 0;
  int n = epoll_wait(epfd, ev, 8, 0);
  /*@ loop invariant 0 <= i <= 8;
      loop assigns i, seen;
      loop variant n - i; */
  for (int i = 0; i < n; i++)
    seen += (ev[i].events & EPOLLIN) != 0;   /* the index needs n <= 8 */
  return seen;
}

/*@ requires 0 <= epfd < __FC_MAX_OPEN_FILES;
    requires \valid(ev + (0 .. 7)) && \valid_read(mask);
    assigns ev[0 .. 7];
    ensures -1 <= \result <= 8; */
int ppoll8(int epfd, struct epoll_event *ev, const sigset_t *mask) { return epoll_pwait(epfd, ev, 8, 0, mask); }

/*@ requires 0 <= fd < __FC_MAX_OPEN_FILES;
    assigns \nothing;
    ensures \result >= -1; */
int watch_etc(int fd) { return inotify_add_watch(fd, "/etc", IN_MODIFY); }
"""

# What the E-ACSL frontend reads is glibc's header: epoll_pwait2 exists only there (under _GNU_SOURCE).
LINUX_EVENT_HOST = r"""#include <sys/epoll.h>
#include <sys/inotify.h>
#include <signal.h>
#include <time.h>
int host(void) {
  struct epoll_event ev[4];
  char buf[sizeof(struct inotify_event) + 16];
  struct inotify_event *e = (struct inotify_event *)buf;
  struct timespec ts = {0, 0};
  sigset_t mask;
  int fd = epoll_create1(EPOLL_CLOEXEC);
  if (fd < 0) return -1;
  sigemptyset(&mask);
  e->len = 0;
  return epoll_pwait2(fd, ev, 4, &ts, &mask) + inotify_init1(IN_CLOEXEC) + (int)sizeof(e->name[0]);
}
"""

LINUX_EVENT_MAINS = ["loop", "pwait", "watch", "short_events", "unchecked_fd", "add_without_event", "unterminated_path"]


@pytest.mark.integration
@pytest.mark.slow
def test_linux_event_headers_in_eva_wp_and_against_glibc(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    exprs = LINUX_EVENT_LAYOUT + _linux_event_constants()
    sources = {
        "eva.c": LINUX_EVENT_EVA,
        "late.c": LINUX_EVENT_LATE,
        "wp.c": LINUX_EVENT_WP,
        "host.c": LINUX_EVENT_HOST,
        "gen.c": _static_assert_generator("sys/epoll.h", exprs, pre="#include <sys/inotify.h>\n"),
    }
    for name, text in sources.items():
        (tmp_path / name).write_text(text, encoding="utf-8", newline="\n")
    fc = "timeout 300 frama-c -no-unicode -machdep gcc_x86_64"
    script = "".join(
        f'echo "@@MAIN {m}"; {fc} eva.c -cpp-extra-args="$A" -eva -eva-no-show-progress -warn-invalid-pointer '
        f"-main {m} 2>&1; "
        for m in LINUX_EVENT_MAINS
    )
    script += (
        f'echo "@@MAIN late"; {fc} late.c -cpp-extra-args="$A" 2>&1 && echo PARSE_OK; '
        f'echo "@@MAIN wp"; {fc} wp.c -cpp-extra-args="$A" -wp -wp-rte -wp-timeout 30 2>&1; '
        # glibc's values (gcc) become _Static_asserts that Frama-C checks against this header.
        'echo "@@MAIN layout"; gcc -o gen gen.c && ./gen > asserts.inc && '
        '{ printf "#include <stddef.h>\\n#include <sys/epoll.h>\\n#include <sys/inotify.h>\\n"; cat asserts.inc; } '
        f'> check.c && {fc} check.c -cpp-extra-args="$A" 2>&1 && echo FRAMAC_OK; '
        f'echo "@@MAIN host"; {fc} host.c -cpp-extra-args="$F -D_GNU_SOURCE" -no-frama-c-stdlib 2>&1 && echo PARSE_OK'
    )
    log = _docker(ANALYSIS_IMAGE, tmp_path, script, timeout=1800)
    per = _per_main(log)
    for main in ("pwait", "watch"):
        _assert_clean(per[main])
    # The loop: every precondition holds. One alarm stays, on the events the loop reads: Eva joins the
    # `full` and `partial_timeout_or_error` behaviors and loses the link between n and the initialized
    # prefix, as it does for read() (stated in pub/frama-c#2828; README of fc_stubs).
    assert re.search(r"Preconditions\s+\d+ valid\s+0 unknown\s+0 invalid", per["loop"]), per["loop"]
    assert "assert \\initialized(&ev[i].events);" in per["loop"], per["loop"]
    assert "1 alarm generated by the analysis" in per["loop"], per["loop"]
    for main, failed in (
        ("short_events", "epoll_wait: precondition 'valid_events' got status invalid"),
        ("unchecked_fd", "epoll_wait: precondition 'valid_epfd' got status unknown"),
        ("add_without_event", "epoll_ctl: precondition 'valid_event' got status invalid"),
        ("unterminated_path", "inotify_add_watch: precondition 'valid_pathname' got status invalid"),
    ):
        assert f"function {failed}" in per[main], per[main]
    for main in LINUX_EVENT_MAINS:
        assert "User Error" not in per[main] and "found two contracts" not in per[main], per[main]
    assert "PARSE_OK" in per["late"] and "Warning" not in per["late"], per["late"]
    # count_ready's index proof needs `result_bounded`, the clause the pipeline added to the patch's text.
    assert all(proved == total for proved, total in wp_proved_goals(per["wp"])), per["wp"]
    assert "FRAMAC_OK" in per["layout"] and "User Error" not in per["layout"], per["layout"]
    assert (tmp_path / "asserts.inc").read_text(encoding="utf-8").count("_Static_assert") == len(exprs), log
    assert "PARSE_OK" in per["host"], per["host"]
    assert "User Error" not in per["host"] and "undeclared" not in per["host"], per["host"]


# ---------------------------------------------------------------------------------------------------
# glibc names __fc_libc lacks, found on c-ares: pipe2, getservbyname_r, getservbyport_r, IN6_IS_ADDR_*
# ---------------------------------------------------------------------------------------------------

# function -> (the behavior of a success, the behavior of a failure) in its fc_compat_types.h contract
LIBC_GAP_BEHAVIORS = {
    "pipe2": ("ok", "error"),
    "getservbyname_r": ("found", "not_found_or_error"),
    "getservbyport_r": ("found", "not_found_or_error"),
}
LIBC_GAP_IN6 = [
    "UNSPECIFIED",
    "LOOPBACK",
    "MULTICAST",
    "LINKLOCAL",
    "SITELOCAL",
    "V4MAPPED",
    "V4COMPAT",
    "MC_NODELOCAL",
    "MC_LINKLOCAL",
    "MC_SITELOCAL",
    "MC_ORGLOCAL",
    "MC_GLOBAL",
]


def _fc_libc_branch() -> str:
    text = _read("fc_compat_types.h")
    return text.split("#else /* Frama-C __fc_libc */", 1)[1].split("#endif /* __FRAMAC_EACSL__ */", 1)[0]


def _contract_parts(contract: str) -> tuple[str, dict[str, str]]:
    """(the clauses before the first behavior, {behavior: its clauses without the `assumes`})."""
    head, *rest = re.split(r"^\s*behavior\s+(\w+):\s*$", contract, flags=re.M)
    behaviors = {}
    for name, body in zip(rest[0::2], rest[1::2], strict=True):
        body = re.sub(r"^\s*(?:complete|disjoint) behaviors;\s*$", "", body, flags=re.M)
        behaviors[name] = re.sub(r"^\s*assumes\b[^;]*;\s*$", "", body, flags=re.M)
    return head, behaviors


def _in6_macro_block() -> str:
    block = _fc_libc_branch().split("#ifndef IN6_IS_ADDR_UNSPECIFIED\n", 1)[1]
    return block.split("#endif /* IN6_IS_ADDR_UNSPECIFIED */", 1)[0]


def test_libc_gap_names_are_declared_for_eva_and_wp_after_the_renaming_blocks():
    text = _read("fc_compat_types.h")
    fc_libc = _fc_libc_branch()
    # After the blocks that must be the first to include <sys/socket.h>, <unistd.h> and <string.h>.
    order = [
        fc_libc.index('#include "fc_strlcpy.h"'),
        fc_libc.index("#ifndef FC_STUBS_NO_PIPE2_DECL"),
        fc_libc.index("extern int pipe2("),
        fc_libc.index("#ifndef FC_STUBS_NO_NETDB_DECLS"),
        fc_libc.index("#include <netdb.h>"),
        fc_libc.index("extern int getservbyname_r("),
        fc_libc.index("#endif /* FC_STUBS_NO_NETDB_DECLS */"),
    ]
    assert order == sorted(order)
    assert fc_libc.count("#include <netdb.h>") == 1
    # The netinet/tcp block includes <netinet/in.h> again, so it still parses with FC_STUBS_NO_NETDB_DECLS.
    netdb_block = fc_libc.split("#ifndef FC_STUBS_NO_NETDB_DECLS", 1)[1].split("#endif /* FC_STUBS_NO_NETDB_DECLS */", 1)[0]
    assert netdb_block.count("#include <netinet/in.h>") == 1
    # E-ACSL builds take all of them from glibc.
    eacsl_branch = text.split("#if defined(__FRAMAC_EACSL__)", 1)[1].split("#else /* Frama-C __fc_libc */", 1)[0]
    assert not re.search(r"pipe2|getservby|IN6_IS_ADDR", eacsl_branch)
    for name, wanted in LIBC_GAP_BEHAVIORS.items():
        contract = _contract_of(fc_libc, name)
        head, behaviors = _contract_parts(contract)
        assert tuple(behaviors) == wanted, name
        assert "complete behaviors;" in contract and "disjoint behaviors;" in contract, name
        # What WP can use is stated outside the behaviors, which split on a volatile.
        assert "Frama_C_entropy_source" not in re.sub(r"indirect:Frama_C_entropy_source", "", head), name
        assert head.count("ensures ") >= 4, name


def test_pipe2_leaves_the_ends_alone_on_error():
    head, behaviors = _contract_parts(_contract_of(_fc_libc_branch(), "pipe2"))
    assert "ensures result_ok_or_error: \\result == 0 || \\result == -1;" in head
    # __fc_libc's pipe() claims both ends initialized and valid whatever the result.
    assert "\\result == 0 ==> \\initialized(&pipefd[0 .. 1]);" in head
    assert not re.search(r"ensures [\w:]+: \\initialized", head)
    assert "\\result == -1 ==> pipefd[0] == \\old(pipefd[0]) && pipefd[1] == \\old(pipefd[1]);" in head
    assert "pipefd" not in behaviors["error"]


@pytest.mark.parametrize("name", ["getservbyname_r", "getservbyport_r"])
def test_getservby_r_can_give_the_callers_structure(name):
    head, behaviors = _contract_parts(_contract_of(_fc_libc_branch(), name))
    # `\from result_buf`: with a \from that leaves the caller's structure out, Eva can only give NULL
    # (__fc_libc's getpwnam_r, docs/upstream/frama-c/frama-c-hunt-2026-11-18-candidates.md, N6).
    assert re.search(r"assigns \*res \\from result_buf,", head)
    assert "ensures result_null_or_result_buf: *res == \\null || *res == result_buf;" in head
    assert "ensures null_on_error: \\result != 0 ==> *res == \\null;" in head
    assert "proto == \\null || valid_read_string(proto)" in head
    # Field by field: the padding after s_port is not written, and s_port holds no address.
    assert "assigns *result_buf" not in head and "\\initialized(result_buf)" not in head
    assert re.search(r"assigns result_buf->s_port \\from (?!buf)", head)
    assert "*res == result_buf" in behaviors["found"] and "*res == \\null" in behaviors["not_found_or_error"]


def test_in6_macros_are_the_posix_family_and_read_bytes():
    block = _in6_macro_block()
    assert re.findall(r"^#define IN6_IS_ADDR_(\w+)\(a\)", block, flags=re.M) == LIBC_GAP_IN6
    # Through s6_addr, the one member __fc_libc's struct in6_addr has: no word cast, no byte order.
    code = re.sub(r"/\*.*?\*/", "", block, flags=re.S)
    assert not re.search(r"uint(?:8|16|32)_t|htonl|ntohl|__in6_u", code)
    assert code.count("(const struct in6_addr *)(a)") == 1


LIBC_GAP_EVA = r"""#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include "__fc_builtin.h"

/* c-ares, ares_event_wake_pipe.c: both ends preset to -1, closed on failure when not -1. */
int wake_pipe(void) {
  int fds[2] = {-1, -1};
  if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) {
    Frama_C_show_each_error(fds[0], fds[1]);
    //@ check error_keeps_the_ends: fds[0] == -1 && fds[1] == -1;
    if (fds[0] != -1) close(fds[0]);
    return -1;
  }
  Frama_C_show_each_ok(fds[0], fds[1]);
  close(fds[0]);
  close(fds[1]);
  return 0;
}
int pipe_uninit(void) {
  int fds[2];
  if (pipe2(fds, 0) != 0) return -1;
  close(fds[0]);
  close(fds[1]);
  return 0;
}
int pipe_short(void) { int one; return pipe2(&one, 0); }

/* c-ares, ares_getaddrinfo.c: the service's port. */
int by_name(void) {
  struct servent se, *sep;
  char tmp[4096];
  memset(&se, 0, sizeof se);
  sep = &se;
  memset(tmp, 0, sizeof tmp);
  if (getservbyname_r("http", "tcp", &se, (void *)tmp, sizeof tmp, &sep) != 0) sep = NULL;
  if (sep) {
    Frama_C_show_each_found(sep, sep->s_port);
    return sep->s_port;
  }
  Frama_C_show_each_none(sep);
  return -1;
}
int by_name_any_proto(void) {
  struct servent se, *sep;
  char tmp[512];
  int r = getservbyname_r("http", NULL, &se, tmp, sizeof tmp, &sep);
  Frama_C_show_each_any(r, sep);
  return sep != NULL;
}
/* c-ares, ares_getnameinfo.c: the port's service name, which is then copied. */
int by_port(void) {
  struct servent se, *sep;
  char tmp[4096];
  memset(&se, 0, sizeof se);
  sep = &se;
  memset(tmp, 0, sizeof tmp);
  if (getservbyport_r(htons(80), "tcp", &se, (void *)tmp, sizeof tmp, &sep) != 0) sep = NULL;
  if (sep && sep->s_name) {
    Frama_C_show_each_port(sep->s_port, sep->s_name);
    return (int)strlen(sep->s_name);
  }
  return -1;
}
int short_buf(void) {
  struct servent se, *sep;
  char tmp[16];
  return getservbyname_r("http", "tcp", &se, tmp, 64, &sep);
}
int unterminated_name(void) {
  struct servent se, *sep;
  char tmp[64], n[4] = {'h', 't', 't', 'p'};
  return getservbyname_r(n, "tcp", &se, tmp, sizeof tmp, &sep);
}
int null_res(void) {
  struct servent se;
  char tmp[64];
  return getservbyport_r(80, "tcp", &se, tmp, sizeof tmp, NULL);
}
int overlap(void) {
  struct servent se, *sep;
  return getservbyname_r("http", "tcp", &se, (char *)&se, sizeof se, &sep);
}

static int scope(const struct in6_addr *a) { /* c-ares, ares_sortaddrinfo.c: get_scope */
  if (IN6_IS_ADDR_MULTICAST(a)) return 1;
  else if (IN6_IS_ADDR_LOOPBACK(a) || IN6_IS_ADDR_LINKLOCAL(a)) return 2;
  else if (IN6_IS_ADDR_SITELOCAL(a)) return 5;
  else if (IN6_IS_ADDR_V4COMPAT(a) || IN6_IS_ADDR_V4MAPPED(a)) return 4;
  return 14;
}
int in6(void) {
  struct in6_addr lo = IN6ADDR_LOOPBACK_INIT, any = IN6ADDR_ANY_INIT;
  struct in6_addr ll = {{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
  struct in6_addr sl = {{0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
  struct in6_addr mc = {{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
  struct in6_addr v4m = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4}};
  struct in6_addr v4c = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}};
  struct sockaddr_in6 sa;
  memset(&sa, 0, sizeof sa);
  sa.sin6_addr = ll;
  int a = scope(&lo), b = scope(&ll), c = scope(&sl), d = scope(&mc), e = scope(&v4m), f = scope(&v4c);
  int g = scope(&any);
  //@ check scopes: a == 2 && b == 2 && c == 5 && d == 1 && e == 4 && f == 4 && g == 14;
  int u = IN6_IS_ADDR_UNSPECIFIED(&any), nu = IN6_IS_ADDR_UNSPECIFIED(&lo);
  int v = IN6_IS_ADDR_V4COMPAT(&lo), w = IN6_IS_ADDR_V4COMPAT(&any);
  //@ check unspecified: u == 1 && nu == 0 && v == 0 && w == 0;
  int is_ll = IN6_IS_ADDR_LINKLOCAL(&sa.sin6_addr), is_mcll = IN6_IS_ADDR_MC_LINKLOCAL(&sa.sin6_addr);
  int m1 = IN6_IS_ADDR_MC_LINKLOCAL(&mc);
  int m2 = IN6_IS_ADDR_MC_NODELOCAL(&mc) + IN6_IS_ADDR_MC_SITELOCAL(&mc) + IN6_IS_ADDR_MC_ORGLOCAL(&mc)
           + IN6_IS_ADDR_MC_GLOBAL(&mc);
  //@ check multicast_scopes: is_ll == 1 && is_mcll == 0 && m1 == 1 && m2 == 0;
  int n = 0;
  const struct in6_addr *p = &lo;
  int once = IN6_IS_ADDR_LOOPBACK((n++, p));
  //@ check evaluated_once: once == 1 && n == 1;
  return a + b + c + d + e + f + g;
}
"""

LIBC_GAP_WP = r"""#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

/*@ requires \valid(fds + (0 .. 1));
    assigns fds[0 .. 1];
    ensures \result == 0 || \result == -1;
    ensures \result == 0 ==> 0 <= fds[0] < 1024 && 0 <= fds[1] < 1024;
    ensures \result == -1 ==> fds[0] == \old(fds[0]) && fds[1] == \old(fds[1]); */
int open_pair(int *fds) { return pipe2(fds, 0); }

/*@ requires valid_read_string(name);
    assigns \nothing;
    ensures \result == 0 || \result == 1; */
int known_service(const char *name) {
  struct servent se, *sep = &se;
  char tmp[1024];
  int r = getservbyname_r(name, (const char *)0, &se, tmp, sizeof tmp, &sep);
  if (r != 0) {
    //@ assert error_gives_null: sep == \null;
    return 0;
  }
  if (sep == (struct servent *)0) return 0;
  //@ assert found_is_the_callers: sep == &se;
  //@ assert found_strings: valid_read_string(se.s_name) && valid_read_string(se.s_proto);
  return 1;
}

/*@ assigns \nothing;
    ensures \result == -1 || \result == port; */
int port_or_minus_one(int port) {
  struct servent se, *sep = &se;
  char tmp[1024];
  if (getservbyport_r(port, "tcp", &se, tmp, sizeof tmp, &sep) != 0) return -1;
  if (sep == (struct servent *)0) return -1;
  return se.s_port;
}

/*@ requires \valid_read(a);
    assigns \nothing;
    ensures a->s6_addr[0] == 0xff ==> \result == 1;
    ensures a->s6_addr[0] == 0xfe && (a->s6_addr[1] & 0xc0) == 0x80 ==> \result == 2;
    ensures \result == 1 || \result == 2 || \result == 14; */
int scope(const struct in6_addr *a) {
  if (IN6_IS_ADDR_MULTICAST(a)) return 1;
  else if (IN6_IS_ADDR_LOOPBACK(a) || IN6_IS_ADDR_LINKLOCAL(a)) return 2;
  return 14;
}
"""

# What the E-ACSL frontend reads is glibc: the ten names c-ares uses must come from there, untouched.
LIBC_GAP_HOST = r"""#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
int host(const struct sockaddr_in6 *a) {
  int fds[2] = {-1, -1};
  struct servent se, *sep = &se;
  char tmp[1024];
  const struct in6_addr *p = &a->sin6_addr;
  int n = pipe2(fds, O_CLOEXEC) + getservbyname_r("http", "tcp", &se, tmp, sizeof tmp, &sep)
          + getservbyport_r(80, (const char *)0, &se, tmp, sizeof tmp, &sep);
  return n + IN6_IS_ADDR_LINKLOCAL(p) + IN6_IS_ADDR_LOOPBACK(p) + IN6_IS_ADDR_MC_LINKLOCAL(p)
         + IN6_IS_ADDR_MULTICAST(p) + IN6_IS_ADDR_SITELOCAL(p) + IN6_IS_ADDR_V4COMPAT(p) + IN6_IS_ADDR_V4MAPPED(p);
}
"""

# glibc's macros against the stub's, renamed FC_IN6_IS_ADDR_*, in one gcc program.
LIBC_GAP_IN6_CMP = r"""#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
@@OURS@@
static unsigned long n, bad;
static struct in6_addr a;
#define CMP(name)                                                              \
  do {                                                                         \
    int g = IN6_IS_ADDR_##name(&a) != 0, o = FC_IN6_IS_ADDR_##name(&a) != 0;   \
    n++;                                                                       \
    if (g != o && bad++ < 5) {                                                 \
      printf("MISMATCH %s glibc=%d stub=%d:", #name, g, o);                    \
      for (int k = 0; k < 16; k++) printf(" %02x", a.s6_addr[k]);              \
      printf("\n");                                                            \
    }                                                                          \
  } while (0)
static void all(const unsigned char *b) {
  memcpy(a.s6_addr, b, 16);
@@CMPS@@
}
int main(void) {
  static const unsigned char tails[][14] = {
    {0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
    {0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4},
    {1},
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
  };
  unsigned char b[16];
  /* every value of the first two bytes, over each tail */
  for (unsigned t = 0; t < sizeof tails / sizeof tails[0]; t++)
    for (unsigned hi = 0; hi < 65536; hi++) {
      b[0] = (unsigned char)(hi >> 8);
      b[1] = (unsigned char)hi;
      memcpy(b + 2, tails[t], 14);
      all(b);
    }
  /* every value of each pair of bytes, the others zero */
  for (int i = 0; i < 16; i++)
    for (int j = i + 1; j < 16; j++)
      for (unsigned v = 0; v < 65536; v++) {
        memset(b, 0, 16);
        b[i] = (unsigned char)(v >> 8);
        b[j] = (unsigned char)v;
        all(b);
      }
  /* a fixed pseudo-random sample */
  unsigned long long s = 0x9e3779b97f4a7c15ull;
  for (int r = 0; r < 200000; r++) {
    for (int k = 0; k < 16; k++) {
      s = s * 6364136223846793005ull + 1442695040888963407ull;
      b[k] = (unsigned char)(s >> 56);
    }
    all(b);
  }
  printf("IN6_CMP n=%lu bad=%lu\n", n, bad);
  return bad != 0;
}
"""

# The real glibc functions behind wrappers that carry the contract text of fc_compat_types.h: `top_` its
# clauses outside the behaviors, the others the clauses of one behavior. Each case calls `top_`, then the
# wrapper of the behavior the outcome belongs to, so E-ACSL checks that glibc keeps what the contract says.
LIBC_GAP_REAL = r"""#define _GNU_SOURCE
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
@@WRAPPERS@@
static char buf[4096], buf2[4096];
static int in_buf(const char *p, const char *b, size_t len) { return p >= b && p < b + len; }

/* E-ACSL does not see glibc's writes, so the \initialized clauses hold from the fill below. `written`
   says the fields left the fill pattern and point into the caller's buffer. */
static int entry_written(const struct servent *se, const char *b, size_t len) {
  return se->s_port != 0x5a5a5a5a && in_buf(se->s_name, b, len) && in_buf(se->s_proto, b, len)
         && in_buf((const char *)se->s_aliases, b, len);
}
static void lookup(int by_port, const char *name, int port, const char *proto, size_t len) {
  struct servent se, se2, *sep = &se2, *sep2 = &se;
  int r, r2, found, written = 0;
  memset(&se, 0x5a, sizeof se);
  memset(&se2, 0x5a, sizeof se2);
  memset(buf, 0, sizeof buf);
  memset(buf2, 0, sizeof buf2);
  r = by_port ? top_getservbyport_r(port, proto, &se, buf, len, &sep)
              : top_getservbyname_r(name, proto, &se, buf, len, &sep);
  found = sep != NULL;
  if (found) {
    r2 = by_port ? found_getservbyport_r(port, proto, &se2, buf2, len, &sep2)
                 : found_getservbyname_r(name, proto, &se2, buf2, len, &sep2);
    written = entry_written(&se, buf, len) && entry_written(&se2, buf2, len);
  } else {
    r2 = by_port ? not_found_or_error_getservbyport_r(port, proto, &se2, buf2, len, &sep2)
                 : not_found_or_error_getservbyname_r(name, proto, &se2, buf2, len, &sep2);
  }
  printf("r=%d found=%d r2=%d written=%d\n", r, found, r2, written);
}
static void pipes(int flags) {
  int fds[2] = {-1, -1}, fds2[2] = {-1, -1};
  int r = top_pipe2(fds, flags), r2;
  int kept = fds[0] == -1 && fds[1] == -1;
  if (r == 0) {
    r2 = ok_pipe2(fds2, flags);
    close(fds[0]);
    close(fds[1]);
    if (r2 == 0) {
      close(fds2[0]);
      close(fds2[1]);
    }
  } else {
    r2 = error_pipe2(fds2, flags);
    kept = kept && fds2[0] == -1 && fds2[1] == -1;
  }
  printf("r=%d r2=%d kept=%d\n", r, r2, kept);
}
int main(int argc, char **argv) {
  const char *c = argc > 1 ? argv[1] : "";
  if (!strcmp(c, "name_found")) lookup(0, "http", 0, "tcp", sizeof buf);
  if (!strcmp(c, "name_any_proto")) lookup(0, "domain", 0, NULL, sizeof buf);
  if (!strcmp(c, "name_not_found")) lookup(0, "no-such-service", 0, "tcp", sizeof buf);
  if (!strcmp(c, "name_wrong_proto")) lookup(0, "http", 0, "no-such-proto", sizeof buf);
  if (!strcmp(c, "name_small_buf")) lookup(0, "http", 0, "tcp", 8);
  if (!strcmp(c, "port_found")) lookup(1, NULL, htons(80), "tcp", sizeof buf);
  if (!strcmp(c, "port_any_proto")) lookup(1, NULL, htons(53), NULL, sizeof buf);
  if (!strcmp(c, "port_not_found")) lookup(1, NULL, htons(65000), "tcp", sizeof buf);
  if (!strcmp(c, "port_small_buf")) lookup(1, NULL, htons(80), "tcp", 8);
  if (!strcmp(c, "pipe_ok")) pipes(O_CLOEXEC | O_NONBLOCK);
  if (!strcmp(c, "pipe_bad_flags")) pipes(-1);
  printf("%s done\n", c);
  return 0;
}
"""

_SERVENT_ARGS = "(%s, const char *proto, struct servent *result_buf, char *buf, size_t buflen, struct servent **res)"
LIBC_GAP_SIGNATURES = {
    "pipe2": ("(int pipefd[2], int flags)", "(pipefd, flags)"),
    "getservbyname_r": (_SERVENT_ARGS % "const char *name", "(name, proto, result_buf, buf, buflen, res)"),
    "getservbyport_r": (_SERVENT_ARGS % "int port", "(port, proto, result_buf, buf, buflen, res)"),
}

# case -> what it prints: the result, whether an entry was found, and what the behavior's wrapper gave.
# 34 is ERANGE; an entry glibc 2.41 does not find is result 0 with a NULL *res.
LIBC_GAP_REAL_CASES = {
    "name_found": "r=0 found=1 r2=0 written=1",
    "name_any_proto": "r=0 found=1 r2=0 written=1",
    "name_not_found": "r=0 found=0 r2=0 written=0",
    "name_wrong_proto": "r=0 found=0 r2=0 written=0",
    "name_small_buf": "r=34 found=0 r2=34 written=0",
    "port_found": "r=0 found=1 r2=0 written=1",
    "port_any_proto": "r=0 found=1 r2=0 written=1",
    "port_not_found": "r=0 found=0 r2=0 written=0",
    "port_small_buf": "r=34 found=0 r2=34 written=0",
    "pipe_ok": "r=0 r2=0 kept=0",
    "pipe_bad_flags": "r=-1 r2=-1 kept=1",
}

LIBC_GAP_MAINS = [
    "wake_pipe",
    "pipe_uninit",
    "pipe_short",
    "by_name",
    "by_name_any_proto",
    "by_port",
    "short_buf",
    "unterminated_name",
    "null_res",
    "overlap",
    "in6",
]


def _libc_gap_wrappers() -> str:
    fc_libc = _fc_libc_branch()
    out = []
    for name, (params, args) in LIBC_GAP_SIGNATURES.items():
        head, behaviors = _contract_parts(_contract_of(fc_libc, name))
        for prefix, clauses in (("top", head), *behaviors.items()):
            out.append(f"/*@{clauses}*/\nint {prefix}_{name}{params} {{ return {name}{args}; }}\n")
    return "".join(out)


@pytest.mark.integration
@pytest.mark.slow
def test_libc_gap_names_in_eva_wp_and_against_glibc(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    prototypes = stub_prototypes("fc_compat_types.h", set(LIBC_GAP_BEHAVIORS))
    assert len(prototypes) == len(LIBC_GAP_BEHAVIORS), prototypes
    ours = _in6_macro_block().replace("IN6_IS_ADDR_", "FC_IN6_IS_ADDR_")
    cmps = "".join(f"  CMP({name});\n" for name in LIBC_GAP_IN6)
    sources = {
        "eva.c": LIBC_GAP_EVA,
        "wp.c": LIBC_GAP_WP,
        "host.c": LIBC_GAP_HOST,
        "abi.c": "#define _GNU_SOURCE\n#include <netdb.h>\n#include <unistd.h>\n" + "\n".join(prototypes) + "\n",
        "in6.c": LIBC_GAP_IN6_CMP.replace("@@OURS@@", ours).replace("@@CMPS@@", cmps),
        "real.c": LIBC_GAP_REAL.replace("@@WRAPPERS@@", _libc_gap_wrappers()),
    }
    for name, text in sources.items():
        (tmp_path / name).write_text(text, encoding="utf-8", newline="\n")
    fc = "timeout 300 frama-c -no-unicode -machdep gcc_x86_64"
    cases = " ".join(LIBC_GAP_REAL_CASES)
    # -eva-slevel 100 is the pipeline's default (pipeline_make.DEFAULT_EVA_SLEVEL): with it Eva keeps the
    # two behaviors of a call apart.
    script = "".join(
        f'echo "@@MAIN {m}"; {fc} eva.c -cpp-extra-args="$A" -eva -eva-no-show-progress -warn-invalid-pointer '
        f"-eva-slevel 100 -main {m} 2>&1; "
        for m in LIBC_GAP_MAINS
    )
    script += (
        f'echo "@@MAIN wp"; {fc} wp.c -cpp-extra-args="$A" -wp -wp-rte -wp-timeout 30 2>&1; '
        'echo "@@MAIN abi"; gcc -fsyntax-only -Werror abi.c 2>&1 && echo ABI_OK; '
        'echo "@@MAIN in6cmp"; gcc -O1 -o in6 in6.c 2>&1 && ./in6; '
        f'echo "@@MAIN host"; {fc} host.c -cpp-extra-args="$F -D_GNU_SOURCE" -no-frama-c-stdlib 2>&1 && echo PARSE_OK; '
        'echo "@@MAIN real"; e-acsl-gcc --full-mtracking -G clang -E "$F" '
        '-e "-I/opt/framac-pipeline/templates/fc_stubs" -O rb real.c > real.build.log 2>&1 || cat real.build.log; '
        f'for k in {cases}; do timeout 60 ./rb.e-acsl $k > $k.out 2>&1; echo "case $k rc=$?"; done'
    )
    log = _docker(ANALYSIS_IMAGE, tmp_path, script, timeout=1800)
    per = _per_main(log)
    for main in LIBC_GAP_MAINS:
        assert "User Error" not in per[main] and "found two contracts" not in per[main], per[main]
        assert "undeclared function" not in per[main], per[main]
    # The pipe idiom of c-ares: -1 kept on error, two descriptors close() accepts on success.
    for main in ("wake_pipe", "pipe_uninit", "in6"):
        _assert_clean(per[main])
    assert "Frama_C_show_each_error: {-1}, {-1}" in per["wake_pipe"], per["wake_pipe"]
    assert "Frama_C_show_each_ok: [0..1023], [0..1023]" in per["wake_pipe"], per["wake_pipe"]
    assert re.search(r"Assertions\s+1 valid\s+0 unknown\s+0 invalid", per["wake_pipe"]), per["wake_pipe"]
    assert re.search(r"Assertions\s+4 valid\s+0 unknown\s+0 invalid", per["in6"]), per["in6"]
    # Both outcomes of a lookup are reachable (the found branch is dead with __fc_libc's getpwnam_r shape).
    for main in ("by_name", "by_name_any_proto"):
        assert "0 alarms generated by the analysis." in per[main], per[main]
        assert re.search(r"Preconditions\s+\d+ valid\s+0 unknown\s+0 invalid", per[main]), per[main]
    assert "Frama_C_show_each_found: {{ &se }}" in per["by_name"], per["by_name"]
    assert "Frama_C_show_each_none: {0}" in per["by_name"], per["by_name"]
    assert "Frama_C_show_each_any: {0}, {{ &se }}" in per["by_name_any_proto"], per["by_name_any_proto"]
    # The found name lies in the caller's buffer. One Unknown stays: Eva cannot tell that the bytes the
    # call wrote there are a string.
    assert "Frama_C_show_each_port: [0..65535], {{ &tmp + [0..4095] }}" in per["by_port"], per["by_port"]
    assert "function strlen: precondition 'valid_string_s' got status unknown" in per["by_port"], per["by_port"]
    assert re.search(r"Preconditions\s+\d+ valid\s+1 unknown\s+0 invalid", per["by_port"]), per["by_port"]
    assert "0 alarms generated by the analysis." in per["by_port"], per["by_port"]
    for main, failed in (
        ("pipe_short", "pipe2: precondition 'valid_pipefd'"),
        ("short_buf", "getservbyname_r: precondition 'valid_buf'"),
        ("unterminated_name", "getservbyname_r: precondition 'valid_name'"),
        ("null_res", "getservbyport_r: precondition 'valid_res'"),
        ("overlap", "getservbyname_r: precondition 'separation'"),
    ):
        assert f"function {failed} got status invalid" in per[main], per[main]
    assert all(proved == total for proved, total in wp_proved_goals(per["wp"])), per["wp"]
    assert "ABI_OK" in per["abi"], per["abi"]
    compared = re.search(r"IN6_CMP n=(\d+) bad=0\b", per["in6cmp"])
    assert compared and int(compared.group(1)) > 100_000_000, per["in6cmp"]
    assert "PARSE_OK" in per["host"], per["host"]
    assert "User Error" not in per["host"] and "undeclared" not in per["host"], per["host"]
    # E-ACSL runs every clause but the six `\subset` of the two `found` behaviors (and no `assigns`);
    # the program's own `written` covers what those say.
    build = (tmp_path / "real.build.log").read_text(encoding="utf-8", errors="replace")
    skipped = re.findall(r"E-ACSL construct\s+`([^']+)'\s+is not yet supported", build)
    assert sorted(set(skipped)) == [
        "assigns clause",
        "logic functions or predicates with no definition nor reads clause",
    ]
    assert skipped.count("logic functions or predicates with no definition nor reads clause") == 6, build
    for case, printed in LIBC_GAP_REAL_CASES.items():
        out = (tmp_path / f"{case}.out").read_text(encoding="utf-8", errors="replace")
        assert f"case {case} rc=0" in log and f"{case} done" in out, (case, out, per["real"])
        assert printed in out, (case, out)


# ---------------------------------------------------------------------------------------------------
# glibc <sched.h> CPU affinity names __fc_libc lacks, found on nginx: cpu_set_t, CPU_*, sched_*affinity
# ---------------------------------------------------------------------------------------------------

# In the order fc_compat_types.h defines them.
SCHED_MACROS = [
    "CPU_SETSIZE",
    "CPU_SET_S",
    "CPU_CLR_S",
    "CPU_ISSET_S",
    "CPU_ZERO_S",
    "CPU_COUNT_S",
    "CPU_SET",
    "CPU_CLR",
    "CPU_ISSET",
    "CPU_ZERO",
    "CPU_COUNT",
    "CPU_ALLOC_SIZE",
]
# function -> (return type, parameters, what glibc runs for it): glibc 2.41's prototypes, and for the
# pipeline's model of CPU_ZERO_S glibc's macro itself.
SCHED_SIGNATURES = {
    "__sched_cpucount": ("int", "(size_t setsize, const cpu_set_t *setp)", "__sched_cpucount(setsize, setp)"),
    "__fc_sched_cpuzero": ("void", "(size_t setsize, cpu_set_t *setp)", "CPU_ZERO_S(setsize, setp)"),
    "sched_setaffinity": (
        "int", "(pid_t pid, size_t cpusetsize, const cpu_set_t *mask)", "sched_setaffinity(pid, cpusetsize, mask)"
    ),
    "sched_getaffinity": (
        "int", "(pid_t pid, size_t cpusetsize, cpu_set_t *mask)", "sched_getaffinity(pid, cpusetsize, mask)"
    ),
}  # fmt: skip


def _sched_block() -> str:
    block = _fc_libc_branch().split("#ifndef FC_STUBS_NO_SCHED_AFFINITY_DECLS\n", 1)[1]
    return block.split("#endif /* FC_STUBS_NO_SCHED_AFFINITY_DECLS */", 1)[0]


def _sched_macro_block() -> str:
    """The CPU_* macros: from `#define CPU_SETSIZE` to the first contract after it."""
    return "#define CPU_SETSIZE" + _sched_block().split("#define CPU_SETSIZE", 1)[1].split("/*@", 1)[0]


def test_sched_affinity_names_are_declared_for_eva_and_wp_after_the_netdb_block():
    text = _read("fc_compat_types.h")
    fc_libc = _fc_libc_branch()
    order = [
        fc_libc.index("#endif /* FC_STUBS_NO_NETDB_DECLS */"),
        fc_libc.index("#ifndef FC_STUBS_NO_SCHED_AFFINITY_DECLS"),
        fc_libc.index("#include <sched.h>"),
        fc_libc.index("#ifndef CPU_SETSIZE"),
        fc_libc.index("} cpu_set_t;"),
        fc_libc.index("#define CPU_SETSIZE"),
        fc_libc.index("extern int __sched_cpucount("),
        fc_libc.index("extern void __fc_sched_cpuzero("),
        fc_libc.index("extern int sched_setaffinity("),
        fc_libc.index("extern int sched_getaffinity("),
        fc_libc.index("#endif /* CPU_SETSIZE */"),
        fc_libc.index("#endif /* FC_STUBS_NO_SCHED_AFFINITY_DECLS */"),
    ]
    assert order == sorted(order)
    assert fc_libc.count("#include <sched.h>") == 1
    # E-ACSL builds take all of them from glibc.
    eacsl_branch = text.split("#if defined(__FRAMAC_EACSL__)", 1)[1].split("#else /* Frama-C __fc_libc */", 1)[0]
    assert not re.search(r"cpu_set_t|CPU_|sched_", eacsl_branch)
    # glibc x86_64's layout: 1024 CPUs in unsigned longs.
    block = _sched_block()
    assert "typedef unsigned long int __cpu_mask;" in block
    assert "__cpu_mask __bits[__CPU_SETSIZE / __NCPUBITS];" in block
    assert re.findall(r"^#define (CPU_\w+)", _sched_macro_block(), flags=re.M) == SCHED_MACROS
    prototypes = stub_prototypes("fc_compat_types.h", set(SCHED_SIGNATURES))
    assert len(prototypes) == len(SCHED_SIGNATURES), prototypes


def test_sched_macros_evaluate_the_cpu_once_and_need_no_cast():
    macros = re.sub(r"/\*.*?\*/", "", _sched_macro_block(), flags=re.S)
    # glibc's semantics: the CPU number is read once, and one at or past setsize * 8 is ignored.
    assert macros.count("size_t __fc_cpu = (cpu);") == 3
    assert macros.count("__fc_cpu / 8 < (setsize)") == 3
    # Through `__bits` itself, the one member: no pointer cast for WP's Typed model to refuse.
    assert not re.search(r"\(\s*(?:const\s+)?__cpu_mask\s*\*\s*\)", macros)
    assert "__sched_cpucount(" in macros
    # Nor a conversion to memset's `void *`: CPU_ZERO_S is a declared model on whole words.
    assert "memset" not in macros and "__fc_sched_cpuzero(" in macros
    # CPU_ZERO: the same bytes, which Eva follows; every word explicit, which WP needs.
    assert "*(cpusetp) = (cpu_set_t){{" + ", ".join(["0"] * 16) + "}};" in macros
    head, _ = _contract_parts(_contract_of(_sched_block(), "__fc_sched_cpuzero"))
    assert "requires whole_words: setsize % sizeof(__cpu_mask) == 0;" in head
    assert "\\subset(setp->__bits[0 .. setsize / sizeof(__cpu_mask) - 1], {0})" in head
    # A set of CPU_ALLOC_SIZE(n) bytes has more than the member's sixteen words: the macros reach a word
    # through a pointer to the first one, never as `__bits[i]` (Eva: an out-of-bounds index from 16 on).
    assert macros.count("__FC_CPU_WORD(cpusetp, __fc_cpu)") == 3
    assert "#define __FC_CPU_WORD(cpusetp, cpu) ((&(cpusetp)->__bits[0])[__FC_CPU_ELT(cpu)])" in macros
    code = macros.split("#define __FC_CPU_WORD", 1)[1]
    assert not re.search(r"__bits\s*\[(?!0\])", code)


def test_sched_affinity_contracts_split_success_from_failure():
    block = _sched_block()
    head, behaviors = _contract_parts(_contract_of(block, "sched_getaffinity"))
    assert tuple(behaviors) == ("ok", "error")
    assert "ensures result_ok_or_error: \\result == 0 || \\result == -1;" in head
    # What WP uses is stated outside the behaviors, which split on a volatile.
    assert "Frama_C_entropy_source" not in re.sub(r"indirect:Frama_C_entropy_source", "", head)
    assert re.search(r"ensures initialized_on_success:\s*\\result == 0 ==> \\initialized\(mask->__bits", head)
    assert "mask" not in re.sub(r"assigns \\result[^;]*;", "", behaviors["error"])
    head, behaviors = _contract_parts(_contract_of(block, "sched_setaffinity"))
    assert not behaviors
    assert re.search(r"requires valid_mask:\s*\\valid_read\(mask->__bits", head)
    assert re.search(r"requires initialized_mask:\s*\\initialized\(mask->__bits", head)
    assert "ensures result_ok_or_error: \\result == 0 || \\result == -1;" in head
    head, _ = _contract_parts(_contract_of(block, "__sched_cpucount"))
    assert "ensures count_range: 0 <= \\result <= 8 * setsize;" in head


SCHED_EVA = r"""#define _GNU_SOURCE
#include <sched.h>
#include "__fc_builtin.h"

typedef cpu_set_t ngx_cpuset_t; /* nginx, src/os/unix/ngx_setaffinity.h */

/* nginx, src/os/unix/ngx_setaffinity.c: ngx_setaffinity */
static int set_affinity(ngx_cpuset_t *cpu_affinity) {
  unsigned long i, n = 0;
  for (i = 0; i < CPU_SETSIZE; i++) {
    if (CPU_ISSET(i, cpu_affinity)) n++; /* nginx logs "using cpu #%ui" */
  }
  if (sched_setaffinity(0, sizeof(cpu_set_t), cpu_affinity) == -1) return -1;
  return n != 0;
}

/* nginx, src/core/nginx.c: worker_cpu_affinity and ngx_get_cpu_affinity */
int masks(void) {
  ngx_cpuset_t mask[2], result;
  unsigned long i;
  CPU_ZERO(&mask[0]);
  for (i = 0; i < 8; i++) CPU_SET(i, &mask[0]);
  CPU_ZERO(&mask[1]);
  CPU_SET(3, &mask[1]);
  int in = CPU_ISSET(3, &mask[1]) != 0, out = CPU_ISSET(4, &mask[1]) != 0;
  //@ check members: in == 1 && out == 0;
  CPU_CLR(3, &mask[1]);
  int cleared = CPU_ISSET(3, &mask[1]) != 0;
  //@ check cleared: cleared == 0;
  CPU_ZERO(&result);
  CPU_SET(5000 % CPU_SETSIZE, &result);
  int ignored = CPU_SET(5000, &result) != 0; /* past CPU_SETSIZE: nothing written, as glibc */
  int big = CPU_ISSET(5000, &result) != 0, low = CPU_ISSET(5000 % CPU_SETSIZE, &result) != 0;
  //@ check out_of_range: ignored == 0 && big == 0 && low == 1;
  int k = 0;
  CPU_SET((k++, 7), &result);
  //@ check evaluated_once: k == 1;
  int c = CPU_COUNT(&mask[0]);
  Frama_C_show_each_count(c);
  return set_affinity(&mask[0]) + set_affinity(&result) + c;
}

int get(void) {
  cpu_set_t set;
  if (sched_getaffinity(0, sizeof set, &set) != 0) {
    Frama_C_show_each_error(0);
    return -1;
  }
  int n = CPU_COUNT(&set); /* the set is initialized on success */
  Frama_C_show_each_ok(n);
  return n + (CPU_ISSET(0, &set) != 0);
}

/* A set of CPU_ALLOC_SIZE(200) bytes, with the _S forms. */
int dynamic(void) {
  unsigned long words[4];
  cpu_set_t *s = (cpu_set_t *)words;
  size_t size = CPU_ALLOC_SIZE(200);
  CPU_ZERO_S(size, s);
  CPU_SET_S(130, size, s);
  int x = CPU_ISSET_S(130, size, s) != 0;
  int far = CPU_SET_S(256, size, s) != 0; /* 256 / 8 == 32 bytes: past the set */
  CPU_CLR_S(130, size, s);
  int gone = CPU_ISSET_S(130, size, s) != 0;
  /* Eva follows CPU_ZERO_S's model as "initialized, any value": x and gone are only {0; 1}. */
  Frama_C_show_each_dynamic(x, gone);
  //@ check dynamic_bits: size == 32 && far == 0;
  int c = CPU_COUNT_S(size, s);
  if (sched_getaffinity(0, size, s) == 0) c += CPU_COUNT_S(size, s);
  return c + sched_setaffinity(0, size, s);
}

/* A set of CPU_ALLOC_SIZE(2048) bytes: thirty-two words, past the sixteen the member declares. */
int big(void) {
  unsigned long words[32];
  cpu_set_t *s = (cpu_set_t *)words;
  size_t size = CPU_ALLOC_SIZE(2048);
  CPU_ZERO_S(size, s);
  int far = CPU_SET_S(1500, size, s) != 0;
  int x = CPU_ISSET_S(2047, size, s), past = CPU_ISSET_S(2048, size, s);
  CPU_CLR_S(2047, size, s);
  //@ check big_set: size == 256 && far == 1 && past == 0;
  int c = CPU_COUNT_S(size, s);
  if (sched_getaffinity(0, size, s) == 0) c += CPU_COUNT_S(size, s) + x;
  return c + sched_setaffinity(0, size, s);
}

int short_mask(void) {
  unsigned long w = 0;
  return sched_getaffinity(0, sizeof(cpu_set_t), (cpu_set_t *)&w);
}
int uninit_mask(void) {
  cpu_set_t s;
  return sched_setaffinity(0, sizeof s, &s);
}
int uninit_count(void) {
  cpu_set_t s;
  return CPU_COUNT(&s);
}
"""

SCHED_WP = r"""#define _GNU_SOURCE
#include <sched.h>

/*@ requires \valid(cpus);
    assigns *cpus;
    ensures \result == 0 || \result == -1;
    ensures \result == 0 ==> \initialized(&cpus->__bits[0 .. 15]); */
int current(cpu_set_t *cpus) { return sched_getaffinity(0, sizeof(cpu_set_t), cpus); }

/*@ requires \valid_read(cpus) && \initialized(&cpus->__bits[0 .. 15]);
    assigns \nothing;
    ensures \result == 0 || \result == -1; */
int apply(const cpu_set_t *cpus) { return sched_setaffinity(0, sizeof(cpu_set_t), cpus); }

/*@ requires \valid_read(cpus) && \initialized(&cpus->__bits[0 .. 15]);
    assigns \nothing;
    ensures 0 <= \result <= 1024; */
int count(const cpu_set_t *cpus) { return CPU_COUNT(cpus); }

/*@ requires \valid(cpus);
    assigns cpus->__bits[cpu / 64]; */
void add(cpu_set_t *cpus, unsigned long cpu) {
  if (cpu < CPU_SETSIZE) CPU_SET(cpu, cpus);
}

/*@ requires \valid_read(cpus);
    assigns \nothing;
    ensures \result == 0 || \result == 1; */
int has(const cpu_set_t *cpus, unsigned long cpu) { return CPU_ISSET(cpu, cpus) != 0; }

/*@ requires \valid(cpus);
    assigns *cpus;
    ensures cpus->__bits[0] == 0 && cpus->__bits[15] == 0; */
void zero(cpu_set_t *cpus) { CPU_ZERO(cpus); }

/*@ requires \valid(cpus);
    assigns cpus->__bits[0 .. 15];
    ensures \initialized(&cpus->__bits[0 .. 15]);
    ensures cpus->__bits[0] == 0 && cpus->__bits[15] == 0; */
void zero_s(cpu_set_t *cpus) { CPU_ZERO_S(sizeof(cpu_set_t), cpus); }
"""

# What the E-ACSL frontend reads is glibc: the names nginx uses must come from there, untouched.
SCHED_HOST = r"""#include <sched.h>
typedef cpu_set_t ngx_cpuset_t;
int host(ngx_cpuset_t *m) {
  unsigned long i;
  int n = 0;
  for (i = 0; i < CPU_SETSIZE; i++)
    if (CPU_ISSET(i, m)) n++;
  CPU_SET(1, m);
  return n + sched_setaffinity(0, sizeof(cpu_set_t), m) + sched_getaffinity(0, sizeof(cpu_set_t), m);
}
"""

# glibc's macros against the stub's, renamed FC_CPU_*, in one gcc program (both on glibc's cpu_set_t).
SCHED_CMP = r"""#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <string.h>
@@OURS@@
/* What the contract of the CPU_ZERO_S model says, for whole words. */
static void __fc_sched_cpuzero(size_t setsize, cpu_set_t *setp) {
  for (size_t k = 0; k < setsize / sizeof(__cpu_mask); k++) setp->__bits[k] = 0;
}
static unsigned long n, bad, g[32], o[32];
static void report(const char *what, long long cpu, size_t size, long long gv, long long ov) {
  if (bad++ < 5) printf("MISMATCH %s cpu=%lld size=%zu glibc=%lld stub=%lld\n", what, cpu, size, gv, ov);
}
static void fill(unsigned seed) {
  for (int k = 0; k < 32; k++)
    g[k] = o[k] = (unsigned long)(seed * 2654435761u + (unsigned)k * 40503u) * 0x9e3779b97f4a7c15ul;
}
#define SAME(what, cpu, size, gexpr, oexpr)                                         \
  do {                                                                              \
    long long gv = (long long)(gexpr), ov = (long long)(oexpr);                     \
    n++;                                                                            \
    if (gv != ov || memcmp(g, o, sizeof g)) report(what, cpu, size, gv, ov);        \
  } while (0)
static void sized(long long cpu, size_t size, unsigned seed) {
  cpu_set_t *gs = (cpu_set_t *)g, *os = (cpu_set_t *)o;
  fill(seed);
  SAME("ISSET_S", cpu, size, CPU_ISSET_S(cpu, size, gs) != 0, FC_CPU_ISSET_S(cpu, size, os) != 0);
  SAME("SET_S", cpu, size, CPU_SET_S(cpu, size, gs), FC_CPU_SET_S(cpu, size, os));
  SAME("ISSET_S", cpu, size, CPU_ISSET_S(cpu, size, gs) != 0, FC_CPU_ISSET_S(cpu, size, os) != 0);
  SAME("COUNT_S", cpu, size, CPU_COUNT_S(size, gs), FC_CPU_COUNT_S(size, os));
  SAME("CLR_S", cpu, size, CPU_CLR_S(cpu, size, gs), FC_CPU_CLR_S(cpu, size, os));
  SAME("COUNT_S", cpu, size, CPU_COUNT_S(size, gs), FC_CPU_COUNT_S(size, os));
  if (size % sizeof(__cpu_mask) == 0) { /* the model's precondition */
    CPU_ZERO_S(size, gs);
    FC_CPU_ZERO_S(size, os);
    SAME("ZERO_S", cpu, size, 0, 0);
  }
}
static void fixed(long long cpu, unsigned seed) {
  cpu_set_t *gs = (cpu_set_t *)g, *os = (cpu_set_t *)o;
  fill(seed);
  SAME("SET", cpu, 0, CPU_SET(cpu, gs), FC_CPU_SET(cpu, os));
  SAME("ISSET", cpu, 0, CPU_ISSET(cpu, gs) != 0, FC_CPU_ISSET(cpu, os) != 0);
  SAME("COUNT", cpu, 0, CPU_COUNT(gs), FC_CPU_COUNT(os));
  SAME("CLR", cpu, 0, CPU_CLR(cpu, gs), FC_CPU_CLR(cpu, os));
  CPU_ZERO(gs);
  FC_CPU_ZERO(os);
  SAME("ZERO", cpu, 0, CPU_COUNT(gs), FC_CPU_COUNT(os));
}
int main(void) {
  static const size_t sizes[] = {0, 1, 3, 7, 8, 9, 16, 64, 127, 128, 129, 200, 255, 256};
  static const long long odd[] = {-1, -64, -1025, 1ll << 33, 1ll << 40, (long long)(~0ull >> 1)};
  for (unsigned s = 0; s < sizeof sizes / sizeof sizes[0]; s++)
    for (long long cpu = -70; cpu < 2200; cpu++) sized(cpu, sizes[s], (unsigned)(cpu + 7 * s));
  for (unsigned s = 0; s < sizeof sizes / sizeof sizes[0]; s++)
    for (unsigned j = 0; j < sizeof odd / sizeof odd[0]; j++) sized(odd[j], sizes[s], j);
  for (long long cpu = -70; cpu < 2200; cpu++) fixed(cpu, (unsigned)cpu);
  for (unsigned j = 0; j < sizeof odd / sizeof odd[0]; j++) fixed(odd[j], j);
  for (size_t count = 0; count < 5000; count++) {
    n++;
    if (CPU_ALLOC_SIZE(count) != FC_CPU_ALLOC_SIZE(count)) report("ALLOC_SIZE", (long long)count, 0, 0, 0);
  }
  n++;
  if (CPU_SETSIZE != FC_CPU_SETSIZE) report("SETSIZE", 0, 0, CPU_SETSIZE, FC_CPU_SETSIZE);
  /* Each argument evaluated once. */
  int ge = 0, oe = 0;
  cpu_set_t gset, oset;
  CPU_ZERO(&gset);
  FC_CPU_ZERO(&oset);
  (void)CPU_SET_S((ge++, 5), (ge++, sizeof gset), &gset);
  (void)FC_CPU_SET_S((oe++, 5), (oe++, sizeof oset), &oset);
  (void)CPU_ISSET_S((ge++, 5), (ge++, sizeof gset), &gset);
  (void)FC_CPU_ISSET_S((oe++, 5), (oe++, sizeof oset), &oset);
  (void)CPU_CLR((ge++, 5), &gset);
  (void)FC_CPU_CLR((oe++, 5), &oset);
  n++;
  if (ge != oe || ge != 5) report("EVALUATIONS", 0, 0, ge, oe);
  printf("SCHED_CMP n=%lu bad=%lu\n", n, bad);
  return bad != 0;
}
"""

SCHED_LAYOUT = [
    "sizeof(cpu_set_t)",
    "_Alignof(cpu_set_t)",
    "sizeof(__cpu_mask)",
    "(__cpu_mask)-1 > 0",
    "offsetof(cpu_set_t, __bits)",
    "sizeof(((cpu_set_t *)0)->__bits)",
    "CPU_SETSIZE",
    "__CPU_SETSIZE",
    "__NCPUBITS",
    "CPU_ALLOC_SIZE(1)",
    "CPU_ALLOC_SIZE(64)",
    "CPU_ALLOC_SIZE(65)",
    "CPU_ALLOC_SIZE(1024)",
    "CPU_ALLOC_SIZE(2048)",
]

# The real glibc functions behind wrappers that carry the contract text of fc_compat_types.h (as for pipe2).
SCHED_REAL = r"""#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <string.h>
@@WRAPPERS@@
static unsigned long buf[32], buf2[32];
/* E-ACSL does not see the kernel's writes: the \initialized clauses hold from the fill. */
static void get(size_t size) {
  memset(buf, 0x5a, sizeof buf);
  memset(buf2, 0x5a, sizeof buf2);
  int r = top_sched_getaffinity(0, size, (cpu_set_t *)buf), r2, n = -1;
  if (r == 0) {
    r2 = ok_sched_getaffinity(0, size, (cpu_set_t *)buf2);
    n = top___sched_cpucount(size, (cpu_set_t *)buf);
  } else {
    r2 = error_sched_getaffinity(0, size, (cpu_set_t *)buf2);
  }
  int counted = r != 0 || (n > 0 && n == CPU_COUNT_S(size, (cpu_set_t *)buf));
  printf("r=%d r2=%d counted=%d past=%d\n", r, r2, counted, size >= sizeof buf || ((unsigned char *)buf)[size] == 0x5a);
}
static void set(int empty, size_t size) {
  cpu_set_t cur;
  memset(buf, 0, sizeof buf);
  if (!empty && sched_getaffinity(0, sizeof cur, &cur) == 0) memcpy(buf, &cur, sizeof cur);
  printf("r=%d\n", top_sched_setaffinity(0, size, (cpu_set_t *)buf));
}
/* glibc's CPU_ZERO_S under the contract of the model. */
static void zero(size_t size) {
  memset(buf, 0x5a, sizeof buf);
  top___fc_sched_cpuzero(size, (cpu_set_t *)buf);
  printf("count=%d past=%d\n", CPU_COUNT_S(size, (cpu_set_t *)buf),
         size >= sizeof buf || ((unsigned char *)buf)[size] == 0x5a);
}
int main(int argc, char **argv) {
  const char *c = argc > 1 ? argv[1] : "";
  if (!strcmp(c, "get_static")) get(sizeof(cpu_set_t));
  if (!strcmp(c, "get_two_sets")) get(2 * sizeof(cpu_set_t));
  if (!strcmp(c, "get_word")) get(8);
  if (!strcmp(c, "get_odd_size")) get(12);
  if (!strcmp(c, "get_zero")) get(0);
  if (!strcmp(c, "set_current")) set(0, sizeof(cpu_set_t));
  if (!strcmp(c, "set_empty")) set(1, sizeof(cpu_set_t));
  if (!strcmp(c, "set_odd_size")) set(0, 12);
  if (!strcmp(c, "zero_static")) zero(sizeof(cpu_set_t));
  if (!strcmp(c, "zero_dynamic")) zero(CPU_ALLOC_SIZE(600));
  if (!strcmp(c, "zero_big")) zero(CPU_ALLOC_SIZE(2048));
  printf("%s done\n", c);
  return 0;
}
"""

# case -> what it prints. 8 bytes hold 64 CPUs, enough for the container (`nproc` well under 64): a
# size the kernel refuses (not whole words, 0) is -1 with nothing written.
SCHED_REAL_CASES = {
    "get_static": "r=0 r2=0 counted=1 past=1",
    "get_two_sets": "r=0 r2=0 counted=1 past=1",
    "get_word": "r=0 r2=0 counted=1 past=1",
    "get_odd_size": "r=-1 r2=-1 counted=1 past=1",
    "get_zero": "r=-1 r2=-1 counted=1 past=1",
    "set_current": "r=0",
    "set_empty": "r=-1",
    "set_odd_size": "r=0",
    "zero_static": "count=0 past=1",
    "zero_dynamic": "count=0 past=1",
}
# E-ACSL checks `setp->__bits[k]` in the `\forall` as an index of the sixteen-word member: on a set of more
# words it stops there, though glibc zeroed the set (Eva and WP read the word at that offset).
SCHED_REAL_EACSL_LIMIT = ("zero_big", "index out of bounds")

SCHED_MAINS = ["masks", "get", "dynamic", "big", "short_mask", "uninit_mask", "uninit_count"]


def _sched_wrappers() -> str:
    block = _sched_block()
    out = []
    for name, (ret, params, call) in SCHED_SIGNATURES.items():
        head, behaviors = _contract_parts(_contract_of(block, name))
        body = f"{call};" if ret == "void" else f"return {call};"
        for prefix, clauses in (("top", head), *behaviors.items()):
            out.append(f"/*@{clauses}*/\n{ret} {prefix}_{name}{params} {{ {body} }}\n")
    return "".join(out)


@pytest.mark.integration
@pytest.mark.slow
def test_sched_affinity_in_eva_wp_and_against_glibc(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    prototypes = stub_prototypes("fc_compat_types.h", set(SCHED_SIGNATURES))
    assert len(prototypes) == len(SCHED_SIGNATURES), prototypes
    ours = re.sub(r"\bCPU_", "FC_CPU_", _sched_macro_block())
    pre = "#define _GNU_SOURCE\n"
    sources = {
        "eva.c": SCHED_EVA,
        "wp.c": SCHED_WP,
        "host.c": SCHED_HOST,
        "abi.c": pre + "#include <sched.h>\n" + "\n".join(prototypes) + "\n",
        "cmp.c": SCHED_CMP.replace("@@OURS@@", ours),
        "gen.c": _static_assert_generator("sched.h", SCHED_LAYOUT),
        "real.c": SCHED_REAL.replace("@@WRAPPERS@@", _sched_wrappers()),
    }
    for name, text in sources.items():
        (tmp_path / name).write_text(text, encoding="utf-8", newline="\n")
    fc = "timeout 300 frama-c -no-unicode -machdep gcc_x86_64"
    cases = " ".join([*SCHED_REAL_CASES, SCHED_REAL_EACSL_LIMIT[0]])
    script = "".join(
        f'echo "@@MAIN {m}"; {fc} eva.c -cpp-extra-args="$A" -eva -eva-no-show-progress -warn-invalid-pointer '
        f"-eva-slevel 100 -main {m} 2>&1; "
        for m in SCHED_MAINS
    )
    script += (
        f'echo "@@MAIN wp"; {fc} wp.c -cpp-extra-args="$A" -wp -wp-rte -wp-timeout 30 2>&1; '
        # Phase 0's parse: no annotations, the whole nginx idiom must still parse.
        f'echo "@@MAIN noannot"; {fc} -no-annot eva.c -cpp-extra-args="$A" 2>&1 && echo PARSE_OK; '
        'echo "@@MAIN abi"; gcc -fsyntax-only -Werror abi.c 2>&1 && echo ABI_OK; '
        'echo "@@MAIN cmp"; gcc -O1 -Wall -o cmp cmp.c 2>&1 && timeout 300 ./cmp; '
        # glibc's values (gcc) become _Static_asserts that Frama-C checks against this header.
        'echo "@@MAIN layout"; gcc -D_GNU_SOURCE -o gen gen.c 2>&1 && ./gen > asserts.inc && '
        '{ printf "#include <stddef.h>\\n#include <sched.h>\\n"; cat asserts.inc; } '
        f'> check.c && {fc} check.c -cpp-extra-args="$A" 2>&1 && echo FRAMAC_OK; '
        f'echo "@@MAIN host"; {fc} host.c -cpp-extra-args="$F -D_GNU_SOURCE" -no-frama-c-stdlib 2>&1 && echo PARSE_OK; '
        # -D_GNU_SOURCE: in the E-ACSL frontend the force-included fc_compat_types.h reads glibc's
        # <features.h> before the source's own `#define _GNU_SOURCE`, which then exposes nothing (glibc's
        # CPU_* macros would be calls to undefined functions).
        'echo "@@MAIN real"; e-acsl-gcc --full-mtracking -G clang -E "$F -D_GNU_SOURCE" '
        '-e "-I/opt/framac-pipeline/templates/fc_stubs" -O rb real.c > real.build.log 2>&1 || cat real.build.log; '
        f'for k in {cases}; do timeout 60 ./rb.e-acsl $k > $k.out 2>&1; echo "case $k rc=$?"; done'
    )
    log = _docker(ANALYSIS_IMAGE, tmp_path, script, timeout=1800)
    per = _per_main(log)
    for main in [*SCHED_MAINS, "wp", "noannot"]:
        assert "User Error" not in per[main] and "found two contracts" not in per[main], per[main]
        assert "undeclared function" not in per[main], per[main]
    assert "PARSE_OK" in per["noannot"], per["noannot"]
    # nginx's idioms: every check holds, every precondition is valid.
    for main in ("masks", "get", "dynamic", "big"):
        _assert_clean(per[main])
    assert re.search(r"Assertions\s+4 valid\s+0 unknown\s+0 invalid", per["masks"]), per["masks"]
    for main in ("dynamic", "big"):
        assert re.search(r"Assertions\s+1 valid\s+0 unknown\s+0 invalid", per[main]), per[main]
    assert "Frama_C_show_each_dynamic: {0; 1}, {0; 1}" in per["dynamic"], per["dynamic"]
    assert "Frama_C_show_each_count: [0..1024]" in per["masks"], per["masks"]
    # Both outcomes of sched_getaffinity are reachable, and the set is initialized on success.
    assert "Frama_C_show_each_error: {0}" in per["get"], per["get"]
    assert "Frama_C_show_each_ok: [0..1024]" in per["get"], per["get"]
    for main, failed in (
        ("short_mask", "sched_getaffinity: precondition 'valid_mask'"),
        ("uninit_mask", "sched_setaffinity: precondition 'initialized_mask'"),
        ("uninit_count", "__sched_cpucount: precondition 'initialized_set'"),
    ):
        assert f"function {failed} got status invalid" in per[main], per[main]
    assert all(proved == total for proved, total in wp_proved_goals(per["wp"])), per["wp"]
    assert "ABI_OK" in per["abi"], per["abi"]
    compared = re.search(r"SCHED_CMP n=(\d+) bad=0\b", per["cmp"])
    assert compared and int(compared.group(1)) > 200_000, per["cmp"]
    assert "FRAMAC_OK" in per["layout"] and "User Error" not in per["layout"], per["layout"]
    assert (tmp_path / "asserts.inc").read_text(encoding="utf-8").count("_Static_assert") == len(SCHED_LAYOUT), log
    assert "PARSE_OK" in per["host"] and "User Error" not in per["host"], per["host"]
    build = (tmp_path / "real.build.log").read_text(encoding="utf-8", errors="replace")
    # E-ACSL runs every clause but `assigns` and the one `\subset` of __fc_sched_cpuzero, whose `\forall`
    # twin it does run.
    skipped = re.findall(r"E-ACSL construct\s+`([^']+)'\s+is not yet supported", build)
    assert sorted(set(skipped)) == [
        "assigns clause",
        "logic functions or predicates with no definition nor reads clause",
    ], build
    assert skipped.count("logic functions or predicates with no definition nor reads clause") == 1, build
    for case, printed in SCHED_REAL_CASES.items():
        out = (tmp_path / f"{case}.out").read_text(encoding="utf-8", errors="replace")
        assert f"case {case} rc=0" in log and f"{case} done" in out, (case, out, per["real"])
        assert printed in out, (case, out)
    case, stopped = SCHED_REAL_EACSL_LIMIT
    out = (tmp_path / f"{case}.out").read_text(encoding="utf-8", errors="replace")
    assert stopped in out and "top___fc_sched_cpuzero" in out and f"{case} done" not in out, out


# ---------------------------------------------------------------------------------------------------
# Linux <netinet/in.h> / <netinet/tcp.h> names __fc_libc lacks, found on nginx: in_pktinfo, tcp_info, ...
# ---------------------------------------------------------------------------------------------------

# Every IP_, IPV6_, TCP_ and TCPI_OPT_ macro of glibc 2.41's <netinet/in.h> and <netinet/tcp.h> (with
# _GNU_SOURCE) that __fc_libc (34.0~beta) lacks, in the order fc_compat_types.h defines them.
NETINET_LINUX_CONSTANTS = [
    "IP_NODEFRAG", "IP_CHECKSUM", "IP_BIND_ADDRESS_NO_PORT", "IP_RECVFRAGSIZE", "IP_RECVERR_RFC4884",
    "IP_MULTICAST_ALL", "IP_UNICAST_IF", "IP_LOCAL_PORT_RANGE", "IP_PROTOCOL", "IP_PMTUDISC_INTERFACE",
    "IP_PMTUDISC_OMIT", "IPV6_MULTICAST_ALL", "IPV6_ROUTER_ALERT_ISOLATE", "IPV6_RECVERR_RFC4884",
    "IPV6_HDRINCL", "IPV6_RECVPATHMTU", "IPV6_PATHMTU", "IPV6_DONTFRAG", "IPV6_AUTOFLOWLABEL",
    "IPV6_ADDR_PREFERENCES", "IPV6_MINHOPCOUNT", "IPV6_ORIGDSTADDR", "IPV6_RECVORIGDSTADDR",
    "IPV6_TRANSPARENT", "IPV6_UNICAST_IF", "IPV6_RECVFRAGSIZE", "IPV6_FREEBIND", "IPV6_PMTUDISC_INTERFACE",
    "IPV6_PMTUDISC_OMIT", "TCP_MSS", "TCP_MAXWIN", "TCP_MAX_WINSHIFT", "TCP_REPAIR_WINDOW",
    "TCP_FASTOPEN_CONNECT", "TCP_ULP", "TCP_MD5SIG_EXT", "TCP_FASTOPEN_KEY", "TCP_FASTOPEN_NO_COOKIE",
    "TCP_ZEROCOPY_RECEIVE", "TCP_INQ", "TCP_CM_INQ", "TCP_TX_DELAY", "TCP_REPAIR_ON", "TCP_REPAIR_OFF",
    "TCP_REPAIR_OFF_NO_WP", "TCP_MD5SIG_FLAG_PREFIX", "TCP_MD5SIG_FLAG_IFINDEX", "TCP_MD5SIG_MAXKEYLEN",
    "TCP_COOKIE_MIN", "TCP_COOKIE_MAX", "TCP_COOKIE_PAIR_SIZE", "TCP_COOKIE_IN_ALWAYS", "TCP_COOKIE_OUT_NEVER",
    "TCP_S_DATA_IN", "TCP_S_DATA_OUT", "TCP_MSS_DEFAULT", "TCP_MSS_DESIRED", "TCPI_OPT_TIMESTAMPS",
    "TCPI_OPT_SACK", "TCPI_OPT_WSCALE", "TCPI_OPT_ECN", "TCPI_OPT_ECN_SEEN", "TCPI_OPT_SYN_DATA",
]  # fmt: skip
# glibc names of the same families still missing from the Eva/WP parse (README, "Not declared").
NETINET_LINUX_LEFT_OUT = ["IP_MSFILTER_SIZE"]
NETINET_LINUX_LAYOUT = [
    "sizeof(struct in_pktinfo)",
    "_Alignof(struct in_pktinfo)",
    "offsetof(struct in_pktinfo, ipi_ifindex)",
    "offsetof(struct in_pktinfo, ipi_spec_dst)",
    "offsetof(struct in_pktinfo, ipi_addr)",
    "sizeof(struct tcp_info)",
    "_Alignof(struct tcp_info)",
    "offsetof(struct tcp_info, tcpi_options)",
    "offsetof(struct tcp_info, tcpi_rto)",
    "offsetof(struct tcp_info, tcpi_rtt)",
    "offsetof(struct tcp_info, tcpi_rttvar)",
    "offsetof(struct tcp_info, tcpi_snd_cwnd)",
    "offsetof(struct tcp_info, tcpi_rcv_space)",
    "offsetof(struct tcp_info, tcpi_total_retrans)",
]


def _netinet_linux_block() -> str:
    block = _fc_libc_branch().split("#ifndef FC_STUBS_NO_NETINET_LINUX_DECLS\n", 1)[1]
    return block.split("#endif /* FC_STUBS_NO_NETINET_LINUX_DECLS */", 1)[0]


def test_netinet_linux_names_are_declared_for_eva_and_wp_after_the_sched_block():
    text = _read("fc_compat_types.h")
    fc_libc = _fc_libc_branch()
    order = [
        fc_libc.index("#endif /* FC_STUBS_NO_SCHED_AFFINITY_DECLS */"),
        fc_libc.index("#ifndef FC_STUBS_NO_NETINET_LINUX_DECLS"),
        fc_libc.index("#include <netinet/tcp.h>"),
        fc_libc.index("struct in_pktinfo {"),
        fc_libc.index("struct tcp_info {"),
        fc_libc.index("#endif /* FC_STUBS_NO_NETINET_LINUX_DECLS */"),
    ]
    assert order == sorted(order)
    eacsl_branch = text.split("#if defined(__FRAMAC_EACSL__)", 1)[1].split("#else /* Frama-C __fc_libc */", 1)[0]
    assert not re.search(r"in_pktinfo|tcp_info|IP_BIND_ADDRESS_NO_PORT", eacsl_branch)
    block = _netinet_linux_block()
    assert re.findall(r"^#define (\w+)", block, flags=re.M) == NETINET_LINUX_CONSTANTS
    # Each constant steps aside when a later libc (or the target) defines it.
    for name in NETINET_LINUX_CONSTANTS:
        assert block.count(f"#ifndef {name}\n#define {name} ") == 1, name


NETINET_LINUX_USE = r"""#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>

/* nginx, src/http/ngx_http_variables.c: the $tcpinfo_* variables */
int info(void) {
  struct tcp_info ti;
  socklen_t len = sizeof(struct tcp_info);
  memset(&ti, 0, sizeof ti);
  if (getsockopt(3, IPPROTO_TCP, TCP_INFO, &ti, &len) == -1) return -1;
  return (int)(ti.tcpi_rtt / 1000 + ti.tcpi_rttvar / 1000 + (ti.tcpi_options & TCPI_OPT_SACK));
}

/* nginx, src/event/ngx_event_connect.c */
int bind_no_port(void) {
  int on = 1;
  return setsockopt(3, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &on, sizeof on);
}

/* nginx, src/event/ngx_event_udp.h: the control message of a datagram's destination address */
typedef union {
  struct in_pktinfo pkt;
  struct in6_pktinfo pkt6;
} addrinfo_t;
int pktinfo(void) {
  addrinfo_t a;
  memset(&a, 0, sizeof a);
  a.pkt.ipi_ifindex = 1;
  return a.pkt.ipi_ifindex + (int)sizeof(a) + IPV6_DONTFRAG + IP_PMTUDISC_OMIT;
}
"""


@pytest.mark.integration
@pytest.mark.slow
def test_netinet_linux_names_in_eva_and_against_glibc(tmp_path):
    require_docker_images(ANALYSIS_IMAGE)
    exprs = NETINET_LINUX_LAYOUT + NETINET_LINUX_CONSTANTS
    sources = {
        "use.c": NETINET_LINUX_USE,
        "gen.c": _static_assert_generator("netinet/tcp.h", exprs, pre="#include <netinet/in.h>\n"),
    }
    for name, text in sources.items():
        (tmp_path / name).write_text(text, encoding="utf-8", newline="\n")
    fc = "timeout 300 frama-c -no-unicode -machdep gcc_x86_64"
    script = "".join(
        f'echo "@@MAIN {m}"; {fc} use.c -cpp-extra-args="$A" -eva -eva-no-show-progress -warn-invalid-pointer '
        f"-eva-slevel 100 -main {m} 2>&1; "
        for m in ("info", "bind_no_port", "pktinfo")
    )
    script += (
        f'echo "@@MAIN noannot"; {fc} -no-annot use.c -cpp-extra-args="$A" 2>&1 && echo PARSE_OK; '
        # glibc's values (gcc) become _Static_asserts that Frama-C checks against this header.
        'echo "@@MAIN layout"; gcc -D_GNU_SOURCE -o gen gen.c 2>&1 && ./gen > asserts.inc && '
        '{ printf "#include <stddef.h>\\n#include <netinet/in.h>\\n#include <netinet/tcp.h>\\n"; cat asserts.inc; } '
        f'> check.c && {fc} check.c -cpp-extra-args="$A" 2>&1 && echo FRAMAC_OK; '
        # Every glibc name of the four families, looked up in the Eva/WP parse.
        'echo "@@MAIN missing"; printf "#define _GNU_SOURCE\\n#include <netinet/in.h>\\n#include <netinet/tcp.h>\\n" > g.c; '
        "gcc -dM -E g.c | awk '{print $2}' | sed 's/(.*//' | grep -E '^(IP|IPV6|TCP|TCPI_OPT)_' | sort -u > names.txt; "
        '{ printf "#include <netinet/in.h>\\n#include <netinet/tcp.h>\\n"; '
        'while read -r n; do printf "#ifndef %s\\nint missing_%s;\\n#endif\\n" "$n" "$n"; done < names.txt; } > m.c; '
        f'echo "glibc names: $(wc -l < names.txt)"; {fc} m.c -cpp-extra-args="$A" -print 2>&1 | grep -o "missing_[A-Za-z0-9_]*" | sort -u; '
        f'echo "@@MAIN host"; {fc} use.c -cpp-extra-args="$F -D_GNU_SOURCE" -no-frama-c-stdlib 2>&1 && echo PARSE_OK'
    )
    log = _docker(ANALYSIS_IMAGE, tmp_path, script, timeout=1800)
    per = _per_main(log)
    for main in ("info", "bind_no_port", "pktinfo", "noannot"):
        assert "User Error" not in per[main] and "undeclared function" not in per[main], per[main]
    assert "PARSE_OK" in per["noannot"], per["noannot"]
    for main in ("info", "bind_no_port", "pktinfo"):
        assert re.search(r"Preconditions\s+\d+ valid\s+0 unknown\s+0 invalid", per[main]), per[main]
    assert "FRAMAC_OK" in per["layout"] and "User Error" not in per["layout"], per["layout"]
    assert (tmp_path / "asserts.inc").read_text(encoding="utf-8").count("_Static_assert") == len(exprs), log
    counted = re.search(r"glibc names: (\d+)", per["missing"])
    assert counted and int(counted.group(1)) > 150, per["missing"]
    missing = re.findall(r"^missing_(\w+)$", per["missing"], flags=re.M)
    assert missing == NETINET_LINUX_LEFT_OUT, per["missing"]
    assert "PARSE_OK" in per["host"] and "User Error" not in per["host"], per["host"]
