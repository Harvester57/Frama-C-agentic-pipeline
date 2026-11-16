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
# <sys/epoll.h> and <sys/inotify.h>: glibc's headers, parsed by Frama-C (c-ares run-1, 2026-11-16)
# ---------------------------------------------------------------------------------------------------

LINUX_EVENT_SHIMS = {
    "sys/epoll.h": ("__attr_access", "____sigset_t_defined", "_STRUCT_TIMESPEC"),
    "sys/inotify.h": ("__flexarr",),
}
_EVA_WP_ONLY = "#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)"


@pytest.mark.unit
@pytest.mark.parametrize("rel", sorted(LINUX_EVENT_SHIMS))
def test_linux_event_shims_only_reconcile_glibc_for_eva_and_wp(rel):
    text = _read(rel)
    # Declarations stay in glibc's header, so stub_gen classifies the functions as host_header, not pipeline_stub.
    assert stub_prototypes(rel) == []
    assert f"#include_next <{rel}>" in text
    # Never glibc's <sys/cdefs.h>: it would redefine __THROW, __nonnull, ... for every later libc header.
    assert not re.search(r"#\s*include\s*<sys/cdefs\.h>", text)
    fixes = text.split(_EVA_WP_ONLY, 1)[1].split("#endif /* Eva / WP */", 1)[0]
    rest = text.replace(fixes, "")
    for name in LINUX_EVENT_SHIMS[rel]:
        # A run's hand-written overlay wrapper may have defined it already: every definition is guarded.
        assert re.search(rf"#\s*ifndef {name}\b", fixes), name
        assert not re.search(rf"#\s*(?:define|ifndef) {name}\b", rest), f"{name} outside the Eva / WP branch"
    assert text.index(_EVA_WP_ONLY) < text.index(f"#include_next <{rel}>")


EPOLL_USE = r"""#include <sys/epoll.h>
#include <signal.h>
#include <time.h>
int use_epoll(void) {
  struct epoll_event ev[4];
  sigset_t mask;
  struct timespec ts = {0, 0};
  int fd = epoll_create1(EPOLL_CLOEXEC);
  if (fd < 0) return -1;
  ev[0].events = EPOLLIN;
  ev[0].data.u64 = 1;
  (void)epoll_ctl(fd, EPOLL_CTL_ADD, 0, ev);
  sigemptyset(&mask);
  return epoll_wait(fd, ev, 4, 0) + epoll_pwait(fd, ev, 4, 0, &mask) + epoll_pwait2(fd, ev, 4, &ts, &mask);
}
"""

# Frama-C's <signal.h> and <time.h> before glibc's <sys/epoll.h>.
EPOLL_LATE = "#include <signal.h>\n#include <time.h>\n" + EPOLL_USE

INOTIFY_USE = r"""#include <sys/inotify.h>
int use_inotify(void) {
  char buf[sizeof(struct inotify_event) + 16];
  struct inotify_event *e = (struct inotify_event *)buf;
  int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  if (fd < 0) return -1;
  e->len = 0;
  return inotify_add_watch(fd, "/etc", IN_MODIFY) + inotify_rm_watch(fd, 1) + (int)sizeof(e->name[0]);
}
"""

# A filled stub_gen overlay header in front of the shim: overlay -> fc_stubs shim -> glibc.
EPOLL_OVERLAY_BLOCK = """
/* fc-stub: epoll_create1 */
/*@ assigns \\result \\from __flags; */
extern int epoll_create1(int __flags);
"""
LINUX_EVENT_CASES = (
    # (case, source, flags variable, extra Frama-C options)
    ("epoll", "epoll.c", "$A", ""),
    ("epoll_late", "epoll_late.c", "$A", ""),
    ("inotify", "inotify.c", "$A", ""),
    ("overlay", "epoll.c", "$O", "-print"),
    ("eacsl_epoll", "epoll.c", "$F", "-no-frama-c-stdlib"),
    ("eacsl_inotify", "inotify.c", "$F", "-no-frama-c-stdlib"),
)


@pytest.mark.integration
@pytest.mark.slow
def test_frama_c_parses_glibc_epoll_and_inotify_with_the_pipeline_flags(tmp_path):
    import stub_gen

    require_docker_images(ANALYSIS_IMAGE)
    for name, text in (("epoll.c", EPOLL_USE), ("epoll_late.c", EPOLL_LATE), ("inotify.c", INOTIFY_USE)):
        (tmp_path / name).write_text(text, encoding="utf-8", newline="\n")
    overlay = tmp_path / "ov" / "sys"
    overlay.mkdir(parents=True)
    (overlay / "epoll.h").write_text(
        stub_gen.header_preamble("sys/epoll.h", "/usr/include/x86_64-linux-gnu/sys/epoll.h") + EPOLL_OVERLAY_BLOCK,
        encoding="utf-8",
        newline="\n",
    )
    # c-ares's own defines (phase0 log of run-1): glibc declares epoll_pwait2 under __USE_GNU.
    defines = "-D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700"
    script = (
        'O=$(FRAMAC_STUB_OVERLAY_DIR=/w/ov python3 -c "$py import framac_common; '
        'print(framac_common.augment_framac_cppflags(\\"-I.\\"))"); '
    )
    for case, src, flags, extra in LINUX_EVENT_CASES:
        script += (
            f'echo "@@MAIN {case}"; timeout 300 frama-c -no-unicode -machdep gcc_x86_64 {src} '
            f'-cpp-extra-args="{flags} {defines}" {extra} 2>&1 && echo PARSE_OK; '
        )
    log = _docker(ANALYSIS_IMAGE, tmp_path, script, timeout=1200)
    per = _per_main(log)
    for case, *_ in LINUX_EVENT_CASES:
        assert "PARSE_OK" in per[case], per[case]
        assert "User Error" not in per[case] and "incompatible" not in per[case].lower(), per[case]
    for case in ("epoll", "epoll_late", "inotify", "overlay"):
        assert "Warning" not in per[case], per[case]
    # The overlay's contract reached Frama-C: overlay -> shim -> glibc.
    assert re.search(r"assigns \\result\s*\\from __flags;", per["overlay"]), per["overlay"]
