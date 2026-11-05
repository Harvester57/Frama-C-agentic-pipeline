"""Per-function reading slices (scripts/function_slice.py): canned preprocessor output, real tools when present."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import cache
import function_slice as fs
from acsl_ast import tokenize_c_acsl

HAS_GCC = shutil.which("gcc") is not None
HAS_FRAMAC = shutil.which("frama-c") is not None
WORK = Path("workspace/work")
FLAGS = "-I. -Iworkspace/work"


def _cp(cmd, rc=0, out="", err=""):
    return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr=err)


def gcc_runner(text, calls=None):
    """subprocess.run stand-in: no Frama-C on the machine, `gcc -E` prints `text`."""

    def run(cmd, **kwargs):
        if calls is not None:
            calls.append((list(cmd), kwargs))
        if cmd[0] == "frama-c":
            raise FileNotFoundError(cmd[0])
        return _cp(cmd, out=text)

    return run


def no_tools(cmd, **kwargs):
    raise FileNotFoundError(cmd[0])


def real_gcc_only(cmd, **kwargs):
    if cmd[0] == "frama-c":
        raise FileNotFoundError(cmd[0])
    return subprocess.run(cmd, **kwargs)


def write_tree(run_dir: Path, files: dict[str, str], tree: str = "workspace/work") -> None:
    for rel, text in files.items():
        path = run_dir / tree / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")


def cpp_like(rel: str, source: str, tree: str = "workspace/work") -> str:
    """Enough of `gcc -E -dD` for a source without includes or conditionals: comments gone, lines kept."""
    blank = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), source, flags=re.DOTALL)
    return f'# 1 "{tree}/{rel}"\n{blank}'


def slice_of(run_dir: Path, c_file: str, function: str, text: str | None = None, **kwargs) -> dict:
    kwargs.setdefault("runner", gcc_runner(text))
    return fs.build_slice(
        run_dir, kwargs.pop("work_dir", WORK), c_file, function, kwargs.pop("cppflags", FLAGS), **kwargs
    )


def by_name(result: dict) -> dict[str, dict]:
    return {c["name"]: c for c in result["callees"]}


@pytest.fixture
def run_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("FRAMAC_CACHE", raising=False)
    monkeypatch.delenv("FRAMAC_CACHE_MODE", raising=False)
    run = tmp_path / "run"
    (run / "workspace" / "work").mkdir(parents=True)
    return run


# ---------------------------------------------------------------------------
# #if resolution
# ---------------------------------------------------------------------------

BRANCHES_C = """\
#include "cfg.h"
#ifdef USE_WIDE
typedef long value_t;
#define LIMIT 100
static value_t scale(value_t v) { return v * 2; }
#else
typedef short value_t;
#define LIMIT 10
static value_t scale(value_t v) { return v + 1; }
#endif

int compute(int a)
{
    return scale(a) + LIMIT;
}
"""
BRANCHES_H = "#define CFG_UNUSED 1\n"
BRANCHES_CANNED = """\
# 0 "workspace/work/cfg.c"
# 0 "<built-in>"
#define __STDC__ 1
# 0 "<command-line>"
#define __FRAMAC__ 1
# 1 "workspace/work/cfg.c"
# 1 "workspace/work/cfg.h" 1
#define CFG_UNUSED 1
# 2 "workspace/work/cfg.c" 2
# 7 "workspace/work/cfg.c"
typedef short value_t;
#define LIMIT 10
static value_t scale(value_t v) { return v + 1; }
# 12 "workspace/work/cfg.c"
int compute(int a)
{
    return scale(a) + 10;
}
"""


def _assert_else_branch(result: dict) -> None:
    assert result["status"] == "ok"
    assert result["conditionals"] == "resolved"
    text = result["text"]
    assert "typedef short value_t;" in text
    assert "typedef long" not in text
    assert "#define LIMIT 10\n" in text
    assert "LIMIT 100" not in text
    assert "CFG_UNUSED" not in text
    assert "__STDC__" not in text
    assert by_name(result)["scale"]["file"] == "cfg.c"
    assert by_name(result)["scale"]["line"] == 9
    assert result["target"] == {"file": "cfg.c", "start_line": 12, "end_line": 15}


class TestConditionals:
    def test_only_the_active_branch_is_used(self, run_dir):
        write_tree(run_dir, {"cfg.c": BRANCHES_C, "cfg.h": BRANCHES_H})
        result = slice_of(run_dir, "cfg.c", "compute", BRANCHES_CANNED)
        _assert_else_branch(result)
        assert result["reason"] and "gcc" in result["reason"]  # Frama-C's view was not available

    def test_defined_only_in_an_inactive_branch_is_not_found(self, run_dir):
        write_tree(run_dir, {"i.c": "#if 0\nint ghost_fn(void) { return 0; }\n#endif\nint other(void) { return 1; }\n"})
        canned = '# 1 "workspace/work/i.c"\n\n\n\nint other(void) { return 1; }\n'
        result = slice_of(run_dir, "i.c", "ghost_fn", canned)
        assert result["status"] == "not_found"
        assert "inactive" in result["reason"]

    def test_inactive_lines_of_the_target_are_flagged_and_not_followed(self, run_dir):
        source = (
            "#define FAST 0\n"
            "int helper_fast(int);\n"
            "int helper_slow(int);\n"
            "int pick(int a)\n"
            "{\n"
            "#if FAST\n"
            "    return helper_fast(a);\n"
            "#else\n"
            "    return helper_slow(a);\n"
            "#endif\n"
            "}\n"
        )
        canned = (
            '# 1 "workspace/work/p.c"\n#define FAST 0\nint helper_fast(int);\nint helper_slow(int);\n'
            "int pick(int a)\n{\n\n\n\n    return helper_slow(a);\n\n}\n"
        )
        write_tree(run_dir, {"p.c": source})
        result = slice_of(run_dir, "p.c", "pick", canned)
        assert list(by_name(result)) == ["helper_slow"]
        assert "Lines 7-7 are in inactive #if branches" in result["text"]
        assert "int helper_fast(int);" not in result["text"]
        assert "return helper_fast(a);" in result["text"]  # the target stays verbatim
        assert "#define FAST 0" in result["text"]  # the macro deciding the branch

    def test_acsl_declared_in_an_inactive_branch_is_skipped(self, run_dir):
        source = (
            "#ifdef NOPE\n"
            "int nope_marker;\n"
            "/*@ predicate pick_me(integer x) = x > 100; */\n"
            "#else\n"
            "int yes_marker;\n"
            "/*@ predicate pick_me(integer x) = x > 0; */\n"
            "#endif\n"
            "/*@ requires pick_me(a); */\n"
            "int target(int a) { return a; }\n"
        )
        canned = '# 1 "workspace/work/a.c"\n\n\n\n\nint yes_marker;\n\n\n\nint target(int a) { return a; }\n'
        write_tree(run_dir, {"a.c": source})
        result = slice_of(run_dir, "a.c", "target", canned)
        assert "x > 0" in result["text"]
        assert "x > 100" not in result["text"]


# ---------------------------------------------------------------------------
# Closure
# ---------------------------------------------------------------------------


class TestClosure:
    def test_macros_followed_transitively_and_a_callee_hidden_in_one(self, run_dir):
        source = (
            "int hidden_callee(int x);\n"
            "#define INNER(v) hidden_callee(v)\n"
            "#define OUTER(v) INNER((v) + OFFSET)\n"
            "#define OFFSET 4\n"
            "#define UNUSED_MACRO 7\n"
            "int target(int a)\n"
            "{\n"
            "    return OUTER(a);\n"
            "}\n"
        )
        canned = (
            '# 1 "workspace/work/m.c"\nint hidden_callee(int x);\n#define INNER(v) hidden_callee(v)\n'
            "#define OUTER(v) INNER((v) + OFFSET)\n#define OFFSET 4\n#define UNUSED_MACRO 7\n"
            "int target(int a)\n{\n    return hidden_callee((a) + 4);\n}\n"
        )
        write_tree(run_dir, {"m.c": source})
        result = slice_of(run_dir, "m.c", "target", canned)
        text = result["text"]
        for wanted in ("#define OUTER(v)", "#define INNER(v)", "#define OFFSET 4", "int hidden_callee(int x);"):
            assert wanted in text
        assert "UNUSED_MACRO" not in text
        assert by_name(result)["hidden_callee"]["kind"] == "in_tree"
        assert result["stats"]["macros"] == 3

    def test_callee_made_by_token_pasting_is_only_visible_expanded(self, run_dir):
        source = (
            "int parse_token_v2(int x);\n"
            "#define PARSE(kind, v) parse_##kind(v)\n"
            "int target(int a) { return PARSE(token_v2, a); }\n"
        )
        canned = (
            '# 1 "workspace/work/m.c"\nint parse_token_v2(int x);\n#define PARSE(kind,v) parse_ ##kind(v)\n'
            "int target(int a) { return parse_token_v2(a); }\n"
        )
        write_tree(run_dir, {"m.c": source})
        result = slice_of(run_dir, "m.c", "target", canned)
        assert "parse_token_v2" in by_name(result)
        assert "int parse_token_v2(int x);" in result["text"]
        assert "#define PARSE(kind, v) parse_##kind(v)" in result["text"]  # real text, not -dD's

    def test_types_enumerators_and_globals(self, run_dir):
        header = (
            "typedef struct {\n"
            "    int len;\n"
            "} buf_t;\n"
            "typedef int (*cb_t)(buf_t *b, int n);\n"
            "enum color { RED, GREEN = 5, BLUE };\n"
            "typedef unsigned char u8;\n"
            "typedef struct { int z; } unused_t;\n"
            "enum other { NOPE };\n"
            "extern int g_count;\n"
            "int g_unused;\n"
            "static const int table[3] = {1, 2, 3};\n"
        )
        source = (
            '#include "t.h"\n'
            "int g_count = 3;\n"
            "int target(buf_t *b, cb_t cb, u8 k)\n"
            "{\n"
            "    return cb(b, GREEN) + g_count + table[k];\n"
            "}\n"
        )
        canned = (
            f'# 1 "workspace/work/t.c"\n# 1 "workspace/work/t.h" 1\n{header}# 2 "workspace/work/t.c" 2\n'
            "int g_count = 3;\nint target(buf_t *b, cb_t cb, u8 k)\n{\n    return cb(b, 5) + g_count + table[k];\n}\n"
        )
        write_tree(run_dir, {"t.c": source, "t.h": header})
        result = slice_of(run_dir, "t.c", "target", canned)
        text = result["text"]
        assert "} buf_t;" in text
        assert "typedef int (*cb_t)(buf_t *b, int n);" in text
        assert "enum color { RED, GREEN = 5, BLUE };" in text
        assert "typedef unsigned char u8;" in text
        assert "int g_count = 3;" in text  # the definition, not the extern declaration
        assert "extern int g_count" not in text
        assert "static const int table[3] = {1, 2, 3};" in text
        for absent in ("unused_t", "enum other", "g_unused"):
            assert absent not in text
        assert result["callees"] == []  # `cb` is a parameter
        assert result["stats"]["types"] == 4
        assert result["stats"]["globals"] == 2
        assert text.index("} buf_t;") < text.index("typedef int (*cb_t)")  # definitions precede uses

    def test_a_tag_reached_through_a_typedef_and_a_forward_declaration(self, run_dir):
        source = (
            "struct node;\n"
            "typedef struct node node_t;\n"
            "struct node { node_t *next; int v; };\n"
            "struct opaque;\n"
            "int target(node_t *n, struct opaque *o) { return n->v; }\n"
        )
        write_tree(run_dir, {"t.c": source})
        result = slice_of(run_dir, "t.c", "target", cpp_like("t.c", source))
        assert "typedef struct node node_t;" in result["text"]
        assert "struct node { node_t *next; int v; };" in result["text"]
        assert "struct opaque;" in result["text"]
        assert "/* t.c:1-1 */" not in result["text"]  # the definition replaces `struct node;`

    def test_member_names_only_resolve_to_macros(self, run_dir):
        source = (
            "#include <s.h>\n"
            "int len;\n"
            "#define value real_value\n"
            "int target(struct s *p) { return p->len + p->value; }\n"
        )
        canned = (
            '# 1 "workspace/work/t.c"\n# 1 "/opt/libc/s.h" 1\nstruct s { int len; int real_value; };\n'
            '# 2 "workspace/work/t.c" 2\nint len;\n#define value real_value\n'
            "int target(struct s *p) { return p->len + p->real_value; }\n"
        )
        write_tree(run_dir, {"t.c": source})
        result = slice_of(run_dir, "t.c", "target", canned)
        assert "#define value real_value" in result["text"]
        assert "int len;" not in result["text"]  # `p->len` is a member, not the global

    def test_attribute_arguments_are_not_calls(self, run_dir):
        source = "int target(void)\n{\n    static const char ALIGNED_BUF __attribute__((aligned(16))) = 0;\n    return ALIGNED_BUF;\n}\n"
        write_tree(run_dir, {"t.c": source})
        result = slice_of(run_dir, "t.c", "target", cpp_like("t.c", source))
        assert result["callees"] == []

    def test_function_pointer_parameters_and_locals_are_not_callees(self, run_dir):
        source = (
            "typedef int (*fn_t)(int);\n"
            "int target(fn_t cb, int v)\n"
            "{\n"
            "    int (*local)(int) = cb;\n"
            "    fn_t other = cb;\n"
            "    return cb(v) + local(v) + other(v);\n"
            "}\n"
        )
        write_tree(run_dir, {"t.c": source})
        result = slice_of(run_dir, "t.c", "target", cpp_like("t.c", source))
        assert result["callees"] == []

    def test_libc_and_tool_headers_are_never_printed(self, run_dir):
        source = "#include <string.h>\nint target(char *d, const char *s) { memcpy(d, s, SIZE_CONST); return 0; }\n"
        canned = (
            '# 1 "workspace/work/t.c"\n'
            '# 1 "/opt/fc/share/libc/string.h" 1\n'
            "#define SIZE_CONST 4\n"
            "typedef unsigned long size_t;\n"
            "void *memcpy(void *d, const void *s, size_t n);\n"
            '# 2 "workspace/work/t.c" 2\n'
            "int target(char *d, const char *s) { memcpy(d, s, 4); return 0; }\n"
        )
        write_tree(run_dir, {"t.c": source})
        result = slice_of(run_dir, "t.c", "target", canned)
        info = by_name(result)["memcpy"]
        assert info["kind"] == "libc_or_external"
        assert info["file"] == "/opt/fc/share/libc/string.h"
        assert "#define SIZE_CONST" not in result["text"]
        assert "typedef unsigned long" not in result["text"]
        assert "not shown: memcpy" in result["text"]
        assert "SIZE_CONST" in result["text"]  # named only, in the header comment and the target

    def test_fc_stubs_and_harness_compat_headers_are_not_in_tree(self, run_dir):
        tree = fs._Tree(run_dir, run_dir / "agents" / "a1" / "scratch" / "work")
        assert tree.rel("/opt/framac-pipeline/templates/fc_stubs/fc_compat_types.h") is None
        assert tree.rel("/home/opam/.opam/5.5/share/frama-c/share/libc/stdio.h") is None
        assert tree.rel("workspace/harnesses/compat.h") is None
        assert tree.rel("<built-in>") is None
        assert tree.rel("agents/a1/scratch/work/a/b.h") == "a/b.h"
        assert tree.rel("./workspace/work/x/../b.h") == "b.h"
        assert tree.rel("/framac-run/workspace/work/b.h") == "b.h"
        assert tree.rel("/target/inc/b.h") == "inc/b.h"
        assert tree.rel((run_dir / "workspace" / "work" / "c.h").as_posix()) == "c.h"

    def test_a_path_that_merely_contains_workspace_work_is_not_in_tree(self, run_dir):
        tree = fs._Tree(run_dir, run_dir / "workspace" / "work")
        assert tree.rel("/home/me/workspace/work/libfoo/foo.h") is None

    def test_acsl_logic_declarations_reached_from_target_and_callee_contracts(self, run_dir):
        header = (
            "/*@ predicate is_ok(integer x) = x > 0; */\n"
            "/*@ predicate unused_pred(integer x) = x < 0; */\n"
            "/*@ logic integer twice(integer x) = 2 * x; */\n"
            "/*@ axiomatic Ax {\n"
            "  @   logic integer hidden_fn(integer x);\n"
            "  @ }\n"
            "  @*/\n"
            "/*@ requires is_ok(a);\n"
            "  @ ensures \\result == twice(a) + hidden_fn(a); */\n"
            "int callee(int a);\n"
        )
        source = '#include "l.h"\n/*@ requires is_ok(v); */\nint target(int v) { return callee(v); }\n'
        canned = (
            '# 1 "workspace/work/l.c"\n# 1 "workspace/work/l.h" 1\n'
            '# 10 "workspace/work/l.h"\nint callee(int a);\n# 2 "workspace/work/l.c" 2\n'
            "\nint target(int v) { return callee(v); }\n"
        )
        write_tree(run_dir, {"l.c": source, "l.h": header})
        result = slice_of(run_dir, "l.c", "target", canned)
        text = result["text"]
        assert "predicate is_ok" in text
        assert "logic integer twice" in text
        assert "axiomatic Ax" in text
        assert "unused_pred" not in text
        assert result["stats"]["logic_decls"] == 3

    def test_a_macro_defined_in_the_body_is_shown_once_and_followed(self, run_dir):
        source = (
            "#define BASE 4\n"
            "int target(void)\n"
            "{\n"
            "#define TMP (BASE + 1)\n"
            "    int v = TMP;\n"
            "#undef TMP\n"
            "    return v;\n"
            "}\n"
        )
        canned = (
            '# 1 "workspace/work/m.c"\n#define BASE 4\nint target(void)\n{\n#define TMP (BASE + 1)\n'
            "    int v = (4 + 1);\n#undef TMP\n    return v;\n}\n"
        )
        write_tree(run_dir, {"m.c": source})
        result = slice_of(run_dir, "m.c", "target", canned)
        assert result["text"].count("#define TMP") == 1
        assert "/* m.c:1 */\n#define BASE 4" in result["text"]

    def test_undef_and_redefinition_resolve_by_position(self, run_dir):
        source = (
            "#define LEVEL 1\n"
            "#define GONE 3\n"
            "#undef GONE\n"
            "#undef LEVEL\n"
            "#define LEVEL 2\n"
            "int target(void)\n"
            "{\n"
            "    int GONE = 0;\n"
            "    return LEVEL + GONE;\n"
            "}\n"
            "#undef LEVEL\n"
            "#define LEVEL 3\n"
        )
        canned = (
            '# 1 "workspace/work/u.c"\n#define LEVEL 1\n#define GONE 3\n#undef GONE\n#undef LEVEL\n#define LEVEL 2\n'
            "int target(void)\n{\n    int GONE = 0;\n    return 2 + GONE;\n}\n#undef LEVEL\n#define LEVEL 3\n"
        )
        write_tree(run_dir, {"u.c": source})
        text = slice_of(run_dir, "u.c", "target", canned)["text"]
        assert "/* u.c:5 */\n#define LEVEL 2" in text
        assert "#define LEVEL 1" not in text
        assert "#define LEVEL 3" not in text
        assert "#define GONE" not in text

    def test_a_declaration_uses_the_macro_active_at_its_own_position(self, run_dir):
        source = (
            "#define SIZE 8\n"
            "struct s { char b[SIZE]; };\n"
            "#undef SIZE\n"
            "#define SIZE 16\n"
            "int target(struct s *p) { return SIZE; }\n"
        )
        canned = (
            '# 1 "workspace/work/m.c"\n#define SIZE 8\nstruct s { char b[8]; };\n#undef SIZE\n#define SIZE 16\n'
            "int target(struct s *p) { return 16; }\n"
        )
        write_tree(run_dir, {"m.c": source})
        text = slice_of(run_dir, "m.c", "target", canned)["text"]
        assert "#define SIZE 8" in text
        assert "#define SIZE 16" in text


# ---------------------------------------------------------------------------
# Callee contracts, same-named statics, callee bodies
# ---------------------------------------------------------------------------

STATIC_A = "/*@ ensures \\result == x + 1; */\nstatic int helper(int x) { return x + 1; }\nint use_a(int v) { return helper(v); }\n"
STATIC_B = "/*@ ensures \\result == x + 2; */\nstatic int helper(int x) { return x + 2; }\nint use_b(int v) { return helper(v); }\n"


class TestCallees:
    def test_callee_with_and_without_a_contract(self, run_dir):
        header = (
            "/*@ requires a >= 0; assigns \\nothing; */\n"
            "int with_contract(int a);\n"
            "int bare(int a);\n"
            "int def_holds(int a);\n"
        )
        source = (
            '#include "h.h"\n'
            "/*@ ensures \\result >= 0; */\n"
            "int def_holds(int a) { return a; }\n"
            "int top(int a) { return with_contract(a) + bare(a) + def_holds(a); }\n"
        )
        canned = (
            '# 1 "workspace/work/m.c"\n# 1 "workspace/work/h.h" 1\n\nint with_contract(int a);\nint bare(int a);\n'
            'int def_holds(int a);\n# 2 "workspace/work/m.c" 2\n\nint def_holds(int a) { return a; }\n'
            "int top(int a) { return with_contract(a) + bare(a) + def_holds(a); }\n"
        )
        write_tree(run_dir, {"m.c": source, "h.h": header})
        result = slice_of(run_dir, "m.c", "top", canned)
        callees = by_name(result)
        assert callees["with_contract"] == {
            "name": "with_contract",
            "file": "h.h",
            "line": 1,
            "has_contract": True,
            "kind": "in_tree",
        }
        assert callees["bare"]["has_contract"] is False
        assert callees["def_holds"]["has_contract"] is True
        assert callees["def_holds"]["file"] == "m.c"  # the holder, not the bare prototype
        text = result["text"]
        assert "requires a >= 0; assigns \\nothing;" in text
        assert "ensures \\result >= 0;" in text
        assert text.count("/* no contract yet */") == 1
        assert "/* no contract yet */\nint bare(int a);" in text
        assert "{ return a; }" not in text.split("======== Target")[0]  # a callee's body stays out

    def test_contracts_are_read_from_the_snapshot_not_the_shared_tree(self, run_dir):
        write_tree(
            run_dir, {"h.h": "int callee(int a);\n", "m.c": '#include "h.h"\nint top(int a) { return callee(a); }\n'}
        )
        snapshot = {
            "h.h": "/*@ requires a > 7; */\nint callee(int a);\n",
            "m.c": '#include "h.h"\nint top(int a) { return callee(a); }\n',
        }
        write_tree(run_dir, snapshot, "agents/a1/scratch/work")
        canned = (
            '# 1 "agents/a1/scratch/work/m.c"\n# 1 "agents/a1/scratch/work/h.h" 1\n\nint callee(int a);\n'
            '# 2 "agents/a1/scratch/work/m.c" 2\nint top(int a) { return callee(a); }\n'
        )
        result = slice_of(
            run_dir,
            "m.c",
            "top",
            canned,
            work_dir=Path("agents/a1/scratch/work"),
            cppflags="-Iagents/a1/scratch/work -I.",
        )
        assert "requires a > 7;" in result["text"]
        assert by_name(result)["callee"]["has_contract"] is True

    def test_same_named_statics_resolve_within_the_translation_unit(self, run_dir):
        write_tree(run_dir, {"a.c": STATIC_A, "b.c": STATIC_B})
        canned_a = cpp_like("a.c", STATIC_A)
        dag = {"helper": {"name": "helper", "file": "b.c", "is_static": True}}
        for dag_functions in (dag, {"helper": {"name": "helper", "file": "b.c"}}, None):
            result = slice_of(
                run_dir,
                "a.c",
                "use_a",
                canned_a,
                dag_functions=dag_functions,
                out_dir=run_dir / "out",
                max_inline_lines=500,
            )
            assert by_name(result)["helper"]["file"] == "a.c"
            assert by_name(result)["helper"]["line"] == 1
            assert "\\result == x + 1" in result["text"]
            assert "\\result == x + 2" not in result["text"]
            bodies = (run_dir / result["callee_bodies_file"]).read_text(encoding="utf-8")
            assert "return x + 1;" in bodies
            assert "return x + 2;" not in bodies

    def test_the_target_itself_comes_from_the_requested_file(self, run_dir):
        write_tree(run_dir, {"a.c": STATIC_A, "b.c": STATIC_B})
        result = slice_of(run_dir, "b.c", "helper", cpp_like("b.c", STATIC_B))
        assert result["target"]["file"] == "b.c"
        assert "return x + 2;" in result["text"]
        assert "return x + 1;" not in result["text"]

    def test_dag_locates_the_body_of_a_callee_in_another_translation_unit(self, run_dir):
        files = {
            "h.h": "int ext_fn(int x);\n",
            "main.c": '#include "h.h"\nint top(int a) { return ext_fn(a); }\n',
            "c.c": '#include "h.h"\n/*@ requires x > 0; */\nint ext_fn(int x) { return x * 3; }\n',
            "d.c": "static int ext_fn(int x) { return x * 4; }\n",
            "e.c": "int unrelated(void) { return 0; }\n",
        }
        canned = (
            '# 1 "workspace/work/main.c"\n# 1 "workspace/work/h.h" 1\nint ext_fn(int x);\n'
            '# 2 "workspace/work/main.c" 2\nint top(int a) { return ext_fn(a); }\n'
        )
        write_tree(run_dir, files)
        out = run_dir / "out"
        good = slice_of(run_dir, "main.c", "top", canned, dag_functions={"ext_fn": {"file": "c.c"}}, out_dir=out)
        assert by_name(good)["ext_fn"]["has_contract"] is True
        assert "requires x > 0;" in good["text"]
        assert "return x * 3;" in (run_dir / good["callee_bodies_file"]).read_text(encoding="utf-8")

        for bad_meta in (
            {"file": "d.c"},
            {"file": "e.c"},
            {"file": "nope.c"},
            {"file": "../../etc/x.c"},
            {"file": 3},
            "x",
        ):
            bad = slice_of(run_dir, "main.c", "top", canned, dag_functions={"ext_fn": bad_meta}, out_dir=out)
            assert by_name(bad)["ext_fn"]["has_contract"] is False
            assert by_name(bad)["ext_fn"]["file"] == "h.h"
            assert bad["callee_bodies_file"] is None
            assert "/* no contract yet */" in bad["text"]
        assert not (out / "top.callee_bodies.c").exists()  # the earlier run's file does not survive as stale

    def test_dag_collision_keys_are_understood(self, run_dir):
        files = {
            "main.c": "int ext_fn(int x);\nint top(int a) { return ext_fn(a); }\n",
            "c.c": "int ext_fn(int x) { return x * 3; }\n",
        }
        write_tree(run_dir, files)
        canned = cpp_like("main.c", files["main.c"])
        result = slice_of(
            run_dir, "main.c", "top", canned, dag_functions={"c.c#ext_fn": {"file": "c.c"}}, out_dir=run_dir / "o"
        )
        assert result["callee_bodies_file"] is not None

    def test_an_undeclared_callee_known_only_to_the_dag_still_shows_its_contract(self, run_dir):
        files = {
            "main.c": "int top(int a) { return ext_fn(a); }\n",
            "c.c": "/*@ requires x > 5; */\nint ext_fn(int x) { return x; }\n",
        }
        write_tree(run_dir, files)
        result = slice_of(
            run_dir, "main.c", "top", cpp_like("main.c", files["main.c"]), dag_functions={"ext_fn": {"file": "c.c"}}
        )
        assert by_name(result)["ext_fn"]["kind"] == "in_tree"
        assert "requires x > 5;" in result["text"]

    def test_header_prototype_of_the_target(self, run_dir):
        header = (
            "#ifndef P_H\n"
            "#define P_H\n"
            "/*@ requires n > 0;\n"
            "  @ ensures \\result >= 0;\n"
            "  @*/\n"
            "int target(int n);\n"
            "#endif\n"
        )
        source = '#include "p.h"\nint target(int n) { return n; }\n'
        canned = (
            '# 1 "workspace/work/p.c"\n# 1 "workspace/work/p.h" 1\n\n#define P_H\n\n\n\nint target(int n);\n'
            '# 2 "workspace/work/p.c" 2\nint target(int n) { return n; }\n'
        )
        write_tree(run_dir, {"p.c": source, "p.h": header})
        for header_file in ("p.h", None):
            result = slice_of(run_dir, "p.c", "target", canned, header_file=header_file)
            assert result["header_prototype"] == {"file": "p.h", "start_line": 3, "end_line": 6}
            assert "requires n > 0;" in result["text"]
            assert result["target"] == {"file": "p.c", "start_line": 2, "end_line": 2}

    def test_header_named_by_the_caller_but_not_in_the_unit_is_read_lexically(self, run_dir):
        files = {"q.h": "/*@ requires n > 9; */\nint target(int n);\n", "p.c": "int target(int n) { return n; }\n"}
        write_tree(run_dir, files)
        result = slice_of(run_dir, "p.c", "target", cpp_like("p.c", files["p.c"]), header_file="q.h")
        assert result["header_prototype"] == {"file": "q.h", "start_line": 1, "end_line": 2}
        assert "requires n > 9;" in result["text"]

    def test_contract_after_a_normal_comment_and_attribute_after_the_parameters(self, run_dir):
        header = (
            "/* Doc comment before the contract. */\n"
            "/*@ requires a > 1; */\n"
            "/* Doc comment after it. */\n"
            "int quirky(int a) __attribute__((const));\n"
        )
        source = '#include "h.h"\nint top(int a) { return quirky(a); }\n'
        canned = (
            '# 1 "workspace/work/m.c"\n# 1 "workspace/work/h.h" 1\n\n\n\nint quirky(int a) __attribute__((const));\n'
            '# 2 "workspace/work/m.c" 2\nint top(int a) { return quirky(a); }\n'
        )
        write_tree(run_dir, {"h.h": header, "m.c": source})
        result = slice_of(run_dir, "m.c", "top", canned)
        assert by_name(result)["quirky"]["has_contract"] is True
        assert by_name(result)["quirky"]["line"] == 2
        assert "Doc comment before" not in result["text"]

    def test_callee_bodies_bounds_and_note(self, run_dir, monkeypatch):
        monkeypatch.setattr(fs, "CALLEE_BODY_MAX_LINES", 5)
        monkeypatch.setattr(fs, "CALLEE_BODIES_MAX_LINES", 7)
        long_body = "\n".join(f"    x += {i};" for i in range(20))
        source = (
            f"static int long_one(int x)\n{{\n{long_body}\n    return x;\n}}\n"
            "static int short_one(int x) { return x; }\n"
            "static int short_two(int x) { return x; }\n"
            "static int short_three(int x) { return x; }\n"
            "static int short_four(int x) { return x; }\n"
            "int top(int a) { return long_one(a) + short_one(a) + short_two(a) + short_three(a) + short_four(a); }\n"
        )
        write_tree(run_dir, {"m.c": source})
        result = slice_of(run_dir, "m.c", "top", cpp_like("m.c", source), out_dir=run_dir / "o")
        bodies = (run_dir / result["callee_bodies_file"]).read_text(encoding="utf-8")
        assert "WP only ever uses callee contracts" in bodies
        assert "more lines omitted; see m.c:1-" in bodies
        assert "x += 2;" in bodies
        assert "x += 3;" not in bodies
        assert "Omitted for size" in bodies
        assert "short_two" in bodies.split("Omitted for size")[1]
        assert result["callee_bodies_file"] == "o/top.callee_bodies.c"

    def test_callee_bodies_can_be_turned_off(self, run_dir):
        write_tree(run_dir, {"a.c": STATIC_A})
        result = slice_of(
            run_dir, "a.c", "use_a", cpp_like("a.c", STATIC_A), out_dir=run_dir / "o", callee_bodies=False
        )
        assert result["callee_bodies_file"] is None
        assert result["slice_file"] == "o/use_a.slice.c"
        assert not (run_dir / "o" / "use_a.callee_bodies.c").exists()


# ---------------------------------------------------------------------------
# Layout and size bounds
# ---------------------------------------------------------------------------


def _big_source(macros: int = 40, callees: int = 5, body_lines: int = 30) -> str:
    parts = [f"#define M{i} {i}" for i in range(macros)]
    parts += [f"/*@ requires a > {i}; */\nint callee{i}(int a);" for i in range(callees)]
    uses = " + ".join(f"M{i}" for i in range(macros))
    calls = " + ".join(f"callee{i}(a)" for i in range(callees))
    body = [f"    /* body line {i} */ a += {i};" for i in range(body_lines)]
    parts += ["int target(int a)", "{", *body, f"    return {uses} + {calls};", "}"]
    return "\n".join(parts) + "\n"


class TestLayoutAndBounds:
    def test_slice_file_layout(self, run_dir):
        write_tree(run_dir, {"t.c": BRANCHES_C, "cfg.h": BRANCHES_H, "cfg.c": BRANCHES_C})
        result = slice_of(run_dir, "cfg.c", "compute", BRANCHES_CANNED, out_dir=run_dir / "agents" / "a1" / "scratch")
        assert result["slice_file"] == "agents/a1/scratch/compute.slice.c"
        text = (run_dir / result["slice_file"]).read_text(encoding="utf-8")
        assert text == result["text"]
        assert "READING CONTEXT ONLY" in text
        assert "Do not compile, include or edit" in text
        assert "workspace/work/cfg.c, lines 12-15" in text
        order = [text.index(word) for word in ("Macros (", "Types (", "Callee prototypes", "Target: compute")]
        assert order == sorted(order)
        assert "/* cfg.c:8 */\n#define LIMIT 10" in text
        assert "/* cfg.c:7-7 */\ntypedef short value_t;" in text
        assert text.endswith("}\n")
        assert result["stats"]["lines"] == text.count("\n")

    def test_relative_out_dir_resolves_against_the_run_dir(self, run_dir, tmp_path, monkeypatch):
        write_tree(run_dir, {"a.c": STATIC_A})
        monkeypatch.chdir(tmp_path)
        result = slice_of(run_dir, "a.c", "use_a", cpp_like("a.c", STATIC_A), out_dir=Path("rel/out"))
        assert result["slice_file"] == "rel/out/use_a.slice.c"
        assert (run_dir / "rel" / "out" / "use_a.slice.c").is_file()
        assert not (tmp_path / "rel").exists()

    def test_no_out_dir_writes_nothing(self, run_dir):
        write_tree(run_dir, {"a.c": STATIC_A})
        before = {p for p in run_dir.rglob("*")}
        result = slice_of(run_dir, "a.c", "use_a", cpp_like("a.c", STATIC_A))
        assert result["slice_file"] is None and result["callee_bodies_file"] is None
        assert {p for p in run_dir.rglob("*")} == before

    def test_under_the_bound_nothing_is_cut(self, run_dir):
        source = _big_source(macros=3, callees=1, body_lines=2)
        write_tree(run_dir, {"t.c": source})
        result = slice_of(run_dir, "t.c", "target", cpp_like("t.c", source))
        assert result["truncated"] is False
        assert "TRUNCATED" not in result["text"]

    def test_the_bound_keeps_target_and_callees_over_macros(self, run_dir):
        source = _big_source()
        write_tree(run_dir, {"t.c": source})
        result = slice_of(run_dir, "t.c", "target", cpp_like("t.c", source), out_dir=run_dir / "o", max_inline_lines=80)
        text = result["text"]
        assert result["truncated"] is True
        assert text.count("\n") <= 80
        for i in range(30):
            assert f"/* body line {i} */ a += {i};" in text
        for i in range(5):
            assert f"requires a > {i};" in text
        assert "TRUNCATED" in text
        assert "the target below is complete" in text
        assert "o/target.slice.c" in text
        omitted = text.split("Omitted:")[1].split("*/")[0]
        assert "macros:" in omitted
        kept = {i for i in range(40) if f"#define M{i} {i}\n" in text}
        assert len(kept) < 40
        for i in set(range(40)) - kept:
            assert re.search(rf"\bM{i}\b", omitted), f"M{i} omitted but not named"
        full = (run_dir / "o" / "target.slice.c").read_text(encoding="utf-8")
        assert all(f"#define M{i} {i}\n" in full for i in range(40))

    def test_a_target_longer_than_the_bound_is_never_cut(self, run_dir):
        source = _big_source(macros=5, callees=2, body_lines=60)
        write_tree(run_dir, {"t.c": source})
        result = slice_of(run_dir, "t.c", "target", cpp_like("t.c", source), max_inline_lines=5)
        for i in range(60):
            assert f"/* body line {i} */ a += {i};" in result["text"]
        assert result["truncated"] is True
        assert "The full slice was not written" in result["text"]
        assert "requires a > 0;" not in result["text"]

    def test_closer_entries_survive_a_cut_first(self):
        far = fs._Entry("macros", (1,), 3, "/* far */\n#define FAR 1", "FAR")
        near = fs._Entry("macros", (2,), 0, "/* near */\n#define NEAR 1", "NEAR")
        kept, omitted = fs._fit_entries([far, near], 5)
        assert [e.label for e in kept] == ["NEAR"]
        assert [e.label for e in omitted] == ["FAR"]

    def test_a_long_initializer_is_abbreviated_with_a_note(self, run_dir):
        values = "\n".join(f"    {i}," for i in range(40))
        source = f"static const int big[] = {{\n{values}\n}};\nint target(int i) {{ return big[i]; }}\n"
        write_tree(run_dir, {"t.c": source})
        result = slice_of(run_dir, "t.c", "target", cpp_like("t.c", source), out_dir=run_dir / "o")
        for text in (result["text"], (run_dir / result["slice_file"]).read_text(encoding="utf-8")):
            assert "static const int big[] = {" in text
            assert "initializer abbreviated here" in text
            assert "t.c:1-42" in text
            assert "    39," not in text

    def test_a_short_table_keeps_its_values(self, run_dir):
        source = 'static const char *map = "\\0\\1"\n                       "\\1\\0";\nint target(int i) { return map[i]; }\n'
        write_tree(run_dir, {"t.c": source})
        result = slice_of(run_dir, "t.c", "target", cpp_like("t.c", source))
        assert '"\\1\\0";' in result["text"]
        assert "abbreviated" not in result["text"]

    def test_long_types_lose_normal_comments_but_keep_acsl(self, run_dir):
        fields = "\n".join(f"    /* doc of field {i} */\n    int f{i};" for i in range(25))
        source = (
            f"struct big {{\n{fields}\n    /*@ ghost int g; */\n}};\nint target(struct big *b) {{ return b->f0; }}\n"
        )
        write_tree(run_dir, {"t.c": source})
        text = slice_of(run_dir, "t.c", "target", cpp_like("t.c", source))["text"]
        assert "int f24;" in text
        assert "doc of field" not in text
        assert "ghost int g" in text
        assert "comments removed for size" in text

    def test_short_types_keep_their_comments(self, run_dir):
        source = "struct s {\n    /* why this field */\n    int f;\n};\nint target(struct s *b) { return b->f; }\n"
        write_tree(run_dir, {"t.c": source})
        text = slice_of(run_dir, "t.c", "target", cpp_like("t.c", source))["text"]
        assert "why this field" in text

    def test_a_declaration_ending_in_a_multi_line_macro_call_prints_whole(self, run_dir):
        source = "#define MAKE(a, b) { a, b }\nstatic const int pair[2] = MAKE(\n    1,\n    2);\nint target(void) { return pair[0]; }\n"
        canned = (
            '# 1 "workspace/work/e.c"\n#define MAKE(a,b) { a, b }\nstatic const int pair[2] = { 1, 2 };\n\n\n'
            "int target(void) { return pair[0]; }\n"
        )
        write_tree(run_dir, {"e.c": source})
        result = slice_of(run_dir, "e.c", "target", canned)
        assert "    2);" in result["text"]
        assert "/* e.c:2-4 */" in result["text"]
        assert "#define MAKE(a, b) { a, b }" in result["text"]

    def test_a_macro_that_declares_something_is_not_part_of_the_next_function(self, run_dir):
        source = "#define DECLARE(n) static int n;\nDECLARE(counter)\nint target(void)\n{\n    return counter;\n}\n"
        canned = (
            '# 1 "workspace/work/e.c"\n#define DECLARE(n) static int n;\nstatic int counter;\n'
            "int target(void)\n{\n    return counter;\n}\n"
        )
        write_tree(run_dir, {"e.c": source})
        result = slice_of(run_dir, "e.c", "target", canned)
        assert result["target"] == {"file": "e.c", "start_line": 3, "end_line": 6}
        assert "/* e.c:2-2 */\nDECLARE(counter)" in result["text"]
        assert "#define DECLARE(n) static int n;" in result["text"]

    def test_output_is_deterministic(self, run_dir):
        source = _big_source(macros=12, callees=4, body_lines=3)
        write_tree(run_dir, {"t.c": source})
        first = slice_of(run_dir, "t.c", "target", cpp_like("t.c", source), max_inline_lines=30)
        second = slice_of(run_dir, "t.c", "target", cpp_like("t.c", source), max_inline_lines=30)
        assert first == second
        script = (
            "import function_slice as fs, sys\n"
            "from pathlib import Path\n"
            "def tool(cmd, **k): raise FileNotFoundError(cmd[0])\n"
            "r = fs.build_slice(Path(sys.argv[1]), Path('workspace/work'), 't.c', 'target', '-I.', runner=tool)\n"
            "sys.stdout.reconfigure(encoding='utf-8', newline='\\n')\n"
            "sys.stdout.write(r['text'])\n"
        )
        outs = set()
        for seed in ("1", "2", "3"):
            env = {
                **os.environ,
                "PYTHONHASHSEED": seed,
                "PYTHONPATH": str(Path(fs.__file__).parent),
                "PYTHONIOENCODING": "utf-8",
            }
            outs.add(
                subprocess.run(
                    [sys.executable, "-c", script, str(run_dir)], capture_output=True, env=env, check=True
                ).stdout
            )
        assert len(outs) == 1

    def test_specifier_macro_on_its_own_line_and_contract_above_it(self, run_dir):
        source = "#define API\n/*@ requires a > 3; */\nAPI\nint exported(int a);\nint target(int a) { return exported(a); }\n"
        canned = '# 1 "workspace/work/e.c"\n#define API\n\n\nint exported(int a);\nint target(int a) { return exported(a); }\n'
        write_tree(run_dir, {"e.c": source})
        result = slice_of(run_dir, "e.c", "target", canned)
        assert by_name(result)["exported"]["has_contract"] is True
        assert "API\nint exported(int a);" in result["text"]
        assert "#define API" in result["text"]


# ---------------------------------------------------------------------------
# Degraded mode and failures
# ---------------------------------------------------------------------------


class TestDegradedAndFailures:
    FILES = {
        "inc/h.h": (
            "#ifndef H_H\n#define H_H\n#define FROM_HEADER 2\n/*@ requires a > 0; */\nint in_header(int a);\n#endif\n"
        ),
        "d.c": (
            '#include "inc/h.h"\n'
            "#include <string.h>\n"
            "#if 0\n"
            "it's prose, not code\n"
            "typedef char never_t;\n"
            "#endif\n"
            "#ifdef __cplusplus\n"
            'extern "C" {\n'
            "#endif\n"
            "#ifdef WIDE\n"
            "typedef long branch_t;\n"
            "#define PICK 1\n"
            "#else\n"
            "typedef short branch_t;\n"
            "#define PICK 2\n"
            "#endif\n"
            "#define VIA_MACRO(x) in_macro(x)\n"
            "int in_macro(int x);\n"
            "int target(never_t *n, branch_t v)\n"
            "{\n"
            "    memset(&v, 0, sizeof v);\n"
            "    return in_header(v) + PICK + FROM_HEADER + VIA_MACRO(1);\n"
            "}\n"
        ),
    }

    def test_lexical_slice_when_no_preprocessor_exists(self, run_dir):
        write_tree(run_dir, self.FILES)
        result = slice_of(run_dir, "d.c", "target", runner=no_tools, out_dir=run_dir / "o")
        assert result["status"] == "degraded"
        assert result["conditionals"] == "unresolved"
        assert result["preprocessor"] == "lexical"
        for step in ("Frama-C preprocessor failed", "gcc -E failed", "conditionals unresolved"):
            assert step in result["reason"]
        text = result["text"]
        assert "WARNING: NO PREPROCESSOR RAN" in text
        assert "typedef long branch_t;" in text and "typedef short branch_t;" in text  # both branches, flagged
        assert "#define PICK 1" in text and "#define PICK 2" in text
        assert "#define FROM_HEADER 2" in text
        assert "typedef char never_t;" not in text  # #if 0 needs no preprocessor
        callees = by_name(result)
        assert callees["in_header"]["file"] == "inc/h.h"
        assert callees["in_header"]["has_contract"] is True
        assert callees["in_macro"]["kind"] == "in_tree"  # hidden in a macro, found through its body
        assert callees["memset"] == {
            "name": "memset",
            "file": None,
            "line": 0,
            "has_contract": False,
            "kind": "libc_or_external",
        }
        assert "VIA_MACRO" not in callees and "PICK" not in callees
        assert result["target"]["start_line"] == 19
        assert (run_dir / result["slice_file"]).read_text(encoding="utf-8") == text

    def test_preprocessor_failure_falls_back_with_its_message(self, run_dir):
        write_tree(run_dir, self.FILES)

        def failing(cmd, **kwargs):
            if cmd[0] == "frama-c":
                raise FileNotFoundError(cmd[0])
            return _cp(cmd, 1, err="In file included from x.c:1:\nx.c:1:10: fatal error: nope.h: No such file\n")

        result = slice_of(run_dir, "d.c", "target", runner=failing)
        assert result["status"] == "degraded"
        assert "fatal error: nope.h" in result["reason"]

    def test_timeout_falls_back(self, run_dir):
        write_tree(run_dir, {"t.c": "int target(void) { return 0; }\n"})

        def slow(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, float(kwargs.get("timeout") or 1))

        assert slice_of(run_dir, "t.c", "target", runner=slow)["status"] == "degraded"

    def test_unbalanced_braces_across_branches_keep_later_functions_visible(self, run_dir):
        source = (
            "#ifdef A\n"
            "int first(int x) {\n"
            "#else\n"
            "int first(long x) {\n"
            "#endif\n"
            "    return 0;\n"
            "}\n"
            "int after(void) { return 1; }\n"
        )
        write_tree(run_dir, {"u.c": source})
        result = slice_of(run_dir, "u.c", "after", runner=no_tools)
        assert result["status"] == "degraded"
        assert result["target"] == {"file": "u.c", "start_line": 8, "end_line": 8}

    def test_several_definitions_under_unresolved_conditionals_are_reported(self, run_dir):
        source = "#ifdef A\nint f(void) { return 1; }\n#else\nint f(void) { return 2; }\n#endif\n"
        write_tree(run_dir, {"u.c": source})
        result = slice_of(run_dir, "u.c", "f", runner=no_tools)
        assert result["status"] == "degraded"
        assert "several definitions" in result["reason"]
        assert result["target"]["start_line"] == 2

    def test_lexical_includes_stay_in_the_tree_and_use_the_snapshot(self, run_dir):
        write_tree(run_dir, {"s.h": "int shared_only(int a);\n"})
        write_tree(run_dir, {"s.h": "/*@ requires a > 2; */\nint shared_only(int a);\n"}, "agents/a1/scratch/work")
        write_tree(
            run_dir, {"t.c": "#include <s.h>\nint target(void) { return shared_only(1); }\n"}, "agents/a1/scratch/work"
        )
        result = slice_of(
            run_dir,
            "t.c",
            "target",
            runner=no_tools,
            work_dir=Path("agents/a1/scratch/work"),
            cppflags="-Iworkspace/work",
        )
        assert by_name(result)["shared_only"]["has_contract"] is True
        assert "requires a > 2;" in result["text"]

    @pytest.mark.parametrize(
        "c_file, function",
        [
            ("t.c", "missing_function"),
            ("t.c", "only_declared"),
            ("nope.c", "target"),
            ("t.c", "not an identifier"),
            ("t.c", ""),
            ("../outside.c", "target"),
            ("/abs/outside.c", "target"),
            ("", "target"),
            (None, "target"),
            ("t.c", None),
        ],
    )
    def test_bad_targets_are_a_status(self, run_dir, c_file, function):
        write_tree(run_dir, {"t.c": "int only_declared(void);\nint target(void) { return 0; }\n"})
        result = fs.build_slice(run_dir, WORK, c_file, function, FLAGS, runner=no_tools)
        assert result["status"] == "not_found"
        assert result["reason"]
        assert result["text"] == ""
        assert result["target"] is None
        json.dumps(result)

    def test_a_file_the_tokenizer_cannot_repair_is_not_found_rather_than_a_crash(self, run_dir, monkeypatch):
        write_tree(run_dir, {"t.c": "int target(void) { return 0; }\n"})
        monkeypatch.setattr(fs, "_tokenize_tolerant", lambda text: (text + "\n'", []))
        result = fs.build_slice(run_dir, WORK, "t.c", "target", FLAGS, runner=no_tools)
        assert result["status"] == "not_found"
        assert "no definition" in result["reason"]

    def test_bad_arguments_never_raise(self, run_dir):
        write_tree(run_dir, {"t.c": "int target(void) { return 0; }\n"})
        result = fs.build_slice(None, WORK, "t.c", "target", FLAGS, runner=no_tools)  # type: ignore[arg-type]
        assert result["status"] == "not_found"
        assert "slice failed" in result["reason"]

    def test_unparsable_cppflags_degrade(self, run_dir):
        write_tree(run_dir, {"t.c": "int target(void) { return 0; }\n"})
        result = fs.build_slice(run_dir, WORK, "t.c", "target", "-I'unbalanced", runner=no_tools)
        assert result["status"] == "degraded"
        assert "unparsable cppflags" in result["reason"]

    def test_unwritable_out_dir_is_reported_not_raised(self, run_dir):
        write_tree(run_dir, {"a.c": STATIC_A})
        blocker = run_dir / "blocker"
        blocker.write_text("x", encoding="utf-8")
        result = slice_of(run_dir, "a.c", "use_a", cpp_like("a.c", STATIC_A), out_dir=blocker / "sub")
        assert result["status"] == "ok"
        assert result["slice_file"] is None
        assert "could not write" in result["reason"]
        assert "use_a" in result["text"]

    def test_dag_style_function_key_is_accepted(self, run_dir):
        write_tree(run_dir, {"a.c": STATIC_A})
        result = slice_of(run_dir, "a.c", "a.c#use_a", cpp_like("a.c", STATIC_A))
        assert result["function"] == "use_a"
        assert result["status"] == "ok"

    def test_workspace_prefix_on_c_file_is_tolerated(self, run_dir):
        write_tree(run_dir, {"a.c": STATIC_A})
        result = slice_of(run_dir, "workspace/work/a.c", "use_a", cpp_like("a.c", STATIC_A))
        assert result["status"] == "ok"
        assert result["file"] == "a.c"

    def test_result_is_json_serializable_with_every_documented_key(self, run_dir):
        write_tree(run_dir, {"a.c": STATIC_A})
        result = slice_of(run_dir, "a.c", "use_a", cpp_like("a.c", STATIC_A))
        json.dumps(result)
        for key in (
            "status",
            "reason",
            "function",
            "file",
            "conditionals",
            "slice_file",
            "callee_bodies_file",
            "text",
            "truncated",
            "target",
            "header_prototype",
            "callees",
            "stats",
        ):
            assert key in result
        assert set(result["stats"]) == {"lines", "macros", "types", "globals", "callees", "logic_decls"}


# ---------------------------------------------------------------------------
# Preprocessor command
# ---------------------------------------------------------------------------

FRAMAC_COMMAND = (
    "gcc -E -C -I. -I'/tmp/__fc_machdepabc.dir' -I'/fc/share/libc' -U__STDC_UTF16__ -D__FRAMAC__ -dD -nostdinc -undef "
    "-imacros __fc_builtin_macros.h -std=c11 -Wno-builtin-macro-redefined -D__FC_SLICE_FLAGS__ "
    "'/run/workspace/work/t.c' -o '/tmp/t.c123.i'"
)
SIMPLE_C = "int target(void) { return 0; }\n"


def framac_runner(calls, *, cpp_rc=0, gcc_text=None):
    def run(cmd, **kwargs):
        calls.append((list(cmd), kwargs))
        if cmd[0] == "frama-c":
            if "-print-cpp-commands" in cmd:
                return _cp(cmd, out=f"[kernel] Preprocessing command:\n  {FRAMAC_COMMAND}\n")
            if "-print-machdep-builtin-macros" in cmd:
                return _cp(cmd, out="#define __FC_BUILTIN 1\n")
            if "-print-machdep-header" in cmd:
                return _cp(cmd, out="#define __FC_MACHDEP 1\n")
            raise AssertionError(cmd)
        if "-nostdinc" in cmd and cpp_rc:
            return _cp(cmd, cpp_rc, err="fatal error: frama-c libc lacks a header\n")
        return _cp(cmd, out=gcc_text if gcc_text is not None else cpp_like("t.c", SIMPLE_C))

    return run


class TestPreprocessorCommand:
    def test_framac_command_is_used_without_comments_or_output_file(self, run_dir):
        write_tree(run_dir, {"t.c": SIMPLE_C})
        calls: list = []
        result = fs.build_slice(
            run_dir, WORK, "t.c", "target", "-Iinc -fplugin=evil.so -DX=1 -include x.h", runner=framac_runner(calls)
        )
        assert result["status"] == "ok"
        assert result["preprocessor"] == "framac"
        assert result["reason"] is None
        probe = next(c for c, _ in calls if "-print-cpp-commands" in c)
        assert "-machdep" in probe and "gcc_x86_64" in probe
        cmd, kwargs = calls[-1]
        assert cmd[:2] == ["gcc", "-E"]
        assert "-C" not in cmd and "-o" not in cmd
        assert "-dD" in cmd and "-nostdinc" in cmd and "-undef" in cmd
        assert cmd[-1] == "workspace/work/t.c"
        assert kwargs["cwd"] == str(run_dir.resolve())
        assert "-Iinc" in cmd and "-DX=1" in cmd
        assert cmd[cmd.index("-include") :].count("x.h") == 1
        assert not any("evil" in word for word in cmd)
        assert fs._FLAGS_SENTINEL not in cmd
        assert not any("__fc_machdepabc" in word for word in cmd)
        machdep_dir = next(word[2:] for word in cmd if "fc_slice_machdep_" in word)
        assert (Path(machdep_dir) / "__fc_builtin_macros.h").read_text(encoding="utf-8") == "#define __FC_BUILTIN 1\n"
        assert (Path(machdep_dir) / "__fc_machdep.h").read_text(encoding="utf-8") == "#define __FC_MACHDEP 1\n"
        assert "Frama-C's preprocessor" in result["text"]

    def test_plain_gcc_is_the_second_step_and_is_recorded(self, run_dir):
        write_tree(run_dir, {"t.c": SIMPLE_C})
        calls: list = []
        result = fs.build_slice(run_dir, WORK, "t.c", "target", "-Iinc", runner=framac_runner(calls, cpp_rc=1))
        assert result["status"] == "ok"
        assert result["conditionals"] == "resolved"
        assert result["preprocessor"] == "gcc"
        assert "frama-c libc lacks a header" in result["reason"]
        assert "plain gcc" in result["reason"]
        cmd, _ = calls[-1]
        assert cmd[:3] == ["gcc", "-E", "-dD"]
        for define in cache.FRAMAC_DEP_DEFINES:
            assert define in cmd
        assert "plain gcc" in result["text"]

    @pytest.mark.parametrize(
        "printed",
        [
            "[kernel] nothing useful\n",
            "[kernel] Preprocessing command:\n  gcc -E -I. '/run/workspace/work/t.c' -o '/tmp/x.i'\n",
            "[kernel] Preprocessing command:\n  gcc -E -D__FC_SLICE_FLAGS__ -o '/tmp/x.i'\n",
            "[kernel] Preprocessing command:\n  gcc -E 'unterminated\n",
        ],
    )
    def test_an_unusable_printed_command_falls_back(self, run_dir, printed):
        write_tree(run_dir, {"t.c": SIMPLE_C})

        def run(cmd, **kwargs):
            if cmd[0] == "frama-c":
                return _cp(cmd, out=printed)
            return _cp(cmd, out=cpp_like("t.c", SIMPLE_C))

        result = fs.build_slice(run_dir, WORK, "t.c", "target", "-I.", runner=run)
        assert result["status"] == "ok"
        assert result["preprocessor"] == "gcc"
        assert "Frama-C preprocessor failed" in result["reason"]

    def test_the_real_tools_template_is_memoized_once_across_threads(self, monkeypatch, tmp_path):
        monkeypatch.setattr(fs, "_framac_templates", {})
        probes = []

        def probe(machdep, source, run_dir, runner):
            probes.append(machdep)
            return ["gcc", "-E", fs._FLAGS_SENTINEL, fs._SOURCE_SLOT]

        monkeypatch.setattr(fs, "_probe_framac_template", probe)
        with ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda _: fs._framac_template("gcc_x86_64", "x.c", tmp_path, None), range(32)))
        assert probes == ["gcc_x86_64"]
        assert all(r == results[0] for r in results)
        fs._framac_template("gcc_x86_32", "x.c", tmp_path, None)
        assert probes == ["gcc_x86_64", "gcc_x86_32"]

    def test_a_stand_in_runner_is_never_memoized(self, monkeypatch, run_dir):
        monkeypatch.setattr(fs, "_framac_templates", {})
        write_tree(run_dir, {"t.c": SIMPLE_C})
        fs.build_slice(run_dir, WORK, "t.c", "target", "-I.", runner=framac_runner([]))
        assert fs._framac_templates == {}

    def test_shared_include_dirs_get_a_snapshot_twin_first(self, run_dir):
        work = run_dir / "agents" / "a1" / "scratch" / "work"
        (work / "inc").mkdir(parents=True)
        (work / "src").mkdir()
        tree = fs._Tree(run_dir.resolve(), work.resolve())
        flags = ["-I.", "-Iworkspace/work/inc", "-I", "workspace/work/src", "-Iworkspace/work/gone", "-DX"]
        assert fs._snapshot_first(flags, tree) == [
            "-I.",
            "-Iagents/a1/scratch/work/inc",
            "-Iworkspace/work/inc",
            "-Iagents/a1/scratch/work/src",
            "-I",
            "workspace/work/src",
            "-Iworkspace/work/gone",
            "-DX",
        ]
        assert fs._snapshot_first(["-Iagents/a1/scratch/work"], tree) == ["-Iagents/a1/scratch/work"]
        same = fs._Tree(run_dir.resolve(), (run_dir / "workspace" / "work").resolve())
        assert fs._snapshot_first(["-Iworkspace/work"], same) == ["-Iworkspace/work"]


# ---------------------------------------------------------------------------
# Scanning and parsing
# ---------------------------------------------------------------------------


def _tokens(code: str):
    return [t for t in tokenize_c_acsl(code) if t.kind in ("c_token", "string")]


class TestParsing:
    @pytest.mark.parametrize(
        "decl, expected",
        [
            ("int x;", {"objects": ["x"]}),
            ("int a, *b, c[3];", {"objects": ["a", "b", "c"]}),
            ("foo_t bar;", {"objects": ["bar"]}),
            ("unsigned x = 3, y;", {"objects": ["x", "y"], "has_init": True}),
            ("typedef unsigned char u8;", {"typedefs": ["u8"]}),
            ("typedef unsigned long size_t;", {"typedefs": ["size_t"]}),
            ("typedef struct { int a; } foo_t, *foo_p;", {"typedefs": ["foo_t", "foo_p"]}),
            ("typedef struct tag { int a; } foo_t;", {"typedefs": ["foo_t"], "tags": ["tag"]}),
            ("typedef struct tag foo_t;", {"typedefs": ["foo_t"], "fwd_tags": ["tag"]}),
            ("typedef int (*cb_t)(int, void *);", {"typedefs": ["cb_t"]}),
            ("typedef int fn_t(int);", {"typedefs": ["fn_t"]}),
            ("typedef int arr_t[4];", {"typedefs": ["arr_t"]}),
            ("int (*fp)(int);", {"objects": ["fp"]}),
            ("foo_t (*fp)(int);", {"objects": ["fp"]}),
            ("int (*tab[3])(void);", {"objects": ["tab"]}),
            ("int (*const fp)(int) = 0;", {"objects": ["fp"], "has_init": True}),
            ("int (*(*pf)(int))[3];", {"objects": ["pf"]}),
            ("int f(void);", {"functions": ["f"]}),
            ("void (*signal(int sig, void (*func)(int)))(int);", {"functions": ["signal"]}),
            ("int (f)(void);", {"functions": ["f"]}),
            ("char *f(void), g;", {"functions": ["f"], "objects": ["g"]}),
            ("int f(void) __attribute__((noreturn));", {"functions": ["f"]}),
            ("__attribute__((noreturn)) void f(void);", {"functions": ["f"]}),
            ('int f(void) __asm__("f2");', {"functions": ["f"]}),
            ("int f(struct s *p, enum e k);", {"functions": ["f"]}),
            (
                "static const struct foo table[] = { {1, 2}, {3, 4} };",
                {"objects": ["table"], "static": True, "has_init": True},
            ),
            (
                "__attribute__((unused)) static int x = 1, y = 2;",
                {"objects": ["x", "y"], "static": True, "has_init": True},
            ),
            ("int __attribute__((aligned(8))) z;", {"objects": ["z"]}),
            ("extern int g;", {"objects": ["g"], "extern": True}),
            ("typeof(int) w;", {"objects": ["w"]}),
            ("_Atomic(int) w;", {"objects": ["w"]}),
            ("__extension__ typedef long long ll_t;", {"typedefs": ["ll_t"]}),
            ("struct foo;", {"fwd_tags": ["foo"]}),
            ("struct foo { int a; };", {"tags": ["foo"]}),
            ("struct foo { int a; } v;", {"tags": ["foo"], "objects": ["v"]}),
            ("struct foo v;", {"objects": ["v"]}),
            ("enum { A, B = 2, C };", {"enumerators": ["A", "B", "C"]}),
            (
                "enum e { A, B = (1, 2) } v = A;",
                {"tags": ["e"], "enumerators": ["A", "B"], "objects": ["v"], "has_init": True},
            ),
            (
                "struct outer { struct inner { int x; } y; enum { K } z; };",
                {"tags": ["outer", "inner"], "enumerators": ["K"]},
            ),
        ],
    )
    def test_declarations(self, decl, expected):
        item = fs._parse_declaration(_tokens(decl)[:-1])
        assert item is not None
        for name in ("functions", "objects", "typedefs", "enumerators", "tags", "fwd_tags"):
            assert getattr(item, name) == expected.get(name, []), name
        for flag in ("static", "extern", "has_init"):
            assert getattr(item, flag) is expected.get(flag, False), flag

    @pytest.mark.parametrize("decl", ["foo_t;", "int;", '_Static_assert(1, "x");', "struct;"])
    def test_statements_that_declare_nothing(self, decl):
        assert fs._parse_declaration(_tokens(decl)[:-1]) is None

    def test_function_definitions_and_linkage_blocks(self):
        code = (
            'extern "C" {\n'
            "int (*get(int a))(void) { return 0; }\n"
            "}\n"
            "__attribute__((noreturn)) static void die(void) __attribute__((cold)) { for (;;) {} }\n"
            "struct pair { int a; } make(void) { struct pair p = {0}; return p; }\n"
            "int table[2] = { 1, 2 };\n"
            "static inline int use(int x) { return get(x)() + other((x)); }\n"
        )
        scan = fs._scan_text(f'# 1 "t.c"\n{code}')
        items = fs._parse_items(scan)
        definitions = {it.functions[0]: it for it in items if it.kind == "def"}
        assert set(definitions) == {"get", "die", "make", "use"}
        assert definitions["die"].static is True
        assert definitions["use"].calls == ["get", "other"]
        assert any(it.objects == ["table"] for it in items)
        assert any(it.tags == ["pair"] for it in items) or definitions["make"]

    def test_scan_maps_lines_through_markers_directives_and_blanks(self):
        text = (
            '# 0 "a.c"\n'
            '# 0 "<built-in>"\n'
            "#define B 1\n"
            '# 1 "a.c"\n'
            "int a;\n"
            "\n"
            "#define M 1\n"
            '# 1 "h.h" 1\n'
            "int h;\n"
            '# 5 "a.c" 2\n'
            "int b; int c;\n"
            "#undef M\n"
            "int d;\n"
        )
        scan = fs._scan_text(text)
        items = fs._parse_items(scan)
        origins = {it.objects[0]: scan.origin(it.start) for it in items}
        assert origins == {"a": ("a.c", 1), "h": ("h.h", 1), "b": ("a.c", 5), "c": ("a.c", 5), "d": ("a.c", 7)}
        assert [(e.is_define, e.file, e.line) for e in scan.macros["M"]] == [(True, "a.c", 3), (False, "a.c", 6)]
        assert scan.macros["B"][0].file == "<built-in>"

    def test_scan_digest_ignores_markers_and_whitespace_but_not_tokens(self):
        base = '# 1 "agents/a1/scratch/work/x.c"\nint a;\nint f(void) { return g(1); }\n'
        shifted = '# 1 "agents/a2/scratch/work/x.c"\n\n\nint a;\n# 90 "agents/a2/scratch/work/x.c"\nint f(void)\n{ return g(1); }\n'
        changed = '# 1 "agents/a1/scratch/work/x.c"\nint a;\nint f(void) { return g(2); }\n'
        assert fs._scan_text(base).digest == fs._scan_text(shifted).digest
        assert fs._scan_text(base).digest != fs._scan_text(changed).digest

    def test_tokenizing_survives_prose_in_inactive_code(self):
        clean, tokens = fs._tokenize_tolerant("#if 0\nit's prose\n#endif\nint a;\n")
        assert [t.text for t in tokens if t.kind == "c_token"] == ["int", "a", ";"]
        assert clean.split("\n")[1] == ""
        _, tokens = fs._tokenize_tolerant("int a; /* never closed\n")
        assert [t.text for t in tokens if t.kind == "c_token"] == ["int", "a", ";"]

    def test_macro_refs_skip_parameters_and_survive_stringify(self):
        event = fs._MacroEvent("M", True, 0, "f", 1, "(a,b)", "#a call(a, OTHER) (b)->member")
        refs, fields = fs._macro_refs(event)
        assert refs == {"call", "OTHER"}
        assert fields == {"member"}

    def test_acsl_refs_skip_builtins_and_see_ranges(self):
        refs, fields = fs._acsl_refs(
            '\\valid(p + (0 .. limit - 1)) && \\forall integer i; p->len == K && s.m == "str_lit"'
        )
        assert {"p", "limit", "integer", "i", "K", "s"} <= refs
        assert "valid" not in refs and "forall" not in refs and "str_lit" not in refs
        assert fields == {"len", "m"}


# ---------------------------------------------------------------------------
# Cached index
# ---------------------------------------------------------------------------

CACHED_C = "#define K 3\nstatic int helper(int x);\nint target(int a)\n{\n    return helper(a) + K;\n}\n"


def _agent_canned(agent: str, shift: int = 0) -> str:
    tree = f"agents/{agent}/scratch/work"
    return (
        f'# 1 "{tree}/c.c"\n#define K 3\nstatic int helper(int x);\n'
        + (f'# {3 + shift} "{tree}/c.c"\n' if shift else "")
        + f'int target(int a)\n{{\n    const char *f = "{tree}/c.c";\n    return helper(a) + 3;\n}}\n'
    )


class TestIndexCache:
    @pytest.fixture
    def cached_run(self, run_dir):
        (run_dir / "run-metadata.json").write_text("{}", encoding="utf-8")
        return run_dir

    def _slice(self, run: Path, agent: str, text: str) -> dict:
        tree = f"agents/{agent}/scratch/work"
        return fs.build_slice(run, Path(tree), "c.c", "target", f"-I{tree} -I.", runner=gcc_runner(text))

    def _entries(self, run: Path) -> list[Path]:
        return list((run / "state" / "cache" / "slice-index").glob("*/*/meta.json"))

    def test_agents_share_one_entry(self, cached_run):
        for agent in ("a1", "a2-long-name"):
            write_tree(cached_run, {"c.c": CACHED_C}, f"agents/{agent}/scratch/work")
        first = self._slice(cached_run, "a1", _agent_canned("a1"))
        second = self._slice(cached_run, "a2-long-name", _agent_canned("a2-long-name"))
        assert first["index_cache"] == "miss"
        assert second["index_cache"] == "hit"
        assert len(self._entries(cached_run)) == 1
        assert second["target"] == first["target"]
        assert second["text"].replace("a2-long-name", "a1") == first["text"]

    def test_an_agent_path_in_a_macro_body_does_not_split_the_entry(self, cached_run):
        for agent in ("a1", "a2"):
            write_tree(cached_run, {"c.c": CACHED_C}, f"agents/{agent}/scratch/work")
            tree = f"agents/{agent}/scratch/work"
            text = f'# 0 "<command-line>"\n#define WHERE "{tree}/c.c"\n{_agent_canned(agent)}'
            result = self._slice(cached_run, agent, text)
        assert result["index_cache"] == "hit"
        assert len(self._entries(cached_run)) == 1

    def test_markers_keep_the_real_origin_after_normalization(self):
        scan = fs._scan_text('# 1 "agents/a1/scratch/work/x.c"\nint a;\n')
        assert scan.files == ["", "agents/a1/scratch/work/x.c"]

    def test_a_hit_does_not_parse_and_acsl_merges_shift_lines_correctly(self, cached_run, monkeypatch):
        write_tree(cached_run, {"c.c": CACHED_C}, "agents/a1/scratch/work")
        self._slice(cached_run, "a1", _agent_canned("a1"))
        merged = (
            "#define K 3\n"
            "/*@ requires x > 0;\n"
            "  @ assigns \\nothing;\n"
            "  @*/\n"
            "static int helper(int x);\n"
            "/*@ requires a > 1; */\n"
            "int target(int a)\n"
            "{\n"
            "    return helper(a) + K;\n"
            "}\n"
        )
        write_tree(cached_run, {"c.c": merged}, "agents/a2/scratch/work")
        canned = (
            '# 1 "agents/a2/scratch/work/c.c"\n#define K 3\n'
            '# 5 "agents/a2/scratch/work/c.c"\nstatic int helper(int x);\n\n'
            'int target(int a)\n{\n    const char *f = "agents/a2/scratch/work/c.c";\n    return helper(a) + 3;\n}\n'
        )

        def explode(scan):
            raise AssertionError("the index must come from the cache")

        monkeypatch.setattr(fs, "_parse_items", explode)
        result = self._slice(cached_run, "a2", canned)
        assert result["status"] == "ok"
        assert result["index_cache"] == "hit"
        assert result["target"] == {"file": "c.c", "start_line": 6, "end_line": 11}
        assert "requires a > 1;" in result["text"]  # the slice text reflects this snapshot
        assert "requires x > 0;" in result["text"]
        assert by_name(result)["helper"]["line"] == 2
        assert len(self._entries(cached_run)) == 1

    def test_new_contracts_appear_though_the_index_is_cached(self, cached_run):
        write_tree(cached_run, {"c.c": CACHED_C}, "agents/a1/scratch/work")
        self._slice(cached_run, "a1", _agent_canned("a1"))
        write_tree(
            cached_run,
            {"c.c": CACHED_C.replace("static int helper", "/*@ requires x > 41; */ static int helper")},
            "agents/a1/scratch/work",
        )
        result = self._slice(cached_run, "a1", _agent_canned("a1"))
        assert result["index_cache"] == "hit"
        assert "requires x > 41;" in result["text"]

    def test_changed_c_code_misses(self, cached_run):
        write_tree(cached_run, {"c.c": CACHED_C}, "agents/a1/scratch/work")
        self._slice(cached_run, "a1", _agent_canned("a1"))
        result = self._slice(cached_run, "a1", _agent_canned("a1").replace("+ 3", "+ 4"))
        assert result["index_cache"] == "miss"
        assert len(self._entries(cached_run)) == 2

    def test_cache_off_outside_a_run_and_when_forced(self, run_dir, monkeypatch):
        write_tree(run_dir, {"c.c": CACHED_C}, "agents/a1/scratch/work")
        assert self._slice(run_dir, "a1", _agent_canned("a1"))["index_cache"] == "off"
        assert not (run_dir / "state").exists()
        (run_dir / "run-metadata.json").write_text("{}", encoding="utf-8")
        monkeypatch.setenv("FRAMAC_CACHE", "off")
        assert self._slice(run_dir, "a1", _agent_canned("a1"))["index_cache"] == "off"
        assert not (run_dir / "state").exists()

    def test_read_only_store_and_corrupt_entries_only_cost_a_parse(self, cached_run):
        write_tree(cached_run, {"c.c": CACHED_C}, "agents/a1/scratch/work")
        (cached_run / "state").write_text("not a directory", encoding="utf-8")
        result = self._slice(cached_run, "a1", _agent_canned("a1"))
        assert result["status"] == "ok" and result["index_cache"] == "miss"
        (cached_run / "state").unlink()
        self._slice(cached_run, "a1", _agent_canned("a1"))
        index = next((cached_run / "state" / "cache" / "slice-index").rglob("index.json"))
        index.write_text("{broken", encoding="utf-8")
        again = self._slice(cached_run, "a1", _agent_canned("a1"))
        assert again["status"] == "ok" and again["index_cache"] == "miss"
        assert "helper" in by_name(again)

    def test_concurrent_provers_get_the_same_answer(self, cached_run):
        agents = [f"p{i}" for i in range(8)]
        for agent in agents:
            write_tree(cached_run, {"c.c": CACHED_C}, f"agents/{agent}/scratch/work")
        cwd = os.getcwd()
        with ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda a: self._slice(cached_run, a, _agent_canned(a)), agents))
        assert os.getcwd() == cwd
        assert {r["status"] for r in results} == {"ok"}
        assert {json.dumps(r["target"]) for r in results} == {json.dumps(results[0]["target"])}
        assert len(self._entries(cached_run)) == 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCli:
    def test_prints_json_without_text(self, run_dir, capsys):
        write_tree(run_dir, {"a.c": STATIC_A})
        dag = run_dir / "dag.json"
        dag.write_text(json.dumps({"functions": {"helper": {"file": "b.c"}}}), encoding="utf-8")
        code = fs.main(
            [
                "--run-dir",
                str(run_dir),
                "--work-dir",
                "workspace/work",
                "--file",
                "a.c",
                "--function",
                "use_a",
                "--cppflags",
                "-I.",
                "--out-dir",
                "out",
                "--dag",
                "dag.json",
                "--max-inline-lines",
                "100",
            ]
        )
        result = json.loads(capsys.readouterr().out)
        assert code == 0
        assert "text" not in result
        assert result["status"] in ("ok", "degraded")
        assert result["slice_file"] == "out/use_a.slice.c"
        assert (run_dir / "out" / "use_a.slice.c").is_file()

    def test_a_broken_dag_file_only_means_no_dag(self, run_dir, capsys):
        write_tree(run_dir, {"a.c": STATIC_A})
        (run_dir / "dag.json").write_text("{broken", encoding="utf-8")
        args = ["--run-dir", str(run_dir), "--work-dir", "workspace/work", "--file", "a.c", "--function", "use_a"]
        assert fs.main([*args, "--dag", "dag.json", "--cppflags=-I."]) == 0
        assert json.loads(capsys.readouterr().out)["status"] in ("ok", "degraded")

    def test_not_found_exits_non_zero(self, run_dir, capsys):
        write_tree(run_dir, {"a.c": STATIC_A})
        code = fs.main(
            [
                "--run-dir",
                str(run_dir),
                "--work-dir",
                "workspace/work",
                "--file",
                "a.c",
                "--function",
                "nope",
                "--cppflags=-I.",
            ]
        )
        assert code == 1
        assert json.loads(capsys.readouterr().out)["status"] == "not_found"


# ---------------------------------------------------------------------------
# Real tools
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_GCC, reason="needs gcc")
class TestRealGcc:
    def test_active_branch_with_real_gcc(self, run_dir):
        write_tree(run_dir, {"cfg.c": BRANCHES_C, "cfg.h": BRANCHES_H})
        result = fs.build_slice(run_dir, WORK, "cfg.c", "compute", FLAGS, runner=real_gcc_only)
        _assert_else_branch(result)
        assert result["preprocessor"] == "gcc"

    def test_a_define_on_the_flags_flips_the_branch(self, run_dir):
        write_tree(run_dir, {"cfg.c": BRANCHES_C, "cfg.h": BRANCHES_H})
        result = fs.build_slice(run_dir, WORK, "cfg.c", "compute", f"{FLAGS} -DUSE_WIDE", runner=real_gcc_only)
        assert "typedef long value_t;" in result["text"]
        assert "typedef short value_t;" not in result["text"]
        assert by_name(result)["scale"]["line"] == 5

    def test_multi_line_macro_call_and_shifted_lines_with_real_gcc(self, run_dir):
        comment = "\n".join(f"/* filler {i} */" for i in range(20))
        source = (
            "#define MAKE(a, b) { a, b }\n"
            "static const int pair[2] = MAKE(\n"
            "    1,\n"
            "    2);\n"
            f"{comment}\n"
            "/*@ assigns \\nothing;\n"
            "  @ ensures \\result == 1; */\n"
            "int target(void)\n"
            "{\n"
            "    return pair[0];\n"
            "}\n"
        )
        write_tree(run_dir, {"e.c": source})
        result = fs.build_slice(run_dir, WORK, "e.c", "target", FLAGS, runner=real_gcc_only)
        assert "/* e.c:2-4 */" in result["text"]
        assert result["target"] == {"file": "e.c", "start_line": 25, "end_line": 30}
        assert "ensures \\result == 1;" in result["text"]

    def test_flags_naming_the_shared_tree_still_read_the_snapshot(self, run_dir):
        write_tree(run_dir, {"inc/x.h": "int callee(int a);\n"})
        write_tree(
            run_dir,
            {
                "inc/x.h": "/* added\n   lines */\n/*@ requires a > 6; */\nint callee(int a);\n",
                "src/t.c": "#include <x.h>\nint target(int a) { return callee(a); }\n",
            },
            "agents/a1/scratch/work",
        )
        result = fs.build_slice(
            run_dir,
            Path("agents/a1/scratch/work"),
            "src/t.c",
            "target",
            "-Iagents/a1/scratch/work -I. -Iworkspace/work/inc",
            runner=real_gcc_only,
        )
        assert by_name(result)["callee"] == {
            "name": "callee",
            "file": "inc/x.h",
            "line": 3,
            "has_contract": True,
            "kind": "in_tree",
        }
        assert "requires a > 6;" in result["text"]

    def test_a_target_defined_in_a_header_preprocesses_that_header(self, run_dir):
        header = "#define STEP 2\n/*@ assigns \\nothing; */\nstatic inline int next_of(int a) { return a + STEP; }\n"
        write_tree(run_dir, {"inline.h": header})
        result = fs.build_slice(run_dir, WORK, "inline.h", "next_of", FLAGS, runner=real_gcc_only)
        assert result["status"] == "ok"
        assert result["target"] == {"file": "inline.h", "start_line": 2, "end_line": 3}
        assert "#define STEP 2" in result["text"]

    def test_macro_events_in_a_body_and_a_macro_hidden_callee_with_real_gcc(self, run_dir):
        source = (
            "int hidden(int x);\n"
            "#define CALL(v) hidden(v)\n"
            "int target(int a)\n"
            "{\n"
            "#define LOCAL_M(x) CALL(x)\n"
            "    return LOCAL_M(a);\n"
            "#undef LOCAL_M\n"
            "}\n"
        )
        write_tree(run_dir, {"m.c": source})
        result = fs.build_slice(run_dir, WORK, "m.c", "target", FLAGS, runner=real_gcc_only)
        assert "hidden" in by_name(result)
        assert "#define CALL(v) hidden(v)" in result["text"]
        assert result["text"].count("#define LOCAL_M") == 1

    def test_slice_compiles_with_only_the_libc_headers_added(self, run_dir):
        header = (
            "#include <stddef.h>\n"
            "typedef struct { const char *p; size_t n; } view_t;\n"
            "enum kind { K_A, K_B };\n"
            "#define MAX_LEN 16\n"
            "/*@ requires v != \\null; */\n"
            "int view_kind(const view_t *v);\n"
            "int view_unused(const view_t *v);\n"
        )
        source = (
            '#include <string.h>\n#include "v.h"\n'
            "static const int weights[2] = {1, 2};\n"
            "#define WEIGHT(k) weights[k]\n"
            "int target(const view_t *v, char *out)\n"
            "{\n"
            "    if (v->n > MAX_LEN) return K_B;\n"
            "    memcpy(out, v->p, v->n);\n"
            "    return view_kind(v) + WEIGHT(K_A);\n"
            "}\n"
        )
        write_tree(run_dir, {"v.h": header, "t.c": source})
        result = fs.build_slice(run_dir, WORK, "t.c", "target", FLAGS, runner=real_gcc_only, out_dir=run_dir / "o")
        assert "view_unused" not in result["text"]
        probe = run_dir / "probe.c"
        probe.write_text(f"#include <stddef.h>\n#include <string.h>\n{result['text']}", encoding="utf-8")
        proc = subprocess.run(["gcc", "-fsyntax-only", "-w", str(probe)], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr


@pytest.mark.skipif(not HAS_FRAMAC or not HAS_GCC, reason="needs frama-c and gcc")
class TestRealFramaC:
    def test_framac_view_of_the_conditionals(self, run_dir):
        source = (
            "#include <stdint.h>\n"
            "#ifdef __FRAMAC__\n"
            "typedef uint8_t fc_view_t;\n"
            "#else\n"
            "typedef uint32_t host_view_t;\n"
            "#endif\n"
            "#if __SIZEOF_POINTER__ == 8\n"
            "#define PTR_KIND 64\n"
            "#else\n"
            "#define PTR_KIND 0\n"
            "#endif\n"
            "int target(fc_view_t v) { return v + PTR_KIND; }\n"
        )
        write_tree(run_dir, {"t.c": source})
        result = fs.build_slice(run_dir, WORK, "t.c", "target", FLAGS, out_dir=run_dir / "o")
        assert result["status"] == "ok"
        assert result["preprocessor"] == "framac"
        assert result["reason"] is None
        assert "typedef uint8_t fc_view_t;" in result["text"]
        assert "host_view_t" not in result["text"]
        assert "#define PTR_KIND 64" in result["text"]
        assert "typedef unsigned" not in result["text"]  # libc stays out

    def test_libc_callee_reports_frama_c_contract(self, run_dir):
        source = "#include <string.h>\nvoid target(char *d, const char *s) { memcpy(d, s, 1); }\n"
        write_tree(run_dir, {"t.c": source})
        result = fs.build_slice(run_dir, WORK, "t.c", "target", FLAGS)
        info = by_name(result)["memcpy"]
        assert info["kind"] == "libc_or_external"
        assert info["has_contract"] is True
        assert info["file"].endswith("libc/string.h")
