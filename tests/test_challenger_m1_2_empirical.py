"""
Adversarial empirical stress-tests for Milestone M1 (AST Foundations & Stubs).
Author: challenger_m1_2 (Challenger 2)

Empirically challenges and stress-tests:
1. `c_definitions.returns_void`, `c_definitions.return_type_tokens`, `stub_check.parse_proto`
   - Malformed/unusual prototypes, attributes, paren groupings, pointer returns, qualifiers.
2. `stub_check.struct_members`, `stub_check.check_shipped_layout`
   - Complex struct definitions, multi-declarators, function pointers, bitfields, macro members, unclosed syntax,
     and layout bypass vulnerabilities on attribute-tagged structs.
3. `frame_skeleton._classify_offset`, `frame_skeleton._offset_expr`, `frame_skeleton.compute`
   - Multi-dimensional/nested subscripts `p[a[b[i]]].m[j]`, complex loop guards with reversed operators,
     parenthesized conjuncts, non-atomic bounds, bitwise shifts.
4. `function_facts._temp_pattern`, `function_facts._link_callers`, `function_facts._render_callers`
   - User variable shadowing (`tmp`, `tmp_1`, `__retres`), compiler temp filtering, legacy caller linking.
"""

from __future__ import annotations

import pytest

import c_definitions
import frame_skeleton
import function_facts
import stub_check
from acsl_ast import AcslSyntaxError

pytestmark = pytest.mark.unit


# ===========================================================================
# 1. Adversarial Prototypes and Void Returns (B12 & S3)
# ===========================================================================


class TestAdversarialPrototypesAndVoidReturns:
    """Stress-test prototype declarator resolution, void return detection, and parameter extraction."""

    @pytest.mark.parametrize(
        ("proto", "expected_void"),
        [
            # Standard functions returning void
            ("void f(void);", True),
            ("void f();", True),
            ("void f(int x);", True),
            ("void f(int a, char const *b);", True),
            ("extern void f(void);", True),
            ("static void f(void);", True),
            ("inline void f(void);", True),
            ("__inline void f(void);", True),
            ("__inline__ void f(void);", True),
            ("_Noreturn void f(void);", True),
            ("__extension__ void f(void);", True),
            ("register void f(void);", True),
            ("const void f(void);", True),
            ("volatile void f(void);", True),
            ("__const void f(void);", True),
            ("__volatile__ void f(void);", True),
            # Attributes in various positions
            ("__attribute__((__noreturn__)) void f(void);", True),
            ("void __attribute__((__cdecl__)) f(void);", True),
            ("void f(void) __attribute__((__noreturn__));", True),
            ("__attribute__((__noreturn__, __leaf__)) void f(int);", True),
            ("void f(int) __attribute__((alias('target')));", True),
            ("__attribute__((format(printf, 1, 2))) void log_fn(const char *fmt, ...);", True),
            ("__declspec(noreturn) void f(void);", True),
            ("asm('my_f') void f(void);", True),
            # Parenthesized declarators
            ("void (f)(void);", True),
            ("void ( __attribute__((__noreturn__)) f)(void);", True),
            # Non-void returns
            ("int f(void);", False),
            ("char *f(void);", False),
            ("void *f(void);", False),
            ("void **f(void);", False),
            ("void * const f(void);", False),
            ("const char *f(void);", False),
            ("void const *f(void);", False),
            ("unsigned int f(void);", False),
            ("struct stat f(void);", False),
            ("union u f(void);", False),
            ("size_t f(void);", False),
            ("uint64_t f(void);", False),
            ("void (*f(int))(void);", False),  # returns function pointer
            ("void (*signal(int sig, void (*func)(int)))(int);", False),
            # Typedef with pointer return -> prefix contains '*', evaluated as non-void (False)
            ("typedef void (*fn_t)(void);", False),
            # Variadic functions returning non-void
            ("int printf(const char *fmt, ...);", False),
            # Invalid/non-prototype syntax -> fail closed (None)
            ("", None),
            ("   ", None),
            ("void", None),
            ("int", None),
            ("void f", None),
            ("void f;", None),
            ("void f(;", None),
            ("void f);", None),
            ("void f(int;", None),
            ("void (void);", None),
            ("123", None),
            ("int (*f(void))[10];", None),  # returns pointer to array: trailing bracket syntax
        ],
    )
    def test_returns_void_adversarial_matrix(self, proto: str, expected_void: bool | None):
        res = c_definitions.returns_void(proto)
        assert res is expected_void, f"returns_void failed on {proto!r}: got {res}, expected {expected_void}"

    def test_returns_void_redundant_parentheses(self):
        # ISO C allows direct-declarator to be wrapped in arbitrary parentheses ((f))
        assert c_definitions.returns_void("void ((f))(void);") is True

    def test_prototype_with_multiple_chained_attributes(self):
        proto = "__attribute__((nothrow)) __attribute__((leaf)) void __attribute__((cdecl)) multi_attr(int x) __attribute__((nonnull));"
        assert c_definitions.returns_void(proto) is True
        sig = stub_check.parse_proto(proto)
        assert sig is not None
        assert sig["name"] == "multi_attr"
        assert sig["returns_void"] is True
        assert len(sig["params"]) == 1
        assert sig["params"][0]["name"] == "x"

    def test_parse_proto_handles_unusual_params(self):
        # Array parameters with dimensions
        proto = "void process_buf(char buf[64], int len);"
        sig = stub_check.parse_proto(proto)
        assert sig is not None
        assert sig["name"] == "process_buf"
        assert sig["params"][0]["name"] == "buf"
        assert sig["params"][0]["array"] == 64
        assert sig["params"][0]["type"] == "char *"
        assert sig["params"][1]["name"] == "len"

        # Unnamed pointer parameters
        proto = "void clear_mem(void *, size_t);"
        sig = stub_check.parse_proto(proto)
        assert sig is not None
        assert sig["params"][0]["name"] == "a0"
        assert sig["params"][0]["type"] == "void *"
        assert sig["params"][1]["name"] == "a1"
        assert sig["params"][1]["type"] == "size_t"

        # Variadic functions cannot be called generically -> None
        assert stub_check.parse_proto("void log_msg(const char *fmt, ...);") is None

        # Function pointer returns cannot be called generically -> None
        assert stub_check.parse_proto("void (*get_handler(int id))(void);") is None

        # Function pointer parameter cannot be called generically -> None
        assert stub_check.parse_proto("void reg_cb(void (*cb)(int));") is None


# ===========================================================================
# 2. Adversarial Struct Members and Fail-Closed Layout (B12 & S3)
# ===========================================================================


class TestAdversarialStructMembersAndLayout:
    """Stress-test struct_members parsing across declarator varieties and syntax failure modes."""

    def test_multiple_declarators_in_single_statement(self):
        text = """
        struct multi {
            int a, b, c;
            char *p, *q, r;
            unsigned int x, y[10], *z;
        };
        """
        members = stub_check.struct_members(text)
        assert "multi" in members
        assert members["multi"] == ["a", "b", "c", "p", "q", "r", "x", "y", "z"]

    def test_function_pointer_members_and_arrays_of_function_pointers(self):
        text = """
        struct ops {
            void (*init)(void);
            int (*read)(char *buf, int len);
            void (*callbacks[8])(int event);
            int (**dyn_handlers)(void);
        };
        """
        members = stub_check.struct_members(text)
        assert "ops" in members
        assert members["ops"] == ["init", "read", "callbacks", "dyn_handlers"]

    def test_bitfields_omitted_while_adjacent_members_retained(self):
        # Bit-fields must be omitted (offsetof cannot take bit-field address)
        text = """
        struct flags {
            unsigned int is_set: 1;
            unsigned int mode: 3;
            unsigned int : 4; /* anonymous padding bitfield */
            int regular_field;
            unsigned int a: 2, b: 2, non_bitfield;
        };
        """
        members = stub_check.struct_members(text)
        assert "flags" in members
        assert "regular_field" in members["flags"]
        assert "is_set" not in members["flags"]
        assert "mode" not in members["flags"]
        assert "a" not in members["flags"]
        assert "b" not in members["flags"]
        assert "non_bitfield" in members["flags"]

    def test_nested_structs_unions_and_member_macros(self):
        text = """
        struct parent {
            int top;
            union {
                int raw;
                struct {
                    short lo;
                    short hi;
                } parts;
            } data;
            #define p_lo data.parts.lo
            #define p_hi data.parts.hi
            int bottom;
        };
        """
        members = stub_check.struct_members(text)
        assert "parent" in members
        expected = ["top", "data", "p_lo", "p_hi", "bottom"]
        assert members["parent"] == expected

    def test_struct_with_member_attributes_and_qualifiers(self):
        text = """
        struct member_attrs {
            const int id;
            volatile char state;
            char * __restrict buffer;
            int normal __attribute__((aligned(4)));
        };
        """
        members = stub_check.struct_members(text)
        assert "member_attrs" in members
        assert members["member_attrs"] == ["id", "state", "buffer", "normal"]

    def test_vulnerability_struct_level_attribute_drops_struct_and_bypasses_layout_check(self, tmp_path):
        text = "struct __attribute__((packed)) packed_s { int id; };"
        members = stub_check.struct_members(text)
        assert "packed_s" in members
        assert members == {"packed_s": ["id"]}
        res = stub_check.check_shipped_layout("header.h", text, tmp_path, [], tmp_path)
        assert res.get("structs") != 0

    def test_struct_level_attributes_should_be_parsed(self):
        text = "struct __attribute__((packed)) packed_s { int id; };"
        members = stub_check.struct_members(text)
        assert "packed_s" in members
        assert members["packed_s"] == ["id"]

    def test_fail_closed_on_unclosed_literals_and_comments(self, tmp_path):
        bad_text = "struct broken { int x; char *s = \"unclosed string; };"
        with pytest.raises(AcslSyntaxError):
            stub_check.struct_members(bad_text)
        res = stub_check.check_shipped_layout("bad.h", bad_text, tmp_path, [], tmp_path)
        assert res["status"] == "error"
        assert "does not tokenize" in res["reason"]

    def test_unclosed_struct_brace_returns_empty_or_handles_gracefully(self):
        # A header with an unclosed struct '{' (syntax error in C)
        text = "struct unclosed { int x; int y;"
        members = stub_check.struct_members(text)
        # Because the brace never closes, 'unclosed' is not a completed struct definition
        assert "unclosed" not in members


# ===========================================================================
# 3. Adversarial Loop Bounds, Guards, and Nested Subscripts (C8)
# ===========================================================================


class TestAdversarialLoopBoundsAndNestedSubscripts:
    """Stress-test _offset_expr bracket matching and _classify_offset guard parsing."""

    @pytest.mark.parametrize(
        ("lval", "root", "expected_kind", "expected_expr"),
        [
            ("p", "p", "zero", "0"),
            ("*p", "p", "zero", "0"),
            ("*(p)", "p", "zero", "0"),
            ("p->f", "p", "zero", "0"),
            ("(*p).f", "p", "zero", "0"),
            ("*(p + 4)", "p", "expr", "4"),
            ("*(p + i)", "p", "expr", "i"),
            ("p[i]", "p", "expr", "i"),
            ("p[42]", "p", "expr", "42"),
            # Nested bracket groups
            ("p[a[i]]", "p", "expr", "a[i]"),
            ("p[a[b[i]]]", "p", "expr", "a[b[i]]"),
            ("p[a[b[i]]].m[j]", "p", "expr", "a[b[i]]"),
            ("p[matrix[row][col]]", "p", "expr", "matrix[row][col]"),
            ("p[(i + 1)]", "p", "expr", "(i + 1)"),
            ("p[x * 2 + y]", "p", "expr", "x * 2 + y"),
            # Not rooted at p
            ("q[i]", "p", None, None),
            ("other->p[i]", "p", None, None),
        ],
    )
    def test_offset_expr_bracket_group_robustness(
        self, lval: str, root: str, expected_kind: str | None, expected_expr: str | None
    ):
        res = frame_skeleton._offset_expr(lval, root)
        if expected_kind is None:
            assert res is None, f"Expected None for {lval!r} rooted at {root!r}, got {res}"
        else:
            assert res is not None, f"Expected non-None for {lval!r} rooted at {root!r}"
            kind, val = res
            assert kind == expected_kind
            assert val == expected_expr

    def test_offset_expr_unbalanced_brackets_fails_closed(self):
        assert frame_skeleton._offset_expr("p[a[b[i]", "p") is None
        assert frame_skeleton._offset_expr("p[unclosed", "p") is None

    @pytest.mark.parametrize(
        ("guard", "var", "expected_bound", "expected_inclusive"),
        [
            # Standard forward bounds
            ("i < n", "i", "n", False),
            ("i <= n", "i", "n", True),
            ("i < 100", "i", "100", False),
            ("i <= 100u", "i", "100u", True),  # Keeps literal format as written in source
            # Cast on lhs
            ("(unsigned int)i < n", "i", "n", False),
            ("(size_t) i <= max_len", "i", "max_len", True),
            # Parenthesized expressions
            ("((i < n))", "i", "n", False),
            ("(((i <= n)))", "i", "n", True),
            # Reversed relations
            ("n > i", "i", "n", False),
            ("n >= i", "i", "n", True),
            ("100 > i", "i", "100", False),
            ("100 >= i", "i", "100", True),
            ("(n > i)", "i", "n", False),
            ("((n >= i))", "i", "n", True),
            # Multi-conjunct guards (e.g. lower bound + upper bound)
            ("i >= 0 && i < n", "i", "n", False),
            ("0 <= i && n > i", "i", "n", False),
            ("p != 0 && (i < n) && flag", "i", "n", False),
            ("valid && (n >= i)", "i", "n", True),
        ],
    )
    def test_classify_offset_extracts_bounds_accurately(
        self, guard: str, var: str, expected_bound: str, expected_inclusive: bool
    ):
        loops = [{"scalars": [{"var": var}], "guard": guard}]
        kind, val = frame_skeleton._classify_offset(var, loops)
        assert kind == "range"
        assert val == (expected_bound, expected_inclusive)

    @pytest.mark.parametrize(
        ("guard", "var"),
        [
            # Disjunction in guard -> must fail closed to unknown
            ("i < n || flag", "i"),
            ("flag || i < n", "i"),
            # Non-atomic upper bound
            ("i < n - 1", "i"),
            ("i < s->len", "i"),
            ("i < n * 2", "i"),
            ("i < a[j]", "i"),
            # Reversed non-atomic bound
            ("n - 1 > i", "i"),
            ("s->len >= i", "i"),
            # Bitwise operations
            ("i << 2 < n", "i"),
            # Equality guards
            ("i != n", "i"),
            ("i == n", "i"),
            # Unrelated variable
            ("j < n", "i"),
            ("", "i"),
        ],
    )
    def test_classify_offset_fails_closed_to_unknown(self, guard: str, var: str):
        loops = [{"scalars": [{"var": var}], "guard": guard}]
        kind, val = frame_skeleton._classify_offset(var, loops)
        assert kind == "unknown"
        assert val is None


# ===========================================================================
# 4. Adversarial Compiler Temp Filtering and Caller Conditions (B9)
# ===========================================================================


class TestAdversarialCompilerTempsAndCallerLinking:
    """Stress-test compiler temporary filtering, user variable shadowing, and caller linking."""

    def test_temp_pattern_compilation(self):
        # When temps is None -> fallback _TEMP_RE matching tmp, tmp_1, __retres
        p_none = function_facts._temp_pattern(None)
        assert p_none.search("tmp")
        assert p_none.search("tmp_1")
        assert p_none.search("__retres")
        assert not p_none.search("attempt")

        # When temps is empty list -> matches nothing (never matches)
        p_empty = function_facts._temp_pattern([])
        assert not p_empty.search("tmp")
        assert not p_empty.search("tmp_1")
        assert not p_empty.search("__retres")

        # When temps has explicit Cil temporaries -> matches ONLY those
        p_explicit = function_facts._temp_pattern(["tmp_3", "tmp_4"])
        assert p_explicit.search("tmp_3")
        assert p_explicit.search("tmp_4")
        assert not p_explicit.search("tmp")  # user 'tmp' preserved!
        assert not p_explicit.search("tmp_1")  # user 'tmp_1' preserved!
        assert not p_explicit.search("__retres")  # user '__retres' preserved!

    def test_user_shadowing_compiler_temps_is_preserved_in_function_record(self):
        # A function with user variables named 'tmp', 'tmp_1', '__retres'
        # AST dump has "temps": ["tmp_99"] (only tmp_99 is a compiler temp)
        raw = {
            "name": "user_fn",
            "kernel_name": "user_fn",
            "loc": "file.c:10",
            "temps": ["tmp_99"],
            "formals": [{"name": "tmp", "kind": "scalar"}],
            "writes": [
                {
                    "lval": "tmp",
                    "base": "tmp",
                    "base_kind": "local",
                    "through_pointer": False,
                    "values": ["tmp + 1"],
                    "loc": "file.c:12",
                },
                {
                    "lval": "tmp_99",
                    "base": "tmp_99",
                    "base_kind": "local",
                    "through_pointer": False,
                    "values": ["42"],
                    "loc": "file.c:13",
                },
            ],
            "reads": [
                {"lval": "tmp_1", "base": "tmp_1", "base_kind": "local", "loc": "file.c:14"},
                {"lval": "tmp_99", "base": "tmp_99", "base_kind": "local", "loc": "file.c:15"},
            ],
            "loops": [],
            "return_paths": [
                {"value": "__retres", "conditions": ["tmp > 0", "tmp_99 != 0"], "loc": "file.c:16"}
            ],
        }
        rec = function_facts._function_record(
            raw,
            file="file.c",
            text="void user_fn(int tmp) { }",
            cycle=None,
            by_kernel={},
            flows={"status": "unavailable"},
            spans={},
        )
        assert rec["kernel_temps"] == ["tmp_99"]
        # In return_paths: 'tmp > 0' and '__retres' should be PRESERVED, while 'tmp_99 != 0' is FILTERED!
        assert len(rec["return_paths"]) == 1
        path = rec["return_paths"][0]
        assert path["value"] == "__retres"
        assert path["conditions"] == ["tmp > 0"]  # tmp_99 != 0 was filtered!

    def test_caller_conditions_linking_filters_by_caller_temps(self):
        caller_raw = {
            "kernel_name": "caller_fn",
            "name": "caller_fn",
            "loc": "c.c:1",
            "temps": ["tmp_42"],  # caller's only compiler temp
            "calls": [
                {
                    "callee": "callee_fn",
                    "kernel_name": "callee_fn",
                    "indirect": False,
                    "args": ["tmp", "tmp_1"],
                    "conditions": ["tmp > 0", "tmp_1 != 0", "tmp_42 == 1"],
                    "loc": "c.c:5",
                    "in_loop": False,
                }
            ],
        }
        callee_raw = {"kernel_name": "callee_fn", "name": "callee_fn", "loc": "c.c:20"}
        records: dict[str, dict] = {
            "c.c#callee_fn": {"kernel_name": "callee_fn", "name": "callee_fn", "called_by": []}
        }
        function_facts._link_callers([caller_raw, callee_raw], records)
        called_by = records["c.c#callee_fn"]["called_by"]
        assert len(called_by) == 1
        # 'tmp > 0' and 'tmp_1 != 0' are caller user variables and must be kept.
        # 'tmp_42 == 1' is caller compiler temporary and must be filtered.
        assert called_by[0]["conditions"] == ["tmp > 0", "tmp_1 != 0"]

        # Render caller brief
        lines: list[str] = []
        function_facts._render_callers(records["c.c#callee_fn"], lines)
        assert any("when `tmp > 0 && tmp_1 != 0`" in line for line in lines)
        assert not any("tmp_42" in line for line in lines)

    def test_legacy_caller_conditions_fallback_behavior(self):
        # When a caller record comes from an older schema without 'in_loop':
        legacy_rec = {
            "name": "target_fn",
            "called_by": [
                {"caller": "old_caller", "args": ["a"], "conditions": ["tmp > 0", "a > 0"]}
            ],
        }
        lines: list[str] = []
        function_facts._render_callers(legacy_rec, lines)
        # Because 'in_loop' is not in item, it falls back to _TEMP_RE, stripping 'tmp > 0'
        assert any("when `a > 0`" in line for line in lines)
        assert not any("tmp > 0" in line for line in lines)

    def test_vulnerability_caller_conditions_leak_temps_when_caller_temps_is_none(self):
        """
        When an AST dump has no 'temps' key (caller_temps is None), _link_callers falls back
        to _temp_pattern(None) (which returns _TEMP_RE).
        Compiler temporary conditions like 'tmp_1 > 0' are filtered, while user conditions
        like 'user_var > 0' are preserved.
        """
        caller_no_temps = {
            "kernel_name": "legacy_caller",
            "name": "legacy_caller",
            "loc": "legacy.c:1",
            # No "temps" key
            "calls": [
                {
                    "callee": "target",
                    "kernel_name": "target",
                    "indirect": False,
                    "args": [],
                    "conditions": ["tmp_1 > 0", "user_var > 0"],
                    "loc": "legacy.c:5",
                    "in_loop": False,
                }
            ],
        }
        callee = {"kernel_name": "target", "name": "target", "loc": "legacy.c:10"}
        records: dict[str, dict] = {"legacy.c#target": {"kernel_name": "target", "name": "target", "called_by": []}}
        function_facts._link_callers([caller_no_temps, callee], records)

        # 'tmp_1 > 0' is filtered out; user_var > 0 is preserved
        assert "tmp_1 > 0" not in records["legacy.c#target"]["called_by"][0]["conditions"]
        assert records["legacy.c#target"]["called_by"][0]["conditions"] == ["user_var > 0"]

        lines: list[str] = []
        function_facts._render_callers(records["legacy.c#target"], lines)
        # Caller brief does not render the compiler temporary
        assert not any("tmp_1 > 0" in line for line in lines)
        assert any("user_var > 0" in line for line in lines)
