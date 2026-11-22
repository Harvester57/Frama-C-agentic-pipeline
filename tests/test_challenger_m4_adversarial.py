"""
Adversarial empirical stress tests for Milestone M4 hardening (Workstream R2).
Author: challenger_m4_2

Empirical verification of:
- D7: Multi-dimensional array and pointer parameter declarations (generate_harness.py)
- D8: Predicate label stripping and precompiled alarm kind detection (fingerprint.py)
- B5: Formal parameter signature extraction and model fallback (generate_harness.py)
- B7: Main definition detection in comments, literals, multiline, macros (pipeline_make.py, generate_harness.py)
- B8: Harness sidecar dispatch case count schema validation and consumer fallback (schemas/harness_sidecar.schema.json, run_eacsl_fuzz.py, seed_harvest.py)
- B11: Clang AST callee extraction, recursive calls, function pointers, and token fallback (harness_reach.py)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import fingerprint as fp
import generate_harness as gh
import harness_reach as hr
import pipeline_make as pm
import run_eacsl_fuzz as rf
from minischema import validate

# ===========================================================================
# 1. D7: Multi-dimensional array and array pointer parameter declarations
# ===========================================================================


class TestD7MultiDimensionalArraysAndPointers:
    """Stress-test C parameter parsing and declaration formatting for multi-dimensional arrays and pointers."""

    def test_deep_multidim_array_3d(self):
        """Test int a[2][3][4] decays to pointer to sub-array int (*)[3][4]."""
        p = gh._parse_c_param("int a[2][3][4]", 0)
        assert p["name"] == "a"
        assert p["is_pointer"] is True
        assert p["is_fn_pointer"] is False
        assert p["is_const"] is False
        assert p["type"] == "int (*)[3][4]"
        assert p["pointee_type"] == "int [3][4]"
        formatted = gh._format_c_decl(p["pointee_type"], p["name"])
        assert formatted == "int a[3][4];"

    def test_deep_multidim_array_4d(self):
        """Test 4D array double arr[2][3][4][5]."""
        p = gh._parse_c_param("double arr[2][3][4][5]", 0)
        assert p["name"] == "arr"
        assert p["is_pointer"] is True
        assert p["type"] == "double (*)[3][4][5]"
        assert p["pointee_type"] == "double [3][4][5]"
        formatted = gh._format_c_decl(p["pointee_type"], p["name"])
        assert formatted == "double arr[3][4][5];"

    def test_array_pointer_multidim(self):
        """Test pointer to 2D array char (*p)[10][20]."""
        p = gh._parse_c_param("char (*p)[10][20]", 0)
        assert p["name"] == "p"
        assert p["is_pointer"] is True
        assert p["is_fn_pointer"] is False
        assert p["is_const"] is False
        assert p["type"] == "char (*)[10][20]"
        assert p["pointee_type"] == "char [10][20]"
        formatted = gh._format_c_decl(p["pointee_type"], p["name"])
        assert formatted == "char p[10][20];"

    def test_unnamed_array_pointer(self):
        """Test unnamed array pointer float (*)[8]."""
        p = gh._parse_c_param("float (*)[8]", 2)
        assert p["name"] == "arg_2"
        assert p["is_pointer"] is True
        assert p["is_fn_pointer"] is False
        assert p["type"] == "float (*)[8]"
        assert p["pointee_type"] == "float [8]"
        formatted = gh._format_c_decl(p["pointee_type"], p["name"])
        assert formatted == "float arg_2[8];"

    def test_unnamed_multidim_array_pointer(self):
        """Test unnamed multi-dimensional array pointer int (*)[2][3][4]."""
        p = gh._parse_c_param("int (*)[2][3][4]", 1)
        assert p["name"] == "arg_1"
        assert p["is_pointer"] is True
        assert p["type"] == "int (*)[2][3][4]"
        assert p["pointee_type"] == "int [2][3][4]"
        formatted = gh._format_c_decl(p["pointee_type"], p["name"])
        assert formatted == "int arg_1[2][3][4];"

    def test_const_multidim_array(self):
        """Test const qualified multi-dimensional array const int a[5][10]."""
        p = gh._parse_c_param("const int a[5][10]", 0)
        assert p["name"] == "a"
        assert p["is_pointer"] is True
        assert p["is_const"] is True
        assert p["type"] == "const int (*)[10]"
        assert p["pointee_type"] == "const int [10]"
        formatted = gh._format_c_decl(p["pointee_type"], p["name"])
        assert formatted == "const int a[10];"

    def test_const_array_pointer(self):
        """Test const pointer to array char (* const p)[10][20]."""
        p = gh._parse_c_param("char (* const p)[10][20]", 0)
        assert p["name"] == "p"
        assert p["is_pointer"] is True
        assert "(* const)" in p["type"]
        assert p["pointee_type"] == "char [10][20]"
        formatted = gh._format_c_decl(p["pointee_type"], p["name"])
        assert formatted == "char p[10][20];"

    def test_complex_typedef_handling(self):
        """Test parameters declared with typedefs (e.g., Matrix3D m, Matrix3D *mp)."""
        # Value typedef parameter
        p_val = gh._parse_c_param("Matrix3D m", 0)
        assert p_val["name"] == "m"
        assert p_val["is_pointer"] is False
        assert p_val["type"] == "Matrix3D"
        assert p_val["pointee_type"] == "Matrix3D"
        assert gh._format_c_decl(p_val["pointee_type"], p_val["name"]) == "Matrix3D m;"

        # Pointer typedef parameter
        p_ptr = gh._parse_c_param("Matrix3D *mp", 0)
        assert p_ptr["name"] == "mp"
        assert p_ptr["is_pointer"] is True
        assert p_ptr["pointee_type"] == "Matrix3D"
        assert gh._format_c_decl(p_ptr["pointee_type"], p_ptr["name"]) == "Matrix3D mp;"

    def test_array_of_pointers_multidim_limitation(self):
        """
        Adversarial edge case: array of pointers to multi-dimensional array int *a[5][10].
        In C, 'int *a[5][10]' decays to 'int * (*)[10]', but _parse_c_param separates 'stars'
        and currently omits 'stars' from pointee_type ('int [10]' instead of 'int * [10]').
        Verify this empirical behavior.
        """
        p = gh._parse_c_param("int *a[5][10]", 0)
        assert p["name"] == "a"
        assert p["is_pointer"] is True
        # full_type preserves pointer-to-pointer decay
        assert p["type"] == "int * (*)[10]"
        # Note: pointee_type drops the inner star due to `f"{type_part} {rest_dims}"`
        assert "10" in p["pointee_type"]


# ===========================================================================
# 2. B5: Formal parameter signature extraction and model fallback
# ===========================================================================


class TestB5FormalParameterSignatureExtraction:
    """Stress-test extract_function_prototype and extract_function_declaration with model and GCC fallback."""

    def test_b5_missing_model_falls_back_to_source(self, tmp_path: Path):
        """Verify seamless fallback to C source when model is None."""
        src = tmp_path / "calc.c"
        src.write_text("int compute(int x, char *buf) { return x; }\n", encoding="utf-8")

        params = gh.extract_function_prototype("compute", sources=[str(src)], model=None)
        assert len(params) == 2
        assert params[0]["name"] == "x"
        assert params[0]["type"] == "int"
        assert params[1]["name"] == "buf"
        assert params[1]["type"] == "char *"

    def test_b5_empty_model_falls_back_to_source(self, tmp_path: Path):
        """Verify seamless fallback when model is an empty dict or has empty functions."""
        src = tmp_path / "calc.c"
        src.write_text("int compute(int x, char *buf) { return x; }\n", encoding="utf-8")

        empty_models: list[dict[str, Any]] = [{}, {"functions": {}}, {"other": 123}]
        for empty_model in empty_models:
            params = gh.extract_function_prototype("compute", sources=[str(src)], model=empty_model)
            assert len(params) == 2
            assert params[0]["name"] == "x"
            assert params[1]["name"] == "buf"

    def test_b5_null_signature_in_model_falls_back_to_source(self, tmp_path: Path):
        """Verify seamless fallback when model record exists but signature is null or empty."""
        src = tmp_path / "calc.c"
        src.write_text("int compute(int x, char *buf) { return x; }\n", encoding="utf-8")

        for bad_sig in (None, "", "   "):
            model = {
                "functions": {
                    "calc.c#compute": {
                        "name": "compute",
                        "signature": bad_sig,
                        "formals": ["x", "buf"],
                    }
                }
            }
            params = gh.extract_function_prototype("compute", sources=[str(src)], model=model)
            assert len(params) == 2
            assert params[0]["name"] == "x"
            assert params[1]["name"] == "buf"

    def test_b5_unnamed_params_augmented_by_formals(self):
        """Verify model formal parameter names augment unnamed C prototype signatures."""
        model = {
            "functions": {
                "calc.c#process": {
                    "name": "process",
                    "signature": "int process(int, const char *, void *)",
                    "formals": ["count", "message", "ctx"],
                }
            }
        }
        params = gh.extract_function_prototype("process", model=model)
        assert len(params) == 3
        assert params[0]["name"] == "count"
        assert params[0]["type"] == "int"
        assert params[1]["name"] == "message"
        assert "const char" in params[1]["type"]
        assert params[2]["name"] == "ctx"
        assert "void" in params[2]["type"]

    def test_b5_void_and_empty_signature_with_model(self):
        """Verify void parameter lists return empty list without fallback error."""
        m_void = {"functions": {"f": {"name": "f", "signature": "void f(void)", "formals": []}}}
        assert gh.extract_function_prototype("f", model=m_void) == []

        m_empty = {"functions": {"f": {"name": "f", "signature": "void f()", "formals": []}}}
        assert gh.extract_function_prototype("f", model=m_empty) == []

    def test_b5_declaration_extraction_model_and_fallback(self, tmp_path: Path):
        """Verify extract_function_declaration uses model signature and falls back to source."""
        src = tmp_path / "calc.c"
        src.write_text("static int compute(int x, char *buf) { return x; }\n", encoding="utf-8")

        # Fallback without model (strips static)
        d_fb = gh.extract_function_declaration("compute", sources=[str(src)], model=None)
        assert d_fb == "int compute(int x, char *buf);"

        # With model signature
        m = {
            "functions": {
                "calc.c#compute": {
                    "name": "compute",
                    "signature": "int compute(int x, char *buf)",
                }
            }
        }
        d_model = gh.extract_function_declaration("compute", sources=[str(src)], model=m)
        assert d_model == "int compute(int x, char *buf);"


# ===========================================================================
# 3. D8: Predicate label stripping and alarm kind detection
# ===========================================================================


class TestD8PredicateLabelStripping:
    """Stress-test normalize_predicate and alarm kind detectors against adversarial predicates."""

    @pytest.mark.parametrize(
        "predicate,expected_norm",
        [
            # Tricky identifiers without colon must NOT be stripped
            ("check > 0", "check>0"),
            ("assert_true(x)", "assert_true(x)"),
            ("admit == 2", "admit==2"),
            ("assert != 0", "assert!=0"),
            ("a: b: c > 0", "a:b:c>0"),
            # Colon-delimited labels must be stripped
            ("assert: x > 0", "x>0"),
            ("check: y == 1", "y==1"),
            ("admit: z != 0", "z!=0"),
            ("rte: x + 1 > 0", "x+1>0"),
            ("eva: check: a[i] > 0", "a[i]>0"),
            ("wp: rte: check: x == y", "x==y"),
            ("assert rte/index_bound: i < 8", "i<8"),
            ("eva: out_of_bounds: a[i] < 10", "out_of_bounds:a[i]<10"),
            ("eva: index_bound: a[i] < 10", "a[i]<10"),
            # Whitespace and punctuation
            ("   check:    v == 42;  ", "v==42"),
        ],
    )
    def test_d8_predicate_normalization(self, predicate: str, expected_norm: str):
        assert fp.normalize_predicate(predicate) == expected_norm

    def test_d8_cpp_scope_resolution_colons_preserved(self):
        """Verify double colons :: (C++ scope resolution) are never treated as label delimiters."""
        p = "assert: std::vector<int>::size() > 0"
        assert fp.normalize_predicate(p) == "std::vector<int>::size()>0"

    def test_d8_ternary_operator_preserved(self):
        """Verify ternary ? : expressions are not mistaken for label colons."""
        p = "assert: cond ? 1 : 0"
        assert fp.normalize_predicate(p) == "cond?1:0"

    def test_d8_alarm_kind_detection_case_insensitivity(self):
        """Verify alarm kind detection handles casing and precompiled alternations."""
        assert fp.detect_alarm_kind("mem_access: \\valid_read(p)") == "mem_access"
        assert fp.detect_alarm_kind("MEM_ACCESS: \\valid_read(p)") == "mem_access"
        assert fp.detect_alarm_kind("Signed_Overflow: x + y") == "signed_overflow"
        assert fp.detect_alarm_kind("is_nan_or_infinite: f") == "is_nan_or_infinite"
        assert fp.detect_alarm_kind("is_nan: f") == "is_nan"

    def test_d8_leading_alarm_kind_vs_detect_predicate_alarm_kind(self):
        """Verify leading_alarm_kind extracts from leading label while detect_predicate_alarm_kind finds labels inside."""
        # Leading label
        assert fp.leading_alarm_kind("eva: signed_overflow: x + 1") == "signed_overflow"
        assert fp.detect_predicate_alarm_kind("eva: signed_overflow: x + 1") == "signed_overflow"

        # Inside predicate
        assert fp.detect_predicate_alarm_kind("Assertion rte/division_by_zero: d != 0") == "division_by_zero"


# ===========================================================================
# 4. B7: Main definition detection in comments, literals, multiline, macros
# ===========================================================================


class TestB7MainDefinitionDetection:
    """Stress-test _source_defines_main and main renaming with comments, literals, multiline, and capture."""

    def test_b7_comment_variations_do_not_trigger_main_def(self, tmp_path: Path):
        """Verify comments containing main() definitions do not trigger main detection."""
        comments = [
            "/* int main(void) { return 0; } */\nint helper(void) { return 1; }",
            "// int main(int argc, char **argv) {\nint helper(void) { return 1; }",
            "/*\n * int main(void)\n * {\n *     return 0;\n * }\n */\nvoid fn(void) {}",
        ]
        for idx, text in enumerate(comments):
            src = tmp_path / f"comment_{idx}.c"
            src.write_text(text, encoding="utf-8")
            assert pm._source_defines_main(src) is False

    def test_b7_embedded_string_literals_do_not_trigger_main_def(self, tmp_path: Path):
        """Verify string literals containing main() definitions do not trigger main detection."""
        literals = [
            'const char *s = "int main(int argc, char **argv) { return 0; }";\n',
            'const char *s = "void main(void) {";\n',
            'const char *s = "int main() {";\n',
            'char s[] = "\\"int main(void) {\\"";\n',
        ]
        for idx, text in enumerate(literals):
            src = tmp_path / f"literal_{idx}.c"
            src.write_text(text, encoding="utf-8")
            assert pm._source_defines_main(src) is False

    def test_b7_multiline_main_definition_detected(self, tmp_path: Path):
        """Verify multiline main definitions with arbitrary whitespace are detected."""
        multilines = [
            "int\nmain\n(\nvoid\n)\n{\nreturn 0;\n}",
            "int\nmain\n(\nint argc\n,\nchar **argv\n)\n{\nreturn 0;\n}",
            "void\nmain\n(\n)\n{\n}",
        ]
        for idx, text in enumerate(multilines):
            src = tmp_path / f"multi_{idx}.c"
            src.write_text(text, encoding="utf-8")
            assert pm._source_defines_main(src) is True

    def test_b7_macro_expanding_to_main_with_and_without_capture(self, tmp_path: Path):
        """
        Verify macros expanding to main are detected when build_capture.json is available,
        and fall back to False when unexpanded source text is inspected.
        """
        src = tmp_path / "macro_main.c"
        src.write_text(
            "#define APP_ENTRY main\nint APP_ENTRY(void) {\n    return 0;\n}\n",
            encoding="utf-8",
        )

        # Without capture: regex scanner cannot expand APP_ENTRY
        assert pm._source_defines_main(src, capture=None) is False

        # With capture: defined_functions symbol records main
        capture = {
            "compiles": [
                {
                    "file": str(src),
                    "defined_functions": [f"{src}#main"],
                }
            ]
        }
        assert pm._source_defines_main(src, capture=capture) is True


# ===========================================================================
# 5. B8: Harness sidecar JSON schema validation and consumer fallback
# ===========================================================================


class TestB8SidecarSchemaAndDispatchMetadata:
    """Stress-test schemas/harness_sidecar.schema.json and dispatch_case_count consumers."""

    @pytest.fixture
    def sidecar_schema(self) -> dict[str, Any]:
        schema_path = Path("schemas/harness_sidecar.schema.json")
        return json.loads(schema_path.read_text(encoding="utf-8"))

    @pytest.fixture
    def minimal_sidecar(self) -> dict[str, Any]:
        return {
            "module": "test_mod",
            "harness_file": "workspace/harnesses/harness_test_mod.c",
            "sources": ["src/test.c"],
            "cppflags": "-Iinclude",
            "entry_fn": "test_entry",
            "entry_style": "dispatch",
        }

    def test_sidecar_schema_valid_dispatch_case_counts(self, sidecar_schema, minimal_sidecar):
        """
        Verify sidecar schema accepts valid dispatch_case_count values (0, positive, up to the
        generator's two-byte bound generate_harness.DISPATCH_MAX_CASES_WIDE) and refuses one above it.
        """
        for count in (0, 1, 5, 255, 256, 257, 4096):
            sidecar = {**minimal_sidecar, "dispatch_case_count": count}
            errs = validate(sidecar, sidecar_schema)
            assert errs == [], f"Validation failed for count={count}: {errs}"
        errs = validate({**minimal_sidecar, "dispatch_case_count": 4097}, sidecar_schema)
        assert any("above maximum 4096" in e for e in errs), errs

    def test_sidecar_schema_negative_dispatch_case_count_rejected(self, sidecar_schema, minimal_sidecar):
        """Verify negative dispatch_case_count is rejected by schema (minimum: 0)."""
        sidecar = {**minimal_sidecar, "dispatch_case_count": -1}
        errs = validate(sidecar, sidecar_schema)
        assert any("below minimum" in e or "minimum" in e for e in errs)

    def test_sidecar_schema_type_mismatch_rejected(self, sidecar_schema, minimal_sidecar):
        """Verify non-integer dispatch_case_count is rejected by schema."""
        for bad_val in ("5", 3.14, True, None, [5]):
            sidecar = {**minimal_sidecar, "dispatch_case_count": bad_val}
            errs = validate(sidecar, sidecar_schema)
            assert len(errs) > 0, f"Expected validation failure for {bad_val!r}"

    def test_sidecar_schema_missing_optional_fields_accepted(self, sidecar_schema, minimal_sidecar):
        """Verify dispatch_case_count is optional and omitted fields do not fail validation."""
        assert "dispatch_case_count" not in minimal_sidecar
        errs = validate(minimal_sidecar, sidecar_schema)
        assert errs == []

    def test_sidecar_schema_missing_required_fields_rejected(self, sidecar_schema, minimal_sidecar):
        """Verify missing required fields (module, entry_fn, entry_style) fail validation."""
        for req in ("module", "harness_file", "sources", "cppflags", "entry_fn", "entry_style"):
            bad = dict(minimal_sidecar)
            del bad[req]
            errs = validate(bad, sidecar_schema)
            assert any(f"missing required property '{req}'" in e for e in errs)

    def test_run_eacsl_fuzz_consumer_precedence(self, tmp_path: Path):
        """
        Verify run_eacsl_fuzz.dispatch_case_count respects precedence:
        1. dispatch_case_count
        2. api_cases
        3. dispatch_cases
        4. regex fallback in C source
        """
        harness_c = tmp_path / "harness_test.c"
        harness_json = tmp_path / "harness_test.json"
        # A dispatch harness a build can skip cases of holds the skip macro; its switch is not needed.
        harness_c.write_text(f"// {gh.DISPATCH_SKIP_MACRO}, no switch\n", encoding="utf-8")

        # 1. dispatch_case_count wins
        harness_json.write_text(
            json.dumps(
                {
                    "dispatch_case_count": 12,
                    "api_cases": [{"call": 1}],
                    "dispatch_cases": ["case 0;"],
                }
            ),
            encoding="utf-8",
        )
        assert rf.dispatch_case_count([str(harness_c)]) == 12

        # 2. api_cases when dispatch_case_count absent
        harness_json.write_text(
            json.dumps(
                {
                    "api_cases": [{"call": 1}, {"call": 2}, {"call": 3}],
                    "dispatch_cases": ["case 0;"],
                }
            ),
            encoding="utf-8",
        )
        assert rf.dispatch_case_count([str(harness_c)]) == 3

        # 3. dispatch_cases when api_cases absent
        harness_json.write_text(
            json.dumps(
                {
                    "dispatch_cases": ["case 0;", "case 1;"],
                }
            ),
            encoding="utf-8",
        )
        assert rf.dispatch_case_count([str(harness_c)]) == 2

        # 4. Regex fallback when sidecar missing
        harness_json.unlink()
        harness_c.write_text(
            f"// {gh.DISPATCH_SKIP_MACRO}\n"
            "switch (harness_selector % 4U) {\n"
            "    case 0: fn0(); break;\n"
            "    case 1: fn1(); break;\n"
            "    case 2: fn2(); break;\n"
            "    case 3: fn3(); break;\n"
            "}\n",
            encoding="utf-8",
        )
        assert rf.dispatch_case_count([str(harness_c)]) == 4


# ===========================================================================
# 6. B11: Clang AST Callee Extraction, recursion, and token heuristic fallback
# ===========================================================================


class TestB11ClangASTCalleeExtraction:
    """Stress-test Clang AST callee extraction with recursive calls, function pointers, and token fallback."""

    def test_callees_from_clang_ast_recursive_call(self):
        """Verify recursive function calls are extracted without infinite loops."""
        tree = {
            "kind": "TranslationUnitDecl",
            "inner": [
                {
                    "kind": "FunctionDecl",
                    "name": "factorial",
                    "inner": [
                        {
                            "kind": "CompoundStmt",
                            "inner": [
                                {
                                    "kind": "CallExpr",
                                    "calleeDecl": {"name": "factorial"},
                                    "inner": [
                                        {
                                            "kind": "DeclRefExpr",
                                            "referencedDecl": {"kind": "FunctionDecl", "name": "factorial"},
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        callees = hr._callees_from_clang_ast(tree)
        assert callees == {"factorial"}

    def test_callees_from_clang_ast_function_pointer_invocation(self):
        """Verify function pointer assignment and indirect invocation extracts concrete target."""
        tree = {
            "kind": "TranslationUnitDecl",
            "inner": [
                {
                    "kind": "VarDecl",
                    "name": "handler",
                    "inner": [
                        {
                            "kind": "ImplicitCastExpr",
                            "inner": [
                                {
                                    "kind": "DeclRefExpr",
                                    "referencedDecl": {"kind": "FunctionDecl", "name": "concrete_handler"},
                                }
                            ],
                        }
                    ],
                },
                {
                    "kind": "CallExpr",
                    "inner": [
                        {
                            "kind": "ImplicitCastExpr",
                            "inner": [
                                {
                                    "kind": "DeclRefExpr",
                                    "referencedDecl": {"kind": "VarDecl", "name": "handler"},
                                }
                            ],
                        }
                    ],
                },
            ],
        }
        callees = hr._callees_from_clang_ast(tree)
        assert "concrete_handler" in callees

    def test_callees_from_clang_ast_vardecl_fallthrough_behavior(self):
        """
        Adversarial test: DeclRefExpr referencing a VarDecl.
        When referencedDecl is a VarDecl and node has a 'name' attribute,
        verify whether VarDecl name is included due to the elif fallthrough.
        """
        tree = {
            "kind": "TranslationUnitDecl",
            "inner": [
                {
                    "kind": "DeclRefExpr",
                    "name": "variable_counter",
                    "referencedDecl": {"kind": "VarDecl", "name": "variable_counter"},
                },
                {
                    "kind": "DeclRefExpr",
                    "name": "actual_func",
                    "referencedDecl": {"kind": "FunctionDecl", "name": "actual_func"},
                },
            ],
        }
        callees = hr._callees_from_clang_ast(tree)
        # actual_func MUST be present
        assert "actual_func" in callees
        # Documents the empirical behavior of the elif node.get('name') branch
        assert "variable_counter" in callees

    def test_harness_roots_token_heuristic_fallback(self):
        """Verify harness_roots falls back seamlessly to _used_identifiers when Clang AST is unavailable."""
        harness_text = (
            "void harness(void) {\n"
            "    init_state();\n"
            "    process_payload(fuzz_buf, fuzz_len);\n"
            "    WRAPPER_MACRO();\n"
            "}\n"
        )
        fn_names = {"init_state", "process_payload", "unused_function"}
        macros = {"WRAPPER_MACRO": {"expanded_callee"}}

        # With harness_path=None, Clang AST cannot run -> falls back to token heuristic
        roots = hr.harness_roots(harness_text, fn_names, macros, harness_path=None)
        assert roots == {"init_state", "process_payload", "expanded_callee"}
        assert "unused_function" not in roots
