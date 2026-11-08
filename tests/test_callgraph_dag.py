"""Tests for scripts/build_callgraph_dag.py (token-driven extraction, Tarjan SCC, structural tiers, and WP blockers)."""

from __future__ import annotations

import json
from pathlib import Path

from build_callgraph_dag import (
    _filter_host_system_flags,
    analyze_body,
    analyze_signature,
    build_dag,
    classify_module_tier,
    compute_topological_waves,
    discover_in_tree_cppflags,
    extract_functions_from_code,
    extract_prototypes_from_code,
    infer_security_properties,
    tokenize_c_acsl,
)


class TestTokenFunctionExtraction:
    """Tests for token-based C function definition extraction."""

    def test_extracts_multiline_attributes_and_function_pointer_params(self) -> None:
        src = """\
#include <stddef.h>
#include <stdint.h>

/* Forward declaration must not be treated as a definition */
int proto_only(const uint8_t *buf, size_t len);

__attribute__((warn_unused_result))
static inline const uint8_t *
step_cursor(
    const uint8_t * restrict cursor,
    size_t remaining,
    int (*on_byte)(uint8_t b, void *ctx),
    void *ctx
) {
    if (cursor == NULL || remaining == 0) {
        return NULL;
    }
    if (on_byte != NULL) {
        int rc = on_byte(cursor[0], ctx);
        if (rc < 0) {
            return NULL;
        }
    }
    return cursor + 1;
}

/* Function returning a function pointer */
int (*select_op(int mode))(int, int) {
    (void)mode;
    return 0;
}
"""
        fns = extract_functions_from_code(src)
        names = [f["name"] for f in fns]
        assert names == ["step_cursor", "select_op"]

        step = fns[0]
        sig = analyze_signature(step["decl_tokens"], step["param_tokens"])
        assert sig["is_static"] is True
        assert sig["returns_pointer"] is True
        assert sig["takes_bounded_buffer"] is True
        assert "on_byte" in sig["fn_ptr_params"]

    def test_macro_call_with_brace_argument_does_not_hide_later_functions(self):
        # x509-parser: DECL_HASH_ALG(md2, "MD2", P99_PROTECT({ 0x06, 0x08 }));
        src = """
int before(void) { return 0; }
DECLARE_TABLE(md2, "MD2", PROTECT({ 0x06, 0x08 }));
int after(int x) { return x; }
static int last(void) { return 1; }
"""
        assert [f["name"] for f in extract_functions_from_code(src)] == ["before", "after", "last"]

    def test_statement_expression_argument_does_not_hide_later_functions(self):
        src = """
int value = WRAP(({ int y = 1; y; }));
int after(void) { return value; }
"""
        assert [f["name"] for f in extract_functions_from_code(src)] == ["after"]

    def test_extern_c_block_still_exposes_its_functions_and_later_ones(self):
        src = """
extern "C" {
int inner(void) { return 0; }
}
int outer(void) { return 1; }
"""
        assert [f["name"] for f in extract_functions_from_code(src)] == ["inner", "outer"]


class TestStructuralBodyAnalysis:
    """Tests for structural C body inspection (indirect calls, backward goto, allocators, zeroization)."""

    def test_detects_direct_and_indirect_calls_and_unsigned_wrap(self) -> None:
        src = """\
int process_items(const uint8_t *data, size_t count, struct ops *vtable, int (*hook)(uint8_t)) {
    size_t total = 0;
    while (count--) {
        uint8_t b = *data++;
        total += helper_step(b);
        vtable->consume(b);
        (*hook)(b);
    }
    return (int)total;
}
"""
        fns = extract_functions_from_code(src)
        assert len(fns) == 1
        sig = analyze_signature(fns[0]["decl_tokens"], fns[0]["param_tokens"])
        body = analyze_body("process_items", fns[0]["body_tokens"], sig)

        assert "helper_step" in body["direct_callees"]
        assert "consume" not in body["direct_callees"]
        assert "vtable->consume" in body["indirect_calls"]
        assert "(*hook)" in body["indirect_calls"]
        assert body["has_loops"] is True
        assert body["has_unsigned_wrap_idiom"] is True
        assert body["verifiability"] == "needs_calls_annotation"

    def test_distinguishes_forward_cleanup_goto_from_backward_irreducible_goto(self) -> None:
        src = """\
int forward_cleanup(const uint8_t *buf, size_t len) {
    if (buf == 0 || len == 0) {
        goto fail;
    }
    return (int)buf[0];
fail:
    return -1;
}

int backward_retry(uint8_t *buf, size_t len) {
    size_t i = 0;
retry:
    if (i < len) {
        buf[i] = 0;
        i++;
        goto retry;
    }
    return 0;
}
"""
        fns = extract_functions_from_code(src)
        by_name = {f["name"]: f for f in fns}

        fwd_sig = analyze_signature(
            by_name["forward_cleanup"]["decl_tokens"], by_name["forward_cleanup"]["param_tokens"]
        )
        fwd_body = analyze_body("forward_cleanup", by_name["forward_cleanup"]["body_tokens"], fwd_sig)
        assert fwd_body["has_backward_goto"] is False
        assert fwd_body["verifiability"] == "core_provable"

        bwd_sig = analyze_signature(by_name["backward_retry"]["decl_tokens"], by_name["backward_retry"]["param_tokens"])
        bwd_body = analyze_body("backward_retry", by_name["backward_retry"]["body_tokens"], bwd_sig)
        assert bwd_body["has_backward_goto"] is True
        assert "irreducible_goto" in bwd_body["wp_blockers"]
        assert bwd_body["verifiability"] == "shell_unverifiable_wp"
        assert bwd_body["has_zeroization"] is True

    def test_detects_allocators_and_container_of(self) -> None:
        src = """\
void *alloc_node(void *member_ptr, size_t sz) {
    void *parent = container_of(member_ptr, struct node, link);
    (void)parent;
    return calloc(1, sz);
}
"""
        fns = extract_functions_from_code(src)
        sig = analyze_signature(fns[0]["decl_tokens"], fns[0]["param_tokens"])
        body = analyze_body("alloc_node", fns[0]["body_tokens"], sig)
        assert body["has_dynamic_alloc"] is True
        assert body["has_container_of"] is True
        assert set(body["wp_blockers"]) == {"dynamic_allocation", "container_of"}

    def test_marks_fuzz_and_eva_harness_entrypoints_as_shell_unverifiable_wp(self) -> None:
        src = """\
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    return size > 0 ? data[0] : 0;
}
int eva_main(void) {
    return 0;
}
"""
        fns = {f["name"]: f for f in extract_functions_from_code(src)}
        for name in ("LLVMFuzzerTestOneInput", "eva_main"):
            sig = analyze_signature(fns[name]["decl_tokens"], fns[name]["param_tokens"])
            body = analyze_body(name, fns[name]["body_tokens"], sig)
            assert "fuzz_or_eva_harness_entrypoint" in body["wp_blockers"]
            assert body["verifiability"] == "shell_unverifiable_wp"

    def test_ignores_do_while_zero_macros_and_counts_do_while_once(self) -> None:
        src = """\
int macro_only(int x) {
    do {
        x += 1;
    } while (0);
    return x;
}

int real_do_while(int n) {
    int i = 0;
    do {
        i++;
    } while (i < n);
    return i;
}
"""
        fns = {f["name"]: f for f in extract_functions_from_code(src)}
        sig1 = analyze_signature(fns["macro_only"]["decl_tokens"], fns["macro_only"]["param_tokens"])
        body1 = analyze_body("macro_only", fns["macro_only"]["body_tokens"], sig1)
        assert body1["has_loops"] is False
        assert body1["loop_count"] == 0

        sig2 = analyze_signature(fns["real_do_while"]["decl_tokens"], fns["real_do_while"]["param_tokens"])
        body2 = analyze_body("real_do_while", fns["real_do_while"]["body_tokens"], sig2)
        assert body2["has_loops"] is True
        assert body2["loop_count"] == 1


class TestTarjanWavesAndHintFreeClassification:
    """Tests for Tarjan SCC wave calculation and purely structural module tiering."""

    def test_tarjan_scc_waves_and_mutual_recursion(self) -> None:
        functions = {
            "leaf": {"self_recursive": False},
            "mid": {"self_recursive": False},
            "top": {"self_recursive": False},
            "cycle_a": {"self_recursive": False},
            "cycle_b": {"self_recursive": False},
            "self_rec": {"self_recursive": True},
        }
        call_edges = {
            "leaf": set(),
            "mid": {"leaf"},
            "top": {"mid", "cycle_a"},
            "cycle_a": {"cycle_b", "leaf"},
            "cycle_b": {"cycle_a"},
            "self_rec": {"leaf"},
        }
        waves, cycles = compute_topological_waves(functions, call_edges)
        wave_of = {fn: idx for idx, w in enumerate(waves) for fn in w}
        assert wave_of["leaf"] == 0
        assert wave_of["mid"] == 1
        assert wave_of["cycle_a"] == wave_of["cycle_b"]
        assert wave_of["top"] > wave_of["cycle_a"]
        assert ["cycle_a", "cycle_b"] in cycles
        assert ["self_rec"] in cycles

    def test_structural_tier_classification_without_keyword_hints(self) -> None:
        """Modules with generic names (alpha, beta, gamma, delta) are classified purely by structure."""
        # alpha: bounded binary reader with loops, no dynamic allocation -> Tier 1A
        alpha_fns = [
            {
                "name": "alpha_read_frame",
                "takes_bounded_buffer": True,
                "writes_bounded_buffer": False,
                "has_loops": True,
                "has_dynamic_alloc": False,
                "is_recursive": False,
                "uses_format_or_write": False,
                "verifiability": "core_provable",
                "const_ptr_params": 1,
                "mutable_ptr_params": 0,
            },
            {
                "name": "alpha_read_u16",
                "takes_bounded_buffer": True,
                "writes_bounded_buffer": False,
                "has_loops": False,
                "has_dynamic_alloc": False,
                "is_recursive": False,
                "uses_format_or_write": False,
                "verifiability": "core_provable",
                "const_ptr_params": 1,
                "mutable_ptr_params": 0,
            },
        ]
        assert classify_module_tier("alpha", alpha_fns)["tier"].startswith("Tier 1A")

        # beta: bounded output writer / formatter -> Tier 1B
        beta_fns = [
            {
                "name": "beta_write_record",
                "takes_bounded_buffer": False,
                "writes_bounded_buffer": True,
                "has_loops": True,
                "has_dynamic_alloc": False,
                "is_recursive": False,
                "uses_format_or_write": True,
                "verifiability": "core_provable",
                "const_ptr_params": 0,
                "mutable_ptr_params": 1,
            },
        ]
        assert classify_module_tier("beta", beta_fns)["tier"].startswith("Tier 1B")

        # gamma: recursive + dynamic allocation -> Tier 2
        gamma_fns = [
            {
                "name": "gamma_build_graph",
                "takes_bounded_buffer": True,
                "writes_bounded_buffer": False,
                "has_loops": True,
                "has_dynamic_alloc": True,
                "is_recursive": True,
                "uses_format_or_write": False,
                "verifiability": "shell_unverifiable_wp",
                "const_ptr_params": 1,
                "mutable_ptr_params": 0,
            },
        ]
        assert classify_module_tier("gamma", gamma_fns)["tier"].startswith("Tier 2")

        # delta: internal glue with no buffers, pointers, or loops -> Tier 3
        delta_fns = [
            {
                "name": "delta_get_state",
                "takes_bounded_buffer": False,
                "writes_bounded_buffer": False,
                "has_loops": False,
                "has_dynamic_alloc": False,
                "is_recursive": False,
                "uses_format_or_write": False,
                "verifiability": "core_provable",
                "const_ptr_params": 0,
                "mutable_ptr_params": 0,
            },
        ]
        assert classify_module_tier("delta", delta_fns)["tier"].startswith("Tier 3")

    def test_end_to_end_build_dag_populates_verifiability_and_security_layers(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src" / "codec"
        src_dir.mkdir(parents=True)
        (src_dir / "decoder.c").write_text(
            """\
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static int decode_chunk(const uint8_t *buf, size_t len, size_t *off) {
    if (*off >= len) {
        return -1;
    }
    (*off)++;
    return 0;
}

int decode_stream(const uint8_t *buf, size_t len, uint8_t *scratch, size_t scratch_len) {
    size_t off = 0;
    while (off < len) {
        if (decode_chunk(buf, len, &off) != 0) {
            memset(scratch, 0, scratch_len);
            return -1;
        }
    }
    memset(scratch, 0, scratch_len);
    return 0;
}
""",
            encoding="utf-8",
        )
        dag = build_dag(tmp_path)
        assert dag["callgraph_source"] == "regex"
        assert dag["total_functions"] == 2
        assert dag["modules"]["codec"]["tier"].startswith("Tier 1A")

        dec_chunk = dag["functions"]["decode_chunk"]
        dec_stream = dag["functions"]["decode_stream"]
        assert dec_chunk["wave"] == 0
        assert dec_stream["wave"] == 1
        assert dec_stream["verifiability"] == "core_provable"
        assert dec_stream["wp_blockers"] == []
        layers = {p["layer"] for p in dec_stream["security_properties"]}
        # Loop termination only: Layers 3-6 come from the threat model via security_props.py (I9).
        assert layers == {2}
        assert infer_security_properties is not None

    def test_cross_module_required_sources_and_compile_commands_synthesis(self, tmp_path: Path) -> None:
        inc_dir = tmp_path / "include" / "common"
        inc_dir.mkdir(parents=True)
        (inc_dir / "util.h").write_text("int util_crc(const unsigned char *p, unsigned int n);\n", encoding="utf-8")

        mod_a = tmp_path / "src" / "mod_a"
        mod_b = tmp_path / "src" / "mod_b"
        mod_a.mkdir(parents=True)
        mod_b.mkdir(parents=True)

        (mod_b / "util.c").write_text(
            '#include "util.h"\nint util_crc(const unsigned char *p, unsigned int n) { return n > 0 ? p[0] : 0; }\n',
            encoding="utf-8",
        )
        (mod_a / "parser.c").write_text(
            '#include "util.h"\nint parse_msg(const unsigned char *buf, unsigned int len) { return util_crc(buf, len) + ext_lib_call(len); }\n',
            encoding="utf-8",
        )

        # Verify host /usr/include flags are stripped
        assert _filter_host_system_flags(["-I/usr/include", "-I/usr/local/include/foo", "-Iinclude", "-DTEST=1"]) == [
            "-Iinclude",
            "-DTEST=1",
        ]

        c_files = [mod_a / "parser.c", mod_b / "util.c"]
        in_tree = discover_in_tree_cppflags(tmp_path, c_files)
        assert any(f.endswith("include/common") for f in in_tree["src/mod_a/parser.c"])

        cc_out = tmp_path / "compile_commands.json"
        dag = build_dag(tmp_path, emit_compile_commands=cc_out)
        assert cc_out.is_file()

        mod_a_info = dag["modules"]["mod_a"]
        assert "src/mod_a/parser.c" in mod_a_info["required_sources"]
        assert "src/mod_b/util.c" in mod_a_info["required_sources"]
        assert mod_a_info["cross_module_callees"] == ["util_crc"]
        assert mod_a_info["external_callees"] == ["ext_lib_call"]

    def test_detects_internal_variadic_function_signature_and_blocker(self, tmp_path: Path) -> None:
        src = """\
#include <stddef.h>
#include <stdarg.h>

int log_message(int level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_end(args);
    return level;
}

int fixed_message(int level, const char *msg) {
    return level + (msg != NULL);
}
"""
        fns = extract_functions_from_code(src)
        assert len(fns) == 2
        var_fn = next(f for f in fns if f["name"] == "log_message")
        fix_fn = next(f for f in fns if f["name"] == "fixed_message")

        sig_var = analyze_signature(var_fn["decl_tokens"], var_fn["param_tokens"])
        assert sig_var["is_variadic"] is True
        body_var = analyze_body("log_message", var_fn["body_tokens"], sig_var)
        assert "internal_variadic" in body_var["wp_blockers"]
        assert body_var["verifiability"] == "shell_unverifiable_wp"
        assert any("variadic function" in n for n in body_var["wp_notes"])

        sig_fix = analyze_signature(fix_fn["decl_tokens"], fix_fn["param_tokens"])
        assert sig_fix["is_variadic"] is False
        body_fix = analyze_body("fixed_message", fix_fn["body_tokens"], sig_fix)
        assert "internal_variadic" not in body_fix["wp_blockers"]

        # End-to-end DAG build
        src_file = tmp_path / "logger.c"
        src_file.write_text(src, encoding="utf-8")
        dag = build_dag(tmp_path)
        assert dag["functions"]["log_message"]["is_variadic"] is True
        assert "internal_variadic" in dag["functions"]["log_message"]["wp_blockers"]
        assert dag["functions"]["log_message"]["verifiability"] == "shell_unverifiable_wp"
        assert dag["functions"]["fixed_message"]["is_variadic"] is False

        # Spaced variadic dots (. . .) recognition
        spaced_toks = tokenize_c_acsl("int bar(int x, . . .)")
        lp = [i for i, t in enumerate(spaced_toks) if t.text == "("][0]
        rp = [i for i, t in enumerate(spaced_toks) if t.text == ")"][0]
        sig_spaced = analyze_signature(spaced_toks[: rp + 1], spaced_toks[lp + 1 : rp])
        assert sig_spaced["is_variadic"] is True

    def test_dot_directories_pruning_in_tree_and_compile_commands(self, tmp_path: Path) -> None:
        import json

        # Create directories: real include vs dot-directories
        inc_real = tmp_path / "include"
        inc_real.mkdir(parents=True)
        (inc_real / "api.h").write_text("int api_call(void);\n", encoding="utf-8")

        dot_build = tmp_path / ".build" / "headers"
        dot_build.mkdir(parents=True)
        (dot_build / "cached.h").write_text("int cached_call(void);\n", encoding="utf-8")

        dot_cache = tmp_path / ".cache"
        dot_cache.mkdir(parents=True)
        (dot_cache / "stale.h").write_text("int stale_call(void);\n", encoding="utf-8")

        src_dir = tmp_path / "src"
        src_dir.mkdir(parents=True)
        src_c = src_dir / "app.c"
        src_c.write_text('#include "api.h"\nint app_run(void) { return api_call(); }\n', encoding="utf-8")

        # In-tree discovery skips .build and .cache
        disc = discover_in_tree_cppflags(tmp_path, [src_c])
        assert any("include" in fl for fl in disc.get("src/app.c", []))
        assert not any(".build" in fl or ".cache" in fl for fl in disc.get("src/app.c", []))

        # Fallback discovery skips .build and .tmp C files
        dot_c1 = tmp_path / ".build" / "gen.c"
        dot_c1.write_text("int gen_fn(void) { return 1; }\n", encoding="utf-8")
        dot_c2 = tmp_path / ".tmp" / "tmp.c"
        dot_c2.parent.mkdir(parents=True)
        dot_c2.write_text("int tmp_fn(void) { return 2; }\n", encoding="utf-8")

        dag = build_dag(tmp_path)
        assert "app_run" in dag["functions"]
        assert "gen_fn" not in dag["functions"]
        assert "tmp_fn" not in dag["functions"]

        # compile_commands.json ingestion skips dot-directory entries
        cc = tmp_path / "compile_commands.json"
        cc_entries = [
            {"directory": str(tmp_path), "file": "src/app.c", "command": "clang -c -Iinclude src/app.c"},
            {"directory": str(tmp_path), "file": ".build/gen.c", "command": "clang -c .build/gen.c"},
            {"directory": str(tmp_path), "file": "sub/.cache/extra.c", "command": "clang -c sub/.cache/extra.c"},
        ]
        cc.write_text(json.dumps(cc_entries), encoding="utf-8")
        dag_cc = build_dag(tmp_path, compile_commands_path=cc)
        assert "app_run" in dag_cc["functions"]
        assert "gen_fn" not in dag_cc["functions"]

    def test_main_and_harness_disambiguation_across_multiple_files(self, tmp_path: Path) -> None:
        src_a = tmp_path / "src" / "tool_a"
        src_b = tmp_path / "src" / "tool_b"
        src_a.mkdir(parents=True)
        src_b.mkdir(parents=True)

        (src_a / "main.c").write_text("int main(void) { return 1; }\n", encoding="utf-8")
        (src_b / "main.c").write_text("int main(int argc, char **argv) { return argc; }\n", encoding="utf-8")

        dag = build_dag(tmp_path)
        assert len(dag["name_collisions"]) >= 1
        assert any(c["function"] == "main" for c in dag["name_collisions"])

        # Both definitions must be retained with disambiguated file keys
        key_a = "src/tool_a/main.c#main"
        key_b = "src/tool_b/main.c#main"
        assert key_a in dag["functions"]
        assert key_b in dag["functions"]
        assert dag["functions"][key_a]["file"] == "src/tool_a/main.c"
        assert dag["functions"][key_b]["file"] == "src/tool_b/main.c"

        # Module function lists contain their respective disambiguated keys
        assert key_a in dag["modules"]["tool_a"]["functions"]
        assert key_b in dag["modules"]["tool_b"]["functions"]

    def test_library_module_excludes_main_and_harness_from_required_sources(self, tmp_path: Path) -> None:
        lib_dir = tmp_path / "src" / "codec"
        lib_dir.mkdir(parents=True)
        (lib_dir / "codec.h").write_text("int codec_decode(const char *in);\n", encoding="utf-8")
        (lib_dir / "codec.c").write_text(
            '#include "codec.h"\nint codec_decode(const char *in) { return in != 0; }\n',
            encoding="utf-8",
        )
        # Standalone runner in same module
        (lib_dir / "main.c").write_text(
            '#include "codec.h"\nint main(void) { return codec_decode("test"); }\n',
            encoding="utf-8",
        )
        # Existing fuzz harness file in same module
        (lib_dir / "fuzz_target.c").write_text(
            '#include "codec.h"\n#include <stdint.h>\n#include <stddef.h>\n'
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return codec_decode((const char *)data); }\n",
            encoding="utf-8",
        )

        # Another module that calls codec_decode
        caller_dir = tmp_path / "src" / "service"
        caller_dir.mkdir(parents=True)
        (caller_dir / "service.c").write_text(
            '#include "codec.h"\nint handle_request(const char *req) { return codec_decode(req); }\n',
            encoding="utf-8",
        )

        dag = build_dag(tmp_path)
        codec_mod = dag["modules"]["codec"]
        service_mod = dag["modules"]["service"]

        # codec module files list includes all 3 files
        assert "src/codec/codec.c" in codec_mod["files"]
        assert "src/codec/main.c" in codec_mod["files"]
        assert "src/codec/fuzz_target.c" in codec_mod["files"]

        # But required_sources for codec library MUST exclude main.c and fuzz_target.c
        assert codec_mod["required_sources"] == ["src/codec/codec.c"]

        # service module calls codec_decode: required_sources must only pull codec.c, not main.c or fuzz_target.c
        assert "src/service/service.c" in service_mod["required_sources"]
        assert "src/codec/codec.c" in service_mod["required_sources"]
        assert "src/codec/main.c" not in service_mod["required_sources"]
        assert "src/codec/fuzz_target.c" not in service_mod["required_sources"]
        assert service_mod["cross_module_callees"] == ["codec_decode"]

    def test_macro_callee_and_macro_loop_detection(self, tmp_path: Path) -> None:
        from build_callgraph_dag import extract_macro_definitions

        src = """\
#define ADVANCE_TOKEN(tok, toklen) do { \\
    while (1) { \\
        tok = findchar_fast(tok, buf_end, ranges, sizeof(ranges) - 1, &found); \\
        if (found) break; \\
    } \\
} while (0)

static const char *findchar_fast(const char *buf, const char *buf_end, const char *ranges, int rlen, int *found) {
    *found = 1;
    return buf;
}

static const char *parse_token(const char *buf, const char *buf_end, const char **tok, int *toklen) {
    int found = 0;
    const char ranges[] = "\\x00 ";
    ADVANCE_TOKEN(buf, *toklen);
    return buf;
}
"""
        macros = extract_macro_definitions(src)
        assert "ADVANCE_TOKEN" in macros
        assert "findchar_fast" in macros["ADVANCE_TOKEN"]["callees"]
        assert macros["ADVANCE_TOKEN"]["loop_count"] == 1

        src_dir = tmp_path / "src"
        src_dir.mkdir(parents=True)
        (src_dir / "parser.c").write_text(src, encoding="utf-8")

        dag = build_dag(tmp_path)
        fn_parse = dag["functions"]["parse_token"]
        assert "findchar_fast" in fn_parse["internal_callees"]
        assert fn_parse["has_loops"] is True
        assert fn_parse["loop_count"] == 1
        assert fn_parse["macro_loops"] == ["ADVANCE_TOKEN"]
        assert any("ADVANCE_TOKEN" in note for note in fn_parse["wp_notes"])
        # Topological wave must place findchar_fast before parse_token
        assert dag["functions"]["findchar_fast"]["wave"] < fn_parse["wave"]

    def test_cross_module_symbol_closure_through_global_tables_callbacks_and_header_inlines(
        self, tmp_path: Path
    ) -> None:
        from build_callgraph_dag import extract_file_scope_objects

        inc_dir = tmp_path / "include"
        inc_dir.mkdir(parents=True)
        (inc_dir / "api.h").write_text(
            """\
#ifndef API_H
#define API_H
struct TagEntry {
    int tag_id;
    int (*cb)(const unsigned char *buf, unsigned int len);
};
extern const struct TagEntry GlobalTagTable[];
int number_decode_value(const unsigned char *buf, unsigned int len);
int spiffy_helper(const unsigned char *buf, unsigned int len);

static inline int inline_decode_wrapper(const unsigned char *buf, unsigned int len) {
    return number_decode_value(buf, len);
}
#endif
""",
            encoding="utf-8",
        )

        src_dir = tmp_path / "src"
        src_dir.mkdir(parents=True)

        # Module 1: spiffy_decode.c defines leaf helper called by tag_decode.c
        (src_dir / "spiffy_decode.c").write_text(
            """\
#include "api.h"
int spiffy_helper(const unsigned char *buf, unsigned int len) {
    return len > 0 ? buf[0] : 0;
}
""",
            encoding="utf-8",
        )

        # Module 2: tag_decode.c defines callback functions and an exported file-scope dispatch table
        tag_code = """\
#include "api.h"
int tag_cb_bignum(const unsigned char *buf, unsigned int len) {
    return spiffy_helper(buf, len);
}
const struct TagEntry GlobalTagTable[] = {
    { .tag_id = 2, .cb = tag_cb_bignum },
    { .tag_id = 0, .cb = 0 }
};
"""
        (src_dir / "tag_decode.c").write_text(tag_code, encoding="utf-8")

        objs = extract_file_scope_objects(tag_code, "src/tag_decode.c")
        assert len(objs) == 1
        assert objs[0]["name"] == "GlobalTagTable"
        assert objs[0]["is_static"] is False
        assert "tag_cb_bignum" in objs[0]["refs"]
        assert "tag_id" not in objs[0]["refs"]

        # Module 3: number_decode.c passes callback identifier `tag_cb_bignum` without `(`
        (src_dir / "number_decode.c").write_text(
            """\
#include "api.h"
static int run_cb(int (*fn)(const unsigned char *, unsigned int), const unsigned char *b, unsigned int n) {
    return fn(b, n);
}
int number_decode_value(const unsigned char *buf, unsigned int len) {
    return run_cb(tag_cb_bignum, buf, len);
}
""",
            encoding="utf-8",
        )

        # Module 4: main_decode.c references `GlobalTagTable` (as a value) and calls `inline_decode_wrapper`
        (src_dir / "main_decode.c").write_text(
            """\
#include "api.h"
static int register_table(const struct TagEntry *tbl) {
    return tbl != 0 ? tbl[0].tag_id : -1;
}
int main_decode_entry(const unsigned char *buf, unsigned int len) {
    int rc = register_table(GlobalTagTable);
    return rc + inline_decode_wrapper(buf, len);
}
""",
            encoding="utf-8",
        )

        dag = build_dag(tmp_path)
        assert dag["header_inline_callees"]["inline_decode_wrapper"] == ["number_decode_value"]

        # number_decode references tag_cb_bignum as a callback pointer -> pulls tag_decode.c and transitively spiffy_decode.c
        num_mod = dag["modules"]["number_decode"]
        assert num_mod["required_sources"] == [
            "src/number_decode.c",
            "src/spiffy_decode.c",
            "src/tag_decode.c",
        ]
        assert "tag_cb_bignum" in num_mod["cross_module_callees"]
        assert "spiffy_helper" in num_mod["cross_module_callees"]

        # main_decode references GlobalTagTable and calls inline_decode_wrapper -> pulls tag_decode.c, spiffy_decode.c, and number_decode.c
        main_mod = dag["modules"]["main_decode"]
        assert main_mod["required_sources"] == [
            "src/main_decode.c",
            "src/number_decode.c",
            "src/spiffy_decode.c",
            "src/tag_decode.c",
        ]
        assert "inline_decode_wrapper" not in main_mod["external_callees"]
        assert "number_decode_value" in main_mod["cross_module_callees"]
        assert "tag_cb_bignum" in main_mod["cross_module_callees"]
        assert "spiffy_helper" in main_mod["cross_module_callees"]

        # Verify generate_module_harness also resolves header inline wrappers / callees in --call-expr
        import json

        from generate_harness import generate_module_harness

        reports_dir = tmp_path / "workspace" / "reports"
        harnesses_dir = tmp_path / "workspace" / "harnesses"
        reports_dir.mkdir(parents=True)
        (reports_dir / "callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")

        res = generate_module_harness(
            module_name="spiffy_decode",
            sources=["workspace/work/src/spiffy_decode.c"],
            header_include="api.h",
            entry_fn="spiffy_helper",
            max_input_size=256,
            cppflags="-Iinclude",
            out_dir=harnesses_dir,
            entry_style="custom",
            call_expr="spiffy_helper(fuzz_buf, (unsigned int)fuzz_len); inline_decode_wrapper(fuzz_buf, (unsigned int)fuzz_len);",
            auto_prelude=False,
        )
        assert res["sources"] == [
            "workspace/work/src/spiffy_decode.c",
            "workspace/work/src/number_decode.c",
            "workspace/work/src/tag_decode.c",
        ]

        # When /framac-run/ prefixes are passed in sources and cppflags,
        # generate_module_harness normalizes and deduplicates them against required_sources.
        sliced_dag = {
            "modules": {
                "lib": {
                    "files": ["src/lib/parse.c", "src/lib/buf.c"],
                    "required_sources": ["src/lib/parse.c", "src/lib/buf.c"],
                    "cppflags": ["-I/framac-run/workspace/work/include"],
                }
            },
            "functions": {
                "dns_parse": {"file": "src/lib/parse.c", "module": "lib", "callees": ["buf_read"]},
                "buf_read": {"file": "src/lib/buf.c", "module": "lib", "callees": []},
            },
            "header_inline_callees": {},
        }
        (reports_dir / "callgraph_dag.json").write_text(json.dumps(sliced_dag), encoding="utf-8")
        sliced_res = generate_module_harness(
            module_name="lib",
            sources=["/framac-run/workspace/work/src/lib/parse.c"],
            header_include="none",
            entry_fn="dns_parse",
            max_input_size=256,
            cppflags="-I/framac-run/workspace/work/include",
            out_dir=harnesses_dir,
            entry_style="custom",
            call_expr="dns_parse(fuzz_buf, fuzz_len);",
            auto_prelude=False,
        )
        assert sliced_res["sources"] == [
            "workspace/work/src/lib/parse.c",
            "workspace/work/src/lib/buf.c",
        ]
        assert sliced_res["cppflags"].count("-Iworkspace/work/include") == 1
        assert "/framac-run" not in sliced_res["cppflags"]


class TestParenthesizedDeclarators:
    """Regression tests for PB-1: function-pointer-returning / parenthesized declarators."""

    def test_all_declarator_shapes_resolve_the_real_name(self) -> None:
        cases = {
            "int foo(int a) { return a; }": "foo",
            "void *bar(size_t n) { return 0; }": "bar",
            "void *(baz)(size_t c, void **a) { return 0; }": "baz",
            "int (*qux(int a))(char) { return 0; }": "qux",
            "void (*(quux)(size_t c, void **a)) { return; }": "quux",
            "int (corge)(int x) { return x; }": "corge",
            "static void (*(alloc)(size_t count, void **abstract)) { return; }": "alloc",
        }
        for src, expected in cases.items():
            names = [f["name"] for f in extract_functions_from_code(src, path="<t>")]
            assert names == [expected], f"{src!r} -> {names}"

    def test_type_keywords_are_never_function_names(self) -> None:
        src = "static void (*(ssh2_default_alloc)(size_t count, void **abstract)) { return; }\n"
        names = [f["name"] for f in extract_functions_from_code(src, path="<t>")]
        assert names == ["ssh2_default_alloc"]
        assert "void" not in names

    def test_macro_wrapped_definition_resolves_real_name(self) -> None:
        from build_callgraph_dag import _resolve_macro_wrapped_definitions, extract_macro_definitions

        src = """\
#define LIBSSH2_ALLOC_FUNC(name) void (*(name)(size_t count, void **abstract))
static LIBSSH2_ALLOC_FUNC(ssh2_default_alloc) { return 0; }
static LIBSSH2_ALLOC_FUNC(ssh2_default_free) { return; }
"""
        macros = extract_macro_definitions(src, path="<t>")
        assert macros["LIBSSH2_ALLOC_FUNC"]["params"] == ["name"]
        items = _resolve_macro_wrapped_definitions(extract_functions_from_code(src, path="<t>"), macros)
        names = [i["name"] for i in items]
        assert names == ["ssh2_default_alloc", "ssh2_default_free"]
        assert "LIBSSH2_ALLOC_FUNC" not in names
        # The real parameter list comes from the macro body, not the macro argument.
        assert [t.text for t in items[0]["param_tokens"]][:2] == ["size_t", "count"]


class TestForeignPathMapping:
    """Regression tests for PB-2: compile_commands recorded against another root."""

    def test_map_foreign_path_suffix_match(self, tmp_path: Path) -> None:
        from build_callgraph_dag import _map_foreign_path

        overlay = tmp_path / "work"
        (overlay / "src").mkdir(parents=True)
        (overlay / "src" / "misc.c").write_text("int x;\n", encoding="utf-8")
        foreign = tmp_path / "target"
        (foreign / "src").mkdir(parents=True)
        (foreign / "src" / "misc.c").write_text("int x;\n", encoding="utf-8")
        assert _map_foreign_path(foreign / "src" / "misc.c", overlay) == "src/misc.c"
        assert _map_foreign_path(foreign / "elsewhere" / "misc.c", overlay) == "misc.c"

    def test_build_dag_maps_foreign_compile_commands_into_overlay(self, tmp_path: Path) -> None:
        overlay = tmp_path / "work"
        (overlay / "src").mkdir(parents=True)
        (overlay / "src" / "session.c").write_text(
            "int libssh2_session_init_ex(void) { return ssh2_init_if_needed(); }\n", encoding="utf-8"
        )
        (overlay / "src" / "global.c").write_text("int ssh2_init_if_needed(void) { return 0; }\n", encoding="utf-8")
        foreign = tmp_path / "target"
        (foreign / "src").mkdir(parents=True)
        (foreign / "src" / "session.c").write_text("int x;\n", encoding="utf-8")
        (foreign / "src" / "global.c").write_text("int y;\n", encoding="utf-8")
        cc = tmp_path / "compile_commands.json"
        cc.write_text(
            json.dumps(
                [
                    {
                        "directory": str(foreign),
                        "file": str(foreign / "src" / "session.c"),
                        "command": "clang -c -Iinclude src/session.c",
                    },
                    {
                        "directory": str(foreign),
                        "file": str(foreign / "src" / "global.c"),
                        "command": "clang -c -Iinclude src/global.c",
                    },
                ]
            ),
            encoding="utf-8",
        )
        dag = build_dag(overlay, cc)
        files = {rec["file"] for rec in dag["functions"].values()}
        assert files == {"src/session.c", "src/global.c"}
        assert dag["modules"]["session"]["files"] == ["src/session.c"]
        assert "src/global.c" in dag["modules"]["session"]["required_sources"]


class TestPreflightWarningsAndPrototypeExtraction:
    """Tests for C prototype extraction, multidimensional VLA detection, and param count mismatch warnings."""

    def test_extract_prototypes_handles_declarations_and_skips_typedefs(self) -> None:
        src = """\
#include <stdint.h>

/* Typedef must be skipped */
typedef void (*Callback_T)(int a, int b);
typedef struct State_T State_T;

/* Struct declaration must be skipped */
struct Point { int x; int y; };

/* Function prototypes */
int parse_header(const uint8_t *buf, size_t len);
void process_matrix(double matrix[10][20]);
extern void reset_device(void);

/* Definition should be skipped during prototype extraction */
int helper(int x) {
    return x + 1;
}
"""
        protos = extract_prototypes_from_code(src, path="test.h")
        names = [p["name"] for p in protos]
        assert names == ["parse_header", "process_matrix", "reset_device"]

    def test_multidimensional_vla_preflight_warning(self, tmp_path: Path, capsys) -> None:
        src_dir = tmp_path / "src" / "reader"
        src_dir.mkdir(parents=True)
        (src_dir / "TypesReader.h").write_text(
            """\
typedef double DOUBLE;
#define MaxRows 10
#define MaxCols 20

void ReadData(int id, DOUBLE GstBufferField[MaxRows][MaxCols]);
""",
            encoding="utf-8",
        )
        (src_dir / "TypesReader.c").write_text(
            """\
#include "TypesReader.h"
void ReadData(int id, DOUBLE GstBufferField[MaxRows][MaxCols]) {
    (void)id;
    (void)GstBufferField;
}
""",
            encoding="utf-8",
        )

        dag = build_dag(tmp_path)
        err = capsys.readouterr().err

        assert "warnings" in dag
        vla_warns = [w for w in dag["warnings"] if "multidimensional array/VLA" in w]
        assert len(vla_warns) >= 1
        assert "ReadData" in vla_warns[0]
        assert "TypesReader.h" in vla_warns[0]
        assert "multidimensional array/VLA parameter in function prototype 'ReadData'" in err

    def test_prototype_definition_param_count_mismatch_warning(self, tmp_path: Path, capsys) -> None:
        src_dir = tmp_path / "src" / "steering"
        src_dir.mkdir(parents=True)
        (src_dir / "steering.h").write_text(
            """\
void Stop_Steering(int channel, int speed);
""",
            encoding="utf-8",
        )
        (src_dir / "steering.c").write_text(
            """\
#include "steering.h"
void Stop_Steering(int channel, int speed, int force) {
    (void)channel; (void)speed; (void)force;
}
""",
            encoding="utf-8",
        )

        dag = build_dag(tmp_path)
        err = capsys.readouterr().err

        mismatch_warns = [w for w in dag["warnings"] if "parameter count mismatch" in w]
        assert len(mismatch_warns) == 1
        assert "Stop_Steering" in mismatch_warns[0]
        assert "prototype has 2 parameter(s)" in mismatch_warns[0]
        assert "definition has 3 parameter(s)" in mismatch_warns[0]
        assert "parameter count mismatch for 'Stop_Steering'" in err

    def test_clean_project_emits_no_warnings(self, tmp_path: Path, capsys) -> None:
        src_dir = tmp_path / "src" / "clean"
        src_dir.mkdir(parents=True)
        (src_dir / "clean.h").write_text(
            """\
int add(int a, int b);
void ping(void);
""",
            encoding="utf-8",
        )
        (src_dir / "clean.c").write_text(
            """\
#include "clean.h"
int add(int a, int b) { return a + b; }
void ping(void) {}
""",
            encoding="utf-8",
        )

        dag = build_dag(tmp_path)
        err = capsys.readouterr().err
        assert dag["warnings"] == []
        assert err == ""
