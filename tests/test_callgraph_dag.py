"""Tests for scripts/build_callgraph_dag.py (token-driven extraction, Tarjan SCC, structural tiers, and WP blockers)."""

from __future__ import annotations

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
        assert 2 in layers  # loop termination
        assert 6 in layers  # structural memory zeroization
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

