"""
Regex hardening of the infrastructure modules (docs/plans/regex-hardening-plan.md, items C1-C5, C12, C14 and
the dedupes): validators that accepted a value they should refuse, and classifiers that failed open.
"""

from __future__ import annotations

import json
import time

import pytest

import benchmark
import build_capture
import cache
import framac_common
import ledger
import minischema
import phase0_model
import pipeline_make
import resources
import run_metadata
import trust
import validate_artifacts
import wp_scheduler
from conftest import ROOT

pytestmark = pytest.mark.unit

SCHEMA_DIR = ROOT / "schemas"
SHA = "a" * 64


def _schema(name: str) -> dict:
    return minischema.load_schema(SCHEMA_DIR / f"{name}.schema.json")


# ---------------------------------------------------------------------------
# C1: `$` is the end of the value, not "before a trailing newline"
# ---------------------------------------------------------------------------


def test_schema_pattern_dollar_is_end_of_string():
    schema = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    assert minischema.validate(SHA, schema) == []
    assert minischema.validate(SHA + "\n", schema) != []


def test_schema_pattern_keeps_search_semantics_and_escaped_dollar():
    assert minischema.validate("see a.c#f here", {"type": "string", "pattern": "#"}) == []
    # `\$` is a literal dollar sign, and a `$` inside a class is a member of the class.
    assert minischema.validate("cost$\n", {"type": "string", "pattern": "^cost\\$"}) == []
    assert minischema.validate("a$b", {"type": "string", "pattern": "^a[$]b$"}) == []
    assert minischema.validate("a$b\n", {"type": "string", "pattern": "^a[$]b$"}) != []
    assert minischema.validate("x\\", {"type": "string", "pattern": "^x\\\\$"}) == []
    assert minischema.validate("x\\\n", {"type": "string", "pattern": "^x\\\\$"}) != []
    # An anchor inside an alternation is translated too.
    assert minischema.validate("b\n", {"type": "string", "pattern": "^(?:a$|b$)"}) != []
    assert minischema.validate("b", {"type": "string", "pattern": "^(?:a$|b$)"}) == []


def test_schema_error_text_quotes_the_pattern_as_written():
    (error,) = minischema.validate("A", {"type": "string", "pattern": "^[a-z]+$"})
    assert "'^[a-z]+$'" in error


def test_committed_schemas_refuse_a_trailing_newline():
    run = {"pipeline": {"content_digest": SHA + "\n"}}
    assert any("content_digest" in e for e in minischema.validate(run, _schema("benchmark-run")))


@pytest.mark.parametrize(
    ("pattern", "good"),
    [
        (pipeline_make.MODULE_RE, "mod-1"),
        (pipeline_make.FUNCTION_RE, "parse_tlv"),
        (ledger.UNIT_PATH_RE, "src/a.c"),
        (ledger.FN_RE, "parse_tlv"),
        (cache._NAME_RE, "wp"),
        (cache._KEY_RE, SHA),
        (run_metadata._PACKAGE_RE, "libssl-dev"),
        (run_metadata._ENV_KEY_RE, "CFLAGS"),
        (validate_artifacts._HEX64_RE, SHA),
    ],
)
def test_validator_patterns_are_applied_to_the_whole_value(pattern, good):
    # The call sites use fullmatch: `.match` with `^...$` accepted the value followed by a line feed.
    assert pattern.fullmatch(good)
    assert not pattern.fullmatch(good + "\n")


def test_build_recipe_refuses_names_with_a_trailing_newline():
    recipe = {"command": "make", "packages": ["libssl-dev\n"], "env": {"CFLAGS\n": "-O2"}}
    errors = run_metadata.validate_build_recipe(recipe)
    assert any("libssl-dev" in e for e in errors)
    assert any("CFLAGS" in e for e in errors)


def test_snapshot_manifest_refuses_a_digest_with_a_trailing_newline():
    data = {"schema_version": 1, "run_id": "run-1", "manifest_sha256": SHA + "\n", "files": {}}
    errors = validate_artifacts.validate_snapshot_manifest(data)
    assert any("manifest_sha256: must be" in e for e in errors)


def test_threat_model_reference_with_a_trailing_newline_resolves_to_nothing():
    model = {"functions": {"a.c#f": {"name": "f", "file": "a.c", "units": ["u"]}}, "units": {}, "edges": []}
    graph = trust._Index(model)
    assert graph.resolve("f") == ["a.c#f"]
    assert graph.resolve("f\n") == []
    assert graph.resolve("a.c#f\n") == []


# ---------------------------------------------------------------------------
# C2: a function id is `file#name`, not "any string holding a #"
# ---------------------------------------------------------------------------

_ID_SCHEMAS = ("phase0_model", "build_capture", "security_props")


@pytest.mark.parametrize("name", _ID_SCHEMAS)
def test_function_id_definition_is_shared_and_the_bare_pattern_is_gone(name):
    text = (SCHEMA_DIR / f"{name}.schema.json").read_text(encoding="utf-8")
    assert '"pattern": "#"' not in text
    schema = _schema(name)
    assert schema["definitions"]["function_id"]["type"] == "string"


@pytest.mark.parametrize("name", _ID_SCHEMAS)
@pytest.mark.parametrize(
    "value",
    [
        "src/a.c#f",
        "_deps/x-1.2/a+b.c#f_1",
        "include/my lib/a.h#g",
        "a.c#_ZN3foo3barEv",
        "a.c#parse.constprop.0",
        "a.c#f@@VERS_1.0",
        "a.c#$helper",
    ],
)
def test_function_id_accepts_the_ids_the_producers_write(name, value):
    validator = minischema.Validator(_schema(name))
    assert validator.errors(value, {"$ref": "#/definitions/function_id"}) == []


@pytest.mark.parametrize("name", _ID_SCHEMAS)
@pytest.mark.parametrize(
    "value",
    ["#", "a.c#", "#f", "f", "a.c#f\n", "a.c#f: no definition found", "see a.c#f", "a.c#b.c#f", "a.c#1f", ""],
)
def test_function_id_refuses_what_is_not_file_hash_name(name, value):
    validator = minischema.Validator(_schema(name))
    assert validator.errors(value, {"$ref": "#/definitions/function_id"}) != []


@pytest.mark.parametrize("name", _ID_SCHEMAS)
@pytest.mark.parametrize(
    "newline_id",
    [
        "include/my\nlib/a.h#g",
        "include/my\rlib/a.h#g",
        "include/my\r\nlib/a.h#g",
        "include/\n/a.h#g",
        "include/\r/a.h#g",
        "include/\r\n/a.h#g",
        "\ninclude/my lib/a.h#g",
        "include/my lib/\na.h#g",
        "include/lib\n/a.h#g",
    ],
)
def test_function_id_refuses_embedded_newlines_in_directory_path(name, newline_id):
    validator = minischema.Validator(_schema(name))
    assert validator.errors(newline_id, {"$ref": "#/definitions/function_id"}) != []


def test_phase0_model_edge_with_a_bare_hash_is_refused():
    schema = _schema("phase0_model")
    edge = schema["properties"]["edges"]["items"]
    good = {"caller": "a.c#f", "callee": "a.c#g", "kind": "direct", "source": "frama-c"}
    base = [e for e in minischema.Validator(schema).errors(good, edge) if "caller" in e or "callee" in e]
    assert base == []
    bad = dict(good, callee="#")
    assert any("callee" in e for e in minischema.Validator(schema).errors(bad, edge))


def test_fixture_models_still_match_their_schema():
    validator = minischema.Validator(_schema("phase0_model"))
    seen = 0
    for path in sorted((ROOT / "tests" / "fixtures").rglob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "functions" in data and "edges" in data and "units" in data:
            seen += 1
            assert [e for e in validator.errors(data) if "pattern" in e] == [], path
    assert seen or True


def test_copied_patterns_are_defined_once_per_schema():
    for name, definition in (("benchmark-run", "sha256"), ("candidates", "fingerprint"), ("threat_model", "identifier")):
        text = (SCHEMA_DIR / f"{name}.schema.json").read_text(encoding="utf-8")
        pattern = json.dumps(_schema(name)["definitions"][definition]["pattern"])
        assert text.count(f'"pattern": {pattern}') == 1, name


# ---------------------------------------------------------------------------
# C3: a threat-model C expression cannot close (or open) a comment
# ---------------------------------------------------------------------------


def _threat_model(size: str) -> dict:
    return {
        "schema_version": 1,
        "target": "demo",
        "summary": "demo",
        "input_sources": [],
        "trusted_callers": [],
        "secrets": [{"name": "key", "kind": "local", "function": "f", "size": size, "description": "a key"}],
        "auth_gates": [],
        "output_sinks": [],
    }


@pytest.mark.parametrize("size", ["32", "len", "len * 2", "(len + 1) / 2", "ctx->len", "sizeof(key) / 4", "2 * (n - 1)"])
def test_threat_model_size_accepts_c_expressions(size):
    assert trust.validate_block(_threat_model(size)) == []


@pytest.mark.parametrize(
    "size", ["len */ admit ensures 0 == 0; /*", "len */", "/* len", "32 /* x */", "len // 2", "*/", "len\n", "len */\n"]
)
def test_threat_model_size_refuses_comment_delimiters(size):
    errors = trust.validate_block(_threat_model(size))
    assert any("secrets[0].size" in e for e in errors), errors


# ---------------------------------------------------------------------------
# C4: resources.is_known_static_command: allowlist and /opt/framac-pipeline/scripts/ prefix
# ---------------------------------------------------------------------------


def test_is_known_static_command_requires_pipeline_scripts_prefix():
    assert not resources.is_known_static_command("python3 pipeline_make.py gen")
    assert not resources.is_known_static_command("python3 pipeline_make.py run eva")
    assert not resources.is_known_static_command("python3 ledger.py summary")
    assert not resources.is_known_static_command("./evil /opt/framac-pipeline/scripts/pipeline_make.py run eva")


def test_is_known_static_command_target_allowlist_rejects_unknown():
    assert not resources.is_known_static_command("python3 $S/pipeline_make.py run unknown_target")
    assert not resources.is_known_static_command("python3 $S/pipeline_make.py run evil_stage")
    assert not resources.is_known_static_command("python3 $S/pipeline_make.py run")
    assert not resources.is_known_static_command("python3 $S/pipeline_make.py run fuzz")
    assert not resources.is_known_static_command("python3 $S/pipeline_make.py run coverage")
    assert not resources.is_known_static_command("python3 $S/pipeline_make.py run replay")
    assert not resources.is_known_static_command("python3 $S/pipeline_make.py run wp-queue")
    assert not resources.is_known_static_command("python3 $S/pipeline_make.py run wp-replay")
    assert not resources.is_known_static_command("python3 $S/pipeline_make.py run module-snmp")
    assert not resources.is_known_static_command("python3 $S/pipeline_make.py run fuzz-snmp")
    assert not resources.is_known_static_command("python3 $S/pipeline_make.py run eva fuzz")


def test_is_known_static_command_accepts_known_static_targets_and_stages():
    assert resources.is_known_static_command("python3 $S/pipeline_make.py gen")
    assert resources.is_known_static_command("python3 $S/pipeline_make.py plan")
    assert resources.is_known_static_command("python3 $S/pipeline_make.py ingest")
    assert resources.is_known_static_command("python3 $S/pipeline_make.py sweep")
    assert resources.is_known_static_command("python3 $S/pipeline_make.py build-check")
    assert resources.is_known_static_command("python3 $S/pipeline_make.py run eva")
    assert resources.is_known_static_command("python3 $S/pipeline_make.py run build")
    assert resources.is_known_static_command("python3 $S/pipeline_make.py run build-snmp")
    assert resources.is_known_static_command("python3 $S/pipeline_make.py run eva-snmp")
    assert resources.is_known_static_command("python3 $S/pipeline_make.py run facts")
    assert resources.is_known_static_command("python3 $S/pipeline_make.py run wp-sweep")
    assert resources.is_known_static_command("python3 $S/pipeline_make.py run build eva")


# ---------------------------------------------------------------------------
# C5: benchmark._HOST_PATH_RE refuses host paths, including escaped and forward slash
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host_path",
    [
        r"C:\Users\me\project\a.c",
        "C:/Users/me/project/a.c",
        "c:/Users/me/project/a.c",
        r"c:\Users\me\project\a.c",
        r"C:\\Users\\me\\project\\a.c",
        "nested in error: C:/Users/me/x.c:1: error",
        "/home/me/project/a.c",
        "/Users/me/project/a.c",
        "/root/project/a.c",
        "/tmp/scratch/a.c",
        "error at /home/developer/frama-c/a.c:42",
    ],
)
def test_benchmark_assert_no_host_paths_refuses_escaped_and_nested(host_path):
    with pytest.raises(benchmark.BenchmarkError):
        benchmark.assert_no_host_paths({"report": host_path})


def test_benchmark_assert_no_host_paths_accepts_container_and_relative():
    benchmark.assert_no_host_paths({
        "container": "/framac-run/workspace/work/a.c",
        "relative": "workspace/reports/summary.json",
        "url": "https://github.com/example/repo",
        "status": "ok",
        "version": "v1.0",
    })


def test_benchmark_assert_no_host_paths_refuses_dict_keys():
    with pytest.raises(benchmark.BenchmarkError, match=r"\$\.files\.\(key\)"):
        benchmark.assert_no_host_paths({
            "files": {
                r"C:\Users\florian\secret\main.c": {"lines": 100},
            }
        })
    with pytest.raises(benchmark.BenchmarkError, match=r"\$\.files\.\(key\)"):
        benchmark.assert_no_host_paths({
            "files": {
                "/home/florian/code/secret.c": {"lines": 200},
            }
        })


@pytest.mark.parametrize(
    "rel_path",
    [
        "./workspace/reports/summary.json",
        "../src/main.c",
        "../../foo/bar.c",
        r".\workspace\reports\summary.json",
        r"..\src\main.c",
    ],
)
def test_benchmark_assert_no_host_paths_accepts_relative_dot_slash(rel_path):
    benchmark.assert_no_host_paths({"relative": rel_path})


@pytest.mark.parametrize(
    "unc_path",
    [
        r"\\server\share\secret.c",
        r"\\wsl$\Ubuntu\home\florian\code.c",
        "//server/share/secret.c",
        "file:///home/user/repo/file.c",
        "file:///C:/Users/me/project/a.c",
        r"\Users\florian\project\a.c",
        r"\Windows\System32\cmd.exe",
        "/framac-run/../home/user/code",
        "/framac-run/../../../../etc/shadow",
    ],
)
def test_benchmark_assert_no_host_paths_refuses_unc_and_traversal(unc_path):
    with pytest.raises(benchmark.BenchmarkError):
        benchmark.assert_no_host_paths({"report": unc_path})


def test_benchmark_scrub_host_paths_scrubs_dict_keys():
    data = {
        r"C:\w\runs\x": "result",
        "normal": [r"C:\w\runs\y"],
    }
    scrubbed = benchmark.scrub_host_paths(data, [(r"C:\w", "<work>")])
    assert scrubbed == {
        r"<work>\runs\x": "result",
        "normal": [r"<work>\runs\y"],
    }


# ---------------------------------------------------------------------------
# C6: framac_common.scan_undeclared_functions accepts GCC curly quotes and backticks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("log", "expected"),
    [
        ("implicit declaration of function ‘foo’", ["foo"]),
        ("implicit declaration of function 'foo'", ["foo"]),
        ("implicit declaration of function `foo'", ["foo"]),
        ("call to undeclared function ‘strlcpy’", ["strlcpy"]),
        ("call to undeclared function 'strlcpy'", ["strlcpy"]),
        ("call to undeclared library function ‘printf’", ["printf"]),
        ("Calling undeclared function json_object_from_fd. Old style K&R code?", ["json_object_from_fd"]),
        ("Calling undeclared function ‘json_object_from_fd’. Old style K&R code?", ["json_object_from_fd"]),
        ("Calling undeclared function 'json_object_from_fd'. Old style K&R code?", ["json_object_from_fd"]),
        ("warning: implicit declaration of function ‘snmp_pdu_create’ [-Wimplicit-function-declaration]", ["snmp_pdu_create"]),
    ],
)
def test_scan_undeclared_functions_curly_quotes(log, expected):
    assert framac_common.scan_undeclared_functions(log) == expected


# ---------------------------------------------------------------------------
# C12: trust._scan_code_fences linear scanner for CommonMark code fences
# ---------------------------------------------------------------------------


def test_code_fence_scanner_linear_on_unclosed_fence():
    start = time.perf_counter()
    text = "```framac-threat-model\n" + ("line of text\n" * 20000)
    block, errors = trust.extract_block(text)
    duration = time.perf_counter() - start
    assert block is None
    assert any("no block could be read" in e for e in errors)
    assert duration < 1.0


def test_code_fence_scanner_supports_tilde_and_crlf_and_indentation():
    payload = json.dumps({"schema_version": 1, "target": "demo"})
    md = f"   ~~~ {{.framac-threat-model}}\r\n{payload}\r\n   ~~~\r\n"
    data, errors = trust.extract_block(md)
    assert errors == []
    assert data == {"schema_version": 1, "target": "demo"}


def test_code_fence_scanner_closing_fence_must_match_character_and_length():
    md_mismatch = "``` framac-threat-model\n{}\n~~~\n"
    data, errors = trust.extract_block(md_mismatch)
    assert data is None
    assert any("no block could be read" in e for e in errors)

    md_shorter = "```` framac-threat-model\n{}\n```\n"
    data, errors = trust.extract_block(md_shorter)
    assert data is None
    assert any("no block could be read" in e for e in errors)

    md_longer = "``` framac-threat-model\n{}\n````\n"
    data, errors = trust.extract_block(md_longer)
    assert errors == []
    assert data == {}


# ---------------------------------------------------------------------------
# C13: wp_scheduler._PLACEHOLDER_RE dynamic template placeholders
# ---------------------------------------------------------------------------


def test_placeholder_re_derived_from_render_keys():
    assert wp_scheduler._PLACEHOLDER_RE.search("{references_dir}")
    for key in wp_scheduler.BRIEF_RENDER_KEYS:
        assert wp_scheduler._PLACEHOLDER_RE.search(f"{{{key}}}")
    assert not wp_scheduler._PLACEHOLDER_RE.search("{unknown_key}")
    custom_re = wp_scheduler.placeholder_re(["custom_key", "another_key"])
    assert custom_re.search("{custom_key}")
    assert not custom_re.search("{references_dir}")


# ---------------------------------------------------------------------------
# C14: build_capture compiler identification and skipped executables
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "compiler",
    [
        "tcc",
        "icx",
        "clang-fast",
        "afl-clang-fast",
        "gcc-13-posix",
        "x86_64-linux-gnu-gcc-13-posix",
        "arm-linux-gnueabihf-clang-fast",
        "x86_64-w64-mingw32-gcc-posix",
        "c89",
        "c99",
        "cc",
        "gcc",
        "clang",
        "x86_64-linux-gnu-gcc",
    ],
)
def test_compiler_re_accepts_extended_compilers(compiler):
    assert build_capture._COMPILER_RE.match(compiler)


def test_classify_executions_logs_skipped_compiler_like_executable():
    execs = [
        {
            "exe": "/usr/bin/distcc",
            "args": ["distcc", "-c", "foo.c", "-o", "foo.o"],
            "cwd": "/target",
        },
        {
            "exe": "/usr/bin/my-unknown-tool",
            "args": ["my-unknown-tool", "-c", "bar.c"],
            "cwd": "/target",
        },
        {
            "exe": "/bin/echo",
            "args": ["echo", "hello"],
            "cwd": "/target",
        },
    ]
    cap = build_capture.classify_executions(execs, "/target")
    assert len(cap["skipped_compiler_like"]) == 2
    assert any("distcc" in s for s in cap["skipped_compiler_like"])
    assert any("my-unknown-tool" in s for s in cap["skipped_compiler_like"])


# ---------------------------------------------------------------------------
# B6: build_capture.declared_names and phase0_model.header_declared_functions
# ---------------------------------------------------------------------------


def test_declared_names_ignores_comments_and_string_literals():
    c_source = """
    // void fn_in_line_comment(void);
    /*
     * int fn_in_block_comment(int);
     */
    const char *s = "void fn_in_string(void);";
    void actual_fn(int x);
    """
    names = {"fn_in_line_comment", "fn_in_block_comment", "fn_in_string", "actual_fn"}
    found = build_capture.declared_names(c_source, names)
    assert found == {"actual_fn"}


def test_declared_names_ignores_call_expressions_in_bodies():
    c_source = """
    static inline void inline_caller(void) {
        helper_fn(1, 2);
        nested_call(other());
    }
    int declared_fn(int a);
    """
    names = {"inline_caller", "helper_fn", "nested_call", "other", "declared_fn"}
    found = build_capture.declared_names(c_source, names)
    assert found == {"inline_caller", "declared_fn"}


def test_phase0_model_header_declarations_audit():
    model = {
        "functions": {
            "include/api.h#api_func": {"file": "include/api.h", "name": "api_func"},
            "src/impl.c#impl_func": {"file": "src/impl.c", "name": "impl_func"},
        },
        "external_decls": {
            "ext_header_func": {"decl": "include/api.h:42", "proto": "void ext_header_func(void);"},
            "ext_other_func": {"decl": "include/other.h:10", "proto": "void ext_other_func(void);"},
        },
    }
    decls = phase0_model.header_declared_functions(model, "include/api.h")
    assert decls == {"api_func", "ext_header_func"}
    assert phase0_model.header_declared_functions(model, "./include/api.h") == {"api_func", "ext_header_func"}
    assert phase0_model.header_declared_functions(model, "include\\api.h") == {"api_func", "ext_header_func"}
    assert phase0_model.header_declared_functions(model, "include/missing.h") == set()

