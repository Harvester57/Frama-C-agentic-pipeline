"""
MetAcsl properties checked at run time by the E-ACSL fuzz build (docs/plans/metacsl-exploitation-plan.md,
package C): the stage-1 command, the properties a module loads, the build that goes on without them when
they make it fail, and the identity of a violation (failure_identity).

The unit tests run the real build functions on a fake toolchain. The acceptance test builds and runs
tests/fixtures/metacsl_eacsl in the analysis image (FRAMAC_DOCKER_TESTS=1).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from subprocess import CompletedProcess

import pytest

import eacsl_toolchain
import failure_identity
import fingerprint
import fuzz_build
import run_eacsl_fuzz
import run_wp_function
import security_props as sp
from conftest import ANALYSIS_IMAGE, ROOT, require_docker_images

META_EACSL_FIXTURE = ROOT / "tests" / "fixtures" / "metacsl_eacsl"
FAKE_EACSL_GCC = "/usr/bin/e-acsl-gcc"
MODULE_FUNCTIONS = ["admin", "emit", "login", "logmsg", "mix", "process", "session_close"]

# The meta-properties of the fixture, as templates/metacsl renders them.
ACSL_AUTH_STATE = r"""/*@ meta \prop, \name(L4_auth_state_login), \targets(\diff(\ALL, {login})), \context(\writing),
      \separated(\written, &auth_ok);
*/"""
ACSL_AUTH_REQUIRED = r"""/*@ meta \prop, \name(L4_auth_required_login), \targets({admin}), \context(\precond),
      auth_ok != 0;
*/"""
ACSL_SANITIZED_EMIT = r"""/*@ meta \prop, \name(L5_sanitized_emit), \targets(\ALL), \context(\calling),
      \tguard(\called == emit ==> (\fguard(\initialized(\called_arg(buf) + (0 .. \called_arg(n) - 1)))));
*/"""
ACSL_SANITIZED_LOG = r"""/*@ meta \prop, \name(L5_sanitized_logmsg), \targets(\ALL), \context(\calling),
      \tguard(\called == logmsg ==> (\fguard(no_crlf_string(\called_arg(s)))));
*/"""
ACSL_WIPED = r"""/*@ meta \prop, \name(L6_wiped_session_key), \targets({session_close}), \context(\postcond),
      \fguard(\forall integer i; 0 <= i < 16 ==> session_key[i] == 0);
*/"""
ACSL_NO_LEAK = r"""/*@ meta \prop, \name(L6_no_leak_session_key), \targets(\ALL), \context(\calling),
      \tguard(\called == emit ==> \fguard(\separated(\called_arg(buf), &session_key[0 .. 15])));
*/"""
FIXTURE_PROPERTIES = (
    ("L4_auth_state_login", 4, "auth_state", "l4_auth_state", ACSL_AUTH_STATE, ["process", "mix"]),
    ("L4_auth_required_login", 4, "auth_required", "l4_auth_required", ACSL_AUTH_REQUIRED, ["process"]),
    ("L5_sanitized_emit", 5, "sanitized", "l5_sanitized", ACSL_SANITIZED_EMIT, ["process"]),
    ("L5_sanitized_logmsg", 5, "sanitized", "l5_sanitized", ACSL_SANITIZED_LOG, ["process"]),
    ("L6_wiped_session_key", 6, "wiped", "l6_wiped", ACSL_WIPED, ["session_close"]),
    ("L6_no_leak_session_key", 6, "no_leak", "l6_no_leak", ACSL_NO_LEAK, ["process"]),
)
ALL_PROPERTY_NAMES = [row[0] for row in FIXTURE_PROPERTIES]


def fixture_props(engines: list[str] | None = None, file: str = "src/prog.c") -> dict:
    """A schema-valid security_props.json for the fixture; `engines` is its `meta_engines` (None: no key)."""
    properties: list[dict] = [
        {
            "name": name,
            "layer": layer,
            "kind": kind,
            "obligation_class": cls,
            "acsl": acsl,
            "instances": [f"{file}#{fn}" for fn in functions],
            "sources": [file],
            "notes": [],
        }
        for name, layer, kind, cls, acsl, functions in FIXTURE_PROPERTIES
    ]
    obligations: dict[str, list[dict]] = {}
    for p in properties:
        for fid in p["instances"]:
            obligations.setdefault(fid, []).append(
                {"class": p["obligation_class"], "property": p["name"], "reason": "fixture"}
            )
    doc = {
        "schema_version": 1,
        "generated_at": "2026-11-18T00:00:00Z",
        "threat_model": {"status": "ok", "path": None, "sha256": None, "reason": None},
        "preamble": sp.load_template("preamble")["preamble"],
        "properties": properties,
        "frame": [],
        "obligations": obligations,
        "summary": {},
        "warnings": [],
    }
    if engines is not None:
        doc["meta_engines"] = engines
    return doc


def write_props(path: Path, doc: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    return path


@pytest.fixture
def run_dir(tmp_path, monkeypatch):
    """A run directory (cwd) holding the fixture: workspace/work/src/prog.c and workspace/harnesses/*.c."""
    for name in ("prog.c", "prog.h"):
        dest = tmp_path / "workspace" / "work" / "src" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(META_EACSL_FIXTURE / name, dest)
    for name in ("harness_prog.c", "harness_direct.c"):
        dest = tmp_path / "workspace" / "harnesses" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(META_EACSL_FIXTURE / name, dest)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(fuzz_build.SECURITY_PROPS_ENV, raising=False)
    monkeypatch.setattr(fuzz_build, "_resolve_eacsl_gcc", lambda: (FAKE_EACSL_GCC, True))
    return tmp_path


SOURCES = ["workspace/harnesses/harness_prog.c", "workspace/work/src/prog.c"]
DIRECT_SOURCES = ["workspace/harnesses/harness_direct.c", "workspace/work/src/prog.c"]
OUT_BIN = Path("workspace/work/out/fuzz_prog")
DEFAULT_PROPS = Path("workspace/reports/security_props.json")


def assert_data(function: str, line: int, name: str) -> str:
    """One run-time check as E-ACSL prints it into the instrumented file."""
    return (
        f'  __gen_e_acsl_assert_data.file = "x.c";\n  __gen_e_acsl_assert_data.fct = "{function}";\n'
        f'  __gen_e_acsl_assert_data.line = {line};\n  __gen_e_acsl_assert_data.name = "{name}";\n'
        "  __e_acsl_assert(1,& __gen_e_acsl_assert_data);\n"
    )


PLAIN_INSTRUMENTED = "int process(void) {\n" + assert_data("process", 3, "rte/mem_access") + "  return 0;\n}\n"
META_INSTRUMENTED = (
    PLAIN_INSTRUMENTED
    + assert_data("backdoor", 9, "L4_auth_state_login/meta")
    + assert_data("mix", 9, "L4_auth_state_login/meta")
    + assert_data("process", 15, "L5_sanitized_emit/meta")
    + assert_data("session_close", 21, "L6_wiped_session_key/meta")
)


class FakeToolchain:
    """e-acsl-gcc and clang as compile_eacsl_binary runs them; `stage1(cmd, n)` decides the n-th stage 1."""

    def __init__(self, stage1=None):
        self.stage1 = stage1
        self.stage1_cmds: list[list[str]] = []
        self.stage2_cmds: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        cmd = [str(c) for c in cmd]
        if cmd[0] == "clang" and "-c" in cmd:
            Path(cmd[cmd.index("-o") + 1]).write_bytes(b"OBJ")
            return CompletedProcess(cmd, 0, "", "")
        if cmd[0] == "clang":
            return CompletedProcess(cmd, 0, "", "")
        if cmd[0] == FAKE_EACSL_GCC and "-n" in cmd:
            self.stage1_cmds.append(cmd)
            with_meta = cmd[-1].endswith(failure_identity.SECURITY_META_SUFFIX)
            rc, out, err, text = (
                self.stage1(cmd, len(self.stage1_cmds))
                if self.stage1
                else (0, "", "", META_INSTRUMENTED if with_meta else PLAIN_INSTRUMENTED)
            )
            if rc == 0:
                Path(cmd[cmd.index("-o") + 1]).write_text(text, encoding="utf-8")
            return CompletedProcess(cmd, rc, out, err)
        if cmd[0] == FAKE_EACSL_GCC and "-C" in cmd:
            self.stage2_cmds.append(cmd)
            out_bin = Path(cmd[cmd.index("-O") + 1])
            out_bin.with_name(out_bin.name + ".e-acsl").write_bytes(b"\x7fELF\x00__e_acsl_memory_init\x00")
            return CompletedProcess(cmd, 0, "", "")
        raise AssertionError(f"unexpected command: {cmd}")


def build(monkeypatch, fake: FakeToolchain, sources: list[str] | None = None, **kwargs) -> dict:
    """fuzz_build.build_module_binary on the fake toolchain, cache off unless asked."""
    real = fuzz_build.compile_eacsl_binary
    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", lambda *a, **k: real(*a, **{"runner": fake, **k}))
    options = {"engine": "eacsl", "functions": list(MODULE_FUNCTIONS), "use_cache": False, **kwargs}
    try:
        return fuzz_build.build_module_binary(sources or SOURCES, OUT_BIN, **options)
    finally:
        monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", real)


# ---------------------------------------------------------------------------------------------------
# eacsl_toolchain: the stage split, the meta file of an E-ACSL build, what MetAcsl rejects
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_meta_stage_flags_moves_the_rte_flags_behind_the_metacsl_stage():
    flags = [
        "-rte",
        "-machdep gcc_x86_64",
        "-e-acsl-full-mtracking",
        "-rte-initialized @all",
        "-warn-unsigned-downcast",
        "-rte-select f,g",
        "-e-acsl-functions f,g",
    ]
    first, options = eacsl_toolchain.meta_stage_flags(flags)
    assert first == [
        "-machdep gcc_x86_64",
        "-e-acsl-full-mtracking",
        "-warn-unsigned-downcast",
        "-e-acsl-functions f,g",
        "-meta",
        "-meta-warn-key unknown-func=inactive",
    ]
    assert options == ["--then-last", "--e-acsl-extra", "-rte -rte-initialized @all -rte-select f,g"]
    # Nothing is lost or said twice.
    behind = ["-rte", "-rte-initialized @all", "-rte-select f,g"]
    assert options[2] == " ".join(behind) and sorted(first[:-2] + behind) == sorted(flags)


@pytest.mark.unit
def test_the_eacsl_meta_file_drops_the_libc_include_and_keeps_every_line():
    found = sp.module_meta_file_text(fixture_props())
    assert found is not None
    text, names, _ = found
    assert text.split("\n")[0] == sp.META_INCLUDE
    eacsl_text = eacsl_toolchain.eacsl_meta_file_text(text, sp.META_INCLUDE)
    assert eacsl_text.split("\n")[0] == eacsl_toolchain.EACSL_META_INCLUDE_NOTE
    assert "#include" not in eacsl_text
    assert eacsl_text.split("\n")[1:] == text.split("\n")[1:]
    assert sp.meta_line_names(eacsl_text) == sp.meta_line_names(text)
    assert names == ALL_PROPERTY_NAMES
    # A text that does not start with the include is left as it is.
    assert eacsl_toolchain.eacsl_meta_file_text("/*@ x */\n", sp.META_INCLUDE) == "/*@ x */\n"


ACSL_READING = r"""/*@ meta \prop, \name(L6_no_leak_read), \targets(\callees({emit, logmsg})), \context(\reading),
      \flags(translate:check),
      \separated(\read, &session_key[0 .. 15]);
*/"""


@pytest.mark.unit
def test_the_eacsl_meta_file_guards_each_writing_and_reading_predicate_on_its_own_lines():
    text = "\n".join(
        ["/* note */", ACSL_AUTH_STATE, ACSL_AUTH_REQUIRED, ACSL_SANITIZED_EMIT, ACSL_WIPED, ACSL_READING, ""]
    )
    guarded = eacsl_toolchain.eacsl_meta_guarded_text(text)
    assert guarded.count("\n") == text.count("\n")
    assert sp.meta_line_names(guarded) == sp.meta_line_names(text)
    assert r"\valid(\written) ==> (\separated(\written, &auth_ok));" in guarded
    assert r"\valid_read(\read) ==> (\separated(\read, &session_key[0 .. 15]));" in guarded
    assert r"\flags(translate:check)," in guarded
    # A precondition, a call rule and a postcondition are left as they are.
    for untouched in (ACSL_AUTH_REQUIRED, ACSL_SANITIZED_EMIT, ACSL_WIPED):
        assert untouched in guarded
    # The formal variant's \tguard and a monotonic disjunction are guarded as a whole.
    formal = ACSL_AUTH_STATE.replace(r"\separated(\written, &auth_ok)", r"\tguard(\separated(\written, &c->auth))")
    assert r"\valid(\written) ==> (\tguard(\separated(\written, &c->auth)));" in (
        eacsl_toolchain.eacsl_meta_guarded_text(formal)
    )
    monotonic = ACSL_AUTH_STATE.replace(
        r"\separated(\written, &auth_ok)", r"\separated(\written, &st) || \at(st, Before) <= \at(st, After)"
    )
    assert r"\valid(\written) ==> (\separated(\written, &st) || \at(st, Before) <= \at(st, After));" in (
        eacsl_toolchain.eacsl_meta_guarded_text(monotonic)
    )


@pytest.mark.unit
def test_every_writing_and_reading_template_is_guarded_in_the_eacsl_meta_file():
    templates = sorted((ROOT / "templates" / "metacsl").glob("*.acsl"))
    seen = 0
    for path in templates:
        for variant, body in sp.load_template(path.stem).items():
            if not re.search(r"\\context\(\\(writing|reading)\)", body):
                continue
            text = re.sub(r"\$\{\w+\}", "x", body)
            guarded = eacsl_toolchain.eacsl_meta_guarded_text(text)
            access = r"\valid(\written)" if r"\context(\writing)" in text else r"\valid_read(\read)"
            assert f"{access} ==> (" in guarded and guarded.count("\n") == text.count("\n"), (path.name, variant)
            seen += 1
    assert seen >= 6


@pytest.mark.unit
def test_the_libc_contracts_declare_exactly_the_listed_writers_with_glibcs_formals():
    text = eacsl_toolchain.eacsl_meta_libc_text()
    assert text is not None
    declared = re.findall(r"^extern [^(]*?\b(\w+)\(", text, re.MULTILINE)
    assert declared == list(eacsl_toolchain.EACSL_META_LIBC_WRITERS)
    assert not set(declared) & set(eacsl_toolchain.EACSL_META_LIBC_UNCHECKED)
    # glibc's formal names, which MetAcsl keeps from the first declaration it meets.
    contracts = "\n".join(ln for ln in text.splitlines() if ln.lstrip().startswith(("/*@", "assigns", "extern")))
    assert "__dest" in contracts and not re.search(r"\b(dest|src|n|s|c)\b", contracts)
    # Nothing in it is a property, so the sidecar's line map stops at the last one.
    assert "meta" not in contracts


@pytest.mark.unit
def test_libc_writer_calls_lists_the_calls_in_the_module_functions_only():
    printed = (
        "extern char *strcpy(char * restrict __dest, char const * restrict __src);\n"
        "int process(unsigned char const *data,\n            size_t n)\n{\n"
        '  __e_acsl_builtin_strcpy(line, (char const *)data);\n  n = (size_t)sprintf(out, "%d", 1);\n'
        "  return 0;\n}\n\n"
        "static void mix(unsigned char *dst)\n{\n  memcpy((void *)dst, (void const *)src, 4UL);\n}\n\n"
        "int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size)\n{\n  read(0, buf, 4UL);\n  return 0;\n}\n"
    )
    names = [*eacsl_toolchain.EACSL_META_LIBC_UNCHECKED, "memcpy"]
    assert eacsl_toolchain.libc_writer_calls(printed, ["process", "mix"], names) == {
        "memcpy": ["mix"],
        "sprintf": ["process"],
        "strcpy": ["process"],
    }
    assert eacsl_toolchain.libc_writer_calls(printed, ["process"], []) == {}


METACSL_REJECTION = """[kernel] Parsing m.security_meta.c (with preprocessing)
[meta] User Error: Error during the typing of a HILARE!
  What: the HILARE named 'L4_auth_state_login' (m.security_meta.c:9)
  Where: in function 'emit', at m.security_meta.c:9
  Why: unbound logic variable auth_ok
[kernel] Plug-in meta aborted: invalid user input.
e-acsl-gcc: fatal error: aborted by Frama-C
"""


@pytest.mark.unit
def test_rejected_meta_property_names_the_property_and_the_reason():
    assert eacsl_toolchain.rejected_meta_property(METACSL_REJECTION) == (
        "L4_auth_state_login",
        "unbound logic variable auth_ok",
    )
    assert eacsl_toolchain.rejected_meta_property("[kernel] User Error: failed to run: gcc -E x.c") is None
    assert eacsl_toolchain.rejected_meta_property("") is None


@pytest.mark.unit
def test_meta_checks_counts_the_checks_of_each_property_per_function():
    found = eacsl_toolchain.meta_checks(META_INSTRUMENTED, ALL_PROPERTY_NAMES)
    assert found["L4_auth_state_login"] == {"checks": 2, "functions": ["backdoor", "mix"]}
    assert found["L5_sanitized_emit"] == {"checks": 1, "functions": ["process"]}
    assert found["L6_no_leak_session_key"] == {"checks": 0, "functions": []}
    assert eacsl_toolchain.meta_checks(PLAIN_INSTRUMENTED, ["L4_auth_state_login"]) == {
        "L4_auth_state_login": {"checks": 0, "functions": []}
    }


# ---------------------------------------------------------------------------------------------------
# fuzz_build.resolve_security_meta: which file, which engine, which properties
# ---------------------------------------------------------------------------------------------------


@pytest.mark.unit
def test_the_fixture_properties_are_a_valid_security_props_document():
    for engines in (None, [], ["eacsl"], ["eva", "eacsl"]):
        assert sp.validate(fixture_props(engines)) == []
    assert fuzz_build.SECURITY_PROPS_ENV == run_wp_function.SECURITY_PROPS_ENV
    assert Path(sp.DEFAULT_OUT) == Path(run_wp_function.DEFAULT_SECURITY_PROPS) == DEFAULT_PROPS


@pytest.mark.unit
@pytest.mark.parametrize("spec", ["none", "off", "", " NONE "])
def test_none_turns_the_properties_off_whatever_the_run_holds(run_dir, spec):
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    assert fuzz_build.resolve_security_meta(spec, SOURCES, OUT_BIN) is None


@pytest.mark.unit
def test_the_file_is_the_option_then_the_environment_then_the_run_default(run_dir, monkeypatch):
    assert fuzz_build.resolve_security_meta(None, SOURCES, OUT_BIN) is None  # no file at all
    missing = fuzz_build.resolve_security_meta("nowhere.json", SOURCES, OUT_BIN)
    assert missing == {"status": "error", "props": "nowhere.json", "reason": "security properties file not found"}

    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    by_default = fuzz_build.resolve_security_meta(None, SOURCES, OUT_BIN)
    assert by_default is not None
    assert by_default["status"] == "loaded" and Path(by_default["props"]) == DEFAULT_PROPS

    other = write_props(run_dir / "other" / "props.json", fixture_props(["eva"]))
    monkeypatch.setenv(fuzz_build.SECURITY_PROPS_ENV, str(other))
    assert fuzz_build.resolve_security_meta(None, SOURCES, OUT_BIN) is None  # the environment's file: eva only
    by_option = fuzz_build.resolve_security_meta(str(DEFAULT_PROPS), SOURCES, OUT_BIN)
    assert by_option is not None
    assert by_option["status"] == "loaded"
    monkeypatch.setenv(fuzz_build.SECURITY_PROPS_ENV, str(run_dir / "gone.json"))
    assert fuzz_build.resolve_security_meta(None, SOURCES, OUT_BIN) is None  # as run_wp_function: not an error

    DEFAULT_PROPS.write_text("{not json", encoding="utf-8")
    broken = fuzz_build.resolve_security_meta(str(DEFAULT_PROPS), SOURCES, OUT_BIN)
    assert broken is not None
    assert broken["status"] == "error" and broken["reason"].startswith("unreadable: ")


@pytest.mark.unit
@pytest.mark.parametrize("engines", [None, [], ["eva"]])
def test_nothing_is_loaded_unless_the_eacsl_engine_is_on(run_dir, engines):
    write_props(DEFAULT_PROPS, fixture_props(engines))
    assert fuzz_build.resolve_security_meta(None, SOURCES, OUT_BIN) is None
    assert fuzz_build.resolve_security_meta(str(DEFAULT_PROPS), SOURCES, OUT_BIN) is None


@pytest.mark.unit
def test_the_properties_are_the_ones_with_an_instance_in_the_module(run_dir):
    doc = fixture_props(["eacsl"])
    doc["properties"].append(
        {
            **doc["properties"][0],
            "name": "L4_auth_state_elsewhere",
            "acsl": ACSL_AUTH_STATE.replace("L4_auth_state_login", "L4_auth_state_elsewhere"),
            "instances": ["lib/other.c#f"],
        }
    )
    doc["properties"].append({**doc["properties"][4], "name": "L6_wiped_decided", "instances": []})
    write_props(DEFAULT_PROPS, doc)
    plan = fuzz_build.resolve_security_meta(None, SOURCES, OUT_BIN)
    assert plan is not None
    assert plan["status"] == "loaded" and plan["properties"] == ALL_PROPERTY_NAMES
    assert plan["left_out"] == []
    assert plan["functions"]["process"] == ["src/prog.c"] and plan["functions"]["backdoor"] == ["src/prog.c"]
    assert "LLVMFuzzerTestOneInput" not in plan["functions"]
    assert plan["harness_functions"] == ["LLVMFuzzerTestOneInput"]

    # A module none of whose functions holds an instance loads nothing, and says so.
    other = run_dir / "workspace" / "work" / "lib" / "unrelated.c"
    other.parent.mkdir(parents=True)
    other.write_text("int unrelated(int x) { return x; }\n", encoding="utf-8")
    skipped = fuzz_build.resolve_security_meta(None, ["workspace/work/lib/unrelated.c"], OUT_BIN)
    assert skipped is not None
    assert skipped["status"] == "skipped" and "no property has an instance" in skipped["reason"]


@pytest.mark.unit
def test_a_precondition_the_harness_can_break_itself_is_left_out(run_dir):
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    plan = fuzz_build.resolve_security_meta(None, DIRECT_SOURCES, OUT_BIN)
    assert plan is not None
    assert plan["status"] == "loaded"
    assert plan["left_out"] == [{"property": "L4_auth_required_login", "reason": "the harness names its target admin"}]
    assert plan["properties"] == [n for n in ALL_PROPERTY_NAMES if n != "L4_auth_required_login"]
    written = fuzz_build.write_security_meta(plan, OUT_BIN)
    assert written is not None
    text = Path(written["meta_file"]).read_text(encoding="utf-8")
    assert "L4_auth_required_login" not in text and "translate:check" not in text
    # The other contexts stay: the harness's own writes and calls are not instrumented.
    assert "L4_auth_state_login" in text and "auth_ok" in Path(DIRECT_SOURCES[0]).read_text(encoding="utf-8")


@pytest.mark.unit
def test_harness_induced_reasons():
    words = {"process", "admin", "LLVMFuzzerTestOneInput"}
    assert fuzz_build._harness_induced(ACSL_AUTH_REQUIRED, words) == "the harness names its target admin"
    assert fuzz_build._harness_induced(ACSL_AUTH_REQUIRED, {"process"}) is None
    over_all = ACSL_AUTH_REQUIRED.replace("{admin}", r"\diff(\ALL, {login})")
    reason = fuzz_build._harness_induced(over_all, {"process"})
    assert reason is not None
    assert "not a list of functions" in reason
    two = ACSL_AUTH_REQUIRED.replace("{admin}", "{admin, process}")
    assert fuzz_build._harness_induced(two, words) == "the harness names its targets admin, process"
    for other in (ACSL_AUTH_STATE, ACSL_SANITIZED_EMIT, ACSL_WIPED, ACSL_NO_LEAK):
        assert fuzz_build._harness_induced(other, words | {"session_close", "emit"}) is None


# ---------------------------------------------------------------------------------------------------
# The build: today's command without the engine, the MetAcsl stage with it
# ---------------------------------------------------------------------------------------------------

PLAIN_FC_FLAGS = (
    "-rte -machdep gcc_x86_64 -e-acsl-full-mtracking -rte-initialized @all "
    f"-rte-select {','.join(MODULE_FUNCTIONS)} -e-acsl-functions {','.join(MODULE_FUNCTIONS)}"
)


@pytest.mark.unit
def test_without_the_eacsl_engine_the_build_command_is_todays(run_dir, monkeypatch):
    builds = {}
    fake = FakeToolchain()
    builds["no file"] = build(monkeypatch, fake)
    write_props(DEFAULT_PROPS, fixture_props([]))
    builds["engine off"] = build(monkeypatch, fake)
    write_props(DEFAULT_PROPS, fixture_props(["eva"]))
    builds["eva only"] = build(monkeypatch, fake)
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    builds["none"] = build(monkeypatch, fake, security_props="none")
    reference = builds["no file"]["compile"]
    for label, built in builds.items():
        comp = built["compile"]
        assert comp["returncode"] == 0, label
        assert comp["command"] == reference["command"], label
        assert "security_props" not in comp and "security_meta" not in comp, label
        assert not OUT_BIN.with_suffix(failure_identity.SECURITY_META_SUFFIX).exists(), label
    assert len(fake.stage1_cmds) == 4 and all(cmd == fake.stage1_cmds[0] for cmd in fake.stage1_cmds)
    # The command itself, spelled out: what the build ran before this option existed.
    assert fake.stage1_cmds[0] == [
        FAKE_EACSL_GCC,
        "-n",
        "--no-constfold",
        *eacsl_toolchain.EACSL_GCC_CHECK_OPTIONS,
        "-G",
        "clang",
        "-F",
        PLAIN_FC_FLAGS,
        "-E",
        reference["frontend_flags"],
        "-o",
        str(OUT_BIN.with_suffix(".instrumented.c")),
        *SOURCES,
    ]


@pytest.mark.unit
def test_the_cache_key_does_not_know_the_properties(run_dir):
    material = fuzz_build._eacsl_cache_material(
        SOURCES, OUT_BIN, "gcc_x86_64", "-I.", "all", True, MODULE_FUNCTIONS, "", True, False, True
    )
    assert material is not None
    assert sorted(material) == sorted(
        [
            "kind",
            "libc_shim",
            "eacsl_gcc",
            "sources",
            "out_bin",
            "machdep",
            "cppflags",
            "frontend",
            "backend",
            "ldflags",
            "rte",
            "fuzzer",
            "functions",
            "variadic_translation",
            "warn_unsigned_downcast",
            "rte_initialized",
            "no_constfold",
            "concurrency",
            "ignored_annotations",
            "check_options",
            "runtime_patches",
            "zone_sizes",
        ]
    )


@pytest.mark.unit
def test_with_the_eacsl_engine_stage_1_runs_metacsl_before_rte(run_dir, monkeypatch):
    fake = FakeToolchain()
    plain = build(monkeypatch, fake)["compile"]
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    # The cache of a build with the properties: tests/test_metacsl_eacsl_wiring.py (package C2).
    comp = build(monkeypatch, fake)["compile"]
    assert comp["returncode"] == 0 and comp["cache"] == {"hit": False, "key": None}
    base, meta = fake.stage1_cmds
    meta_file = OUT_BIN.with_suffix(failure_identity.SECURITY_META_SUFFIX)
    assert base[base.index("-F") + 1] == PLAIN_FC_FLAGS
    assert meta[: meta.index("--then-last")] == base[: base.index("-G")]
    assert meta[meta.index("--then-last") : meta.index("-G")] == [
        "--then-last",
        "--e-acsl-extra",
        f"-rte -rte-initialized @all -rte-select {','.join(MODULE_FUNCTIONS)}",
    ]
    assert meta[meta.index("-F") + 1] == (
        f"-machdep gcc_x86_64 -e-acsl-full-mtracking -e-acsl-functions {','.join(MODULE_FUNCTIONS)} "
        "-meta -meta-warn-key unknown-func=inactive"
    )
    assert meta[meta.index("-E") : -1] == base[base.index("-E") :]
    assert meta[-1] == meta_file.as_posix()
    # Stage 2 and the sources the other builds read do not see the meta file.
    assert fake.stage2_cmds[0] == fake.stage2_cmds[1]
    assert plain["frontend_flags"] == comp["frontend_flags"]

    text = meta_file.read_text(encoding="utf-8")
    assert text.split("\n")[0] == eacsl_toolchain.EACSL_META_INCLUDE_NOTE and "\r" not in text
    record = comp["security_props"]
    assert record["status"] == "loaded" and Path(record["props"]) == DEFAULT_PROPS
    assert record["meta_file"] == meta_file.as_posix() and record["properties"] == ALL_PROPERTY_NAMES
    # The libc writers' assigns follow the last property; the line map covers the properties only.
    contracts = eacsl_toolchain.eacsl_meta_libc_text()
    assert contracts and text.endswith(contracts)
    properties_text = text[: -len(contracts)]
    assert record["line_names"] == {str(k): v for k, v in sp.meta_line_names(properties_text).items()}
    assert record["libc_contracts"] == {"status": "loaded", "functions": list(eacsl_toolchain.EACSL_META_LIBC_WRITERS)}
    assert record["libc_unchecked"] == {}
    assert sorted(record["translated"]) == ["L4_auth_state_login", "L5_sanitized_emit", "L6_wiped_session_key"]
    assert record["translated"]["L4_auth_state_login"] == {"checks": 2, "functions": ["backdoor", "mix"]}
    assert record["not_translated"] == ["L4_auth_required_login", "L5_sanitized_logmsg", "L6_no_leak_session_key"]
    assert record["unplanned_instances"] == {"L4_auth_state_login": ["backdoor"]}
    assert record["left_out"] == [] and "rejected" not in record
    assert "security_meta" not in comp

    sidecar = json.loads(failure_identity.meta_sidecar_path(meta_file).read_text(encoding="utf-8"))
    assert sidecar["properties"]["L6_wiped_session_key"] == {
        "obligation_class": "l6_wiped",
        "instances": ["src/prog.c#session_close"],
    }
    assert sidecar["functions"]["session_close"] == ["src/prog.c"]
    assert sidecar["harness_functions"] == ["LLVMFuzzerTestOneInput"]


@pytest.mark.unit
def test_the_optional_flags_keep_their_stage(run_dir, monkeypatch):
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    fake = FakeToolchain()
    comp = build(monkeypatch, fake, warn_unsigned_downcast=True, variadic_translation=False, rte_initialized=False)[
        "compile"
    ]
    assert comp["returncode"] == 0
    (meta,) = fake.stage1_cmds
    assert meta[meta.index("--e-acsl-extra") + 1] == f"-rte -rte-select {','.join(MODULE_FUNCTIONS)}"
    assert meta[meta.index("-F") + 1] == (
        "-machdep gcc_x86_64 -e-acsl-full-mtracking -warn-unsigned-downcast -no-variadic-translation "
        f"-e-acsl-functions {','.join(MODULE_FUNCTIONS)} -meta -meta-warn-key unknown-func=inactive"
    )


@pytest.mark.unit
def test_a_property_metacsl_rejects_is_dropped_and_the_others_stay(run_dir, monkeypatch):
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))

    def stage1(cmd, n):
        if n == 1:
            return 1, METACSL_REJECTION, "", ""
        return 0, "", "", META_INSTRUMENTED.replace("L4_auth_state_login", "L4_other")

    fake = FakeToolchain(stage1)
    comp = build(monkeypatch, fake)["compile"]
    assert comp["returncode"] == 0 and len(fake.stage1_cmds) == 2
    record = comp["security_props"]
    assert record["status"] == "loaded"
    assert record["rejected"] == [{"property": "L4_auth_state_login", "reason": "unbound logic variable auth_ok"}]
    assert record["properties"] == [n for n in ALL_PROPERTY_NAMES if n != "L4_auth_state_login"]
    text = Path(record["meta_file"]).read_text(encoding="utf-8")
    assert "L4_auth_state_login" not in text and "L6_wiped_session_key" in text
    sidecar = json.loads(failure_identity.meta_sidecar_path(record["meta_file"]).read_text(encoding="utf-8"))
    assert "L4_auth_state_login" not in sidecar["properties"]


@pytest.mark.unit
def test_a_build_the_properties_break_is_redone_without_them(run_dir, monkeypatch):
    fake_plain = FakeToolchain()
    reference = build(monkeypatch, fake_plain)["compile"]
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))

    def stage1(cmd, n):
        if cmd[-1].endswith(failure_identity.SECURITY_META_SUFFIX):
            return 1, "", "[e-acsl] internal error: cannot translate\ne-acsl-gcc: fatal error: aborted by Frama-C\n", ""
        return 0, "", "", PLAIN_INSTRUMENTED

    fake = FakeToolchain(stage1)
    comp = build(monkeypatch, fake)["compile"]
    assert comp["returncode"] == 0 and comp["command"] == reference["command"]
    # With the libc writers' assigns, again without them, then the plain build.
    assert len(fake.stage1_cmds) == 3 and fake.stage1_cmds[2] == fake_plain.stage1_cmds[0]
    record = comp["security_props"]
    assert record["status"] == "dropped" and record["properties"] == ALL_PROPERTY_NAMES
    assert record["reason"] == "the E-ACSL build failed with the properties (eacsl_instrumentation_failed)"
    assert "cannot translate" in Path(record["log"]).read_text(encoding="utf-8")
    assert Path(record["log"]) == OUT_BIN.with_suffix(fuzz_build.SECURITY_META_LOG_SUFFIX)
    assert record["libc_contracts"]["status"] == "dropped"
    assert Path(record["libc_contracts"]["log"]) == OUT_BIN.with_suffix(fuzz_build.SECURITY_META_LIBC_LOG_SUFFIX)

    # A module that does not build either way: the properties are not what broke it.
    broken = FakeToolchain(lambda cmd, n: (1, "", "[kernel] User Error: syntax error\n", ""))
    failed = build(monkeypatch, broken)["compile"]
    assert failed["returncode"] != 0 and len(broken.stage1_cmds) == 3
    assert failed["security_props"]["reason"].endswith("; the build without them fails too")


@pytest.mark.unit
def test_a_properties_build_killed_at_the_time_limit_is_not_redone_without_the_libc_contracts(run_dir, monkeypatch):
    # nginx run-5: a whole-program E-ACSL build ran into the build class's fixed limit (S14). Rebuilding
    # the properties without the libc writers' assigns would spend that limit again for nothing: the
    # contracts did not stop the build, its size did.
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))

    def stage1(cmd, n):
        if cmd[-1].endswith(failure_identity.SECURITY_META_SUFFIX):
            raise subprocess.TimeoutExpired(cmd, 3600.0, output=b"", stderr=b"")
        return 0, "", "", PLAIN_INSTRUMENTED

    fake = FakeToolchain(stage1)
    comp = build(monkeypatch, fake)["compile"]
    # The properties build with the libc contracts, then straight to the plain build.
    assert comp["returncode"] == 0 and len(fake.stage1_cmds) == 2
    assert not fake.stage1_cmds[1][-1].endswith(failure_identity.SECURITY_META_SUFFIX)
    record = comp["security_props"]
    assert record["status"] == "dropped"
    assert record["reason"] == "the E-ACSL build failed with the properties (eacsl_build_timeout)"
    assert record["libc_contracts"]["status"] == "loaded"


LIBC_CALLS_INSTRUMENTED = (
    META_INSTRUMENTED
    + "\nint process(unsigned char const *data, size_t n)\n{\n  memcpy((void *)(& auth_ok),(void const *)(work),4UL);\n"
    + '  __e_acsl_builtin_strcpy(line,"abc");\n  return 0;\n}\n'
)


@pytest.mark.unit
def test_a_build_the_libc_contracts_break_keeps_the_properties_without_them(run_dir, monkeypatch):
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    with_contracts: list[bool] = []

    def stage1(cmd, n):
        if not cmd[-1].endswith(failure_identity.SECURITY_META_SUFFIX):
            return 0, "", "", PLAIN_INSTRUMENTED
        with_contracts.append("extern void *memcpy" in Path(cmd[-1]).read_text(encoding="utf-8"))
        if with_contracts[-1]:
            err = "x.c:9:50: error: use of undeclared identifier '__dest'\ne-acsl-gcc: fatal error: aborted\n"
            return 1, "", err, ""
        return 0, "", "", LIBC_CALLS_INSTRUMENTED

    fake = FakeToolchain(stage1)
    comp = build(monkeypatch, fake)["compile"]
    assert comp["returncode"] == 0 and with_contracts == [True, False] and len(fake.stage1_cmds) == 2
    record = comp["security_props"]
    assert record["status"] == "loaded" and record["properties"] == ALL_PROPERTY_NAMES
    libc = record["libc_contracts"]
    assert libc["status"] == "dropped" and libc["functions"] == list(eacsl_toolchain.EACSL_META_LIBC_WRITERS)
    assert libc["reason"].startswith("the E-ACSL build failed with them (")
    assert "__dest" in Path(libc["log"]).read_text(encoding="utf-8")
    # Without the contracts memcpy is unchecked too; harness functions are not listed.
    assert record["libc_unchecked"] == {"memcpy": ["process"], "strcpy": ["process"]}
    warnings = run_eacsl_fuzz.security_props_warnings(record)
    assert any(w.startswith("libc contracts dropped: the assigns of memcpy, memmove") for w in warnings), warnings
    assert any(
        w.startswith("libc unchecked: memcpy (called in process); strcpy (called in process): no contract")
        for w in warnings
    ), warnings
    # The meta file left next to the binary is the one the binary was built from.
    assert "extern void *memcpy" not in Path(record["meta_file"]).read_text(encoding="utf-8")


@pytest.mark.unit
def test_a_build_with_the_libc_contracts_lists_only_the_writers_without_one():
    record = {
        "status": "loaded",
        "libc_contracts": {"status": "loaded", "functions": list(eacsl_toolchain.EACSL_META_LIBC_WRITERS)},
        "libc_unchecked": {},
    }
    assert run_eacsl_fuzz.security_props_warnings(record) == []
    # A build that lost every property says so once: the libc lines would only repeat it.
    lost = {**record, "status": "dropped", "libc_unchecked": {"strcpy": ["process"]}}
    assert [w.split(":")[0] for w in run_eacsl_fuzz.security_props_warnings(lost)] == ["dropped"]


@pytest.mark.unit
def test_metacsl_rejections_are_bounded(run_dir, monkeypatch):
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    order = list(ALL_PROPERTY_NAMES)

    def stage1(cmd, n):
        if cmd[-1].endswith(failure_identity.SECURITY_META_SUFFIX):
            return 1, METACSL_REJECTION.replace("L4_auth_state_login", order[n - 1]), "", ""
        return 0, "", "", PLAIN_INSTRUMENTED

    fake = FakeToolchain(stage1)
    comp = build(monkeypatch, fake)["compile"]
    assert comp["returncode"] == 0
    with_meta = [cmd for cmd in fake.stage1_cmds if cmd[-1].endswith(failure_identity.SECURITY_META_SUFFIX)]
    assert len(with_meta) == fuzz_build.SECURITY_META_MAX_REJECTED + 1 and len(fake.stage1_cmds) == len(with_meta) + 1
    record = comp["security_props"]
    assert record["status"] == "dropped"
    assert [r["property"] for r in record["rejected"]] == order[: fuzz_build.SECURITY_META_MAX_REJECTED]


@pytest.mark.unit
def test_a_frontend_without_the_vocabulary_builds_plain(run_dir, monkeypatch):
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    real = fuzz_build.build_eacsl_flag_sets

    def no_stubs(*args, **kwargs):
        return real(*args, **{**kwargs, "fc_stubs": None})

    monkeypatch.setattr(fuzz_build, "build_eacsl_flag_sets", no_stubs)
    fake = FakeToolchain()
    comp = build(monkeypatch, fake)["compile"]
    assert comp["returncode"] == 0 and len(fake.stage1_cmds) == 1
    assert "-meta" not in " ".join(fake.stage1_cmds[0]) and "--then-last" not in fake.stage1_cmds[0]
    record = comp["security_props"]
    assert record["status"] == "skipped" and "fc_compat_types.h" in record["reason"]
    assert "MetAcsl properties not loaded" in Path(comp["compile_log"]).read_text(encoding="utf-8")


@pytest.mark.unit
def test_the_other_callers_of_the_eacsl_build_never_load_the_properties(run_dir):
    # The selftest canary, the guardrail and the seed loop call compile_eacsl_binary themselves.
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    fake = FakeToolchain()
    comp = fuzz_build.compile_eacsl_binary(
        SOURCES, OUT_BIN, functions=list(MODULE_FUNCTIONS), runner=fake, use_cache=False
    )
    assert comp["returncode"] == 0 and "security_props" not in comp
    assert fake.stage1_cmds[0][fake.stage1_cmds[0].index("-F") + 1] == PLAIN_FC_FLAGS


# ---------------------------------------------------------------------------------------------------
# failure_identity: a violation is named after its property, wherever the meta file was written
# ---------------------------------------------------------------------------------------------------

STACK_HEAD = (
    "==1098== ERROR: libFuzzer: deadly signal\n"
    "    #0 0x634458e93758 in __sanitizer_print_stack_trace (/run/fuzz_prog.e-acsl+0x7e758)\n"
    "    #1 0x634458e6632c in fuzzer::PrintStackTrace() (/run/fuzz_prog.e-acsl+0x5132c)\n"
    "    #5 0x72c61f48fc41 in raise (/lib/x86_64-linux-gnu/libc.so.6+0x3fc41)\n"
)
STACK_TAIL = (
    "    #9 0x634458e4c9aa in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/run/f+0x379aa)\n"
    "    #12 0x634458e66e96 in main (/run/fuzz_prog.e-acsl+0x51e96)\n"
    "SUMMARY: libFuzzer: deadly signal\n"
)


def eacsl_report(meta_file: str, function: str, line: int, kind: str, label: str, predicate: str, frames: str) -> str:
    return (
        "Running: crash-1\n"
        f"{meta_file}: In function '{function}'\n"
        f"{meta_file}:{line}: Error: {kind} failed:\n"
        "\tThe failing predicate is:\n"
        f"\t{label}:\n"
        f"\t\t{predicate}.\n"
        "\tWith values at failure point:\n"
        "\t- auth_ok: 0\n" + STACK_HEAD + frames + STACK_TAIL
    )


WRITE_FRAMES = (
    "    #6 0x634458e96792 in backdoor /run/fuzz_prog.instrumented.c:2657:5\n"
    "    #7 0x634458e96792 in process /run/fuzz_prog.instrumented.c:2943:15\n"
    "    #8 0x634458e93efd in LLVMFuzzerTestOneInput /run/fuzz_prog.instrumented.c:743:3\n"
)
TARGET_CALL_FRAMES = (
    "    #6 0x597bafc830d9 in __gen_e_acsl_admin /run/fuzz_prog.instrumented.c:4894:5\n"
    "    #7 0x597bafc82f26 in process /run/fuzz_prog.instrumented.c:2901:12\n"
    "    #8 0x597bafc82f26 in LLVMFuzzerTestOneInput /run/fuzz_prog.instrumented.c:743:3\n"
)
HARNESS_CALL_FRAMES = (
    "    #6 0x597bafc830d9 in __gen_e_acsl_admin /run/fuzz_prog.instrumented.c:4894:5\n"
    "    #7 0x597bafc82f26 in LLVMFuzzerTestOneInput /run/fuzz_prog.instrumented.c:744:38\n"
)


@pytest.fixture
def built_meta(run_dir):
    """The meta file and sidecar of a build of the fixture, as write_security_meta leaves them."""
    write_props(DEFAULT_PROPS, fixture_props(["eacsl"]))
    plan = fuzz_build.resolve_security_meta(None, SOURCES, OUT_BIN)
    assert plan is not None
    written = fuzz_build.write_security_meta(plan, OUT_BIN)
    assert written is not None
    return written["meta_file"]


@pytest.mark.unit
def test_a_violated_property_is_named_in_the_failure_and_its_fingerprint(built_meta):
    text = eacsl_report(
        built_meta, "backdoor", 9, "Assertion", "L4_auth_state_login/meta", r"\separated(state, &auth_ok)", WRITE_FRAMES
    )
    failure = failure_identity.parse_runtime_failure(text)
    assert failure == {
        "file": "src/prog.c",
        "line": 0,
        "function": "backdoor",
        "kind": "assertion",
        "alarm_kind": "meta_L4_auth_state_login",
        "is_rte": False,
        "label": "L4_auth_state_login/meta",
        "predicate": r"L4_auth_state_login: meta: \separated(state, &auth_ok)",
        "meta_property": "L4_auth_state_login",
        "obligation_class": "l4_auth_state",
        "meta_location": f"{built_meta}:9",
    }
    fp = failure_identity.failure_fingerprint(failure)
    assert fp is not None
    assert fp.startswith("src/prog.c#backdoor::meta_l4_auth_state_login::") and fingerprint.is_valid_fingerprint(fp)
    assert not failure_identity.needs_attribution(failure)
    # The three other places that compute a fingerprint use the same four fields.
    assert fp == fingerprint.make_fingerprint(
        failure["file"], failure["function"], failure["alarm_kind"] or failure["kind"], failure["predicate"]
    )
    # What the ledger reads today maps the candidate to the property's class.
    as_goal = {"kind": failure["kind"], "annotation": failure["predicate"]}
    assert run_wp_function.goal_obligation_class(as_goal) == "l4_auth_state"


@pytest.mark.unit
def test_the_identity_does_not_depend_on_where_the_meta_file_is(built_meta, tmp_path):
    here = eacsl_report(built_meta, "session_close", 21, "Postcondition", "L6_wiped_session_key/meta", "P", "")
    replay_copy = tmp_path / "agents" / "v1" / "scratch" / "out" / "fuzz_prog.security_meta.c"
    replay_copy.parent.mkdir(parents=True)
    for path in (Path(built_meta), failure_identity.meta_sidecar_path(built_meta)):
        shutil.copy(path, replay_copy.parent / path.name)
    there = eacsl_report(str(replay_copy), "session_close", 34, "Postcondition", "L6_wiped_session_key/meta", "P", "")
    first, second = (failure_identity.parse_runtime_failure(t) for t in (here, there))
    assert first is not None and second is not None
    assert first["kind"] == "postcondition" and first["obligation_class"] == "l6_wiped"
    assert first["meta_location"] != second["meta_location"]
    first_fp = failure_identity.failure_fingerprint(first)
    assert first_fp is not None
    assert first_fp == failure_identity.failure_fingerprint(second)
    assert first_fp.startswith("src/prog.c#session_close::meta_l6_wiped_session_key::")


@pytest.mark.unit
def test_without_the_sidecar_the_property_and_its_class_are_still_named(tmp_path):
    text = eacsl_report(
        "elsewhere/fuzz_m.security_meta.c",
        "admin",
        12,
        "Precondition",
        "L4_auth_required_login/meta",
        "auth_ok ≢ 0",
        "",
    )
    failure = failure_identity.parse_runtime_failure(text)
    assert failure is not None
    assert failure["file"] == "unknown" and failure["meta_property"] == "L4_auth_required_login"
    assert failure["obligation_class"] == "l4_auth_required"  # from the name, as the ledger reads it
    assert "caller" not in failure and "harness_induced" not in failure
    fp = failure_identity.failure_fingerprint(failure)
    assert fp is not None
    assert fp.startswith("unknown#admin::meta_l4_auth_required_login::") and fingerprint.is_valid_fingerprint(fp)
    assert not failure_identity.needs_attribution(failure)
    # A name that spells no class the ledger knows.
    odd = failure_identity.parse_runtime_failure(text.replace("L4_auth_required_login", "my_rule"))
    assert odd is not None
    assert odd["obligation_class"] is None and odd["alarm_kind"] == "meta_my_rule"


@pytest.mark.unit
def test_a_failed_precondition_names_its_caller_and_a_harness_call(built_meta):
    args = (built_meta, "admin", 12, "Precondition", "L4_auth_required_login/meta", "auth_ok ≢ 0")
    real = failure_identity.parse_runtime_failure(eacsl_report(*args, TARGET_CALL_FRAMES))
    induced = failure_identity.parse_runtime_failure(eacsl_report(*args, HARNESS_CALL_FRAMES))
    assert real is not None and induced is not None
    assert real["function"] == induced["function"] == "admin" and real["kind"] == "precondition"
    assert (real["caller"], real["harness_induced"]) == ("process", False)
    assert (induced["caller"], induced["harness_induced"]) == ("LLVMFuzzerTestOneInput", True)
    # One property, one protected function: one identity. `harness_induced` tells the two apart.
    assert failure_identity.failure_fingerprint(real) == failure_identity.failure_fingerprint(induced)


@pytest.mark.unit
def test_a_class_the_name_does_not_spell_is_written_in_the_kind(built_meta):
    sidecar_path = failure_identity.meta_sidecar_path(built_meta)
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    sidecar["properties"]["L4_auth_state_login"]["obligation_class"] = "l3_writers"
    sidecar_path.write_text(json.dumps(sidecar), encoding="utf-8")
    failure_identity._META_SIDECARS.clear()
    text = eacsl_report(
        built_meta, "mix", 9, "Assertion", "L4_auth_state_login/meta", r"\separated(dst + i, &auth_ok)", ""
    )
    failure = failure_identity.parse_runtime_failure(text)
    assert failure is not None
    assert failure["obligation_class"] == "l3_writers"
    assert failure["alarm_kind"] == "meta_l3_writers_L4_auth_state_login"
    fp = failure_identity.failure_fingerprint(failure)
    assert fp is not None
    assert fp.startswith("src/prog.c#mix::meta_l3_writers_l4_auth_state_login::")


@pytest.mark.unit
def test_a_failed_guard_of_a_property_names_the_property(built_meta):
    # E-ACSL guards what a property's predicate reads; such a guard has the property's line, no label of it.
    sidecar = json.loads(failure_identity.meta_sidecar_path(built_meta).read_text(encoding="utf-8"))
    line = next(int(k) for k, v in sidecar["line_names"].items() if v == "L5_sanitized_logmsg")
    args = (built_meta, "process", line, "E-ACSL RTE", "memory access", r"\valid_read(s + i)", "")
    failure = failure_identity.parse_runtime_failure(eacsl_report(*args))
    assert failure is not None
    assert failure["meta_property"] == "L5_sanitized_logmsg" and failure["meta_guard"] == "memory access"
    assert (failure["file"], failure["line"], failure["function"]) == ("src/prog.c", 0, "process")
    assert failure["predicate"] == r"L5_sanitized_logmsg: meta: guard memory access: \valid_read(s + i)"
    fp = failure_identity.failure_fingerprint(failure)
    assert fp is not None
    assert fp.startswith("src/prog.c#process::meta_l5_sanitized_logmsg::") and fingerprint.is_valid_fingerprint(fp)
    violated = failure_identity.parse_runtime_failure(
        eacsl_report(built_meta, "process", line, "Assertion", "L5_sanitized_logmsg/meta", "no_crlf_string(line)", "")
    )
    assert fp != failure_identity.failure_fingerprint(violated)
    # A line of the meta file that holds no property, or a meta file without its sidecar: as before.
    for report in (
        eacsl_report(built_meta, "process", 1, "E-ACSL RTE", "memory access", "P", ""),
        eacsl_report("elsewhere/fuzz_m.security_meta.c", "process", line, "E-ACSL RTE", "memory access", "P", ""),
    ):
        parsed = failure_identity.parse_runtime_failure(report)
        assert parsed is not None
        assert "meta_property" not in parsed


RTE_REPORT = (
    "prog.c: In function 'mix'\n"
    "prog.c:48: Error: Assertion failed:\n"
    "\tThe failing predicate is:\n"
    "\trte/mem_access:\n"
    "\t\t\\valid(dst + i).\n"
    "\tWith values at failure point:\n"
    "\t- rte: mem_access: \\valid(dst + i): 0\n"
)


@pytest.mark.unit
def test_other_failures_keep_their_identity():
    failure = failure_identity.parse_runtime_failure(RTE_REPORT)
    assert failure == {
        "file": "prog.c",
        "line": 48,
        "function": "mix",
        "kind": "assertion",
        "alarm_kind": "mem_access",
        "is_rte": True,
        "label": "rte/mem_access",
        "predicate": "\\valid(dst + i)",
    }
    assert failure_identity.failure_fingerprint(failure) == "prog.c#mix::mem_access::60975404fe"
    # A hand-written annotation whose name merely ends in `meta` is no MetAcsl check.
    named = RTE_REPORT.replace("rte/mem_access", "my_meta").replace("prog.c", "harness_m.c")
    parsed = failure_identity.parse_runtime_failure(named)
    assert parsed is not None
    assert "meta_property" not in parsed
    assert failure_identity.needs_attribution({"file": "unknown", "line": 0, "function": "f"})


# ---------------------------------------------------------------------------------------------------
# Acceptance, in the image: the planted violations stop the binary, the correct program runs clean
# ---------------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def image_result(tmp_path_factory):
    """tests/fixtures/metacsl_eacsl/drive.py in the analysis image: five builds of the fixture and their runs."""
    require_docker_images(ANALYSIS_IMAGE)
    props = tmp_path_factory.mktemp("metacsl_eacsl_props")
    write_props(props / "on.json", fixture_props(["eacsl"]))
    write_props(props / "off.json", fixture_props([]))
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
        "-v", f"{META_EACSL_FIXTURE.resolve()}:/fixture:ro",
        "-v", f"{props.resolve()}:/props:ro",
        "-v", f"{ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
        "-v", f"{ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro",
        "-v", f"{ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
        ANALYSIS_IMAGE, "-c",
        "mkdir -p /tmp/run && cd /tmp/run && "
        "timeout 1500 python3 /fixture/drive.py /fixture /props/on.json /props/off.json",
    ]  # fmt: skip
    res = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800, check=False
    )
    lines = [ln for ln in res.stdout.splitlines() if ln.startswith("RESULT ")]
    assert res.returncode == 0 and lines, res.stdout[-4000:] + res.stderr[-4000:]
    result = json.loads(lines[-1][len("RESULT ") :])
    failed = {tag: b for tag, b in result["builds"].items() if b["returncode"] != 0}
    assert not failed, json.dumps(failed, indent=1)[-6000:]
    return result


@pytest.mark.integration
@pytest.mark.slow
def test_in_the_image_the_engine_switch_decides_the_build(image_result):
    builds = image_result["builds"]
    for tag in ("off", "viol_plain"):
        assert builds[tag]["security_props"] is None and "-meta" not in builds[tag]["command"], tag
        assert "--then-last" not in builds[tag]["command"], tag
    for tag in ("ok", "viol", "direct"):
        record = builds[tag]["security_props"]
        assert record["status"] == "loaded", (tag, record)
        assert "--then-last --e-acsl-extra -rte" in builds[tag]["command"], tag
        assert builds[tag]["cache"] == {"hit": False, "key": None}
        assert set(record["translated"]) | set(record["not_translated"]) == set(record["properties"]), record
        # The meta file never joins the sources the other builds and the report read.
        assert not any(s.endswith(".security_meta.c") for s in builds[tag]["sources"])
    assert builds["ok"]["security_props"]["properties"] == ALL_PROPERTY_NAMES
    assert builds["ok"]["security_props"]["left_out"] == []
    assert builds["direct"]["security_props"]["left_out"] == [
        {"property": "L4_auth_required_login", "reason": "the harness names its target admin"}
    ]
    # Every property has a run-time check in the program that violates it.
    assert sorted(builds["viol"]["security_props"]["translated"]) == sorted(ALL_PROPERTY_NAMES)
    assert builds["viol"]["security_props"]["unplanned_instances"] == {"L4_auth_state_login": ["backdoor"]}
    assert "L4_auth_required_login" not in builds["direct"]["security_props"]["properties"]


@pytest.mark.integration
@pytest.mark.slow
def test_in_the_image_no_check_of_the_plain_build_is_lost(image_result):
    for tag, found in image_result["assertions"].items():
        assert found["lost"] == [], (tag, found)
        assert found["with_properties"] > found["base"] > 0, (tag, found)
        assert any(name.endswith("/meta") for name in found["added_names"]), (tag, found)


@pytest.mark.integration
@pytest.mark.slow
def test_in_the_image_the_correct_program_runs_clean(image_result):
    for tag in ("ok", "direct"):
        for name, got in image_result["runs"][tag].items():
            assert got["rc"] == 0 and not got["error_lines"] and "failure" not in got, (tag, name, got)


@pytest.mark.integration
@pytest.mark.slow
def test_in_the_image_each_planted_violation_is_reported_under_its_property(image_result):
    runs = image_result["runs"]["viol"]
    expected = {
        "backdoor": ("L4_auth_state_login", "l4_auth_state", "backdoor", "assertion"),
        "admin": ("L4_auth_required_login", "l4_auth_required", "admin", "precondition"),
        "emit": ("L5_sanitized_emit", "l5_sanitized", "process", "assertion"),
        "text": ("L5_sanitized_logmsg", "l5_sanitized", "process", "assertion"),
        "close": ("L6_wiped_session_key", "l6_wiped", "session_close", "postcondition"),
        "leak": ("L6_no_leak_session_key", "l6_no_leak", "process", "assertion"),
    }
    for name, (prop, cls, function, kind) in expected.items():
        got = runs[name]
        assert got["rc"] != 0 and "failure" in got, (name, got)
        failure = got["failure"]
        assert failure["meta_property"] == prop and failure["obligation_class"] == cls, (name, failure)
        assert (failure["file"], failure["function"], failure["kind"]) == ("src/prog.c", function, kind), failure
        assert got["fingerprint"].startswith(f"src/prog.c#{function}::meta_{prop.lower()}::"), got["fingerprint"]
        assert got["fingerprint_valid"] and not got["needs_attribution"] and got["ledger_class"] == cls, got
    assert (runs["admin"]["failure"]["caller"], runs["admin"]["failure"]["harness_induced"]) == ("process", False)
    for name in ("login", "other"):
        assert runs[name]["rc"] == 0 and "failure" not in runs[name], (name, runs[name])
    # libFuzzer stops on the violating input and keeps it.
    campaign = image_result["campaign"]
    assert campaign["rc"] != 0 and campaign["artifacts"] and campaign["artifacts"][0].startswith("crash-"), campaign
    assert campaign["artifact_bytes"][0] == "B" and campaign["fingerprint"] == runs["backdoor"]["fingerprint"]


@pytest.mark.integration
@pytest.mark.slow
def test_in_the_image_a_libc_write_into_the_state_is_reported_and_an_overflow_keeps_its_identity(image_result):
    builds, runs = image_result["builds"], image_result["runs"]
    for tag in ("ok", "viol", "direct"):
        record = builds[tag]["security_props"]
        assert record["libc_contracts"] == {
            "status": "loaded",
            "functions": list(eacsl_toolchain.EACSL_META_LIBC_WRITERS),
        }, (tag, record)
        assert record["libc_unchecked"] == {}, (tag, record)
    # memcpy into the authentication state: a violation of the property, in the caller.
    got = runs["viol"]["memcpy_auth"]
    assert got["rc"] != 0 and "failure" in got, got
    failure = got["failure"]
    assert (failure["meta_property"], failure["function"], failure["kind"]) == (
        "L4_auth_state_login",
        "process",
        "assertion",
    ), failure
    assert got["fingerprint"].startswith("src/prog.c#process::meta_l4_auth_state_login::"), got["fingerprint"]
    # A correct memcpy runs clean, with and without the planted violations.
    for tag in ("ok", "viol"):
        assert runs[tag]["memcpy_ok"]["rc"] == 0 and "failure" not in runs[tag]["memcpy_ok"], runs[tag]
    # An overflow through memcpy is reported by E-ACSL's replacement, as without the properties:
    # the property's validity guard (eacsl_meta_guarded_text) keeps its check from firing first.
    plain, meta = runs["viol_plain"]["memcpy_overflow"], runs["viol"]["memcpy_overflow"]
    assert plain["rc"] != 0 and plain["fingerprint"], plain
    assert meta["fingerprint"] == plain["fingerprint"], (plain, meta)
    # A zero-length memcpy writes nothing: the empty range must not fail the guard or the property.
    for tag in ("viol_plain", "viol"):
        empty = runs[tag]["memcpy_empty"]
        assert empty["rc"] == 0 and "failure" not in empty, (tag, empty)


@pytest.mark.integration
@pytest.mark.slow
def test_in_the_image_an_ordinary_defect_keeps_its_identity(image_result):
    with_properties = image_result["runs"]["viol"]["long"]
    plain = image_result["runs"]["viol_plain"]["long"]
    assert plain["rc"] != 0 and plain["failure"]["alarm_kind"] == "mem_access", plain
    assert with_properties["fingerprint"] == plain["fingerprint"], (with_properties, plain)
    assert with_properties["failure"] == plain["failure"]
    # Without the properties the same input is no failure at all.
    assert image_result["runs"]["viol_plain"]["backdoor"]["rc"] == 0
