"""tools/check_generated_text.py: one test group per rule, with the real past bugs as fixtures."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import check_generated_text as cgt

pytestmark = pytest.mark.unit

# Control characters are built at run time so this module's own source stays clean.
CR, VT, FF, BEL, BS, ESC, DEL = "\r", "\x0b", "\x0c", "\x07", "\x08", "\x1b", "\x7f"
BSL = "\\"


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    return path


def _rules(tmp_path: Path, name: str, text: str, **kw) -> list[tuple[int, str]]:
    path = _write(tmp_path, name, text)
    return [(v.line, v.rule) for v in cgt.check_file(path, root=tmp_path, **kw)]


# --- control-char ----------------------------------------------------------------------------------


class TestControlChars:
    @pytest.mark.parametrize("suffix", [".py", ".md", ".sh", ".c", ".h"])
    def test_each_checked_type_flags_a_control_character(self, tmp_path: Path, suffix: str) -> None:
        assert (2, "control-char") in _rules(tmp_path, "f" + suffix, "ok\nbad " + ESC + " here\n")

    def test_tab_and_newline_are_fine(self, tmp_path: Path) -> None:
        assert _rules(tmp_path, "a.c", "int\tx;\n\nint y;\n") == []

    def test_del_is_a_control_character(self, tmp_path: Path) -> None:
        assert _rules(tmp_path, "a.md", "x" + DEL + "\n") == [(1, "control-char")]

    def test_lone_cr_is_flagged_but_a_crlf_ending_is_left_to_the_crlf_rule(self, tmp_path: Path) -> None:
        assert _rules(tmp_path, "a.c", "int x;\r\nint y;\r\n") == []
        assert _rules(tmp_path, "b.c", "a" + CR + "b\n") == [(1, "control-char")]

    def test_other_suffixes_are_not_checked(self, tmp_path: Path) -> None:
        assert _rules(tmp_path, "a.txt", ESC + "\r\n") == []

    def test_message_names_the_acsl_builtin_a_control_character_replaced(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "a.c", "/*@ ensures " + CR + "esult == 0; */\n")
        messages = [v.message for v in cgt.check_file(path, root=tmp_path) if v.rule == "control-char"]
        assert messages and "\\result" in messages[0]


# --- crlf ------------------------------------------------------------------------------------------


class TestCrlf:
    @pytest.mark.parametrize("name", ["run.sh", "mod.py"])
    def test_crlf_is_flagged_in_shell_and_python(self, tmp_path: Path, name: str) -> None:
        violations = cgt.check_file(_write(tmp_path, name, "a = 1\r\nb = 2\r\n"), root=tmp_path)
        crlf = [v for v in violations if v.rule == "crlf"]
        assert len(crlf) == 1 and crlf[0].line == 1 and "2 lines" in crlf[0].message
        assert not [v for v in violations if v.rule == "control-char"]

    @pytest.mark.parametrize("name", ["a.c", "a.h", "a.md"])
    def test_crlf_is_not_a_finding_elsewhere(self, tmp_path: Path, name: str) -> None:
        assert _rules(tmp_path, name, "x\r\ny\r\n") == []

    def test_lf_only_is_fine(self, tmp_path: Path) -> None:
        assert _rules(tmp_path, "run.sh", "#!/bin/sh\necho hi\n") == []


# --- sh-literal-newline ----------------------------------------------------------------------------


class TestShLiteralNewline:
    def test_a_script_written_as_one_escaped_string_is_flagged(self, tmp_path: Path) -> None:
        text = "#!/bin/sh" + BSL + "nset -e" + BSL + "nmake all" + BSL + "n"
        assert _rules(tmp_path, "build.sh", text) == [(1, "sh-literal-newline")]

    def test_echo_without_e_is_flagged(self, tmp_path: Path) -> None:
        assert _rules(tmp_path, "a.sh", 'echo "a' + BSL + 'nb" > out\n') == [(1, "sh-literal-newline")]

    @pytest.mark.parametrize(
        "line",
        [
            "printf 'a" + BSL + "nb'",
            "echo -e 'a" + BSL + "nb'",
            "x=$'a" + BSL + "nb'",
            "sed 's/,/" + BSL + "n/g' f",
            "# comment with " + BSL + "n",
            "echo '" + BSL + BSL + "n is escaped'",
        ],
    )
    def test_intended_spellings_are_fine(self, tmp_path: Path, line: str) -> None:
        assert _rules(tmp_path, "a.sh", line + "\n") == []

    def test_acsl_nothing_and_null_in_an_embedded_annotation_are_fine(self, tmp_path: Path) -> None:
        text = (
            "cat > s.h <<'EOF'\n/*@ assigns " + BSL + "nothing; ensures " + BSL + "result != " + BSL + "null; */\nEOF\n"
        )
        assert _rules(tmp_path, "a.sh", text) == []

    def test_only_shell_scripts_are_checked(self, tmp_path: Path) -> None:
        assert _rules(tmp_path, "a.md", "line" + BSL + "n\n") == []


# --- acsl-corrupted: the real past bugs ------------------------------------------------------------


class TestAcslCorrupted:
    def test_corrupted_result_in_c(self, tmp_path: Path) -> None:
        """The `\\result` that a non-raw Python string turned into CR + `esult`."""
        text = "/*@ requires n >= 0;\n    ensures " + CR + "esult == n; */\nint f(int n);\n"
        rules = _rules(tmp_path, "f.c", text)
        assert (2, "control-char") in rules

    def test_mangled_valid_read_in_a_header(self, tmp_path: Path) -> None:
        """The `\\valid_read` whose `\\v` became a vertical tab."""
        text = "/*@ requires " + VT + "alid_read(p + (0 .. n - 1)); */\nint g(const char *p, int n);\n"
        path = _write(tmp_path, "g.h", text)
        violations = cgt.check_file(path, root=tmp_path)
        assert {v.rule for v in violations} == {"control-char"}
        assert "\\valid_read" in violations[0].message

    def test_mangled_valid_read_with_the_control_character_stripped(self, tmp_path: Path) -> None:
        """What Frama-C reported as `unbound logic variable`: backslash and letter both gone."""
        text = "/*@ requires alid_read(p); ensures \\result == 0; */\n"
        assert _rules(tmp_path, "g.c", text) == [(1, "acsl-corrupted")]

    @pytest.mark.parametrize("tail", ["alse", "orall integer i; i >= 0", "esult == 0", "othing"])
    def test_stripped_builtins_inside_an_annotation(self, tmp_path: Path, tail: str) -> None:
        assert ("acsl-corrupted") in [r for _, r in _rules(tmp_path, "a.c", "//@ assert " + tail + ";\n")]

    def test_nothing_turned_into_a_newline_inside_an_annotation(self, tmp_path: Path) -> None:
        text = "/*@ assigns \nothing; */\n"
        assert _rules(tmp_path, "a.c", text) == [(1, "acsl-corrupted")]

    def test_builtins_outside_annotations_are_not_checked(self, tmp_path: Path) -> None:
        assert _rules(tmp_path, "a.c", "int alse = 0; /* plain comment: alid */\n") == []

    def test_correct_annotations_are_fine(self, tmp_path: Path) -> None:
        text = (
            "/*@ requires \\valid_read(p) && \\valid(q);\n"
            "    assigns \\nothing;\n"
            "    ensures \\result == \\old(*q) && \\forall integer i; \\true || \\false; */\n"
        )
        assert _rules(tmp_path, "a.c", text) == []


class TestAcslCorruptedInPython:
    def test_non_raw_result_in_python_source(self, tmp_path: Path) -> None:
        """The source shape that produced the corrupted `\\result`: a non-raw string."""
        source = 'CLAUSE = "ensures ' + BSL + 'result == 0;"\n'
        violations = cgt.check_file(_write(tmp_path, "gen.py", source), root=tmp_path)
        assert [(v.line, v.rule) for v in violations] == [(1, "acsl-corrupted")]
        assert "raw string" in violations[0].message

    def test_non_raw_valid_read_in_python_source(self, tmp_path: Path) -> None:
        source = 'pre = "requires ' + BSL + 'valid_read(p);"\n'
        assert _rules(tmp_path, "gen.py", source) == [(1, "acsl-corrupted")]

    @pytest.mark.parametrize(
        "literal",
        [
            'r"ensures ' + BSL + 'result == 0;"',
            '"ensures ' + BSL + BSL + 'result == 0;"',
            'r"""/*@ requires ' + BSL + 'valid_read(p); */"""',
        ],
    )
    def test_raw_or_escaped_strings_are_fine(self, tmp_path: Path, literal: str) -> None:
        assert _rules(tmp_path, "gen.py", "x = " + literal + "\n") == []

    def test_nothing_and_true_escapes_are_flagged_in_acsl_strings(self, tmp_path: Path) -> None:
        source = (
            'A = "/*@ assigns ' + BSL + 'nothing; */"\n'
            'B = "/*@ assert ' + BSL + 'true; */"\n'
            'C = "Error:' + BSL + 'nothing to report"\n'
        )
        assert _rules(tmp_path, "gen.py", source) == [(1, "acsl-corrupted"), (2, "acsl-corrupted")]

    def test_f_strings_are_checked(self, tmp_path: Path) -> None:
        source = 'def f(x):\n    return f"ensures ' + BSL + 'result == {x};"\n'
        assert _rules(tmp_path, "gen.py", source) == [(2, "acsl-corrupted")]

    def test_line_numbers_inside_a_triple_quoted_string(self, tmp_path: Path) -> None:
        source = 'S = """/*@\n  requires n > 0;\n  ensures ' + BSL + 'result > 0;\n*/"""\n'
        assert _rules(tmp_path, "gen.py", source) == [(3, "acsl-corrupted")]


# --- acsl-missing-backslash ------------------------------------------------------------------------


class TestAcslMissingBackslash:
    @pytest.mark.parametrize(
        "annotation",
        [
            "/*@ requires valid_read(p); */",
            "/*@ requires valid(p + (0 .. 3)); */",
            "/*@ ensures *p == old(*p) + 1; */",
            "/*@ assigns nothing; */",
            "/*@ ensures result == 0; */",
            "//@ assert initialized(&x);",
        ],
    )
    def test_builtins_without_backslash_are_flagged(self, tmp_path: Path, annotation: str) -> None:
        assert [r for _, r in _rules(tmp_path, "a.c", annotation + "\n")] == ["acsl-missing-backslash"]

    @pytest.mark.parametrize(
        "annotation",
        [
            "/*@ ensures result: \\result == 0; */",
            "/*@ ensures ok: s->result == 1; */",
            "/*@ requires \\valid(p) && p->valid(1); */",
        ],
    )
    def test_labels_and_members_are_fine(self, tmp_path: Path, annotation: str) -> None:
        assert _rules(tmp_path, "a.c", annotation + "\n") == []

    def test_c_code_is_not_acsl(self, tmp_path: Path) -> None:
        assert _rules(tmp_path, "a.c", "int valid(int x); int result = valid(1); /* old(x) */\n") == []

    def test_python_strings_holding_annotations_are_checked(self, tmp_path: Path) -> None:
        source = 'S = "/*@ requires valid_read(p); */"\nT = "requires valid(p);"\nU = "This ensures result is valid."\n'
        assert _rules(tmp_path, "gen.py", source) == [(1, "acsl-missing-backslash"), (2, "acsl-missing-backslash")]

    def test_format_placeholders_are_fine(self, tmp_path: Path) -> None:
        source = 'S = "/*@ ensures ok: {result}; */"\n'
        assert _rules(tmp_path, "gen.py", source) == []

    def test_markdown_code_blocks_are_checked(self, tmp_path: Path) -> None:
        text = "Example:\n\n```c\n/*@ requires valid(p); */\n```\n"
        assert _rules(tmp_path, "doc.md", text) == [(4, "acsl-missing-backslash")]


# --- test-constant-redefined -----------------------------------------------------------------------


class TestTestConstantRedefined:
    def test_redefined_tree_constant(self, tmp_path: Path) -> None:
        """The TREE collision: a test module importing another one that already defines TREE."""
        _write(tmp_path, "test_model.py", 'TREE = "/framac-scratch/tree"\n\ndef model_run():\n    return TREE\n')
        child = 'from test_model import model_run\n\nTREE = "/s/tree"\n\ndef test_x():\n    assert model_run()\n'
        rules = _rules(tmp_path, "test_capture.py", child, search_paths=[])
        assert rules == [(3, "test-constant-redefined")]
        path = tmp_path / "test_capture.py"
        message = cgt.check_file(path, root=tmp_path, search_paths=[])[0].message
        assert "TREE" in message and "test_model" in message

    def test_plain_import_and_conftest_count_too(self, tmp_path: Path) -> None:
        _write(tmp_path, "conftest.py", "from pathlib import Path\nROOT = Path(__file__).parent\n")
        child = "import conftest\nfrom pathlib import Path\nROOT = Path('.')\n"
        assert _rules(tmp_path, "test_a.py", child, search_paths=[]) == [(3, "test-constant-redefined")]

    def test_modules_on_the_search_path_are_resolved(self, tmp_path: Path) -> None:
        _write(tmp_path, "scripts/helper.py", "LIMIT: int = 5\n")
        _write(tmp_path, "tests/test_b.py", "import helper\nLIMIT = 6\n")
        path = tmp_path / "tests" / "test_b.py"
        violations = cgt.check_file(path, root=tmp_path, search_paths=[tmp_path / "scripts"])
        assert [(v.line, v.rule) for v in violations] == [(2, "test-constant-redefined")]

    def test_distinct_names_and_lowercase_are_fine(self, tmp_path: Path) -> None:
        _write(tmp_path, "test_model.py", 'TREE = "/t"\ntree_root = "/t"\n')
        child = 'from test_model import TREE\nCAPTURE_TREE = "/s"\ntree_root = "/s"\n'
        assert _rules(tmp_path, "test_c.py", child, search_paths=[]) == []

    def test_a_constant_with_no_imported_twin_is_fine(self, tmp_path: Path) -> None:
        _write(tmp_path, "test_model.py", 'OTHER = "/t"\n')
        assert _rules(tmp_path, "test_d.py", 'import test_model\nTREE = "/s"\n', search_paths=[]) == []

    def test_only_test_modules_are_checked(self, tmp_path: Path) -> None:
        _write(tmp_path, "base.py", 'TREE = "/t"\n')
        assert _rules(tmp_path, "tool.py", 'import base\nTREE = "/s"\n', search_paths=[]) == []


# --- allowlist and driver --------------------------------------------------------------------------


class TestAllowlist:
    def test_entries_need_a_justification(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "a.allow", "tests/x.py control-char\n")
        with pytest.raises(ValueError, match="justification"):
            cgt.load_allowlist(path)

    def test_unknown_rules_are_refused(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "a.allow", "tests/x.py no-such-rule -- because\n")
        with pytest.raises(ValueError, match="unknown rule"):
            cgt.load_allowlist(path)

    def test_matching_by_glob_and_rule(self, tmp_path: Path) -> None:
        allow = cgt.load_allowlist(_write(tmp_path, "a.allow", "# c\n\ndocs/*.md control-char -- fixture\n"))
        hit = cgt.Violation("docs/a.md", 1, "control-char", "x")
        other_rule = cgt.Violation("docs/a.md", 1, "crlf", "x")
        other_file = cgt.Violation("src/a.md", 1, "control-char", "x")
        assert cgt.filter_allowed([hit, other_rule, other_file], allow) == [other_rule, other_file]

    def test_the_repository_allowlist_parses(self) -> None:
        assert all(entry.justification for entry in cgt.load_allowlist(cgt.DEFAULT_ALLOWLIST))


class TestCli:
    def test_exit_status_and_output(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        bad = _write(tmp_path, "a.c", "x" + BEL + "\n")
        good = _write(tmp_path, "b.c", "int x;\n")
        assert cgt.main([str(good), "--root", str(tmp_path), "--no-allowlist"]) == 0
        assert cgt.main([str(bad), "--root", str(tmp_path), "--no-allowlist"]) == 1
        assert "a.c:1: [control-char]" in capsys.readouterr().out

    def test_the_repository_is_clean(self) -> None:
        """Every tracked file passes, apart from the justified entries in check_generated_text.allow."""
        allow = cgt.load_allowlist(cgt.DEFAULT_ALLOWLIST)
        violations = cgt.check_paths(cgt.repo_files(cgt.ROOT), root=cgt.ROOT, allow=allow)
        assert [v.format() for v in violations] == []


# --- PostToolUse hook ------------------------------------------------------------------------------


class TestHook:
    def test_write_of_a_bad_file_is_reported_to_the_agent(self, tmp_path: Path) -> None:
        bad = _write(tmp_path, "gen.py", 'S = "ensures ' + BSL + 'result == 0;"\n')
        payload = {"tool_name": "Write", "tool_input": {"file_path": str(bad)}, "cwd": str(tmp_path)}
        code, message = cgt.run_hook(json.dumps(payload), root=tmp_path, allowlist=tmp_path / "none")
        assert code == 2
        assert "gen.py:1: [acsl-corrupted]" in message and "Edit tool" in message

    def test_clean_edit_passes_silently(self, tmp_path: Path) -> None:
        good = _write(tmp_path, "ok.c", "int x;\n")
        payload = {"tool_name": "Edit", "tool_input": {"file_path": str(good)}, "cwd": str(tmp_path)}
        assert cgt.run_hook(json.dumps(payload), root=tmp_path, allowlist=tmp_path / "none") == (0, "")

    def test_files_named_in_a_shell_command_are_checked(self, tmp_path: Path) -> None:
        _write(tmp_path, "out/run.sh", "echo hi\r\n")
        payload = {"tool_name": "Bash", "tool_input": {"command": "sed -i 's/a/b/' 'out/run.sh'"}, "cwd": str(tmp_path)}
        code, message = cgt.run_hook(json.dumps(payload), root=tmp_path, allowlist=tmp_path / "none")
        assert code == 2 and "[crlf]" in message

    def test_recently_modified_dirty_files_count_as_touched_by_a_shell_command(self, tmp_path: Path) -> None:
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        _write(tmp_path, "gen/x.h", "/*@ requires valid(p); */\n")
        payload = {"tool_name": "PowerShell", "tool_input": {"command": "python make_headers.py"}, "cwd": str(tmp_path)}
        code, message = cgt.run_hook(json.dumps(payload), root=tmp_path, allowlist=tmp_path / "none")
        assert code == 2 and "gen/x.h:1: [acsl-missing-backslash]" in message

    @pytest.mark.parametrize("stdin", ["", "not json", "[]", '{"tool_name": "Read"}'])
    def test_unusable_payloads_pass(self, tmp_path: Path, stdin: str) -> None:
        assert cgt.run_hook(stdin, root=tmp_path, allowlist=tmp_path / "none") == (0, "")

    def test_hook_entry_point_exits_2_on_violations(self, tmp_path: Path) -> None:
        bad = _write(tmp_path, "a.md", "x" + FF + "orall\n")
        payload = {"tool_name": "Write", "tool_input": {"file_path": str(bad)}, "cwd": str(tmp_path)}
        proc = subprocess.run(
            [sys.executable, str(Path(cgt.__file__)), "--hook", "--root", str(tmp_path)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 2
        assert "[control-char]" in proc.stderr and "\\forall" in proc.stderr


def test_settings_wire_both_hooks_to_existing_scripts() -> None:
    settings = json.loads((cgt.ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    hooks = settings["hooks"]
    pre = hooks["PreToolUse"][0]
    post = hooks["PostToolUse"][0]
    assert set(pre["matcher"].split("|")) == {"Bash", "PowerShell"}
    assert {"Write", "Edit", "Bash"} <= set(post["matcher"].split("|"))
    assert "tools/block_heredoc_writes.py" in pre["hooks"][0]["command"]
    assert "tools/check_generated_text.py" in post["hooks"][0]["command"]
    assert "--hook" in post["hooks"][0]["command"]
    assert (cgt.ROOT / "tools" / "block_heredoc_writes.py").is_file()
