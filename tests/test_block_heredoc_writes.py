"""tools/block_heredoc_writes.py: the PreToolUse hook that refuses heredoc/here-string file writes."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import block_heredoc_writes as bhw

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "command",
    [
        "cat > scripts/gen.py <<'EOF'\nS = r'ensures \\result == 0;'\nEOF",
        "cat <<EOF > out.c\nint x;\nEOF",
        "cat <<-EOF >> notes.md\n\tline\n\tEOF",
        'cat << "END" | tee docs/a.md\ntext\nEND',
        "tee -a log.txt <<EOF\nx\nEOF",
        "cat <<< 'int x;' > a.c",
        "cd /tmp && cat > a.sh <<'EOF'\necho hi\nEOF\nbash a.sh",
    ],
)
def test_bash_heredoc_writes_are_blocked(command: str) -> None:
    message = bhw.check("Bash", command)
    assert message is not None and "Write tool" in message


@pytest.mark.parametrize(
    "command",
    [
        "python - <<'EOF'\nprint('x > y')\nEOF",
        "git commit -F - <<EOF\nmsg\nEOF",
        "cat <<EOF >/dev/null\nx\nEOF",
        "python - <<'EOF' 2>&1\nopen('a').read()\nEOF",
        # A `>` inside the heredoc body is not a redirection.
        "python - <<'EOF'\nwith open('a', 'w') as f: f.write('x')  # cat > b\nEOF",
        "ls > files.txt",
        "echo hi",
        "[[ $a > $b ]] && echo ok",
    ],
)
def test_bash_commands_without_a_heredoc_write_pass(command: str) -> None:
    assert bhw.check("Bash", command) is None


@pytest.mark.parametrize(
    "command",
    [
        "@'\nensures \\result == 0;\n'@ | Set-Content gen.py",
        'Set-Content -Path a.c -Value @"\nint x;\n"@',
        "$t = @'\nx\n'@\n$t | Out-File -Encoding utf8 a.md",
        "@'\nx\n'@ > a.txt",
        "[IO.File]::WriteAllText('a.h', @'\nint x;\n'@)",
        "New-Item a.sh -Value @'\necho hi\n'@",
        "@'\nx\n'@ | Add-Content log.md",
    ],
)
def test_powershell_here_string_writes_are_blocked(command: str) -> None:
    message = bhw.check("PowerShell", command)
    assert message is not None and "here-string" in message


@pytest.mark.parametrize(
    "command",
    [
        "git commit -m @'\nsubject\n\nbody > details\n'@",
        "Set-Content a.txt 'x'",
        "@'\nx\n'@ | python -",
        "docker ps 2>$null",
        "$x = @'\nSet-Content inside the body is data\n'@\nWrite-Host $x",
    ],
)
def test_powershell_commands_without_a_here_string_write_pass(command: str) -> None:
    assert bhw.check("PowerShell", command) is None


def test_other_tools_are_ignored() -> None:
    assert bhw.check("Write", "cat > a <<EOF\nEOF") is None


def _run(payload: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(Path(bhw.__file__))],
        input=payload if isinstance(payload, str) else json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
    )


def test_entry_point_blocks_with_exit_2_and_a_reason() -> None:
    proc = _run({"tool_name": "Bash", "tool_input": {"command": "cat > a.c <<'EOF'\nint x;\nEOF"}})
    assert proc.returncode == 2
    assert "Blocked" in proc.stderr and "Write tool" in proc.stderr


@pytest.mark.parametrize("payload", [{"tool_name": "Bash", "tool_input": {"command": "ls"}}, "garbage", {}])
def test_entry_point_passes_everything_else(payload: object) -> None:
    proc = _run(payload)
    assert proc.returncode == 0 and proc.stderr == ""
