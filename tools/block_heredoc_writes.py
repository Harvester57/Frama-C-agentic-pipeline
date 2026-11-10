#!/usr/bin/env python3
"""
Claude Code PreToolUse hook: refuse Bash/PowerShell commands that write a file through a heredoc or a
here-string.

Text written that way passes through the shell's quoting first, and on this Windows host that is where
ACSL backslashes (``\\result``, ``\\valid_read``), ``\\n`` sequences and line endings get rewritten. The
Write and Edit tools store the text exactly, so the hook sends the agent there.

Blocked (the write is on the command's own lines, not inside the heredoc/here-string body):

* bash heredoc ``<<EOF`` / ``<<-'EOF'`` or here-string ``<<<`` whose command redirects into a file
  (``>``, ``>>``) or pipes into ``tee FILE``;
* PowerShell here-string ``@'...'@`` / ``@"..."@`` in a command that writes a file (``Set-Content``,
  ``Add-Content``, ``Out-File``, ``Tee-Object``, ``New-Item -Value``, ``[IO.File]::Write*``, ``>``).

Not blocked: heredocs fed to a program's stdin (``python - <<'EOF'``, ``git commit -F - <<EOF``),
redirections to ``/dev/null`` / ``$null``, and here-strings passed as arguments (``git commit -m @'...'@``).

Exit 2 with the reason on stderr blocks the call and shows the reason to the agent; anything else is 0.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Sequence

# --- bash ------------------------------------------------------------------------------------------

_HEREDOC_RE = re.compile(r"(?<!<)<<(?!<)(-?)\s*(?:'([^'\n]+)'|\"([^\"\n]+)\"|\\?([A-Za-z_][\w.-]*))")
_HERESTRING_RE = re.compile(r"<<<")
_NULL_SINKS = {"/dev/null", "/dev/stderr", "/dev/stdout", "nul", "$null"}
# `>` / `>>` not part of `2>`, `&>`, `>&2`, `->`, `=>`, `<>`, nor a comparison inside `[[ ]]`.
_BASH_REDIRECT_RE = re.compile(r"(?<![\d&=<>-])>>?\|?\s*(?!&)([^\s;&|()<>]+)")
_TEE_RE = re.compile(r"\btee\b((?:\s+-[a-zA-Z]+)*)\s+([^\s;&|()<>]+)")


_QUOTED_RE = re.compile(r"'[^']*'|\"(?:\\.|[^\"\\])*\"")


def _mask_quotes(line: str) -> str:
    """Blank quoted text (data such as `printf '... <<EOF > f'`), keeping quoted heredoc delimiters."""

    def blank(match: re.Match[str]) -> str:
        before = line[: match.start()].rstrip()
        if before.endswith("<<") or before.endswith("<<-"):
            return match.group(0)
        return match.group(0)[0] + " " * (len(match.group(0)) - 2) + match.group(0)[-1]

    return _QUOTED_RE.sub(blank, line)


def _bash_command_lines(command: str) -> tuple[list[str], bool, list[str]]:
    """(heredoc/here-string start lines, any found, all non-body lines)."""
    starts: list[str] = []
    outside: list[str] = []
    pending: list[tuple[str, bool]] = []  # (delimiter, strip leading tabs)
    found = False
    for line in command.split("\n"):
        if pending:
            delimiter, strip_tabs = pending[0]
            candidate = line.lstrip("\t") if strip_tabs else line
            if candidate.rstrip("\r") == delimiter:
                pending.pop(0)
            continue
        outside.append(line)
        masked = _mask_quotes(line)
        heredocs = list(_HEREDOC_RE.finditer(masked))
        if heredocs or _HERESTRING_RE.search(masked):
            found = True
            starts.append(masked)
        for match in heredocs:
            delimiter = match.group(2) or match.group(3) or match.group(4)
            pending.append((delimiter, match.group(1) == "-"))
    return starts, found, outside


def _writes_file_bash(line: str) -> str | None:
    for match in _BASH_REDIRECT_RE.finditer(line):
        target = match.group(1).strip("'\"")
        if target.lower() not in _NULL_SINKS:
            return f"redirects into {target}"
    tee = _TEE_RE.search(line)
    if tee and tee.group(2).strip("'\"").lower() not in _NULL_SINKS:
        return f"pipes into tee {tee.group(2)}"
    return None


def bash_violation(command: str) -> str | None:
    starts, found, _ = _bash_command_lines(command)
    if not found:
        return None
    for line in starts:
        reason = _writes_file_bash(line)
        if reason:
            return f"heredoc/here-string {reason}"
    return None


# --- PowerShell ------------------------------------------------------------------------------------

_PS_HERE_OPEN_RE = re.compile(r"@(['\"])\s*$")
_PS_WRITE_RE = re.compile(
    r"\b(Set-Content|Add-Content|Out-File|Tee-Object)\b"
    r"|\bNew-Item\b[^\n]*-Value\b"
    r"|\[(?:System\.)?IO\.File\]::(?:Write|Append)\w*"
    r"|(?:^|[^\d=<>-])>>?\s*(?!\$null\b|&)[^\s;|]+",
    re.IGNORECASE,
)


def _powershell_outside_lines(command: str) -> tuple[list[str], bool]:
    outside: list[str] = []
    closing: str | None = None
    found = False
    for line in command.split("\n"):
        if closing is not None:
            if line.startswith(closing):
                outside.append(line[len(closing) :])
                closing = None
            continue
        outside.append(line)
        opened = _PS_HERE_OPEN_RE.search(line)
        if opened:
            found = True
            closing = opened.group(1) + "@"
    return outside, found


def powershell_violation(command: str) -> str | None:
    outside, found = _powershell_outside_lines(command)
    if not found:
        return None
    for line in outside:
        match = _PS_WRITE_RE.search(line)
        if match:
            return f"here-string written to a file ({match.group(0).strip()})"
    return None


# --- hook ------------------------------------------------------------------------------------------

MESSAGE = (
    "Blocked: {reason}. Do not write files through heredocs or here-strings: the shell rewrites "
    "backslashes (ACSL \\result, \\valid_read, \\n) and line endings on the way. Create the file with the "
    "Write tool (or change it with Edit), then run your command on it. For a commit message, Write it to "
    "a file and use `git commit -F <file>`. See CLAUDE.md, 'Windows shell & file-writing rules'."
)


def check(tool_name: str, command: str) -> str | None:
    """The block message for this tool call, or None to let it run."""
    if tool_name == "PowerShell":
        reason = powershell_violation(command)
    elif tool_name == "Bash":
        reason = bash_violation(command)
    else:
        return None
    return MESSAGE.format(reason=reason) if reason else None


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        return 0
    if not isinstance(payload, dict):
        return 0
    tool_input = payload.get("tool_input") or {}
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return 0
    message = check(str(payload.get("tool_name", "")), command)
    if message:
        print(message, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
