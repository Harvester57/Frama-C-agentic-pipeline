#!/usr/bin/env python3
"""
Guardrail against the escaping and platform bugs that keep reappearing in generated text.

Agents on Windows write files through shells and Python strings that silently rewrite backslashes
and line endings. The ACSL that results looks right in a diff and fails much later in Frama-C
(``unbound logic variable alse``), a shell script breaks in the Linux container, or two test modules
quietly disagree about a shared constant. This checker flags those shapes at write time.

Rules (rule id: what it flags):

``control-char``
    ASCII control characters other than tab and newline in .py, .md, .sh, .c and .h files. A CR that
    ends a CRLF line is a line-ending question, not a corrupted escape: ``crlf`` covers it for .sh and
    .py, the only types where it breaks something.
``crlf``
    CRLF line endings in .sh and .py files (bash in the Linux containers reads ``$'\\r'``).
``sh-literal-newline``
    A literal backslash-n in a .sh file outside the places that mean it (printf formats, ``echo -e``,
    ``$'...'``, sed/awk/tr/grep programs): the sign of a script written as one escaped string.
``acsl-corrupted``
    An ACSL builtin whose backslash became a control character (``\\result`` -> CR + ``esult``,
    ``\\valid_read`` -> VT + ``alid_read``), or lost it and its letter (``alse``, ``orall``). In .py
    files the check also runs on the runtime value of every string literal, so a non-raw
    ``"ensures \\result"`` is caught before it is ever written out.
``acsl-missing-backslash``
    An ACSL builtin written without its backslash inside an annotation (``valid_read(p)``,
    ``old(x)``, ``assigns nothing``, ``ensures result == 0``).
``test-constant-redefined``
    A test module (``test_*.py``, ``conftest.py``) that defines a module-level constant which a module
    it imports already defines (the TREE collision).

Usage::

    python tools/check_generated_text.py                 # whole repository
    python tools/check_generated_text.py FILE...         # these files
    python tools/check_generated_text.py --hook          # Claude Code PostToolUse hook (JSON on stdin)

Known, justified hits live in ``tools/check_generated_text.allow``. Exit status: 0 clean, 1 violations
(2 in ``--hook`` mode, which Claude Code feeds back to the agent).
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import re
import subprocess
import sys
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ALLOWLIST = Path(__file__).resolve().parent / "check_generated_text.allow"
CHECKED_SUFFIXES = frozenset({".py", ".md", ".sh", ".c", ".h"})
# Where `import X` in a test module is looked up, besides the module's own directory.
IMPORT_ROOTS = ("tests", "scripts", "tools")
# In --hook mode after a shell command: dirty files modified this recently count as touched by it.
HOOK_RECENT_SECONDS = 120
HOOK_MAX_FILES = 300

RULES = (
    "control-char",
    "crlf",
    "sh-literal-newline",
    "acsl-corrupted",
    "acsl-missing-backslash",
    "test-constant-redefined",
)

# --- ACSL vocabulary -------------------------------------------------------------------------------

# What an ACSL builtin turns into when its backslash is read as a C/Python escape: the escape's control
# character followed by the rest of the word. \n and \t become ordinary whitespace, so their tails are
# only trusted inside ACSL text.
_ESCAPE_TAILS: dict[str, tuple[str, str]] = {
    "\x07": ("a", r"t\b|bs\b|lloca(?:ble|tion)\b"),
    "\x08": ("b", r"ase_addr\b|lock_length\b"),
    "\x0c": ("f", r"alse\b|orall\b|resh\b|reeable\b|rom\b"),
    "\x0b": ("v", r"alid(?:_read|_function|_index|_range)?\b"),
    "\x0d": ("r", r"esult\b"),
    "\n": ("n", r"othing\b|ull\b|umof\b"),
    "\t": ("t", r"rue\b"),
}
_STRONG_CORRUPTION_RE = re.compile(
    "|".join(f"(?P<c{ord(c)}>{re.escape(c)}(?:{tails}))" for c, (_, tails) in _ESCAPE_TAILS.items() if c not in "\n\t")
)
_WEAK_CORRUPTION_RE = re.compile(
    "|".join(f"(?P<c{ord(c)}>{re.escape(c)}(?:{tails}))" for c, (_, tails) in _ESCAPE_TAILS.items() if c in "\n\t")
)
# The same builtins with backslash and first letter both gone (the control character was stripped on
# the way out). These fragments are not words, so seeing one in an annotation is enough.
_BARE_TAIL_RE = re.compile(
    r"(?<![\\\w$])(alse|orall|esult|alid_read|alid|othing|ase_addr|lock_length)\b(?!\s*[:=]\s)",
)
# Builtins called like functions; written without a backslash they are unbound logic functions.
_CALLED_BUILTINS = (
    "valid|valid_read|valid_function|valid_index|valid_range|old|at|initialized|separated|base_addr|"
    "block_length|offset|freeable|fresh|allocable|dangling|object_pointer|is_finite|is_NaN"
)
# `{` excludes format placeholders ({result}); a following `:` is a clause label (`ensures result: ...`).
_MISSING_CALL_RE = re.compile(rf"(?<![\\\w.>${{])({_CALLED_BUILTINS})\s*\(")
_MISSING_NOTHING_RE = re.compile(r"\b(assigns|frees|allocates)\s+(nothing|result)\b")
_MISSING_RESULT_RE = re.compile(r"(?<![\\\w.>${])result\b(?!\s*:(?!:)|\})")
_ENSURES_CLAUSE_RE = re.compile(r"\bensures\b([^;]*)")

_ACSL_REGION_RE = re.compile(r"/\*@.*?(?:\*/|\Z)|//@[^\n]*", re.DOTALL)
# A Python string is ACSL when it holds an annotation, or a line that is a whole ACSL clause.
_ACSL_CLAUSE_LINE_RE = re.compile(
    r"^\s*(?:requires|ensures|assigns|loop\s+(?:invariant|assigns|variant)|assert|frees|allocates|"
    r"decreases|terminates|predicate|logic|axiom|lemma)\b[^\n]*;\s*$",
    re.MULTILINE,
)

# --- shell -----------------------------------------------------------------------------------------

_SH_NEWLINE_RE = re.compile(r"(?<!\\)(?:\\\\)*\\n")
# Lines where a backslash-n is the intended spelling.
_SH_NEWLINE_OK_RE = re.compile(r"\bprintf\b|\becho\s+-[a-zA-Z]*e|\$'|\b(?:sed|awk|gawk|tr|grep|perl)\b")

_CONSTANT_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    rule: str
    message: str

    def format(self) -> str:
        return f"{self.path}:{self.line}: [{self.rule}] {self.message}"


@dataclass(frozen=True)
class AllowEntry:
    pattern: str
    rule: str
    justification: str

    def matches(self, violation: Violation) -> bool:
        return (self.rule in ("*", violation.rule)) and fnmatch.fnmatchcase(violation.path, self.pattern)


# --- helpers ---------------------------------------------------------------------------------------


def _line_of(text: str, offset: int, base: int = 1) -> int:
    return base + text.count("\n", 0, offset)


def _describe(char: str) -> str:
    return f"0x{ord(char):02x}"


def _restored(match: re.Match[str]) -> str:
    text = match.group(0)
    letter = _ESCAPE_TAILS[text[0]][0]
    return "\\" + letter + text[1:]


# --- rules -----------------------------------------------------------------------------------------


def _control_chars(rel: str, text: str) -> list[Violation]:
    out: list[Violation] = []
    for lineno, line in enumerate(text.split("\n"), start=1):
        body = line[:-1] if line.endswith("\r") else line
        for col, ch in enumerate(body):
            code = ord(ch)
            if (code < 0x20 and ch != "\t") or code == 0x7F:
                hint = ""
                tail_match = _STRONG_CORRUPTION_RE.match(body, col)
                if tail_match:
                    hint = f" (corrupted ACSL {_restored(tail_match)}?)"
                out.append(
                    Violation(
                        rel, lineno, "control-char", f"control character {_describe(ch)} at column {col + 1}{hint}"
                    )
                )
    return out


def _crlf(rel: str, text: str) -> list[Violation]:
    count = text.count("\r\n")
    if not count:
        return []
    first = _line_of(text, text.index("\r\n"))
    return [Violation(rel, first, "crlf", f"CRLF line endings ({count} lines); write LF only")]


def _sh_literal_newlines(rel: str, text: str) -> list[Violation]:
    out: list[Violation] = []
    for lineno, line in enumerate(text.split("\n"), start=1):
        stripped = line.lstrip()
        # A comment may say \n; a shebang line holding one is the whole script on one line.
        is_comment = stripped.startswith("#") and not stripped.startswith("#!")
        if is_comment or _SH_NEWLINE_OK_RE.search(line):
            continue
        for match in _SH_NEWLINE_RE.finditer(line):
            after = line[match.end() : match.end() + 6]
            if re.match(r"othing\b|ull\b|umof\b", after):
                continue  # an ACSL \nothing / \null in an embedded annotation
            out.append(
                Violation(
                    rel,
                    lineno,
                    "sh-literal-newline",
                    "literal \\n in a shell script; was this file written as one escaped string?",
                )
            )
            break
    return out


def _acsl_text_findings(text: str) -> list[tuple[int, str, str]]:
    """(offset, rule, message) for ACSL text, i.e. the inside of an annotation."""
    out: list[tuple[int, str, str]] = []
    for m in _WEAK_CORRUPTION_RE.finditer(text):
        # A newline/tab directly followed by `othing`, `ull`, `rue`: no annotation is laid out that way.
        out.append((m.start(), "acsl-corrupted", f"{_restored(m)!r} turned into {_describe(m.group(0)[0])} + text"))
    for m in _BARE_TAIL_RE.finditer(text):
        before = m.start() - 1
        if before >= 0 and (_STRONG_CORRUPTION_RE.match(text, before) or _WEAK_CORRUPTION_RE.match(text, before)):
            continue  # already reported as the corrupted escape it is
        out.append(
            (m.start(), "acsl-corrupted", f"{m.group(1)!r} looks like an ACSL builtin that lost '\\' + a letter")
        )
    for m in _MISSING_CALL_RE.finditer(text):
        out.append((m.start(), "acsl-missing-backslash", f"'{m.group(1)}(' should be '\\{m.group(1)}('"))
    for m in _MISSING_NOTHING_RE.finditer(text):
        out.append((m.start(2), "acsl-missing-backslash", f"'{m.group(0)}' should be '{m.group(1)} \\{m.group(2)}'"))
    for clause in _ENSURES_CLAUSE_RE.finditer(text):
        for m in _MISSING_RESULT_RE.finditer(clause.group(1)):
            out.append((clause.start(1) + m.start(), "acsl-missing-backslash", "'result' should be '\\result'"))
    return out


def _acsl_regions(rel: str, text: str) -> list[Violation]:
    out: list[Violation] = []
    for region in _ACSL_REGION_RE.finditer(text):
        for offset, rule, message in _acsl_text_findings(region.group(0)):
            out.append(Violation(rel, _line_of(text, region.start() + offset), rule, message))
    return out


def _python_string_values(tree: ast.AST) -> Iterable[tuple[int, bool, str]]:
    """(line, spans several source lines, runtime value) of every string literal; f-string holes become `{}`."""
    in_fstring: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                    in_fstring.add(id(value))
                else:
                    parts.append("{}")
            yield node.lineno, (node.end_lineno or node.lineno) > node.lineno, "".join(parts)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in in_fstring:
            yield node.lineno, (node.end_lineno or node.lineno) > node.lineno, node.value


def _python_values(rel: str, text: str) -> list[Violation]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    out: list[Violation] = []
    for first_line, multiline, value in _python_string_values(tree):

        def line_at(offset: int, first_line: int = first_line, multiline: bool = multiline, value: str = value) -> int:
            # Only a triple-quoted literal maps value newlines to source lines; `"a\nb"` is one line.
            return first_line + value.count("\n", 0, offset) if multiline else first_line

        for m in _STRONG_CORRUPTION_RE.finditer(value):
            out.append(
                Violation(
                    rel,
                    line_at(m.start()),
                    "acsl-corrupted",
                    f"string evaluates to {_describe(m.group(0)[0])} + {m.group(0)[1:]!r}: "
                    f"use a raw string or '\\\\' for {_restored(m)!r}",
                )
            )
        acsl_parts: list[tuple[int, str]] = [(r.start(), r.group(0)) for r in _ACSL_REGION_RE.finditer(value)]
        if not acsl_parts and _ACSL_CLAUSE_LINE_RE.search(value):
            acsl_parts = [(0, value)]
        for start, part in acsl_parts:
            for offset, rule, message in _acsl_text_findings(part):
                if rule == "acsl-corrupted" and part[offset] in "\n\t":
                    message += " (string escape: use a raw string or '\\\\')"
                out.append(Violation(rel, line_at(start + offset), rule, message))
    return out


def _module_constants(tree: ast.Module) -> dict[str, int]:
    names: dict[str, int] = {}
    for node in tree.body:
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
        for target in targets:
            for sub in ast.walk(target):
                if isinstance(sub, ast.Name) and _CONSTANT_NAME_RE.match(sub.id):
                    names.setdefault(sub.id, node.lineno)
    return names


def _resolve_module(name: str, search: Sequence[Path]) -> Path | None:
    parts = name.split(".")
    for base in search:
        candidate = base.joinpath(*parts)
        for path in (candidate.with_suffix(".py"), candidate / "__init__.py"):
            if path.is_file():
                return path
    return None


def is_test_module(path: Path) -> bool:
    return path.suffix == ".py" and (path.name.startswith("test_") or path.name == "conftest.py")


def _test_constants(rel: str, path: Path, text: str, search_paths: Sequence[Path]) -> list[Violation]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    own = _module_constants(tree)
    if not own:
        return []
    search = [path.parent, *search_paths]
    imported: dict[str, tuple[str, Path]] = {}  # constant -> (module name, file)
    cache: dict[Path, dict[str, int]] = {}
    for node in tree.body:
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            modules = [node.module]
        for module in modules:
            target = _resolve_module(module, search)
            if target is None or target.resolve() == path.resolve():
                continue
            if target not in cache:
                try:
                    cache[target] = _module_constants(ast.parse(target.read_text(encoding="utf-8", errors="replace")))
                except (SyntaxError, ValueError, OSError):
                    cache[target] = {}
            for name in cache[target]:
                imported.setdefault(name, (module, target))
    out: list[Violation] = []
    for name, lineno in sorted(own.items(), key=lambda item: item[1]):
        if name in imported:
            module, _ = imported[name]
            out.append(
                Violation(
                    rel,
                    lineno,
                    "test-constant-redefined",
                    f"{name} is already defined in imported module '{module}'; reuse it or pick a distinct name",
                )
            )
    return out


# --- driver ----------------------------------------------------------------------------------------


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def check_text(
    path: Path,
    text: str,
    *,
    rel: str | None = None,
    search_paths: Sequence[Path] | None = None,
) -> list[Violation]:
    """Every violation in `text`, the content of `path` (whose suffix selects the rules)."""
    rel = rel if rel is not None else path.as_posix()
    suffix = path.suffix.lower()
    if suffix not in CHECKED_SUFFIXES:
        return []
    out = _control_chars(rel, text)
    if suffix in (".sh", ".py"):
        out += _crlf(rel, text)
    if suffix == ".sh":
        out += _sh_literal_newlines(rel, text)
    if suffix == ".py":
        out += _python_values(rel, text)
        if is_test_module(path):
            roots = search_paths if search_paths is not None else [ROOT / d for d in IMPORT_ROOTS]
            out += _test_constants(rel, path, text, roots)
    else:
        out += _acsl_regions(rel, text)
    unique = sorted(set(out), key=lambda v: (v.path, v.line, v.rule, v.message))
    return unique


def check_file(path: Path, *, root: Path = ROOT, search_paths: Sequence[Path] | None = None) -> list[Violation]:
    if path.suffix.lower() not in CHECKED_SUFFIXES or not path.is_file():
        return []
    data = path.read_bytes()
    text = data.decode("utf-8", errors="replace")
    return check_text(path, text, rel=_relative(path, root), search_paths=search_paths)


def load_allowlist(path: Path) -> list[AllowEntry]:
    """Lines `<path glob> <rule|*> -- <justification>`; a justification is required."""
    if not path.is_file():
        return []
    entries: list[AllowEntry] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        head, sep, justification = line.partition(" -- ")
        fields = head.split()
        if not sep or not justification.strip() or len(fields) != 2:
            raise ValueError(f"{path}:{lineno}: expected '<path glob> <rule> -- <justification>'")
        if fields[1] != "*" and fields[1] not in RULES:
            raise ValueError(f"{path}:{lineno}: unknown rule {fields[1]!r}")
        entries.append(AllowEntry(fields[0], fields[1], justification.strip()))
    return entries


def filter_allowed(violations: Iterable[Violation], allow: Sequence[AllowEntry]) -> list[Violation]:
    return [v for v in violations if not any(entry.matches(v) for entry in allow)]


def repo_files(root: Path) -> list[Path]:
    """Tracked and untracked-but-not-ignored files with a checked suffix."""
    proc = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    names = [n for n in proc.stdout.decode("utf-8", errors="replace").split("\0") if n]
    return sorted(root / n for n in names if Path(n).suffix.lower() in CHECKED_SUFFIXES and (root / n).is_file())


def check_paths(paths: Iterable[Path], *, root: Path = ROOT, allow: Sequence[AllowEntry] = ()) -> list[Violation]:
    out: list[Violation] = []
    for path in paths:
        out += check_file(path, root=root)
    return filter_allowed(out, allow)


# --- Claude Code hook ------------------------------------------------------------------------------

_PATH_TOKEN_RE = re.compile(r"""(?:"([^"]+)"|'([^']+)'|([^\s"'`;|&<>()]+))""")


_CHDIR_COMMANDS = frozenset({"cd", "pushd", "set-location", "sl", "chdir"})


def _paths_in_command(command: str, cwd: Path) -> list[Path]:
    """
    The files with a checked suffix a shell command names. A relative name is resolved against the
    directory the command changed to before naming it (`cd <dir>; pytest tests/x.py`), not only against
    the session's directory: an agent working in another worktree would otherwise have the session
    worktree's copy of the file checked.
    """
    found: list[Path] = []
    previous = ""
    for match in _PATH_TOKEN_RE.finditer(command):
        token = next(g for g in match.groups() if g is not None)
        if previous.lower() in _CHDIR_COMMANDS:
            target = Path(token) if Path(token).is_absolute() else cwd / token
            if target.is_dir():
                cwd = target
        previous = token
        if Path(token).suffix.lower() not in CHECKED_SUFFIXES:
            continue
        candidate = Path(token) if Path(token).is_absolute() else cwd / token
        if candidate.is_file():
            found.append(candidate)
    return found


def _checkout_root(path: Path, root: Path) -> Path:
    """
    The checkout a file belongs to: the nearest ancestor holding a `.git` entry (a directory in a clone,
    a file in a worktree), else `root`. Allowlist patterns are relative to it, so a file in a worktree
    under `<root>/.claude/worktrees/<name>/` matches the same entries as the main checkout's copy.
    """
    resolved = path.resolve()
    for parent in resolved.parents:
        if (parent / ".git").exists():
            return parent
    return root


def _recently_dirty(root: Path, horizon: float) -> list[Path]:
    try:
        proc = subprocess.run(
            ["git", "status", "--porcelain", "-z", "-uall"],
            cwd=root,
            capture_output=True,
            check=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    out: list[Path] = []
    for entry in proc.stdout.decode("utf-8", errors="replace").split("\0"):
        if len(entry) < 4:
            continue
        path = root / entry[3:]
        if path.suffix.lower() in CHECKED_SUFFIXES and path.is_file():
            try:
                if path.stat().st_mtime >= horizon:
                    out.append(path)
            except OSError:
                continue
    return out


def hook_targets(payload: dict, root: Path) -> list[Path]:
    """The files a Write/Edit/Bash/PowerShell tool call touched, as far as can be told."""
    tool_input = payload.get("tool_input") or {}
    cwd = Path(payload.get("cwd") or root)
    paths: list[Path] = []
    for key in ("file_path", "notebook_path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            paths.append(Path(value) if Path(value).is_absolute() else cwd / value)
    command = tool_input.get("command")
    if isinstance(command, str) and command:
        paths += _paths_in_command(command, cwd)
        paths += _recently_dirty(root, time.time() - HOOK_RECENT_SECONDS)
    unique: dict[str, Path] = {}
    for path in paths:
        unique.setdefault(str(path.resolve()).lower(), path)
    return list(unique.values())[:HOOK_MAX_FILES]


def run_hook(stdin_text: str, root: Path = ROOT, allowlist: Path = DEFAULT_ALLOWLIST) -> tuple[int, str]:
    """Exit code and stderr text for a PostToolUse payload. Exit 2 makes Claude Code show it to the agent."""
    try:
        payload = json.loads(stdin_text or "{}")
    except json.JSONDecodeError:
        return 0, ""
    if not isinstance(payload, dict):
        return 0, ""
    allow = load_allowlist(allowlist)
    violations: list[Violation] = []
    for path in hook_targets(payload, root):
        own_root = _checkout_root(path, root)
        hits = check_paths([path], root=own_root, allow=allow)
        if own_root.resolve() != root.resolve():
            # Matched against the allowlist by its own checkout's path; shown by where the file is.
            hits = [replace(v, path=_relative(path, root)) for v in hits]
        violations += hits
    if not violations:
        return 0, ""
    lines = [v.format() for v in violations[:50]]
    if len(violations) > 50:
        lines.append(f"... and {len(violations) - 50} more")
    message = (
        "check_generated_text found escaping/platform problems in the files this tool call touched:\n"
        + "\n".join(lines)
        + "\nFix them with the Edit tool (raw strings for ACSL in Python, LF line endings, no heredocs). "
        "If a hit is intended, add it to tools/check_generated_text.allow with a justification."
    )
    return 2, message


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[1] if __doc__ else None)
    parser.add_argument("paths", nargs="*", type=Path, help="files to check (default: the whole repository)")
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root (default: %(default)s)")
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--no-allowlist", action="store_true", help="report allowlisted hits too")
    parser.add_argument("--hook", action="store_true", help="run as a Claude Code PostToolUse hook")
    args = parser.parse_args(argv)

    if args.hook:
        try:
            code, message = run_hook(sys.stdin.read(), root=args.root, allowlist=args.allowlist)
        except Exception as exc:  # a broken hook must not block the agent's work
            print(f"check_generated_text hook error (ignored): {exc}", file=sys.stderr)
            return 0
        if message:
            print(message, file=sys.stderr)
        return code

    allow = [] if args.no_allowlist else load_allowlist(args.allowlist)
    paths = args.paths or repo_files(args.root)
    violations = check_paths(paths, root=args.root, allow=allow)
    for violation in violations:
        print(violation.format())
    if violations:
        print(f"{len(violations)} violation(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
