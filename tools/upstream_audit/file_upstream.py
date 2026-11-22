"""File and validate the upstream Frama-C packages of docs/upstream/frama-c through glab.

  file_upstream.py check [NN ...]        validate issue drafts against Frama-C bug reporting guidelines
  file_upstream.py show issue|mr NN      print what would be sent (no network write)
  file_upstream.py issue NN              create the issue, read it back, record it in the ledger
  file_upstream.py mr NN                 create the merge request, read it back, record it
  file_upstream.py subst                 write the known numbers into the filing texts

Filing publishes under the owner's name: run `issue` and `mr` only on their go-ahead.

The title is the first line of the filing text and the description is everything below its
HTML comment. Placeholders: `#<issue>` (the package's own issue), `#<issue-NN>` and `#ISSUE-NN`
(another package's). A text with a placeholder whose number is not in the ledger is refused, so
file the issues in an order that lets each text cite the ones it needs, then run `subst`.

Issue texts (other than the `00` overview discussion) are validated against upstream's
Guidelines for Reporting Bugs (https://git.frama-c.com/pub/frama-c/-/wikis/Guidelines-for-reporting-bugs)
and `bug_report.md` template before `show`, `issue`, or `check` succeeds. Filing texts whose
HTML marker names `Tracker: pub/meta` are validated for `pub/meta` and refused by `issue`/`mr`,
because this script files on `pub/frama-c` only.

Nothing is retried. On any error the script stops; look at the tracker before sending again,
because a duplicate cannot be removed. The branch of a merge request must already be on the fork
(see make_branches.sh). The ledger (ledger.json, beside this file) maps NN to its numbers.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any

HOST = "git.frama-c.com"
UPSTREAM = 780  # pub/frama-c
FORK = 2007  # Harvester57/frama-c
AUTHOR_ID = 1315
ROOT = Path(__file__).resolve().parents[2] / "docs" / "upstream" / "frama-c"
FILING = ROOT / "filing"
PATCHES = ROOT / "patches"
LEDGER = Path(__file__).with_name("ledger.json")
MARKER = "<!-- Everything below this line is the"
PLACEHOLDER = re.compile(r"#<issue|#ISSUE-|!<MR")


def glab() -> str:
    local = os.environ.get("LOCALAPPDATA")
    if local and (Path(local) / "Programs" / "glab" / "glab.exe").exists():
        return str(Path(local) / "Programs" / "glab" / "glab.exe")
    return "glab"


def api(method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    cmd = [glab(), "api", "--hostname", HOST, "-X", method, path]
    tmp = None
    if payload is not None:
        # A JSON file, not arguments: titles hold backticks and quotes that a shell would mangle.
        fd, tmp = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(payload, f, ensure_ascii=False)
        cmd += ["--input", tmp, "-H", "Content-Type: application/json"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=False)
    finally:
        if tmp:
            os.unlink(tmp)
    if r.returncode != 0:
        sys.exit(f"glab {method} {path} failed ({r.returncode}):\n{r.stdout}\n{r.stderr}")
    return json.loads(r.stdout) if r.stdout.strip() else None


def ledger() -> dict[str, dict[str, Any]]:
    return json.loads(LEDGER.read_text(encoding="utf-8")) if LEDGER.exists() else {}


def save(led: dict[str, dict[str, Any]]) -> None:
    with open(LEDGER, "w", encoding="utf-8", newline="\n") as f:
        json.dump(led, f, indent=1, sort_keys=True)
        f.write("\n")


def text_file(kind: str, nn: str) -> Path:
    found = sorted(FILING.glob(f"{nn}-*-{kind}.md"))
    if len(found) != 1:
        sys.exit(f"expected one {kind} text for {nn}, found {found}")
    return found[0]


def substitute(text: str, nn: str, led: dict[str, dict[str, Any]]) -> str:
    def issue_of(n: str) -> str | None:
        num = led.get(n, {}).get("issue")
        return f"#{num}" if num else None

    own = issue_of(nn)
    if own:
        text = text.replace("#<issue>", own)

    def named(m: re.Match[str]) -> str:
        return issue_of(m.group(1)) or m.group(0)

    text = re.sub(r"#<issue-(\d+)>", named, text)
    return re.sub(r"#ISSUE-(\d+)", named, text)


TITLE_TAG_RE = re.compile(r"^\[[A-Za-z][A-Za-z0-9 _.-]*\]\s+\S")
FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})")
HEADING_RE = re.compile(r"^(#{2,6})\s+(.+?)\s*$")
CMD_RE = re.compile(r"\b(?:frama-c|e-acsl-gcc|gcc|clang|make|opam)\b")
CRASH_RE = re.compile(r"Unexpected error|aborted:\s*internal error|Please report as 'crash'")
BACKTRACE_FRAME_RE = re.compile(r"\b(?:Raised at|Called from)\b")
BACKTRACE_STRIPPED_RE = re.compile(r"backtraces?\s+(?:removed|omitted)|^\[\.\.\.\]$", re.I | re.M)
PHANTOM_ATTACH_RE = re.compile(r"\b(?:in the attached file|see the attached|attached file)\b", re.I)
REL_REPO_LINK_RE = re.compile(r"\]\(\.\.?/")
CAUSE_FIX_RE = re.compile(r"^\*\*(?:Cause|Fix)\b", re.M)
FREESTANDING_HEADERS = frozenset({"stddef.h", "stdint.h", "stdbool.h", "limits.h", "stdarg.h", "float.h", "iso646.h"})
HOST_INCLUDE_RE = re.compile(r"#include\s*<([^>]+)>")
NAMED_C_BLOCK_RE = re.compile(r"`([A-Za-z0-9_.-]+\.[chi])`[^\n]*\n+\s*```[a-zA-Z0-9_-]*\n(.*?)```", re.S)


def detect_tracker(marker_line: str) -> str:
    """Detect target tracker from the HTML description marker line."""
    return "pub/meta" if "pub/meta" in marker_line else "pub/frama-c"


def extract_sections(desc: str) -> tuple[dict[str, str], str, bool]:
    """Return (lower_heading -> body, non-code prose, has_unclosed_fence)."""
    lines = desc.split("\n")
    sections: dict[str, list[str]] = {}
    prose: list[str] = []
    current: str | None = None
    fence_char = ""
    fence_len = 0

    for line in lines:
        fm = FENCE_RE.match(line)
        if fm:
            marker = fm.group(1)
            if not fence_char:
                fence_char, fence_len = marker[0], len(marker)
            elif marker[0] == fence_char and len(marker) >= fence_len and line.strip() == marker:
                fence_char, fence_len = "", 0
            if current is not None:
                sections[current].append(line)
            continue

        if not fence_char:
            hm = HEADING_RE.match(line)
            if hm and len(hm.group(1)) <= 3:
                current = hm.group(2).strip().lower()
                sections.setdefault(current, [])
                continue
            prose.append(line)

        if current is not None:
            sections[current].append(line)

    rendered = {k: "\n".join(v).strip() for k, v in sections.items()}
    return rendered, "\n".join(prose), bool(fence_char)


def _lookup_section(sections: dict[str, str], *aliases: str) -> str | None:
    for alias in aliases:
        if alias in sections:
            return sections[alias]
    return None


def validate_issue(title: str, desc: str, *, tracker: str = "pub/frama-c") -> tuple[list[str], list[str]]:
    """Validate an upstream issue against Frama-C's Guidelines-for-reporting-bugs and bug_report.md.

    Returns (errors, warnings). Errors block filing; warnings flag advisory improvements.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if len(title) > 255:
        errors.append(f"title too long ({len(title)} > 255)")
    if tracker == "pub/frama-c" and not TITLE_TAG_RE.match(title):
        errors.append(
            "title must start with a category/plug-in tag for pub/frama-c "
            "(e.g. [E-ACSL], [e-acsl-gcc], [Kernel], [Libc], [WP], [Eva])"
        )

    sections, prose, unclosed = extract_sections(desc)
    if unclosed:
        errors.append("unclosed Markdown code fence in description")

    if REL_REPO_LINK_RE.search(prose):
        errors.append("description contains a relative repository link; filing texts must be self-contained")
    if PHANTOM_ATTACH_RE.search(prose):
        errors.append("description refers to an attached file; inline the exact reproducer instead")

    summary = _lookup_section(sections, "summary")
    if not summary:
        errors.append("missing or empty '### Summary' section")

    repro = _lookup_section(sections, "steps to reproduce the issue")
    if not repro:
        errors.append("missing or empty '### Steps to reproduce the issue' section")
    elif "```" not in repro and not CMD_RE.search(repro):
        errors.append("'### Steps to reproduce the issue' must include inline input files or exact commands")

    expected = _lookup_section(sections, "expected behaviour", "expected behavior")
    if not expected:
        errors.append("missing or empty '### Expected behaviour' section")

    actual = _lookup_section(sections, "actual behaviour", "actual behavior")
    if not actual:
        errors.append("missing or empty '### Actual behaviour' section")

    ctx = _lookup_section(sections, "contextual information")
    if not ctx:
        errors.append("missing or empty '### Contextual information' section")
    else:
        required_ctx = [
            ("Frama-C installation mode", r"^- Frama-C installation mode:\s*\S"),
            ("Frama-C version", r"^- Frama-C version:\s*\S"),
            ("OS name", r"^- OS name:\s*\S"),
            ("OS version", r"^- OS version:\s*\S"),
        ]
        for label, pat in required_ctx:
            if not re.search(pat, ctx, re.M):
                errors.append(f"'### Contextual information' missing '{label}:' bullet")
        has_plugin = bool(re.search(r"^- Plug-in used:\s*\S", ctx, re.M))
        if tracker == "pub/frama-c":
            if not has_plugin:
                errors.append("'### Contextual information' missing 'Plug-in used:' bullet (category)")
        elif not has_plugin:
            if not re.search(r"\bMetAcsl\b", ctx):
                errors.append("'### Contextual information' missing 'Plug-in used:' or MetAcsl version")
            else:
                warnings.append("consider adding an explicit 'Plug-in used: MetAcsl ...' bullet")

    # Inline reproducer line-number check: if Steps names `foo.c` right above a C block,
    # flag diagnostics in Actual/Steps citing `foo.c:<line>` past that block's line count.
    if repro:
        block_lines: dict[str, int] = {}
        for m in NAMED_C_BLOCK_RE.finditer(repro):
            fname = m.group(1)
            nlines = len(m.group(2).splitlines())
            block_lines[fname] = max(block_lines.get(fname, 0), nlines)
        for fname, nlines in block_lines.items():
            for lm in re.finditer(rf"\b{re.escape(fname)}:(\d+):", (actual or "") + "\n" + repro):
                cited = int(lm.group(1))
                if cited > nlines:
                    errors.append(f"diagnostic cites {fname}:{cited}, but inline {fname} has only {nlines} lines")
                    break

    # Advisory warnings from Guidelines-for-reporting-bugs.
    if actual:
        if CRASH_RE.search(actual) and (BACKTRACE_STRIPPED_RE.search(actual) or not BACKTRACE_FRAME_RE.search(actual)):
            warnings.append(
                "crash/internal error omits or strips the OCaml backtrace "
                "(include verbatim backtrace, e.g. in a <details> block)"
            )
        if CAUSE_FIX_RE.search(actual):
            warnings.append("move Cause/Fix analysis out of 'Actual behaviour' into 'Additional information'")

    if repro and re.search(r"\be-acsl-gcc\b|-no-frama-c-stdlib", repro):
        c_fences = "\n".join(re.findall(r"```c\n(.*?)```", repro, re.S))
        host_incs = [h for h in HOST_INCLUDE_RE.findall(c_fences) if h not in FREESTANDING_HEADERS]
        if host_incs and not re.search(r"\b(?:glibc|musl|\.i)\b", desc, re.I):
            warnings.append(
                f"reproducer includes host headers ({', '.join(sorted(set(host_incs)))}) under "
                "-no-frama-c-stdlib/e-acsl-gcc without stating libc version or providing a .i file"
            )

    return errors, warnings


def check_issue_file(
    path: Path,
    led: dict[str, dict[str, Any]] | None = None,
    *,
    allow_placeholders: bool = True,
) -> tuple[list[str], list[str]]:
    """Validate an issue filing markdown file on disk. Returns (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []
    raw_bytes = path.read_bytes()
    raw = raw_bytes.decode("utf-8")
    if "\r" in raw:
        errors.append("CRLF in the filing text")
        raw = raw.replace("\r\n", "\n")

    lines = raw.split("\n")
    if not lines or not lines[0].startswith("# "):
        errors.append("first line is not a '# Title' heading")
        title = ""
    else:
        title = lines[0][2:].strip()

    idx = [i for i, line in enumerate(lines) if line.startswith(MARKER)]
    if len(idx) != 1:
        errors.append("description marker ('<!-- Everything below this line...') not found exactly once")
        tracker = "pub/frama-c"
        desc = "\n".join(lines[1:]).strip("\n")
    else:
        tracker = detect_tracker(lines[idx[0]])
        desc = "\n".join(lines[idx[0] + 1 :]).strip("\n")

    nn = path.name.split("-", 1)[0]
    if led is not None:
        desc = substitute(desc, nn, led)

    leftover = PLACEHOLDER.findall(title) + PLACEHOLDER.findall(desc)
    if leftover:
        msg = f"unresolved placeholder(s): {leftover}"
        if allow_placeholders:
            warnings.append(msg)
        else:
            errors.append(msg)

    if nn != "00":
        v_err, v_warn = validate_issue(title, desc, tracker=tracker)
        errors.extend(v_err)
        warnings.extend(v_warn)

    return errors, warnings


def parse(kind: str, nn: str, led: dict[str, dict[str, Any]]) -> dict[str, str]:
    # Bytes, not read_text: text mode turns CRLF into LF before the check below can see it.
    raw = text_file(kind, nn).read_bytes().decode("utf-8")
    if "\r" in raw:
        sys.exit("CRLF in the filing text")
    lines = raw.split("\n")
    if not lines[0].startswith("# "):
        sys.exit("first line is not a title")
    title = lines[0][2:].strip()
    idx = [i for i, line in enumerate(lines) if line.startswith(MARKER)]
    if len(idx) != 1:
        sys.exit("description marker not found exactly once")
    tracker = detect_tracker(lines[idx[0]])
    desc = substitute("\n".join(lines[idx[0] + 1 :]).strip("\n"), nn, led)
    out = {"title": title, "description": desc, "tracker": tracker}
    if kind == "mr":
        m = re.search(r"^- Source branch: `([^`]+)`", raw, re.M)
        p = re.search(r"\.\./patches/([^)\s`\]]+\.patch)", raw)
        if not m or not p:
            sys.exit("source branch or patch not found in the MR text")
        out["source_branch"] = m.group(1)
        out["patch"] = p.group(1)
    for k in ("title", "description"):
        if PLACEHOLDER.search(out[k]):
            sys.exit(f"placeholder left in the {k}: {PLACEHOLDER.findall(out[k])}")
    if len(title) > 255:
        sys.exit(f"title too long ({len(title)})")
    if kind == "issue" and nn != "00":
        errs, _ = validate_issue(title, desc, tracker=tracker)
        if errs:
            sys.exit("issue failed Frama-C bug reporting guidelines:\n  - " + "\n  - ".join(errs))
    return out


def norm(s: str) -> str:
    return "\n".join(line.rstrip() for line in s.replace("\r\n", "\n").strip().split("\n"))


def check_back(got: dict[str, Any], sent: dict[str, str]) -> None:
    for k in ("title", "description"):
        same = norm(got[k] or "") == norm(sent[k])
        print(f"  read back {k}: {'identical' if same else 'DIFFERENT'}")
        if not same:
            sys.exit("the stored text differs from the file")


def do_issue(nn: str) -> None:
    led = ledger()
    if led.get(nn, {}).get("issue"):
        sys.exit(f"{nn} already has issue #{led[nn]['issue']}")
    sent = parse("issue", nn, led)
    tracker = sent.pop("tracker")
    if tracker != "pub/frama-c":
        sys.exit(f"{nn} targets {tracker}; file_upstream.py posts to pub/frama-c only")
    mine = api("GET", f"projects/{UPSTREAM}/issues?author_id={AUTHOR_ID}&per_page=100&order_by=created_at")
    for it in mine:
        if it["title"] == sent["title"]:
            sys.exit(f"an issue with this title exists: #{it['iid']} {it['web_url']}")
    made = api("POST", f"projects/{UPSTREAM}/issues", dict(sent))
    led.setdefault(nn, {})["issue"] = made["iid"]
    led[nn]["issue_url"] = made["web_url"]
    save(led)
    print(f"{nn}: issue #{made['iid']} {made['web_url']}")
    check_back(api("GET", f"projects/{UPSTREAM}/issues/{made['iid']}"), sent)


def do_mr(nn: str) -> None:
    led = ledger()
    if led.get(nn, {}).get("mr"):
        sys.exit(f"{nn} already has MR !{led[nn]['mr']}")
    sent = parse("mr", nn, led)
    tracker = sent.pop("tracker")
    if tracker != "pub/frama-c":
        sys.exit(f"{nn} targets {tracker}; file_upstream.py posts to pub/frama-c only")
    branch = sent.pop("source_branch")
    patch = (PATCHES / sent.pop("patch")).read_text(encoding="utf-8")
    nfiles = len(re.findall(r"^diff --git ", patch, re.M))
    ncommits = len(re.findall(r"^From [0-9a-f]{40} ", patch, re.M))
    head = api("GET", f"projects/{FORK}/repository/commits/{urllib.parse.quote(branch, safe='')}")
    print(f"  branch {branch}: {head['short_id']} {head['title']}")
    if ncommits == 1 and head["title"] != sent["title"]:
        sys.exit("the branch head subject is not the MR title")
    if head["author_email"] != head["committer_email"] or "noreply" not in head["author_email"]:
        sys.exit(f"unexpected identity: {head['author_email']} / {head['committer_email']}")
    mine = api("GET", f"projects/{UPSTREAM}/merge_requests?author_id={AUTHOR_ID}&state=all&per_page=100")
    for it in mine:
        if it["source_branch"] == branch or it["title"] == sent["title"]:
            sys.exit(f"a merge request for this branch or title exists: !{it['iid']} {it['web_url']}")
    body = dict(
        sent,
        source_branch=branch,
        target_branch="master",
        target_project_id=UPSTREAM,
        remove_source_branch=True,
        allow_collaboration=True,
        squash=False,
    )
    made = api("POST", f"projects/{FORK}/merge_requests", body)
    led.setdefault(nn, {})["mr"] = made["iid"]
    led[nn]["mr_url"] = made["web_url"]
    save(led)
    print(f"{nn}: MR !{made['iid']} {made['web_url']}")
    base = f"projects/{UPSTREAM}/merge_requests/{made['iid']}"
    check_back(api("GET", base), sent)
    # pub/frama-c has autoclose_referenced_issues off: this list is empty for every merge
    # request. A non-empty one must hold the package's own issue and nothing else.
    closes = sorted(i["iid"] for i in api("GET", f"{base}/closes_issues"))
    own = [led[nn]["issue"]] if re.search(r"^Closes #\d+", sent["description"], re.M) else []
    print(f"  closes: {closes} (allowed: [] or {own})")
    commits: list[Any] = []
    changed = 0
    # GitLab computes the commit list and the diff a few seconds after the creation: read at once,
    # !58 (package 41) showed 0 commits, and the check below failed on a correct merge request.
    for _ in range(6):
        commits = api("GET", f"{base}/commits")
        changed = len(api("GET", f"{base}/diffs?per_page=100"))
        if commits and changed:
            break
        time.sleep(5)
    print(f"  commits: {len(commits)} (patch has {ncommits})")
    print(f"  files changed: {changed} (patch has {nfiles})")
    if closes not in ([], own) or len(commits) != ncommits or changed != nfiles:
        sys.exit("CHECK FAILED after creation: look at the merge request before going on")


def do_subst() -> None:
    led = ledger()
    for path in sorted(FILING.glob("*.md")):
        nn = path.name.split("-", 1)[0]
        if nn not in led:
            continue
        raw = path.read_text(encoding="utf-8")
        new = substitute(raw, nn, led)
        if new != raw:
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(new)
            left = PLACEHOLDER.findall(new)
            print(f"{path.name}: updated{' (left: ' + str(left) + ')' if left else ''}")


def do_check(args: list[str]) -> int:
    strict_placeholders = False
    nns: list[str] = []
    for arg in args:
        if arg == "--strict-placeholders":
            strict_placeholders = True
        else:
            nns.append(arg)
    led = ledger()
    paths = [text_file("issue", nn) for nn in nns] if nns else sorted(FILING.glob("*-issue.md"))
    failed = 0
    warned = 0
    for path in paths:
        errors, warnings = check_issue_file(path, led, allow_placeholders=not strict_placeholders)
        if errors:
            failed += 1
            print(f"FAIL {path.name}")
            for err in errors:
                print(f"  ERROR: {err}")
        elif warnings:
            warned += 1
            print(f"WARN {path.name}")
        else:
            print(f"OK   {path.name}")
        for warn in warnings:
            print(f"  WARN: {warn}")
    print(
        f"Checked {len(paths)} issue file(s): {len(paths) - failed} passed ({warned} with warnings), {failed} failed."
    )
    return 1 if failed else 0


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "check":
        raise SystemExit(do_check(sys.argv[2:]))
    elif cmd == "show" and len(sys.argv) == 4:
        out = parse(sys.argv[2], sys.argv[3], ledger())
        print(json.dumps({k: v for k, v in out.items() if k != "description"}, ensure_ascii=False))
        print(out["description"])
    elif cmd == "issue" and len(sys.argv) == 3:
        do_issue(sys.argv[2])
    elif cmd == "mr" and len(sys.argv) == 3:
        do_mr(sys.argv[2])
    elif cmd == "subst":
        do_subst()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
