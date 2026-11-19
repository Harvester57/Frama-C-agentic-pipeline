"""File the upstream Frama-C packages of docs/upstream/frama-c through glab.

  file_upstream.py show issue|mr NN      print what would be sent (no network write)
  file_upstream.py issue NN              create the issue, read it back, record it in the ledger
  file_upstream.py mr NN                 create the merge request, read it back, record it
  file_upstream.py subst                 write the known numbers into the filing texts

Filing publishes under the owner's name: run `issue` and `mr` only on their go-ahead.

The title is the first line of the filing text and the description is everything below its
HTML comment. Placeholders: `#<issue>` (the package's own issue), `#<issue-NN>` and `#ISSUE-NN`
(another package's). A text with a placeholder whose number is not in the ledger is refused, so
file the issues in an order that lets each text cite the ones it needs, then run `subst`.

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
    desc = substitute("\n".join(lines[idx[0] + 1:]).strip("\n"), nn, led)
    out = {"title": title, "description": desc}
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
    body = dict(sent, source_branch=branch, target_branch="master", target_project_id=UPSTREAM,
                remove_source_branch=True, allow_collaboration=True, squash=False)
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


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "show" and len(sys.argv) == 4:
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
