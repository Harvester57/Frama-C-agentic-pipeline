#!/usr/bin/env python3
"""
A/B of prover briefs on a small fixed sample of small assert programs, judged by this pipeline's own
oracles rather than the dataset's. See docs/benchmark.md.

The dataset stays outside the repository and its path is always a parameter. Nothing it names is ever
written down: samples are identified by content digest, because some of its file names look like
student identifiers. benchmark/briefs_sample.json holds only digests, corpus labels and line counts.

  sample  --dataset DIR                pick the fixed sample (deterministic, independent of location)
  control --dataset DIR                judge the unannotated programs: the floor, no LLM needed
  prepare --dataset DIR --arm A=BRIEF  one task per program and arm, for an LLM host to answer
  judge   --dir DIR                    run the oracles on the answers; writes metrics.json
  report  --dir DIR                    per-arm rates and the paired comparison between arms

Oracles, in order, for one answer:
  1. Pure ACSL: the C tokens are unchanged, no admit, axiom or vacuous \\false (acsl_ast.verify_acsl_only).
  2. Every annotation the program came with is still there: deleting the assert to prove is not a proof.
  3. WP with -wp-rte and smoke tests on every defined function, through run_wp_function.py and its
     soundness gates. A goal that timed out is not proved.
  4. A new value precondition on an entry function may define the problem away. Without a dynamic
     oracle here (these programs have no corpus), such a proof is reported apart, as conditional.

The E-ACSL guardrail is not one of these oracles; docs/benchmark.md says what that leaves open.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acsl_ast import AcslSyntaxError, tokenize_c_acsl, verify_acsl_only  # noqa: E402
from benchmark_compare import rate_block  # noqa: E402

SCRIPTS_DIR = Path(__file__).resolve().parent
DEFAULT_SAMPLE = SCRIPTS_DIR.parent / "benchmark" / "briefs_sample.json"
CORPORA = ("autobench", "live24", "live25")
DEFAULT_PER_CORPUS = 10
DEFAULT_SALT = "framac-benchmark-v1"
MAX_LINES = 80
CONTAINER_SCRIPTS = "/opt/framac-pipeline/scripts"
WP_GOAL_TIMEOUT_S = 15  # run_wp_function's default, fixed so results do not depend on the machine

_LOOP_RE = re.compile(r"\b(?:while|for|do)\b")
_ACSL_ASSERT_RE = re.compile(r"(?:/\*@|//@)[^\n]*\bassert\b")
_CLAUSE_SPLIT_RE = re.compile(r";")
_REQUIRES_RE = re.compile(r"\brequires\s+(?:[A-Za-z_]\w*\s*:\s*)?([^;]+);")
_MEMORY_SHAPE_RE = re.compile(
    r"\\(?:valid|valid_read|separated|initialized|valid_string|valid_read_string)\b|\bvalid_read_n?string\b"
)
_FUNCTION_DEF_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_TIMEOUT_COUNT_RE = re.compile(r"Timeout:\s*(\d+)")

PLACEHOLDERS = {
    "c_file": "answer.c",
    "header_file": "answer.c",
    "module_name": "sample",
    "wave_index": "0",
    "coverage_ids_json": "[]",
    "unknown_obligations_json": "[]",
    "security_properties_json": "[]",
    "reachability": "internal_api",
    "max_retries": "4",
    "function_name": "every function in the program",
}

TASK_SUFFIX = """

---

## Benchmark task

The brief above was written for one function of a larger project. Here the assignment is the small
program below, as a whole. Annotate it with ACSL so that `frama-c -wp -wp-rte` proves every goal of
every function, including the annotations the program already has.

Write the complete annotated program to `answer.c` next to this file. Change only ACSL comments: the
C code must stay token for token, and every annotation already there must stay. Optionally write
`usage.json` next to it: {{"input_tokens": N, "output_tokens": N, "iterations": N}}.

```c
{program}
```
"""


class BriefsError(RuntimeError):
    pass


def sha256_text(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_candidate(text: str) -> bool:
    """A program the briefs can differ on: small, with an ACSL assert and a loop to invariant over."""
    return (
        text.count("\n") + 1 <= MAX_LINES
        and bool(_ACSL_ASSERT_RE.search(text))
        and bool(_LOOP_RE.search(strip_comments(text)))
    )


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", text)


def scan_dataset(dataset: Path) -> dict[str, dict]:
    """Content digest -> {corpus, path, lines}, for every program. Paths stay in memory, never in a file."""
    found: dict[str, dict] = {}
    for corpus in CORPORA:
        folder = dataset / corpus
        if not folder.is_dir():
            raise BriefsError(f"{dataset} has no {corpus} directory")
        for path in sorted(folder.glob("*.c")):
            data = path.read_bytes()
            digest = sha256_text(data)
            found.setdefault(digest, {"corpus": corpus, "path": path, "data": data})
    return found


def select_sample(programs: dict[str, dict], per_corpus: int, salt: str) -> list[dict]:
    """
    Rank by a salted digest of the content, so the choice depends on neither file names nor location.
    Equal content in two corpora counts once. Ordered by corpus and rank.
    """
    chosen: list[dict] = []
    for corpus in CORPORA:
        rows = []
        for digest, entry in programs.items():
            if entry["corpus"] != corpus:
                continue
            text = entry["data"].decode("utf-8", errors="replace")
            if is_candidate(text):
                rank = sha256_text(f"{salt}:{digest}".encode())
                rows.append((rank, digest, text.count("\n") + 1))
        rows.sort()
        chosen.extend(
            {"id": f"s-{digest[:12]}", "corpus": corpus, "sha256": digest, "lines": lines}
            for _, digest, lines in rows[:per_corpus]
        )
    return chosen


def load_sample(path: Path = DEFAULT_SAMPLE) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def resolve_sample(sample: dict, dataset: Path) -> tuple[list[dict], list[str]]:
    """The fixed sample's programs from wherever the dataset is now; ids whose content is gone, separately."""
    programs = scan_dataset(dataset)
    resolved, missing = [], []
    for row in sample["programs"]:
        entry = programs.get(row["sha256"])
        if entry is None:
            missing.append(row["id"])
        else:
            resolved.append({**row, "data": entry["data"]})
    return resolved, missing


# ---------------------------------------------------------------------------
# Oracles (pure, no tool)
# ---------------------------------------------------------------------------


def _acsl_tokens(text: str) -> list[str]:
    return [t.text for t in tokenize_c_acsl(text) if t.kind in ("acsl_block", "acsl_line")]


def _clauses(acsl_text: str) -> set[str]:
    """Clauses of one ACSL annotation with comment markers and all whitespace removed."""
    body = re.sub(r"^\s*/\*@|\*/\s*$|^\s*//@", "", acsl_text)
    body = re.sub(r"(?m)^\s*@", "", body)
    return {re.sub(r"\s+", "", part) for part in _CLAUSE_SPLIT_RE.split(body) if part.strip()}


def missing_annotations(original: str, answer: str) -> list[str]:
    """Clauses of the original program's annotations that are not in the answer."""
    kept: set[str] = set()
    for token in _acsl_tokens(answer):
        kept |= _clauses(token)
    gone: list[str] = []
    for token in _acsl_tokens(original):
        gone.extend(sorted(_clauses(token) - kept))
    return gone


def defined_functions(text: str) -> list[str]:
    from c_definitions import extract_functions_from_code

    return [f["name"] for f in extract_functions_from_code(text, path="answer.c")]


def _called_names(text: str, defined: list[str]) -> set[str]:
    code = strip_comments(text)
    calls = Counter(_FUNCTION_DEF_RE.findall(code))
    # A defined function appears once as its own definition; more means something calls it.
    return {name for name in defined if calls[name] > 1}


def _contract_requires(text: str, function: str) -> list[str]:
    from acsl_ast import locate_function_span

    span = locate_function_span(text, function)
    if span is None:
        return []
    clauses: list[str] = []
    for token in tokenize_c_acsl(span.text):
        if token.kind == "c_token" and token.text == "{":
            break  # the body; a brace inside an annotation, as in `x \in {1, 2}`, is part of its token
        if token.kind in ("acsl_block", "acsl_line"):
            clauses.extend(re.sub(r"\s+", "", m.group(1)) for m in _REQUIRES_RE.finditer(token.text))
    return clauses


def added_entry_preconditions(original: str, answer: str) -> list[str]:
    """New value `requires` on functions nothing in the program calls: they can define the problem away."""
    defined = defined_functions(answer)
    called = _called_names(answer, defined)
    added: list[str] = []
    for function in defined:
        if function in called:
            continue
        before = set(_contract_requires(original, function))
        for clause in _contract_requires(answer, function):
            if clause not in before and not _MEMORY_SHAPE_RE.search(clause):
                added.append(f"{function}: {clause}")
    return added


def static_oracle(original: str, answer: str) -> list[str]:
    """Reasons the answer is refused before any proof is attempted (empty: it may go to WP)."""
    try:
        problems = verify_acsl_only(original, answer, path="answer.c")
        gone = missing_annotations(original, answer)
    except AcslSyntaxError as exc:
        return [f"unparsable answer: {exc}"]
    problems = list(problems)
    if gone:
        problems.append("annotations removed or changed: " + ", ".join(gone[:5]))
    return problems


def judge_sample(static_problems: list[str], reports: list[dict], added_requires: list[str]) -> dict:
    """
    One program's outcome from its oracles. proved requires every function all_proven with no new
    entry precondition; timeout and tool_failure mean no tool decided.
    """
    base: dict = {
        "outcome": "not_proved",
        "functions": len(reports),
        "goals_total": sum(int(r.get("total_goals") or 0) for r in reports),
        "goals_proven": sum(
            int(r.get("proven_count") or 0) + int(r.get("proven_under_hyp_count") or 0) for r in reports
        ),
    }
    if static_problems:
        return {**base, "outcome": "oracle_rejected", "detail": static_problems[:3]}
    if not reports:
        return {**base, "outcome": "tool_failure", "detail": ["no function could be analyzed"]}
    statuses = [r.get("status") for r in reports]
    if "analysis_error" in statuses:
        return {
            **base,
            "outcome": "tool_failure",
            "detail": sorted({str(r.get("reason")) for r in reports if r.get("status") == "analysis_error"}),
        }
    if all(s == "all_proven" for s in statuses):
        if added_requires:
            return {**base, "outcome": "proved_conditional", "detail": added_requires[:3]}
        return {**base, "outcome": "proved"}
    unproven = sum(int(r.get("unproven_count") or 0) for r in reports)
    timed_out = sum(_timeouts(r) for r in reports)
    if unproven and timed_out >= unproven and all(s in ("all_proven", "unproven_goals_remain") for s in statuses):
        return {**base, "outcome": "timeout", "detail": [f"{timed_out} goal(s) timed out"]}
    return {**base, "outcome": "not_proved", "detail": sorted({str(s) for s in statuses if s != "all_proven"})}


def _timeouts(report: dict) -> int:
    return sum(int(m) for m in _TIMEOUT_COUNT_RE.findall(str(report.get("wp_log_tail") or "")))


PASSED = ("proved",)
FAILED = ("not_proved", "oracle_rejected", "proved_conditional")
UNDECIDED = ("timeout", "tool_failure", "not_answered")


def outcome_rates(samples: dict[str, dict]) -> dict:
    """Over decided cases, and with every timeout, tool failure or missing answer counted as a failure."""
    counts = Counter(s["outcome"] for s in samples.values())
    block = rate_block(
        sum(counts[o] for o in PASSED), sum(counts[o] for o in FAILED), sum(counts[o] for o in UNDECIDED)
    )
    block["outcomes"] = dict(sorted(counts.items()))
    return block


def summarize_arm(samples: dict[str, dict], missing: list[str]) -> dict:
    by_corpus: dict[str, dict[str, dict]] = {}
    for sid, sample in samples.items():
        by_corpus.setdefault(sample.get("corpus", "unknown"), {})[sid] = sample
    tokens = {
        "input": sum(int((s.get("usage") or {}).get("input_tokens") or 0) for s in samples.values()),
        "output": sum(int((s.get("usage") or {}).get("output_tokens") or 0) for s in samples.values()),
        "iterations": sum(int((s.get("usage") or {}).get("iterations") or 0) for s in samples.values()),
        "samples_reporting": sum(1 for s in samples.values() if s.get("usage")),
    }
    return {
        "sample_size": len(samples),
        "missing_programs": missing,
        "rates": outcome_rates(samples),
        "by_corpus": {c: outcome_rates(rows) for c, rows in sorted(by_corpus.items())},
        "usage": tokens,
        "samples": dict(sorted(samples.items())),
    }


def paired_comparison(arm_a: dict, arm_b: dict) -> dict:
    """Program by program: where exactly one arm proved it. These are the counts a paired test would use."""
    a, b = arm_a.get("samples") or {}, arm_b.get("samples") or {}
    only_a, only_b, both, neither = [], [], 0, 0
    for sid in sorted(set(a) & set(b)):
        pa, pb = a[sid]["outcome"] in PASSED, b[sid]["outcome"] in PASSED
        if pa and pb:
            both += 1
        elif pa:
            only_a.append(sid)
        elif pb:
            only_b.append(sid)
        else:
            neither += 1
    return {
        "compared": len(set(a) & set(b)),
        "both_proved": both,
        "neither_proved": neither,
        "only_first_proved": only_a,
        "only_second_proved": only_b,
    }


# ---------------------------------------------------------------------------
# Tasks and judging
# ---------------------------------------------------------------------------


def render_task(brief: str, sample_id: str, program: str) -> str:
    text = brief
    for key, value in {**PLACEHOLDERS, "agent_id": f"sample-{sample_id}"}.items():
        text = text.replace("{" + key + "}", value)
    return text + TASK_SUFFIX.format(program=program)


def prepare(dataset: Path, out_dir: Path, arms: dict[str, Path], sample_path: Path = DEFAULT_SAMPLE) -> dict:
    sample = load_sample(sample_path)
    programs, missing = resolve_sample(sample, dataset)
    (out_dir / "samples").mkdir(parents=True, exist_ok=True)
    for row in programs:
        folder = out_dir / "samples" / row["id"]
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "input.c").write_bytes(row["data"])
    for arm, brief_path in arms.items():
        brief = Path(brief_path).read_text(encoding="utf-8")
        for row in programs:
            folder = out_dir / "arms" / arm / row["id"]
            folder.mkdir(parents=True, exist_ok=True)
            task = render_task(brief, row["id"], row["data"].decode("utf-8", errors="replace"))
            (folder / "task.md").write_text(task, encoding="utf-8", newline="\n")
    plan = {
        "arms": sorted(arms),
        "programs": [{k: row[k] for k in ("id", "corpus", "sha256", "lines")} for row in programs],
        "missing_programs": missing,
    }
    (out_dir / "plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8", newline="\n")
    return plan


def _judge_one(sample_dir: Path, wp_par: int, use_smoke: bool = True) -> dict:
    """All oracles on one answer, from a directory holding input.c and answer.c (container side)."""
    from run_wp_function import run_wp_on_function

    original = (sample_dir / "input.c").read_text(encoding="utf-8", errors="replace")
    answer_path = sample_dir / "answer.c"
    started = time.monotonic()
    answer = answer_path.read_text(encoding="utf-8", errors="replace")
    problems = static_oracle(original, answer)
    if problems:
        result = judge_sample(problems, [], [])
        result["wall_s"] = round(time.monotonic() - started, 1)
        return result
    reports = []
    for function in defined_functions(answer):
        reports.append(
            run_wp_on_function(
                answer_path,
                function,
                sample_dir / "wp" / function,
                cppflags=f"-I{sample_dir.as_posix()}",
                wp_par=wp_par,
                timeout=WP_GOAL_TIMEOUT_S,
                smoke_tests=use_smoke,
                cache_dir=None,
            )
        )
    result = judge_sample([], reports, added_entry_preconditions(original, answer))
    result["wall_s"] = round(time.monotonic() - started, 1)
    return result


def inner_judge(args: argparse.Namespace) -> int:
    """Judge every answer under answers/ of the run directory, in parallel within this container's lease."""
    from resources import FRAMAC_KERNEL_RESERVE_MB, WP_MEMLIMIT_MB, Budget, job_budget, wp_parallelism

    plan = json.loads(Path("plan.json").read_text(encoding="utf-8"))
    budget = job_budget()
    workers = max(1, min(budget.cpus, budget.mem_mb // (FRAMAC_KERNEL_RESERVE_MB + WP_MEMLIMIT_MB)))
    per_worker = Budget(max(1, budget.cpus // workers), budget.mem_mb // workers, budget.source)
    wp_par = wp_parallelism(per_worker)
    rows = {row["id"]: row for row in plan["programs"]}

    def job(sid: str) -> tuple[str, dict]:
        folder = Path("answers") / sid
        if not (folder / "answer.c").is_file():
            return sid, {"outcome": "not_answered", "functions": 0, "goals_total": 0, "goals_proven": 0}
        try:
            return sid, _judge_one(folder, wp_par)
        except Exception as exc:  # one broken program must not lose the whole arm
            return sid, {
                "outcome": "tool_failure",
                "functions": 0,
                "goals_total": 0,
                "goals_proven": 0,
                "detail": [f"{type(exc).__name__}: {str(exc)[:300]}"],
            }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = dict(pool.map(job, sorted(rows)))
    for sid, result in results.items():
        result["corpus"] = rows[sid]["corpus"]
    Path("judged.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(Counter(r["outcome"] for r in results.values()), indent=1))
    return 0


def judge_arm(out_dir: Path, arm: str, answers: dict[str, Path], plan: dict, run_id: str = "judge") -> dict:
    """Copy one arm's answers into a fresh run directory and judge them in one container."""
    import benchmark

    run_dir = (out_dir / "runs" / run_id / arm / benchmark.RUN_DIR_NAME).resolve()
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    programs = {row["id"]: row for row in plan["programs"]}
    (run_dir / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8", newline="\n")
    usage: dict[str, dict] = {}
    for sid in programs:
        folder = run_dir / "answers" / sid
        folder.mkdir(parents=True)
        shutil.copyfile(out_dir / "samples" / sid / "input.c", folder / "input.c")
        answer = answers.get(sid)
        if answer is not None and answer.is_file():
            shutil.copyfile(answer, folder / "answer.c")
            usage_file = answer.with_name("usage.json")
            if usage_file.is_file():
                usage[sid] = json.loads(usage_file.read_text(encoding="utf-8"))
    target = (out_dir / "samples").resolve()
    command = f"python3 {CONTAINER_SCRIPTS}/benchmark_briefs.py inner-judge"
    stage = benchmark.run_stage(f"judge-{arm}", command, target, run_dir, "briefs", cls="phase-static")
    judged = benchmark.read_json(run_dir / "judged.json", None)
    if stage["rc"] != 0 or judged is None:
        raise BriefsError(f"judging arm {arm} failed (rc={stage['rc']}); see {run_dir / 'bench' / 'logs'}")
    for sid, entry in usage.items():
        judged[sid]["usage"] = entry
    arm_summary = summarize_arm(judged, plan.get("missing_programs") or [])
    arm_summary["wall_s"] = stage["wall_s"]
    return arm_summary


def run_control_arm(dataset: Path, work_dir: Path, run_id: str, sample_path: Path = DEFAULT_SAMPLE) -> dict:
    """The no-LLM floor: each program unannotated. Needs no host, and shows what briefs have to improve on."""
    out_dir = work_dir / "briefs" / run_id
    plan = prepare(dataset, out_dir, {}, sample_path)
    answers = {row["id"]: out_dir / "samples" / row["id"] / "input.c" for row in plan["programs"]}
    return judge_arm(out_dir, "control", answers, plan, run_id)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def cmd_sample(args: argparse.Namespace) -> int:
    programs = scan_dataset(Path(args.dataset))
    chosen = select_sample(programs, args.per_corpus, args.salt)
    doc = {
        "comment": "Fixed sample of the assert-program dataset. Content digests only: never add file names (docs/benchmark.md).",
        "salt": args.salt,
        "per_corpus": args.per_corpus,
        "max_lines": MAX_LINES,
        "programs": chosen,
    }
    Path(args.out).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(Counter(p["corpus"] for p in chosen), indent=1))
    return 0


def _parse_arms(values: list[str]) -> dict[str, Path]:
    arms: dict[str, Path] = {}
    for value in values:
        name, sep, path = value.partition("=")
        if not sep or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise BriefsError(f"--arm expects NAME=BRIEF_FILE, got {value!r}")
        arms[name] = Path(path)
    return arms


def cmd_prepare(args: argparse.Namespace) -> int:
    plan = prepare(Path(args.dataset), Path(args.out), _parse_arms(args.arm), Path(args.sample))
    print(json.dumps({"arms": plan["arms"], "programs": len(plan["programs"]), "missing": plan["missing_programs"]}))
    print(f"Answer each {args.out}/arms/<arm>/<id>/task.md by writing answer.c next to it, then run `judge`.")
    return 0


def cmd_judge(args: argparse.Namespace) -> int:
    out_dir = Path(args.dir).resolve()
    plan = json.loads((out_dir / "plan.json").read_text(encoding="utf-8"))
    metrics: dict = {"arms": {}}
    arms = args.arm or plan["arms"]
    for arm in arms:
        answers = {row["id"]: out_dir / "arms" / arm / row["id"] / "answer.c" for row in plan["programs"]}
        metrics["arms"][arm] = judge_arm(out_dir, arm, answers, plan)
    path = out_dir / "metrics.json"
    path.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(render_report(metrics))
    print(f"Metrics: {path}")
    return 0


def render_report(metrics: dict) -> str:
    lines: list[str] = []
    arms = metrics.get("arms") or {}
    for name, arm in sorted(arms.items()):
        rates = arm["rates"]
        usage = arm.get("usage") or {}
        lines.append(
            f"{name}: proved {rates['passed']}/{arm['sample_size']}; over decided {rates['over_decided']}, "
            f"strict {rates['strict']}; outcomes {rates['outcomes']}; tokens in {usage.get('input')}, out {usage.get('output')}, "
            f"iterations {usage.get('iterations')} (reported by {usage.get('samples_reporting')} samples)"
        )
    names = sorted(arms)
    for i, first in enumerate(names):
        for second in names[i + 1 :]:
            pair = paired_comparison(arms[first], arms[second])
            lines.append(
                f"{first} vs {second}: both {pair['both_proved']}, neither {pair['neither_proved']}, "
                f"only {first} {len(pair['only_first_proved'])}, only {second} {len(pair['only_second_proved'])}"
            )
    return "\n".join(lines)


def cmd_control(args: argparse.Namespace) -> int:
    import benchmark

    work_dir = Path(args.work_dir).resolve() if args.work_dir else benchmark.default_work_dir()
    arm = run_control_arm(Path(args.dataset), work_dir, args.run_id or benchmark.new_run_id())
    if args.out:
        Path(args.out).write_text(json.dumps(arm, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(render_report({"arms": {"control": arm}}))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    print(render_report(json.loads((Path(args.dir) / "metrics.json").read_text(encoding="utf-8"))))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A/B of prover briefs on a fixed sample of small assert programs.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("sample", help="Pick the fixed sample from the dataset (content digests only)")
    p.add_argument("--dataset", required=True)
    p.add_argument("--per-corpus", type=int, default=DEFAULT_PER_CORPUS)
    p.add_argument("--salt", default=DEFAULT_SALT)
    p.add_argument("--out", default=str(DEFAULT_SAMPLE))
    p.set_defaults(func=cmd_sample)
    p = sub.add_parser("prepare", help="Write one task per program and arm")
    p.add_argument("--dataset", required=True)
    p.add_argument("--arm", action="append", required=True, help="NAME=BRIEF_FILE (repeatable)")
    p.add_argument("--out", required=True)
    p.add_argument("--sample", default=str(DEFAULT_SAMPLE))
    p.set_defaults(func=cmd_prepare)
    p = sub.add_parser("judge", help="Run the oracles on the answers in a prepared directory")
    p.add_argument("--dir", required=True)
    p.add_argument("--arm", action="append", default=None)
    p.set_defaults(func=cmd_judge)
    p = sub.add_parser("control", help="Judge the unannotated programs: the no-LLM floor")
    p.add_argument("--dataset", required=True)
    p.add_argument("--work-dir", default=None)
    p.add_argument("--run-id", default=None)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_control)
    p = sub.add_parser("report", help="Print the metrics of a judged directory")
    p.add_argument("--dir", required=True)
    p.set_defaults(func=cmd_report)
    p = sub.add_parser("inner-judge", help="Container-side step, started by `judge`")
    p.set_defaults(func=inner_judge)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (BriefsError, OSError, ValueError) as exc:
        print(f"benchmark_briefs: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
