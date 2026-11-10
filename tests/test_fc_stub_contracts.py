"""Lint for templates/fc_stubs: every function prototype carries an ACSL contract with `assigns` (plan step S1).

Companion of the "fc_stubs headers contain no function bodies" check in
test_acsl_only_and_merge.py::TestVerifyAcslOnly::test_templates_acsl_are_pure_acsl. A bodyless prototype
without a contract makes Eva assume default assigns and WP report `unsound_proof`; this test turns that
into a suite failure instead of something a run discovers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from acsl_ast import Token, tokenize_c_acsl

pytestmark = pytest.mark.unit

FC_STUBS = Path(__file__).resolve().parent.parent / "templates" / "fc_stubs"

# (header path relative to templates/fc_stubs, function name) of every prototype that has no contract
# with an `assigns` clause today. It may only shrink: the test fails when an entry gains a contract or
# disappears. Step S4 of docs/templates-and-stubs-improvement-plan.md empties it.
MISSING_CONTRACT_ALLOWLIST: frozenset[tuple[str, str]] = frozenset(
    ("json-c/json.h", name)
    for name in (
        "json_tokener_parse",
        "json_object_from_file",
        "json_object_from_fd",
        "json_object_to_file",
        "json_object_to_file_ext",
        "json_object_to_json_string",
        "json_object_to_json_string_ext",
        "json_object_get",
        "json_object_put",
        "json_object_is_type",
        "json_object_get_type",
        "json_object_new_object",
        "json_object_object_length",
        "json_object_object_add",
        "json_object_object_del",
        "json_object_object_get",
        "json_object_object_get_ex",
        "json_object_new_array",
        "json_object_new_array_ext",
        "json_object_array_length",
        "json_object_array_add",
        "json_object_array_put_idx",
        "json_object_array_get_idx",
        "json_object_new_boolean",
        "json_object_get_boolean",
        "json_object_new_int",
        "json_object_new_int64",
        "json_object_new_uint64",
        "json_object_get_int",
        "json_object_get_int64",
        "json_object_get_uint64",
        "json_object_new_double",
        "json_object_get_double",
        "json_object_new_string",
        "json_object_new_string_len",
        "json_object_get_string",
        "json_object_get_string_len",
    )
)

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_ASSIGNS_RE = re.compile(r"(?<![A-Za-z0-9_])assigns\b")
_ACSL_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_ACSL_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
# Identifiers followed by a parenthesised group that are never the declared function's name.
_NOT_A_NAME = frozenset(
    {
        "__attribute__",
        "__attribute",
        "__declspec",
        "__asm__",
        "__asm",
        "asm",
        "_Alignas",
        "alignas",
        "__typeof__",
        "typeof",
        "_Static_assert",
        "static_assert",
    }
)


@dataclass(frozen=True, slots=True)
class Prototype:
    """A top-level function declaration and the ACSL block directly in front of it, if any."""

    name: str
    line: int
    contract: str | None


def _has_assigns(contract: str | None) -> bool:
    if contract is None:
        return False
    body = _ACSL_LINE_COMMENT_RE.sub("", _ACSL_STRING_RE.sub('""', contract[3:-2]))
    return _ASSIGNS_RE.search(body) is not None


def _prototype_name(stmt: list[Token]) -> str | None:
    """Return the declared function name if this top-level statement is a function prototype."""
    texts = [t.text for t in stmt]
    if not texts or texts[0] in ("typedef", "_Static_assert", "static_assert") or "{" in texts or "=" in texts:
        return None
    depth = 0
    for i, text in enumerate(texts):
        if text == "(":
            if depth == 0 and i > 0:
                prev = texts[i - 1]
                if texts[i + 1 : i + 2] == ["*"]:
                    # `T (*name)(...)` is a function-pointer object; `T (*name(params))(...)` is a
                    # function returning a function pointer.
                    j = i + 2
                    while j < len(texts) and texts[j] in ("*", "const", "volatile", "restrict"):
                        j += 1
                    if j + 1 < len(texts) and _IDENT_RE.match(texts[j]) and texts[j + 1] == "(":
                        return texts[j]
                    return None
                if prev not in _NOT_A_NAME and _IDENT_RE.match(prev):
                    # A bare `MACRO(args);` has no declaration specifiers in front of the name.
                    return prev if i >= 2 else None
            depth += 1
        elif text == ")":
            depth -= 1
    return None


def parse_prototypes(source: str, path: str = "<input>") -> list[Prototype]:
    """List the top-level function prototypes in a header, each with its immediately preceding ACSL block.

    "Immediately preceding" allows only whitespace and plain C comments between the end of the ACSL
    block and the first token of the declaration; a preprocessor line or another declaration in
    between detaches the contract. Brace groups (struct, union, enum bodies) are skipped, and
    `extern "C" { ... }` linkage braces are transparent.
    """
    tokens = tokenize_c_acsl(source, path=path)
    prototypes: list[Prototype] = []
    stmt: list[Token] = []
    pending_contract: str | None = None
    stmt_contract: str | None = None
    depth = 0
    linkage_stack: list[bool] = []

    for tok in tokens:
        if tok.kind in ("whitespace", "c_comment"):
            continue
        if depth > 0:
            if tok.kind == "c_token" and tok.text == "{":
                depth += 1
                linkage_stack.append(False)
            elif tok.kind == "c_token" and tok.text == "}":
                depth -= 1
                linkage_stack.pop()
            continue
        if tok.kind == "acsl_block":
            pending_contract = tok.text if not stmt else pending_contract
            continue
        if tok.kind in ("pp_directive", "acsl_line"):
            if not stmt:
                pending_contract = None
            continue
        if tok.kind == "c_token" and tok.text == "{":
            if len(stmt) == 2 and stmt[0].text == "extern" and stmt[1].kind == "string":
                stmt = []
                linkage_stack.append(True)
                pending_contract = None
                continue
            depth += 1
            linkage_stack.append(False)
            stmt.append(tok)
            continue
        if tok.kind == "c_token" and tok.text == "}" and linkage_stack and linkage_stack[-1]:
            linkage_stack.pop()
            stmt = []
            pending_contract = None
            continue
        if not stmt:
            stmt_contract = pending_contract
            pending_contract = None
        if tok.kind == "c_token" and tok.text == ";":
            name = _prototype_name(stmt)
            if name is not None:
                prototypes.append(Prototype(name, stmt[0].line, stmt_contract))
            stmt = []
            continue
        stmt.append(tok)
    return prototypes


def _stub_headers() -> list[Path]:
    return sorted(FC_STUBS.rglob("*.h"))


def _missing_contracts() -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """Return (all prototype keys, keys of prototypes with at least one occurrence lacking an assigns contract)."""
    seen: set[tuple[str, str]] = set()
    missing: set[tuple[str, str]] = set()
    for header in _stub_headers():
        rel = header.relative_to(FC_STUBS).as_posix()
        for proto in parse_prototypes(header.read_text(encoding="utf-8"), path=str(header)):
            key = (rel, proto.name)
            seen.add(key)
            if not _has_assigns(proto.contract):
                missing.add(key)
    return seen, missing


def test_parse_prototypes_on_synthetic_header() -> None:
    source = """\
/* header comment with a fake prototype: int not_real(void); */
#ifndef X_H
#define X_H
#define MACRO_FN(a) ((a) + 1)
typedef int (*callback_t)(int);
typedef struct pt { int x; int (*fp)(int); } pt;
struct node { struct node *next; };
enum color { RED, GREEN };
extern int a_global;
int initialised = 3;
int (*fn_ptr_object)(int);
DECLARE_THING(foo);
static_assert(sizeof(int) == 4, "int");

/*@ requires \\valid(p);
  @ assigns *p;
  @*/
extern int with_contract(int *p);

/*@ ensures \\result == 0; */
int no_assigns(void);

/*@ assigns \\nothing; */
/* plain comment between contract and prototype */
__attribute__((nonnull(1)))
const char *
multi_line(const char *s,
           unsigned long n) __attribute__((pure));

/*@ assigns \\nothing; */
#if defined(SOMETHING)
int detached_by_pp(void);
#endif

/*@ assigns \\nothing; */
int (*returns_fp(int sel))(int);

int bare(void);

extern "C" {
//@ assigns \\nothing;
int in_linkage(void);
}
#endif
"""
    protos = parse_prototypes(source)
    by_name = {p.name: p for p in protos}
    assert [p.name for p in protos] == [
        "with_contract",
        "no_assigns",
        "multi_line",
        "detached_by_pp",
        "returns_fp",
        "bare",
        "in_linkage",
    ]
    assert _has_assigns(by_name["with_contract"].contract)
    assert by_name["no_assigns"].contract is not None and not _has_assigns(by_name["no_assigns"].contract)
    assert _has_assigns(by_name["multi_line"].contract)
    assert by_name["detached_by_pp"].contract is None
    assert _has_assigns(by_name["returns_fp"].contract)
    assert by_name["bare"].contract is None
    # `//@` line annotations are not function contracts in this lint.
    assert by_name["in_linkage"].contract is None
    assert by_name["multi_line"].line == source.splitlines().index("__attribute__((nonnull(1)))") + 1
    # `assigns` inside an ACSL string or a `//` comment does not count.
    assert not _has_assigns('/*@ requires p: "assigns"; // assigns x\n */')
    assert _has_assigns("/*@ behavior b: assumes x; assigns \\nothing; */")


def test_parser_finds_the_known_shipped_prototypes() -> None:
    seen, _ = _missing_contracts()
    for key in (
        ("bsd/string.h", "strlcpy"),
        ("bsd/string.h", "strlcat"),
        ("bsd/string.h", "strnstr"),
        ("fc_compat_types.h", "abs"),
        ("fc_compat_types.h", "getsockopt"),
        ("json-c/json.h", "json_tokener_parse"),
    ):
        assert key in seen, f"parser lost {key}"
    # errno.h declares an object, ip_icmp.h only types and macros.
    assert not any(rel in ("errno.h", "netinet/ip_icmp.h") for rel, _ in seen)


def test_fc_stub_prototypes_have_contract_with_assigns() -> None:
    seen, missing = _missing_contracts()
    new_missing = sorted(missing - MISSING_CONTRACT_ALLOWLIST)
    assert not new_missing, (
        "fc_stubs prototypes without a preceding /*@ ... */ contract containing an `assigns` clause "
        f"(write one; do not extend the allowlist): {new_missing}"
    )
    gone = sorted(MISSING_CONTRACT_ALLOWLIST - seen)
    assert not gone, f"allowlisted prototypes no longer declared; remove them from MISSING_CONTRACT_ALLOWLIST: {gone}"
    fixed = sorted((MISSING_CONTRACT_ALLOWLIST & seen) - missing)
    assert not fixed, (
        f"allowlisted prototypes now have a contract; remove them from MISSING_CONTRACT_ALLOWLIST: {fixed}"
    )
