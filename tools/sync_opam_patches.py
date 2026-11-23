#!/usr/bin/env python3
"""
Generate and verify the curated local opam patch queue for Frama-C and MetAcsl (stdlib only).

`docs/upstream/frama-c/patches/` holds the full upstream `git format-patch` commits (with
regression tests, oracles, and Changelog entries). This tool extracts only the production
source hunks for the curated Tier 1 allowlists below, writes them into the local opam
repository under `opam/packages/.../files/`, updates the `patches:` and `extra-files:`
stanzas in both `opam` files, and records `opam/patches-manifest.json`.

    python tools/sync_opam_patches.py            # regenerate opam patch queue and manifest
    python tools/sync_opam_patches.py --check    # exit 1 on any drift (tests, CI)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UPSTREAM_PATCHES_DIR = ROOT / "docs" / "upstream" / "frama-c" / "patches"
OPAM_DIR = ROOT / "opam"
MANIFEST_PATH = OPAM_DIR / "patches-manifest.json"

FRAMAC_VERSION = "34.0~beta"
METACSL_VERSION = "0.12~beta"

FRAMAC_PKG_DIR = OPAM_DIR / "packages" / "frama-c" / f"frama-c.{FRAMAC_VERSION}"
METACSL_PKG_DIR = OPAM_DIR / "packages" / "frama-c-metacsl" / f"frama-c-metacsl.{METACSL_VERSION}"

BEGIN_MARKER = "# BEGIN pipeline-patches (managed by tools/sync_opam_patches.py)"
END_MARKER = "# END pipeline-patches"


@dataclass(frozen=True)
class PatchSpec:
    filename: str
    issue: str
    mr: str | None
    summary: str


# Curated Tier 1 Frama-C patches applied in order onto 34.0~beta.
# Excluded on purpose:
#   - 09 (#2808 / !39): deprecated CLI alias unused by the pipeline
#   - 22 (#2816): open design choice awaiting upstream maintainers
#   - 37, 38 (#2826, #2827 / !54, !55): bittree memory model (pipeline uses segment model)
#   - 40 (#2829 / !57): WP LaTeX manual only (not built by opam)
# Note: 12 must precede 10 (10 builds on 12), 30 precedes 50, and 04 precedes 54 (context refreshed).
FRAMAC_PATCHES: tuple[PatchSpec, ...] = (
    PatchSpec(
        "01-eacsl-gcc-option-arguments-reparsed.patch",
        "pub/frama-c#2807",
        "pub/frama-c!38",
        "e-acsl-gcc: do not re-parse option arguments as flags",
    ),
    PatchSpec(
        "03-variadic-fallback-local-init.patch",
        "pub/frama-c#2796",
        "pub/frama-c!27",
        "kernel/variadic: preserve local initializer symbol name on fallback",
    ),
    PatchSpec(
        "04-eacsl-unbounded-range-abort.patch",
        "pub/frama-c#2798",
        "pub/frama-c!29",
        "e-acsl: do not abort whole instrumentation on unbounded ranges",
    ),
    PatchSpec(
        "04b-libc-getsockopt-unbounded-range.patch",
        "pub/frama-c#2799",
        "pub/frama-c!30",
        "libc: bound getsockopt optval range",
    ),
    PatchSpec(
        "05-eacsl-incomplete-type-sizeof.patch",
        "pub/frama-c#2805",
        "pub/frama-c!36",
        "e-acsl: reject sizeof/alignof of incomplete types cleanly",
    ),
    PatchSpec(
        "08-eacsl-struct-result-initialized.patch",
        "pub/frama-c#2801",
        "pub/frama-c!32",
        "e-acsl: avoid false \\initialized(&\\result.f) checks",
    ),
    PatchSpec(
        "12-eacsl-gcc-default-source.patch",
        "pub/frama-c#2809",
        "pub/frama-c!40",
        "e-acsl-gcc: pass -D_DEFAULT_SOURCE when compiling generated C",
    ),
    PatchSpec(
        "10-eacsl-gcc-clang-cflags.patch",
        "pub/frama-c#2810",
        "pub/frama-c!41",
        "e-acsl-gcc: preserve CFLAGS under -G clang",
    ),
    PatchSpec(
        "13-eacsl-formal-params-initialized.patch",
        "pub/frama-c#2797",
        "pub/frama-c!28",
        "e-acsl: mark formal parameters and argc/argv initialized",
    ),
    PatchSpec(
        "14-eacsl-iff-labelled-term.patch",
        "pub/frama-c#2800",
        "pub/frama-c!31",
        "e-acsl: support <==> over labelled terms",
    ),
    PatchSpec(
        "16-eacsl-loop-variant-logic-function-application.patch",
        "pub/frama-c#2806",
        "pub/frama-c!37",
        "e-acsl: type logic function applications in loop variants",
    ),
    PatchSpec(
        "17-eacsl-memcmp-overlapping-buffers.patch",
        "pub/frama-c#2803",
        "pub/frama-c!34",
        "e-acsl: allow overlapping buffers in memcmp replacement",
    ),
    PatchSpec(
        "18-eacsl-memory-init-clobbers-environ.patch",
        "pub/frama-c#2802",
        "pub/frama-c!33",
        "e-acsl: preserve environ during runtime memory initialization",
    ),
    PatchSpec(
        "19-wp-counter-examples-drops-frame.patch",
        "pub/frama-c#2811",
        "pub/frama-c!42",
        "wp: keep frame conditions when probes are present",
    ),
    PatchSpec(
        "20-kernel-alignas-member-printed-after-declarator.patch",
        "pub/frama-c#2812",
        "pub/frama-c!43",
        "kernel: print _Alignas before struct/union member declarators",
    ),
    PatchSpec(
        "21-eacsl-register-local-full-mtracking.patch",
        "pub/frama-c#2804",
        "pub/frama-c!35",
        "e-acsl: handle register locals under --full-mtracking",
    ),
    PatchSpec(
        "24-eacsl-guarded-exists-drops-conjunct.patch",
        "pub/frama-c#2793",
        "pub/frama-c!25",
        "e-acsl: keep guarded quantifier conjuncts (soundness)",
    ),
    PatchSpec(
        "25-kernel-offsetof-non-constant-index.patch",
        "pub/frama-c#2813",
        "pub/frama-c!44",
        "kernel: accept non-constant array index in offsetof",
    ),
    PatchSpec(
        "26-libc-socket-header-gaps.patch",
        "pub/frama-c#2814",
        "pub/frama-c!45",
        "libc: fix sockaddr_in sin_zero padding, ip_mreq, fd_set",
    ),
    PatchSpec(
        "27-eacsl-readonly-scalar-global-address.patch",
        "pub/frama-c#2794/#2795",
        "pub/frama-c!26",
        "e-acsl: pass address of const globals (scalars, unions, structs) to mark_readonly",
    ),
    PatchSpec(
        "28-eacsl-full-mtracking-tail-merged-literals.patch",
        "pub/frama-c#2817",
        "pub/frama-c!46",
        "e-acsl: demote string literals to avoid clang tail-merging overlap",
    ),
    PatchSpec(
        "29-eacsl-object-pointer-readonly-static.patch",
        "pub/frama-c#2818",
        "pub/frama-c!47",
        "e-acsl: recognize read-only static blocks in \\object_pointer",
    ),
    PatchSpec(
        "30-eacsl-format-promoted-argument-signedness.patch",
        "pub/frama-c#2819",
        "pub/frama-c!48",
        "e-acsl: accept promoted unsigned char/short/_Bool in format checks",
    ),
    PatchSpec(
        "31-eacsl-format-fp-argument-slots.patch",
        "pub/frama-c#2820",
        "pub/frama-c!49",
        "e-acsl: read floating-point arguments with their own va_arg types",
    ),
    PatchSpec(
        "32-eacsl-format-star-width-precision.patch",
        "pub/frama-c#2822",
        "pub/frama-c!50",
        "e-acsl: account for * width/precision arguments in format validation",
    ),
    PatchSpec(
        "33-eacsl-format-literal-without-full-mtracking.patch",
        "pub/frama-c#2821",
        "pub/frama-c!51",
        "e-acsl: track format-string literals without --full-mtracking",
    ),
    PatchSpec(
        "35-kernel-restrict-gnu-spelling.patch",
        "pub/frama-c#2824",
        "pub/frama-c!52",
        "kernel: accept GNU __restrict__ spelling in C lexer",
    ),
    PatchSpec(
        "36-eacsl-heap-zone-size-overflow.patch",
        "pub/frama-c#2825",
        "pub/frama-c!53",
        "e-acsl: prevent 32-bit int overflow in large heap/stack zone sizes",
    ),
    PatchSpec(
        "39-libc-linux-header-gaps.patch",
        "pub/frama-c#2828",
        "pub/frama-c!56",
        "libc: add Linux <sys/epoll.h> and <sys/inotify.h> headers and specs",
    ),
    PatchSpec(
        "41-libc-ioctl-modem-bits.patch",
        "pub/frama-c#2830",
        "pub/frama-c!58",
        "libc: add TIOCM_* modem-line bits to <sys/ioctl.h>",
    ),
    PatchSpec(
        "42-wp-hexadecimal-float-literals.patch",
        "pub/frama-c#2831",
        "pub/frama-c!59",
        "wp: parse hexadecimal and f32/f64 float literals (soundness)",
    ),
    PatchSpec(
        "43-eacsl-real-constant-notation.patch",
        "unfiled-43",
        None,
        "e-acsl: parse exponent/hex real constants and reject silent 0.1L -> 0 (soundness)",
    ),
    PatchSpec(
        "44-libc-strlcat-contract.patch",
        "unfiled-44",
        None,
        "libc: fix strlcat ensures/assigns/separation contract (soundness)",
    ),
    PatchSpec(
        "46-libc-sched-cpu-set.patch",
        "unfiled-46",
        None,
        "libc: add cpu_set_t, CPU_* macros, sched_setaffinity/sched_getaffinity to <sched.h>",
    ),
    PatchSpec(
        "50-eacsl-format-enum-argument.patch",
        "unfiled-50",
        None,
        "e-acsl: handle enum arguments and enum pointers in --validate-format-strings",
    ),
    PatchSpec(
        "51-kernel-float-const-printing.patch",
        "unfiled-51",
        None,
        "kernel: print CReal without source text at exact precision and valid C non-finite expressions",
    ),
    PatchSpec(
        "52-eacsl-rational-cast-double-rounding.patch",
        "unfiled-52",
        None,
        "e-acsl: round rational casts to double/float to nearest-even instead of mpq_get_d truncation (soundness)",
    ),
    PatchSpec(
        "53-eacsl-non-finite-real-constant.patch",
        "unfiled-53",
        None,
        "e-acsl: reject non-finite suffixed real constants cleanly instead of emitting inf or SIGFPE",
    ),
    PatchSpec(
        "54-eacsl-typing-not-performed-guard.patch",
        "unfiled-54",
        None,
        "e-acsl: type sibling subterms and quantifier goals before re-raising Not_yet",
    ),
    PatchSpec(
        "56-kernel-float-cast-dropped-exact.patch",
        "unfiled-56",
        None,
        "kernel: check single-precision exactness in Cil.isExactFloat before dropping (float) cast (soundness)",
    ),
    PatchSpec(
        "57-kernel-bool-cast-dropped-logic.patch",
        "unfiled-57",
        None,
        "kernel: fix Cil.fitsInInt and truncateInteger64 for IBool so (_Bool) casts are not dropped (soundness)",
    ),
    PatchSpec(
        "58-kernel-acsl-string-sizeof-escaped.patch",
        "unfiled-58",
        None,
        "kernel: unescape ACSL string literals before computing their array type/sizeof (soundness)",
    ),
    PatchSpec(
        "59-kernel-acsl-hex-octal-escapes.patch",
        "unfiled-59",
        None,
        "kernel: fix ACSL hex/octal escapes and wide-character truncation (soundness)",
    ),
    PatchSpec(
        "64-wp-void-object-size.patch",
        "unfiled-64",
        None,
        "wp: size TVoid objects as char rather than int (soundness)",
    ),
    PatchSpec(
        "65-wp-floor-ceil-truncate-float-cast.patch",
        "unfiled-65",
        None,
        "wp: compute \\floor/\\ceil/\\truncate and float-to-int constant casts with exact Zarith (soundness)",
    ),
    PatchSpec(
        "66-wp-empty-range-addition-shift.patch",
        "unfiled-66",
        None,
        "wp: guard range addition/subtraction and pointer shifts on range non-emptiness (soundness)",
    ),
    PatchSpec(
        "68-wp-non-finite-float-constant.patch",
        "unfiled-68",
        None,
        "wp: guard non-finite floating-point constants from becoming infinite reals or crashing Why3 export",
    ),
    PatchSpec(
        "72-libc-pclose-pipe-status-soundness.patch",
        "unfiled-72",
        None,
        "libc: track pipe state via ghost __fc_pipe_status so pclose does not prove \\false in WP (soundness)",
    ),
    PatchSpec(
        "73-libc-sigaction-oldact-contract.patch",
        "unfiled-73",
        None,
        "libc: fix sigaction oldact assigns and \\old postcondition so Eva does not mark post-call code dead",
    ),
    PatchSpec(
        "74-libc-reentrant-result-pointer-assigns.patch",
        "unfiled-74",
        None,
        "libc: fix getpwnam_r/getpwuid_r/getut*_r result pointer assigns so Eva reaches success branches",
    ),
    PatchSpec(
        "75-libc-syslog-string-axiomatic.patch",
        "unfiled-75",
        None,
        "libc: include __fc_string_axiomatic.h in <syslog.h> so variadic syslog checks string preconditions",
    ),
    PatchSpec(
        "80-kernel-hex-float-double-rounding.patch",
        "unfiled-80",
        None,
        "kernel: single-round hexadecimal floating-point literals with exact Z arithmetic (soundness)",
    ),
)

# Curated Tier 1 MetAcsl patches applied in order onto 0.12~beta.
METACSL_PATCHES: tuple[PatchSpec, ...] = (
    PatchSpec(
        "45-metacsl-result-in-postcond.patch",
        "unfiled-45",
        None,
        "metacsl: allow \\result in \\postcond properties",
    ),
    PatchSpec(
        "47-metacsl-callee-old-label-in-written.patch",
        "unfiled-47",
        None,
        "metacsl: map callee Old/Pre/Here labels to Before in \\written/\\read (soundness)",
    ),
    PatchSpec(
        "48-metacsl-fold-annotation-location.patch",
        "unfiled-48",
        None,
        "metacsl: preserve property source locations under -meta-fold",
    ),
    PatchSpec(
        "49-metacsl-eacsl-libc-instances.patch",
        "unfiled-49",
        None,
        "metacsl: warn with call-site locations under category no-footprint",
    ),
)

_DIFF_SPLIT_RE = re.compile(r"(?m)^(?=diff --git )")
_DIFF_HEADER_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")
_TRAILING_GIT_SIG_RE = re.compile(r"\n-- \n[0-9][^\n]*\n?\Z")

# Context adjustment when stacking 50 directly after 30 so `patch -p1 --fuzz=0` passes.
# Patch 30 expands `| TInt k -> get_ikind_str k ^ acc` into a multi-line match ending with
# `str ^ acc`, shifting the single context line above `| TFloat k` in Hunk #3 of patch 50.
_PATCH_50_BEFORE = (
    "@@ -152,7 +153,8 @@ module Libc = struct\n"
    "            | TInt k -> get_ikind_str k ^ acc\n"
    "            | TFloat k -> get_fkind_str k ^ acc\n"
)
_PATCH_50_AFTER = (
    "@@ -179,7 +180,8 @@ module Libc = struct\n"
    "              str ^ acc\n"
    "            | TFloat k -> get_fkind_str k ^ acc\n"
)

# Context adjustment when stacking 54 after 04 so `patch -p1 --fuzz=0` passes.
# Patch 04 changes `Options.abort ~current:true "unbounded ranges are not part of E-ACSl"`
# to `Error.untypable "unbounded range"`, which is the single context line above `Trange` in
# Hunk #5 of patch 54.
_PATCH_54_BEFORE = (
    "     | Trange(None, _) | Trange(_, None) ->\n"
    '       Options.abort ~current:true "unbounded ranges are not part of E-ACSl"\n'
    "     | Trange(Some n1, Some n2) ->\n"
)
_PATCH_54_AFTER = (
    "     | Trange(None, _) | Trange(_, None) ->\n"
    '       Error.untypable "unbounded range"\n'
    "     | Trange(Some n1, Some n2) ->\n"
)


def _is_non_source_path(rel_path: str) -> bool:
    return (
        "/tests/" in rel_path
        or rel_path.startswith("tests/")
        or rel_path.startswith("doc/")
        or "/doc/" in rel_path
        or rel_path.endswith("Changelog")
        or rel_path in ("CHANGELOG.md", "README.md")
    )


def extract_source_patch(raw_text: str, spec: PatchSpec) -> tuple[str, list[str]]:
    """Strip tests, oracles, and docs from an upstream `git format-patch` file."""
    normalized = raw_text.replace("\r\n", "\n")
    parts = _DIFF_SPLIT_RE.split(normalized)
    kept_parts: list[str] = []
    touched_files: list[str] = []

    for part in parts[1:]:
        first_line = part.split("\n", 1)[0]
        m = _DIFF_HEADER_RE.match(first_line)
        if not m:
            continue
        rel_path = m.group(1)
        if _is_non_source_path(rel_path):
            continue
        cleaned = _TRAILING_GIT_SIG_RE.sub("\n", part)
        if not cleaned.endswith("\n"):
            cleaned += "\n"
        kept_parts.append(cleaned)
        touched_files.append(rel_path)

    if not kept_parts:
        raise ValueError(f"No source hunks remained in {spec.filename}")

    body = "".join(kept_parts)
    if spec.filename == "50-eacsl-format-enum-argument.patch":
        if _PATCH_50_BEFORE not in body:
            raise ValueError(f"Expected context anchor not found in {spec.filename}")
        body = body.replace(_PATCH_50_BEFORE, _PATCH_50_AFTER, 1)
    elif spec.filename == "54-eacsl-typing-not-performed-guard.patch":
        if _PATCH_54_BEFORE not in body:
            raise ValueError(f"Expected context anchor not found in {spec.filename}")
        body = body.replace(_PATCH_54_BEFORE, _PATCH_54_AFTER, 1)

    ref = f"{spec.issue}, {spec.mr}" if spec.mr else spec.issue
    header = (
        f"# Source-only opam patch extracted from docs/upstream/frama-c/patches/{spec.filename}\n"
        f"# Upstream ref: {ref}\n"
        f"# Summary: {spec.summary}\n"
        "\n"
    )
    return header + body, touched_files


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _render_opam_patch_block(entries: list[tuple[str, str]]) -> str:
    patch_lines = "\n".join(f'  "{name}"' for name, _ in entries)
    extra_lines = "\n".join(f'  ["{name}" "sha256={digest}"]' for name, digest in entries)
    return (
        f"{BEGIN_MARKER}\n"
        f"patches: [\n{patch_lines}\n]\n"
        f"extra-files: [\n{extra_lines}\n]\n"
        f"{END_MARKER}\n"
    )


def _update_opam_text(original: str, entries: list[tuple[str, str]]) -> str:
    text = original.replace("\r\n", "\n")
    block = _render_opam_patch_block(entries)
    if BEGIN_MARKER in text and END_MARKER in text:
        pattern = re.compile(
            re.escape(BEGIN_MARKER) + r".*?" + re.escape(END_MARKER) + r"\n?",
            re.DOTALL,
        )
        return pattern.sub(block, text, count=1)
    if not text.endswith("\n"):
        text += "\n"
    return text + "\n" + block


def compute_expected(
    upstream_dir: Path = UPSTREAM_PATCHES_DIR,
    framac_pkg_dir: Path = FRAMAC_PKG_DIR,
    metacsl_pkg_dir: Path = METACSL_PKG_DIR,
) -> tuple[dict[Path, bytes], dict[str, object]]:
    """Build the full map of expected opam files and manifest content."""
    expected_files: dict[Path, bytes] = {}
    manifest_pkgs: dict[str, list[dict[str, object]]] = {}
    digest_inputs: list[list[str]] = []

    for pkg_key, pkg_dir, specs in (
        ("frama_c", framac_pkg_dir, FRAMAC_PATCHES),
        ("metacsl", metacsl_pkg_dir, METACSL_PATCHES),
    ):
        files_dir = pkg_dir / "files"
        opam_entries: list[tuple[str, str]] = []
        manifest_entries: list[dict[str, object]] = []

        for spec in specs:
            src_patch = upstream_dir / spec.filename
            if not src_patch.is_file():
                raise FileNotFoundError(f"Missing upstream patch: {src_patch}")
            content, touched = extract_source_patch(src_patch.read_text(encoding="utf-8"), spec)
            raw = content.encode("utf-8")
            sha = _sha256_bytes(raw)
            expected_files[files_dir / spec.filename] = raw
            opam_entries.append((spec.filename, sha))
            digest_inputs.append([pkg_key, spec.filename, sha])
            manifest_entries.append(
                {
                    "filename": spec.filename,
                    "issue": spec.issue,
                    "mr": spec.mr,
                    "summary": spec.summary,
                    "files": touched,
                    "sha256": sha,
                }
            )

        opam_file = pkg_dir / "opam"
        updated_opam = _update_opam_text(opam_file.read_text(encoding="utf-8"), opam_entries)
        expected_files[opam_file] = updated_opam.encode("utf-8")
        manifest_pkgs[pkg_key] = manifest_entries

    stack_digest = _sha256_bytes(
        json.dumps(
            {
                "frama_c_version": FRAMAC_VERSION,
                "metacsl_version": METACSL_VERSION,
                "patches": digest_inputs,
            },
            separators=(",", ":"),
        ).encode("utf-8")
    )
    manifest: dict[str, object] = {
        "schema_version": 1,
        "frama_c_version": FRAMAC_VERSION,
        "metacsl_version": METACSL_VERSION,
        "digest": stack_digest,
        "frama_c": manifest_pkgs["frama_c"],
        "metacsl": manifest_pkgs["metacsl"],
    }
    expected_files[MANIFEST_PATH] = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    return expected_files, manifest


def check_sync() -> list[str]:
    """Return a list of drift descriptions; empty list means opam/ is fully in sync."""
    expected, _ = compute_expected()
    diffs: list[str] = []

    for path, want in sorted(expected.items()):
        rel = path.relative_to(ROOT).as_posix()
        if not path.is_file():
            diffs.append(f"missing: {rel}")
        elif path.read_bytes() != want:
            diffs.append(f"out of sync: {rel}")

    for pkg_dir in (FRAMAC_PKG_DIR, METACSL_PKG_DIR):
        files_dir = pkg_dir / "files"
        if files_dir.is_dir():
            for existing in sorted(files_dir.iterdir()):
                if existing.is_file() and existing not in expected:
                    diffs.append(f"unexpected stale patch: {existing.relative_to(ROOT).as_posix()}")

    return diffs


def apply_sync() -> dict[str, object]:
    """Write all generated patch files, opam files, and manifest; remove stale patch files."""
    expected, manifest = compute_expected()

    for pkg_dir in (FRAMAC_PKG_DIR, METACSL_PKG_DIR):
        files_dir = pkg_dir / "files"
        files_dir.mkdir(parents=True, exist_ok=True)
        for existing in sorted(files_dir.iterdir()):
            if existing.is_file() and existing not in expected:
                existing.unlink()

    for path, content in sorted(expected.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sync local opam patch queue from docs/upstream/frama-c/patches/.")
    parser.add_argument("--check", action="store_true", help="Exit 1 if opam/ is out of sync without writing.")
    args = parser.parse_args(argv)

    if args.check:
        diffs = check_sync()
        if diffs:
            for line in diffs:
                print(line, file=sys.stderr)
            print("Run: python tools/sync_opam_patches.py", file=sys.stderr)
            return 1
        print("opam patch queue is in sync.")
        return 0

    manifest = apply_sync()
    fc_n = len(manifest["frama_c"]) if isinstance(manifest["frama_c"], list) else 0
    meta_n = len(manifest["metacsl"]) if isinstance(manifest["metacsl"], list) else 0
    print(f"Synced {fc_n} Frama-C patches + {meta_n} MetAcsl patches (digest {manifest['digest']}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
