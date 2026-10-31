#!/usr/bin/env python3
"""
Unit tests for scripts/workspace_overlay.py:
- Canonical ACSL vocabulary header inclusion and declarations
- Transitive include header deduplication (declarations preserved across unrelated headers)
- Conflicting predicate profile detection and diagnostics during agent merge
"""

from __future__ import annotations

from pathlib import Path

import pytest

import workspace_overlay
from acsl_ast import (
    ConflictingProfileError,
    extract_top_level_acsl_declarations,
    verify_acsl_only,
)

BASELINE_C = """#include "parser.h"

int parse_magic(const uint8_t *buf, size_t len) {
    if (!buf || len < 4) return 0;
    return (buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F');
}
"""

BASELINE_H = """#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>
#include <stdint.h>

int parse_magic(const uint8_t *buf, size_t len);

#endif /* PARSER_H */
"""


class TestAcslVocabularyAndOverlayDeduplication:
    def test_acsl_vocabulary_declarations_and_inclusion(self) -> None:
        """Verify templates/acsl/acsl_vocabulary.h exists, has canonical signatures, and is included via fc_compat_types.h."""
        vocab_p = workspace_overlay.resolve_acsl_vocabulary_path()
        assert vocab_p is not None
        assert vocab_p.is_file()

        content = vocab_p.read_text(encoding="utf-8")
        decls = extract_top_level_acsl_declarations(content, path="acsl_vocabulary.h")
        profiles = {d["full_profile"] for d in decls}

        # Check all required canonical signatures
        assert "c_strlen(char *)" in profiles
        assert "valid_c_string(char *)" in profiles
        assert "valid_read_buffer(char *, integer)" in profiles
        assert "valid_read_buffer(unsigned char *, integer)" in profiles
        assert "valid_write_buffer(char *, integer)" in profiles
        assert "valid_write_buffer(unsigned char *, integer)" in profiles
        assert "is_printable_ascii(char)" in profiles
        assert "no_crlf_or_nul(char *, integer)" in profiles
        assert "buffer_is_zeroed(unsigned char *, integer)" in profiles

        # Check inclusion under __FRAMAC__ in templates/fc_stubs/fc_compat_types.h
        fc_compat = Path(__file__).resolve().parent.parent / "templates" / "fc_stubs" / "fc_compat_types.h"
        assert fc_compat.is_file()
        compat_text = fc_compat.read_text(encoding="utf-8")
        assert "acsl_vocabulary.h" in compat_text
        assert "defined(__FRAMAC__)" in compat_text

    def test_transitive_include_header_dedup_preserves_unrelated_headers(self, tmp_path: Path) -> None:
        """
        Headers only deduplicate declarations from acsl_vocabulary.h or transitively included
        headers. Unrelated headers sharing a custom predicate definition keep their definitions.
        """
        target = tmp_path / "target"
        target.mkdir()
        h_a = "#ifndef HDR_A_H\n#define HDR_A_H\nint fn_a(void);\n#endif\n"
        h_b = "#ifndef HDR_B_H\n#define HDR_B_H\nint fn_b(void);\n#endif\n"
        h_c = '#ifndef HDR_C_H\n#define HDR_C_H\n#include "hdr_a.h"\nint fn_c(void);\n#endif\n'
        (target / "hdr_a.h").write_text(h_a, encoding="utf-8")
        (target / "hdr_b.h").write_text(h_b, encoding="utf-8")
        (target / "hdr_c.h").write_text(h_c, encoding="utf-8")
        (target / "empty.c").write_text("int dummy = 1;\n", encoding="utf-8")

        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        workspace_overlay.init_overlay(target, overlay)
        workspace_overlay.init_agent_overlay(run_dir, "arch-a", overlay)
        workspace_overlay.init_agent_overlay(run_dir, "arch-b", overlay)
        workspace_overlay.init_agent_overlay(run_dir, "arch-c", overlay)

        custom_decl = (
            "/*@\n"
            "  predicate custom_shared_invariant(char *buf, integer len) =\n"
            "    \\forall integer i; 0 <= i < len ==> buf[i] != 0;\n"
            "*/\n"
        )

        # Agent A defines custom_shared_invariant in hdr_a.h
        (run_dir / "agents/arch-a/scratch/work/hdr_a.h").write_text(
            h_a.replace("int fn_a", custom_decl + "int fn_a"), encoding="utf-8"
        )
        # Agent B defines custom_shared_invariant in unrelated hdr_b.h (does NOT include hdr_a.h)
        (run_dir / "agents/arch-b/scratch/work/hdr_b.h").write_text(
            h_b.replace("int fn_b", custom_decl + "int fn_b"), encoding="utf-8"
        )
        # Agent C defines custom_shared_invariant in hdr_c.h (transitive include of hdr_a.h!)
        (run_dir / "agents/arch-c/scratch/work/hdr_c.h").write_text(
            h_c.replace("int fn_c", custom_decl + "int fn_c"), encoding="utf-8"
        )

        # Merge arch-a: introduced
        r_a = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="arch-a",
            role="architect",
            overlay_dir=overlay,
            header_file="hdr_a.h",
            skip_reverify=True,
        )
        assert r_a["ok"] is True
        assert r_a["deduplicated_declarations"] == []
        assert "custom_shared_invariant" in (overlay / "work/hdr_a.h").read_text(encoding="utf-8")

        # Merge arch-b: unrelated header, NOT stripped!
        r_b = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="arch-b",
            role="architect",
            overlay_dir=overlay,
            header_file="hdr_b.h",
            skip_reverify=True,
        )
        assert r_b["ok"] is True
        assert r_b["deduplicated_declarations"] == []
        assert "custom_shared_invariant" in (overlay / "work/hdr_b.h").read_text(encoding="utf-8")

        # Merge arch-c: transitively includes hdr_a.h -> STRIPPED!
        r_c = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="arch-c",
            role="architect",
            overlay_dir=overlay,
            header_file="hdr_c.h",
            skip_reverify=True,
        )
        assert r_c["ok"] is True
        assert r_c["deduplicated_declarations"] == ["custom_shared_invariant"]
        assert "custom_shared_invariant" not in (overlay / "work/hdr_c.h").read_text(encoding="utf-8")

    def test_conflicting_predicate_profile_detection_against_vocabulary(self, tmp_path: Path) -> None:
        """Merging a header with a conflicting profile against acsl_vocabulary.h raises ConflictingProfileError."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "parser.c").write_text(BASELINE_C, encoding="utf-8")
        (target / "parser.h").write_text(BASELINE_H, encoding="utf-8")

        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        workspace_overlay.init_overlay(target, overlay)
        workspace_overlay.init_agent_overlay(run_dir, "arch-conflict", overlay)

        # acsl_vocabulary.h specifies buffer_is_zeroed(unsigned char *buf, integer len)
        # Agent declares conflicting char *buf
        conflicting_pred = (
            "/*@\n"
            "  predicate buffer_is_zeroed(char *buf, integer len) =\n"
            "    \\forall integer k; 0 <= k < len ==> buf[k] == 0;\n"
            "*/\n"
        )
        (run_dir / "agents/arch-conflict/scratch/work/parser.h").write_text(
            BASELINE_H.replace("int parse_magic", conflicting_pred + "int parse_magic"),
            encoding="utf-8",
        )

        with pytest.raises(ConflictingProfileError) as exc_info:
            workspace_overlay.merge_agent_overlay(
                run_dir=run_dir,
                agent_id="arch-conflict",
                role="architect",
                overlay_dir=overlay,
                header_file="parser.h",
                skip_reverify=True,
            )

        err_text = str(exc_info.value)
        assert "Conflicting profile for predicate 'buffer_is_zeroed'" in err_text
        assert "buffer_is_zeroed(char *, integer)" in err_text
        assert "buffer_is_zeroed(unsigned char *, integer)" in err_text

    def test_conflicting_predicate_profile_detection_across_workspace_headers(self, tmp_path: Path) -> None:
        """Merging a header with conflicting predicate profile against another workspace header raises ConflictingProfileError."""
        target = tmp_path / "target"
        target.mkdir()
        h_a = "#ifndef HDR_A_H\n#define HDR_A_H\nint fn_a(void);\n#endif\n"
        h_b = "#ifndef HDR_B_H\n#define HDR_B_H\nint fn_b(void);\n#endif\n"
        (target / "hdr_a.h").write_text(h_a, encoding="utf-8")
        (target / "hdr_b.h").write_text(h_b, encoding="utf-8")
        (target / "empty.c").write_text("int dummy = 1;\n", encoding="utf-8")

        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        workspace_overlay.init_overlay(target, overlay)
        workspace_overlay.init_agent_overlay(run_dir, "arch-a", overlay)
        workspace_overlay.init_agent_overlay(run_dir, "arch-b", overlay)

        pred_version_1 = (
            "/*@\n"
            "  predicate check_data(unsigned char *p, integer n) =\n"
            "    \\forall integer i; 0 <= i < n ==> p[i] != 0;\n"
            "*/\n"
        )
        pred_version_2 = (
            "/*@\n"
            "  predicate check_data(char *p, integer n) =\n"
            "    \\forall integer i; 0 <= i < n ==> p[i] != 0;\n"
            "*/\n"
        )

        (run_dir / "agents/arch-a/scratch/work/hdr_a.h").write_text(
            h_a.replace("int fn_a", pred_version_1 + "int fn_a"), encoding="utf-8"
        )
        (run_dir / "agents/arch-b/scratch/work/hdr_b.h").write_text(
            h_b.replace("int fn_b", pred_version_2 + "int fn_b"), encoding="utf-8"
        )

        r_a = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="arch-a",
            role="architect",
            overlay_dir=overlay,
            header_file="hdr_a.h",
            skip_reverify=True,
        )
        assert r_a["ok"] is True

        with pytest.raises(ConflictingProfileError) as exc_info:
            workspace_overlay.merge_agent_overlay(
                run_dir=run_dir,
                agent_id="arch-b",
                role="architect",
                overlay_dir=overlay,
                header_file="hdr_b.h",
                skip_reverify=True,
            )

        err_text = str(exc_info.value)
        assert "Conflicting profile for predicate 'check_data'" in err_text
        assert "check_data(char *, integer)" in err_text
        assert "check_data(unsigned char *, integer)" in err_text

    def test_merge_header_with_both_valid_read_buffer_overloads_succeeds(self, tmp_path: Path) -> None:
        """
        Regression test for Bug 2: Merging an agent header that defines both canonical overloads
        of valid_read_buffer (char* and unsigned char*) must succeed without raising ConflictingProfileError,
        and both overloads should subsequently be deduplicated against acsl_vocabulary.h.
        """
        target = tmp_path / "target"
        target.mkdir()
        h_buf = "#ifndef BUFFER_OPS_H\n#define BUFFER_OPS_H\nint read_data(const void *buf, int len);\n#endif\n"
        (target / "buffer_ops.h").write_text(h_buf, encoding="utf-8")
        (target / "main.c").write_text("int d = 0;\n", encoding="utf-8")

        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        workspace_overlay.init_overlay(target, overlay)
        workspace_overlay.init_agent_overlay(run_dir, "arch-buf", overlay)

        # Agent header defining both canonical overloads of valid_read_buffer
        header_with_overloads = """#ifndef BUFFER_OPS_H
#define BUFFER_OPS_H

/*@
  predicate valid_read_buffer(char *buf, integer len) =
    len >= 0 && (len == 0 || (buf != \\null && \\valid_read(buf + (0 .. len - 1))));

  predicate valid_read_buffer(unsigned char *buf, integer len) =
    len >= 0 && (len == 0 || (buf != \\null && \\valid_read(buf + (0 .. len - 1))));
*/

int read_data(const void *buf, int len);

#endif
"""
        (run_dir / "agents/arch-buf/scratch/work/buffer_ops.h").write_text(header_with_overloads, encoding="utf-8")

        result = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="arch-buf",
            role="architect",
            overlay_dir=overlay,
            header_file="buffer_ops.h",
            skip_reverify=True,
        )

        assert result["ok"] is True
        assert "valid_read_buffer" in result["deduplicated_declarations"]
        merged_header = (overlay / "work/buffer_ops.h").read_text(encoding="utf-8")
        # Empty annotation comment block was cleanly stripped and declarations removed
        assert "/*@" not in merged_header
        assert "int read_data(const void *buf, int len);" in merged_header


class TestParentReverifyWithExtraSources:
    def test_run_parent_reverify_passes_wp_extra_sources(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "run"
        overlay_dir = run_dir / "workspace"
        work_dir = overlay_dir / "work"
        work_dir.mkdir(parents=True)
        (work_dir / "calc.c").write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        (run_dir / "agents/prover-1/scratch/parent_wp").mkdir(parents=True)

        captured_cmds: list[list[str]] = []

        def fake_run(cmd, *args, **kwargs):
            captured_cmds.append(list(cmd))
            # Write a valid wp report JSON so parent reverify passes
            out_json = Path(cmd[cmd.index("--out-json") + 1])
            out_json.parent.mkdir(parents=True, exist_ok=True)
            out_json.write_text('{"status": "all_proven"}', encoding="utf-8")
            class Res:
                returncode = 0
                stdout = ""
                stderr = ""
            return Res()

        monkeypatch.setattr("subprocess.run", fake_run)

        ok, reason = workspace_overlay._run_parent_reverify(
            run_dir=run_dir,
            agent_id="prover-1",
            role="prover",
            overlay_dir=overlay_dir,
            c_file="calc.c",
            function="add",
            module="math_mod",
            sources=None,
            cppflags="-I.",
            wp_extra_sources=["helper.c", "util.c"],
        )

        assert ok is True
        assert reason == "verified"
        assert len(captured_cmds) == 1
        cmd = captured_cmds[0]
        assert "--extra-sources" in cmd
        extra_idx = cmd.index("--extra-sources")
        assert cmd[extra_idx + 1 : extra_idx + 3] == ["helper.c", "util.c"]

    def test_merge_agent_overlay_and_batch_forward_wp_extra_sources(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "run"
        overlay = run_dir / "workspace"
        target = tmp_path / "target"
        target.mkdir()
        (target / "calc.c").write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        workspace_overlay.init_overlay(target, overlay)
        workspace_overlay.init_agent_overlay(run_dir, "prover-1", overlay)

        # Prover adds an ACSL contract
        annotated = "/*@ ensures \\result == a + b; */\nint add(int a, int b) { return a + b; }\n"
        (run_dir / "agents/prover-1/scratch/work/calc.c").write_text(annotated, encoding="utf-8")

        captured_extra: list[list[str] | None] = []

        def fake_reverify(run_dir, agent_id, role, overlay_dir, c_file, function, module, sources, cppflags, ldflags="", wp_par=None, wp_extra_sources=None):
            captured_extra.append(wp_extra_sources)
            return True, "verified"

        monkeypatch.setattr(workspace_overlay, "_run_parent_reverify", fake_reverify)

        # Test single overlay merge forwarding wp_extra_sources
        res_single = workspace_overlay.merge_agent_overlay(
            run_dir=run_dir,
            agent_id="prover-1",
            role="prover",
            overlay_dir=overlay,
            c_file="calc.c",
            function="add",
            wp_extra_sources=["extra_a.c", "extra_b.c"],
        )
        assert res_single["ok"] is True
        assert captured_extra[-1] == ["extra_a.c", "extra_b.c"]

        # Test batch merge forwarding wp_extra_sources
        workspace_overlay.init_agent_overlay(run_dir, "prover-2", overlay)
        (run_dir / "agents/prover-2/scratch/work/calc.c").write_text(annotated, encoding="utf-8")

        res_batch = workspace_overlay.merge_agent_batch(
            run_dir=run_dir,
            entries=[
                {
                    "agent_id": "prover-2",
                    "role": "prover",
                    "c_file": "calc.c",
                    "function": "add",
                    "wp_extra_sources": ["batch_extra.c"],
                }
            ],
            overlay_dir=overlay,
        )
        assert res_batch["ok"] is True
        assert captured_extra[-1] == ["batch_extra.c"]


