from framac_common import (
    STATUS_ASSUMED,
    STATUS_DEAD,
    STATUS_INVALID,
    STATUS_OTHER,
    STATUS_UNKNOWN,
    STATUS_VALID,
    STATUS_VALID_UNDER_HYP,
    is_safe_agent_id,
    is_safe_relative_path,
    normalize_status,
    read_report_csv,
)


def test_status_spellings_from_different_frama_c_releases():
    assert normalize_status("Valid") == STATUS_VALID
    assert normalize_status("Valid under hyp.") == STATUS_VALID_UNDER_HYP
    assert normalize_status("Valid_under_hyp") == STATUS_VALID_UNDER_HYP
    assert normalize_status("Unknown") == STATUS_UNKNOWN
    assert normalize_status("Invalid") == STATUS_INVALID
    assert normalize_status("Invalid but dead") == STATUS_DEAD
    assert normalize_status("Invalid_but_dead") == STATUS_DEAD
    assert normalize_status("Considered valid") == STATUS_ASSUMED
    assert normalize_status("weird") == STATUS_OTHER


def test_report_csv_with_current_and_legacy_headers(tmp_path):
    current = tmp_path / "current.csv"
    current.write_text(
        "directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n"
        "src\tber.c\t42\tber_len\tassertion\tUnknown\tmem_access: \\valid_read(p)\n"
        "src\tber.c\t50\tber_len\tassertion\tInvalid but dead\tdivision_by_zero: d != 0\n",
        encoding="utf-8",
    )
    rows = read_report_csv(current)
    assert rows[0]["kind"] == "assertion"
    assert rows[0]["property"].startswith("mem_access")
    assert rows[0]["status"] == STATUS_UNKNOWN and rows[0]["line"] == 42
    assert rows[1]["status"] == STATUS_DEAD

    legacy = tmp_path / "legacy.csv"
    legacy.write_text("file\tline\tfunction\tkind\tstatus\tannotation\nx.c\t1\tf\tassigns\tValid\tassigns \\nothing\n", encoding="utf-8")
    row = read_report_csv(legacy)[0]
    assert row["kind"] == "assigns" and row["property"] == "assigns \\nothing" and row["status"] == STATUS_VALID


def test_safe_paths_and_agent_ids():
    assert is_safe_relative_path("workspace/reports/eva/x.json")
    for bad in ("", "/abs", "C:/x", "a/../b", "a\\b", "./a", "aux/x", " a"):
        assert not is_safe_relative_path(bad), bad
    assert is_safe_agent_id("prover-ber-len-1")
    assert not is_safe_agent_id("Prover")
    assert not is_safe_agent_id("con")
