"""Candidates grouped by statement site (D1, D1a): the site key and the ledger's use of it."""

from __future__ import annotations

import pytest

import failure_identity as FI

pytestmark = pytest.mark.unit

SITE_SOURCE = """\
int f(int *p, int n) {
    p[n] = 0;
    p[n] = 0;
    return p[0];
}
int g(int *q) {
    q[1] = 0;
    return q[1];
}
"""


@pytest.fixture
def site_run(tmp_path, monkeypatch):
    """A run directory whose workspace/work holds src/site.c."""
    src = tmp_path / "workspace" / "work" / "src"
    src.mkdir(parents=True)
    (src / "site.c").write_text(SITE_SOURCE, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_two_identical_lines_in_one_function_give_two_sites(site_run):
    fn_range = (1, 5)  # f
    first = FI.site_key("src/site.c", "f", 2, fn_range)
    second = FI.site_key("src/site.c", "f", 3, fn_range)
    assert first is not None and second is not None
    assert first != second
    assert first.endswith("#1") and second.endswith("#2")


def test_a_unique_line_has_no_occurrence_suffix(site_run):
    key = FI.site_key("src/site.c", "g", 7, (6, 9))
    assert key is not None and "#" not in key.split("@", 1)[1]


def test_the_key_ignores_the_range_when_the_line_is_unique_in_it(site_run):
    with_range = FI.site_key("src/site.c", "g", 7, (6, 9))
    without_range = FI.site_key("src/site.c", "g", 7)
    assert with_range == without_range


def test_lines_inserted_above_keep_the_site(site_run):
    before = FI.site_key("src/site.c", "g", 7, (6, 9))
    text = (site_run / "workspace" / "work" / "src" / "site.c").read_text(encoding="utf-8")
    (site_run / "workspace" / "work" / "src" / "site.c").write_text(
        "/* a */\n/* b */\n/* c */\n" + text, encoding="utf-8"
    )
    after = FI.site_key("src/site.c", "g", 10, (9, 12))
    assert before is not None and before == after


def test_a_site_needs_a_readable_line(site_run):
    assert FI.site_key("src/missing.c", "f", 2) is None
    assert FI.site_key("src/site.c", "f", 0) is None
    assert FI.site_key("src/site.c", "f", 999) is None


def test_the_site_key_is_file_function_and_text_hash(site_run):
    key = FI.site_key("src/site.c", "g", 7)
    assert key == f"src/site.c#g@{FI.line_text_hash('src/site.c', 7)}"
