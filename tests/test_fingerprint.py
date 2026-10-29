from fingerprint import is_valid_fingerprint, make_fingerprint, normalize_file, normalize_kind, normalize_predicate


def test_fingerprint_is_stable_across_tools_paths_and_formatting():
    a = make_fingerprint("/framac-run/workspace/work/src/ber.c", "ber_len", "Assertion", r"rte: mem_access: \valid_read(buf + i).")
    b = make_fingerprint("src/ber.c", "ber_len", "mem_access", r"\valid_read(buf+i)")
    c = make_fingerprint("workspace/work/src/ber.c", "ber_len", "assertion", r"assert Eva: mem_access: \valid_read(buf +  i);")
    assert a == b == c
    assert a.startswith("src/ber.c#ber_len::mem_access::")
    assert is_valid_fingerprint(a)


def test_fingerprint_has_no_line_number_and_distinguishes_predicates():
    a = make_fingerprint("src/x.c", "f", "", r"\valid(p)")
    b = make_fingerprint("src/x.c", "f", "", r"\valid(q)")
    assert a != b
    assert ":42" not in a


def test_normalizers():
    assert normalize_file("./src/a.c") == "src/a.c"
    assert normalize_file("/target/src/a.c") == "src/a.c"
    assert normalize_kind("Precondition") == "precondition"
    assert normalize_kind("Loop invariant") == "loop_invariant"
    assert normalize_kind("Assertion", "signed_overflow: x + 1 <= 2147483647") == "signed_overflow"
    assert normalize_predicate("rte: mem_access: \\valid_read(p) .") == "\\valid_read(p)"


def test_invalid_fingerprints_rejected():
    assert not is_valid_fingerprint("no-separators")
    assert not is_valid_fingerprint("src/a.c#f::k::abc with space")
