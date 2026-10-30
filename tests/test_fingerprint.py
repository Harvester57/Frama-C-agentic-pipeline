from fingerprint import is_valid_fingerprint, make_fingerprint, normalize_file, normalize_kind, normalize_predicate


def test_fingerprint_is_stable_across_tools_paths_and_formatting():
    a = make_fingerprint("/framac-run/workspace/work/src/ber.c", "ber_len", "Assertion", r"rte: mem_access: \valid_read(buf + i).")
    b = make_fingerprint("src/ber.c", "ber_len", "mem_access", r"\valid_read(buf+i)")
    c = make_fingerprint("workspace/work/src/ber.c", "ber_len", "assertion", r"assert Eva: mem_access: \valid_read(buf +  i);")
    assert a == b == c
    assert a.startswith("src/ber.c#ber_len::mem_access::")
    assert is_valid_fingerprint(a)


def test_eacsl_crash_and_eva_red_alarm_on_the_same_property_share_a_fingerprint():
    # Frama-C 33: E-ACSL reports label `rte/index_bound` and predicate `i < 8`; Eva's CSV row has
    # directory/file columns, name `index_bound` and property `i < 8`.
    eacsl = make_fingerprint("workspace/work/src/parser/parser.c", "parse_record", "index_bound", "i < 8")
    eva = make_fingerprint("src/parser/parser.c", "parse_record", "index_bound", "i < 8")
    labelled = make_fingerprint("src/parser/parser.c", "parse_record", "assertion", "rte/index_bound: i < 8.")
    assert eacsl == eva == labelled
    # Unicode (E-ACSL output) and ASCII (-no-unicode) spellings of one predicate are the same property.
    assert normalize_predicate("0 ≤ \\result ≤ 0xF") == normalize_predicate("0 <= \\result <= 0xF")
    assert normalize_predicate("∀ ℤ i; p(i) ⇒ q(i)") == normalize_predicate("\\forall integer i; p(i) ==> q(i)")


def test_fingerprint_has_no_line_number_and_distinguishes_predicates():
    a = make_fingerprint("src/x.c", "f", "", r"\valid(p)")
    b = make_fingerprint("src/x.c", "f", "", r"\valid(q)")
    assert a != b
    assert ":42" not in a


def test_normalizers():
    assert normalize_file("./src/a.c") == "src/a.c"
    assert normalize_file("/target/src/a.c") == "src/a.c"
    # Every copy of the same file normalizes to the same repository-relative path.
    for copy in (
        "workspace/work/src/a.c",
        "/framac-run/workspace/work/src/a.c",
        "agents/prover-3/scratch/work/src/a.c",
        "/framac-run/agents/prover-3/scratch/base/src/a.c",
        "/home/u/framac-pipeline/demo/run-4/workspace/work/src/a.c",
        "C:\\Users\\u\\framac-pipeline\\demo\\run-4\\workspace\\work\\src\\a.c",
        "/home/u/framac-pipeline/demo/run-4/agents/prover-3/scratch/work/src/a.c",
    ):
        assert normalize_file(copy) == "src/a.c", copy
    assert normalize_kind("Precondition") == "precondition"
    assert normalize_kind("Loop invariant") == "loop_invariant"
    assert normalize_kind("Assertion", "signed_overflow: x + 1 <= 2147483647") == "signed_overflow"
    assert normalize_predicate("rte: mem_access: \\valid_read(p) .") == "\\valid_read(p)"


def test_invalid_fingerprints_rejected():
    assert not is_valid_fingerprint("no-separators")
    assert not is_valid_fingerprint("src/a.c#f::k::abc with space")
    assert not is_valid_fingerprint("SyncMem.c#UpdateSyncMem::rte::oob_read_memcpy")
    assert not is_valid_fingerprint("src/a.c#f::mem_access::012345678")
    assert not is_valid_fingerprint("src/a.c#f::mem_access::0123456789a")
    assert is_valid_fingerprint("harness_snmp.c#unknown_function::unparsed_crash::0123456789")
