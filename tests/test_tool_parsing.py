from fingerprint import is_valid_fingerprint
from run_eacsl_fuzz import (
    _discover_slice_functions,
    classify_campaign,
    classify_guardrail,
    derive_eacsl_diagnostic_hints,
    parse_eacsl_failure,
    parse_runtime_failure,
    parse_sanitizer_failure,
    stable_ubsan_message,
)
from run_eva_slice import extract_error_summary
from run_wp_function import (
    extract_vc_goal_dumps,
    goal_obligation_class,
    scan_wp_log_soundness,
)

NEW_STYLE = """INFO: Seed: 123
src/snmp/ber.c: In function 'ber_decode_len'
src/snmp/ber.c:42: Error: Assertion failed:
	The failing predicate is:
	mem_access: \\valid_read(buf + off).
==1== ERROR: libFuzzer: deadly signal
"""

OLD_STYLE = """Precondition failed at line 17 in function parse_hdr.
The failing predicate is:
len <= 64.
"""

ANNOTATION = """src/x.c: In function 'f'
src/x.c:9: Error: Loop invariant failed:
	The failing predicate is:
	0 <= i <= n - 1.
"""


FRAMAC33_RTE = """workspace/work/src/parser/parser.c: In function 'parse_record'
workspace/work/src/parser/parser.c:30: Error: Assertion failed:
\tThe failing predicate is:
\trte/index_bound:
\t\ti < 8.
\tWith values at failure point:
\t- i: 8
==181== ERROR: libFuzzer: deadly signal
"""

FRAMAC33_POST = """state/w/src/util/sum.h: In function 'checksum'
state/w/src/util/sum.h:11: Error: Postcondition failed:
\tThe failing predicate is:
\trange:
\t\t0 ≤ \\result ≤
\t\t0xF.
\tWith values at failure point:
\t- \\result: 101
"""


def test_parse_new_style_rte_failure():
    f = parse_eacsl_failure(NEW_STYLE)
    assert f is not None
    assert f["file"] == "src/snmp/ber.c" and f["line"] == 42
    assert f["function"] == "ber_decode_len"
    assert f["kind"] == "assertion" and f["alarm_kind"] == "mem_access" and f["is_rte"]
    assert (f["label"], f["predicate"]) == ("mem_access", "\\valid_read(buf + off)")


def test_parse_framac33_label_line_then_predicate():
    f = parse_eacsl_failure(FRAMAC33_RTE)
    assert f is not None
    assert (f["line"], f["function"], f["kind"]) == (30, "parse_record", "assertion")
    assert (f["label"], f["predicate"], f["alarm_kind"], f["is_rte"]) == (
        "rte/index_bound",
        "i < 8",
        "index_bound",
        True,
    )
    post = parse_eacsl_failure(FRAMAC33_POST)
    assert post is not None
    assert (post["kind"], post["label"], post["predicate"]) == ("postcondition", "range", "0 ≤ \\result ≤ 0xF")
    assert post["alarm_kind"] is None and not post["is_rte"]


def test_parse_old_style_precondition_failure():
    f = parse_eacsl_failure(OLD_STYLE)
    assert f is not None
    assert f["line"] == 17 and f["function"] == "parse_hdr"
    assert f["kind"] == "precondition" and not f["is_rte"]
    assert f["predicate"] == "len <= 64"


def test_parse_returns_none_without_report():
    assert parse_eacsl_failure("random libFuzzer output") is None


def test_parse_sanitizer_ubsan_and_asan_failures():
    ubsan_log = """INFO: Running with entropic power schedule
src/LibPtfCom/PtfMsg.c:91:28: runtime error: signed integer overflow: 2147483640 + 100 cannot be represented in type 'int'
    #0 0x555555601234 in CheckMessageValidity /framac-run/workspace/work/src/LibPtfCom/PtfMsg.c:91:28
    #1 0x555555602000 in LLVMFuzzerTestOneInput /framac-run/workspace/harnesses/harness_PtfMsg.c:30:5
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/LibPtfCom/PtfMsg.c:91:28
"""
    f_ub = parse_sanitizer_failure(ubsan_log)
    assert f_ub is not None
    assert f_ub["file"] == "src/LibPtfCom/PtfMsg.c"
    assert f_ub["line"] == 91
    assert f_ub["function"] == "CheckMessageValidity"
    assert f_ub["alarm_kind"] == "signed_overflow"
    assert f_ub["is_rte"] is True
    assert (
        f_ub["predicate"] == "rte: signed_overflow: signed integer overflow: N + N cannot be represented in type 'int'"
    )
    assert f_ub["message"] == "signed integer overflow: 2147483640 + 100 cannot be represented in type 'int'"

    asan_log = """=================================================================
==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014 at pc 0x55555558a123 bp 0x7fffffffd100 sp 0x7fffffffd0f8
READ of size 4 at 0x602000000014 thread T0
    #0 0x55555558a122 in __asan_memcpy (/framac-run/workspace/harnesses/fuzz_SyncMem+0x4a122)
    #1 0x5555555c9876 in UpdateSyncMem /framac-run/workspace/work/src/LibPtfCom/SyncMem.c:292:9
    #2 0x5555555ca000 in LLVMFuzzerTestOneInput /framac-run/workspace/harnesses/harness_SyncMem.c:40:5
"""
    f_as = parse_runtime_failure(asan_log)
    assert f_as is not None
    assert f_as["file"] == "/framac-run/workspace/work/src/LibPtfCom/SyncMem.c"
    assert f_as["line"] == 292
    assert f_as["function"] == "UpdateSyncMem"
    assert f_as["alarm_kind"] == "mem_access"


def test_discover_slice_functions_and_eva_error_summary(tmp_path):
    c_file = tmp_path / "mod.c"
    c_file.write_text("int helper(int x) { return x + 1; }\nint entry(int y) { return helper(y); }\n", encoding="utf-8")
    h_file = tmp_path / "harness_mod.c"
    h_file.write_text("int LLVMFuzzerTestOneInput(const char *d, int s) { return entry(s); }\n", encoding="utf-8")
    fns = _discover_slice_functions([str(c_file), str(h_file)])
    assert fns == ["entry", "helper"]

    eva_err = """[kernel] Parsing mod.c (with preprocessing)
[kernel:annot-error] mod.c:12: Warning: unbound logic variable alse. Ignoring logic specification of function foo
[kernel] User Error: warning annot-error treated as fatal error.
[kernel] Frama-C aborted: invalid user input.
"""
    summary = extract_error_summary(eva_err)
    assert any("unbound logic variable alse" in line for line in summary)
    assert any("Frama-C aborted: invalid user input" in line for line in summary)


def test_ubsan_resolves_function_from_source_line_without_stacktrace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src_file = tmp_path / "workspace" / "work" / "src" / "LibPtfCom" / "Events.c"
    src_file.parent.mkdir(parents=True)
    src_file.write_text(
        "int Helper(int x) {\n    return x;\n}\n\nint SendEvent(const char *name, int code) {\n    int arr[2] = {1, 2};\n    return arr[code];\n}\n",
        encoding="utf-8",
    )
    # Single-line UBSan output with no #0 stack frame
    ubsan_no_stack = "src/LibPtfCom/Events.c:7:12: runtime error: index 5 out of bounds for type 'int[2]'\n"
    parsed = parse_sanitizer_failure(ubsan_no_stack)
    assert parsed is not None
    assert parsed["file"] == "src/LibPtfCom/Events.c"
    assert parsed["line"] == 7
    assert parsed["function"] == "SendEvent"
    assert parsed["alarm_kind"] == "index_bound"


def test_ubsan_runtime_values_leave_the_predicate_and_the_fingerprint():
    from fingerprint import make_fingerprint

    cases = {
        "left shift of negative value -2806": "left shift of negative value N",
        "signed integer overflow: -2147483648 - 1 cannot be represented in type 'int'": (
            "signed integer overflow: N - N cannot be represented in type 'int'"
        ),
        "index 1025 out of bounds for type 'char[1024]'": "index N out of bounds for type 'char[1024]'",
        "shift exponent 40 is too large for 32-bit type 'int32_t'": (
            "shift exponent N is too large for N-bit type 'int32_t'"
        ),
        "load of misaligned address 0x7ffd1a2b for type 'uint32_t', which requires 4 byte alignment": (
            "load of misaligned address N for type 'uint32_t', which requires N byte alignment"
        ),
        "1.5e+10 is outside the range of representable values of type 'int'": (
            "N is outside the range of representable values of type 'int'"
        ),
        "negation of -2147483648 cannot be represented in type 'int'; cast to an unsigned type": (
            "negation of N cannot be represented in type 'int'; cast to an unsigned type"
        ),
    }
    for raw, stable in cases.items():
        assert stable_ubsan_message(raw) == stable

    def fp(value: int) -> str:
        log = f"tweetnacl.c:282:9: runtime error: left shift of negative value {value}\n"
        f = parse_sanitizer_failure(log)
        assert f is not None
        return make_fingerprint(f["file"], "car25519", f["alarm_kind"], f["predicate"])

    assert fp(-2806) == fp(-19345)


def test_campaign_classification():
    assert classify_campaign(0, False, []) == "clean"
    assert classify_campaign(1, False, []) == "fuzzer_error"
    assert classify_campaign(0, True, []) == "fuzzer_error"
    assert classify_campaign(1, False, [{"kind": "crash"}]) == "crash_found"
    assert classify_campaign(1, False, [{"kind": "timeout"}]) == "timeout_found"
    assert classify_campaign(1, False, [{"kind": "oom"}]) == "oom_found"


def test_guardrail_separates_code_faults_from_overconstrained_contracts():
    assert classify_guardrail(0, False, "")["status"] == "passed_dynamic_oracle"
    rte = classify_guardrail(1, False, NEW_STYLE)
    assert rte["status"] == "code_fault" and rte["fingerprint"].startswith(
        "src/snmp/ber.c#ber_decode_len::mem_access::"
    )
    assert classify_guardrail(1, False, ANNOTATION)["status"] == "rejected_overconstrained"
    assert classify_guardrail(1, False, "segfault")["status"] == "guardrail_error"


def test_guardrail_classifies_annotation_rte_and_alarm_labeled_contracts(tmp_path):
    # 1. E-ACSL runtime error inside an ACSL annotation (Error: RTE failed / RTE failed at line ...)
    annot_rte_new = (
        "rte.i: In function 'is_dividable'\n"
        "rte.i:5: Error: RTE failed:\n"
        "\tThe failing predicate is:\n"
        "\trte: division_by_zero: y != 0.\n"
    )
    f_new = parse_eacsl_failure(annot_rte_new)
    assert f_new is not None
    assert f_new["kind"] == "rte"
    assert f_new["is_rte"] is False
    assert f_new.get("annotation_rte") is True
    res_new = classify_guardrail(1, False, annot_rte_new)
    assert res_new["status"] == "rejected_overconstrained"
    assert res_new.get("annotation_rte") is True

    annot_rte_old = (
        "RTE failed at line 5 in function is_dividable.\nThe failing predicate is:\nrte: division_by_zero: y != 0.\n"
    )
    f_old = parse_eacsl_failure(annot_rte_old)
    assert f_old is not None
    assert f_old["kind"] == "rte" and not f_old["is_rte"] and f_old.get("annotation_rte") is True
    res_old = classify_guardrail(1, False, annot_rte_old)
    assert res_old["status"] == "rejected_overconstrained"
    assert res_old.get("annotation_rte") is True

    # 2. Precondition / loop invariant whose label or predicate matches KNOWN_ALARM_KINDS
    # (e.g. valid_string, separation, index_bound) must NOT be misclassified as code_fault
    pre_alarm_label = (
        "src/str.c: In function 'parse_name'\n"
        "src/str.c:12: Error: Precondition failed:\n"
        "\tThe failing predicate is:\n"
        "\tvalid_string:\n"
        "\t\tvalid_read_string(s).\n"
    )
    f_pre = parse_eacsl_failure(pre_alarm_label)
    assert f_pre is not None
    assert f_pre["kind"] == "precondition"
    assert f_pre["alarm_kind"] == "valid_string"
    assert f_pre["is_rte"] is False
    assert classify_guardrail(1, False, pre_alarm_label)["status"] == "rejected_overconstrained"

    # 3. Source-line disambiguation: Assertion failed on an ACSL-only line vs executable C line
    src_file = tmp_path / "mod.c"
    src_file.write_text(
        "int check(const int *p, int i) {\n    /*@ assert mem_access: \\valid_read(p + i); */\n    return p[i];\n}\n",
        encoding="utf-8",
    )
    acsl_line_out = (
        f"{src_file.as_posix()}: In function 'check'\n"
        f"{src_file.as_posix()}:2: Error: Assertion failed:\n"
        "\tThe failing predicate is:\n"
        "\tmem_access: \\valid_read(p + i).\n"
    )
    c_line_out = (
        f"{src_file.as_posix()}: In function 'check'\n"
        f"{src_file.as_posix()}:3: Error: Assertion failed:\n"
        "\tThe failing predicate is:\n"
        "\tmem_access: \\valid_read(p + i).\n"
    )
    res_acsl_line = classify_guardrail(1, False, acsl_line_out)
    assert res_acsl_line["failure"]["file"] == src_file.as_posix()
    assert res_acsl_line["status"] == "rejected_overconstrained"
    assert res_acsl_line.get("annotation_rte") is True

    res_c_line = classify_guardrail(1, False, c_line_out)
    assert res_c_line["status"] == "code_fault"
    assert is_valid_fingerprint(res_c_line["fingerprint"])


def test_guardrail_classifies_unsound_verdicts():
    # When returncode == 0, unsound verdict warning must NOT pass the guardrail
    ok_unsound = "Warning: no sound verdict for Assertion (guess: ok).\nDone."
    res_ok = classify_guardrail(0, False, ok_unsound)
    assert res_ok["status"] == "guardrail_error"
    assert res_ok["unsound"] is True
    assert "unsound verdict" in res_ok["reason"]

    # Also match alternate wording 'Warning: unsound verdict reached' and 'warning: unsound verdict'
    res_unsound2 = classify_guardrail(0, False, "Warning: unsound verdict reached\n")
    assert res_unsound2["status"] == "guardrail_error" and res_unsound2["unsound"] is True
    res_unsound3 = classify_guardrail(0, False, "warning: unsound verdict\n")
    assert res_unsound3["status"] == "guardrail_error" and res_unsound3["unsound"] is True

    # When returncode != 0, unsound verdict warning must NOT be reported as code_fault or rejected_overconstrained
    fail_unsound = "Warning: no sound verdict for Assertion (guess: FAIL).\n" + ANNOTATION
    res_fail = classify_guardrail(1, False, fail_unsound)
    assert res_fail["status"] == "guardrail_error"
    assert res_fail["unsound"] is True
    assert "unsound E-ACSL verdict" in res_fail["reason"]
    assert res_fail.get("failure") is not None

    # Normal execution without unsound warning preserves standard behavior
    assert classify_guardrail(0, False, "Clean run\n")["status"] == "passed_dynamic_oracle"
    assert classify_guardrail(1, False, ANNOTATION)["status"] == "rejected_overconstrained"


def test_eacsl_hints_for_unsound_verdict():
    res = {
        "status": "guardrail_error",
        "reason": "Assertion failed under unsound E-ACSL verdict",
        "unsound": True,
    }
    hints = derive_eacsl_diagnostic_hints(res)
    assert any("unsound verdict warning" in h for h in hints)
    assert any("unsupported C standard library functions" in h for h in hints)


def test_wp_goal_to_obligation_class():
    assert (
        goal_obligation_class(
            {"kind": "postcondition", "annotation": "ensures L5_no_crlf: no_crlf_or_nul(out, \\result)"}
        )
        == "rte"
    )
    # D8: the pre-I9 layer classes are gone; a hand-named L5/L6 clause is classed by its kind.
    assert (
        goal_obligation_class({"kind": "postcondition", "annotation": "L6_key_wiped: buffer_is_zeroed(k, 32)"}) == "rte"
    )
    assert goal_obligation_class({"kind": "loop variant", "annotation": "n - i"}) == "l2_termination"
    assert goal_obligation_class({"kind": "assigns", "annotation": "assigns out[0..n-1]"}) == "l3_frame"
    assert goal_obligation_class({"kind": "assertion", "annotation": "rte: mem_access: \\valid(p)"}) == "rte"


def test_scan_wp_log_soundness_detects_abort_and_silent_unsoundness():
    clean_log = """
[kernel] Parsing src/foo.c (with preprocessing)
[rte:annot] annotating function foo
[wp] 4 goals scheduled
[wp] Proved goals:    4 / 4
"""
    clean = scan_wp_log_soundness(clean_log)
    assert clean["ok"] is True
    assert clean["tier_a_aborts"] == []
    assert clean["tier_b_unsound"] == []

    abort_log = """
[kernel] Parsing src/foo.c (with preprocessing)
[wp] user error: No 'calls' specification for function pointer call
"""
    aborted = scan_wp_log_soundness(abort_log)
    assert aborted["ok"] is False
    assert len(aborted["tier_a_aborts"]) == 1

    unsound_log = """
[wp] warning: Missing assigns clause (assigns 'everything' instead)
[wp] warning: Ignoring terminates specification for foo
[wp] warning: Memory model hypotheses for function 'foo':
[rte:annot] warning: Through function pointer (*cb): cannot generate validity guard
[wp] Smoke Tests : 0 / 1
"""
    unsound = scan_wp_log_soundness(
        unsound_log,
        check_memory_model=False,
        unsigned_reduced=True,
        warn_invalid_pointer=False,
    )
    assert unsound["ok"] is False
    assert any("Missing assigns clause" in w for w in unsound["tier_b_unsound"])
    assert any("Ignoring terminates specification" in w for w in unsound["tier_b_unsound"])
    assert any("Memory model hypotheses" in w for w in unsound["tier_b_unsound"])
    assert any("Smoke Tests" in w for w in unsound["tier_b_unsound"])
    assert len(unsound["skipped_rte_guards"]) == 1
    assert len(unsound["reduced_checks"]) == 2


def test_extract_vc_goal_dumps_parses_wp_print_sequents():
    sample_log = """
------------------------------------------------------------
Goal Post-condition 'bound' in 'parse_hdr':
Assume {
  Type: is_sint32(n).
  (* Pre-condition *)
  Have: 0 <= n.
}
Prove: 0 <= result.
Prover Alt-Ergo 2.5.4 returns Timeout (Qed:2ms) (10s)
------------------------------------------------------------
"""
    dumps = extract_vc_goal_dumps(sample_log)
    assert len(dumps) == 1
    assert "Goal Post-condition 'bound' in 'parse_hdr':" in dumps[0]
    assert "Prove: 0 <= result." in dumps[0]


def test_wp_counter_example_model_goals_parse():
    import run_wp_function as W

    log = (
        "[wp] [Unsuccess] typed_check_lemma_wrong (CVC4) (Model)\n"
        "[wp] [Valid] typed_ok (Alt-Ergo)\n"
        "[wp] [Unsuccess] typed_wrong_ensures (Z3) (Model)\n"
    )
    goals = [{"goal": m.group(1).strip(), "prover": m.group(2).strip()} for m in W._MODEL_GOAL_RE.finditer(log)]
    assert goals == [
        {"goal": "typed_check_lemma_wrong", "prover": "CVC4"},
        {"goal": "typed_wrong_ensures", "prover": "Z3"},
    ]


def test_wp_counter_examples_flag_is_threaded():
    import inspect

    import run_wp_function as W

    sig = inspect.signature(W.run_wp_on_function)
    assert "counter_examples" in sig.parameters and sig.parameters["counter_examples"].default is False
    src = inspect.getsource(W)
    assert 'cmd.append("-wp-counter-examples")' in src
    assert '"counter_example_goals": model_goals' in src
