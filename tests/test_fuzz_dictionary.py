import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from fuzz_dictionary import (  # noqa: E402
    build_dictionary,
    collect_source_files,
    extract_string_literals,
    generate_extreme_numeric_tokens,
    write_dictionary,
)


def test_generate_extreme_numeric_tokens():
    tokens = generate_extreme_numeric_tokens()
    # Verify mandatory decimal boundaries and off-by-ones
    mandatory_decimal = [
        "0",
        "1",
        "-1",
        "127",
        "-128",
        "255",
        "256",
        "32767",
        "-32768",
        "65535",
        "2147483647",
        "-2147483648",
        "4294967295",
        "9223372036854775807",
        "-9223372036854775808",
        "18446744073709551615",
    ]
    for tok in mandatory_decimal:
        assert tok in tokens, f"Missing decimal token: {tok}"

    # Verify hex representations
    mandatory_hex = [
        "0x0",
        "0x1",
        "0x7f",
        "0x80",
        "0xff",
        "0x7fff",
        "0x8000",
        "0xffff",
        "0x7fffffff",
        "0x80000000",
        "0xffffffff",
    ]
    for h in mandatory_hex:
        assert h in tokens, f"Missing hex token: {h}"

    # Verify escaped byte representations
    mandatory_bytes = [
        r"\x00",
        r"\xff",
        r"\x7f",
        r"\x80",
        r"\x00\x00",
        r"\xff\xff",
        r"\x00\x00\x00\x00",
        r"\xff\xff\xff\xff",
    ]
    for b in mandatory_bytes:
        assert b in tokens, f"Missing byte token: {b}"


def test_extract_string_literals_from_c_code():
    c_code = """
    #include <stdio.h>
    #define PREFIX "CMD:"

    void parse(const char *buf) {
        if (strcmp(buf, "GET /index") == 0) {
            printf("Found request\\n");
        }
        char *empty = "";
        char *duplicate = "CMD:";
    }
    """
    literals = extract_string_literals(c_code)
    assert "CMD:" in literals
    assert "GET /index" in literals
    assert r"Found request\n" in literals
    # Empty string should be excluded
    assert "" not in literals
    # Duplicates should be collapsed
    assert literals.count("CMD:") == 1


def test_collect_source_files_skips_dot_dirs(tmp_path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "mod.c").write_text("int f(void) { return 0; }", encoding="utf-8")
    (src_dir / "mod.h").write_text("int f(void);", encoding="utf-8")

    dot_dir = tmp_path / ".cache"
    dot_dir.mkdir()
    (dot_dir / "cached.c").write_text("int cached(void) { return 1; }", encoding="utf-8")

    build_dir = tmp_path / "build"
    build_dir.mkdir()
    (build_dir / "out.c").write_text("int out(void) { return 2; }", encoding="utf-8")

    files = collect_source_files([tmp_path])
    file_names = {f.name for f in files}
    assert "mod.c" in file_names
    assert "mod.h" in file_names
    assert "cached.c" not in file_names
    assert "out.c" not in file_names


def test_build_and_write_dictionary(tmp_path):
    c_file = tmp_path / "parser.c"
    c_file.write_text('const char *magic = "HEADER_V1";\n', encoding="utf-8")

    dict_file = tmp_path / "test.dict"
    tokens = build_dictionary(sources=[c_file])
    assert "HEADER_V1" in tokens
    assert "-2147483648" in tokens

    write_dictionary(dict_file, tokens)
    assert dict_file.exists()
    content = dict_file.read_text(encoding="utf-8")
    assert '"HEADER_V1"' in content
    assert '"-2147483648"' in content
    assert '"2147483647"' in content
    assert r'"\x00"' in content
    assert r'"\xff"' in content


def test_cli_execution(tmp_path):
    c_file = tmp_path / "app.c"
    c_file.write_text('const char *k = "SECRET_KEY";\n', encoding="utf-8")
    out_dict = tmp_path / "out.dict"

    res = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/fuzz_dictionary.py"),
            "--sources",
            str(c_file),
            "--out-dict",
            str(out_dict),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, res.stderr
    assert out_dict.exists()
    text = out_dict.read_text(encoding="utf-8")
    assert '"SECRET_KEY"' in text
    assert '"4294967295"' in text

    # Test with --no-numeric
    out_no_num = tmp_path / "no_num.dict"
    res = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/fuzz_dictionary.py"),
            str(c_file),
            "-o",
            str(out_no_num),
            "--no-numeric",
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, res.stderr
    text_no_num = out_no_num.read_text(encoding="utf-8")
    assert '"SECRET_KEY"' in text_no_num
    assert '"2147483647"' not in text_no_num
