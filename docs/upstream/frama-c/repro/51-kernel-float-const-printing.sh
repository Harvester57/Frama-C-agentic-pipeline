#!/bin/sh
# Issue 51: [Kernel] C printer for synthesized CReal constants truncates double
# values to 12 significant digits and prints non-finite values as undeclared
# inf/-inf/nan/NaN identifiers.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/51-kernel-float-const-printing.patch built and installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     51-kernel-float-const-printing.sh
#
# Output before (master 189053d4a2; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   constfold_double_gcc: 0x1.5555555553de1p-2 0x1.ffffffffff735p-1 0x1.5555555553de1p-2 0x1.921fb54442eeap+2 0x1.999999fffdf51p-4 -0x0p+0
#   constfold_double_clang: 0x1.5555555553de1p-2 0x1.ffffffffff735p-1 0x1.5555555553de1p-2 0x1.921fb54442eeap+2 0x1.999999fffdf51p-4 -0x0p+0
#   eacsl_constfold: 0x1.5555555553de1p-2 0x1.ffffffffff735p-1 0x1.5555555553de1p-2 0x1.921fb54442eeap+2 0x1.999999fffdf51p-4 -0x0p+0
#   eacsl_annot: run exit 134
#   scf_double: 0x1.5555555553de1p-2 0x1.555555555611p-1 0x1.33333400005p-2
#   nonfinite_gcc: compile failed (... error: 'inf' undeclared ...)
#   nonfinite_clang: compile failed (... error: use of undeclared identifier 'inf')
#   nonfinite_reparse: reparse failed
#   nonfinite_hex_gcc: compile failed (... error: 'inf' undeclared ...)
#   nonfinite_eacsl: build failed (... error: 'inf' undeclared ...)
#   ext_f32_f64_gcc: compile failed (... error: 'inff32' undeclared ...)
#   RESULT: bug present (11 of 11 cases fail)
#
# Output after (master 189053d4a2 + patches/51-kernel-float-const-printing.patch):
#   35.0~~dev (Bromine)
#   constfold_double_gcc: 0x1.5555555555555p-2 0x1p+0 0x1.5555555555555p-2 0x1.921fb54442d18p+2 0x1.99999ap-4 -0x0p+0
#   constfold_double_clang: 0x1.5555555555555p-2 0x1p+0 0x1.5555555555555p-2 0x1.921fb54442d18p+2 0x1.99999ap-4 -0x0p+0
#   eacsl_constfold: 0x1.5555555555555p-2 0x1p+0 0x1.5555555555555p-2 0x1.921fb54442d18p+2 0x1.99999ap-4 -0x0p+0
#   eacsl_annot: run exit 0
#   scf_double: 0x1.5555555555555p-2 0x1.5555555555555p-1 0x1.333334p-2
#   nonfinite_gcc: inf -inf 1 inf 1 | inf -inf 1 inf 1
#   nonfinite_clang: inf -inf 1 inf 1 | inf -inf 1 inf 1
#   nonfinite_reparse: reparse ok
#   nonfinite_hex_gcc: inf -inf 1 inf 1 | inf -inf 1 inf 1
#   nonfinite_eacsl: inf -inf 1 inf 1 | inf -inf 1 inf 1
#   ext_f32_f64_gcc: 1 1 1 0x1.5555555555555p-2
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
command -v gcc >/dev/null 2>&1 || { echo "gcc is not in PATH" >&2; exit 2; }
EG=$(command -v e-acsl-gcc || command -v e-acsl-gcc.sh) || { echo "e-acsl-gcc is not in PATH" >&2; exit 2; }
n=51-kernel-float-const-printing
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

check() { # $1: label, $2: expected, $3: actual
  total=$((total + 1))
  echo "$1: $3"
  [ "$3" = "$2" ] || fail=$((fail + 1))
}

# Ground truth outputs from gcc
gcc -DCASE_fold "$n.c" -o "$tmp/fold_ref" && ref_fold=$("$tmp/fold_ref")
gcc -DCASE_scf "$n.c" -o "$tmp/scf_ref" && ref_scf=$("$tmp/scf_ref")
gcc -DCASE_nonfinite "$n.c" -o "$tmp/nf_ref" && ref_nf=$("$tmp/nf_ref")
gcc -DCASE_ext "$n.c" -o "$tmp/ext_ref" && ref_ext=$("$tmp/ext_ref")

# 1. -constfold -print -ocode -> gcc (and clang if present)
frama-c -machdep gcc_x86_64 -no-frama-c-stdlib -cpp-extra-args="-DCASE_fold" \
  -constfold "$n.c" -print -ocode "$tmp/fold_out.c" >/dev/null 2>&1
if gcc "$tmp/fold_out.c" -o "$tmp/fold_out" 2>"$tmp/err.log"; then
  got=$("$tmp/fold_out")
else
  got="compile failed"
fi
check constfold_double_gcc "$ref_fold" "$got"

if command -v clang >/dev/null 2>&1; then
  if clang "$tmp/fold_out.c" -o "$tmp/fold_out_cl" 2>"$tmp/err.log"; then
    got=$("$tmp/fold_out_cl")
  else
    got="compile failed"
  fi
  check constfold_double_clang "$ref_fold" "$got"
fi

# 2. default e-acsl-gcc (passes -constfold) on fold
if "$EG" -q -c -E "-DCASE_fold" -e "-DCASE_fold" \
    -o "$tmp/fold.gen.c" -O "$tmp/fold_e" "$n.c" >"$tmp/err.log" 2>&1; then
  got=$("$tmp/fold_e.e-acsl")
else
  got="build failed"
fi
check eacsl_constfold "$ref_fold" "$got"

# 3. e-acsl-gcc --no-constfold on exact float/double/integer assertions
if "$EG" -q --no-constfold -c -E "-DCASE_annot" -e "-DCASE_annot" \
    -o "$tmp/annot.gen.c" -O "$tmp/annot_e" "$n.c" >"$tmp/err.log" 2>&1; then
  prlimit --core=1:1 "$tmp/annot_e.e-acsl" >"$tmp/run.log" 2>&1
  rc=$?
  got="run exit $rc"
else
  got="build failed"
fi
check eacsl_annot "run exit 0" "$got"

# 4. -scf -then-last -print -ocode -> gcc
frama-c -machdep gcc_x86_64 -no-frama-c-stdlib -no-variadic-translation \
  -cpp-extra-args="-DCASE_scf" "$n.c" \
  -scf -then-last -print -ocode "$tmp/scf_out.c" >/dev/null 2>&1
if gcc "$tmp/scf_out.c" -o "$tmp/scf_out" 2>"$tmp/err.log"; then
  got=$("$tmp/scf_out")
else
  got="compile failed"
fi
check scf_double "$ref_scf" "$got"

# 5. non-finite -constfold -print -ocode -> gcc, clang, frama-c re-parse
frama-c -machdep gcc_x86_64 -no-frama-c-stdlib -cpp-extra-args="-DCASE_nonfinite" \
  -constfold "$n.c" -print -ocode "$tmp/nf_out.c" >/dev/null 2>&1
if gcc -std=c99 "$tmp/nf_out.c" -o "$tmp/nf_out" 2>"$tmp/err.log"; then
  got=$("$tmp/nf_out")
else
  err=$(grep -m1 "error:" "$tmp/err.log")
  got="compile failed ($err)"
fi
check nonfinite_gcc "$ref_nf" "$got"

if command -v clang >/dev/null 2>&1; then
  if clang -std=c99 "$tmp/nf_out.c" -o "$tmp/nf_out_cl" 2>"$tmp/err.log"; then
    got=$("$tmp/nf_out_cl")
  else
    err=$(grep -m1 "error:" "$tmp/err.log")
    got="compile failed ($err)"
  fi
  check nonfinite_clang "$ref_nf" "$got"
fi

if frama-c -machdep gcc_x86_64 -no-frama-c-stdlib "$tmp/nf_out.c" >/dev/null 2>"$tmp/err.log"; then
  got="reparse ok"
else
  got="reparse failed"
fi
check nonfinite_reparse "reparse ok" "$got"

# 6. non-finite with -float-print hex
frama-c -machdep gcc_x86_64 -no-frama-c-stdlib -cpp-extra-args="-DCASE_nonfinite" \
  -constfold -float-print hex "$n.c" -print -ocode "$tmp/nf_hex.c" >/dev/null 2>&1
if gcc -std=c99 "$tmp/nf_hex.c" -o "$tmp/nf_hex" 2>"$tmp/err.log"; then
  got=$("$tmp/nf_hex")
else
  err=$(grep -m1 "error:" "$tmp/err.log")
  got="compile failed ($err)"
fi
check nonfinite_hex_gcc "$ref_nf" "$got"

# 7. non-finite via default e-acsl-gcc
if "$EG" -q -c -E "-DCASE_nonfinite" -e "-DCASE_nonfinite" \
    -o "$tmp/nf.gen.c" -O "$tmp/nf_e" "$n.c" >"$tmp/err.log" 2>&1; then
  got=$("$tmp/nf_e.e-acsl")
else
  err=$(grep -m1 "error:" "$tmp/err.log")
  got="build failed ($err)"
fi
check nonfinite_eacsl "$ref_nf" "$got"

# 8. _Float32 / _Float64 suffixes (gcc)
frama-c -machdep gcc_x86_64 -no-frama-c-stdlib -cpp-extra-args="-DCASE_ext" \
  -constfold "$n.c" -print -ocode "$tmp/ext_out.c" >/dev/null 2>&1
if gcc "$tmp/ext_out.c" -o "$tmp/ext_out" 2>"$tmp/err.log"; then
  got=$("$tmp/ext_out")
else
  err=$(grep -m1 "error:" "$tmp/err.log")
  got="compile failed ($err)"
fi
check ext_f32_f64_gcc "$ref_ext" "$got"

rm -rf "$tmp"
if [ "$fail" = 0 ]; then
  echo "RESULT: fixed"
  exit 0
else
  echo "RESULT: bug present ($fail of $total cases fail)"
  exit 1
fi
