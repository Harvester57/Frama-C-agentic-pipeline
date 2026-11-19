#!/bin/sh
# E-ACSL marks a monitored const global read-only with
# __e_acsl_mark_readonly((void *)g): the global's value, not its address.
# For a scalar, the runtime then aborts on the value used as an address. For a
# const struct with a bitfield member, E-ACSL aborts while taking the member's
# address. For a multi-field const struct, E-ACSL marks each field address with
# the whole enclosing block length, writing read-only shadow bits past the end
# of the block (aborting under --rt-debug). The const union case is
# 23-eacsl-static-const-union-cast.
#
# Images: framac-master-audit:b80fcac (master b80fcac74f, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 27-eacsl-readonly-scalar-global-address.sh
# e-acsl-gcc -X builds the instrumented program only. The script prints the
# error lines of the build log (Frama-C errors and e-acsl-gcc's own verdict),
# not the warnings, the backtrace or the compiler command lines.
#
# Output before the fix (master b80fcac74f; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -X  27-eacsl-readonly-scalar-global-address.c
#   build: exit 0
#   run: exit 0
#   --- e-acsl-gcc -q -X -M 27-eacsl-readonly-scalar-global-address.c
#   build: exit 0
#       __e_acsl_mark_readonly((void *)kMaxEmbeddedInt);
#   share/e-acsl/observation_model/segment_model/e_acsl_segment_tracking.c:226: Use of invalid address 0x17 in predicate
#   Aborted
#   run: exit 134
#   --- e-acsl-gcc -q -X -M 27-eacsl-readonly-scalar-global-address-bitfield.c
#   [kernel] Failure: Taking the address of a bitfield with &[ cb.a ]
#   e-acsl-gcc: fatal error: aborted by Frama-C
#   build: exit 1
#   --- e-acsl-gcc -q -X -M --rt-debug 27-eacsl-readonly-scalar-global-address-struct.c
#   build: exit 0
#       __e_acsl_mark_readonly((void *)(& cp.a));
#       __e_acsl_mark_readonly((void *)(& cp.b));
#   share/e-acsl/observation_model/segment_model/e_acsl_segment_tracking.c:497: Attempt to mark read-only 8 bytes past block boundaries
#   starting at <addr+4> with block length 8 at base address <addr>
#   ...
#   Aborted
#   run: exit 134
#
# Output after the fix (master b80fcac74f + patches/27-eacsl-readonly-scalar-global-address.patch):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -X  27-eacsl-readonly-scalar-global-address.c
#   build: exit 0
#   run: exit 0
#   --- e-acsl-gcc -q -X -M 27-eacsl-readonly-scalar-global-address.c
#   build: exit 0
#       __e_acsl_mark_readonly((void *)(& kMaxEmbeddedInt));
#   run: exit 0
#   --- e-acsl-gcc -q -X -M 27-eacsl-readonly-scalar-global-address-bitfield.c
#   build: exit 0
#       __e_acsl_mark_readonly((void *)(& cb));
#   run: exit 0
#   --- e-acsl-gcc -q -X -M --rt-debug 27-eacsl-readonly-scalar-global-address-struct.c
#   build: exit 0
#       __e_acsl_mark_readonly((void *)(& cp));
#   run: exit 0
set -u
n=27-eacsl-readonly-scalar-global-address
tmp=$(mktemp -d)
frama-c -version
build_and_run() { # <source> <e-acsl-gcc options>...
  src=$1; shift
  echo "--- e-acsl-gcc -q -X $* $src"
  e-acsl-gcc -q -X "$@" -o "$tmp/inst.c" -O "$tmp/t" "$src" > "$tmp/build.log" 2>&1
  status=$?
  grep -E '^\[kernel\] (Failure|Unexpected error)|^e-acsl-gcc: ' "$tmp/build.log"
  echo "build: exit $status"
  if [ "$status" -eq 0 ]; then
    grep '__e_acsl_mark_readonly(' "$tmp/inst.c" | grep -v FC_BUILTIN
    "$tmp/t.e-acsl" > "$tmp/run.log" 2>&1
    status=$?
    sed 's|^.*/share/e-acsl/|share/e-acsl/|' "$tmp/run.log"
    echo "run: exit $status"
  fi
  rm -f "$tmp/t.e-acsl" "$tmp/inst.c"
}
build_and_run "$n.c"
build_and_run "$n.c" -M
build_and_run "$n-bitfield.c" -M
build_and_run "$n-struct.c" -M --rt-debug
rm -rf "$tmp"
