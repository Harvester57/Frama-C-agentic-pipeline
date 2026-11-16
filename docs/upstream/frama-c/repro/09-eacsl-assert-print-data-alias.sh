#!/bin/sh
# The deprecated option -e-acsl-assert-print-data is an alias of -e-acsl-O-valid
# instead of -e-acsl-O-print-values.
#
# Image: framac-master-audit:3dff90f (master 3dff90fc70), framac-analysis:fc34 (34.0~beta).
# Run from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 09-eacsl-assert-print-data-alias.sh
#
# Output on master 3dff90fc70 (same on 34.0~beta):
#   == deprecation warnings
#   [kernel] Warning: -e-acsl-assert-print-data is a deprecated alias for option -e-acsl-O-valid.
#     Please use -e-acsl-O-valid instead.
#   [kernel] Warning: -e-acsl-no-assert-print-data is a deprecated alias
#     for option -e-acsl-O-no-valid. Please use -e-acsl-O-no-valid instead.
#   == __e_acsl_assert_register_* calls in the instrumented code
#   default:                         2
#   -e-acsl-O-no-print-values:       0
#   -e-acsl-no-assert-print-data:    2
#   == __e_acsl_assert calls after WP proved the assertion
#   default:                         0
#   -e-acsl-O-valid:                 2
#   -e-acsl-assert-print-data:       2
#
# Output with the fix (alias registered on Print_values):
#   == deprecation warnings
#   [kernel] Warning: -e-acsl-assert-print-data is a deprecated alias
#     for option -e-acsl-O-print-values. Please use -e-acsl-O-print-values instead.
#   [kernel] Warning: -e-acsl-no-assert-print-data is a deprecated alias
#     for option -e-acsl-O-no-print-values.
#     Please use -e-acsl-O-no-print-values instead.
#   == __e_acsl_assert_register_* calls in the instrumented code
#   default:                         2
#   -e-acsl-O-no-print-values:       0
#   -e-acsl-no-assert-print-data:    0
#   == __e_acsl_assert calls after WP proved the assertion
#   default:                         0
#   -e-acsl-O-valid:                 2
#   -e-acsl-assert-print-data:       0

F=09-eacsl-assert-print-data-alias.c
FC="frama-c -machdep gcc_x86_64 $F"

echo '== deprecation warnings'
$FC -e-acsl -e-acsl-assert-print-data 2>&1 | sed -n '/deprecated alias/,/instead\./p'
$FC -e-acsl -e-acsl-no-assert-print-data 2>&1 | sed -n '/deprecated alias/,/instead\./p'

# Values involved in a failed assertion are registered with
# __e_acsl_assert_register_*: zero calls means value printing is off.
count() { $FC -e-acsl "$@" -then-last -print 2>/dev/null | grep -c '__e_acsl_assert_register_'; }
echo '== __e_acsl_assert_register_* calls in the instrumented code'
echo "default:                         $(count)"
echo "-e-acsl-O-no-print-values:       $(count -e-acsl-O-no-print-values)"
echo "-e-acsl-no-assert-print-data:    $(count -e-acsl-no-assert-print-data)"

# The assertion is proved by WP, so E-ACSL does not instrument it unless
# -e-acsl-O-valid is set.
countv() { $FC -wp -wp-prover qed -then -e-acsl "$@" -then-last -print 2>/dev/null | grep -c '__e_acsl_assert('; }
echo '== __e_acsl_assert calls after WP proved the assertion'
echo "default:                         $(countv)"
echo "-e-acsl-O-valid:                 $(countv -e-acsl-O-valid)"
echo "-e-acsl-assert-print-data:       $(countv -e-acsl-assert-print-data)"
