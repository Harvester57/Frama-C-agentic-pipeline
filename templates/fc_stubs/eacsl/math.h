/*
 * <math.h> for the E-ACSL frontend only.
 *
 * build_eacsl_flag_sets() (scripts/eacsl_toolchain.py) puts this directory first on the E-ACSL `-E`
 * (Frama-C frontend) flags; Eva and WP never see it (they get templates/fc_stubs, not its eacsl/
 * subdirectory), nor does the backend compile of the instrumented file.
 *
 * glibc's classification macros expand to GCC builtins (__builtin_isnan, __builtin_signbit, ...).
 * Frama-C does not know them: it reports "Calling undeclared function __builtin_isnan", prints a
 * K&R prototype for it in the instrumented file, and clang then refuses to compile it ("cannot
 * redeclare builtin function", QCBOR run-4). The frontend gets -D__SUPPORT_SNAN__ (EACSL_DEFINES),
 * which makes glibc call its library functions instead for isnan, isinf, isfinite, isnormal and
 * fpclassify, through its type-generic dispatch __MATH_TG.
 *
 * Two things remain, fixed here after glibc's own definitions:
 *  - __MATH_TG is a _Generic over float, _Float32, long double, _Float64x and _Float128. Frama-C
 *    treats _Float32 as float (and the frontend maps _Float128 to double), so the selection has
 *    duplicate types and Frama-C rejects it ("multiple compatible types in _Generic selection").
 *    Here it selects over float, long double and default (double) only. Not glibc's sizeof-based
 *    fallback: Frama-C folds the constant `sizeof` tests of its nested ternary and drops the
 *    declaration of a temporary the instrumented code still reads (clang: undeclared 'tmp_7').
 *  - signbit is not behind __SUPPORT_SNAN__: it uses __builtin_signbit whenever __GNUC_PREREQ (6,0).
 *    It goes through __MATH_TG to __signbitf / __signbit / __signbitl, which <math.h> declares.
 *
 * Macros only: no function bodies (README rule 1).
 */
#include_next <math.h>

#if defined(__FRAMAC_EACSL__) && defined(__GLIBC__)
#undef __MATH_TG
#define __MATH_TG(TG_ARG, FUNC, ARGS) _Generic((TG_ARG), float: FUNC##f ARGS, long double: FUNC##l ARGS, default: FUNC ARGS)
#ifdef signbit
#undef signbit
#define signbit(x) __MATH_TG((x), __signbit, (x))
#endif
#endif
