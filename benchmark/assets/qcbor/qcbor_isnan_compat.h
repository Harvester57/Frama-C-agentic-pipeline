#ifndef QCBOR_ISNAN_COMPAT_H
#define QCBOR_ISNAN_COMPAT_H
/* Force-included for E-ACSL/Eva/WP builds. Frama-C host-header mode expands
 * isnan() to __builtin_isnan and emits a clang-rejected redeclaration of that
 * builtin. isnan(x) <=> x != x for IEEE-754 values. */
#include <math.h>
#undef isnan
#define isnan(x) ((x) != (x))
#endif
