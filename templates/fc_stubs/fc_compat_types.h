/*
 * Frama-C Compatibility Primitive Types (force-included by the pipeline)
 *
 * This header is a Frama-C parse aid only. It contains typedefs and includes,
 * never C function bodies, and it is EMPTY whenever __FRAMAC__ is undefined
 * (Clang compile of the self-contained E-ACSL output, sanitizer builds), so it
 * can never redefine types in code that already contains them.
 *
 *   __FRAMAC__ && __FRAMAC_EACSL__  (E-ACSL host-header mode, -no-frama-c-stdlib)
 *       Include host glibc <sys/types.h>: glibc itself is the only source of
 *       __int32_t, u_short, etc., so every alias is identical by construction.
 *
 *   __FRAMAC__ && !__FRAMAC_EACSL__ (Eva / WP with Frama-C's __fc_libc, -nostdinc)
 *       __fc_libc lacks the glibc-internal aliases (__int8_t .. __uint64_t) and
 *       some BSD aliases. Derive them from the compiler-predefined
 *       __INTn_TYPE__ / __UINTn_TYPE__ macros when available, which match the
 *       machdep ABI exactly (e.g. __int64_t is `long` on LP64), otherwise from
 *       <stdint.h>. Identical re-typedefs are valid C11.
 */

#ifndef FRAMAC_COMPAT_TYPES_H
#define FRAMAC_COMPAT_TYPES_H

#if defined(__FRAMAC__)

#ifndef _Float32
#define _Float32 float
#endif
#ifndef _Float64
#define _Float64 double
#endif
#ifndef _Float32x
#define _Float32x double
#endif
#ifndef _Float64x
#define _Float64x double
#endif
#ifndef _Float128
#define _Float128 double
#endif

#if defined(__FRAMAC_EACSL__)

#include <stdint.h>
#include <sys/types.h>

#else /* Frama-C __fc_libc */

#include <stdint.h>
#include <sys/types.h>

#ifndef __FC_COMPAT_INT_TYPES_DEFINED
#define __FC_COMPAT_INT_TYPES_DEFINED 1
#ifndef __GLIBC_INTERNAL_INT_TYPES_DEFINED
#define __GLIBC_INTERNAL_INT_TYPES_DEFINED 1
#endif
#if defined(__INT8_TYPE__) && defined(__UINT8_TYPE__) && defined(__INT16_TYPE__) && defined(__UINT16_TYPE__) \
    && defined(__INT32_TYPE__) && defined(__UINT32_TYPE__) && defined(__INT64_TYPE__) && defined(__UINT64_TYPE__)
typedef __INT8_TYPE__ __int8_t;
typedef __UINT8_TYPE__ __uint8_t;
typedef __INT16_TYPE__ __int16_t;
typedef __UINT16_TYPE__ __uint16_t;
typedef __INT32_TYPE__ __int32_t;
typedef __UINT32_TYPE__ __uint32_t;
typedef __INT64_TYPE__ __int64_t;
typedef __UINT64_TYPE__ __uint64_t;
#else
typedef int8_t __int8_t;
typedef uint8_t __uint8_t;
typedef int16_t __int16_t;
typedef uint16_t __uint16_t;
typedef int32_t __int32_t;
typedef uint32_t __uint32_t;
typedef int64_t __int64_t;
typedef uint64_t __uint64_t;
#endif
#endif /* __FC_COMPAT_INT_TYPES_DEFINED */

#ifndef __FC_COMPAT_BSD_ALIASES_DEFINED
#define __FC_COMPAT_BSD_ALIASES_DEFINED 1
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;
#endif /* __FC_COMPAT_BSD_ALIASES_DEFINED */

#endif /* __FRAMAC_EACSL__ */

#if defined(__has_include)
#if __has_include("../acsl/acsl_vocabulary.h")
#include "../acsl/acsl_vocabulary.h"
#elif __has_include(<acsl_vocabulary.h>)
#include <acsl_vocabulary.h>
#endif
#else
#include "../acsl/acsl_vocabulary.h"
#endif

#endif /* __FRAMAC__ */

#endif /* FRAMAC_COMPAT_TYPES_H */
