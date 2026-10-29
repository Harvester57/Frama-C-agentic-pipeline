/*
 * Frama-C Compatibility Primitive Types for -nostdinc (__fc_libc)
 *
 * Provides standard glibc internal primitive type aliases (__int8_t .. __uint64_t)
 * that are absent from Frama-C's __fc_libc headers when -nostdinc is active.
 * Contains typedef declarations only (never C function bodies).
 */

#ifndef FRAMAC_COMPAT_TYPES_H
#define FRAMAC_COMPAT_TYPES_H

#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)
#include <stdint.h>
#include <sys/types.h>

#ifndef __GLIBC_INTERNAL_INT_TYPES_DEFINED
#define __GLIBC_INTERNAL_INT_TYPES_DEFINED 1
typedef int8_t __int8_t;
typedef uint8_t __uint8_t;
typedef int16_t __int16_t;
typedef uint16_t __uint16_t;
typedef int32_t __int32_t;
typedef uint32_t __uint32_t;
typedef int64_t __int64_t;
typedef uint64_t __uint64_t;
#endif

#endif /* defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__) */

#endif /* FRAMAC_COMPAT_TYPES_H */
