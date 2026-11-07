/*
 * errno for E-ACSL builds only.
 *
 * glibc's errno is `(*__errno_location())`, thread-local memory that E-ACSL never registers, so
 * every `errno = ...` in instrumented code aborts in the runtime ("Use of invalid address in
 * unsafe_initialize") before any target bug can show. Under __FRAMAC_EACSL__, errno becomes an
 * ordinary global that E-ACSL tracks. Caveat: errno values set by the real libc are not visible
 * through it; a target that branches on errno after a libc call sees the last value it wrote.
 * Eva and WP (Frama-C's libc) and the sanitizer build see the real <errno.h> unchanged.
 */
#ifndef FC_STUBS_ERRNO_H
#define FC_STUBS_ERRNO_H
#include_next <errno.h>
#ifdef __FRAMAC_EACSL__
int __fc_eacsl_errno; /* tentative definition: one object however many slice files include this */
#undef errno
#define errno __fc_eacsl_errno
#endif
#endif
