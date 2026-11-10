/*
 * errno for E-ACSL builds only.
 *
 * glibc's errno is `(*__errno_location())`, which lives in libc.so's TLS block. The E-ACSL runtime
 * shadows only the executable's own TLS block, so every `errno = ...` in instrumented code aborts
 * in the runtime ("Use of invalid address ... in unsafe_initialize") before any target bug can
 * show, and registering the address (`__e_acsl_store_block(__errno_location(), sizeof(int))`)
 * crashes in shadow_alloca instead. Under __FRAMAC_EACSL__, errno therefore becomes an ordinary
 * global that E-ACSL tracks.
 *
 * libc never writes that global itself. The build links a generated errno shim
 * (`<out>_errno_shim/eacsl_errno_shim.o`, `-Wl,--wrap=<fn>`) for the errno-setting libc
 * functions the slice calls (eacsl_toolchain.ERRNO_SHIM_FUNCTIONS): each wrapper hands the global
 * to libc before the call and copies libc's errno back after it, and the Variadic fallbacks do the
 * same. The build result lists them in `errno_shim`. After any other libc call the target still
 * reads the last value it (or a wrapped call) wrote; the global is shared across threads.
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
