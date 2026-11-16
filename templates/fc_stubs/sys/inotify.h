/*
 * <sys/inotify.h>: glibc's header, made parseable by Frama-C (Eva / WP).
 *
 * Frama-C's libc has no <sys/inotify.h>, so the host one resolves through the `-idirafter
 * /usr/include/x86_64-linux-gnu` that augment_framac_cppflags() appends. glibc's header declares
 * `char name __flexarr;` (line 34), and `__flexarr` comes from glibc's <sys/cdefs.h>, which Frama-C's
 * libc never includes: Frama-C stopped with a syntax error (c-ares run-1). For Eva and WP this header
 * defines `__flexarr` as glibc does for C99 (`[]`) when nothing defined it, includes glibc's header,
 * then drops the macro again. Never glibc's <sys/cdefs.h>: it redefines __THROW, __nonnull, ... for
 * every libc header after it.
 *
 * E-ACSL (host headers) and any compile without __FRAMAC__ get glibc's header unchanged.
 * No declarations: inotify_* stay declared in glibc's header (stub_gen.py: host_header), and their
 * contracts go in the run's stub overlay, which #include_next's this header.
 */

#ifndef FC_STUBS_SYS_INOTIFY_H
#define FC_STUBS_SYS_INOTIFY_H

#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)
#ifndef __flexarr
#define __flexarr []
#define FC_STUBS_INOTIFY_FLEXARR
#endif
#endif /* Eva / WP */

#include_next <sys/inotify.h>

#ifdef FC_STUBS_INOTIFY_FLEXARR
#undef __flexarr
#undef FC_STUBS_INOTIFY_FLEXARR
#endif

#endif /* FC_STUBS_SYS_INOTIFY_H */
