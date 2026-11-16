/*
 * <sys/epoll.h>: glibc's header, made parseable by Frama-C (Eva / WP).
 *
 * Frama-C's libc has no <sys/epoll.h>, so the host one resolves through the `-idirafter
 * /usr/include/x86_64-linux-gnu` that augment_framac_cppflags() appends. glibc's header assumes glibc's
 * own <sys/cdefs.h> and <bits/types/...> guards, and Frama-C stopped on it (c-ares run-1):
 *  - `__attr_access ((__write_only__, 2, 3))` (line 139): a glibc cdefs macro Frama-C's <features.h>
 *    does not define (it defines __THROW, __nonnull and __BEGIN_DECLS itself);
 *  - `const __sigset_t *` (epoll_pwait): Frama-C's sigset_t typedef sets `__sigset_t_defined`, the guard
 *    of glibc's <bits/types/sigset_t.h>, so glibc's `#include <bits/types/__sigset_t.h>` is skipped;
 *  - glibc's <bits/types/struct_timespec.h> (guard `_STRUCT_TIMESPEC`) redefines the struct timespec
 *    of Frama-C's <time.h>.
 * For Eva and WP this header defines just those, each under #ifndef (a run's own overlay wrapper may
 * have defined them first), then includes glibc's header. `__sigset_t` is Frama-C's sigset_t, so
 * `epoll_pwait(fd, ev, n, t, &mask)` with a <signal.h> mask type-checks against the libc model.
 * Never glibc's <sys/cdefs.h>: it redefines __THROW, __nonnull, ... for every libc header after it.
 *
 * E-ACSL (host headers) and any compile without __FRAMAC__ get glibc's header unchanged.
 * No declarations: epoll_* stay declared in glibc's header (stub_gen.py: host_header), and their
 * contracts go in the run's stub overlay, which #include_next's this header.
 */

#ifndef FC_STUBS_SYS_EPOLL_H
#define FC_STUBS_SYS_EPOLL_H

#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)
#include <signal.h>
#include <time.h>
#ifndef ____sigset_t_defined
#define ____sigset_t_defined 1
typedef sigset_t __sigset_t;
#endif
#ifndef _STRUCT_TIMESPEC
#define _STRUCT_TIMESPEC 1
#endif
#ifndef __attr_access
#define __attr_access(x)
#define FC_STUBS_EPOLL_ATTR_ACCESS
#endif
#endif /* Eva / WP */

#include_next <sys/epoll.h>

#ifdef FC_STUBS_EPOLL_ATTR_ACCESS
#undef __attr_access
#undef FC_STUBS_EPOLL_ATTR_ACCESS
#endif

#endif /* FC_STUBS_SYS_EPOLL_H */
