/*
 * <link.h> for Frama-C: the dynamic linker's object list (dl_iterate_phdr, struct dl_phdr_info,
 * struct link_map, struct r_debug), Eva / WP and the E-ACSL frontend alike.
 *
 * Frama-C's libc has no <link.h> (34.0~beta). glibc's resolves through the `-idirafter` host directories
 * and fails twice, found on sudo (run-1, 2026-11-21), whose lib/util/getentropy.c includes it when
 * configure finds dl_iterate_phdr:
 *   - glibc's <link.h> always includes <bits/link.h>, whose x86_64 audit types are GCC vector types
 *     (`typedef float La_x86_64_xmm __attribute__ ((__vector_size__ (16)));`), and Frama-C stops on each:
 *     "bits/link.h:68: User Error: Unsupported attribute: __vector_size__";
 *   - struct dl_phdr_info and dl_iterate_phdr are declared under __USE_GNU, which __fc_libc's <features.h>
 *     never defines, so `info->dlpi_addr` was "Cannot find field dlpi_addr in type struct dl_phdr_info".
 * Both happen in the E-ACSL frontend too (glibc's own headers there, the same Frama-C parser: "bits/link.h:97:
 * syntax error"), so every Frama-C parse gets the declarations of fc_link.h, which name no __fc_libc model
 * object. A compile without __FRAMAC__ (gcc, clang, the sanitizer builds) gets glibc's header unchanged.
 *
 * The declarations are in fc_link.h rather than here: `stub_check.py shipped` compiles this file's
 * structures against glibc's <link.h> without _GNU_SOURCE, where struct dl_phdr_info is incomplete, and
 * without __FRAMAC__, where this file is glibc's header anyway. tests/test_fc_glibc_gaps.py compares the
 * layouts with glibc's under _GNU_SOURCE instead.
 */

#ifndef FC_STUBS_LINK_H
#define FC_STUBS_LINK_H

#if defined(__FRAMAC__)

#include "fc_link.h"

#else /* no Frama-C: glibc's header */

#include_next <link.h>

#endif /* __FRAMAC__ */

#endif /* FC_STUBS_LINK_H */
