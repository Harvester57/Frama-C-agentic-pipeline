/**************************************************************************/
/*                                                                        */
/*  SPDX-License-Identifier LGPL-2.1                                      */
/*  Copyright (C)                                                         */
/*  CEA (Commissariat à l'énergie atomique et aux énergies alternatives)  */
/*                                                                        */
/**************************************************************************/

/*
 * Frama-C 34.0~beta's <utmpx.h> with glibc's `struct utmpx`; nothing else changed. Read in its place because
 * scripts/fc_cpp_wrapper.py puts this directory (templates/fc_stubs/fc_libc) on the include path right
 * before __fc_libc's (see grp.h here).
 *
 * Found on sudo (run-1, 2026-11-21): src/utmp.c:233 `ut_new->ut_exit.e_termination = ...` stopped the parse
 * with "Cannot find field ut_exit in type struct utmpx". __fc_libc's struct has POSIX's members in POSIX's
 * order plus ut_host, ut_addr_v6 and __glibc_reserved, but neither ut_exit nor ut_session. This one is
 * glibc 2.41's x86_64 structure (checked against glibc by tests/test_fc_glibc_gaps.py): ut_session and ut_tv
 * are 32-bit (`__WORDSIZE_TIME64_COMPAT32`), so ut_tv is not a struct timeval, as with glibc; code that
 * builds against glibc builds here. glibc names the members of struct __exit_status e_termination / e_exit
 * under _GNU_SOURCE and __e_termination / __e_exit otherwise; each pair is an anonymous union here, so both
 * spellings work whatever the unit's feature-test macros. The guard, the includes (the constants of
 * __fc_utmp_constants.h: ut_name, ut_time, the entry types) and the contracts are __fc_libc's.
 */

#ifndef __FC_UTMPX_H
#define __FC_UTMPX_H
#include "features.h"
__PRAGMA_PUSH("utmpx.h")

#include "__fc_define_pid_t.h"
#include "__fc_utmp_constants.h"
#include <stdint.h>
#include <sys/time.h>

__BEGIN_DECLS

struct __exit_status {
  union {
    short int e_termination;
    short int __e_termination;
  };
  union {
    short int e_exit;
    short int __e_exit;
  };
};

struct utmpx {
  short int ut_type;
  pid_t ut_pid;
  char ut_line[32];
  char ut_id[4];
  char ut_user[32];
  char ut_host[256];
  struct __exit_status ut_exit;
  int32_t ut_session;
  struct {
    uint32_t tv_sec;
    int32_t tv_usec;
  } ut_tv;
  int32_t ut_addr_v6[4];
  char __glibc_reserved[20];
};

// static storage used by some getter functions
__FC_EXTERN struct utmpx __fc_getx;

/*@
  assigns \result \from &__fc_getx, indirect:__fc_utmp;
  assigns __fc_getx \from __fc_getx, indirect:__fc_utmp;
*/
extern struct utmpx *getutxent (void);

/*@
  assigns __fc_utmp \from __fc_utmp;
*/
extern void setutxent (void);

/*@
  assigns __fc_utmp \from __fc_utmp;
*/
extern void endutxent (void);

/*@
  assigns \result \from &__fc_getx, indirect:__fc_utmp, indirect:*id;
  assigns __fc_getx \from __fc_getx, indirect:__fc_utmp, indirect:*id;
*/
extern struct utmpx *getutxid (const struct utmpx *id);

/*@
  assigns \result \from &__fc_getx, indirect:__fc_utmp, indirect:*line;
  assigns __fc_getx \from __fc_getx, indirect:__fc_utmp, indirect:*line;
*/
extern struct utmpx *getutxline (const struct utmpx *line);

/*@
  assigns __fc_utmp \from __fc_utmp, *utmp_ptr;
  assigns \result \from utmp_ptr;
*/
extern struct utmpx *pututxline (const struct utmpx *utmp_ptr);

__END_DECLS
__POP_FC_STDLIB
#endif
