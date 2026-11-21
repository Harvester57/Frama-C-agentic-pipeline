/**************************************************************************/
/*                                                                        */
/*  SPDX-License-Identifier LGPL-2.1                                      */
/*  Copyright (C)                                                         */
/*  CEA (Commissariat à l'énergie atomique et aux énergies alternatives)  */
/*                                                                        */
/**************************************************************************/

/*
 * Frama-C 34.0~beta's <grp.h> with glibc's `struct group`; nothing else changed. Read in its place because
 * scripts/fc_cpp_wrapper.py puts this directory (templates/fc_stubs/fc_libc) on the include path right
 * before __fc_libc's, in every Frama-C preprocessing that reads __fc_libc (Eva, WP, the Phase 0 model);
 * the E-ACSL frontend reads glibc's header.
 *
 * Found on sudo (run-1, 2026-11-21): plugins/group_file/getgrent.c:128 `gr.gr_passwd = cp;` stopped the
 * parse with "Cannot find field gr_passwd in type struct group" (also plugins/sudoers/pwutil_impl.c:183,
 * cvtsudoers_pwutil.c:227). __fc_libc's struct has gr_name, gr_gid and gr_mem only: POSIX requires no more,
 * but glibc, musl and the BSDs all have gr_passwd, and __fc_libc's struct passwd has pw_passwd. The members
 * are glibc's, in glibc's order (layout checked against glibc by tests/test_fc_glibc_gaps.py); the guard,
 * the includes and the contracts are __fc_libc's, so Eva and WP read the same frames as before.
 * The declarations are marked as __fc_libc's <grp.h> (`fc_stdlib`) under that name.
 */

#ifndef __FC_GRP_H
#define __FC_GRP_H
#include "features.h"
__PRAGMA_PUSH("grp.h")
#include "__fc_define_uid_and_gid.h"
#include "__fc_define_size_t.h"
#include <errno.h>

__BEGIN_DECLS

struct group {
  char   *gr_name;
  char   *gr_passwd;
  gid_t   gr_gid;
  char  **gr_mem;
};

volatile struct group __fc_grp;

/*@
  //missing: assigns <all below> \from 'group database';
  assigns \result \from indirect:gid, &__fc_grp;
  assigns errno \from indirect:gid;
*/
extern struct group *getgrgid(gid_t gid);

/*@
  //missing: assigns <all below> \from 'group database';
  assigns \result \from indirect:name[0..], &__fc_grp;
  assigns errno \from indirect:name[0..];
*/
extern struct group *getgrnam(const char *name);

/*@
  //missing: assigns <all below> \from 'group database';
  assigns \result \from indirect:gid, indirect:bufsize;
  assigns *grp \from gid, indirect:bufsize;
  assigns buffer[0 .. bufsize-1] \from gid, indirect:bufsize;
  assigns *result \from grp;
  assigns errno \from indirect:gid, indirect:bufsize;
*/
extern int getgrgid_r(gid_t gid, struct group *grp, char *buffer,
                      size_t bufsize, struct group **result);

/*@
  //missing: assigns <all below> \from 'group database';
  assigns \result \from indirect:name[0..], indirect:bufsize;
  assigns *grp \from name[0..], indirect:bufsize;
  assigns buffer[0 .. bufsize-1] \from name[0..], indirect:bufsize;
  assigns *result \from grp;
  assigns errno \from indirect:name[0..], indirect:bufsize;
*/
extern int getgrnam_r(const char *name, struct group *grp, char *buffer,
                      size_t bufsize, struct group **result);

/*@
  //missing: assigns <all below> \from 'group database';
  assigns \result \from &__fc_grp;
  assigns errno \from indirect:__fc_grp;
*/
extern struct group *getgrent(void);

/*@
  //missing: assigns <all below> \from 'group database';
  assigns errno \from indirect:__fc_grp;
*/
extern void endgrent(void);

/*@
  //missing: assigns <all below> \from 'group database';
  assigns errno \from indirect:__fc_grp;
*/
extern void setgrent(void);

/* BSD function */
/*@
  // missing: ... \from groups database
  assigns \result \from indirect:user[0..], indirect:group, indirect:*ngroups;
  assigns groups[0 .. \old(*ngroups) - 1], *ngroups
          \from indirect:user[0..], group, *ngroups;
*/
extern int getgrouplist(const char *user, gid_t group,
                        gid_t *groups, int *ngroups);

/*@
  //missing: assigns <all below> \from 'group database';
  assigns \result \from indirect:user[0..], indirect:group;
  assigns errno \from indirect:user[0..], indirect:group;
*/
extern int initgroups(const char *user, gid_t group);

__END_DECLS

__POP_FC_STDLIB
#endif
