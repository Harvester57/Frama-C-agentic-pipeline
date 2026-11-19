/*
 * <sys/inotify.h> for Frama-C: Linux's inotify interface, with ACSL contracts (Eva / WP).
 *
 * Frama-C's libc has no <sys/inotify.h> (34.0~beta, and master on 2026-11-18). Without this header
 * glibc's own resolves through the `-idirafter` host directories that augment_framac_cppflags() appends,
 * and Frama-C stops on it: `char name __flexarr;`
 * (c-ares run-1 lost Eva and WP on its whole library).
 *
 * Eva / WP: the header proposed upstream in pub/frama-c!56 (issue #2828), taken from
 * docs/upstream/frama-c/patches/39-libc-linux-header-gaps.patch. From __BEGIN_DECLS to __END_DECLS the
 * text is the patch's, line for line; tests/test_fc_stub_repairs.py compares the two, so change both
 * together. What differs from the patch: no licence banner, `<...>` includes where the patch has the
 * libc-relative `"../..."`, and no __PUSH_FC_STDLIB / __POP_FC_STDLIB (this is not a libc file).
 * Declared, as in the patch: inotify_init, inotify_init1, inotify_add_watch, inotify_rm_watch.
 * glibc's header declares no other function.
 * The functions are declared here, so stub_gen.py classifies them `pipeline_stub` and writes no block
 * for them in a run's stub overlay.
 * Frama-C puts its own libc directory before this one: when a release ships <sys/inotify.h>, that header
 * is read and this file no longer is.
 *
 * E-ACSL (host headers) and any compile without __FRAMAC__ get glibc's header unchanged: the contracts
 * name libc model objects (__FC_MAX_OPEN_FILES, Frama_C_entropy_source) that exist only in Frama-C's libc.
 */

#ifndef FC_STUBS_SYS_INOTIFY_H
#define FC_STUBS_SYS_INOTIFY_H

#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)

#include <features.h>
#include <stdint.h>
__BEGIN_DECLS

#include <__fc_define_max_open_files.h>
#include <__fc_string_axiomatic.h>
#include <errno.h>

struct inotify_event {
  int wd;
  uint32_t mask;
  uint32_t cookie;
  uint32_t len; // size of name, including the terminating null bytes
  char name[];
};

// The values used below are based on Linux.
#define IN_ACCESS 0x00000001
#define IN_MODIFY 0x00000002
#define IN_ATTRIB 0x00000004
#define IN_CLOSE_WRITE 0x00000008
#define IN_CLOSE_NOWRITE 0x00000010
#define IN_CLOSE (IN_CLOSE_WRITE | IN_CLOSE_NOWRITE)
#define IN_OPEN 0x00000020
#define IN_MOVED_FROM 0x00000040
#define IN_MOVED_TO 0x00000080
#define IN_MOVE (IN_MOVED_FROM | IN_MOVED_TO)
#define IN_CREATE 0x00000100
#define IN_DELETE 0x00000200
#define IN_DELETE_SELF 0x00000400
#define IN_MOVE_SELF 0x00000800
#define IN_UNMOUNT 0x00002000
#define IN_Q_OVERFLOW 0x00004000
#define IN_IGNORED 0x00008000
#define IN_ONLYDIR 0x01000000
#define IN_DONT_FOLLOW 0x02000000
#define IN_EXCL_UNLINK 0x04000000
#define IN_MASK_CREATE 0x10000000
#define IN_MASK_ADD 0x20000000
#define IN_ISDIR 0x40000000
#define IN_ONESHOT 0x80000000
#define IN_ALL_EVENTS                                                    \
  (IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE \
   | IN_OPEN | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE       \
   | IN_DELETE_SELF | IN_MOVE_SELF)

// Flags for inotify_init1; same values as O_CLOEXEC and O_NONBLOCK
#define IN_CLOEXEC 0x80000
#define IN_NONBLOCK 0x800

/*@
  assigns \result, errno \from \nothing;
  ensures valid_fd_or_error: \result == -1 || 0 <= \result < __FC_MAX_OPEN_FILES;
*/
extern int inotify_init(void);

/*@
  assigns \result, errno \from indirect:flags;
  ensures valid_fd_or_error: \result == -1 || 0 <= \result < __FC_MAX_OPEN_FILES;
*/
extern int inotify_init1(int flags);

/*@
  requires valid_fd: 0 <= fd < __FC_MAX_OPEN_FILES;
  requires valid_pathname: valid_read_string(pathname);
  //missing: assigns 'watch list of fd' \from pathname[0 ..], mask;
  assigns \result, errno \from indirect:fd, indirect:pathname[0 ..],
                               indirect:mask;
  ensures watch_descriptor_or_error: \result == -1 || \result >= 0;
*/
extern int inotify_add_watch(int fd, const char *pathname, uint32_t mask);

/*@
  requires valid_fd: 0 <= fd < __FC_MAX_OPEN_FILES;
  //missing: assigns 'watch list of fd' \from wd;
  assigns \result, errno \from indirect:fd, indirect:wd;
  ensures result_ok_or_error: \result == 0 || \result == -1;
*/
extern int inotify_rm_watch(int fd, int wd);

__END_DECLS

#else /* E-ACSL (host headers), or no Frama-C at all: glibc's header */

#include_next <sys/inotify.h>

#endif /* Eva / WP */

#endif /* FC_STUBS_SYS_INOTIFY_H */
