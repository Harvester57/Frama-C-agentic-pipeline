/*
 * <sys/epoll.h> for Frama-C: Linux's epoll interface, with ACSL contracts (Eva / WP).
 *
 * Frama-C's libc has no <sys/epoll.h> (34.0~beta, and master on 2026-11-18). Without this header
 * glibc's own resolves through the `-idirafter` host directories that augment_framac_cppflags() appends,
 * and Frama-C stops on it: `__attr_access`, `__sigset_t`, a second `struct timespec`
 * (c-ares run-1 lost Eva and WP on its whole library).
 *
 * Eva / WP: the header proposed upstream in pub/frama-c!56 (issue #2828), taken from
 * docs/upstream/frama-c/patches/39-libc-linux-header-gaps.patch. From __BEGIN_DECLS to __END_DECLS the
 * text is the patch's, line for line, except the lines marked `pipeline addition`;
 * tests/test_fc_stub_repairs.py compares the two, so change both together. What differs from the patch:
 * no licence banner, `<...>` includes where the patch has the libc-relative `"../..."`, and no
 * __PUSH_FC_STDLIB / __POP_FC_STDLIB (this is not a libc file).
 * Pipeline addition: `ensures result_bounded` on epoll_wait and epoll_pwait. The patch states the result
 * only inside the `full` / `partial_timeout_or_error` behaviors, whose `assumes` read the volatile
 * Frama_C_entropy_source. WP gives each read of a volatile its own value, so it can assume neither
 * behavior and knew nothing about the result (the same holds for libc's read()): a caller could not
 * prove `n <= maxevents`, which the index of `events[i]` in an event loop needs.
 * Declared, as in the patch: epoll_create, epoll_create1, epoll_ctl, epoll_wait, epoll_pwait.
 * Not declared: glibc's epoll_pwait2, and struct epoll_params with its EPIOCGPARAMS, EPIOCSPARAMS and
 * EPOLL_IOC_TYPE (every other name of glibc 2.41's header is here). Add them, with a contract, when a
 * target uses them (README rule 5).
 * The functions are declared here, so stub_gen.py classifies them `pipeline_stub` and writes no block
 * for them in a run's stub overlay.
 * Frama-C puts its own libc directory before this one: when a release ships <sys/epoll.h>, that header
 * is read and this file no longer is, and `result_bounded` goes with it unless the release has it.
 *
 * E-ACSL (host headers) and any compile without __FRAMAC__ get glibc's header unchanged: the contracts
 * name libc model objects (__FC_MAX_OPEN_FILES, Frama_C_entropy_source) that exist only in Frama-C's libc.
 */

#ifndef FC_STUBS_SYS_EPOLL_H
#define FC_STUBS_SYS_EPOLL_H

#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)

#include <features.h>
#include <stdint.h>
#include <signal.h>
__BEGIN_DECLS

#include <__fc_define_max_open_files.h>

extern volatile int Frama_C_entropy_source;

// The values used below are based on Linux.
#define EPOLLIN 0x001
#define EPOLLPRI 0x002
#define EPOLLOUT 0x004
#define EPOLLERR 0x008
#define EPOLLHUP 0x010
#define EPOLLRDNORM 0x040
#define EPOLLRDBAND 0x080
#define EPOLLWRNORM 0x100
#define EPOLLWRBAND 0x200
#define EPOLLMSG 0x400
#define EPOLLRDHUP 0x2000
#define EPOLLEXCLUSIVE (1u << 28)
#define EPOLLWAKEUP (1u << 29)
#define EPOLLONESHOT (1u << 30)
#define EPOLLET (1u << 31)

// Same value as O_CLOEXEC
#define EPOLL_CLOEXEC 0x80000

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

typedef union epoll_data {
  void *ptr;
  int fd;
  uint32_t u32;
  uint64_t u64;
} epoll_data_t;

// On x86_64, Linux packs this structure (12 bytes instead of 16).
struct epoll_event {
  uint32_t events;
  epoll_data_t data;
}
#ifdef __x86_64__
  __attribute__((__packed__))
#endif
  ;

/*@
  requires valid_size: size > 0;
  assigns \result \from indirect:size;
  ensures valid_fd_or_error: \result == -1 || 0 <= \result < __FC_MAX_OPEN_FILES;
*/
extern int epoll_create(int size);

/*@
  assigns \result \from indirect:flags;
  ensures valid_fd_or_error: \result == -1 || 0 <= \result < __FC_MAX_OPEN_FILES;
*/
extern int epoll_create1(int flags);

/*@
  requires valid_epfd: 0 <= epfd < __FC_MAX_OPEN_FILES;
  requires valid_fd: 0 <= fd < __FC_MAX_OPEN_FILES;
  requires valid_op:
    op == EPOLL_CTL_ADD || op == EPOLL_CTL_DEL || op == EPOLL_CTL_MOD;
  requires valid_event: op == EPOLL_CTL_DEL || \valid_read(event);
  //missing: assigns 'interest list of epfd' \from fd, op, event->events, event->data;
  assigns \result \from indirect:epfd, indirect:op, indirect:fd,
                        indirect:Frama_C_entropy_source;
  ensures result_ok_or_error: \result == 0 || \result == -1;
*/
extern int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

/*@
  requires valid_epfd: 0 <= epfd < __FC_MAX_OPEN_FILES;
  requires valid_maxevents: maxevents > 0;
  requires valid_events: \valid(events + (0 .. maxevents - 1));
  assigns \result \from indirect:epfd, indirect:maxevents, indirect:timeout,
                        indirect:Frama_C_entropy_source;
  assigns events[0 .. maxevents - 1]
    \from indirect:epfd, indirect:maxevents, indirect:timeout,
          indirect:Frama_C_entropy_source;
  ensures result_bounded: -1 <= \result <= maxevents; // pipeline addition (not in !56)
  behavior full:
    assumes nondet_full: Frama_C_entropy_source != 0;
    ensures result_full: \result == maxevents;
    ensures initialization:events: \initialized(events + (0 .. maxevents - 1));
  behavior partial_timeout_or_error:
    assumes nondet_partial: Frama_C_entropy_source == 0;
    ensures error_timeout_or_bounded: -1 <= \result < maxevents;
    ensures initialization:events: \initialized(events + (0 .. \result - 1));
    //note: for \result <= 0, the above range is empty, as intended
  disjoint behaviors;
  complete behaviors;
*/
extern int epoll_wait(int epfd, struct epoll_event *events,
                      int maxevents, int timeout);

/*@
  requires valid_epfd: 0 <= epfd < __FC_MAX_OPEN_FILES;
  requires valid_maxevents: maxevents > 0;
  requires valid_events: \valid(events + (0 .. maxevents - 1));
  requires valid_sigmask_or_null: sigmask == \null || \valid_read(sigmask);
  assigns \result \from indirect:epfd, indirect:maxevents, indirect:timeout,
                        indirect:sigmask, indirect:Frama_C_entropy_source;
  assigns events[0 .. maxevents - 1]
    \from indirect:epfd, indirect:maxevents, indirect:timeout,
          indirect:sigmask, indirect:Frama_C_entropy_source;
  ensures result_bounded: -1 <= \result <= maxevents; // pipeline addition (not in !56)
  behavior full:
    assumes nondet_full: Frama_C_entropy_source != 0;
    ensures result_full: \result == maxevents;
    ensures initialization:events: \initialized(events + (0 .. maxevents - 1));
  behavior partial_timeout_or_error:
    assumes nondet_partial: Frama_C_entropy_source == 0;
    ensures error_timeout_or_bounded: -1 <= \result < maxevents;
    ensures initialization:events: \initialized(events + (0 .. \result - 1));
  disjoint behaviors;
  complete behaviors;
*/
extern int epoll_pwait(int epfd, struct epoll_event *events,
                       int maxevents, int timeout, const sigset_t *sigmask);

__END_DECLS

#else /* E-ACSL (host headers), or no Frama-C at all: glibc's header */

#include_next <sys/epoll.h>

#endif /* Eva / WP */

#endif /* FC_STUBS_SYS_EPOLL_H */
