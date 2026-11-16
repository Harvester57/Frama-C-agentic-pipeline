#ifndef EPOLL_STUB_H
#define EPOLL_STUB_H
/* Copied from the c-ares run-1 overlay (workspace/stubs/sys/epoll.h:91): no \from on the events range. */
struct epoll_event {
    unsigned int events;
    unsigned long data;
};

/*@
  requires positive_maxevents: __maxevents > 0;
  requires writable_events: \valid(__events + (0 .. __maxevents - 1));
  terminates \true;
  exits \false;
  assigns __events[0 .. __maxevents - 1], \result;
  ensures result_count_or_error: \result >= 0 || \result == -1;
  ensures result_at_most_maxevents: \result <= __maxevents;
  ensures events_initialized: \initialized(__events + (0 .. \result - 1));
*/
extern int epoll_wait(int __epfd, struct epoll_event *__events, int __maxevents, int __timeout);

/* A second spec-only stub without \from, called twice. */
/*@ assigns *out; */
void fill_two(int *out);
#endif
