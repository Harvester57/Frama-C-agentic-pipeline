/* A minimal inotify watcher, the pattern of programs that reload their
   configuration when a file changes. gcc with glibc compiles it; Frama-C
   stops at the include, since share/libc has no sys/inotify.h. */
#include <sys/inotify.h>
#include <unistd.h>

int main(void)
{
  int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  if (fd == -1)
    return 1;
  int wd = inotify_add_watch(fd, "/etc/resolv.conf",
                             IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF);
  if (wd != -1)
    inotify_rm_watch(fd, wd);
  close(fd);
  return (int)sizeof(struct inotify_event) != 16;
}
