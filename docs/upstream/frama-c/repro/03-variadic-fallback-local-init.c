#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
  (void)argc;
  int fd = open(argv[0], O_RDONLY);
  int fl = fcntl(fd, F_GETFL);
  close(fd);
  return fl < 0;
}
