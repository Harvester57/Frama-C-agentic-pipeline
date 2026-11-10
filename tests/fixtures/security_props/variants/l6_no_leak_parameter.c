/* L6_no_leak, calling, parameter secret: derive never hands key to the sink. */
#include <stddef.h>

void net_send(int fd, const unsigned char *buf, size_t n);

/*@ requires 1 <= len && \valid_read(key + (0 .. len - 1)); */
void derive(const unsigned char *key, size_t len, int fd)
{
    unsigned char hdr[2];
    hdr[0] = 1;
    hdr[1] = 2;
#ifdef VIOLATE
    net_send(fd, key, len); /* leak */
#else
    net_send(fd, hdr, 2);
#endif
}
