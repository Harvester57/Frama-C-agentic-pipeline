/* L5_sanitized, emit/bytes: every byte handed to a network sink with a length is initialized. */
#include <stddef.h>

void send_bytes(const unsigned char *buf, size_t n);

void emit(unsigned char v)
{
    unsigned char b[2];
    b[0] = v;
#ifndef VIOLATE
    b[1] = v; /* VIOLATE leaves b[1] uninitialized */
#endif
    send_bytes(b, 2);
}
