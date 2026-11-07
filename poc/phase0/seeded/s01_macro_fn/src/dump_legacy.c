/*
 * Hex dump used by the v0 record tool. Kept for reference; it is no
 * longer part of the library (see Makefile: LIB_OBJS).
 */
#include "rec.h"

static const char hexdig[] = "0123456789abcdef";

int rec_dump_legacy(const uint8_t *buf, size_t len)
{
    char line[48];
    size_t i, o = 0;

    for (i = 0; i < len; i++) {
        line[o++] = hexdig[buf[i] >> 4];
        line[o++] = hexdig[buf[i] & 0xF];
        line[o++] = ' ';
    }
    line[o] = '\0';
    return (int)o;
}
