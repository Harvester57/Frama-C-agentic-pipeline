#ifndef TLV_H
#define TLV_H

#include <stddef.h>
#include <stdint.h>

struct tlv_stats {
    unsigned long count;        /* elements seen */
    unsigned long constructed;  /* elements containing nested elements */
    unsigned long bytes;        /* primitive payload bytes */
    int max_depth;
};

/* Walks a buffer of [tag][len be16][value] elements; tags with bit 0x20
 * set contain nested elements. Returns 0 or -1 on malformed input. */
int tlv_walk(const uint8_t *buf, size_t n, struct tlv_stats *st);

const char *tlv_version(void);

#endif
