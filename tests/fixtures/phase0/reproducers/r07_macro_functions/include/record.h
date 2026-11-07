#ifndef RECORD_H
#define RECORD_H

#include <stddef.h>
#include <stdint.h>

/* X-macro listing the header fields of a record, in wire order. */
#define RECORD_FIELDS(X) \
    X(uint8_t,  version) \
    X(uint16_t, flags)   \
    X(uint32_t, length)  \
    X(uint32_t, seq)

#define REC_DECLARE_FIELD(T, name) T name;

struct record {
    RECORD_FIELDS(REC_DECLARE_FIELD)
    const uint8_t *payload;
};

/* Public accessors: uint8_t rec_get_version(const struct record *), ... */
#define REC_DECLARE_GETTER(T, name) T rec_get_##name(const struct record *r);
RECORD_FIELDS(REC_DECLARE_GETTER)

/* Wire: [0x52][version][flags be16][length be32][seq be32][payload].
 * Returns bytes consumed or -1. */
int rec_decode(const uint8_t *buf, size_t n, struct record *rec);

void rec_set_verbose(int on);

#endif
