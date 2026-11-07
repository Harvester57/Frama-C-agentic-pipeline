#include <string.h>

#include "cursor.h"

/* Generates a big-endian reader read_<name> for an unsigned type. */
#define DEFINE_READER(name, type)                                   \
    int read_##name(struct cursor *c, type *out)                    \
    {                                                               \
        type v = 0;                                                 \
        size_t i;                                                   \
        if (c->len - c->pos < sizeof(type))                         \
            return -1;                                              \
        for (i = 0; i < sizeof(type); i++)                          \
            v = (type)((v << 8) | c->p[c->pos + i]);                \
        c->pos += sizeof(type);                                     \
        *out = v;                                                   \
        return 0;                                                   \
    }

/* Generates a reader for a u8-length-prefixed string of at most `cap` bytes. */
#define DEFINE_STR_READER(name, cap)                                \
    int read_##name(struct cursor *c, char *out)                    \
    {                                                               \
        uint8_t n;                                                  \
        if (read_u8(c, &n) != 0)                                    \
            return -1;                                              \
        if (n > (cap) || c->len - c->pos < n)                       \
            return -1;                                              \
        memcpy(out, c->p + c->pos, n); out[n] = '\0';               \
        c->pos += n;                                                \
        return (int)n;                                              \
    }

DEFINE_READER(u8, uint8_t)
DEFINE_READER(u16, uint16_t)
DEFINE_READER(u32, uint32_t)

DEFINE_STR_READER(label, LABEL_MAX)
