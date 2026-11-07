#include "record.h"
#include "log.h"

#define RECORD_MAGIC 0x52u

struct cursor {
    const uint8_t *p;
    size_t n;
    size_t off;
};

static int cursor_need(const struct cursor *c, size_t k)
{
    return (c->n - c->off >= k) ? 0 : -1;
}

/* Generates static big-endian readers read_u8, read_u16, read_u32. */
#define DEFINE_READER(bits)                                               \
    static int read_u##bits(struct cursor *c, uint##bits##_t *out)        \
    {                                                                     \
        uint##bits##_t v = 0;                                             \
        size_t i;                                                         \
        if (cursor_need(c, sizeof v))                                     \
            return -1;                                                    \
        for (i = 0; i < sizeof v; i++)                                    \
            v = (uint##bits##_t)((v << 8) | c->p[c->off + i]);            \
        c->off += sizeof v;                                               \
        *out = v;                                                         \
        return 0;                                                         \
    }

DEFINE_READER(8)
DEFINE_READER(16)
DEFINE_READER(32)

/* A call to read_uN hidden behind token pasting, plus a call to
 * rec_log_fail hidden behind LOG_FAIL. */
#define READ_FIELD(c, rec, bits, name)                  \
    do {                                                \
        if (read_u##bits((c), &(rec)->name))            \
            return LOG_FAIL(#name);                     \
    } while (0)

int rec_decode(const uint8_t *buf, size_t n, struct record *rec)
{
    struct cursor c;
    uint8_t magic;

    c.p = buf;
    c.n = n;
    c.off = 0;
    if (read_u8(&c, &magic))
        return LOG_FAIL("magic");
    if (magic != RECORD_MAGIC)
        return LOG_FAIL("bad magic");
    READ_FIELD(&c, rec, 8, version);
    READ_FIELD(&c, rec, 16, flags);
    READ_FIELD(&c, rec, 32, length);
    READ_FIELD(&c, rec, 32, seq);
    if (rec->length > n - c.off)
        return LOG_FAIL("length");
    rec->payload = buf + c.off;
    return (int)(c.off + rec->length);
}
