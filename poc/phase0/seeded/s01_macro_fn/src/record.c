#include "rec.h"
#include "cursor.h"

#define REC_VERSION 1

static int read_header(struct cursor *c, uint16_t *count)
{
    uint8_t ver;

    if (read_u8(c, &ver) != 0 || ver != REC_VERSION)
        return -1;
    return read_u16(c, count);
}

int rec_parse(const uint8_t *buf, size_t len)
{
    struct cursor c = { buf, len, 0 };
    char label[LABEL_MAX];
    uint16_t count, i, v16;
    uint32_t v32;
    uint8_t type;
    int labels = 0;

    if (read_header(&c, &count) != 0)
        return -1;
    for (i = 0; i < count; i++) {
        if (read_u8(&c, &type) != 0)
            return -1;
        switch (type) {
        case 1:
            if (read_u32(&c, &v32) != 0)
                return -1;
            break;
        case 2:
            if (read_label(&c, label) < 0)
                return -1;
            labels++;
            break;
        case 3:
            if (read_u16(&c, &v16) != 0)
                return -1;
            break;
        default:
            return -1;
        }
    }
    return labels;
}

long rec_sum(const uint8_t *buf, size_t len)
{
    struct cursor c = { buf, len, 0 };
    uint16_t count, i, v16;
    uint32_t v32;
    uint8_t type, skip;
    long sum = 0;

    if (read_header(&c, &count) != 0)
        return -1;
    for (i = 0; i < count; i++) {
        if (read_u8(&c, &type) != 0)
            return -1;
        if (type == 1) {
            if (read_u32(&c, &v32) != 0)
                return -1;
            sum += (long)(v32 & 0xFFu);
        } else if (type == 3) {
            if (read_u16(&c, &v16) != 0)
                return -1;
            sum += v16 & 0xFFu;
        } else if (type == 2) {
            if (read_u8(&c, &skip) != 0 || c.len - c.pos < skip)
                return -1;
            c.pos += skip;
        } else {
            return -1;
        }
    }
    return sum;
}
