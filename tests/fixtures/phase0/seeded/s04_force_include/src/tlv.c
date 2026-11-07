#include <string.h>

#include "tlv.h"
#include "tlv_limits.h"
#include "bytes.h"

enum { T_NAME = 1, T_ID = 2, T_FLAGS = 3 };

int tlv_parse(const uint8_t *buf, size_t len)
{
    char name[TLV_NAME_BUF];
    size_t pos = 0;
    int records = 0;

    while (pos < len) {
        uint8_t type, l;
        const uint8_t *v;

        if (len - pos < 2)
            return -1;
        type = buf[pos];
        l = buf[pos + 1];
        pos += 2;
        if (l > len - pos)
            return -1;
        v = buf + pos;
        switch (type) {
        case T_NAME:
            if (l == 0 || l > TLV_NAME_MAX || !all_printable(v, l))
                return -1;
            memcpy(name, v, l); name[l] = '\0';
            if (strcmp(name, "#reserved") == 0)
                return -1;
            break;
        case T_ID:
            if (l != 2 || be16_at(pos, buf, len) == 0)
                return -1;
            break;
        case T_FLAGS:
            if (l != 1)
                return -1;
            break;
        default:
            break;
        }
        pos += l;
        records++;
    }
    return records;
}

size_t tlv_get_name(uint8_t *out, size_t cap, const uint8_t *in, size_t len)
{
    size_t pos = 0;

    while (len - pos >= 2) {
        uint8_t type = in[pos], l = in[pos + 1];
        pos += 2;
        if (l > len - pos)
            return 0;
        if (type == T_NAME) {
            size_t n = l < cap ? l : cap;
            memcpy(out, in + pos, n);
            return n;
        }
        pos += l;
    }
    return 0;
}

long tlv_get_id(const uint8_t *buf, size_t len)
{
    size_t pos = 0;

    while (len - pos >= 2) {
        uint8_t type = buf[pos], l = buf[pos + 1];
        pos += 2;
        if (l > len - pos)
            return -1;
        if (type == T_ID && l == 2)
            return be16_at(pos, buf, len);
        pos += l;
    }
    return -1;
}
