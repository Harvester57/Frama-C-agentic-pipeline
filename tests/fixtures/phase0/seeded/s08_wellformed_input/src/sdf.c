#include "sdf.h"

#include <string.h>

struct sdf_info {
    unsigned flags;
    unsigned exts;
    char name[SDF_NAME_BUF + 1];
    uint32_t value;
    uint8_t unit;
};

static int ext_name(struct sdf_info *info, const uint8_t *p, size_t l)
{
    char name[SDF_NAME_BUF];
    if (l > SDF_NAME_MAX)
        return -1;
    memcpy(name, p, l);
    memcpy(info->name, name, l < SDF_NAME_BUF ? l : SDF_NAME_BUF);
    return 0;
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint16_t sdf_checksum(const uint8_t *buf, size_t len)
{
    uint16_t s1 = 0, s2 = 0;
    for (size_t i = 0; i < len; i++) {
        s1 = (uint16_t)((s1 + buf[i]) % 255);
        s2 = (uint16_t)((s2 + s1) % 255);
    }
    return (uint16_t)((s2 << 8) | s1);
}

int sdf_parse(const uint8_t *buf, size_t len)
{
    struct sdf_info info;
    const uint8_t *p, *end;
    unsigned count;

    memset(&info, 0, sizeof info);
    if (buf == NULL || len < SDF_HDR_LEN)
        return -1;
    if (rd32(buf) != SDF_MAGIC)
        return -1;
    if ((uint16_t)(sdf_checksum(buf, SDF_HDR_LEN - 2) ^ rd16(buf + 10)) != 0)
        return -1;
    if (buf[4] != SDF_VERSION)
        return -1;
    info.flags = buf[5];
    count = buf[6];
    if (count == 0 || count > SDF_MAX_EXT)
        return -1;
    p = buf + SDF_HDR_LEN;
    end = buf + len;
    for (unsigned i = 0; i < count; i++) {
        uint8_t type, l;
        if (end - p < 2)
            return -1;
        type = p[0];
        l = p[1];
        p += 2;
        if ((size_t)(end - p) < l)
            return -1;
        switch (type) {
        case SDF_EXT_NAME:
            if (ext_name(&info, p, l) != 0)
                return -1;
            break;
        case SDF_EXT_VALUE:
            if (l != 4)
                return -1;
            info.value = rd32(p);
            break;
        case SDF_EXT_UNIT:
            if (l != 1)
                return -1;
            info.unit = p[0];
            break;
        default:
            return -1;
        }
        p += l;
        info.exts++;
    }
    return (int)info.exts;
}
