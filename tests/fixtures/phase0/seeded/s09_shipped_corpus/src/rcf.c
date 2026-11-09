#include "rcf.h"

#include <string.h>

static const uint32_t rcf_scale[RCF_SCALES] = {1, 10, 100, 1000, 10000, 100000};

struct rcf_info {
    unsigned flags;
    unsigned recs;
    char name[RCF_NAME_MAX + 1];
    uint64_t value;
};

static int rec_scale(struct rcf_info *info, const uint8_t *p)
{
    unsigned idx = p[0];
    uint64_t mant = (uint64_t)(p[1] | (p[2] << 8));
    if (idx > RCF_SCALES)
        return -1;
    info->value = mant * rcf_scale[idx];
    return 0;
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint32_t rcf_crc32(const uint8_t *buf, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return crc ^ 0xFFFFFFFFu;
}

int rcf_parse(const uint8_t *buf, size_t len)
{
    struct rcf_info info;
    const uint8_t *p, *end;
    unsigned count;

    memset(&info, 0, sizeof info);
    if (buf == NULL || len < RCF_HDR_LEN)
        return -1;
    if (rd32(buf) != RCF_MAGIC)
        return -1;
    if ((rcf_crc32(buf, RCF_HDR_LEN - 4) ^ rd32(buf + 8)) != 0)
        return -1;
    if (buf[4] != RCF_VERSION)
        return -1;
    count = buf[5];
    if (count == 0 || count > RCF_MAX_REC)
        return -1;
    info.flags = buf[6];
    p = buf + RCF_HDR_LEN;
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
        case RCF_REC_NAME:
            if (l == 0 || l > RCF_NAME_MAX)
                return -1;
            memcpy(info.name, p, l);
            break;
        case RCF_REC_VALUE:
            if (l != 4)
                return -1;
            info.value = rd32(p);
            break;
        case RCF_REC_SCALE:
            if (l != 3 || rec_scale(&info, p) != 0)
                return -1;
            break;
        default:
            return -1;
        }
        p += l;
        info.recs++;
    }
    return (int)info.recs;
}
