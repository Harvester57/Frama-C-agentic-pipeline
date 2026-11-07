/* Internal definitions; found only through -iquote src/internal. */
#ifndef TLVDEFS_H
#define TLVDEFS_H

#include <stdint.h>

#define TLV_HDR_LEN 3u
#define TLV_TAG_CONSTRUCTED 0x20u

struct tlv_hdr {
    uint8_t tag;
    uint16_t len;
};

#endif
