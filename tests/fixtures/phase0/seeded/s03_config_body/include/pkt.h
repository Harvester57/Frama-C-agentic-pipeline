#ifndef PKT_H
#define PKT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Framed packets: u8 type, then a body escaped with 0x7D (the byte after
 * 0x7D is XORed with 0x20). Type 0x01 carries a text body, type 0x02 a
 * binary body whose first decoded byte is a channel number below 8.
 */

#define PKT_ESC 0x7D
#define PKT_BODY_MAX 64

/* Unescapes `in` into `out`. Returns the number of bytes written. */
size_t pkt_unescape(uint8_t *out, size_t cap, const uint8_t *in, size_t len);

/* Decodes one packet. Returns the decoded body length, or -1. */
int pkt_decode(const uint8_t *buf, size_t len);

/* Counts the bytes that would need escaping in `buf`. */
size_t pkt_escape_cost(const uint8_t *buf, size_t len);

#endif
