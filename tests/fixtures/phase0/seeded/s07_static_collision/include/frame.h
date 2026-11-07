#ifndef FRAME_H
#define FRAME_H

#include <stddef.h>
#include <stdint.h>

/*
 * Frame: u8 kind, u8 header length H (counting these two bytes), header
 * option bytes up to offset H, then the payload. Each option byte is
 * XORed into the frame's option digest.
 */

/* Validates a frame. Returns its payload length, or -1. */
long frame_parse(const uint8_t *buf, size_t len);

/* Returns the option digest of a frame, or -1. */
int frame_digest(const uint8_t *buf, size_t len);

/* Byte histogram summary of a payload: the count of the most frequent
 * byte value whose index is a multiple of `stride` (1..16). */
size_t frame_stats(unsigned stride, const uint8_t *buf, size_t len);

/* Sum of the payload bytes of a frame, or -1. */
long frame_payload_sum(const uint8_t *buf, size_t len);

/* Copies the name of the frame kind of `in` to `out`. Returns its length. */
size_t frame_kind_name(uint8_t *out, size_t cap, const uint8_t *in, size_t len);

#endif
