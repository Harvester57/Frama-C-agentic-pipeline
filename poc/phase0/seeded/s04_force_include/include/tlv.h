#ifndef TLV_H
#define TLV_H

#include <stddef.h>
#include <stdint.h>

/*
 * A message is a sequence of records: u8 type, u8 length, value.
 *   type 1: device name, 1..TLV_NAME_MAX bytes of text
 *   type 2: device id, u16 big-endian (length 2)
 *   type 3: flags, u8 (length 1)
 * Unknown types are skipped.
 */

/* Validates a message. Returns the number of records, or -1. */
int tlv_parse(const uint8_t *buf, size_t len);

/* Copies the first device name of message `in` to `out`. Returns its length. */
size_t tlv_get_name(uint8_t *out, size_t cap, const uint8_t *in, size_t len);

/* Returns the device id of a message, or -1 when there is none. */
long tlv_get_id(const uint8_t *buf, size_t len);

#endif
