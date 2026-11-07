#ifndef REC_H
#define REC_H

#include <stddef.h>
#include <stdint.h>

/*
 * Record format (big-endian):
 *   u8  version (must be 1)
 *   u16 item count
 *   items: u8 type, then
 *     type 1: u32 value
 *     type 2: u8 length, then that many label bytes
 *     type 3: u16 value
 */

/* Validates a record. Returns the number of labels, or -1. */
int rec_parse(const uint8_t *buf, size_t len);

/* Sums the numeric items of a record. Returns the sum, or -1. */
long rec_sum(const uint8_t *buf, size_t len);

#endif
