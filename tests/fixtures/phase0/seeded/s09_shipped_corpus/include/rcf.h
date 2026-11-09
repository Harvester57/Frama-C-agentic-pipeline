#ifndef RCF_H
#define RCF_H

#include <stddef.h>
#include <stdint.h>

/*
 * Record container frame: a 12-byte header, then `count` records.
 *
 *   header: magic "RCF1" (u32 LE), version (u8, RCF_VERSION), count (u8, 1..RCF_MAX_REC),
 *           flags (u8), reserved (u8), crc (u32 LE, rcf_crc32 over the first 8 bytes)
 *   record: type (u8), length (u8), `length` bytes of data
 *     RCF_REC_NAME:  1..RCF_NAME_MAX bytes
 *     RCF_REC_VALUE: u32 LE
 *     RCF_REC_SCALE: scale index (u8, below RCF_SCALES), mantissa (u16 LE)
 */
#define RCF_MAGIC 0x31464352u
#define RCF_VERSION 1
#define RCF_HDR_LEN 12
#define RCF_MAX_REC 8

#define RCF_REC_NAME 1
#define RCF_REC_VALUE 2
#define RCF_REC_SCALE 3

#define RCF_NAME_MAX 16
#define RCF_SCALES 6

/* CRC-32 (IEEE 802.3) of `len` bytes. */
uint32_t rcf_crc32(const uint8_t *buf, size_t len);

/* Parses one frame; returns the number of records, or -1 when the frame is malformed. */
int rcf_parse(const uint8_t *buf, size_t len);

#endif
