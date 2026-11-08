#ifndef SDF_H
#define SDF_H

#include <stddef.h>
#include <stdint.h>

/*
 * Sealed data frame: a 12-byte header, then `count` extensions.
 *
 *   header: magic "SDF1" (u32 LE), version (u8, SDF_VERSION), flags (u8),
 *           count (u8, 1..SDF_MAX_EXT), reserved (u8), reserved (u16),
 *           checksum (u16 LE, sdf_checksum over the first 10 bytes)
 *   extension: type (u8), length (u8), `length` bytes of data
 */
#define SDF_MAGIC 0x31464453u
#define SDF_VERSION 2
#define SDF_HDR_LEN 12
#define SDF_MAX_EXT 8

#define SDF_EXT_NAME 1
#define SDF_EXT_VALUE 2
#define SDF_EXT_UNIT 3

#define SDF_NAME_BUF 8
#define SDF_NAME_MAX 32

/* Fletcher-16 of `len` bytes. */
uint16_t sdf_checksum(const uint8_t *buf, size_t len);

/* Parses one frame; returns the number of extensions, or -1 when the frame is malformed. */
int sdf_parse(const uint8_t *buf, size_t len);

#endif
