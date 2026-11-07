/* Vendored portability header, added with -isystem vendor/include. */
#ifndef ENDIAN_COMPAT_H
#define ENDIAN_COMPAT_H

#include <stdint.h>

#define compat_be16(p) ((uint16_t)(((uint16_t)(p)[0] << 8) | (uint16_t)(p)[1]))

#endif
