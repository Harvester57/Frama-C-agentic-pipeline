#ifndef PLATFORM_H
#define PLATFORM_H

#include <stddef.h>
#include <stdint.h>

/* Reads up to cap bytes of a file; returns 0 on success. */
int plat_read_file(const char *path, uint8_t *buf, size_t cap, size_t *out);

#endif
