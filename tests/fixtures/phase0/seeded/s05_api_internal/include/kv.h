#ifndef KV_H
#define KV_H

#include <stddef.h>
#include <stdint.h>

#define KV_SLOTS 8
#define KV_KEY_MAX 24
#define KV_VAL_MAX 32

/*
 * Loads a table image: a sequence of entries, each u8 key length, key
 * bytes, u8 value length, value bytes. Replaces the current table and
 * returns the number of entries loaded (at most KV_SLOTS), or -1.
 */
int kv_load(const uint8_t *buf, size_t len);

/* Returns the slot holding `key`, or -1. */
int kv_find(const char *key);

/* Returns 1 when slot `slot` (below kv_count()) holds `key`, else 0. */
int kv_key_equals(unsigned slot, const uint8_t *key, size_t len);

/* Copies the value stored under `key` (len bytes in `in`) to `out`.
 * Returns the value length, or 0 when the key is absent. */
size_t kv_get(uint8_t *out, size_t cap, const uint8_t *in, size_t len);

/* Number of loaded entries. */
int kv_count(void);

#endif
