#include <string.h>

#include "kv.h"

struct kv_entry {
    uint8_t klen;
    uint8_t vlen;
    uint8_t key[KV_KEY_MAX];
    uint8_t val[KV_VAL_MAX];
};

static struct kv_entry kv_table[KV_SLOTS];
static unsigned kv_used;

int kv_count(void)
{
    return (int)kv_used;
}

int kv_load(const uint8_t *buf, size_t len)
{
    size_t pos = 0;

    kv_used = 0;
    while (pos < len && kv_used < KV_SLOTS) {
        struct kv_entry *e = &kv_table[kv_used];
        uint8_t kl, vl;

        kl = buf[pos++];
        if (kl == 0 || kl > KV_KEY_MAX || kl > len - pos)
            return -1;
        memcpy(e->key, buf + pos, kl);
        pos += kl;
        if (pos >= len)
            return -1;
        vl = buf[pos++];
        if (vl > KV_VAL_MAX || vl > len - pos)
            return -1;
        memcpy(e->val, buf + pos, vl);
        pos += vl;
        e->klen = kl;
        e->vlen = vl;
        kv_used++;
    }
    return (int)kv_used;
}

int kv_key_equals(unsigned slot, const uint8_t *key, size_t len)
{
    return kv_table[slot].klen == len && memcmp(kv_table[slot].key, key, len) == 0;
}

static int find_slot(const uint8_t *key, size_t len)
{
    unsigned i;

    for (i = 0; i < kv_used; i++)
        if (kv_key_equals(i, key, len))
            return (int)i;
    return -1;
}

int kv_find(const char *key)
{
    return find_slot((const uint8_t *)key, strlen(key));
}

size_t kv_get(uint8_t *out, size_t cap, const uint8_t *in, size_t len)
{
    int slot = find_slot(in, len);
    size_t n;

    if (slot < 0)
        return 0;
    n = kv_table[slot].vlen;
    if (n > cap)
        n = cap;
    memcpy(out, kv_table[slot].val, n);
    return n;
}
