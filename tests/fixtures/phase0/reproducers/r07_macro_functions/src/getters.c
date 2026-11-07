#include "record.h"

/* Expands to rec_get_version, rec_get_flags, rec_get_length, rec_get_seq. */
#define REC_DEFINE_GETTER(T, name) \
    T rec_get_##name(const struct record *r) { return r->name; }

RECORD_FIELDS(REC_DEFINE_GETTER)
