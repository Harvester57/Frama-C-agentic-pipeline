#ifndef HANDLERS_H
#define HANDLERS_H

#include "proto.h"

/* Internal: op handlers, reached only through the dispatch table. */
int h_ping(const struct msg *m, struct sink *out);
int h_echo(const struct msg *m, struct sink *out);
int h_sum(const struct msg *m, struct sink *out);
int h_reset(const struct msg *m, struct sink *out);

#endif
