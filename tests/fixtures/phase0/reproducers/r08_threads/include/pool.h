#ifndef POOL_H
#define POOL_H

#include <stddef.h>

/* A fixed-size pool of worker threads hashing submitted lines. */
struct pool;

struct pool *pool_create(unsigned nworkers);
/* Copies the line (truncated to 255 bytes) and queues it; blocks if full. */
int pool_submit(struct pool *p, const char *line, size_t n);
/* Number of jobs completed so far (thread-safe). */
unsigned long pool_progress(struct pool *p);
/* Drains the queue, joins the workers, reports totals, frees the pool. */
void pool_finish(struct pool *p, unsigned long *jobs, unsigned long *digest);

#endif
