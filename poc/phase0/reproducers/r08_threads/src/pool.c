#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pool.h"
#include "queue.h"

#define MAX_WORKERS 8

struct pool {
    struct queue q;
    pthread_t tids[MAX_WORKERS];
    unsigned nworkers;
    pthread_mutex_t stats_lock;
    unsigned long jobs;
    unsigned long digest;
};

/* FNV-1a over one line. */
static uint32_t line_hash(const char *s, size_t n)
{
    uint32_t h = 2166136261u;
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 16777619u;
    }
    return h;
}

/* Thread start routine; runs concurrently with the submitting thread. */
static void *worker_main(void *arg)
{
    struct pool *p = arg;
    struct job j;
    uint32_t h;

    while (q_pop(&p->q, &j) == 0) {
        h = line_hash(j.data, j.len);
        pthread_mutex_lock(&p->stats_lock);
        p->jobs++;
        p->digest ^= h;
        pthread_mutex_unlock(&p->stats_lock);
    }
    return NULL;
}

struct pool *pool_create(unsigned nworkers)
{
    struct pool *p;
    unsigned i;

    if (nworkers == 0 || nworkers > MAX_WORKERS)
        return NULL;
    p = calloc(1, sizeof *p);
    if (!p)
        return NULL;
    if (q_init(&p->q) != 0) {
        free(p);
        return NULL;
    }
    pthread_mutex_init(&p->stats_lock, NULL);
    for (i = 0; i < nworkers; i++) {
        if (pthread_create(&p->tids[i], NULL, worker_main, p) != 0)
            break;
    }
    p->nworkers = i;
    if (i == 0) {
        q_destroy(&p->q);
        pthread_mutex_destroy(&p->stats_lock);
        free(p);
        return NULL;
    }
    return p;
}

int pool_submit(struct pool *p, const char *line, size_t n)
{
    struct job j;
    if (n > JOB_MAX - 1)
        n = JOB_MAX - 1;
    memcpy(j.data, line, n);
    j.data[n] = '\0';
    j.len = n;
    return q_push(&p->q, &j);
}

unsigned long pool_progress(struct pool *p)
{
    unsigned long v;
    pthread_mutex_lock(&p->stats_lock);
    v = p->jobs;
    pthread_mutex_unlock(&p->stats_lock);
    return v;
}

void pool_finish(struct pool *p, unsigned long *jobs, unsigned long *digest)
{
    unsigned i;
    q_close(&p->q);
    for (i = 0; i < p->nworkers; i++)
        pthread_join(p->tids[i], NULL);
    *jobs = p->jobs;
    *digest = p->digest;
    q_destroy(&p->q);
    pthread_mutex_destroy(&p->stats_lock);
    free(p);
}
