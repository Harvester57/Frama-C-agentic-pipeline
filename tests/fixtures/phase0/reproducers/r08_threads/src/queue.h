#ifndef QUEUE_H
#define QUEUE_H

#include <pthread.h>
#include <stddef.h>

#define QUEUE_CAP 16
#define JOB_MAX 256

struct job {
    size_t len;
    char data[JOB_MAX];
};

/* Bounded blocking MPMC queue. */
struct queue {
    struct job slots[QUEUE_CAP];
    size_t head, count;
    int closed;
    pthread_mutex_t lock;
    pthread_cond_t not_empty, not_full;
};

int q_init(struct queue *q);
void q_destroy(struct queue *q);
int q_push(struct queue *q, const struct job *j);   /* -1 if closed */
int q_pop(struct queue *q, struct job *out);        /* -1 if closed and empty */
void q_close(struct queue *q);

#endif
