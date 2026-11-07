#define _POSIX_C_SOURCE 200809L
#include "queue.h"

int q_init(struct queue *q)
{
    q->head = 0;
    q->count = 0;
    q->closed = 0;
    if (pthread_mutex_init(&q->lock, NULL) != 0)
        return -1;
    if (pthread_cond_init(&q->not_empty, NULL) != 0 ||
        pthread_cond_init(&q->not_full, NULL) != 0) {
        pthread_mutex_destroy(&q->lock);
        return -1;
    }
    return 0;
}

void q_destroy(struct queue *q)
{
    pthread_cond_destroy(&q->not_full);
    pthread_cond_destroy(&q->not_empty);
    pthread_mutex_destroy(&q->lock);
}

int q_push(struct queue *q, const struct job *j)
{
    pthread_mutex_lock(&q->lock);
    while (q->count == QUEUE_CAP && !q->closed)
        pthread_cond_wait(&q->not_full, &q->lock);
    if (q->closed) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }
    q->slots[(q->head + q->count) % QUEUE_CAP] = *j;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return 0;
}

int q_pop(struct queue *q, struct job *out)
{
    pthread_mutex_lock(&q->lock);
    while (q->count == 0 && !q->closed)
        pthread_cond_wait(&q->not_empty, &q->lock);
    if (q->count == 0) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }
    *out = q->slots[q->head];
    q->head = (q->head + 1) % QUEUE_CAP;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return 0;
}

void q_close(struct queue *q)
{
    pthread_mutex_lock(&q->lock);
    q->closed = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_cond_broadcast(&q->not_full);
    pthread_mutex_unlock(&q->lock);
}
