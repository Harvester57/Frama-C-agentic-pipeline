#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pool.h"

static pthread_mutex_t done_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t done_cv = PTHREAD_COND_INITIALIZER;
static int done;

/* Second kind of thread: periodic progress reporter. */
static void *progress_main(void *arg)
{
    struct pool *p = arg;
    struct timespec ts;

    pthread_mutex_lock(&done_lock);
    while (!done) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        pthread_cond_timedwait(&done_cv, &done_lock, &ts);
        fprintf(stderr, "progress: %lu jobs\n", pool_progress(p));
    }
    pthread_mutex_unlock(&done_lock);
    return NULL;
}

int main(int argc, char **argv)
{
    char line[1024];
    unsigned long nworkers = 4, jobs, digest;
    struct pool *p;
    pthread_t progress;
    int have_progress;

    if (argc > 1)
        nworkers = strtoul(argv[1], NULL, 10);
    p = pool_create((unsigned)nworkers);
    if (!p) {
        fprintf(stderr, "cannot start %lu workers\n", nworkers);
        return 1;
    }
    have_progress = pthread_create(&progress, NULL, progress_main, p) == 0;

    while (fgets(line, sizeof line, stdin))
        if (pool_submit(p, line, strlen(line)) != 0)
            break;

    pthread_mutex_lock(&done_lock);
    done = 1;
    pthread_cond_signal(&done_cv);
    pthread_mutex_unlock(&done_lock);
    if (have_progress)
        pthread_join(progress, NULL);

    pool_finish(p, &jobs, &digest);
    printf("jobs=%lu digest=%08lx\n", jobs, digest);
    return 0;
}
