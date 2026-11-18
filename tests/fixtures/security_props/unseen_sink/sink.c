/* The sink relay.c reaches through `ctx->backend->send`: a static function of this file. */
#include <stdint.h>

struct link;

typedef struct backend {
    long (*send)(struct link *ctx, const uint8_t *req, int req_length);
} backend_t;

struct link {
    int fd;
    const backend_t *backend;
};

/*@ assigns \nothing; */
long net_write(int fd, const uint8_t *buf, int n);

static long tcp_send(struct link *ctx, const uint8_t *req, int req_length)
{
    return net_write(ctx->fd, req, req_length);
}

const backend_t tcp_backend = {tcp_send};
