/* L5_sanitized, a wrapper sink (the send path of libmodbus): send_frame is the one path of every
   outgoing frame. It completes the frame through the backend's hook, then hands it to the backend's
   send function through a function pointer. The TCP frame builder leaves the two length bytes to the
   hook, so the frame is not initialized yet where send_frame is called, and it is where it is sent.
   The backend's recv function has the type of its send function, as in libmodbus. */
typedef unsigned char uint8_t;
struct link;

typedef struct backend {
    int (*frame_pre)(uint8_t *req, int req_length);
    long (*send)(struct link *ctx, const uint8_t *req, int req_length);
    long (*recv)(struct link *ctx, uint8_t *rsp, int rsp_length);
} backend_t;

struct link {
    int fd;
    const backend_t *backend;
};

/*@ assigns \result \from fd, buf[0 .. n - 1]; */
long net_write(int fd, const uint8_t *buf, int n);

/*@ assigns buf[0 .. n - 1], \result \from fd; */
long net_read(int fd, uint8_t *buf, int n);

static int tcp_frame_pre(uint8_t *req, int req_length)
{
    req[4] = (uint8_t) ((req_length - 6) >> 8);
    req[5] = (uint8_t) (req_length - 6);
    return req_length;
}

static long tcp_send(struct link *ctx, const uint8_t *req, int req_length)
{
    return net_write(ctx->fd, req, req_length);
}

static long tcp_recv(struct link *ctx, uint8_t *rsp, int rsp_length)
{
    return net_read(ctx->fd, rsp, rsp_length);
}

static int rtu_frame_pre(uint8_t *req, int req_length)
{
    req[req_length] = (uint8_t) (req[0] ^ req[1]);
    return req_length + 1;
}

static long rtu_send(struct link *ctx, const uint8_t *req, int req_length)
{
    return net_write(ctx->fd, req, req_length);
}

static long rtu_recv(struct link *ctx, uint8_t *rsp, int rsp_length)
{
    return net_read(ctx->fd, rsp, rsp_length);
}

static const backend_t tcp_backend = {tcp_frame_pre, tcp_send, tcp_recv};
static const backend_t rtu_backend = {rtu_frame_pre, rtu_send, rtu_recv};

static int send_frame(struct link *ctx, uint8_t *msg, int msg_length)
{
    long rc;

    msg_length = ctx->backend->frame_pre(msg, msg_length);
    /*@ check L5_sanitized_send_frame: \initialized((msg) + (0 .. (msg_length) - 1)); */ rc = ctx->backend->send(ctx, msg, msg_length);
    return (int) rc;
}

int request_tcp(struct link *ctx, int addr)
{
    uint8_t req[12];

    req[0] = 0;
    req[1] = 1;
    req[2] = 0;
    req[3] = 0;
    /* req[4] and req[5], the length, are written by tcp_frame_pre */
    req[6] = 0xFF;
    req[7] = 3;
    req[8] = (uint8_t) (addr >> 8);
#ifndef VIOLATE
    req[9] = (uint8_t) addr; /* VIOLATE leaves req[9] uninitialized: no hook writes it */
#endif
    req[10] = 0;
    req[11] = 1;
    return send_frame(ctx, req, 12);
}

int request_rtu(struct link *ctx, int addr)
{
    uint8_t req[7];

    req[0] = 0x11;
    req[1] = 3;
    req[2] = (uint8_t) (addr >> 8);
    req[3] = (uint8_t) addr;
    req[4] = 0;
    req[5] = 1;
    /* req[6], the checksum, is written by rtu_frame_pre */
    return send_frame(ctx, req, 6);
}

/* A direct call of an inner sink, outside the wrapper. */
int ping(struct link *ctx)
{
    uint8_t beat[2];

    beat[0] = 0x55;
#ifndef VIOLATE
    beat[1] = 0xAA; /* VIOLATE leaves beat[1] uninitialized */
#endif
    return (int) tcp_send(ctx, beat, 2);
}

long poll_tcp(struct link *ctx, uint8_t *rsp)
{
    return ctx->backend->recv(ctx, rsp, 12);
}

void link_open(struct link *ctx, int fd, int rtu)
{
    ctx->fd = fd;
    ctx->backend = rtu ? &rtu_backend : &tcp_backend;
}

/* Both backends, one after the other (the entry point of the Eva run in the tests). */
int run_both(int addr)
{
    struct link tcp;
    struct link rtu;

    link_open(&tcp, 3, 0);
    link_open(&rtu, 4, 1);
    return request_tcp(&tcp, addr) + request_rtu(&rtu, addr) + ping(&tcp);
}
