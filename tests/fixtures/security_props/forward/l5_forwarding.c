/*
 * L5_sanitized on a forwarding sink: the shape of libmodbus (send_msg in src/modbus.c, the TCP
 * backend in src/modbus-tcp.c). write_register builds a request and leaves the two length bytes of
 * its header to the backend. send_msg has the backend complete them (send_msg_pre, through a
 * function pointer) and then hands the buffer to the backend's send, the function that transmits.
 * The threat model declares both send_msg and tcp_send as network sinks.
 *
 * VIOLATE: send_msg skips the pre-send hook, so req[4] and req[5] reach tcp_send uninitialized.
 * NO_CALLS: the call of the backend's send has no `calls` annotation, so WP has no callee there
 * and no precondition to prove.
 */
typedef struct ctx ctx_t;

typedef struct backend {
    int (*send_msg_pre)(unsigned char *req, int req_length);
    int (*send)(ctx_t *ctx, const unsigned char *req, int req_length);
} backend_t;

struct ctx {
    int s;
    const backend_t *backend;
};

int net_send(int fd, const unsigned char *buf, int n);

/*@ requires req_length >= 6 && \valid(req + (4 .. 5));
    assigns req[4 .. 5];
    ensures \result == req_length;
    ensures \initialized(req + 4) && \initialized(req + 5);
*/
static int tcp_send_msg_pre(unsigned char *req, int req_length)
{
    int mbap_length = req_length - 6;

    req[4] = (unsigned char)(mbap_length >> 8);
    req[5] = (unsigned char)(mbap_length & 0xFF);
    return req_length;
}

/*@ requires \valid_read(ctx);
    assigns \nothing;
*/
static int tcp_send(ctx_t *ctx, const unsigned char *req, int req_length)
{
    return net_send(ctx->s, req, req_length);
}

const backend_t tcp_backend = {tcp_send_msg_pre, tcp_send};

/*@ requires \valid_read(ctx) && \valid_read(ctx->backend);
    requires ctx->backend->send_msg_pre == &tcp_send_msg_pre && ctx->backend->send == &tcp_send;
    requires 6 <= msg_length <= 260 && \valid(msg + (0 .. msg_length - 1));
    requires \initialized(msg + (0 .. 3)) && \initialized(msg + (6 .. msg_length - 1));
*/
static int send_msg(ctx_t *ctx, unsigned char *msg, int msg_length)
{
#ifndef VIOLATE
    /*@ calls tcp_send_msg_pre; */
    msg_length = ctx->backend->send_msg_pre(msg, msg_length);
#endif
#ifndef NO_CALLS
    /*@ calls tcp_send; */
#endif
    return ctx->backend->send(ctx, msg, msg_length);
}

/*@ requires \valid_read(ctx) && \valid_read(ctx->backend);
    requires ctx->backend->send_msg_pre == &tcp_send_msg_pre && ctx->backend->send == &tcp_send;
*/
int write_register(ctx_t *ctx, unsigned addr, unsigned value)
{
    unsigned char req[12];

    req[0] = 0; /* transaction and protocol identifiers */
    req[1] = 1;
    req[2] = 0;
    req[3] = 0;
    /* req[4] and req[5], the length: left to the backend's send_msg_pre */
    req[6] = 0xFF;
    req[7] = 0x06;
    req[8] = (unsigned char)((addr >> 8) & 0xFF);
    req[9] = (unsigned char)(addr & 0xFF);
    req[10] = (unsigned char)((value >> 8) & 0xFF);
    req[11] = (unsigned char)(value & 0xFF);
    return send_msg(ctx, req, 12);
}
