/*
 * A caller whose translation unit does not declare the sink it reaches: `relay` hands its buffer to
 * `ctx->backend->send`, and the function that pointer holds (`tcp_send`, sink.c) is a static function
 * of another file. The shape of libmodbus `send_msg` (modbus.c) and `_modbus_tcp_send` (modbus-tcp.c).
 *
 * MetAcsl is given `L5_sanitized_tcp_send` for `relay` with relay.c only: it knows no `tcp_send`,
 * generates no instance and reports a successful translation.
 */
#include <stdint.h>

struct link;

typedef struct backend {
    long (*send)(struct link *ctx, const uint8_t *req, int req_length);
} backend_t;

struct link {
    int fd;
    const backend_t *backend;
};

/*@ requires \valid_read(ctx) && \valid_read(ctx->backend);
    terminates \false;
*/
long relay(struct link *ctx, const uint8_t *msg, int msg_length)
{
    return ctx->backend->send(ctx, msg, msg_length);
}
