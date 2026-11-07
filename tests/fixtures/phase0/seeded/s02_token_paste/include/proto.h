#ifndef PROTO_H
#define PROTO_H

#include <stddef.h>
#include <stdint.h>

/*
 * Request: u8 opcode, then the opcode's payload.
 *   0x01 ping   empty payload, replies "pong"
 *   0x02 echo   replies the payload
 *   0x03 sum    replies the 8-bit sum of the payload
 *   0x04 rev    replies the payload reversed
 *   0x05 upper  replies the payload upper-cased
 */

/* Runs one request and writes the reply to `out`. Returns the reply length. */
size_t proto_reply(uint8_t *out, size_t cap, const uint8_t *in, size_t len);

/* Runs a stream of requests, each prefixed by a u8 length. Returns the
 * number of requests that succeeded, or -1 on a malformed stream. */
int proto_run(const uint8_t *buf, size_t len);

#endif
