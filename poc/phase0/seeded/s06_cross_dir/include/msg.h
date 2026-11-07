#ifndef MSG_H
#define MSG_H

#include <stddef.h>
#include <stdint.h>

/*
 * Config messages are ';'-separated "key=value" fields:
 *   ip=<base64 of 4 bytes>   peer IPv4 address
 *   port=<decimal>           peer port, 1..65535
 *   tag=<text>               free text, at most 15 bytes
 * Unknown keys are ignored.
 */

/* Parses a message. Returns the number of known fields, or -1. */
int msg_parse(const char *str);

/* Returns the peer address of a message as a host-order u32, or -1. */
long msg_peer_ip(const char *str);

/* Decodes base64 text `in` into `out`. Returns the decoded length, or 0. */
size_t msg_b64(uint8_t *out, size_t cap, const uint8_t *in, size_t len);

#endif
