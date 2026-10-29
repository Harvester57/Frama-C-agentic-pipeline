/*
 * External Boundary Stub Contracts for Frama-C (Eva & WP)
 *
 * Purpose:
 * Verify that the target C module passes valid, initialized, and properly bounded
 * buffers to external libraries (OpenSSL/mbedTLS, OS sockets, XML/DB drivers)
 * without parsing third-party implementation files inside Frama-C.
 */

#ifndef FRAMAC_EXTERNAL_STUBS_H
#define FRAMAC_EXTERNAL_STUBS_H

#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * 1. Cryptographic Boundary Stubs (e.g., SNMPv3 USM HMAC / AES / SHA)
 * ============================================================================ */

/*@
  requires valid_key: key != \null && \valid_read(key + (0 .. key_len - 1));
  requires valid_data: data != \null && \valid_read(data + (0 .. data_len - 1));
  requires valid_mac: mac_out != \null && \valid(mac_out + (0 .. mac_len - 1));
  requires init_key: \initialized(key + (0 .. key_len - 1));
  requires init_data: \initialized(data + (0 .. data_len - 1));
  requires sep: \separated(mac_out + (0 .. mac_len - 1), key + (0 .. key_len - 1), data + (0 .. data_len - 1));
  terminates \true;
  exits \false;
  assigns mac_out[0 .. mac_len - 1];
  ensures status: \result == 0 || \result == -1;
  ensures init_out: \result == 0 ==> \initialized(mac_out + (0 .. mac_len - 1));
*/
int fc_stub_hmac_compute(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t *mac_out, size_t mac_len
);

/*@
  requires valid_expected: expected_mac != \null && \valid_read(expected_mac + (0 .. mac_len - 1));
  requires valid_computed: computed_mac != \null && \valid_read(computed_mac + (0 .. mac_len - 1));
  requires init_expected: \initialized(expected_mac + (0 .. mac_len - 1));
  requires init_computed: \initialized(computed_mac + (0 .. mac_len - 1));
  terminates \true;
  exits \false;
  assigns \nothing;
  ensures status: \result == 0 || \result == -1;
*/
int fc_stub_constant_time_memcmp(
    const uint8_t *expected_mac,
    const uint8_t *computed_mac,
    size_t mac_len
);

/*@
  requires valid_key: key != \null && \valid_read(key + (0 .. key_len - 1));
  requires valid_iv: iv != \null && \valid_read(iv + (0 .. iv_len - 1));
  requires valid_in: in_buf != \null && \valid_read(in_buf + (0 .. buf_len - 1));
  requires valid_out: out_buf != \null && \valid(out_buf + (0 .. buf_len - 1));
  requires init_key: \initialized(key + (0 .. key_len - 1));
  requires init_iv: \initialized(iv + (0 .. iv_len - 1));
  requires init_in: \initialized(in_buf + (0 .. buf_len - 1));
  requires sep: \separated(out_buf + (0 .. buf_len - 1), key + (0 .. key_len - 1), iv + (0 .. iv_len - 1));
  terminates \true;
  exits \false;
  assigns out_buf[0 .. buf_len - 1];
  ensures status: \result == 0 || \result == -1;
  ensures init_out: \result == 0 ==> \initialized(out_buf + (0 .. buf_len - 1));
*/
int fc_stub_cipher_decrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *in_buf, uint8_t *out_buf, size_t buf_len
);

/* ============================================================================
 * 2. Network Emission Boundary Stubs (e.g., Syslog / UDP / TCP send)
 * ============================================================================ */

/*@
  requires valid_payload: payload != \null;
  requires valid_range: len > 0 ==> \valid_read(payload + (0 .. len - 1));
  requires init_range: len > 0 ==> \initialized(payload + (0 .. len - 1));
  terminates \true;
  exits \false;
  assigns \nothing;
  ensures bound: -1 <= \result <= len;
*/
long fc_stub_network_send(int fd, const uint8_t *payload, size_t len);

#endif /* FRAMAC_EXTERNAL_STUBS_H */
