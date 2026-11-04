/*
 * Frama-C-only stand-in for <gcrypt.h>.
 *
 * CryptoLib's libgcrypt backend is an external-library boundary: under Frama-C
 * these calls must stay bodyless prototypes so the open assumption is visible
 * to the ledger. Parsing the real headers fails inside gpg-error.h under the
 * E-ACSL front-end, so Eva/WP/E-ACSL use these declarations instead.
 *
 * clang (sanitizer + LibFuzzer builds) does define neither __FRAMAC__ nor
 * __FRAMAC_EACSL__, so it transparently falls through to the real header.
 */
#ifndef CRYPTOLIB_FRAMAC_GCRYPT_STUB_H
#define CRYPTOLIB_FRAMAC_GCRYPT_STUB_H

#ifdef __FRAMAC__

#include <stddef.h>

/* Error codes (libgpg-error ABI: low 16 bits are the code). */
typedef int gcry_error_t;
#define GPG_ERR_NO_ERROR 0
#define GPG_ERR_CODE_MASK 0xFFFF

/* Opaque handles. Complete here so E-ACSL can compute alignof/sizeof on them;
 * the real library's definitions remain opaque to the analyser. */
typedef struct gcry_cipher_handle {
    int _framac_unused;
} *gcry_cipher_hd_t;
typedef struct gcry_mac_handle {
    int _framac_unused;
} *gcry_mac_hd_t;

/* Control commands used by CryptoLib. */
#define GCRYCTL_SELFTEST 38
#define GCRYCTL_INITIALIZATION_FINISHED 36

/* Cipher / MAC algorithm and mode identifiers used by CryptoLib. */
#define GCRY_CIPHER_NONE 0
#define GCRY_CIPHER_AES256 9
#define GCRY_CIPHER_CBC_MAC 13
#define GCRY_CIPHER_MODE_CBC 3
#define GCRY_CIPHER_MODE_CCM 8
#define GCRY_CIPHER_MODE_GCM 9
#define GCRY_CIPHER_MODE_SIV 11
#define GCRY_CIPHER_MODE_GCM_SIV 12
#define GCRY_MAC_CMAC_AES 201
#define GCRY_MAC_HMAC_SHA256 202
#define GCRY_MAC_HMAC_SHA512 203
#define GCRY_MAC_FLAG_SECURE 1

/* General. */
#define GCRYPT_VERSION "1.11.0"
#define GCRYPT_VERSION_NUMBER 0x010b00
const char *gcry_check_version(const char *req_version);
gcry_error_t gcry_control(int cmd, ...);
const char *gcry_strerror(gcry_error_t err);
const char *gcry_strsource(gcry_error_t err);

/* Cipher interface. */
gcry_error_t gcry_cipher_open(gcry_cipher_hd_t *hd, int algo, int mode, unsigned int flags);
gcry_error_t gcry_cipher_close(gcry_cipher_hd_t hd);
gcry_error_t gcry_cipher_setkey(gcry_cipher_hd_t hd, const void *key, size_t keylen);
gcry_error_t gcry_cipher_setiv(gcry_cipher_hd_t hd, const void *iv, size_t ivlen);
gcry_error_t gcry_cipher_encrypt(gcry_cipher_hd_t hd, void *out, size_t outsize,
                                 const void *in, size_t inlen);
gcry_error_t gcry_cipher_decrypt(gcry_cipher_hd_t hd, void *out, size_t outsize,
                                 const void *in, size_t inlen);
gcry_error_t gcry_cipher_authenticate(gcry_cipher_hd_t hd, const void *abuf, size_t abuflen);
gcry_error_t gcry_cipher_gettag(gcry_cipher_hd_t hd, void *tag, size_t taglen);
gcry_error_t gcry_cipher_checktag(gcry_cipher_hd_t hd, const void *tag, size_t taglen);
/* In the real header this is a macro over gcry_cipher_ctl(GCRYCTL_SET_DECRYPTION_TAG). */
gcry_error_t gcry_cipher_ctl(gcry_cipher_hd_t hd, int cmd, void *buffer, size_t buflen);
#define GCRYCTL_SET_DECRYPTION_TAG 80
#define gcry_cipher_set_decryption_tag(a, tag, taglen) \
    gcry_cipher_ctl((a), GCRYCTL_SET_DECRYPTION_TAG, (void *)(tag), (taglen))

/* MAC interface. */
gcry_error_t gcry_mac_open(gcry_mac_hd_t *hd, int algo, unsigned int flags, void *ctx);
gcry_error_t gcry_mac_close(gcry_mac_hd_t hd);
gcry_error_t gcry_mac_setkey(gcry_mac_hd_t hd, const void *key, size_t keylen);
gcry_error_t gcry_mac_setiv(gcry_mac_hd_t hd, const void *iv, size_t ivlen);
gcry_error_t gcry_mac_write(gcry_mac_hd_t hd, const void *buffer, size_t length);
gcry_error_t gcry_mac_read(gcry_mac_hd_t hd, void *buffer, size_t *buflen);
gcry_error_t gcry_mac_verify(gcry_mac_hd_t hd, const void *buffer, size_t buflen);
/* In the real header this is a macro over gcry_mac_ctl(GCRYCTL_RESET). */
gcry_error_t gcry_mac_ctl(gcry_mac_hd_t hd, int cmd, void *buffer, size_t buflen);
#define GCRYCTL_RESET 4
#define gcry_mac_reset(h) gcry_mac_ctl((h), GCRYCTL_RESET, NULL, 0)

#else /* !__FRAMAC__ */

#include_next <gcrypt.h>

#endif /* __FRAMAC__ */

#endif /* CRYPTOLIB_FRAMAC_GCRYPT_STUB_H */
