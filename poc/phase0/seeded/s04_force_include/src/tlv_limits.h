#ifndef TLV_LIMITS_H
#define TLV_LIMITS_H

/* Protocol limit on the device name length. */
#define TLV_NAME_MAX 64

/* Size of the on-stack name buffer; a build configuration may lower it. */
#ifndef TLV_NAME_BUF
#define TLV_NAME_BUF 128
#endif

#endif
