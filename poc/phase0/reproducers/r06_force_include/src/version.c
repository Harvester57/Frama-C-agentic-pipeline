#include "tlv.h"

/* TLV_VERSION_STRING is defined only in the force-included config.h. */
const char *tlv_version(void)
{
    return TLV_VERSION_STRING;
}
