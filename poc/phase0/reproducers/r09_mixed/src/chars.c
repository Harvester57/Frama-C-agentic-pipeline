#include <string.h>
#include "internal.h"

/* Each line defines a non-static predicate int cls_<name>(int c). */
#define DEFINE_CLASS(name, expr) \
    int cls_##name(int c) { return (expr); }

DEFINE_CLASS(digit, c >= '0' && c <= '9')
DEFINE_CLASS(alpha, (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
DEFINE_CLASS(hexdig, cls_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
DEFINE_CLASS(tchar, cls_alpha(c) || cls_digit(c) ||
                    (c != 0 && strchr("!#$%&'*+-.^_`|~", c) != NULL))
DEFINE_CLASS(ows, c == ' ' || c == '\t')
