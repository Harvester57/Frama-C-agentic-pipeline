#include <stdio.h>
#include <zlib.h>

#include "config.h"

int main(void)
{
    printf("%s %s\n", GREETING, zlibVersion());
    return 0;
}
