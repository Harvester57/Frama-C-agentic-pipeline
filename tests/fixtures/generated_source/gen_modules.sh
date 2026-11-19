#!/bin/sh
# Writes gen/modules.c into the build tree, as nginx's ./configure writes objs/ngx_modules.c:
# a translation unit the build compiles and the source tree does not have.
set -e
mkdir -p gen
{
    echo '#include "modules.h"'
    echo 'int gen_modules[] = { 1, 2, 3 };'
    echo 'int gen_module_count(void) { return (int) (sizeof gen_modules / sizeof gen_modules[0]); }'
} > gen/modules.c
