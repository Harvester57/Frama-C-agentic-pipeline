#include "modules.h"

int main(void)
{
    return gen_module_count() == 3 && gen_modules[0] == 1 ? 0 : 1;
}
