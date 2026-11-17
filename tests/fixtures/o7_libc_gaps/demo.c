#include <elf.h>
#include <linux/audit.h>
#include <stdio.h>

int main(void)
{
    printf("%d %u\n", EI_NIDENT, (unsigned)AUDIT_ARCH_X86_64);
    return 0;
}
