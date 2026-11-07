#include <stdio.h>
#include "ringbuf.h"

static unsigned char storage[256];

/* Reads stdin through a ring buffer and prints it line by line, numbered. */
int main(void)
{
    struct ringbuf rb;
    unsigned char chunk[64], line[128];
    size_t n, k, taken;
    unsigned long lineno = 0;

    if (rb_init(&rb, storage, sizeof storage) != 0)
        return 1;
    for (;;) {
        k = rb_free_space(&rb);
        if (k > sizeof chunk)
            k = sizeof chunk;
        n = fread(chunk, 1, k, stdin);
        if (rb_write(&rb, chunk, n) != n)
            return 1;
        while ((taken = rb_peek_line(&rb, line, sizeof line)) > 0) {
            printf("%5lu  %s\n", ++lineno, (const char *)line);
            rb_read(&rb, NULL, taken);
        }
        if (n == 0)
            break;
        if (rb_free_space(&rb) == 0) {
            fprintf(stderr, "line too long\n");
            return 2;
        }
    }
    return 0;
}
