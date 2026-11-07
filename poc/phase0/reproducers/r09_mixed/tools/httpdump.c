/* httpdump [-q] < request.txt : parse one HTTP request from stdin. */
#include <stdio.h>
#include <string.h>
#include "httpp.h"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
static void set_binary_mode(void)
{
    _setmode(_fileno(stdin), _O_BINARY);
}
#endif

struct stats {
    unsigned long body_bytes;
    unsigned headers;
};

static struct httpp parser;
static char buf[8192];

static int print_reqline(void *ud, const char *method, const char *target, int minor)
{
    (void)ud;
    printf("request: %s %s HTTP/1.%d\n", method, target, minor);
    return 0;
}

static int print_header(void *ud, const char *name, const char *value)
{
    struct stats *s = ud;
    s->headers++;
    printf("  %s: %s\n", name, value);
    return 0;
}

static int count_body(void *ud, const char *data, size_t n)
{
    struct stats *s = ud;
    (void)data;
    s->body_bytes += n;
    return 0;
}

static void print_summary(void *ud)
{
    struct stats *s = ud;
    printf("complete: %u headers printed, %lu body bytes\n", s->headers, s->body_bytes);
}

int main(int argc, char **argv)
{
    struct httpp_callbacks cb;
    struct stats st;
    const char *host;
    size_t n;
    int quiet = argc > 1 && strcmp(argv[1], "-q") == 0;

#ifdef _WIN32
    set_binary_mode();
#endif
    memset(&cb, 0, sizeof cb);
    memset(&st, 0, sizeof st);
    cb.on_request_line = print_reqline;
    cb.on_header = quiet ? NULL : print_header;
    cb.on_body = count_body;
    cb.on_complete = print_summary;
    httpp_init(&parser, &cb, &st);

    for (;;) {
        n = fread(buf, 1, sizeof buf, stdin);
        if (n == 0)
            break;
        if (httpp_feed(&parser, buf, n) < 0) {
            fprintf(stderr, "parse error\n");
            return 1;
        }
        if (httpp_done(&parser))
            break;
    }
    if (!httpp_done(&parser)) {
        fprintf(stderr, "truncated request\n");
        return 1;
    }
    host = httpp_header_get(&parser, "Host");
    if (host)
        printf("host: %s\n", host);
    return 0;
}
