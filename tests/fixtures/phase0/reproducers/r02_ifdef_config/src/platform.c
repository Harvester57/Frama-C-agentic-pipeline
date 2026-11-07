#define _POSIX_C_SOURCE 200809L
#include "platform.h"

#ifdef _WIN32
#include <windows.h>

static int win_read_all(const char *path, uint8_t *buf, size_t cap, size_t *out)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    DWORD got = 0;
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    if (!ReadFile(h, buf, (DWORD)cap, &got, NULL)) {
        CloseHandle(h);
        return -1;
    }
    CloseHandle(h);
    *out = got;
    return 0;
}

int plat_read_file(const char *path, uint8_t *buf, size_t cap, size_t *out)
{
    return win_read_all(path, buf, cap, out);
}

#else
#include <fcntl.h>
#include <unistd.h>

static int posix_read_all(int fd, uint8_t *buf, size_t cap, size_t *out)
{
    size_t got = 0;
    ssize_t r;
    while (got < cap) {
        r = read(fd, buf + got, cap - got);
        if (r < 0)
            return -1;
        if (r == 0)
            break;
        got += (size_t)r;
    }
    *out = got;
    return 0;
}

int plat_read_file(const char *path, uint8_t *buf, size_t cap, size_t *out)
{
    int fd = open(path, O_RDONLY), rc;
    if (fd < 0)
        return -1;
    rc = posix_read_all(fd, buf, cap, out);
    close(fd);
    return rc;
}

#endif
