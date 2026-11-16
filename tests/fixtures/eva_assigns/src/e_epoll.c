#include "epoll_stub.h"

int eva_main(void)
{
    struct epoll_event evs[4];
    int a = 0, b = 0;
    fill_two(&a);
    int n = epoll_wait(3, evs, 4, -1);
    fill_two(&b);
    if (n > 0)
        return (int)evs[0].events + a + b;
    return a + b;
}
