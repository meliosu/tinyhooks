#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "../tinyhooks.h"

__attribute__((noinline)) void
nop()
{
    asm volatile("nop");
}

void
do_nops(int iters)
{
    struct timespec beg, end;
    clock_gettime(CLOCK_MONOTONIC, &beg);

    for (int i = 0; i < iters; i++)
        nop();

    clock_gettime(CLOCK_MONOTONIC, &end);
    double time = (double)(end.tv_sec - beg.tv_sec) * 1e9 + (double)(end.tv_nsec - beg.tv_nsec);

    fprintf(stdout, "ns./iter.: %.2lf\n", time / (double)iters);
}

static void
on_enter(tinyhook_enter_context_t *ctx, void *data)
{
}

static void
on_leave(tinyhook_leave_context_t *ctx, void *data)
{
}

int
main()
{
    int iters = 1000 * 1000 * 100;

    do_nops(iters);

    tinyhook_t *enter = tinyhook_create_enter(on_enter, NULL);
    tinyhook_t *leave = tinyhook_create_leave(on_leave, NULL);

    tinyhook_attach(enter, nop);
    tinyhook_attach(leave, nop);

    do_nops(iters);

    tinyhook_detach(enter);
    tinyhook_detach(leave);

    tinyhook_destroy(enter);
    tinyhook_destroy(leave);

    do_nops(iters);
}
