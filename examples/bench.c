#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "../tinyhooks.h"

__attribute__((noinline)) void
nop()
{
    asm volatile("nop");
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

    tinyhook_t *enter = tinyhook_create_enter(on_enter, NULL);
    tinyhook_t *leave = tinyhook_create_leave(on_leave, NULL);

    tinyhook_attach(enter, nop);
    tinyhook_attach(leave, nop);

    struct timespec beg, end;
    clock_gettime(CLOCK_MONOTONIC, &beg);

    for (int i = 0; i < iters; i++)
        nop();

    clock_gettime(CLOCK_MONOTONIC, &end);
    double time = (double)(end.tv_sec - beg.tv_sec) * 1e9 + (double)(end.tv_nsec - beg.tv_nsec);
    fprintf(stdout, "%.2lf\n", time / (double)iters);

    tinyhook_destroy(enter);
    tinyhook_destroy(leave);
}
