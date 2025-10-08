#include <stdio.h>
#include <stdlib.h>

#include "../tinyhooks.h"

#define USED(x) asm volatile("" ::"r"((x)))

static void
on_malloc(tinyhook_enter_context_t *ctx, void *data)
{
    size_t *bytes = data;
    *bytes += tinyhook_get_arg(ctx, 0);
}

int
main()
{
    size_t      bytes = 0;
    tinyhook_t *hook  = tinyhook_create_enter(on_malloc, &bytes);
    tinyhook_attach(hook, malloc);

    for (int i = 0; i < 100; i++)
        USED(malloc(i));

    tinyhook_detach(hook);

    fprintf(stdout, "Allocated %lu bytes\n", bytes);
}
