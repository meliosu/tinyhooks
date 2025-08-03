#include <stdio.h>
#include <stdlib.h>

#include "../tinyhooks.h"

static void
on_enter(tinyhook_enter_context_t *ctx, void *data)
{
    int a = tinyhook_get_arg(ctx, 0);
    int b = tinyhook_get_arg(ctx, 1);

    fprintf(stdout, "on_enter (ctx, %p) -> %d + %d = ", data, a, b);
}

static void
on_leave(tinyhook_leave_context_t *ctx, void *data)
{
    int result = tinyhook_get_retval(ctx);

    fprintf(stdout, "%d -> on_leave(ctx, %p)\n", result, data);
}

__attribute__((noinline, visibility("default"))) int
add(int x, int y)
{
    return x + y;
}

__attribute__((noinline, visibility("default"))) int
call_add(int x, int y)
{
    return add(x, y);
}

int
main()
{
    tinyhook_t *enter = tinyhook_create_enter(on_enter, (void *)0xdeadbeef);
    tinyhook_t *leave = tinyhook_create_leave(on_leave, (void *)0xfeedcafe);

    tinyhook_attach(enter, add);
    tinyhook_attach(leave, add);

    for (int i = 0; i < 10; i++)
    {
        fprintf(stdout, "%d + %d = %d\n", i, i * i, call_add(i, i * i));
    }

    tinyhook_detach(enter);
    tinyhook_detach(leave);

    tinyhook_destroy(enter);
    tinyhook_destroy(leave);
}
