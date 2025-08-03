#include <stdio.h>

#include "../tinyhooks.h"

int
fibonacci(int n)
{
    if (n == 0 || n == 1)
        return n;
    else
        return fibonacci(n - 1) + fibonacci(n - 2);
}

static void
on_fibonacci_enter(tinyhook_enter_context_t *ctx, void *data)
{
    fprintf(stderr, "enter\n");
}

static void
on_fibonacci_leave(tinyhook_leave_context_t *ctx, void *data)
{
    fprintf(stderr, "leave\n");
}

int
main()
{
    tinyhook_t *enter = tinyhook_create_enter(on_fibonacci_enter, NULL);
    tinyhook_t *leave = tinyhook_create_leave(on_fibonacci_leave, NULL);

    tinyhook_attach(enter, fibonacci);
    tinyhook_attach(leave, fibonacci);

    fprintf(stdout, "fibonacci(10) = %d\n", fibonacci(10));

    tinyhook_destroy(enter);
    tinyhook_destroy(leave);
}
