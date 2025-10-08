#include <stdio.h>
#include <stdlib.h>

#include "../tinyhooks.h"

#define NOINLINE __attribute__((noinline))
#define BLACK_BOX                                                                                  \
    int __x;                                                                                       \
    asm volatile("" ::"m"(__x));

NOINLINE void
do_print(char *msg)
{
    BLACK_BOX;
    fprintf(stdout, "%s", msg);
}

NOINLINE void
f3()
{
    BLACK_BOX;
    do_print("Hello, World!\n");
}

NOINLINE void
f2()
{
    BLACK_BOX;
    f3();
}

NOINLINE void
f1()
{
    BLACK_BOX;
    f2();
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
    tinyhook_t *enter = tinyhook_create_enter(on_enter, NULL);
    tinyhook_t *leave = tinyhook_create_leave(on_leave, NULL);

    tinyhook_attach(enter, do_print);
    tinyhook_attach(leave, do_print);

    f1();

    tinyhook_destroy(enter);
    tinyhook_destroy(leave);
}
