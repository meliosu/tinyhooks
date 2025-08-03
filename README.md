# tinyhooks

<sup>tiny</sup> hooking library for Linux x86-64.


## Features

- Extremely low overhead
- No initialization or deinitialization
- Stack traces are preserved
- Low runtime memory footprint
- Small binary size

## Limitations

The library only works on **Linux x86-64** and is **not MT-safe**.

## API

See [tinyhooks.h](tinyhooks.h)


## Dependencies

The library depens on [Zydis](https://github.com/zyantific/zydis) for disassembly/code relocation.

You can install it on Ubuntu/Debian using apt:

```bash
sudo apt install libzydis-dev
```


## Build

```
git clone https://github.com/meliosu/tinyhooks -b dev
cd tinyhooks
make
make install
```

The header and static library will be in `devkit/`.


## Benchmark

### Common

```c
__attribute__((noinline)) void nop() { asm volatile("nop"); }

void do_nops(int iters) {
    /* Start timer */

    for (int i = 0; i < iters; i++)
        nop();

    /* End timer */
}
```

### [frida-gum](https://github.com/frida/frida-gum)

```c
#include "frida-gum.h"

static void on_enter(GumInvocationContext *ic, void *data) {}
static void on_leave(GumInvocationContext *ic, void *data) {}

int main() {
    int iters = 1000 * 1000 * 10;

    gum_init_embedded();
    GumInterceptor *interceptor = gum_interceptor_obtain();
    GumInvocationListener *listener = gum_make_call_listener(on_enter, on_leave, NULL, NULL);
    gum_interceptor_attach(interceptor, nop, listener, NULL, GUM_ATTACH_FLAGS_NONE);

    do_nops(iters);

    gum_interceptor_detach(interceptor, listener);
}
```

### tinyhooks

```c
#include "tinyhooks.h"

static void on_enter(tinyhook_enter_context_t *ctx, void *data) {}
static void on_leave(tinyhook_leave_context_t *ctx, void *data) {}

int
main()
{
    int iters = 1000 * 1000 * 100;

    tinyhook_t *enter = tinyhook_create_enter(on_enter, NULL);
    tinyhook_t *leave = tinyhook_create_leave(on_leave, NULL);

    tinyhook_attach(enter, nop);
    tinyhook_attach(leave, nop);

    do_nops(iters);

    tinyhook_detach(enter);
    tinyhook_detach(leave);
}

```

### Results

The results are for **Ryzen 5 7600X**.

|frida-gum|tinyhooks|
|---------|---------|
|181.62 ns./iter.|13.16 ns./iter.|

## Stack traces

You can safely get a backtrace from the enter/leave hooks using frame pointers. The first frame is for the hook itself, second one is for a library internal function, and the third is for the hooked function's caller.

**However**, due to how the return from a hooked function is intercepted, there are two possible scenarios when getting a backtrace from a hooked function directly:
1. It's caller will not be visible in the stack traces.
2. You won't be able to get a stack trace at all.


## Examples

See [examples](examples/)


## TODO
- [ ] Allow near jumps to be relocated
- [ ] Add proper error handling
- [ ] Check that there are no jumps to the patched code
- [ ] Fix other edge cases
