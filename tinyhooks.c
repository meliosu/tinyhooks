#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <immintrin.h>
#include <memory.h>

#include <Zydis/Zydis.h>

#include "tinyhooks.h"

#define PAGE_SIZE 4096
#define TRAMPOLINES_PER_PAGE (int)((PAGE_SIZE - sizeof(page_t)) / sizeof(trampoline_t))
#define ALLOWED_DISTANCE (INT32_MAX - PAGE_SIZE)
#define TRAMPOLINE_MAGIC 0xdeadfeedfacebeef

#define MAX_INSN_SIZE 15
#define JMP_SIZE 5
#define JMP_PTR_SIZE 6
#define LEA_SIZE 7
#define MAX_THUNK_SIZE (MAX_INSN_SIZE + JMP_SIZE - 1)
#define MAX_RELOCATED_SIZE 25 // TODO: remove this magic constant
#define JMP_OPCODE 0xe9

struct tinyhook
{
    bool  is_enter;
    void *callback;
    void *data;

    void *trampoline;

    tinyhook_t *prev;
    tinyhook_t *next;
};

struct tinyhook_enter_context
{
    __m128 xmm0;
    __m128 xmm1;
    __m128 xmm2;
    __m128 xmm3;
    __m128 xmm4;
    __m128 xmm5;
    __m128 xmm6;
    __m128 xmm7;

    size_t rdi;
    size_t rsi;
    size_t rdx;
    size_t rcx;
    size_t r8;
    size_t r9;

    size_t rax;
};

struct tinyhook_leave_context
{
    __m128 xmm0;
    __m128 xmm1;

    size_t rax;
    size_t rdx;
};

typedef struct
{
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];
} insn_t;

typedef struct
{
    tinyhook_t *head;
    tinyhook_t *tail;
} hook_list_t;

typedef struct
{
    uint64_t retaddr;
    uint64_t ptr_to_retaddr;

    // Magic value to differentiate trampolines created by the library
    // from a random jump target. See `get_trampoline`.
    uint64_t magic;

    hook_list_t pre;
    hook_list_t post;

    void *func;

    // We need those pointers because the trampoline
    // may be further than ~2GiB away from those functions,
    // so we use an indirect call
    void (*tinyhook_enter)();
    void (*tinyhook_leave)();

    uint8_t orig_thunk[MAX_THUNK_SIZE];
    size_t  orig_thunk_sz;

    struct
    {
        uint8_t lea[LEA_SIZE];
        uint8_t jmp_ptr[JMP_PTR_SIZE];
        uint8_t thunk[MAX_RELOCATED_SIZE];
        uint8_t jmp[JMP_SIZE];
        uint8_t ret_lea[LEA_SIZE];
        uint8_t ret_jmp_ptr[JMP_PTR_SIZE];
    } insns;
} trampoline_t;

typedef struct page
{
    struct page *next;
    struct page *prev;

    trampoline_t trampolines[];
} page_t;

typedef struct
{
    page_t *head;
    page_t *tail;
} page_allocator_t;

static page_allocator_t page_allocator;

extern void tinyhook_enter();
extern void tinyhook_leave();

trampoline_t *
do_pre_hooks(trampoline_t *trampoline, tinyhook_enter_context_t *ctx)
{
    for (tinyhook_t *hook = trampoline->pre.head; hook != NULL; hook = hook->next)
    {
        tinyhook_enter_callback_t callback = hook->callback;
        void                     *data     = hook->data;

        callback(ctx, data);
    }

    return trampoline;
}

trampoline_t *
do_post_hooks(trampoline_t *trampoline, tinyhook_leave_context_t *ctx)
{
    for (tinyhook_t *hook = trampoline->post.head; hook != NULL; hook = hook->next)
    {
        tinyhook_leave_callback_t callback = hook->callback;
        void                     *data     = hook->data;

        callback(ctx, data);
    }

    return trampoline;
}

static uint64_t
distance(void *ptr1, void *ptr2)
{
    uint64_t p1 = (uint64_t)ptr1;
    uint64_t p2 = (uint64_t)ptr2;

    if (p1 > p2)
        return p1 - p2;
    else
        return p2 - p1;
}

static void *
round_page_down(void *addr)
{
    return (void *)((uint64_t)addr & ~(PAGE_SIZE - 1));
}

static void *
round_page_up(void *addr)
{
    return (void *)(((uint64_t)addr + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1));
}

static int
change_protection(void *addr, size_t len, int prot)
{
    void *beg = round_page_down(addr);
    void *end = round_page_up(addr + len);

    if (beg == end)
        return 0;

    return mprotect(beg, end - beg, prot);
}

static int
protect_region(void *addr, size_t len)
{
    return change_protection(addr, len, PROT_READ | PROT_EXEC);
}

static int
unprotect_region(void *addr, size_t len)
{
    return change_protection(addr, len, PROT_READ | PROT_WRITE | PROT_EXEC);
}

static void *
map_page_rwx(void *addr)
{
    void *mapped = mmap(
        addr,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
        -1,
        0);

    if (mapped == MAP_FAILED)
        return NULL;

    if (mapped != addr)
    {
        munmap(mapped, PAGE_SIZE);
        return NULL;
    }

    return mapped;
}

static page_t *
alloc_page(void *func, void *pivot)
{

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps)
        return NULL;

    uint64_t prev_end = 0;
    uint64_t beg, end;

    uint64_t min_distance      = UINT64_MAX;
    void    *min_distance_page = NULL;

    // Read only beginning and end of each region
    while (fscanf(maps, "%lx-%lx %*[^\n]\n", &beg, &end) == 2)
    {
        // There is no gap between memory regions
        if (beg == prev_end)
            goto next;

        void *page;

        // Choose page from the gap that is closest to func
        if ((uint64_t)func > beg)
            page = (void *)(beg - PAGE_SIZE);
        else
            page = (void *)prev_end;

        // We need a page less than ~2GiB away from `func` and `pivot`
        if (distance(page, func) > ALLOWED_DISTANCE
            || (pivot && distance(page, pivot) > ALLOWED_DISTANCE))
            goto next;

        if (distance(page, func) < min_distance)
        {
            min_distance      = distance(page, func);
            min_distance_page = page;
        }

    next:
        prev_end = end;
    }

    fclose(maps);

    if (!min_distance_page)
        return NULL;

    // Map the page with PROT_READ | PROT_WRITE | PROT_EXEC
    page_t *new_page = map_page_rwx(min_distance_page);
    if (!new_page)
        return NULL;

    // Add newly allocated page to `page_allocator`
    if (!page_allocator.head)
    {
        page_allocator.head = new_page;
        page_allocator.tail = new_page;
    }
    else
    {
        page_allocator.tail->next = new_page;
        new_page->prev            = page_allocator.tail;
        page_allocator.tail       = new_page;
    }

    return new_page;
}

static void
dealloc_page(page_t *page)
{
    if (page->prev)
        page->prev->next = page->next;
    else
        page_allocator.head = page->next;

    if (page->next)
        page->next->prev = page->prev;
    else
        page_allocator.tail = page->prev;

    munmap(page, PAGE_SIZE);
}

static trampoline_t *
alloc_trampoline(void *func, void *pivot)
{
    uint64_t      min_distance = UINT64_MAX;
    trampoline_t *trampoline   = NULL;

    // First, search for the fitting page with the minimum distance to `func`
    // using `page_allocator`
    for (page_t *page = page_allocator.head; page != NULL; page = page->next)
    {
        // We need a page that is less than ~2GiB away from `func` and from `pivot`
        if (distance(page, func) > ALLOWED_DISTANCE
            || (pivot && distance(page, pivot) > ALLOWED_DISTANCE))
            continue;

        bool is_full = true;
        int  i;

        for (i = 0; i < TRAMPOLINES_PER_PAGE; i++)
        {
            if (page->trampolines[i].magic == 0)
            {
                is_full = false;
                break;
            }
        }

        // There are no free trampolines in this page
        if (is_full)
            continue;

        if (distance(page, func) < min_distance)
        {
            min_distance = distance(page, func);
            trampoline   = &page->trampolines[i];
        }
    }

    // Didn't find the page in the `page_allocator`,
    // so we try to allocate it using mmap
    if (!trampoline)
    {
        page_t *page = alloc_page(func, pivot);
        if (!page)
            return NULL;

        trampoline = &page->trampolines[0];
    }

    trampoline->magic = TRAMPOLINE_MAGIC;
    return trampoline;
}

static void
dealloc_trampoline(trampoline_t *trampoline)
{
    // We are detaching the hook while the function that it is attached to
    // hasn't returned yet.
    //
    // Restoring the return address in the stack will bypass tinyhook_leave.
    if (trampoline->retaddr)
        *(void **)trampoline->ptr_to_retaddr = (void *)trampoline->retaddr;

    void *func = trampoline->func;

    unprotect_region(func, trampoline->orig_thunk_sz);
    memcpy(func, trampoline->orig_thunk, trampoline->orig_thunk_sz);
    protect_region(func, trampoline->orig_thunk_sz);

    page_t *page    = round_page_down(trampoline);
    bool    is_last = true;

    memset(trampoline, 0, sizeof(trampoline_t));

    for (int i = 0; i < TRAMPOLINES_PER_PAGE; i++)
    {
        if (page->trampolines[i].magic != 0)
        {
            is_last = false;
            break;
        }
    }

    // Free the page, if all it's trampolines are also freed
    if (is_last)
        dealloc_page(page);
}

static trampoline_t *
get_trampoline(void *func)
{
    uint8_t *insns = func;

    if (insns[0] != JMP_OPCODE)
        return NULL;

    void         *target     = func + *(int32_t *)(insns + 1) + 5;
    trampoline_t *trampoline = target - offsetof(trampoline_t, insns);

    // The trampoline struct can't cross the page boundary,
    // so different pages means that the jump is not to the trampoline.
    //
    // Just checking the `magic` might result in a segmentation fault here,
    // since we would be reading from a page adjacent to the function target's page.
    if (round_page_down(target) != round_page_down(trampoline))
        return NULL;

    if (trampoline->magic != TRAMPOLINE_MAGIC)
        return NULL;

    return trampoline;
}

static void
add_hook(trampoline_t *trampoline, tinyhook_t *hook)
{
    hook_list_t *list;

    if (hook->is_enter)
        list = &trampoline->pre;
    else
        list = &trampoline->post;

    if (!list->head)
    {
        list->head = hook;
        list->tail = hook;
    }
    else
    {
        list->tail->next = hook;
        hook->prev       = list->tail;
        list->tail       = hook;
    }
}

static void
remove_hook(trampoline_t *trampoline, tinyhook_t *hook)
{
    hook_list_t *list;

    if (hook->is_enter)
        list = &trampoline->pre;
    else
        list = &trampoline->post;

    if (hook->prev)
        hook->prev->next = hook->next;
    else
        list->head = hook->next;

    if (hook->next)
        hook->next->prev = hook->prev;
    else
        list->tail = hook->prev;
}

static tinyhook_t *
create_tinyhook(void *cb, void *data, bool is_enter)
{
    tinyhook_t *hook = malloc(sizeof(tinyhook_t));
    hook->is_enter   = is_enter;
    hook->callback   = cb;
    hook->data       = data;
    hook->prev       = NULL;
    hook->next       = NULL;
    hook->trampoline = NULL;
    return hook;
}

// TODO: REFACTOR

static void
fill_trampoline_insns(trampoline_t *trampoline, void *func, size_t insns_sz)
{
    ZydisEncoderRequest lea_req = {
        .machine_mode = ZYDIS_MACHINE_MODE_LONG_64,
        .mnemonic = ZYDIS_MNEMONIC_LEA,
        .operand_count = 2,
        .operands = {
            (ZydisEncoderOperand){
                .type = ZYDIS_OPERAND_TYPE_REGISTER,
                .reg.value = ZYDIS_REGISTER_R11,
            },
            (ZydisEncoderOperand){
                .type = ZYDIS_OPERAND_TYPE_MEMORY,
                .mem = {
                    .base = ZYDIS_REGISTER_RIP,
                    .displacement = (uint64_t)trampoline - ((uint64_t)trampoline->insns.lea + LEA_SIZE),
                    .size = 8,
                },
            },
        },
    };

    ZydisEncoderRequest jmp_ptr_req = {
        .machine_mode = ZYDIS_MACHINE_MODE_LONG_64,
        .mnemonic = ZYDIS_MNEMONIC_JMP,
        .operand_count = 1,
        .operands = {
            (ZydisEncoderOperand){
                .type = ZYDIS_OPERAND_TYPE_MEMORY,
                .mem = {
                    .base = ZYDIS_REGISTER_RIP,
                    .displacement = (uint64_t)&trampoline->tinyhook_enter - ((uint64_t)trampoline->insns.jmp_ptr + JMP_PTR_SIZE),
                    .size = 8,
                },
            },
        },
    };

    ZydisEncoderRequest jmp_req = {
        .machine_mode = ZYDIS_MACHINE_MODE_LONG_64,
        .mnemonic = ZYDIS_MNEMONIC_JMP,
        .operand_count = 1,
        .operands = {
            (ZydisEncoderOperand){
                .type = ZYDIS_OPERAND_TYPE_IMMEDIATE,
                .imm.s = (uint64_t)(func + insns_sz) - ((uint64_t)trampoline->insns.jmp + JMP_SIZE),
            },
        },
    };

    ZydisEncoderRequest ret_lea_req = {
        .machine_mode = ZYDIS_MACHINE_MODE_LONG_64,
        .mnemonic = ZYDIS_MNEMONIC_LEA,
        .operand_count = 2,
        .operands = {
            (ZydisEncoderOperand){
                .type = ZYDIS_OPERAND_TYPE_REGISTER,
                .reg.value = ZYDIS_REGISTER_R11,
            },
            (ZydisEncoderOperand){
                .type = ZYDIS_OPERAND_TYPE_MEMORY,
                .mem = {
                    .base = ZYDIS_REGISTER_RIP,
                    .displacement = (uint64_t)trampoline - ((uint64_t)trampoline->insns.ret_lea + LEA_SIZE),
                    .size = 8,
                },
            },
        },
    };

    ZydisEncoderRequest ret_jmp_ptr_req = {
        .machine_mode = ZYDIS_MACHINE_MODE_LONG_64,
        .mnemonic = ZYDIS_MNEMONIC_JMP,
        .operand_count = 1,
        .operands = {
            (ZydisEncoderOperand){
                .type = ZYDIS_OPERAND_TYPE_MEMORY,
                .mem = {
                    .base = ZYDIS_REGISTER_RIP,
                    .displacement = (uint64_t)&trampoline->tinyhook_leave - ((uint64_t)trampoline->insns.ret_jmp_ptr + JMP_PTR_SIZE),
                    .size = 8,
                },
            },
        },
    };

    size_t     len;
    ZyanStatus status;

    len    = sizeof(trampoline->insns.lea);
    status = ZydisEncoderEncodeInstruction(&lea_req, trampoline->insns.lea, &len);
    assert(ZYAN_SUCCESS(status));

    len    = sizeof(trampoline->insns.jmp_ptr);
    status = ZydisEncoderEncodeInstruction(&jmp_ptr_req, trampoline->insns.jmp_ptr, &len);
    assert(ZYAN_SUCCESS(status));

    len    = sizeof(trampoline->insns.jmp);
    status = ZydisEncoderEncodeInstruction(&jmp_req, trampoline->insns.jmp, &len);
    assert(ZYAN_SUCCESS(status));

    len    = sizeof(trampoline->insns.ret_lea);
    status = ZydisEncoderEncodeInstruction(&ret_lea_req, trampoline->insns.ret_lea, &len);
    assert(ZYAN_SUCCESS(status));

    len    = sizeof(trampoline->insns.ret_jmp_ptr);
    status = ZydisEncoderEncodeInstruction(&ret_jmp_ptr_req, trampoline->insns.ret_jmp_ptr, &len);
    assert(ZYAN_SUCCESS(status));
}

static int
get_insns(void *func, size_t func_sz, insn_t insns[JMP_SIZE], size_t *ninsns, size_t *offset)
{
    *offset = 0;
    *ninsns = 0;

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    while (*offset < JMP_SIZE)
    {
        insn_t *insn = &insns[*ninsns];

        ZyanStatus status
            = ZydisDecoderDecodeFull(&decoder, func + *offset, -1, &insn->insn, insn->operands);

        if (!ZYAN_SUCCESS(status))
            return -1;

        if (*offset >= func_sz && insn->insn.mnemonic != ZYDIS_MNEMONIC_NOP
            && insn->insn.mnemonic != ZYDIS_MNEMONIC_INT3)
            return -1;

        *ninsns += 1;
        *offset += insn->insn.length;
    }

    return 0;
}

static void *
get_pivot(void *func, insn_t *insns, size_t ninsns)
{
    size_t offset = 0;

    for (size_t i = 0; i < ninsns; i++)
    {
        ZydisDecodedInstruction *insn     = &insns[i].insn;
        ZydisDecodedOperand     *operands = insns[i].operands;

        for (int j = 0; j < insn->operand_count; j++)
        {
            ZydisDecodedOperand *operand = &operands[j];

            if (operand->type == ZYDIS_OPERAND_TYPE_MEMORY
                && operand->mem.base == ZYDIS_REGISTER_RIP)
                return func + offset + insn->length + operand->mem.disp.value;
            else if (
                operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand->imm.is_relative
                && operand->size == 32)
                return func + offset + insn->length + operand->imm.value.s;
        }

        offset += insn->length;
    }

    return NULL;
}

static int
relocate(void *func, insn_t *insns, size_t ninsns, void *buffer, size_t *buffer_sz)
{
    size_t input_offset  = 0;
    size_t output_offset = 0;

    for (size_t i = 0; i < ninsns; i++)
    {
        ZydisDecodedInstruction *insn     = &insns[i].insn;
        ZydisDecodedOperand     *operands = insns[i].operands;

        if (insn->attributes & ZYDIS_ATTRIB_IS_RELATIVE)
        {
            for (int j = 0; j < insn->operand_count; j++)
            {
                ZydisDecodedOperand *operand = &operands[j];

                if (operand->type == ZYDIS_OPERAND_TYPE_MEMORY
                    && operand->mem.base == ZYDIS_REGISTER_RIP)
                {
                    operand->mem.disp.value
                        = (uint64_t)func + input_offset + insn->length + operand->mem.disp.value;
                }
                else if (operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand->imm.is_signed)
                {
                    operand->size = 32;
                    operand->imm.value.u
                        = (uint64_t)func + input_offset + insn->length + operand->imm.value.s;
                }
            }

            ZydisEncoderRequest req;
            ZyanStatus          status = ZydisEncoderDecodedInstructionToEncoderRequest(
                insn, operands, insn->operand_count, &req);

            if (!ZYAN_SUCCESS(status))
                return -1;

            size_t len = *buffer_sz - output_offset;
            status     = ZydisEncoderEncodeInstructionAbsolute(
                &req, buffer + output_offset, &len, (uint64_t)func + input_offset);

            if (!ZYAN_SUCCESS(status))
                return -1;

            input_offset += insn->length;
            output_offset += len;
        }
        else
        {
            if (output_offset + insn->length > *buffer_sz)
                return -1;

            memcpy(buffer + output_offset, func + input_offset, insn->length);
            input_offset += insn->length;
            output_offset += insn->length;
        }
    }

    *buffer_sz = output_offset;

    return 0;
}

static trampoline_t *
create_trampoline(void *func)
{
    int    ret;
    insn_t insns[JMP_SIZE];
    size_t ninsns;
    size_t insns_sz;

    ret = get_insns(func, -1, insns, &ninsns, &insns_sz);
    if (ret < 0)
        return NULL;

    void *pivot = get_pivot(func, insns, ninsns);

    trampoline_t *trampoline = alloc_trampoline(func, pivot);
    if (!trampoline)
        return NULL;

    memcpy(trampoline->orig_thunk, func, insns_sz);
    trampoline->orig_thunk_sz = insns_sz;

    trampoline->tinyhook_enter = tinyhook_enter;
    trampoline->tinyhook_leave = tinyhook_leave;
    trampoline->func           = func;

    size_t len = MAX_RELOCATED_SIZE;

    ret = relocate(func, insns, ninsns, trampoline->insns.thunk, &len);
    if (ret < 0)
    {
        dealloc_trampoline(trampoline);
        return NULL;
    }

    if (len < MAX_RELOCATED_SIZE)
        ZydisEncoderNopFill(trampoline->insns.thunk + len, MAX_RELOCATED_SIZE - len);

    fill_trampoline_insns(trampoline, func, insns_sz);

    unprotect_region(func, insns_sz);

    ZydisEncoderRequest jmp_trampoline_req = {
        .machine_mode = ZYDIS_MACHINE_MODE_LONG_64,
        .mnemonic = ZYDIS_MNEMONIC_JMP,
        .operand_count = 1,
        .operands = {
            (ZydisEncoderOperand){
                .type = ZYDIS_OPERAND_TYPE_IMMEDIATE,
                .imm.s = (uint64_t)&trampoline->insns - (uint64_t)(func + JMP_SIZE)
            },
        },
    };

    len               = JMP_SIZE;
    ZyanStatus status = ZydisEncoderEncodeInstruction(&jmp_trampoline_req, func, &len);
    assert(ZYAN_SUCCESS(status));

    if (len < insns_sz)
        ZydisEncoderNopFill(func + len, insns_sz - len);

    protect_region(func, insns_sz);

    return trampoline;
}

// !REFACTOR

static trampoline_t *
get_or_create_trampoline(void *func)
{
    return get_trampoline(func) ?: create_trampoline(func);
}

tinyhook_t *
tinyhook_create_enter(tinyhook_enter_callback_t cb, void *data)
{
    return create_tinyhook(cb, data, true);
}

tinyhook_t *
tinyhook_create_leave(tinyhook_leave_callback_t cb, void *data)
{
    return create_tinyhook(cb, data, false);
}

int
tinyhook_attach(tinyhook_t *hook, void *func)
{
    if (hook->trampoline)
        return -1;

    trampoline_t *trampoline = get_or_create_trampoline(func);
    if (!trampoline)
        return -1;

    hook->trampoline = trampoline;
    add_hook(trampoline, hook);

    return 0;
}

int
tinyhook_detach(tinyhook_t *hook)
{
    trampoline_t *trampoline = hook->trampoline;
    if (!trampoline)
        return -1;

    hook->trampoline = NULL;
    remove_hook(trampoline, hook);

    if (!trampoline->pre.head && !trampoline->post.head)
        dealloc_trampoline(trampoline);

    return 0;
}

void
tinyhook_destroy(tinyhook_t *hook)
{
    if (hook->trampoline)
        tinyhook_detach(hook);

    free(hook);
}

unsigned long
tinyhook_get_arg(tinyhook_enter_context_t *ctx, unsigned int nth)
{
    switch (nth)
    {
    case 0:
        return ctx->rdi;
    case 1:
        return ctx->rsi;
    case 2:
        return ctx->rdx;
    case 3:
        return ctx->rcx;
    case 4:
        return ctx->r8;
    case 5:
        return ctx->r9;
    default:
        return 0;
    }
}

unsigned long
tinyhook_get_retval(tinyhook_leave_context_t *ctx)
{
    return ctx->rax;
}

double
tinyhook_get_arg_double(tinyhook_enter_context_t *ctx, unsigned int nth)
{
    switch (nth)
    {
    case 0:
        return _mm_cvtsd_f64(_mm_castps_pd(ctx->xmm0));
    case 1:
        return _mm_cvtsd_f64(_mm_castps_pd(ctx->xmm1));
    case 2:
        return _mm_cvtsd_f64(_mm_castps_pd(ctx->xmm2));
    case 3:
        return _mm_cvtsd_f64(_mm_castps_pd(ctx->xmm3));
    case 4:
        return _mm_cvtsd_f64(_mm_castps_pd(ctx->xmm4));
    case 5:
        return _mm_cvtsd_f64(_mm_castps_pd(ctx->xmm5));
    case 6:
        return _mm_cvtsd_f64(_mm_castps_pd(ctx->xmm6));
    case 7:
        return _mm_cvtsd_f64(_mm_castps_pd(ctx->xmm7));
    default:
        return 0.0;
    }
}

double
tinyhook_get_retval_double(tinyhook_leave_context_t *ctx)
{
    return _mm_cvtsd_f64(_mm_castps_pd(ctx->xmm0));
}

float
tinyhook_get_arg_float(tinyhook_enter_context_t *ctx, unsigned int nth)
{
    switch (nth)
    {
    case 0:
        return _mm_cvtss_f32(ctx->xmm0);
    case 1:
        return _mm_cvtss_f32(ctx->xmm1);
    case 2:
        return _mm_cvtss_f32(ctx->xmm2);
    case 3:
        return _mm_cvtss_f32(ctx->xmm3);
    case 4:
        return _mm_cvtss_f32(ctx->xmm4);
    case 5:
        return _mm_cvtss_f32(ctx->xmm5);
    case 6:
        return _mm_cvtss_f32(ctx->xmm6);
    case 7:
        return _mm_cvtss_f32(ctx->xmm7);
    default:
        return 0.0;
    }
}

float
tinyhook_get_retval_float(tinyhook_leave_context_t *ctx)
{
    return _mm_cvtss_f32(ctx->xmm0);
}
