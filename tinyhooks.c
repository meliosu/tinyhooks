#include <Zydis/Encoder.h>
#include <assert.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <immintrin.h>
#include <memory.h>

#include <Zydis/Zydis.h>
#include <xmmintrin.h>

#include "tinyhooks.h"

#define PAGE_SIZE 4096
#define TRAMPOLINES_PER_PAGE (int)((PAGE_SIZE - sizeof(page_t)) / sizeof(trampoline_t))
#define ALLOWED_DISTANCE (INT32_MAX - PAGE_SIZE)
#define TRAMPOLINE_MAGIC 0xdeadfeedfacebeef

#define MAX_INSN_SIZE 15
#define JMP_SIZE 5
#define JMP_PTR_SIZE 6
#define LEA_SIZE 7
#define MAX_PROLOGUE_SIZE (MAX_INSN_SIZE + JMP_SIZE - 1)

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
    size_t r10;
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
    tinyhook_t *head;
    tinyhook_t *tail;
} hook_list_t;

typedef struct
{
    uint64_t ret;
    uint64_t saved;

    uint64_t magic;

    hook_list_t pre;
    hook_list_t post;

    void *func;

    void (*tinyhook_enter)();

    size_t  replaced_prologue_size;
    uint8_t replaced_prologue[MAX_PROLOGUE_SIZE];

    struct
    {
        uint8_t lea[LEA_SIZE];
        uint8_t jmp_ptr[JMP_PTR_SIZE];
        uint8_t prologue[MAX_PROLOGUE_SIZE];
        uint8_t jmp[JMP_SIZE];
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

void
do_pre_hooks(trampoline_t *trampoline, tinyhook_enter_context_t *ctx)
{
    for (tinyhook_t *hook = trampoline->pre.head; hook != NULL; hook = hook->next)
    {
        tinyhook_enter_callback_t callback = hook->callback;
        void                     *data     = hook->data;

        callback(ctx, data);
    }
}

void
do_post_hooks(trampoline_t *trampoline, tinyhook_leave_context_t *ctx)
{
    for (tinyhook_t *hook = trampoline->post.head; hook != NULL; hook = hook->next)
    {
        tinyhook_leave_callback_t callback = hook->callback;
        void                     *data     = hook->data;

        callback(ctx, data);
    }
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

    while (fscanf(maps, "%lx-%lx %*[^\n]\n", &beg, &end) == 2)
    {
        if (beg == prev_end)
            goto next;

        void *page;

        if ((uint64_t)func > beg)
            page = (void *)(beg - PAGE_SIZE);
        else
            page = (void *)prev_end;

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

    page_t *new_page = map_page_rwx(min_distance_page);
    if (!new_page)
        return NULL;

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

    for (page_t *page = page_allocator.head; page != NULL; page = page->next)
    {
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

        if (is_full)
            continue;

        if (distance(page, func) < min_distance)
        {
            min_distance = distance(page, func);
            trampoline   = &page->trampolines[i];
        }
    }

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
    void *func = trampoline->func;

    unprotect_region(func, trampoline->replaced_prologue_size);
    memcpy(func, trampoline->replaced_prologue, trampoline->replaced_prologue_size);
    protect_region(func, trampoline->replaced_prologue_size);

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

    if (is_last)
        dealloc_page(page);
}

static trampoline_t *
get_trampoline(void *func)
{
    ZyanU8 *insns = func;

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];
    ZydisDecoderDecodeFull(&decoder, insns, -1, &insn, operands);

    bool is_relative_jump = insn.mnemonic == ZYDIS_MNEMONIC_JMP && insn.operand_count == 2
                            && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                            && operands[0].size == 32
                            && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                            && operands[1].reg.value == ZYDIS_REGISTER_RIP;

    if (!is_relative_jump)
        return NULL;

    void         *target     = func + operands[0].imm.value.u + insn.length;
    trampoline_t *trampoline = target - offsetof(trampoline_t, insns);

    if (round_page_down(target) != round_page_down(trampoline))
        return NULL;

    if (trampoline->magic != TRAMPOLINE_MAGIC)
        return NULL;

    return trampoline;
}

static trampoline_t *
create_trampoline(void *func)
{
    ZyanU8 *insns = func;

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZyanU64 offset = 0;
    void   *pivot  = NULL;

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];

    while (offset < JMP_SIZE
           && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, insns + offset, -1, &insn, operands)))
    {
        if (insn.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
        {
            for (int i = 0; i < insn.operand_count; i++)
            {
                if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[i].imm.is_relative)
                {
                    if (operands[i].size != 32)
                        return NULL;

                    pivot = insns + offset + operands[i].imm.value.s + insn.length;
                }
                else if (
                    operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY
                    && operands[i].mem.base == ZYDIS_REGISTER_RIP)
                {
                    if (!operands[i].mem.disp.has_displacement)
                        return NULL;

                    pivot = insns + offset + operands[i].mem.disp.value + insn.length;
                }
            }
        }

        offset += insn.length;
    }

    trampoline_t *trampoline = alloc_trampoline(func, pivot);
    if (!trampoline)
        return NULL;

    trampoline->tinyhook_enter = tinyhook_enter;
    trampoline->func           = func;

    int32_t shift = trampoline->insns.prologue - insns;

    offset = 0;

    while (offset < JMP_SIZE
           && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, insns + offset, -1, &insn, operands)))
    {
        if (insn.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
        {
            for (int i = 0; i < insn.operand_count; i++)
            {
                if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[i].imm.is_relative)
                {
                    operands[i].imm.value.s += shift;
                }
                else if (
                    operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY
                    && operands[i].mem.base == ZYDIS_REGISTER_RIP)
                {
                    operands[i].mem.disp.value += shift;
                }
            }

            ZydisEncoderRequest req;
            ZydisEncoderDecodedInstructionToEncoderRequest(
                &insn, operands, insn.operand_count, &req);

            ZyanUSize insn_len = insn.length;
            ZydisEncoderEncodeInstruction(&req, trampoline->insns.prologue + offset, &insn_len);
        }
        else
            memcpy(trampoline->insns.prologue + offset, insns + offset, insn.length);

        memcpy(trampoline->replaced_prologue + offset, insns + offset, insn.length);
        offset += insn.length;
    }

    trampoline->replaced_prologue_size = offset;

    if (offset < MAX_PROLOGUE_SIZE)
        ZydisEncoderNopFill(trampoline->insns.prologue + offset, MAX_PROLOGUE_SIZE - offset);

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
                .imm.s = (uint64_t)(func + offset) - ((uint64_t)trampoline->insns.jmp + JMP_SIZE),
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

    ZydisEncoderRequest jmp_trampoline_req = {
        .machine_mode = ZYDIS_MACHINE_MODE_LONG_64,
        .mnemonic = ZYDIS_MNEMONIC_JMP,
        .operand_count = 1,
        .operands = {
            (ZydisEncoderOperand){
                .type = ZYDIS_OPERAND_TYPE_IMMEDIATE,
                .imm.s = (uint64_t)trampoline->insns.lea - (uint64_t)(func + JMP_SIZE)
            },
        },
    };

    unprotect_region(func, offset);

    len    = JMP_SIZE;
    status = ZydisEncoderEncodeInstruction(&jmp_trampoline_req, func, &len);
    assert(ZYAN_SUCCESS(status));

    if (offset > JMP_SIZE)
        ZydisEncoderNopFill(func + JMP_SIZE, offset - JMP_SIZE);

    protect_region(func, offset);

    return trampoline;
}

static trampoline_t *
get_or_create_trampoline(void *func)
{
    return get_trampoline(func) ?: create_trampoline(func);
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

    hook->trampoline = NULL;

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
