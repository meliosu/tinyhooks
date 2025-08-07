#ifndef __TINYHOOKS_H__
#define __TINYHOOKS_H__

typedef struct tinyhook               tinyhook_t;
typedef struct tinyhook_enter_context tinyhook_enter_context_t;
typedef struct tinyhook_leave_context tinyhook_leave_context_t;

typedef void (*tinyhook_enter_callback_t)(tinyhook_enter_context_t *ctx, void *data);
typedef void (*tinyhook_leave_callback_t)(tinyhook_leave_context_t *ctx, void *data);

/*
 * Create an `enter` hook that will be called every time the function
 * it is attached to is called.
 */
tinyhook_t *tinyhook_create_enter(tinyhook_enter_callback_t cb, void *data);

/*
 * Create a `leave` hook that will be called every time the function
 * it is attached to returns.
 */
tinyhook_t *tinyhook_create_leave(tinyhook_leave_callback_t cb, void *data);

/*
 * Destroy the hook.
 * Destroying the hook automatically detaches it first.
 */
void tinyhook_destroy(tinyhook_t *hook);

/*
 * Attached the hook to a function.
 * The hook can only be attached to one function at a time.
 */
int tinyhook_attach(tinyhook_t *hook, void *func);

/*
 * Detach the hook.
 * It can be reattached to another function later.
 */
int tinyhook_detach(tinyhook_t *hook);

/*
 * Get nth integer/pointer argument.
 * Only first 6 arguments are available.
 * Calls with nth >= 6 return 0.
 */
unsigned long tinyhook_get_arg(tinyhook_enter_context_t *ctx, unsigned int nth);

/*
 * Get the integer/pointer return value (in rax).
 */
unsigned long tinyhook_get_retval(tinyhook_leave_context_t *ctx);

/*
 * Get nth floating point argument as a float/double respectively.
 * Only first 8 arguments are available.
 * Calls with nth >= 8 return 0.0.
 *
 * The caller is responsible for using the correct type based on the hooked function.
 */
float  tinyhook_get_arg_float(tinyhook_enter_context_t *ctx, unsigned int nth);
double tinyhook_get_arg_double(tinyhook_enter_context_t *ctx, unsigned int nth);

/*
 * Get the reutrn value (in xmm0) as a float/double respectively.
 *
 * The caller is responsible for using the correct type based on the hooked function.
 */
float  tinyhook_get_retval_float(tinyhook_leave_context_t *ctx);
double tinyhook_get_retval_double(tinyhook_leave_context_t *ctx);

#endif /* !__TINYHOOKS_H__ */
