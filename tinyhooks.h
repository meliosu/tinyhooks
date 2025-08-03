#ifndef __TINYHOOKS_H__
#define __TINYHOOKS_H__

typedef struct tinyhook               tinyhook_t;
typedef struct tinyhook_enter_context tinyhook_enter_context_t;
typedef struct tinyhook_leave_context tinyhook_leave_context_t;

typedef void (*tinyhook_enter_callback_t)(tinyhook_enter_context_t *ctx, void *data);
typedef void (*tinyhook_leave_callback_t)(tinyhook_leave_context_t *ctx, void *data);

tinyhook_t *tinyhook_create_enter(tinyhook_enter_callback_t cb, void *data);
tinyhook_t *tinyhook_create_leave(tinyhook_leave_callback_t cb, void *data);

void tinyhook_destroy(tinyhook_t *hook);

int tinyhook_attach(tinyhook_t *hook, void *func);
int tinyhook_detach(tinyhook_t *hook);

unsigned long tinyhook_get_arg(tinyhook_enter_context_t *ctx, unsigned int nth);
unsigned long tinyhook_get_retval(tinyhook_leave_context_t *ctx);

double tinyhook_get_arg_double(tinyhook_enter_context_t *ctx, unsigned int nth);
double tinyhook_get_retval_double(tinyhook_leave_context_t *ctx);

float tinyhook_get_arg_float(tinyhook_enter_context_t *ctx, unsigned int nth);
float tinyhook_get_retval_float(tinyhook_leave_context_t *ctx);

#endif /* !__TINYHOOKS_H__ */
