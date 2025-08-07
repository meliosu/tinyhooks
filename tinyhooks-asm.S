#define CONTINUE_OFFSET 125
#define RETURN_OFFSET 155

.intel_syntax noprefix

.section .note.GNU-stack

.text
    .extern do_pre_hooks
    .extern do_post_hooks

    .global tinyhook_enter
    .global tinyhook_leave

    .type do_pre_hooks, @function
    .type do_post_hooks, @function
    .type tinyhook_enter, @function
    .type tinyhook_leave, @function


tinyhook_enter:
    .cfi_startproc

    // The pointer to trampoline is passed in r11

    // If the stored return address is not 0, we are in a recursive call and need to exit.
    mov r10, [r11]
    test r10, r10
    jnz 1f

    // Frame pointer
    push rbp
	.cfi_def_cfa_offset 0x10
	.cfi_offset rbp, -0x10
    mov rbp, rsp
    .cfi_def_cfa_register rbp

    sub rsp, 192
    
    // Save floating point arguments
    movdqa [rsp + 0], xmm0
    movdqa [rsp + 16], xmm1
    movdqa [rsp + 32], xmm2
    movdqa [rsp + 48], xmm3
    movdqa [rsp + 64], xmm4
    movdqa [rsp + 80], xmm5
    movdqa [rsp + 96], xmm6
    movdqa [rsp + 112], xmm7

    // Save integer/pointer arguments
    mov [rsp + 128], rdi
    mov [rsp + 136], rsi
    mov [rsp + 144], rdx
    mov [rsp + 152], rcx
    mov [rsp + 160], r8
    mov [rsp + 168], r9

    // Save number of FP arguments when for a variadic function
    mov [rsp + 176], rax

    // do_pre_hooks(trampoline, &enter_context)
    mov rdi, r11
    mov rsi, rsp
    call do_pre_hooks@PLT

    // Save r11 using callee's return value
    mov r11, rax

    movdqa xmm0, [rsp + 0]
    movdqa xmm1, [rsp + 16]
    movdqa xmm2, [rsp + 32]
    movdqa xmm3, [rsp + 48]
    movdqa xmm4, [rsp + 64]
    movdqa xmm5, [rsp + 80]
    movdqa xmm6, [rsp + 96]
    movdqa xmm7, [rsp + 112]

    mov rdi, [rsp + 128]
    mov rsi, [rsp + 136]
    mov rdx, [rsp + 144]
    mov rcx, [rsp + 152]
    mov r8, [rsp + 160]
    mov r9, [rsp + 168]

    mov rax, [rsp + 176]

    add rsp, 192

    pop rbp

    // Save the return address to trampoline->retaddr
    mov r10, [rsp]
    mov [r11], r10

    // Save the stack pointer to trampoline->ptr_to_retaddr
    // It can be used to restore the return address
    // when detaching the hook before the hooked
    // function has returned
    mov [r11 + 8], rsp

    // Overwrite the return address with trampoline->ret_lea
    lea r10, [r11 + RETURN_OFFSET]
    mov [rsp], r10

1:
    // Jump to trampoline->thunk to continue the function
    lea r10, [r11 + CONTINUE_OFFSET]
    jmp r10
    .cfi_endproc

.size tinyhook_enter, . - tinyhook_enter


tinyhook_leave:
    .cfi_startproc

    // The pointer to trampoline is passed in r11

    // Restore the original return address
    mov r10, [r11]
    push r10

    // Frame pointer
    push rbp
	.cfi_def_cfa_offset 0x10
	.cfi_offset rbp, -0x10
    mov rbp, rsp
    .cfi_def_cfa_register rbp

    sub rsp, 48

    // Store floating point return value
    // The xmm1 is used when returning 2 floats/doubles
    movdqa [rsp + 0], xmm0
    movdqa [rsp + 16], xmm1

    // Store integer/pointer return value
    // The rdx is used when returning 128 bit values
    mov [rsp + 32], rax
    mov [rsp + 40], rdx

    // do_post_hooks(trampoline, &leave_ctx)
    mov rdi, r11
    mov rsi, rsp
    call do_post_hooks@PLT

    // Save r11 using callee's return value
    mov r11, rax

    movdqa xmm0, [rsp + 0]
    movdqa xmm1, [rsp + 16]

    mov rax, [rsp + 32]
    mov rdx, [rsp + 40]

    add rsp, 48

    pop rbp

    // Zero the trampoline->retaddr
    xor r10, r10
    mov [r11], r10

    // Return to the actual return address
    // saved by the tinyhook_enter and pushed
    // in the beginning of the function
    ret
    .cfi_endproc

.size tinyhook_leave, . - tinyhook_leave
