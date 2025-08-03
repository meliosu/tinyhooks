#define CONTINUE_OFFSET 112

.intel_syntax noprefix

.section .note.GNU-stack

.text
    .extern do_pre_hooks
    .extern do_post_hooks

    .global tinyhook_enter

    .type do_pre_hooks, @function
    .type do_post_hooks, @function
    .type tinyhook_enter, @function
    .type tinyhook_leave, @function


tinyhook_enter:
    .cfi_startproc
    cmp qword ptr [r11], 0
    jne 1f

    push rbp
	.cfi_def_cfa_offset 0x10
	.cfi_offset rbp, -0x10

    mov rbp, rsp
    .cfi_def_cfa_register rbp

    sub rsp, 192
    
    movdqa [rsp + 0], xmm0
    movdqa [rsp + 16], xmm1
    movdqa [rsp + 32], xmm2
    movdqa [rsp + 48], xmm3
    movdqa [rsp + 64], xmm4
    movdqa [rsp + 80], xmm5
    movdqa [rsp + 96], xmm6
    movdqa [rsp + 112], xmm7

    mov [rsp + 128], rdi
    mov [rsp + 136], rsi
    mov [rsp + 144], rdx
    mov [rsp + 152], rcx
    mov [rsp + 160], r8
    mov [rsp + 168], r9

    mov [rsp + 176], rax
    mov [rsp + 184], r10

    mov [r11 + 8], r12
    mov r12, r11

    mov rdi, r11
    mov rsi, rsp

    call do_pre_hooks@PLT

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
    mov r10, [rsp + 184]

    add rsp, 192

    pop rbp

    mov r11, [rsp]
    mov [r12], r11

    lea r11, [rip + tinyhook_leave]
    mov [rsp], r11

    mov r11, r12

1:
    lea r11, [r11 + CONTINUE_OFFSET]
    jmp r11
    .cfi_endproc

.size tinyhook_enter, . - tinyhook_enter


tinyhook_leave:
    .cfi_startproc
    mov r11, [r12]
    push r11

    push rbp
	.cfi_def_cfa_offset 0x10
	.cfi_offset rbp, -0x10

    mov rbp, rsp
    .cfi_def_cfa_register rbp

    sub rsp, 48

    movdqa [rsp + 0], xmm0
    movdqa [rsp + 16], xmm1

    mov [rsp + 32], rax
    mov [rsp + 40], rdx

    mov rdi, r12
    mov rsi, rsp

    call do_post_hooks@PLT

    movdqa xmm0, [rsp + 0]
    movdqa xmm1, [rsp + 16]

    mov rax, [rsp + 32]
    mov rdx, [rsp + 40]

    add rsp, 48

    pop rbp

    xor r11, r11
    mov [r12], r11

    mov r12, [r12 + 8]

    ret
    .cfi_endproc

.size tinyhook_leave, . - tinyhook_leave
