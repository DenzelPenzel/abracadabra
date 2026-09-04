PUBLIC vmp_runtime_production_probe
PUBLIC vmp_runtime_probe_abi
PUBLIC vmp_runtime_fastfail_begin
PUBLIC vmp_runtime_fastfail_end

HOST_ALLOC             EQU 208h
HOST_MXCSR              EQU 0A0h
HOST_X87_CONTROL        EQU 0A4h

STATE_RFLAGS            EQU 120
STATE_YMM6              EQU 128
STATE_MXCSR             EQU 448
STATE_X87_CONTROL       EQU 452
STATE_VALID_XSTATE      EQU 456

OUT_ENTRY_RSP           EQU 480
OUT_CONTINUATION_RSP    EQU 488
OUT_STATUS              EQU 496
OUT_RUNTIME_RFLAGS      EQU 504
OUT_ABI_RFLAGS          EQU 512
OUT_CANARY_BEFORE       EQU 520
OUT_CANARY_AFTER        EQU 528
OUT_LOW_WATERMARK       EQU 536
OUT_CONTINUATION        EQU 544

FAST_FAIL_FATAL_APP_EXIT EQU 7

ABI_ALLOC               EQU 0E8h
ABI_SAVED_XMM           EQU 020h
ABI_SAVED_MXCSR         EQU 0C0h
ABI_SAVED_X87_CONTROL   EQU 0C4h
ABI_ARGS                EQU 0C8h
ABI_OUTPUT              EQU 0D0h

ABI_OUT_XMM6            EQU 64
ABI_OUT_MXCSR           EQU 224
ABI_OUT_X87_CONTROL     EQU 228
ABI_OUT_RSP_BEFORE      EQU 232
ABI_OUT_RSP_AFTER       EQU 240
ABI_OUT_PROBE_RESULT    EQU 248

.code
vmp_runtime_production_probe PROC FRAME
    push rbx
    .pushreg rbx
    push rbp
    .pushreg rbp
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, HOST_ALLOC
    .allocstack HOST_ALLOC

    movdqa XMMWORD PTR [rsp + 000h], xmm6
    .savexmm128 xmm6, 000h
    movdqa XMMWORD PTR [rsp + 010h], xmm7
    .savexmm128 xmm7, 010h
    movdqa XMMWORD PTR [rsp + 020h], xmm8
    .savexmm128 xmm8, 020h
    movdqa XMMWORD PTR [rsp + 030h], xmm9
    .savexmm128 xmm9, 030h
    movdqa XMMWORD PTR [rsp + 040h], xmm10
    .savexmm128 xmm10, 040h
    movdqa XMMWORD PTR [rsp + 050h], xmm11
    .savexmm128 xmm11, 050h
    movdqa XMMWORD PTR [rsp + 060h], xmm12
    .savexmm128 xmm12, 060h
    movdqa XMMWORD PTR [rsp + 070h], xmm13
    .savexmm128 xmm13, 070h
    movdqa XMMWORD PTR [rsp + 080h], xmm14
    .savexmm128 xmm14, 080h
    movdqa XMMWORD PTR [rsp + 090h], xmm15
    .savexmm128 xmm15, 090h
    stmxcsr DWORD PTR [rsp + HOST_MXCSR]
    fnstcw WORD PTR [rsp + HOST_X87_CONTROL]
    .endprolog

    ; The dedicated writable stack page starts immediately above a guard page.
    ; S is the dispatcher-entry RSP; S-272 is its exact low watermark.
    mov rbx, rcx
    mov r11, QWORD PTR [rbx + 48]
    lea r11, [r11 + 280]

    mov rax, QWORD PTR [rbx + 8]
    mov QWORD PTR [r11 + 8], rax
    mov rax, QWORD PTR [rbx + 16]
    mov QWORD PTR [r11 + 16], rax
    mov rax, QWORD PTR [rbx + 24]
    mov QWORD PTR [r11 + 24], rax
    mov QWORD PTR [r11 + 32], -1
    mov QWORD PTR [r11 + 40], -1
    mov rax, QWORD PTR [rbx + 40]
    mov QWORD PTR [r11 + 48], rax
    mov QWORD PTR [r11 + 56], rsp
    mov rax, QWORD PTR [rbx]
    mov QWORD PTR [r11 + 64], rax
    mov r15, QWORD PTR [rbx + 32]
    mov eax, DWORD PTR [r15 + STATE_VALID_XSTATE]
    mov DWORD PTR [r11 + 72], eax
    mov QWORD PTR [r11 + 80], r15

    mov r10, QWORD PTR [r11 + 48]
    mov rax, QWORD PTR [r11 - 280]
    mov QWORD PTR [r10 + OUT_CANARY_BEFORE], rax

    cmp DWORD PTR [r15 + STATE_VALID_XSTATE], 0
    je load_xmm
    vmovdqu ymm6, YMMWORD PTR [r15 + STATE_YMM6 + 000h]
    vmovdqu ymm7, YMMWORD PTR [r15 + STATE_YMM6 + 020h]
    vmovdqu ymm8, YMMWORD PTR [r15 + STATE_YMM6 + 040h]
    vmovdqu ymm9, YMMWORD PTR [r15 + STATE_YMM6 + 060h]
    vmovdqu ymm10, YMMWORD PTR [r15 + STATE_YMM6 + 080h]
    vmovdqu ymm11, YMMWORD PTR [r15 + STATE_YMM6 + 0A0h]
    vmovdqu ymm12, YMMWORD PTR [r15 + STATE_YMM6 + 0C0h]
    vmovdqu ymm13, YMMWORD PTR [r15 + STATE_YMM6 + 0E0h]
    vmovdqu ymm14, YMMWORD PTR [r15 + STATE_YMM6 + 100h]
    vmovdqu ymm15, YMMWORD PTR [r15 + STATE_YMM6 + 120h]
    jmp vectors_loaded

load_xmm:
    movdqu xmm6, XMMWORD PTR [r15 + STATE_YMM6 + 000h]
    movdqu xmm7, XMMWORD PTR [r15 + STATE_YMM6 + 020h]
    movdqu xmm8, XMMWORD PTR [r15 + STATE_YMM6 + 040h]
    movdqu xmm9, XMMWORD PTR [r15 + STATE_YMM6 + 060h]
    movdqu xmm10, XMMWORD PTR [r15 + STATE_YMM6 + 080h]
    movdqu xmm11, XMMWORD PTR [r15 + STATE_YMM6 + 0A0h]
    movdqu xmm12, XMMWORD PTR [r15 + STATE_YMM6 + 0C0h]
    movdqu xmm13, XMMWORD PTR [r15 + STATE_YMM6 + 0E0h]
    movdqu xmm14, XMMWORD PTR [r15 + STATE_YMM6 + 100h]
    movdqu xmm15, XMMWORD PTR [r15 + STATE_YMM6 + 120h]

vectors_loaded:
    ldmxcsr DWORD PTR [r15 + STATE_MXCSR]
    fldcw WORD PTR [r15 + STATE_X87_CONTROL]

    ; Metadata is complete before the guest state becomes live.
    lea rsp, [r11 + 8]
    mov r15, QWORD PTR [rsp + 72]
    push QWORD PTR [r15 + STATE_RFLAGS]
    popfq
    mov rax, QWORD PTR [r15 + 0]
    mov rcx, QWORD PTR [r15 + 8]
    mov rdx, QWORD PTR [r15 + 16]
    mov rbx, QWORD PTR [r15 + 24]
    mov rbp, QWORD PTR [r15 + 32]
    mov rsi, QWORD PTR [r15 + 40]
    mov rdi, QWORD PTR [r15 + 48]
    mov r8, QWORD PTR [r15 + 56]
    mov r9, QWORD PTR [r15 + 64]
    mov r10, QWORD PTR [r15 + 72]
    mov r11, QWORD PTR [r15 + 80]
    mov r12, QWORD PTR [r15 + 88]
    mov r13, QWORD PTR [r15 + 96]
    mov r14, QWORD PTR [r15 + 104]
    mov r15, QWORD PTR [r15 + 112]
    call QWORD PTR [rsp + 56]

production_continuation:
    ; Snapshot every guest GPR and RFLAGS before using a scratch register.
    pushfq
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov r15, rsp
    mov r10, QWORD PTR [r15 + 168]

    mov rax, QWORD PTR [r15 + 112]
    mov QWORD PTR [r10 + 0], rax
    mov rax, QWORD PTR [r15 + 104]
    mov QWORD PTR [r10 + 8], rax
    mov rax, QWORD PTR [r15 + 96]
    mov QWORD PTR [r10 + 16], rax
    mov rax, QWORD PTR [r15 + 88]
    mov QWORD PTR [r10 + 24], rax
    mov rax, QWORD PTR [r15 + 80]
    mov QWORD PTR [r10 + 32], rax
    mov rax, QWORD PTR [r15 + 72]
    mov QWORD PTR [r10 + 40], rax
    mov rax, QWORD PTR [r15 + 64]
    mov QWORD PTR [r10 + 48], rax
    mov rax, QWORD PTR [r15 + 56]
    mov QWORD PTR [r10 + 56], rax
    mov rax, QWORD PTR [r15 + 48]
    mov QWORD PTR [r10 + 64], rax
    mov rax, QWORD PTR [r15 + 40]
    mov QWORD PTR [r10 + 72], rax
    mov rax, QWORD PTR [r15 + 32]
    mov QWORD PTR [r10 + 80], rax
    mov rax, QWORD PTR [r15 + 24]
    mov QWORD PTR [r10 + 88], rax
    mov rax, QWORD PTR [r15 + 16]
    mov QWORD PTR [r10 + 96], rax
    mov rax, QWORD PTR [r15 + 8]
    mov QWORD PTR [r10 + 104], rax
    mov rax, QWORD PTR [r15]
    mov QWORD PTR [r10 + 112], rax
    mov rax, QWORD PTR [r15 + 120]
    mov QWORD PTR [r10 + STATE_RFLAGS], rax

    lea rax, [r15 + 120]
    mov QWORD PTR [r10 + OUT_ENTRY_RSP], rax
    lea rax, [r15 + 128]
    mov QWORD PTR [r10 + OUT_CONTINUATION_RSP], rax
    mov rax, QWORD PTR [r15 + 152]
    mov QWORD PTR [r10 + OUT_STATUS], rax
    mov rax, QWORD PTR [r15 + 160]
    mov QWORD PTR [r10 + OUT_RUNTIME_RFLAGS], rax

    ; Capture continuation flags first, then keep the harness host DF-safe.
    cld
    pushfq
    pop rax
    mov QWORD PTR [r10 + OUT_ABI_RFLAGS], rax

    cmp DWORD PTR [r15 + 192], 0
    je store_xmm
    vmovdqu YMMWORD PTR [r10 + STATE_YMM6 + 000h], ymm6
    vmovdqu YMMWORD PTR [r10 + STATE_YMM6 + 020h], ymm7
    vmovdqu YMMWORD PTR [r10 + STATE_YMM6 + 040h], ymm8
    vmovdqu YMMWORD PTR [r10 + STATE_YMM6 + 060h], ymm9
    vmovdqu YMMWORD PTR [r10 + STATE_YMM6 + 080h], ymm10
    vmovdqu YMMWORD PTR [r10 + STATE_YMM6 + 0A0h], ymm11
    vmovdqu YMMWORD PTR [r10 + STATE_YMM6 + 0C0h], ymm12
    vmovdqu YMMWORD PTR [r10 + STATE_YMM6 + 0E0h], ymm13
    vmovdqu YMMWORD PTR [r10 + STATE_YMM6 + 100h], ymm14
    vmovdqu YMMWORD PTR [r10 + STATE_YMM6 + 120h], ymm15
    jmp vectors_stored

store_xmm:
    movdqu XMMWORD PTR [r10 + STATE_YMM6 + 000h], xmm6
    movdqu XMMWORD PTR [r10 + STATE_YMM6 + 020h], xmm7
    movdqu XMMWORD PTR [r10 + STATE_YMM6 + 040h], xmm8
    movdqu XMMWORD PTR [r10 + STATE_YMM6 + 060h], xmm9
    movdqu XMMWORD PTR [r10 + STATE_YMM6 + 080h], xmm10
    movdqu XMMWORD PTR [r10 + STATE_YMM6 + 0A0h], xmm11
    movdqu XMMWORD PTR [r10 + STATE_YMM6 + 0C0h], xmm12
    movdqu XMMWORD PTR [r10 + STATE_YMM6 + 0E0h], xmm13
    movdqu XMMWORD PTR [r10 + STATE_YMM6 + 100h], xmm14
    movdqu XMMWORD PTR [r10 + STATE_YMM6 + 120h], xmm15

vectors_stored:
    stmxcsr DWORD PTR [r10 + STATE_MXCSR]
    fnstcw WORD PTR [r10 + STATE_X87_CONTROL]
    mov eax, DWORD PTR [r15 + 192]
    mov DWORD PTR [r10 + STATE_VALID_XSTATE], eax
    mov rax, QWORD PTR [r15 - 160]
    mov QWORD PTR [r10 + OUT_CANARY_AFTER], rax
    mov rax, QWORD PTR [r15 - 152]
    mov QWORD PTR [r10 + OUT_LOW_WATERMARK], rax

    cmp QWORD PTR [r10 + OUT_STATUS], 0
    jne vmp_runtime_fastfail_begin
    mov DWORD PTR [r10 + OUT_CONTINUATION], 1
    cmp DWORD PTR [r15 + 192], 0
    je restore_host
    vzeroupper

restore_host:
    mov rsp, QWORD PTR [r15 + 176]
    ldmxcsr DWORD PTR [rsp + HOST_MXCSR]
    fldcw WORD PTR [rsp + HOST_X87_CONTROL]
    movdqa xmm6, XMMWORD PTR [rsp + 000h]
    movdqa xmm7, XMMWORD PTR [rsp + 010h]
    movdqa xmm8, XMMWORD PTR [rsp + 020h]
    movdqa xmm9, XMMWORD PTR [rsp + 030h]
    movdqa xmm10, XMMWORD PTR [rsp + 040h]
    movdqa xmm11, XMMWORD PTR [rsp + 050h]
    movdqa xmm12, XMMWORD PTR [rsp + 060h]
    movdqa xmm13, XMMWORD PTR [rsp + 070h]
    movdqa xmm14, XMMWORD PTR [rsp + 080h]
    movdqa xmm15, XMMWORD PTR [rsp + 090h]
    add rsp, HOST_ALLOC
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    xor eax, eax
    ret

vmp_runtime_production_probe ENDP

vmp_runtime_fastfail_begin PROC
    mov ecx, FAST_FAIL_FATAL_APP_EXIT
    int 29h
vmp_runtime_fastfail_begin ENDP

vmp_runtime_fastfail_end PROC
vmp_runtime_fastfail_end ENDP

vmp_runtime_probe_abi PROC FRAME
    push rbx
    .pushreg rbx
    push rbp
    .pushreg rbp
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, ABI_ALLOC
    .allocstack ABI_ALLOC

    movdqa XMMWORD PTR [rsp + ABI_SAVED_XMM + 000h], xmm6
    .savexmm128 xmm6, ABI_SAVED_XMM + 000h
    movdqa XMMWORD PTR [rsp + ABI_SAVED_XMM + 010h], xmm7
    .savexmm128 xmm7, ABI_SAVED_XMM + 010h
    movdqa XMMWORD PTR [rsp + ABI_SAVED_XMM + 020h], xmm8
    .savexmm128 xmm8, ABI_SAVED_XMM + 020h
    movdqa XMMWORD PTR [rsp + ABI_SAVED_XMM + 030h], xmm9
    .savexmm128 xmm9, ABI_SAVED_XMM + 030h
    movdqa XMMWORD PTR [rsp + ABI_SAVED_XMM + 040h], xmm10
    .savexmm128 xmm10, ABI_SAVED_XMM + 040h
    movdqa XMMWORD PTR [rsp + ABI_SAVED_XMM + 050h], xmm11
    .savexmm128 xmm11, ABI_SAVED_XMM + 050h
    movdqa XMMWORD PTR [rsp + ABI_SAVED_XMM + 060h], xmm12
    .savexmm128 xmm12, ABI_SAVED_XMM + 060h
    movdqa XMMWORD PTR [rsp + ABI_SAVED_XMM + 070h], xmm13
    .savexmm128 xmm13, ABI_SAVED_XMM + 070h
    movdqa XMMWORD PTR [rsp + ABI_SAVED_XMM + 080h], xmm14
    .savexmm128 xmm14, ABI_SAVED_XMM + 080h
    movdqa XMMWORD PTR [rsp + ABI_SAVED_XMM + 090h], xmm15
    .savexmm128 xmm15, ABI_SAVED_XMM + 090h
    stmxcsr DWORD PTR [rsp + ABI_SAVED_MXCSR]
    fnstcw WORD PTR [rsp + ABI_SAVED_X87_CONTROL]
    mov QWORD PTR [rsp + ABI_ARGS], rcx
    mov QWORD PTR [rsp + ABI_OUTPUT], rdx
    .endprolog

    ; Host sentinels differ from the guest sentinels loaded by the nested probe.
    mov r11, QWORD PTR [rcx + 64]
    mov rbx, QWORD PTR [r11 + 24]
    mov rbp, QWORD PTR [r11 + 32]
    mov rsi, QWORD PTR [r11 + 40]
    mov rdi, QWORD PTR [r11 + 48]
    mov r12, QWORD PTR [r11 + 88]
    mov r13, QWORD PTR [r11 + 96]
    mov r14, QWORD PTR [r11 + 104]
    mov r15, QWORD PTR [r11 + 112]
    movdqu xmm6, XMMWORD PTR [r11 + STATE_YMM6 + 000h]
    movdqu xmm7, XMMWORD PTR [r11 + STATE_YMM6 + 020h]
    movdqu xmm8, XMMWORD PTR [r11 + STATE_YMM6 + 040h]
    movdqu xmm9, XMMWORD PTR [r11 + STATE_YMM6 + 060h]
    movdqu xmm10, XMMWORD PTR [r11 + STATE_YMM6 + 080h]
    movdqu xmm11, XMMWORD PTR [r11 + STATE_YMM6 + 0A0h]
    movdqu xmm12, XMMWORD PTR [r11 + STATE_YMM6 + 0C0h]
    movdqu xmm13, XMMWORD PTR [r11 + STATE_YMM6 + 0E0h]
    movdqu xmm14, XMMWORD PTR [r11 + STATE_YMM6 + 100h]
    movdqu xmm15, XMMWORD PTR [r11 + STATE_YMM6 + 120h]
    ldmxcsr DWORD PTR [r11 + STATE_MXCSR]
    fldcw WORD PTR [r11 + STATE_X87_CONTROL]

    mov r10, QWORD PTR [rsp + ABI_OUTPUT]
    mov QWORD PTR [r10 + ABI_OUT_RSP_BEFORE], rsp
    mov rcx, QWORD PTR [rsp + ABI_ARGS]
    call vmp_runtime_production_probe

    mov r10, QWORD PTR [rsp + ABI_OUTPUT]
    mov DWORD PTR [r10 + ABI_OUT_PROBE_RESULT], eax
    mov QWORD PTR [r10 + ABI_OUT_RSP_AFTER], rsp
    mov QWORD PTR [r10 + 0], rbx
    mov QWORD PTR [r10 + 8], rbp
    mov QWORD PTR [r10 + 16], rsi
    mov QWORD PTR [r10 + 24], rdi
    mov QWORD PTR [r10 + 32], r12
    mov QWORD PTR [r10 + 40], r13
    mov QWORD PTR [r10 + 48], r14
    mov QWORD PTR [r10 + 56], r15
    movdqu XMMWORD PTR [r10 + ABI_OUT_XMM6 + 000h], xmm6
    movdqu XMMWORD PTR [r10 + ABI_OUT_XMM6 + 010h], xmm7
    movdqu XMMWORD PTR [r10 + ABI_OUT_XMM6 + 020h], xmm8
    movdqu XMMWORD PTR [r10 + ABI_OUT_XMM6 + 030h], xmm9
    movdqu XMMWORD PTR [r10 + ABI_OUT_XMM6 + 040h], xmm10
    movdqu XMMWORD PTR [r10 + ABI_OUT_XMM6 + 050h], xmm11
    movdqu XMMWORD PTR [r10 + ABI_OUT_XMM6 + 060h], xmm12
    movdqu XMMWORD PTR [r10 + ABI_OUT_XMM6 + 070h], xmm13
    movdqu XMMWORD PTR [r10 + ABI_OUT_XMM6 + 080h], xmm14
    movdqu XMMWORD PTR [r10 + ABI_OUT_XMM6 + 090h], xmm15
    stmxcsr DWORD PTR [r10 + ABI_OUT_MXCSR]
    fnstcw WORD PTR [r10 + ABI_OUT_X87_CONTROL]

    ldmxcsr DWORD PTR [rsp + ABI_SAVED_MXCSR]
    fldcw WORD PTR [rsp + ABI_SAVED_X87_CONTROL]
    movdqa xmm6, XMMWORD PTR [rsp + ABI_SAVED_XMM + 000h]
    movdqa xmm7, XMMWORD PTR [rsp + ABI_SAVED_XMM + 010h]
    movdqa xmm8, XMMWORD PTR [rsp + ABI_SAVED_XMM + 020h]
    movdqa xmm9, XMMWORD PTR [rsp + ABI_SAVED_XMM + 030h]
    movdqa xmm10, XMMWORD PTR [rsp + ABI_SAVED_XMM + 040h]
    movdqa xmm11, XMMWORD PTR [rsp + ABI_SAVED_XMM + 050h]
    movdqa xmm12, XMMWORD PTR [rsp + ABI_SAVED_XMM + 060h]
    movdqa xmm13, XMMWORD PTR [rsp + ABI_SAVED_XMM + 070h]
    movdqa xmm14, XMMWORD PTR [rsp + ABI_SAVED_XMM + 080h]
    movdqa xmm15, XMMWORD PTR [rsp + ABI_SAVED_XMM + 090h]
    add rsp, ABI_ALLOC
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    xor eax, eax
    ret
vmp_runtime_probe_abi ENDP
END
