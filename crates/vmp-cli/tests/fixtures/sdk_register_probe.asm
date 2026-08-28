option casemap:none

EXTERN __imp_VMProtectBeginMutation:QWORD
EXTERN __imp_VMProtectEnd:QWORD
EXTERN __imp_VMProtectIsProtected:QWORD
EXTERN __imp_VMProtectDecryptStringA:QWORD
EXTERN __imp_VMProtectDecryptStringW:QWORD
EXTERN __imp_VMProtectFreeString:QWORD
EXTERN __imp_RaiseException:QWORD

PUBLIC sdk_register_protected_region

.const
marker_name BYTE "register-sdk-slice", 0
ansi_value BYTE "ansi", 0
ALIGN 2
wide_value WORD 077h, 069h, 064h, 065h, 0

.code
sdk_register_protected_region PROC FRAME
    sub rsp, 56
    .allocstack 56
    .endprolog

    mov DWORD PTR [rsp + 32], ecx

    lea rcx, marker_name
    mov rax, QWORD PTR [__imp_VMProtectBeginMutation]
    call rax

    lea rcx, ansi_value
    mov rax, QWORD PTR [__imp_VMProtectDecryptStringA]
    call rax
    mov QWORD PTR [rsp + 40], rax

    lea rcx, wide_value
    mov rax, QWORD PTR [__imp_VMProtectDecryptStringW]
    call rax
    mov QWORD PTR [rsp + 48], rax

    mov rax, QWORD PTR [__imp_VMProtectIsProtected]
    call rax
    movzx eax, al
    add eax, DWORD PTR [rsp + 32]

    mov r10, QWORD PTR [rsp + 40]
    cmp BYTE PTR [r10], 061h
    jne ansi_done
    inc eax
ansi_done:
    mov r10, QWORD PTR [rsp + 48]
    cmp WORD PTR [r10], 077h
    jne wide_done
    inc eax
wide_done:
    mov DWORD PTR [rsp + 36], eax

    mov rcx, QWORD PTR [rsp + 40]
    mov rax, QWORD PTR [__imp_VMProtectFreeString]
    call rax
    mov rcx, QWORD PTR [rsp + 48]
    mov rax, QWORD PTR [__imp_VMProtectFreeString]
    call rax

    cmp DWORD PTR [rsp + 32], 13
    jne no_exception
    mov ecx, 0E0421001h
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    call QWORD PTR [__imp_RaiseException]

no_exception:
    mov eax, DWORD PTR [rsp + 36]
    cmp DWORD PTR [rsp + 32], 9
    je no_end
    test BYTE PTR [rsp + 32], 1
    jz even_end

    imul eax, eax, 3
    mov DWORD PTR [rsp + 36], eax
    mov rax, QWORD PTR [__imp_VMProtectEnd]
    call rax
    mov eax, DWORD PTR [rsp + 36]
    xor eax, 055h
    jmp finished

even_end:
    sub eax, 2
    mov DWORD PTR [rsp + 36], eax
    mov rax, QWORD PTR [__imp_VMProtectEnd]
    call rax
    mov eax, DWORD PTR [rsp + 36]
    xor eax, 0AAh
    jmp finished

no_end:
    add eax, 900

finished:
    add rsp, 56
    ret
sdk_register_protected_region ENDP
END
