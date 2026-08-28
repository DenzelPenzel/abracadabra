option casemap:none

EXTERN __imp_RaiseException:QWORD

PUBLIC sdk_static_protected_region

.code
sdk_static_protected_region PROC FRAME
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov DWORD PTR [rsp + 32], ecx

    BYTE 0EBh, 010h
    BYTE "VMProtect begin", 02h

    mov eax, DWORD PTR [rsp + 32]
    add eax, 3

    cmp DWORD PTR [rsp + 32], 13
    jne no_exception
    mov ecx, 0E0421001h
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    call QWORD PTR [__imp_RaiseException]

no_exception:
    cmp DWORD PTR [rsp + 32], 9
    je no_end
    test BYTE PTR [rsp + 32], 1
    jz even_end

    imul eax, eax, 3
    BYTE 0EBh, 00Eh
    BYTE "VMProtect end", 0
    xor eax, 055h
    jmp finished

even_end:
    sub eax, 2
    BYTE 0EBh, 00Eh
    BYTE "VMProtect end", 0
    xor eax, 0AAh
    jmp finished

no_end:
    add eax, 900

finished:
    add rsp, 40
    ret
sdk_static_protected_region ENDP
END
