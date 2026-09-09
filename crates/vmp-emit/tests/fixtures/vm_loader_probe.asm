; A leaf native oracle and an absolute pointer that requires loader relocation
.code
PUBLIC VmOriginal
VmOriginal PROC
    ; mov rax, rcx / add rax, rdx / ret
    DB 048h, 089h, 0C8h, 048h, 001h, 0D0h, 0C3h
VmOriginal ENDP

.data
PUBLIC RelocationAnchor
RelocationAnchor QWORD VmOriginal
END
