; Native leaf oracle plus an unrelated runtime-function entry to preserve
.code
PUBLIC VmOriginal
VmOriginal PROC
IFDEF VMP_SUB_PROBE
    DB 048h, 089h, 0C8h, 048h, 029h, 0D0h, 0C3h
ELSE
    DB 048h, 089h, 0C8h, 048h, 001h, 0D0h, 0C3h
ENDIF
VmOriginal ENDP
ExistingFrame PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    pop rbx
    ret
ExistingFrame ENDP
.data
Anchor QWORD VmOriginal
END
