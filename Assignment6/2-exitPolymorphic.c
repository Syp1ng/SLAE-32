#include<stdio.h>
#include<string.h>

unsigned char code[] = "\x31\xc0\x89\xc3\x40\xcd\x80";
void main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}