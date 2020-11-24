#include<stdio.h>

#define cpuid(func,ax,bx,cx,dx)\
	__asm__ __volatile__ ("cpuid":\
	"=a" (ax), "=b" (bx),"=c" (cx), "=d" (dx): "a" (func));

int chech_cpu_support_AEX()	{
	unsigned int a,b,c,d;
	cpuid(1,a,b,c,d);
	return (c &0x2000000);
}

int main()	{
	if(chech_cpu_support_AEX())	{
		printf("AES ni: Soportado\n");
	}
	else	{
		printf("AES ni: NO Soportado\n");
	}
}