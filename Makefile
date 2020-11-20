default:	libaesni
	gcc -Wall -c crackbtcshell.c -o crackbtcshell.o
	gcc -o crackbtcshell intel_aes.o crackbtcshell.o iaesx64.o do_rdtsc.o -pthread

clean:
	rm *.o
	rm crackbtcshell

libaesni:
	yasm -D__linux__ -f elf64 libaesni_custom/asm/iaesx64.s -o iaesx64.o
	yasm -D__linux__ -f elf64 libaesni_custom/asm/do_rdtsc.s -o do_rdtsc.o
	gcc -Wall -fPIC -c libaesni_custom/intel_aes.c -o intel_aes.o
