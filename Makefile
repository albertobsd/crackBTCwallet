default:  libaesni
	gcc -Wall -O3 -fPIC -c ctaes/ctaes.c -o ctaes.o
	gcc -Wall -O3 -c sha512.c -o sha512.o
	gcc -Wall -O3 -c sha256.c -o sha256.o
	gcc -Wall -O3 -c base58.c -o base58.o
	gcc -Wall -O3 -c rmd160.c -o rmd160.o
	gcc -Wall -O3 -c crackbtcshell.c -o crackbtcshell.o
	gcc -o crackbtcshell intel_aes.o crackbtcshell.o ctaes.o iaesx64.o do_rdtsc.o sha512.o sha256.o base58.o -pthread
	gcc -O3 -o get_mkey_ckey get_mkey_ckey.c base58.o sha256.o rmd160.o

noaesni:
	gcc -Wall -O3 -fPIC -c ctaes/ctaes.c -o ctaes.o
	gcc -Wall -O3 -c sha512.c -o sha512.o
	gcc -Wall -O3 -c sha256.c -o sha256.o
	gcc -Wall -O3 -c base58.c -o base58.o
	gcc -Wall -O3 -c rmd160.c -o rmd160.o
	gcc -Wall -c crackbtcshell_noaesni.c -o crackbtcshell.o
	gcc -O3 -o get_mkey_ckey get_mkey_ckey.c base58.o sha256.o rmd160.o
	gcc -o crackbtcshell crackbtcshell.o ctaes.o sha512.o sha256.o base58.o -pthread

clean:
	rm *.o
	rm crackbtcshell
	rm get_mkey_ckey
libaesni:
	yasm -D__linux__ -f elf64 libaesni_custom/asm/iaesx64.s -o iaesx64.o
	yasm -D__linux__ -f elf64 libaesni_custom/asm/do_rdtsc.s -o do_rdtsc.o
	gcc -Wall -fPIC -c libaesni_custom/intel_aes.c -o intel_aes.o
testaes:
	yasm -D__linux__ -f elf64 libaesni_custom/asm/iaesx64.s -o iaesx64.o
	yasm -D__linux__ -f elf64 libaesni_custom/asm/do_rdtsc.s -o do_rdtsc.o
	gcc -Wall -fPIC -c libaesni_custom/intel_aes.c -o intel_aes.o
	gcc -Wall -O3 -fPIC -c ctaes/ctaes.c -o ctaes.o
	gcc -Wall -c tested_aes.c -o tested_aes.o
	gcc -o tested_aes tested_aes.o ctaes.o intel_aes.o do_rdtsc.o iaesx64.o -pthread
