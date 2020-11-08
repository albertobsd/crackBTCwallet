/*
Email: alberto.bsd@gmail.com

this file depend of ctaes.c and ctaes.h

Just compile
g++ -O3 -o crack_ckey_test crack_ckey_test.c -Wint-to-pointer-cast

and execute
./crack_ckey_test
*/

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include"ctaes/ctaes.c"

#include"INT256.h"	//Custom and fast 256 bit unsigned integer

#define AES_BLOCKSIZE 16
#define NTHREADS 1

INT256 secuencial;	//Counter value

void thread_process_secuencial();

char *tohex(char *ptr,int length);
int MyCBCDecrypt(AES256_ctx *ctx, const unsigned char iv[AES_BLOCKSIZE], const unsigned char* data, int size, bool pad, unsigned char* out);

/*  
	padding must by constant and NOT NEED TO BE CHANGE
*/
const unsigned char *padding = (const unsigned char *)"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";

/*
the next values are hardcoded
*/

const unsigned char *pubkey = (const unsigned char *) "\x03\xdd\xa9\x63\xdb\x00\xb6\x40\x2c\x5a\xeb\x3f\x00\x01\x0c\x00\x00\x00\x60\x08\x9a\x5f\x00\x00\x00\x00\x0c\x6d\x2f\x30\x27\x2f\x30";

//a.k.a  ckey
const unsigned char *cipher_key = (const unsigned char *)"\x3f\x71\xb7\x2b\xc2\x65\x7c\xc2\xd6\xc3\x5b\xa5\x76\x40\x9f\xd4\x81\x23\xf4\x55\xb9\xd2\x8e\xdb\x70\xde\x56\xed\x13\x9e\xcd\xf9\xb1\x66\x13\x3f\x35\x9b\xe8\x26\x35\x4a\x29\xee\xd9\xd3\xfb\xf2";


int found = 0;

int main()	{
	/*
		FIXED starting counter
	*/
	memcpy(secuencial.lineal,"\x00\x6E\x36\xC9\x2D\x42\x9C\x51\x40\x98\xAB\x80\xAE\x55\x2B\x1B\x91\xA7\x92\x93\x30\x36\xF4\xF4\xCA\x4C\xB5\xC5\x69\xB3\x02\x7E",32);
	thread_process_secuencial();	
	return 0;
}

void thread_process_secuencial()	{
	AES256_ctx ctx;	//AES256 context
	INT256 *numero256;
	numero256 = &secuencial;
	int entrar,nLen;
	char *copy_cipher_key = NULL,*copy_pubkey = NULL,*decipher_key = NULL,*iv_material,*key_material;
	
	char *temp;
	unsigned int count,dec_len;
	/*
		Every thread work with his own copy of  cipher_key
	*/
	copy_cipher_key = (char *) malloc(48);
	copy_pubkey = (char *) malloc(33);
	decipher_key = (char *) malloc(48);
	iv_material = (char *) malloc(16);
	
	
	key_material = numero256->lineal;
	/*
		Copy values from Global
	*/
	memcpy(copy_cipher_key,cipher_key,48);
	memcpy(copy_pubkey,pubkey,33);
	memcpy(iv_material,copy_pubkey,16);		//We only need the firts 16 bytes of the PUB Key
	

	entrar = 1;
	nLen = 0;
	
	while(entrar && !found)	{
		temp = tohex(key_material,32);
		printf("Testing key %s\n",temp);
		free(temp);
		
		AES256_init(&ctx, (const unsigned char*)key_material);
		nLen = MyCBCDecrypt(&ctx,(const unsigned char*)iv_material,(const unsigned char*)copy_cipher_key,48,true,(unsigned char*)decipher_key);
		if(nLen == 32 && memcmp(decipher_key+32,padding,16) ==0 )	{
			printf("Possible Key found\n");
			temp = tohex(key_material,32);
			printf("key_material: %s\n",temp);
			free(temp);
			temp = tohex(decipher_key,48);
			printf("decipher_key: %s\n",temp);
			free(temp);
			found = 1;
			entrar = 0;
		}
		else	{
			printf("Key not valid for this ckey\n");
		}
		memset(&ctx, 0, sizeof(ctx));
		INT256_increment(numero256);
	}
	free(copy_cipher_key);
	free(copy_pubkey);
	free(iv_material);
	free(decipher_key);
}

/*
	Aux function to get the hexvalues of the data
*/
char *tohex(char *ptr,int length){
  char *buffer;
  int offset = 0;
  unsigned char c;
  buffer = (char *) malloc((length * 2)+1);
  for (int i = 0; i <length; i++) {
    c = ptr[i];
	sprintf((char*) (buffer + offset),"%.2x",c);
	offset+=2;
  }
  buffer[length*2] = 0;
  return buffer;
}

/*
Custom AES256 CBC Decrypt funtion this work with a pointer to AES256_ctx
*/
int MyCBCDecrypt(AES256_ctx *ctx, const unsigned char iv[AES_BLOCKSIZE], const unsigned char* data, int size, bool pad, unsigned char* out)
{
    int written = 0;
    bool fail = false;
    const unsigned char* prev = iv;
    if (!data || !size || !out)
        return 0;
    if (size % AES_BLOCKSIZE != 0)
        return 0;
    while (written != size) {
		AES256_decrypt(ctx, 1, out, data + written);
        for (int i = 0; i != AES_BLOCKSIZE; i++)
            *out++ ^= prev[i];
        prev = data + written;
        written += AES_BLOCKSIZE;
    }
    if (pad) {
        unsigned char padsize = *--out;
        fail = !padsize | (padsize > AES_BLOCKSIZE);
        padsize *= !fail;
        for (int i = AES_BLOCKSIZE; i != 0; i--)
            fail |= ((i > AES_BLOCKSIZE - padsize) & (*out-- != padsize));
        written -= padsize;
    }
    return written * !fail;
}
