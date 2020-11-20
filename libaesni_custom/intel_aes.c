/* 
 * Copyright (c) 2010, Intel Corporation
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice, 
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, 
 *       this list of conditions and the following disclaimer in the documentation 
 *       and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors 
 *       may be used to endorse or promote products derived from this software 
 *       without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE 
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
*/

// 2016, Amirali Sanatinia (amirali@ccs.neu.edu)


#if (__cplusplus)
extern "C" {
#endif

#include "iaesni.h"
#include "iaes_asm_interface.h"

#if (__cplusplus)
}
#endif

#include <stdio.h>
#include <string.h>


#ifdef _WIN32
#include <intrin.h>
#else

static void __cpuid(unsigned int where[4], unsigned int leaf) {
  asm volatile("cpuid":"=a"(*where),"=b"(*(where+1)), "=c"(*(where+2)),"=d"(*(where+3)):"a"(leaf));
  return;
}
#endif


#include <stdlib.h>

#ifdef __APPLE__
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif

#include <memory.h>

#ifndef _WIN32
#include <alloca.h>
#ifndef _alloca
#define _alloca alloca
#endif
#endif

#define BLOCK_SIZE (16) //in bytes
#define AES_128_KEYSIZE (16) //in bytes
#define AES_192_KEYSIZE (24) //in bytes
#define AES_256_KEYSIZE (32) //in bytes


/* 
 * check_for_aes_instructions()
 *   return 1 if support AES-NI and 0 if don't support AES-NI
 */

int check_for_aes_instructions()
{
	unsigned int cpuid_results[4];
	int yes=1, no=0;

	__cpuid(cpuid_results,0);

	if (cpuid_results[0] < 1)
		return no;
/*
 *      MSB         LSB
 * EBX = 'u' 'n' 'e' 'G'
 * EDX = 'I' 'e' 'n' 'i'
 * ECX = 'l' 'e' 't' 'n'
 */
	
	if (memcmp((unsigned char *)&cpuid_results[1], "Genu", 4) != 0 ||
		memcmp((unsigned char *)&cpuid_results[3], "ineI", 4) != 0 ||
		memcmp((unsigned char *)&cpuid_results[2], "ntel", 4) != 0)
		return no;

	__cpuid(cpuid_results,1);

	if (cpuid_results[2] & AES_INSTRCTIONS_CPUID_BIT)
		return yes;

	return no;
}

void intel_AES_enc128(UCHAR *plainText,UCHAR *cipherText,UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iEncExpandKey128(key,expandedKey);
	iEnc128(&aesData);
}

void intel_AES_enc128_CBC(UCHAR *plainText,UCHAR *cipherText,UCHAR *key,size_t numBlocks,UCHAR *iv)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iEncExpandKey128(key,expandedKey);
	iEnc128_CBC(&aesData);
}


void intel_AES_enc192(UCHAR *plainText,UCHAR *cipherText,UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iEncExpandKey192(key,expandedKey);
	iEnc192(&aesData);
}


void intel_AES_enc192_CBC(UCHAR *plainText,UCHAR *cipherText,UCHAR *key,size_t numBlocks,UCHAR *iv)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iEncExpandKey192(key,expandedKey);
	iEnc192_CBC(&aesData);
}


void intel_AES_enc256(UCHAR *plainText,UCHAR *cipherText,UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iEncExpandKey256(key,expandedKey);
	iEnc256(&aesData);
}


void intel_AES_enc256_CBC(UCHAR *plainText,UCHAR *cipherText,UCHAR *key,size_t numBlocks,UCHAR *iv)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iEncExpandKey256(key,expandedKey);
	iEnc256_CBC(&aesData);
}

void intel_AES_dec128(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iDecExpandKey128(key,expandedKey);
	iDec128(&aesData);
}

void intel_AES_dec128_CBC(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t numBlocks,UCHAR *iv)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iDecExpandKey128(key,expandedKey);
	iDec128_CBC(&aesData);
}


void intel_AES_dec192(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iDecExpandKey192(key,expandedKey);
	iDec192(&aesData);
}


void intel_AES_dec192_CBC(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t numBlocks,UCHAR *iv)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iDecExpandKey192(key,expandedKey);
	iDec192_CBC(&aesData);
}


void intel_AES_dec256(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iDecExpandKey256(key,expandedKey);
	iDec256(&aesData);
}


void intel_AES_dec256_CBC(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t numBlocks,UCHAR *iv)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;
	
	iDecExpandKey256(key,expandedKey);
	iDec256_CBC(&aesData);
}

int intel_AES_dec256_CBC_pad(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t numBlocks,UCHAR *iv,int pad)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	char *out;
	int written, fail;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;
	written = numBlocks*16;
	iDecExpandKey256(key,expandedKey);
	iDec256_CBC(&aesData);
    if (pad) {
		fail = 0;
		out = (char*)(plainText+written);
        unsigned char padsize = *--out;
        fail = !padsize | (padsize > 16);
        padsize *= !fail;
        for (int i = 16; i != 0; i--)
            fail |= ((i > 16 - padsize) & (*out-- != padsize));
		
        written -= padsize;
    }
    return written * !fail;
}

void intel_AES_encdec256_CTR(UCHAR *in,UCHAR *out,UCHAR *key,size_t numBlocks,UCHAR *ic)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = in;
	aesData.out_block = out;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = ic;

	iEncExpandKey256(key,expandedKey);
	iEnc256_CTR(&aesData);
}


void intel_AES_encdec192_CTR(UCHAR *in,UCHAR *out,UCHAR *key,size_t numBlocks,UCHAR *ic)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = in;
	aesData.out_block = out;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = ic;

	iEncExpandKey192(key,expandedKey);
	iEnc192_CTR(&aesData);
}


void intel_AES_encdec128_CTR(UCHAR *in,UCHAR *out,UCHAR *key,size_t numBlocks,UCHAR *ic)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = in;
	aesData.out_block = out;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = ic;

	iEncExpandKey128(key,expandedKey);
	iEnc128_CTR(&aesData);
}


int enc_128_CBC(unsigned char *pt, unsigned char *ct, unsigned char *key, unsigned char *iv, int numBlocks)
{
	unsigned int buffer_size =  numBlocks * BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_128_KEYSIZE];
	UCHAR _iv[BLOCK_SIZE];
	UCHAR *plaintext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_key[i] = key[i];
		_iv[i] = iv[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		plaintext[i] = pt[i];
	}

	intel_AES_enc128_CBC(plaintext, ct, _key, numBlocks, _iv);
	return 0;
}


int dec_128_CBC(unsigned char *ct, unsigned char *pt, unsigned char *key, unsigned char *iv, int numBlocks){
	
	unsigned int buffer_size =  numBlocks * BLOCK_SIZE;
	unsigned int i;
	
	UCHAR _key[AES_128_KEYSIZE];
	UCHAR _iv[BLOCK_SIZE];
	UCHAR *ciphertext = (UCHAR*)_alloca(buffer_size);
	
	for (i=0;i<BLOCK_SIZE;i++)
	{
		_key[i] = key[i];
		_iv[i] = iv[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		ciphertext[i] = ct[i];
	}

  	intel_AES_dec128_CBC(ciphertext, pt, _key, numBlocks, _iv);
	return 0;
}


int enc_192_CBC(unsigned char *pt, unsigned char *ct, unsigned char *key, unsigned char *iv, int numBlocks)
{
	unsigned int buffer_size =  numBlocks * BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_192_KEYSIZE];
	UCHAR _iv[BLOCK_SIZE];
	UCHAR *plaintext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_iv[i] = iv[i];
	}
	
	for (i=0;i<AES_192_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		plaintext[i] = pt[i];
	}

	intel_AES_enc192_CBC(plaintext, ct, _key, numBlocks, _iv);

	return 0;

}

int dec_192_CBC(unsigned char *ct, unsigned char *pt, unsigned char *key, unsigned char *iv, int numBlocks){
	
	unsigned int buffer_size =  numBlocks * BLOCK_SIZE;
	unsigned int i;
	
	UCHAR _key[AES_192_KEYSIZE];
	UCHAR _iv[BLOCK_SIZE];
	UCHAR *ciphertext = (UCHAR*)_alloca(buffer_size);
	
	for (i=0;i<BLOCK_SIZE;i++)
	{
		_iv[i] = iv[i];
	}

	for (i=0;i<AES_192_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		ciphertext[i] = ct[i];
	}

  	intel_AES_dec192_CBC(ciphertext, pt, _key, numBlocks, _iv);
	return 0;
}


int enc_256_CBC(unsigned char *pt, unsigned char *ct, unsigned char *key, unsigned char *iv, int numBlocks)
{
	unsigned int buffer_size =  numBlocks * BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_256_KEYSIZE];
	UCHAR _iv[BLOCK_SIZE];
	UCHAR *plaintext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_iv[i] = iv[i];
	}
	
	for (i=0;i<AES_256_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		plaintext[i] = pt[i];
	}

	intel_AES_enc256_CBC(plaintext, ct, _key, numBlocks, _iv);
	return 0;
}


int dec_256_CBC(unsigned char *ct, unsigned char *pt, unsigned char *key, unsigned char *iv, int numBlocks){
	
	unsigned int buffer_size =  numBlocks * BLOCK_SIZE;
	unsigned int i;
	
	UCHAR _key[AES_256_KEYSIZE];
	UCHAR _iv[BLOCK_SIZE];
	UCHAR *ciphertext = (UCHAR*)_alloca(buffer_size);
	
	for (i=0;i<BLOCK_SIZE;i++)
	{
		_iv[i] = iv[i];
	}

	for (i=0;i<AES_256_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		ciphertext[i] = ct[i];
	}

  	intel_AES_dec256_CBC(ciphertext, pt, _key, numBlocks, _iv);
	return 0;
}

int enc_128_CTR(unsigned char *pt, unsigned char *ct, unsigned char *key, unsigned char *ic, int numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_128_KEYSIZE];
	UCHAR _ic[BLOCK_SIZE];
	UCHAR *plaintext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_key[i] = key[i];
		_ic[i] = ic[i];
	}
	for (i=0;i<buffer_size;i++)
	{
		plaintext[i] = pt[i];
	}

	intel_AES_encdec128_CTR(plaintext, ct, _key, numBlocks, _ic);
	
	return 0;
}


int dec_128_CTR(unsigned char *ct, unsigned char *pt, unsigned char *key, unsigned char *ic, int numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_128_KEYSIZE];
	UCHAR _ic[BLOCK_SIZE];
	UCHAR *ciphertext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_key[i] = key[i];
		_ic[i] = ic[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		ciphertext[i] = ct[i];
	}

	intel_AES_encdec128_CTR(ciphertext, pt, _key, numBlocks, _ic);

	return 0;
}

int enc_192_CTR(unsigned char *pt, unsigned char *ct, unsigned char *key, unsigned char *ic, int numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_192_KEYSIZE];
	UCHAR _ic[BLOCK_SIZE];
	UCHAR *plaintext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_ic[i] = ic[i];
	}

	for (i=0;i<AES_192_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		plaintext[i] = pt[i];
	}

	intel_AES_encdec192_CTR(plaintext, ct, _key, numBlocks, _ic);

	return 0;
}

int dec_192_CTR(unsigned char *ct, unsigned char *pt, unsigned char *key, unsigned char *ic, int numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_192_KEYSIZE];
	UCHAR _ic[BLOCK_SIZE];
	UCHAR *ciphertext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_key[i] = key[i];
		_ic[i] = ic[i];
	}

	for (i=0;i<AES_192_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		ciphertext[i] = ct[i];
	}

	intel_AES_encdec192_CTR(ciphertext, pt, _key, numBlocks, _ic);

	return 0;
}


int enc_256_CTR(unsigned char *pt, unsigned char *ct, unsigned char *key, unsigned char *ic, int numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_256_KEYSIZE];
	UCHAR _ic[BLOCK_SIZE];
	UCHAR *plaintext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_ic[i] = ic[i];
	}

	for (i=0;i<AES_256_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		plaintext[i] = pt[i];
	}

	intel_AES_encdec128_CTR(plaintext, ct, _key, numBlocks, _ic);

	return 0;
}

int dec_256_CTR(unsigned char *ct, unsigned char *pt, unsigned char *key, unsigned char *ic, int numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_256_KEYSIZE];
	UCHAR _ic[BLOCK_SIZE];
	UCHAR *ciphertext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_ic[i] = ic[i];
	}

	for (i=0;i<AES_256_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		ciphertext[i] = ct[i];
	}

	intel_AES_encdec128_CTR(ciphertext, pt, _key, numBlocks, _ic);

	return 0;
}
