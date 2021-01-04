/*
	develop by Luis Alberto
	Twitter: @albertobsd
	email: alberto.bsd@gmail.com

	gcc -O3 -c rmd160.c -o rmd160.o
	gcc -O3 -o get_mkey_ckey get_mkey_ckey.c base58.o sha256.o rmd160.o
	Warning:
	I don't know why there some ckeys string "ckeys" in the wallet that doesn't get decrypted by the master key
	If you know please letme know why
*/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include "sha256.h"
#include "rmd160.h"
#include "libbase58.h"


char *tohex(char *ptr,int length);
char *pubkeytopubaddress(char *pkey,int length);

int main(int argc, char **argv)	{
	if(argc < 2 )	{
		printf("usage: %s wallet.dat\n\n",argv[0]);
		exit(0);
	}
	int mkey_offset;
	char *mkey_data, *hex;
	char *ckey_data,*ckey_encrypted,*ckey_publickey,*public_address;
	unsigned char b;
	char mkey[5];
	int count;
	int i = 0;
	int entrar = 1;
	FILE *wallet = fopen(argv[1],"rb");
	if(wallet ==NULL)	{
		fprintf(stderr,"Can't open file %s\n",argv[1]);
	}
	mkey_data = malloc(48);
	ckey_data = malloc(123);
	ckey_encrypted = malloc(48);

	while(fread(mkey,1,4,wallet) == 4 && !feof(wallet) && entrar )	{
		if(strncmp(mkey,"mkey",4) == 0 )	{
			mkey_offset = i;
			//printf("mkey was found @ %i : 0x%x\n",mkey_offset,mkey_offset);
			entrar = 0;
		}
		i++;
		fseek(wallet,i,SEEK_SET);
	}
	if(entrar == 0)	{
		fseek(wallet,mkey_offset -72,SEEK_SET);
		fread(mkey_data,1,48,wallet);
		hex = tohex(mkey_data,48);
		printf("Mkey_encrypted: %s\n",hex);
		free(hex);
	}
	else{
		printf("There is no Master Key in the file\n");
		exit(0);
	}
	fseek(wallet,0,SEEK_SET);
	count = 0;
	i = 0;
	while(fread(mkey,1,4,wallet) == 4 && !feof(wallet) )	{
		if(strncmp(mkey,"ckey",4) == 0 )	{
			mkey_offset = i;
			fseek(wallet,mkey_offset -52,SEEK_SET);
			fread(ckey_data,1,123,wallet);
			memcpy(ckey_encrypted,ckey_data,48);
			memcpy(&b,ckey_data+56,1);	//how many bytes are the ckey_publickey
			ckey_publickey = malloc(b);
			memcpy(ckey_publickey,ckey_data+57,b);

			hex = tohex(ckey_encrypted,48);
			printf("encrypted ckey: %s\n",hex);
			free(hex);

			hex = tohex(ckey_publickey,b);
			printf("public key    : %s\n",hex);

			public_address = pubkeytopubaddress(ckey_publickey,(int)b);
			printf("public address: %s\n\n",public_address);

			free(public_address);
			free(hex);
			free(ckey_publickey);

			count++;

			i+=3;
		}
		i++;
		fseek(wallet,i,SEEK_SET);
	}
	//printf("%i ckey were found\n",count);
	fclose(wallet);
	return 0;
}

char *tohex(char *ptr,int length){
  char *buffer;
  int offset = 0;
  unsigned char c;
  buffer = (char *) malloc((length * 2)+1);
  for (int i = 0; i <length; i++) {
    c = ptr[i];
	sprintf(buffer + offset,"%.2x",c);
	offset+=2;
  }
  buffer[length*2] = 0;
  return buffer;
}


char *pubkeytopubaddress(char *pkey,int length)	{
	char *pubaddress = calloc(100,1);
	char *digest = malloc(60);
	long unsigned int pubaddress_size = 100;
	if(pubaddress == NULL || digest == NULL)	{
		fprintf(stderr,"error malloc()\n");
		exit(0);
	}
	memset(digest,0,60);
	//digest [000...0]
 	sha256(pkey, length, digest);
	//digest [SHA256 32 bytes+000....0]
	RMD160Data(digest,32, digest+1);
	//digest [? +RMD160 20 bytes+????000....0]
	digest[0] = 0;
	//digest [0 +RMD160 20 bytes+????000....0]
	sha256(digest, 21, digest+21);
	//digest [0 +RMD160 20 bytes+SHA256 32 bytes+....0]
	sha256(digest+21, 32, digest+21);
	//digest [0 +RMD160 20 bytes+SHA256 32 bytes+....0]
	if(!b58enc(pubaddress,&pubaddress_size,digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
	free(digest);
	return pubaddress;	// pubaddress need to be free by te caller funtion
}
