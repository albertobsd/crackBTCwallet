/*

develop by Luis Alberto
email: alberto.bsd@gmail.com

This file depends of libaesni with a custom changes
For Fastessssst AES Decryption:
https://github.com/amiralis/libaesni
*/

#include "libaesni_custom/iaes_asm_interface.h"
#include "libaesni_custom/iaesni.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include "util.h"
#include "ctaes/ctaes.h"

#define AES_BLOCKSIZE 16

#define CPUMODE_AESNI 1
#define CPUMODE_LEGACY 2

//void intHandler(int dummy);
void *thread_process_legacy(void *vargp);
void *thread_process(void *vargp);
void *thread_timer(void *vargp);

void tryKey(char *key);
void tryKey_legacy(char *key);
/*
  the padding must by constant and NOT NEED TO BE CHANGE
*/
const unsigned char *padding = (const unsigned char *)"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";
const char *version = "0.1.20211123";

/*Global Values*/

int found = 0;
FILE *devurandom;

pthread_t *tid = NULL;
unsigned int *steps = NULL;

int seconds = 0;
pthread_mutex_t read_random;

int DEBUGCOUNT = 0x100000;
int NTHREADS = 3;
int RANDOMLEN = 65536;
int RANDOMLENFOR = 65504;
int STATUS = 0;
int QUIET = 0;
int RANDOMSOURCE = 0;
int CPUMODE;

const char *commands1[8] = {"start","pause","continue","stats","exit","about","help","version"};
const char *commands3[3] = {"load","set","try"};
const char *params_set[5] = {"threads","randombuffer","debugcount","quiet","randomsource"};
const char *params_load[3] = {"ckey","mkey","file"};

List ckeys_list;

int main()  {
  FILE *input;
  Tokenizer t;
  pthread_t timerid;
  char *temp,*token,*aux,*line;
  //signal(SIGINT, intHandler);
  int *tothread = NULL;
  uint64_t total;
  int i,s,salir,param;
  int AES_ENABLED = check_for_aes_instructions();
  if (AES_ENABLED != 1){
    printf("No Intel AESni enabled, fall back to legacy mode\n");
    CPUMODE = CPUMODE_LEGACY;
  }
  else  {
    CPUMODE = CPUMODE_AESNI;
  }

  memset(&ckeys_list,0,sizeof(List));
  seconds = 0;
  line = malloc(1024);
  salir = 0;
  input = stdin;

  printf("Developed by AlbertoBSD. I wish you very good luck!!\n");
  do {
	if(input == stdin)	{
		printf("crackBTC > ");
	}
	else	{
		if(feof(input))	{
			fclose(input);
			printf("crackBTC > ");
			input = stdin;
		}
	}
    temp = fgets(line,1024,input);
    if(temp == line)  {
      stringtokenizer(line,&t);
      switch(t.n)  {
      /*
        load ckey <data>
        load mkey <data>
        set threads <N>
        set randombuffer <N>
        try key <key>
      */
      case 3:
        token = nextToken(&t);
        switch(indexOf(token,commands3,3))  {
        case 0://LOAD
          token = nextToken(&t);
		  aux = nextToken(&t);
		  switch(indexOf(token,params_load,3))	{
			  case 0://ckey
			  case 1://mkey
				  if(strlen(aux) == 96)  {
					if(isValidHex(aux))  {
					  temp = (char*) malloc(48);
					  hexs2bin(aux,(unsigned char*)temp);
					  addItemList(temp,&ckeys_list);
					  printf("Adding %s to the list\n",aux);
					}
					else  {
					  printf("Invalid hex string :%s\n",aux);
					}
				  }
				  else  {
					printf("Invalid length\n");
				  }
			  break;
			  case 2://file
				input = fopen(aux,"rb");
				if(input == NULL)	{
					printf("Could not load the %s file\n",aux);
					input = stdin;
				}
				else	{
					printf("loading %s\n",aux);
				}
			  break;
			  default:
				printf("Unknow value %s\n",token);
			  break;
		  }

        break;
        case 1://SET
          token = nextToken(&t);
          aux = nextToken(&t);
          param = strtol(aux,NULL,10);
          switch(indexOf(token,params_set,5))  {
			  case 0: //threads
				if(param > 0 && param < 32) {
				  NTHREADS = param;
				}else  {
				  printf("Invalid threads number\n");
				}
			  break;
			  case 1: //randombuffer
				if(param > 31 && param < 1024*1024) {
				  RANDOMLEN = param;
				  RANDOMLENFOR = param - 32;
				}else  {
				  printf("Invalid bufferlengt number\n");
				}
			  break;
			  case 2: //debugcount
				if(param > 0) {
				  DEBUGCOUNT = param;
				}else  {
				  printf("Invalid bufferlengt number\n");
				}
			  break;
			  case 3: //QUIET
				  QUIET = param;
			  break;
			  case 4: //Random Source
				  RANDOMSOURCE = param;
			  break;

			  default:
				printf("Unknow value %s\n",token);
			  break;
          }
        break;
        case 2: //TRY
          token = nextToken(&t);
          aux = nextToken(&t);
          if(strlen(aux) == 64)  {
      			if(isValidHex(aux))  {
      			  temp = (char*) malloc(32);
      			  hexs2bin(aux,(unsigned char*)temp);
              switch(CPUMODE) {
                case CPUMODE_AESNI:
                  tryKey(temp);
                break;
                case CPUMODE_LEGACY:
                  tryKey_legacy(temp);
                break;
              }
      			  free(temp);
      			}
      			else  {
      			  printf("Invalid hex string :%s\n",aux);
      			}
          }
          else  {
              printf("Invalid length\n");
          }
        break;
        default:
          printf("Unknow command %s\n",token);
        break;
        }
      break;
      /*
        start
        pause
        continue
        stats
        exit
      */
      case 1:
        token = nextToken(&t);
        switch(indexOf(token,commands1,8))  {
          case 0:  //start
          if(STATUS == 0)  {
      			STATUS = 1;
      			/*
      			devurandom file descriptor for all the threads,
      			*/
    				devurandom = fopen("/dev/urandom","rb");

      			if(devurandom == NULL )  {
      				printf("Could not open random source\n");
      				exit(0);
      			}

      			steps = (unsigned int *) calloc(NTHREADS,sizeof(int));
      			tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));
      			s = pthread_create(&timerid,NULL,thread_timer,NULL);
      			if(s != 0)  {
      				perror("pthread_create thread_timer");
      			}

      			/* start thread */
      			/* thread related stuff */
      			for(i= 0;i < NTHREADS; i++)  {
      				printf("Starting a random thread!\n");
      				tothread = (int*) malloc(sizeof(int)*2);
      				tothread[0] = i;
              switch(CPUMODE) {
                case CPUMODE_AESNI:
                  s = pthread_create(&tid[i],NULL,thread_process,(void *)tothread);
                break;
                case CPUMODE_LEGACY:
                  s = pthread_create(&tid[i],NULL,thread_process_legacy,(void *)tothread);
                break;
              }
      				if(s != 0)  {
      					perror("pthread_create thread_process");
      				}
      			}
          }
          else  {
            printf("The program is actually running\n");
          }
        break;
        case 1:  //pause
        break;
        case 2: //continue
        break;
        case 3:  //stats
          if(STATUS == 1)  {
      			total = 0;
      			for(i = 0; i < NTHREADS;i++)	{
      				total += (uint64_t)((uint64_t)steps[i] * (uint64_t)DEBUGCOUNT);
      			}
            printf("AES256 block operations %.0f/s\n",(double) ((uint64_t)total/seconds));
          }
          else  {
            printf("The program is NOT running\n");
          }
        break;
        case 4:  //exit
          salir = 1;
        break;
        case 5:  //about
          printf("Developed by AlbertoBSD\nTwitter: @albertobsd\nDonate BTC: 1H3TAVNZFZfiLUp9o9E93oTVY9WgYZ5knX\n");
        break;
        case 6:  //help
        break;
        case 7:  //version
          printf("Version: %s\n",version);
        break;
        default:
          printf("Unknow command %s\n",token);
        break;
        }
      break;
      default:
        printf("Unknow command %s\n",line);
      break;
      }
    }
    freetokenizer(&t);
  }while(!found && !salir );
  if(STATUS == 1)
    fclose(devurandom);
}

void *thread_timer(void *vargp)  {
  seconds = 0;
  do  {
    sleep(1);
    seconds+=1;
  }while(!found);
  pthread_exit(NULL);
}

/*
  random crack thread
*/
void *thread_process(void *vargp)  {
  DEFINE_ROUND_KEYS
  sAesData aesData;
  uint64_t count;
  FILE *file_output;
  int *aux = (int *)vargp;
  int thread_number,entrar,i,j;
  char *decipher_key = NULL,*key_material,*random_buffer,*temp;
  thread_number = aux[0];

  decipher_key = (char *) malloc(48);
  random_buffer = (char *) malloc(RANDOMLEN);

  /* Custom aesData to save some critical steps in ASM */
  aesData.expanded_key = expandedKey;
  aesData.num_blocks = 1;
  aesData.out_block = (unsigned char *)decipher_key;


  steps[thread_number] = 0;
  count = 1;  // Just to skip the firts debug output of (0 % 0x100000 == 0)  is true
  entrar = 1;
  do{
    pthread_mutex_lock(&read_random);
    fread(random_buffer,1,RANDOMLEN,devurandom);

    pthread_mutex_unlock(&read_random);
    for(i = 0; i < RANDOMLENFOR && entrar && !found ; i++)  {

      key_material = random_buffer+i;
	  /*
        We are recycled the expandedKey to use it with many ckeys or mkeys as possible this proccess also save a lot of CPU power
      */
      iDecExpandKey256((unsigned char*)key_material,expandedKey);


      for(j = 0; j < ckeys_list.n; j++){
        if(count % DEBUGCOUNT  == 0 )  {
		  steps[thread_number]++;  //This is just for the stats information
		  if(!QUIET){
			  temp = tohex(key_material,32);
			  printf("Thread %i, current Key: %s\n",thread_number,temp);
			  free(temp);
		  }

        }
        /*
        We have a three cipher blocks : C = [C0, C1, C2]
        We only need decrypt the last block of cipher text, in this case is C2
        The IV in this case is the previous block, in this case is C1

        Decipher text should be equals to padding [0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10] if not, the key tested is incorrect

         C1 is from 0 to 15
         C2 is from 16 to 31
         C3 is from 31 to 47

         We only do one single block Decrypt per Mkey or Ckey instead of 3 decrypts, this save a lot of CPU power
        */


        aesData.in_block = (unsigned char *)ckeys_list.data[j]+32;  //C3
        aesData.iv = (unsigned char *)ckeys_list.data[j]+16;    //C2
        // For CBC the previous cipher block is our IV except for the C1 Block in this case the IV is the Orignal IV,


        imyDec256_CBC(&aesData);  //Custom function dont use this for more than one Cipher block

        if(memcmp(decipher_key,padding,16) == 0 )  {
          printf("Posible Key found\n");
          file_output = fopen("./key_found.txt","wb");
          temp = tohex(key_material,32);
          printf("Thread %i key_material: %s\n",thread_number,temp);
          fprintf(file_output,"Thread %i key_material: %s\n",thread_number,temp);
          free(temp);
          temp = tohex(ckeys_list.data[j],48);
          fprintf(file_output,"Thread %i cipher_texts: %s\n",thread_number,temp);
          free(temp);
          fclose(file_output);
          found = 1;
          entrar = 0;
        }

        count++;
      }

    }  //end While
  }while(entrar && !found);
  free(decipher_key);
  pthread_exit(NULL);
}

void tryKey(char *key)  {
  DEFINE_ROUND_KEYS
  sAesData aesData;
  int j;
  char *decipher_key = NULL,*key_material,*temp;
  decipher_key = (char *) malloc(48);
  aesData.expanded_key = expandedKey;
  aesData.num_blocks = 1;
  aesData.out_block = (unsigned char *)decipher_key;
  key_material = key;
  iDecExpandKey256((unsigned char*)key_material,expandedKey);
  for(j = 0; j < ckeys_list.n; j++){
  	aesData.in_block = (unsigned char *)ckeys_list.data[j]+32;  //C3
  	aesData.iv = (unsigned char *)ckeys_list.data[j]+16;    //C2
  	imyDec256_CBC(&aesData);
  	if(memcmp(decipher_key,padding,16) == 0 )  {
  	  printf("Posible Key found\n");
  	  temp = tohex(key_material,32);
  	  printf("key_material: %s\n",temp);
  	  free(temp);
  	  temp = tohex(ckeys_list.data[j],48);
  	  printf("For ckey or mkey: %s\n",temp);
  	  free(temp);
  	}
  }
  free(decipher_key);
}

/*
  Same as tryKey but for NO AESni devices
*/
void tryKey_legacy(char *key)  {
  AES256_ctx ctx;
  int i,j;
  char *decipher_key = NULL,*temp,*iv;
  decipher_key = (char *) malloc(16);
  AES256_init(&ctx,(const unsigned char*) key);
  for(j = 0; j < ckeys_list.n; j++) {
  	iv = ckeys_list.data[j]+16;
    AES256_decrypt(&ctx, 1,( unsigned char *) decipher_key,(const unsigned char *) ckeys_list.data[j]+32);
    for (i = 0; i != AES_BLOCKSIZE; i++)  {
      decipher_key[i] ^= iv[i];
    }
  	if(memcmp(decipher_key,padding,16) == 0 )  {
  	  printf("Posible Key found\n");
  	  temp = tohex(key,32);
  	  printf("key_material: %s\n",temp);
  	  free(temp);
  	  temp = tohex(ckeys_list.data[j],48);
  	  printf("For ckey or mkey: %s\n",temp);
  	  free(temp);
  	}
  }
  free(decipher_key);
}


void *thread_process_legacy(void *vargp)  {
  AES256_ctx ctx;
  uint64_t count;
  FILE *file_output;
  int *aux = (int *)vargp;
  int thread_number,entrar,i,j,k;
  char *decipher_key = NULL,*key_material,*random_buffer,*temp,*iv;
  thread_number = aux[0];

  decipher_key = (char *) malloc(16);
  random_buffer = (char *) malloc(RANDOMLEN);

  steps[thread_number] = 0;
  count = 1;  // Just to skip the firts debug output of (0 % 0x100000 == 0)  is true
  entrar = 1;
  do{
    pthread_mutex_lock(&read_random);
    fread(random_buffer,1,RANDOMLEN,devurandom);
    pthread_mutex_unlock(&read_random);

    for(i = 0; i < RANDOMLENFOR && entrar && !found ; i++)  {

      key_material = random_buffer+i;
	     /*
        We are recycled the key_material to use it with many ckeys or mkeys as possible this proccess also save a lot of CPU power
      */
      AES256_init(&ctx,(const unsigned char*) key_material);

      for(j = 0; j < ckeys_list.n; j++){
        if(count % DEBUGCOUNT  == 0 )  {
    		  steps[thread_number]++;  //This is just for the stats information
    		  if(!QUIET){
    			  temp = tohex(key_material,32);
    			  printf("Thread %i, current Key: %s\n",thread_number,temp);
    			  free(temp);
    		  }
        }

        iv = ckeys_list.data[j]+16;
        AES256_decrypt(&ctx, 1,( unsigned char *) decipher_key,(const unsigned char *) ckeys_list.data[j]+32);
        for (k = 0; k != AES_BLOCKSIZE; k++){
          decipher_key[k] ^= iv[k];
        }

        if(memcmp(decipher_key,padding,16) == 0 )  {
          printf("Posible Key found\n");
          file_output = fopen("./key_found.txt","wb");
          temp = tohex(key_material,32);
          printf("Thread %i key_material: %s\n",thread_number,temp);
          fprintf(file_output,"Thread %i key_material: %s\n",thread_number,temp);
          free(temp);
          temp = tohex(ckeys_list.data[j],48);
          fprintf(file_output,"Thread %i cipher_texts: %s\n",thread_number,temp);
          free(temp);
          fclose(file_output);
          found = 1;
          entrar = 0;
        }
        count++;
      }
    }  //end While
  }while(entrar && !found);
  free(decipher_key);
  pthread_exit(NULL);
}
