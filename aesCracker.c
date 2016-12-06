#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <math.h>
#include "aes.h"

#define MAX_CHARS 128
#define DICTIONARY_LEN 9500
#define true 1
#define false 0
#define NUM_THREADS 256
#define SIZE 64

typedef char string[MAX_CHARS+1];

//Define what the thread contains
typedef struct threadData{
    uint8_t key[16];
    uint8_t ciphertext[64];
    uint64_t keyCount;
} threadData;

//Stuff for threading
pthread_t threads[NUM_THREADS];
threadData threadDataArray[NUM_THREADS];
pthread_attr_t attr;
pthread_mutex_t lock;
pthread_mutex_t funclock;
int globalCheck;
void *status;

//Dictionary which contains some possible words
string dictionary[DICTIONARY_LEN];

// int inRange(uint8_t *buffer){
// 	int i;
// 	for(i = 0; i < 16; i++){
// 		int temp = (int)buffer[i];
// 		if (32 < temp && temp < 123){
// 			continue;
// 		} else {
// 			return false;
// 		}
// 	}
// 	return true;
// }

int getMaxValue(uint8_t *buffer){
	int i;
	int max = 0;
	for(i = 0; i < 16; i++){
		int temp = (int)buffer[i];
		if (max < temp)
			max = temp;
	}
	return max;
}



void incrementKey(uint8_t* key){
	int max = 0XFF;
	int min = 0x00;
	int i;
	for(i = 15; i > -1; i--){
		if(key[i] < max){
			key[i]++;
			return;
		} else {
			key[i] = min;
		}
	}
}

//Parallel function
void *decryptParallel(void *t){
	uint64_t i, j;
	threadData *tData = (threadData *)t;
	uint8_t key[16] = {0x00};
	uint8_t ciphertext[SIZE] = {0x00};
	for(i = 0; i < 16; i++){
		key[i] = tData->key[i];
	}
	for(i = 0; i < SIZE; i++){
		ciphertext[i] = tData->ciphertext[i];
	}
	uint64_t keyCount = tData->keyCount;

	for(j = 0; j < keyCount; j++){

		// for(i = 0; i < 16; i++){
		// 	printf("%d, ", key[i]);
		// }
		// printf("\n");

		//check to see if the global variable is true;
		if(globalCheck){
			pthread_exit(NULL);
		}
		//printf("%d\n", j);
		uint8_t buffer[SIZE];

		int fail = false;
		for(i = 0; i<(SIZE); i+=16){
			//pthread_mutex_lock(&funclock);
	  		AES128_ECB_decrypt(ciphertext+i, key, buffer+i);
	  		//pthread_mutex_unlock(&funclock);
	  		int max = getMaxValue(buffer+i);
	  		if (max>122){
	  			incrementKey(key);
	  			fail = true;
	  			break;
	  		}
	
	  	}
	  	if (fail){
	  		continue;
	  	}

	    //Save buffer to plaintext 
	  	char *plaintext = (char *)(intptr_t)buffer;
	  	for(i = 0; i < SIZE; i++){
	  		plaintext[i] = tolower(plaintext[i]);
		}

		int count = 0;
		for(i = 0; i < DICTIONARY_LEN; i++){
	  		if(strstr(plaintext, dictionary[i]) != NULL){
	  			//printf("Plaintext contains a word '%s'\n", dictionary[i]);
	  			count++;
	  		}
	  		//If no valid words are found
	  		//printf("%d\n", count);
	  		if (i == DICTIONARY_LEN-1 && count == 0){
	  			incrementKey(key);
	  			fail = true;
	  			break;
	  		}
	  	}
	  	if (fail){
	  		continue;
	  	}

	  	printf("Decryption Successful!\n");
	  	printf("Plaintext = %s\n", plaintext);
	  	
	  	//Make the global variable true
	  	pthread_mutex_lock(&lock);
	  	globalCheck = true;
	  	pthread_mutex_unlock(&lock);
	  	break;
	 }
	 pthread_exit(NULL);
}

int main(){
	
	int i, j;
	globalCheck = false;

	pthread_mutex_init(&lock, NULL);
	pthread_mutex_init(&funclock, NULL);
	
	
	FILE *myfile; //Here we will read from the words.txt file
	myfile = fopen("words.txt", "r");
	for(i = 0; i < DICTIONARY_LEN; i++){
		fscanf(myfile, "%s", dictionary[i]);
	}
	fclose(myfile);


	//CIPHERTEXT and KEY 3
	// uint8_t initVector[] = {0x0A, 0xA4, 0xA9, 0x10, 0xD4, 0x51, 0xE0, 0x69, 0x61, 0x1D, 0x55, 0x71};
	// uint8_t ciphertext[] = {0x57, 0x4D, 0xD2, 0x38, 0x07, 0x0E, 0xC6, 0x6A, 0x02, 0x7F, 0x12, 0x0B, 0x3D, 0x67, 0xA4, 0xB1, 0xFF, 0x20, 0xD1, 0xAA, 0xD5, 0x28, 0x93,
	// 						0xCD, 0x29, 0x70, 0xE7, 0x6B, 0xE7, 0x3A, 0x2C, 0x4A, 0xE8, 0xAE, 0x87, 0xD1, 0xDC, 0x4C, 0xD4, 0xE6, 0xCE, 0x37, 0x33, 0xA2, 0x7D, 0x40,
	// 						0x13, 0x39, 0xE1, 0xE2, 0xA3, 0xFA, 0x9A, 0x0E, 0x86, 0x82, 0x92, 0x84, 0xCA, 0xCD, 0x5A, 0x85, 0x0B, 0xCD};

	//CIPHERTEXT and KEY 1
	// uint8_t initVector[] = {0x63, 0x94, 0x04, 0xCB, 0xD1, 0xA1, 0xBD, 0x23, 0x22, 0xB2, 0x06, 0xC3, 0x91, 0x40};
	// uint8_t ciphertext[] = {0x5A, 0x05, 0x2F, 0x92, 0x84, 0x64, 0xCC, 0x3E, 0x43, 0x71, 0x87, 0xAD, 0xCF, 0xC7, 0xE8, 0xF1, 0xCF, 0x9D, 0xEA, 0xC7, 
	// 							0x05, 0x9B, 0x52, 0x64, 0xE4, 0xE9, 0x40, 0xD8, 0xC3, 0x5A, 0xA6, 0x0E, 0x22, 0x77, 0xD4, 0x83, 0x28, 0x43, 0x04, 0x3F, 0x59,
	// 							0x3F, 0x40, 0xE4, 0x08, 0x46, 0x09, 0xC8, 0x86, 0x68, 0x1B, 0xCF, 0x5B, 0x57, 0x0D, 0x35, 0x3B, 0xFF, 0x24, 0xC0, 0xE1, 0xF4, 0xA6, 0x5E};
	
	//Original test key and ciphertext
	//uint8_t initVector[] = {0x6F, 0x1C, 0x5C, 0xD9, 0x27, 0x0A, 0xC8, 0xDD, 0xEA, 0xE6, 0x43, 0x0F, 0x30, 0x96};
  	//uint8_t ciphertext[] = {0x11, 0x37, 0x59, 0x0E, 0x76, 0x02, 0x25, 0x6E, 0x37, 0xFC, 0xD3, 0x68, 0x55, 0xCC, 0x93, 0x53,0xC1, 0xF2, 0xC2, 0x11, 0x71, 0xF2, 0xEC, 0x03, 0x91, 0xBE, 0xEE, 0x9A, 0x0A, 0x19, 0xB0, 0x84};
  	

  	//CIPHERTEST and KEY 2
	// uint8_t initVector[] = {0xF8, 0x06, 0x27, 0x4A, 0xC0, 0xB4, 0x46, 0xC1, 0x87, 0x25, 0xAB, 0xDC, 0xE5};
	// uint8_t ciphertext[] = {0x9D, 0x73, 0x6A, 0xD6, 0x4E, 0xFE, 0x15, 0x3E, 0x6B, 0xED, 0xE6, 0x89, 0x77, 0x29, 0x76, 0xED, 0x83, 0xFB, 0x89, 0xD0, 0x50, 0x3B,
	// 						0x27, 0xE7, 0xB4, 0xE2, 0xC4, 0xCD, 0xBE, 0x7B, 0x3B, 0xD9, 0xC1, 0xCE, 0x5E, 0x80, 0x0D, 0x39, 0x29, 0xE5, 0x43, 0xC3, 0xAD,
	// 						0x1B, 0x0D, 0x86, 0x29, 0x90, 0xD7, 0xBC, 0xF7, 0x7B, 0x74, 0xA1, 0x26, 0xE2, 0x7F, 0x59, 0x01, 0xEE, 0xFC, 0x50, 0x44, 0xBA};


	//CIPHERTEST and KEY 4
	uint8_t initVector[] = {0x9D, 0x0B, 0x18, 0x0B, 0x5C, 0xD9, 0xDC, 0x07, 0x4A, 0xCB, 0x0E};
	uint8_t ciphertext[] = {0x71, 0x02, 0x10, 0x84, 0x59, 0xF8, 0xB9, 0x72, 0x68, 0x87, 0x03, 0x44, 0x91, 0xC1, 0xB4, 0x09, 0xC2, 0x9B, 0xF9, 0x0C, 0xD1,
							0x89, 0x5B, 0x80, 0x81, 0x5A, 0xBF, 0x24, 0x34, 0xDD, 0x57, 0x32, 0x7C, 0xDF, 0xF1, 0x6B, 0x9C, 0xF0, 0xC9, 0x0C, 0x5F, 0x39,
							0xCC, 0x92, 0xFC, 0x6E, 0xF9, 0x9C, 0xDD, 0xE1, 0xD0, 0xFA, 0x90, 0x23, 0x6F, 0x94, 0x74, 0xDF, 0x14, 0x2B, 0x6B, 0xF1, 0xB6, 0x4B};

	//Assign all of the values to be passed as parameters

	uint64_t stepSize = pow(2,40)/NUM_THREADS;
	int zeros = 16 - (int)sizeof(initVector);

	for(i = 0; i < NUM_THREADS; i++){
		//Initialize key for each thread
		for(j = 15; j > -1; j--){
			threadDataArray[i].key[j] = initVector[j];
		}
		threadDataArray[i].keyCount = stepSize;
		uint64_t temp = i*stepSize;
		for(j = 15; j > 15-zeros; j--){
			threadDataArray[i].key[j] = temp & 0xFF;
			temp = temp >> 8;
		}

		//Initialize ciphertext
		for(j = 0; j < SIZE; j++){
			threadDataArray[i].ciphertext[j] = ciphertext[j];
		}
	}
	

	i = 0;
	clock_t start, end;
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	printf("Starting Attack 4!\n");
	start = clock();
	for(i = 0; i < NUM_THREADS; i++){
		int rc = pthread_create(&threads[i], &attr, decryptParallel, (void*)&threadDataArray[i]);
		if(rc){
			printf("ERROR\n");
			return 0;
		}
	}

	pthread_attr_destroy(&attr);
    for(i=0; i<NUM_THREADS; i++) {
       int rc = pthread_join(threads[i], &status);
       if (rc) {
          printf("ERROR; return code from pthread_join() is %d\n", rc);
          return 0;
          }
    }

	end = clock();
	float timeTaken = (float)((end-start)/(float)CLOCKS_PER_SEC);
	printf("YOU DID IT!!!!!!!!!!!!!!!!!\n");
	printf("Time taken = %f seconds\n", timeTaken);
	pthread_mutex_destroy(&lock);
	pthread_mutex_destroy(&funclock);
	pthread_exit(NULL);

	return 0;
}