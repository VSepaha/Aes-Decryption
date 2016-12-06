#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "aes.h"

#define MAX_CHARS 128
#define DICTIONARY_LEN 9500
#define true 1
#define false 0

typedef char string[MAX_CHARS+1];

int getMaxValue(uint8_t *buffer){
	int i;
	int max = 0;
	for(i = 0; i < 16; i++){
		int temp = (int)buffer[i];
		if (max < temp){
			max = temp;
		}
	}
	return max;
}

int decrypt(uint8_t* key, uint8_t* ciphertext, string *dictionary, int size){
	int i, count;
	uint8_t buffer[size];

	for(i = 0; i<(size); i+=16){
  		AES128_ECB_decrypt(ciphertext+i, key, buffer+i);
  		int max = getMaxValue(buffer+i);
  		if (max > 122)
  			return false;
  	}

  	//Save buffer to plaintext 
  	char *plaintext = (char *)(intptr_t)buffer;
  	for(i = 0; i < size; i++){
  		plaintext[i] = tolower(plaintext[i]);
	}

	count = 0;
	for(i = 0; i < DICTIONARY_LEN; i++){
  		if(strstr(plaintext, dictionary[i]) != NULL){
  			//printf("Plaintext contains a word '%s'\n", dictionary[i]);
  			count++;
  		}
  		//If no valid words are found
  		if (i == DICTIONARY_LEN-1 && count == 0){
  			return false;
  		}
  	}

  	printf("Decryption Successful!\n");
  	printf("Plaintext = %s\n", plaintext);
  	return true;
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

int main(){
	
	//Set the dictionary that we will be using
	int i, check;
	string dictionary[DICTIONARY_LEN];
	
	FILE *myfile; //Here we will read from the words.txt file
	myfile = fopen("words.txt", "r");
	for(i = 0; i < DICTIONARY_LEN; i++){
		fscanf(myfile, "%s", dictionary[i]);
	}
	fclose(myfile);

	//length of 14 (hex)
	//uint8_t *initializationVector = "639404CBD1A1BD2322B206C39140"; 
	//length of 64 (hex)
	//string initCiphertext = "5A052F928464CC3E437187ADCFC7E8F1CF9DEAC7059B5264E4E940D8C35AA60E2277D4832843043F593F40E4084609C886681BCF5B570D353BFF24C0E1F4A65E";


	//This thing is missing the last two hex values
	uint8_t initVector[] = {0x6F, 0x1C, 0x5C, 0xD9, 0x27, 0x0A, 0xC8, 0xDD, 0xEA, 0xE6, 0x43, 0x0F, 0x30, 0x96};
  	uint8_t ciphertext[] = {0x11, 0x37, 0x59, 0x0E, 0x76, 0x02, 0x25, 0x6E, 0x37, 0xFC, 0xD3, 0x68, 0x55, 0xCC, 0x93, 0x53,0xC1, 0xF2, 0xC2, 0x11, 0x71, 0xF2, 0xEC, 0x03, 0x91, 0xBE, 0xEE, 0x9A, 0x0A, 0x19, 0xB0, 0x84};
  	int size = (int)sizeof(ciphertext);

  	//printf("%d\n", initializationVector[0]);

  	//zero padding incase key is not long enough
  	uint8_t key[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  	for(i = 0; i < sizeof(initVector); i++){
	 	key[i] = initVector[i];
	}

	for(i = 0; i < sizeof(initVector); i++){
	 	key[i] = initVector[i];
	}

	i = 0;
	check = false;
	int loopCounter = 0;
	while(!check){
		loopCounter++;
		check = decrypt(key, ciphertext, dictionary, size);
		incrementKey(key);
	}
	printf("Loop counter = %d\n", loopCounter);

	return 0;
}