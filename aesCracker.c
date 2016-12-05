/* For the implementation that I am thinking of, we need to define the key and the 
ciphertext in the main function and call our decryption algorithm from there.
I have all the basics figured out, the second we get the key incrementing then I should be
able to put everything together without any problems.*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "aes.h"

#define MAX_CHARS 50
#define DICTIONARY_LEN 9000
#define SIZE 32
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

int decrypt(uint8_t* key, uint8_t* ciphertext, string *dictionary){
	int i, count;
	uint8_t buffer[SIZE];

	for(i = 0; i<(SIZE); i+=16){
  		AES128_ECB_decrypt(ciphertext+i, key, buffer+i);
  		int max = getMaxValue(buffer+i);
  		if (max > 122)
  			return false;
  	}

  	//Save buffer to plaintext 
  	char *plaintext = (char *)(intptr_t)buffer;
  	for(i = 0; i < (SIZE-1); i++){
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

	uint8_t initVector[] = {0x6F, 0x1C, 0x5C, 0xD9, 0x27, 0x0A, 0xC8, 0xDD, 0xEA, 0xE6, 0x43, 0x0F, 0x30, 0x96, 0xC8, 0x05};
  	uint8_t ciphertext[] = {0x11, 0x37, 0x59, 0x0E, 0x76, 0x02, 0x25, 0x6E, 0x37, 0xFC, 0xD3, 0x68, 0x55, 0xCC, 0x93, 0x53,0xC1, 0xF2, 0xC2, 0x11, 0x71, 0xF2, 0xEC, 0x03, 0x91, 0xBE, 0xEE, 0x9A, 0x0A, 0x19, 0xB0, 0x84};

  	//int IVsize = (int)sizeof(initVector);
  	//printf("Size of IV = %d\n", IVsize);

  	//zero padding incase key is not long enough
  	uint8_t key[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  	for(i = 0; i < sizeof(initVector); i++){
	 	key[i] = initVector[i];
	}

	//Call the test decrpytion function
	// while(!check){
	// 	//increment the key
	// 	//call decrypt
	// }

	//uint8_t *key1 = key_increment(key);
	for(i = 0; i < sizeof(initVector); i++){
	 	key[i] = initVector[i];
	}
	//printf("%d\n", 0XFF);

	printf("Current least significant hex: %d\n", key[15]);
	for(i = 0; i < 20; i++){
		incrementKey(key);
		printf("%d\n", key[15]);
	}

	check = decrypt(key, ciphertext, dictionary);
	if(check){
		printf("Decryption Successful\n");
	} else {
		printf("Decryption Failed\n");
	}
	return 0;
}