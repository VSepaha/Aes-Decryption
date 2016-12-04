#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "aes.h"

#define MAX_CHARS 50
#define DICTIONARY_LEN 9000

typedef char string[MAX_CHARS+1];

void testDecrypt(string *dictionary){
	printf("Test Case: \n");

  	uint8_t key[] = {0x6F, 0x1C, 0x5C, 0xD9, 0x27, 0x0A, 0xC8, 0xDD, 0xEA, 0xE6, 0x43, 0x0F, 0x30, 0x96, 0xC8, 0x06};
  	uint8_t ciphertext[]  = {0x11, 0x37, 0x59, 0x0E, 0x76, 0x02, 0x25, 0x6E, 0x37, 0xFC, 0xD3, 0x68, 0x55, 0xCC, 0x93, 0x53,0xC1, 0xF2, 0xC2, 0x11, 0x71, 0xF2, 0xEC, 0x03, 0x91, 0xBE, 0xEE, 0x9A, 0x0A, 0x19, 0xB0, 0x84};
  	uint8_t buffer[32];
  
  	// Decryption happens here 
  	// Electronic Code book decrypts 16 bytes at a time 
  	int i;
  	for(i = 0; i<sizeof(ciphertext); i+=16){
  		AES128_ECB_decrypt(ciphertext+i, key, buffer+i);
  	}

  	//Convert to plaintext and print
  	char *plaintext = (char *)(intptr_t)buffer;
  	printf("%s\n", plaintext);

  	//Change everything to lowercase so it is easier to compare
  	for(i = 0; i < 31; i++){
  		plaintext[i] = tolower(plaintext[i]);
	}

	//iterate through the dictionary to see if a word is contained in the plaintext
  	for(i = 0; i < DICTIONARY_LEN; i++){
  		if(strstr(plaintext, dictionary[i]) != NULL){
  			//Print all the words contained in the plaintext
  			printf("Plaintext contains a word '%s'\n", dictionary[i]);
  		}
  	}

}

int main(){
	
	//Set the dictionary that we will be using
	int i;
	string dictionary[DICTIONARY_LEN];
	
	FILE *myfile; //Here we will read from the words.txt file
	myfile = fopen("words.txt", "r");
	for(i = 0; i < DICTIONARY_LEN; i++){
		fscanf(myfile, "%s", dictionary[i]);
	}
	fclose(myfile);
	
	//Call the test decrpytion function
	testDecrypt(dictionary);
	return 0;
}