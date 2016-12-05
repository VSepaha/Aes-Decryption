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

//key incrementing function
uint8_t *key_increment(uint8_t* key)	

//Library or Dictionary of keys to iterate through to find correct key
{
	uint8_t key_options[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
					0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
					0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,
					0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,
					0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,
					0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F,
					0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F,
					0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A,0x7B,0x7C,0x7D,0x7E,0x7F,
					0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F,
					0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F,
					0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
					0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF,
					0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF,
					0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF,
					0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF,
					0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF};

//Start with index 0
//Iterate until end of the key library is reached
//dont need a for loop
//increment once and return the key -- not key[]
//MIGHT NEED A FOR LOOP TO CHECK THE CURRENT VALUE OF THE KEY

//key_options = {0,1,2,3,4,5,6,7,8,9} -- ALRAEDY DEFINED THIS

//array = {1,0,0}; -- KEY

//check array[last value] = ? 0
//key_options find index 0
//key_options[0 index +1] = 1
//array[last value] = key_options[0 index +1]
//return array
	//)
	
	//declaring the variables
	int key_last_element;
	int key_2_last_element;
	int key_3_last_element;
	int key_4_last_element;
	int key_5_last_element;
	int key_6_last_element;
	int key_7_last_element;
	int key_8_last_element;
	int key_9_last_element;
	int key_10_last_element;
	int key_11_last_element;
	int key_12_last_element;
	int key_13_last_element;
	int key_14_last_element;
	int key_15_last_element;
	int key_options_last_element;
	int key_options_next_element;
	
	//INCREMENTING THE ONE'S DIGIT
	key_last_element = key[sizeof(key)-1];
	key_options_last_element = key_options[0];
	key_options_next_element = key_options[0+1];
	key[sizeof(key)-1] = key_options[sizeof(key)-sizeof(key)+1];
	return key;
	
	//if the last element of key array is equal to 
	//last element of the key options array
	//move to the 10's digit
	if (key_last_element == key_options_last_element)	
	{
		
		key_2_last_element = key[sizeof(key)-2];
		key_options_last_element = key_options[0];
		key_options_next_element = key_options[0+1];
		key[sizeof(key)-2] = key_options[sizeof(key)-sizeof(key)+1];
		return key;
	}
	
	//we keep doing this until we iterate through all the 16 bytes of the key
	//when the last element of the key options = the second to last element
	//move onto the next digit over
	//keep doing this for the rest of the 16 bytes
	if (key_2_last_element == key_options_last_element)
	{
		
		key_3_last_element = key[sizeof(key)-3];
		key_options_last_element = key_options[0];
		key_options_next_element = key_options[0+1];
		key[sizeof(key)-3] = key_options[sizeof(key)-sizeof(key)+1];
		return key;
	}

	if (key_3_last_element == key_options_last_element)
	{
		
		key_4_last_element = key[sizeof(key)-4];
		key_options_last_element = key_options[0];
		key_options_next_element = key_options[0+1];
		key[sizeof(key)-4] = key_options[sizeof(key)-sizeof(key)+1];
		return key;
	}
	if (key_4_last_element == key_options_last_element)
	{
		
		key_5_last_element = key[sizeof(key)-5];
		key_options_last_element = key_options[0];
		key_options_next_element = key_options[0+1];
		key[sizeof(key)-5] = key_options[sizeof(key)-sizeof(key)+1];
		return key;
	}
	
	if (key_5_last_element == key_options_last_element)
	{
		
		key_6_last_element = key[sizeof(key)-6];
		key_options_last_element = key_options[0];
		key_options_next_element = key_options[0+1];
		key[sizeof(key)-6] = key_options[sizeof(key)-sizeof(key)+1];
		return key;
	}
	
	if (key_6_last_element == key_options_last_element)
	{
		
		key_7_last_element = key[sizeof(key)-7];
		key_options_last_element = key_options[0];
		key_options_next_element = key_options[0+1];
		key[sizeof(key)-7] = key_options[sizeof(key)-sizeof(key)+1];
		return key;
	}
	
	if (key_7_last_element == key_options_last_element)
	{
		
		key_8_last_element = key[sizeof(key)-8];
		key_options_last_element = key_options[0];
		key_options_next_element = key_options[0+1];
		key[sizeof(key)-8] = key_options[sizeof(key)-sizeof(key)+1];
		return key;
	}
	
	if (key_8_last_element == key_options_last_element)
	{
		
		key_9_last_element = key[sizeof(key)-9];
		key_options_last_element = key_options[0];
		key_options_next_element = key_options[0+1];
		key[sizeof(key)-9] = key_options[sizeof(key)-sizeof(key)+1];
		return key;
	}
	
	if (key_9_last_element == key_options_last_element)
	{
		
		key_10_last_element = key[sizeof(key)-10];
		key_options_last_element = key_options[0];
		key_options_next_element = key_options[0+1];
		key[sizeof(key)-10] = key_options[sizeof(key)-sizeof(key)+1];
		return key;
	}
	
		if (key_10_last_element == key_options_last_element)
	{
		
		key_11_last_element = key[sizeof(key)-11];
		key_options_last_element = key_options[0];
		key_options_next_element = key_options[0+1];
		key[sizeof(key)-11] = key_options[sizeof(key)-sizeof(key)+1];
		return key;
	}
		if (key_11_last_element == key_options_last_element)
	{
		
		key_12_last_element = key[sizeof(key)-12];
		key_options_last_element = key_options[0];
		key_options_next_element = key_options[0+1];
		key[sizeof(key)-12] = key_options[sizeof(key)-sizeof(key)+1];
		return key;
	}
		if (key_12_last_element == key_options_last_element)
	{
		
		key_13_last_element = key[sizeof(key)-13];
		key_options_last_element = key_options[0];
		key_options_next_element = key_options[0+1];
		key[sizeof(key)-13] = key_options[sizeof(key)-sizeof(key)+1];
		return key;
	}
		if (key_13_last_element == key_options_last_element)
	{
		
		key_14_last_element = key[sizeof(key)-14];
		key_options_last_element = key_options[0];
		key_options_next_element = key_options[0+1];
		key[sizeof(key)-14] = key_options[sizeof(key)-sizeof(key)+1];
		return key;
	}
		if (key_14_last_element == key_options_last_element)
	{
		
		key_15_last_element = key[sizeof(key)-15];
		key_options_last_element = key_options[0];
		key_options_next_element = key_options[0+1];
		key[sizeof(key)-15] = key_options[sizeof(key)-sizeof(key)+1];
		return key;
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

	uint8_t initVector[] = {0x6F, 0x1C, 0x5C, 0xD9, 0x27, 0x0A, 0xC8, 0xDD, 0xEA, 0xE6, 0x43, 0x0F, 0x30, 0x96, 0xC8, 0x06};
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
	//printf("%s\n", key1[0]);

	check = decrypt(key, ciphertext, dictionary);
	if(check){
		printf("Decryption Successful\n");
	} else {
		printf("Decryption Failed\n");
	}
	return 0;
}