#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"

static void test_decrypt_ecb(void);

int main(){
	test_decrypt_ecb();
	return 0;
}

//Test to see if we get the correct output from the test ciphertext
static void test_decrypt_ecb(void) {

	printf("Test Case: \n");

  	uint8_t key[] = {0x6F, 0x1C, 0x5C, 0xD9, 0x27, 0x0A, 0xC8, 0xDD, 0xEA, 0xE6, 0x43, 0x0F, 0x30, 0x96, 0xC8, 0x06};
  	uint8_t ciphertext[]  = {0x11, 0x37, 0x59, 0x0E, 0x76, 0x02, 0x25, 0x6E, 0x37, 0xFC, 0xD3, 0x68, 0x55, 0xCC, 0x93, 0x53,0xC1, 0xF2, 0xC2, 0x11, 0x71, 0xF2, 0xEC, 0x03, 0x91, 0xBE, 0xEE, 0x9A, 0x0A, 0x19, 0xB0, 0x84};
  	uint8_t buffer[32];
  
  	int i;
  	for(i = 0; i<sizeof(ciphertext); i+=16){
  		AES128_ECB_decrypt(ciphertext+i, key, buffer+i);
  	}

  	//Convert to plaintext and print
  	char *plaintext = (char *)(intptr_t)buffer;
  	printf("%s--------------", plaintext);

  	int rc = strcmp(plaintext, "ECE 424 Course Project Testfile");
  	if(!rc){
  		printf("SUCCESS!\n");
  	} else {
  		printf("FAIL\n");
  	} 

} //TEST PASSED

