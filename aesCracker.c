#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"

//Hello Tim this is a comment for you

static void test_decrypt_ecb(void);

int hex_to_int(char c){
        int first = c / 16 - 3;
        int second = c % 16;
        int result = first*10 + second;
        if(result > 9) result--;
        return result;
}

int hex_to_ascii(char c, char d){
        int high = hex_to_int(c) * 16;
        int low = hex_to_int(d);
        return high+low;
}
void printPlainText(uint8_t* buffer){
		int i;
		char plaintext[32];
		for(i = 0; i < 32; i++){
			plaintext[i] = (char)buffer[i];
		}
	    int length = strlen(plaintext);
        //int i;
        char buf = 0;
        for(i = 0; i < length; i++){
                if(i % 2 != 0){
                        printf("%c", hex_to_ascii(buf, plaintext[i]));
                }else{
                        buf = plaintext[i];
                }
        }
        printf("\n");

}


int main(){
	printf("Start\n");
	test_decrypt_ecb();

	return 0;
}

static void test_decrypt_ecb(void)
{
  uint8_t key[] = {0x6F, 0x1C, 0x5C, 0xD9, 0x27, 0x0A, 0xC8, 0xDD, 0xEA, 0xE6, 0x43, 0x0F, 0x30, 0x96, 0xC8, 0x06};
  uint8_t ciphertext[]  = {0x11, 0x37, 0x59, 0x0E, 0x76, 0x02, 0x25, 0x6E, 0x37, 0xFC, 0xD3, 0x68, 0x55, 0xCC, 0x93, 0x53,0xC1, 0xF2, 0xC2, 0x11, 0x71, 0xF2, 0xEC, 0x03, 0x91, 0xBE, 0xEE, 0x9A, 0x0A, 0x19, 0xB0, 0x84};
  uint8_t buffer[32];
  
  int i;
  for(i = 0; i<sizeof(ciphertext); i+=16){
  	AES128_ECB_decrypt(ciphertext+i, key, buffer+i);
  }

  for(i = 0; i<32; i++){
  	printf("%d ", buffer[i]);
  }
  printf("\n");
}