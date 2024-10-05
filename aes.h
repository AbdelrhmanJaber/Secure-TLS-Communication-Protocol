/*
    aes.h : with Key-128 bits
    Created on: Sep 15, 2024
    Author : Abdelrahman Ibrahim

*/




#define AES_BLOCK_SIZE      16
#define KEY_ROUNDS          10


void keyscheduling(unsigned char * key , unsigned char roundKey [11][16]);

void aesEncryption(unsigned char roundKey[11][16] , unsigned char * plaintext , unsigned char * ciphertext);

void aesDecryption(unsigned char roundKey[11][16] , unsigned char * plaintext , unsigned char * ciphertext);
