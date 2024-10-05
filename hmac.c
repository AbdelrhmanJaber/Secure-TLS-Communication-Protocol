/*
    hmac.c : Hashing with key using sha256
    Created on: oct 2, 2024
    Author : Abdelrahman Ibrahim

*/

#include"hmac.h"


#define I_PAD 0x36
#define O_PAD 0x5C




void hmac(unsigned char * hmac_val , unsigned char * data , unsigned char data_length
 , unsigned char * key , unsigned char key_length){
        sha256_block sha_block;
        unsigned char padded_key[64];
        /*check if key size is bigger than 64 bytes
        then hash it using sha256 to force it into 32 bytes*/
        if(key_length > 64){
            unsigned char tempKey[HMAC_BLOCK_SIZE];
            sha256_init(&sha_block);
            sha256_update(&sha_block , key , key_length);
            sha256_final(&sha_block , tempKey);
            key_length = HMAC_BLOCK_SIZE;
            key = tempKey;
        }
        /*make inner padding*/
        for(unsigned char i = 0 ; i < key_length ; i++){
            padded_key[i] = I_PAD ^ key[i];
        }
        for(unsigned char i = key_length ; i < 64 ; i++){
            padded_key[i] = I_PAD ^ 0;
        }
        /*make hashing for padded key and the data together*/
        sha256_init(&sha_block);
        sha256_update(&sha_block , padded_key , 64);
        sha256_update(&sha_block , data , data_length);
        sha256_final(&sha_block , hmac_val);

        /*make outer padding*/
        for(unsigned char i = 0 ; i < key_length ; i++){
            padded_key[i] = O_PAD ^ key[i];
        }
        for(unsigned char i = key_length ; i < 64 ; i++){
            padded_key[i] = O_PAD ^ 0;
        }

        /*make hashing for outer padded key and result of inner padded hashing together*/
        sha256_init(&sha_block);
        sha256_update(&sha_block , padded_key , 64);
        sha256_update(&sha_block , hmac_val , HMAC_BLOCK_SIZE);
        sha256_final(&sha_block , hmac_val);
 }