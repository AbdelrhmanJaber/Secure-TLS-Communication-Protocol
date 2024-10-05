/*
    sha256.h : Hashing
    Created on: Sep 29, 2024
    Author : Abdelrahman Ibrahim

*/

#ifndef SHA256_H
#define SHA256_H


#include<string.h>

#define HASH_BLOCK_SIZE     32 //32-bit word (word = 4 Bytes => 256 bit)

typedef unsigned char       BYTE;             
typedef unsigned long int      WORD;            

typedef struct {
    BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} sha256_block;


void sha256_init(sha256_block *sha_block);


void sha256_update(sha256_block *sha_block, BYTE data[], unsigned long int len);


void sha256_final(sha256_block *sha_block, BYTE hash[]) ;


#endif