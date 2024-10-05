/*
    hmac.h : hashing with key using sha256
    Created on: oct 3, 2024
    Author : Abdelrahman Ibrahim

*/

#ifndef HMAC_H
#define HMAC_H


#include"sha256.h"

#define HMAC_BLOCK_SIZE            32 //32 Bytes --> 256 bits

 



void hmac(unsigned char * hmac_val , unsigned char * data , unsigned char data_length
 , unsigned char * key , unsigned char key_length);


#endif