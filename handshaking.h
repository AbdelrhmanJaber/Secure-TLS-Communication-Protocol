/*
    handshaking.h 
    Created on: oct 3, 2024
    Author : Abdelrahman Ibrahim

*/

#ifndef HANDSHAKING_H
#define HANDSHAKING_H


#include"rsa.h"
#include"sha256.h"
#include"hmac.h"
#include<stdio.h>


/* * structure of digital signature message
   * the server should hash the message then encrypt using private key
   * the client should recieve data and decrypt it then compare the hash value
   * satisfy if the public key is right or not 
*/


#define SERVER_RANDOM_NUMBERS     2
#define CLIENT_RANDOM_NUMBERS     2


#define SESION_KEYS_NUMBERS       4
#define SESSION_KEY_SIZE          16 //BYTES

#define CLIENT_SESSION_ID         25

#define CLIENT_MAC_SESSION_KEY    0
#define SERVER_MAC_SESSION_KEY    1
#define CLIENT_AES_SESSION_KEY    2
#define SERVER_AES_SESSION_KEY    3


#define PRIVATE_KEY      20849761
#define PRIVATE_N        115795859


typedef struct{
   unsigned char client_random[16];
   unsigned char sessionID;
}client_hello_t;


typedef struct 
{
	unsigned long long  encrypted_hashed_message[32];
   unsigned char server_hello_message[16];
   unsigned char server_random[16];
}signature_message_server_t;


typedef struct 
{
	unsigned long long  decrypted_hashed_message[32];
   unsigned char server_hello_message[16];
}signature_message_client_t;



void clientHello(client_hello_t * client_hello_mes);

void servevrHello(unsigned char * serverMessage , signature_message_server_t  * server_hello_mes);

unsigned char clientCheckDigitalSignature(signature_message_server_t * server_message ,signature_message_client_t * client_message);

void generatePreMasterKey(unsigned char pre_master_key[48] ,
		unsigned long long int encrypted_pre_master_key[48]);

void generateMasterKey(unsigned char pre_master_key[48] , unsigned char random_key[16] , unsigned char master_key[HMAC_BLOCK_SIZE]);


void generateSessionKeys(unsigned char master_key[HMAC_BLOCK_SIZE] , unsigned char random_seed[16] ,
 unsigned char session_keys[SESION_KEYS_NUMBERS][SESSION_KEY_SIZE]);

#endif
