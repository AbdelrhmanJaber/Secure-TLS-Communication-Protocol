/*
 * record.c : for data exchange through tls
 *
 *  Created on: Oct 5, 2024
 *      Author: Abdelrahman Ibrahim
 */



#include"record.h"



void recordSend(uint8_t message[16] , uint8_t cipher[16] , uint8_t key_aes[16]
   , uint8_t key_hmac[16] , uint8_t hmac_val[32]){
	uint8_t roundKey[11][16];
	/*calculate hmac for the message before encryption*/
	hmac(hmac_val, message, 16, key_hmac, 16);
	/*encrypt message with aes*/
	keyscheduling(key_aes , roundKey);
	aesEncryption(roundKey , message , cipher);
}

uint8_t recordReceive(uint8_t message[16] , uint8_t cipher[16] , uint8_t key_aes[16]
   , uint8_t key_hmac[16] , uint8_t hmac_val[32]){
	uint8_t flag = 1;
	uint8_t decrypted_hmac_val[32];
	uint8_t roundKey[11][16];
	/*decrypt the cipher with aes key*/
	keyscheduling(key_aes , roundKey);
	aesDecryption(roundKey, message, cipher);
	/*calculate hmac for the message*/
	hmac(decrypted_hmac_val, message , 16, key_hmac, 16);
	/*compare between two hash values*/
	for(uint8_t i = 0 ; i < 32 ; i++){
		if(hmac_val[i] != decrypted_hmac_val[i]) flag = 0;
	}
	/*return flag*/
	return flag;
}
