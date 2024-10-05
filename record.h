/*
 * record.h : for data exchange through tls
 *
 *  Created on: Oct 5, 2024
 *      Author: Abdelrahman Ibrahim
 */

#ifndef SRC_RECORD_H_
#define SRC_RECORD_H_

#include"handshaking.h"
#include"aes.h"


void recordSend(uint8_t message[16] , uint8_t cipher[16] , uint8_t key_aes[16]
   , uint8_t key_hmac[16] , uint8_t hmac_val[32]);

uint8_t recordReceive(uint8_t message[16] , uint8_t cipher[16] , uint8_t key_aes[16]
   , uint8_t key_hmac[16] , uint8_t hmac_val[32]);

#endif /* SRC_RECORD_H_ */
