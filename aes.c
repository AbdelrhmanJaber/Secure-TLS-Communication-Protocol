/*
    aes.c : with Key-128 bits
    Created on: Sep 15, 2024
    Author : Abdelrahman Ibrahim

*/


#include"aes.h"


/*DEFINE SBOX FOR ENCRYPTION
  FOR MAPPING THE tempCipherText IN SUB STATE*/

static unsigned char sBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };


/*DEFINE SBOX FOR DECRYPTION
  FOR MAPPING THE tempCipherText IN SUB STATE*/


static unsigned char inverseSBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };


static unsigned char roundConstant[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};



/*Mapping the plain text with the sBOX for encryption*/

static void subBytesEncryption(unsigned char * tempCipherText , unsigned char * cipherText){
    for(int i = 0 ; i < 16 ; i++){
          *(tempCipherText + i) = sBOX[*(cipherText + i)] ;
    }
}

/*mapping the plaintext with inverse SBOX for decrypion*/

static void subBytesDecryption(unsigned char * plaintext){
    for(int i = 0 ; i < 16 ; i++){
          *(plaintext + i) = inverseSBOX[*(plaintext + i)] ;
    }
}


/*SHIFT ROW IN ENCRYPTION*/

/*  R0  NO CHANGE 
    R1  SHIFT LEFT WITH 1
    R2  SHIFT LEFT WITH 2
    R3  SHIFT LEFT WITH 3
*/

/*  R0 : S0 S4 S8  S12    |     S0  S4  S8  S12
    R1 : S1 S5 S9  S13    |     S5  S9  S13 S1    
    R2 : S2 S6 S10 S14    |     S10 S14 S2  S6
    R3 : S3 S7 S11 S15    |     S15 S3  S7  S11
*/

static void shiftRowEncryption(unsigned char * tempCipherText){
    unsigned char temp ;
    /*shift second row*/
    temp = tempCipherText[1];
    tempCipherText[1] = tempCipherText[5];
    tempCipherText[5] = tempCipherText[9];
    tempCipherText[9] = tempCipherText[13] ;
    tempCipherText[13] = temp;
    /*shift third row*/
    temp = tempCipherText[2] ;
    tempCipherText[2] = tempCipherText[10];
    tempCipherText[10] = temp;
    temp = tempCipherText[6] ;
    tempCipherText[6] = tempCipherText[14];
    tempCipherText[14] = temp;
    /*shift fourth row*/
    temp = tempCipherText[15];
    tempCipherText[15] = tempCipherText[11];
    tempCipherText[11] = tempCipherText[7];
    tempCipherText[7] = tempCipherText[3];
    tempCipherText[3] = temp;
}


/*  R0 : S0  S4  S8  S12    |  S0  S4  S8  S12
    R1 : S5  S9  S13 S1     |  S1  S5  S9  S13   
    R2 : S10 S14 S2  S6     |  S2  S6  S10 S14
    R3 : S15 S3  S7  S11    |  S3  S7  S11 S15
*/

static void shiftRowDecryption(unsigned char * plaintext){
    unsigned char temp ; 
    /*shift inverse second row*/
    temp = plaintext[13];
    plaintext[13] = plaintext[9];
    plaintext[9] = plaintext[5];
    plaintext[5] = plaintext[1];
    plaintext[1] = temp;
    /*shift inverse third row*/
    temp = plaintext[14];
    plaintext[14] = plaintext[6];
    plaintext[6] = temp;
    temp = plaintext[10];
    plaintext[10] = plaintext[2];
    plaintext[2] = temp;
    /*shift fourth row*/
    temp = plaintext[3];
    plaintext[3] = plaintext[7];
    plaintext[7] = plaintext[11];
    plaintext[11] = plaintext[15];
    plaintext[15] = temp;
}


/*Galois field mutipiction by 2*/

static unsigned char multiBy2(unsigned char elem){
    unsigned char returnValue;
    if(elem & 0x80) returnValue = (elem<<1) ^ 0x1b;
    else returnValue = elem<<1;
    return returnValue;
}


/*pre defined matrix for mixColumn in encrypion
         * [02 03 01 01]   [s0  s4  s8  s12]
         * [01 02 03 01]   [s1  s5  s9  s13]
         * [01 01 02 03]   [s2  s6  s10 s14]
         * [03 01 01 02]   [s3  s7  s11 s15]  
*/

static void mixColumnEncryption(unsigned char * cipherText , unsigned char* tempCipherText){
    unsigned char temp ;
    for(unsigned char i = 0 ; i < AES_BLOCK_SIZE ; i+=4){
        temp = tempCipherText[i] ^ tempCipherText[i+1] ^ tempCipherText[i+2] ^ tempCipherText[i+3];
        cipherText[i] = multiBy2(tempCipherText[i] ^ tempCipherText[i+1]) ^ tempCipherText[i] ^ temp;
        cipherText[i+1] = multiBy2(tempCipherText[i+1] ^ tempCipherText[i+2]) ^ tempCipherText[i+1] ^ temp;
        cipherText[i+2] = multiBy2(tempCipherText[i+2] ^ tempCipherText[i+3]) ^ tempCipherText[i+2] ^ temp;
        cipherText[i+3] = multiBy2(tempCipherText[i+3] ^ tempCipherText[i]) ^ tempCipherText[i+3] ^ temp;
    }
}


/*pre defined matrix for mixColumn in decryption
         * [0E 0B 0D 09]   [s0  s4  s8  s12]
         * [09 0E 0B 0D]   [s1  s5  s9  s13]
         * [0D 09 0E 0B]   [s2  s6  s10 s14]
         * [0B 0D 09 0E]   [s3  s7  s11 s15]  
*/

static void mixColumnDecryption(unsigned char * plaintext , unsigned char* tempPlaintext){
    unsigned char temp , tempOdd , tempEven ;
    for(unsigned char i = 0 ; i < AES_BLOCK_SIZE ; i+=4){
        temp = tempPlaintext[i] ^ tempPlaintext[i+1] ^ tempPlaintext[i+2] ^ tempPlaintext[i+3];
        plaintext[i] =  temp  ^ tempPlaintext[i]    ^ multiBy2(tempPlaintext[i] ^ tempPlaintext[i+1]);
        plaintext[i+1] = temp ^ tempPlaintext[i+1]  ^  multiBy2(tempPlaintext[i+1] ^ tempPlaintext[i+2]);
        plaintext[i+2] = temp ^ tempPlaintext[i+2]  ^  multiBy2(tempPlaintext[i+2] ^ tempPlaintext[i+3]);
        plaintext[i+3] = temp ^ tempPlaintext[i+3]  ^ multiBy2(tempPlaintext[i+3] ^ tempPlaintext[i]);
        tempEven = multiBy2(multiBy2(tempPlaintext[i]   ^ tempPlaintext[i+2]));
        tempOdd = multiBy2(multiBy2(tempPlaintext[i+1] ^ tempPlaintext[i+3]));
        temp = multiBy2(tempEven ^ tempOdd);
        plaintext[i]   ^= temp ^ tempEven;
        plaintext[i+1] ^= temp ^ tempOdd;
        plaintext[i+2] ^= temp ^ tempEven;
        plaintext[i+3] ^= temp ^ tempOdd;
    }
}


/*Generate the rounds of the key - 128*/

void keyscheduling(unsigned char * key , unsigned char roundKey [11][16]){
    unsigned char temp ;
    unsigned char lastFourBytes[4];
    /*fill the round 0 with the key*/
    for(unsigned char i = 0 ; i < 16 ; i++){
        roundKey[0][i] = key[i];
    }
    for(unsigned char i = 1 ; i <= KEY_ROUNDS ; i++){
        /*get the last 4 Bytes from the last round*/
          for(unsigned char j = 0 ; j < 4 ; j++){
            lastFourBytes[j]  = roundKey[i-1][12+j];
        }
        /*rotate the last column vector*/
        temp = lastFourBytes[0];
        lastFourBytes[0] = lastFourBytes[1];
        lastFourBytes[1] = temp;
        temp = lastFourBytes[1];
        lastFourBytes[1] = lastFourBytes[2];
        lastFourBytes[2] = temp;
        temp = lastFourBytes[2];
        lastFourBytes[2] = lastFourBytes[3];
        lastFourBytes[3] = temp;
         /*mapping from SBOX*/
          for(unsigned char l = 0 ; l < 4 ; l++){
         lastFourBytes[l] = sBOX[lastFourBytes[l]];
        }
        /*making XOR*/
        /*first column*/
        roundKey[i][0] = lastFourBytes[0] ^ roundKey[i-1][0] ^ roundConstant[i-1];
        roundKey[i][1] = lastFourBytes[1] ^ roundKey[i-1][1];
        roundKey[i][2] = lastFourBytes[2] ^ roundKey[i-1][2];
        roundKey[i][3] = lastFourBytes[3] ^ roundKey[i-1][3];
        /*second column*/
        roundKey[i][4] =   roundKey[i][0] ^ roundKey[i-1][4];
        roundKey[i][5] =   roundKey[i][1] ^ roundKey[i-1][5];
        roundKey[i][6] =   roundKey[i][2] ^ roundKey[i-1][6];
        roundKey[i][7] =   roundKey[i][3] ^ roundKey[i-1][7];
        /*third column*/
        roundKey[i][8]  =  roundKey[i][4] ^ roundKey[i-1][8];
        roundKey[i][9]  =  roundKey[i][5] ^ roundKey[i-1][9];
        roundKey[i][10] =  roundKey[i][6] ^ roundKey[i-1][10];
        roundKey[i][11] =  roundKey[i][7] ^ roundKey[i-1][11];
        /*fourth column*/
        roundKey[i][12] =  roundKey[i][8] ^ roundKey[i-1][12];
        roundKey[i][13] =  roundKey[i][9] ^ roundKey[i-1][13];
        roundKey[i][14] = roundKey[i][10] ^ roundKey[i-1][14];
        roundKey[i][15] = roundKey[i][11] ^ roundKey[i-1][15];
    }
}


void aesEncryption(unsigned char roundKey[11][16] , unsigned char * plaintext , unsigned char * ciphertext){
    unsigned char tempCiphertext[16];
    /*round 0 XORING plaintext with the key*/
    for(unsigned char i = 0 ; i < AES_BLOCK_SIZE ; i++){
        *(ciphertext + i) = *(plaintext + i) ^ roundKey[0][i];
    }

    /*first 9 rounds*/
    for(unsigned char i = 1 ; i < KEY_ROUNDS ; i++){
     /*sub with SBOX*/
       subBytesEncryption(tempCiphertext , ciphertext);
       /*shift rows*/
       shiftRowEncryption(tempCiphertext);
       /*Mix Column*/
       mixColumnEncryption(ciphertext , tempCiphertext);
       /*add round key*/
       for(unsigned char j = 0 ; j < AES_BLOCK_SIZE ; j++){
            *(ciphertext + j) = *(ciphertext + j) ^ roundKey[i][j];
       }
    }
    /*last round without mixColumnEncryption*/
    subBytesEncryption(ciphertext , ciphertext);
    /*shift rows*/
    shiftRowEncryption(ciphertext);
    /*add the last round key*/
    for(unsigned char i = 0 ; i < AES_BLOCK_SIZE ; i++){
        *(ciphertext + i) = *(ciphertext + i) ^ roundKey[10][i];
    }
}



void aesDecryption(unsigned char roundKey[11][16] , unsigned char * plaintext , unsigned char * ciphertext){
    unsigned char tempPlaintext[16];
    /*first round*/
    for(unsigned char i = 0 ; i < AES_BLOCK_SIZE ; i++){
        *(plaintext+i) = *(ciphertext + i) ^ roundKey[10][i]; 
    }
    shiftRowDecryption(plaintext);
    subBytesDecryption(plaintext);
    /*the remaining 9 rounds*/
    for(unsigned char i = KEY_ROUNDS - 1 ; i >= 1 ; i--){
        /*add round key*/
        for(unsigned char j = 0 ; j < AES_BLOCK_SIZE ; j++){
            *(tempPlaintext + j) = *(plaintext + j) ^ roundKey[i][j]; 
        }
        /*Mix Column inverse*/
        mixColumnDecryption(plaintext , tempPlaintext);
        /*shift row inverse*/
        shiftRowDecryption(plaintext);
        /*sub with inverse SBOX*/
        subBytesDecryption(plaintext);
    }
    /*last round key*/
    for(unsigned char i = 0 ; i < AES_BLOCK_SIZE ; i++){
        *(plaintext+i) ^= roundKey[0][i]; 
    }
}
