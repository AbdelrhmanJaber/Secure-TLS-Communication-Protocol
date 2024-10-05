#ifndef RSA_H
#define RSA_H

#include"prng.h"
#include<math.h>




void generate_key(unsigned long int * e , unsigned long int * n);

void rsaEncryption(unsigned long long int * cipher , unsigned long long int * message , unsigned long int e , unsigned long int n);

void generatePrivateKey(unsigned long int e,unsigned long int *d);

void rsadecryption(unsigned long long int * cipher , unsigned long long int * message , unsigned long int d , unsigned long int n);

#endif