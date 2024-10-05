#include"rsa.h"
#include<stdio.h>


unsigned long int global_phi_n = 0;


//Function to check if the number prime or not

static unsigned char checkPrime(unsigned long int n){
    unsigned char flag = 1;
    if(n <= 1) flag = 0;
    else{
        for(unsigned long int i = 2 ; i <= sqrt(n) ; i++){
            if(n%i == 0){
                flag = 0;
                break;
            } 
        }
    }
    return flag;
}


//function for generate prime random numbers to generate e

static void generate_P_Q_for_key(unsigned long int * p , unsigned long int * q , PRNG * randomSeeds){
    unsigned char flag_p = 0 , flag_q = 0;
    while(!flag_p){
        *p = next_prng(randomSeeds , MODULO_16); //
        flag_p = checkPrime(*p);
    }
    while(!flag_q){
        *q = next_prng(randomSeeds , MODULO_16);
        flag_q = checkPrime(*q);
    }
}


//Function to calculate the greatest common divisor

static unsigned long int gcd(unsigned long int a, unsigned long int b) {
    unsigned long int temp;
    while (b != 0) {
        temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}


//Function to check if e co prime of phi_n or noe
static unsigned char is_coprime(unsigned long int e, unsigned long int phi_n) {
    return gcd(e, phi_n) == 1;
}


/*
    base --> message
    exp --> e (puplic key)
    mod --> n 
*/

unsigned long long int modExp(unsigned long long int base, unsigned long long int exp, unsigned long long int mod) {
    unsigned long long int result = 1;
    base = base % mod;
    
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1; 
        base = (base * base) % mod;
    }
    
    return result;
}


//Function to generate public key (e) for RSA

void generate_key(unsigned long int * e , unsigned long int * n){
    unsigned char flag_e = 0;
    unsigned long int p ,q , phi_n ;
    PRNG  randonSeeds;
    init_prng(&randonSeeds , INIT_SEEDS);
    generate_P_Q_for_key(&p , &q , &randonSeeds);
    *n = p * q;
    phi_n = (p-1) * (q-1);
    global_phi_n = phi_n;
    while (!flag_e)
    {
        *e = next_prng_e(&randonSeeds , phi_n);
        if(checkPrime(*e) == 1 && is_coprime(*e,phi_n)) flag_e = 1;
    }
}


void rsaEncryption(unsigned long long int * cipher , unsigned long long int * message , unsigned long int e , unsigned long int n){
    for(unsigned char i = 0 ; i < 32 ; i++){
        cipher[i] = modExp(message[i] , (unsigned long long int)e , (unsigned long long int)n);
    }
}


static unsigned long int extendedGCD(unsigned long int a, unsigned long int b, unsigned long int *x, unsigned long int *y) {
    unsigned long int x0 = 1, y0 = 0; 
    unsigned long int x1 = 0, y1 = 1; 
    unsigned long int gcd;

    while (b != 0) {
        unsigned long int quotient = a / b;

        unsigned long int temp = b;
        b = a % b;
        a = temp;

        temp = x0;
        x0 = x1;
        x1 = temp - quotient * x1;

        temp = y0;
        y0 = y1;
        y1 = temp - quotient * y1;
    }

    *x = x0;
    *y = y0;
    return a; 
}

static unsigned long int modInverse(unsigned long int a, unsigned long int m) {
    unsigned long int x, y;
    unsigned long int gcd = extendedGCD(a, m, &x, &y);

    if (gcd != 1) {
        return 0; // Inverse doesn't exist
    }

    return (x % m + m) % m; // Ensure the result is positive
}


/*generte privte key d for decryption*/

void generatePrivateKey(unsigned long int e,unsigned long int *d) {
    *d = modInverse(e, global_phi_n);
}

/*decrypt the data*/
void rsadecryption(unsigned long long int * cipher , unsigned long long int * message , unsigned long int d , unsigned long int n){
    for(unsigned char i = 0 ; i < 32 ; i++){
        message[i] = modExp(cipher[i] , (unsigned long long int)d , (unsigned long long int)n);
    }
}




