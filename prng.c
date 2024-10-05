#include"prng.h"
#include<stdio.h>


// Function to initialize the PRNG with a seed
void init_prng(PRNG *prng, unsigned long int seed) {
    prng->seed = seed;
}

// Function to generate general random number with modulo 16
unsigned long int next_prng(PRNG *prng, unsigned long int modulo) {
    // Parameters for the LCG
    unsigned long int a = 1664525; // Multiplier
    unsigned long int c = 12345;   // Increment
    // Update seed
    prng->seed = (a * prng->seed + c) % modulo; 
    return prng->seed; 
}
// Function to generate the next random number for public key in rsa
unsigned long int next_prng_e(PRNG *prng , unsigned long int phi_n) {
    // Parameters for the LCG
    unsigned long int a = 1664525; // Multiplier
    unsigned long int c = 12345; // Increment
    prng->seed = (a * prng->seed + c) % phi_n; // Update seed
    return prng->seed; 
}
