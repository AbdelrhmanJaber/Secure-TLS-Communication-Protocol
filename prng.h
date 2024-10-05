#ifndef PRNG_H
#define PRNG_H



typedef struct {
    unsigned long int seed; // Seed for the PRNG
}PRNG;


#define INIT_SEEDS        12345
#define CLIENT_INIT_SEED  4569876
#define SERVER_INIT_SEED  7961452
#define PRE_MASTER_SEED   4563127 


#define MODULO_8         255
#define MODULO_16        65535
#define MODULO_32        4294967295

void init_prng(PRNG *prng, unsigned long int seed);

unsigned long int next_prng(PRNG *prng , unsigned long int modulo);

unsigned long int next_prng_e(PRNG *prng , unsigned long int phi_n); 

#endif