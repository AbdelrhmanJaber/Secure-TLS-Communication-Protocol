/*
    sha256.c : Hashing
    Created on: Sep 29, 2024
    Author : Abdelrahman Ibrahim
*/

#include "sha256.h"

#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

void sha256_operation(sha256_block *sha_block, BYTE data[]);

/* global array for compression */
static const WORD k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* global array for initialization of hash */
unsigned long int hashInit[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

void sha256_init(sha256_block *sha_block) {
    sha_block->bitlen = 0;
    sha_block->datalen = 0;
    for (unsigned char i = 0; i < 8; i++) {
        sha_block->state[i] = hashInit[i];
    }
}

void sha256_update(sha256_block *sha_block, BYTE data[], unsigned long int len) {
    /* update hash structure for new hash calculation */
    for (unsigned long int i = 0; i < len; ++i) {
        sha_block->data[sha_block->datalen] = data[i];
        sha_block->datalen++;
        if (sha_block->datalen == 64) {
            sha256_operation(sha_block, sha_block->data);
            sha_block->bitlen += 512;
            sha_block->datalen = 0;
        }
    }
}

void sha256_operation(sha256_block *sha_block, BYTE data[]) {
    WORD a, b, c, d, e, f, g, h, t1, t2, m[64];
    
    for (WORD i = 0; i < 16; ++i) {
        m[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) | (data[i * 4 + 2] << 8) | (data[i * 4 + 3]);
    }
    
    for (WORD i = 16; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    a = sha_block->state[0];
    b = sha_block->state[1];
    c = sha_block->state[2];
    d = sha_block->state[3];
    e = sha_block->state[4];
    f = sha_block->state[5];
    g = sha_block->state[6];
    h = sha_block->state[7];

    for (WORD i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    sha_block->state[0] += a;
    sha_block->state[1] += b;
    sha_block->state[2] += c;
    sha_block->state[3] += d;
    sha_block->state[4] += e;
    sha_block->state[5] += f;
    sha_block->state[6] += g;
    sha_block->state[7] += h;
}

void sha256_final(sha256_block *sha_block, BYTE hash[]) {
    WORD i = sha_block->datalen;
    if (sha_block->datalen < 56) {
        sha_block->data[i++] = 0x80;
        while (i < 56) sha_block->data[i++] = 0x00;
    } else {
        sha_block->data[i++] = 0x80;
        while (i < 64) sha_block->data[i++] = 0x00;
        sha256_operation(sha_block, sha_block->data);
        for (i = 0; i < 56; ++i) {
            sha_block->data[i] = 0x00;
        }
    }

    sha_block->bitlen += sha_block->datalen * 8;
    sha_block->data[63] = sha_block->bitlen;
    sha_block->data[62] = sha_block->bitlen >> 8;
    sha_block->data[61] = sha_block->bitlen >> 16;
    sha_block->data[60] = sha_block->bitlen >> 24;
    sha_block->data[59] = sha_block->bitlen >> 32;
    sha_block->data[58] = sha_block->bitlen >> 40;
    sha_block->data[57] = sha_block->bitlen >> 48;
    sha_block->data[56] = sha_block->bitlen >> 56;
    
    sha256_operation(sha_block, sha_block->data);

    for (i = 0; i < 4; ++i) {
        hash[i] = (sha_block->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4] = (sha_block->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8] = (sha_block->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (sha_block->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (sha_block->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (sha_block->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (sha_block->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (sha_block->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}
