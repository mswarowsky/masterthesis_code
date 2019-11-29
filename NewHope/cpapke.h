#ifndef INDCPA_H
#define INDCPA_H


void cpapke_keypair(unsigned char *pk, 
                    unsigned char *sk);

void cpapke_enc(unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk,
               const unsigned char *coins);

void cpapke_dec(unsigned char *m,
               const unsigned char *c,
               const unsigned char *sk);

////made public for the attack
//static void decode_pk(poly *pk,
//        unsigned char *seed,
//        const unsigned char *r);
//static void gen_a(poly *a, const unsigned char *seed);

#endif
