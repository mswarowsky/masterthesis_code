#include <stdio.h>
#include "api.h"
#include "poly.h"
#include "randombytes.h"
#include "fips202.h"

/*************************************************
* Name:        encode_pk
* 
* Description: Serialize the public key as concatenation of the
*              serialization of the polynomial pk and the public seed
*              used to generete the polynomial a.
*
* Arguments:   unsigned char *r:          pointer to the output serialized public key
*              const poly *pk:            pointer to the input public-key polynomial
*              const unsigned char *seed: pointer to the input public seed
**************************************************/
static void encode_pk(unsigned char *r, const poly *pk, const unsigned char *seed)
{
  int i;
  poly_tobytes(r, pk);
  for(i=0;i<NEWHOPE_SYMBYTES;i++)
    r[NEWHOPE_POLYBYTES+i] = seed[i];
}

/*************************************************
* Name:        decode_pk
* 
* Description: De-serialize the public key; inverse of encode_pk
*
* Arguments:   poly *pk:               pointer to output public-key polynomial
*              unsigned char *seed:    pointer to output public seed
*              const unsigned char *r: pointer to input byte array
**************************************************/
static void decode_pk(poly *pk, unsigned char *seed, const unsigned char *r)
{
  int i;
  poly_frombytes(pk, r);
  for(i=0;i<NEWHOPE_SYMBYTES;i++)
    seed[i] = r[NEWHOPE_POLYBYTES+i];
}

/*************************************************
* Name:        encode_c
* 
* Description: Serialize the ciphertext as concatenation of the
*              serialization of the polynomial b and serialization
*              of the compressed polynomial v
*
* Arguments:   - unsigned char *r: pointer to the output serialized ciphertext
*              - const poly *b:    pointer to the input polynomial b
*              - const poly *v:    pointer to the input polynomial v
**************************************************/
static void encode_c(unsigned char *r, const poly *b, const poly *v)
{
  poly_tobytes(r,b);
  poly_compress(r+NEWHOPE_POLYBYTES,v);
}

/*************************************************
* Name:        decode_c
* 
* Description: de-serialize the ciphertext; inverse of encode_c
*
* Arguments:   - poly *b:                pointer to output polynomial b
*              - poly *v:                pointer to output polynomial v
*              - const unsigned char *r: pointer to input byte array
**************************************************/
static void decode_c(poly *b, poly *v, const unsigned char *r)
{
  poly_frombytes(b, r);
  poly_decompress(v, r+NEWHOPE_POLYBYTES);
}

/*************************************************
* Name:        gen_a
* 
* Description: Deterministically generate public polynomial a from seed
*
* Arguments:   - poly *a:                   pointer to output polynomial a
*              - const unsigned char *seed: pointer to input seed
**************************************************/
static void gen_a(poly *a, const unsigned char *seed)
{
  poly_uniform(a,seed);
}


/*************************************************
* Name:        cpapke_keypair
* 
* Description: Generates public and private key 
*              for the CPA public-key encryption scheme underlying
*              the NewHope KEMs
*
* Arguments:   - unsigned char *pk: pointer to output public key
*              - unsigned char *sk: pointer to output private key
**************************************************/
void cpapke_keypair(unsigned char *pk,
                    unsigned char *sk)
{
  poly ahat, ehat, ahat_shat, bhat;
  unsigned char z[2*NEWHOPE_SYMBYTES];
  unsigned char *publicseed = z;
  unsigned char *noiseseed = z+NEWHOPE_SYMBYTES;

  randombytes(z, NEWHOPE_SYMBYTES);
  shake256(z, 2*NEWHOPE_SYMBYTES, z, NEWHOPE_SYMBYTES);

  gen_a(&ahat, publicseed);

    //DEBUG
//    poly shat;
//    poly_sample(&shat, noiseseed, 0);
  //TODO put shat back to the rest
  poly shat = { {1, 1, 12287, 12287, 3, 2, 12288, 12288, 4, 1, 12288, 1, 0, 12288, 12285,
                         12284, 12287, 2, 0, 0, 12286, 1, 0, 5, 12284, 12287, 12288, 2, 0, 12285, 1, 3,
                         12287, 1, 2, 4, 5, 12288, 2, 0, 12288, 0, 12288, 12288, 12288, 4, 12287, 12288,
                         12288, 12288, 12288, 12288, 12288, 12288, 0, 0, 12288, 12287, 2, 12287, 0,
                         12287, 1, 12288, 12288, 1, 0, 12286, 3, 12287, 2, 12287, 12287, 1, 0, 12287,
                         12288, 2, 12287, 3, 0, 1, 12288, 1, 2, 1, 1, 3, 1, 3, 3, 12287, 12288, 3, 1, 2,
                         12286, 12286, 12285, 12287, 12286, 12287, 12288, 1, 12288, 12285, 0, 12288,
                         12288, 2, 0, 12288, 0, 12288, 12285, 3, 2, 12288, 12288, 12285, 1, 2, 12288,
                         12288, 12288, 2, 3, 12288, 12288, 12288, 12288, 12287, 12288, 0, 12287, 4,
                         12288, 12288, 12288, 1, 0, 1, 1, 12288, 12285, 4, 3, 2, 0, 1, 12286, 12287,
                         12286, 0, 2, 12288, 12288, 12287, 1, 4, 12288, 12285, 12286, 12286, 4, 1, 1,
                         12287, 12288, 0, 2, 3, 12286, 2, 0, 3, 12288, 1, 1, 2, 12288, 0, 12286, 2, 2, 2,
                         12287, 12288, 2, 0, 0, 3, 0, 12288, 0, 1, 2, 12288, 0, 0, 2, 12287, 12287, 4,
                         12287, 1, 12288, 12287, 1, 1, 0, 12287, 0, 12287, 12288, 2, 1, 1, 12285, 12284,
                         1, 12288, 12288, 1, 2, 3, 2, 12286, 0, 0, 1, 1, 2, 1, 3, 0, 12284, 0, 0, 2, 1,
                         2, 12288, 1, 0, 12287, 2, 0, 12288, 12288, 12287, 2, 12287, 12288, 4, 12288, 1,
                         1, 0, 12288, 1, 1, 12287, 2, 2, 0, 0, 1, 12287, 12288, 1, 2, 12288, 0, 12288, 2,
                         12288, 12288, 12287, 1, 0, 12284, 1, 12288, 1, 2, 1, 12287, 3, 12287, 0, 2, 4,
                         12287, 0, 0, 12286, 1, 1, 1, 1, 12288, 12288, 12287, 1, 0, 2, 12286, 12287,
                         12288, 12288, 2, 3, 2, 12288, 1, 2, 1, 3, 12287, 12288, 12287, 12285, 4, 12287,
                         2, 2, 0, 12286, 0, 0, 12287, 3, 1, 12287, 12287, 2, 12288, 12288, 0, 12288, 4,
                         0, 12288, 12287, 1, 2, 0, 12287, 2, 12288, 4, 5, 12288, 12286, 12286, 12288, 0,
                         1, 12287, 1, 1, 12288, 0, 5, 12286, 12288, 12288, 12285, 12288, 2, 12287, 2, 2,
                         2, 2, 12288, 4, 12287, 12288, 2, 2, 4, 1, 0, 4, 1, 0, 3, 1, 12287, 2, 1, 12286,
                         12287, 1, 12285, 12286, 0, 12288, 1, 2, 12287, 12288, 1, 12288, 5, 0, 3, 0,
                         12288, 3, 12286, 12285, 0, 1, 12285, 2, 12288, 4, 1, 1, 12287, 0, 12288, 1, 1,
                         12285, 0, 12287, 1, 2, 0, 0, 2, 12288, 0, 2, 3, 0, 0, 1, 0, 2, 4, 0, 0, 12288,
                         0, 0, 12286, 3, 12288, 12288, 0, 12284, 12286, 2, 0, 12287, 12287, 12286, 5, 2,
                         2, 1, 12287, 12287, 2, 1, 12288, 2, 0, 12284, 0, 2, 12287, 2, 1, 1, 12288, 1, 0,
                         12288, 12288, 12286, 1, 1, 2, 1, 2, 12286, 0, 0, 12288, 12288, 12286, 2, 1,
                         12288, 2, 2, 12285, 2, 12286, 2, 12288, 12286, 12287, 3, 2, 1, 0, 2, 2, 12288,
                         12288, 1, 12286, 12287, 0, 4, 1, 12286, 12286, 12288, 12287, 2, 12288, 12286, 3,
                         3, 12287, 12287, 2, 0, 4, 4, 12287, 2, 2, 1, 12288, 1, 4, 0, 2, 1, 4, 12288,
                         12288, 1, 12287, 12286, 12287, 12284, 5, 0, 0, 1, 12288, 12287, 2, 12287, 1, 0,
                         12288, 3, 12288, 0, 12288, 12285, 12288, 12287, 12287, 0, 12287, 12286, 1, 2, 0,
                         1, 12287, 0, 2, 12286, 1, 12287, 12287, 12287, 4, 1, 12287, 1, 12288, 12285, 0,
                         1, 0, 12287, 3, 12285, 2, 3, 12288, 12288, 3, 3, 0, 1, 0, 2, 1, 12286, 0, 12288,
                         12288, 0, 12286, 2, 2, 12286, 0, 0, 0, 3, 12287, 12287, 4, 0, 1, 2, 1, 1, 3, 3,
                         0, 12288, 3, 12283, 0, 12288, 12287, 1, 12287, 12287, 0, 2, 0, 12286, 12288, 0,
                         0, 0, 12288, 0, 2, 2, 1, 0, 0, 1, 2, 0, 12287, 1, 1, 12288, 0, 12288, 12288, 4,
                         0, 0, 12286, 0, 0, 12287, 0, 2, 2, 4, 12288, 12287, 12288, 12288, 2, 0, 1,
                         12288, 0, 1, 12288, 0, 2, 0, 12287, 12288, 12288, 0, 1, 12286, 12287, 12288, 0,
                         1, 12287, 2, 12288, 2, 0, 0, 3, 12288, 2, 5, 12287, 3, 0, 12288, 12285, 3, 0,
                         12287, 12287, 12286, 2, 0, 12288, 12287, 12285, 0, 12288, 1, 0, 12288, 12287, 2,
                         1, 0, 0, 12287, 4, 12285, 0, 12287, 0, 2, 0, 12288, 1, 2, 1, 12287, 12288,
                         12286, 12288, 2, 12288, 4, 12287, 12288, 0, 4, 12287, 12285, 12288, 12288,
                         12287, 12287, 2, 2, 2, 0, 12288, 0, 0, 1, 12288, 0, 2, 1, 12287, 12287, 2, 1, 4,
                         1, 1, 3, 12288, 12288, 12287, 12287, 12288, 12288, 12288, 12286, 0, 0, 12286,
                         12288, 3, 12286, 12287, 2, 12288, 1, 2, 1, 12286, 12287, 12286, 12288, 12287,
                         12287, 5, 12288, 12285, 12285, 12285, 6, 12287, 0, 12287, 2, 12287, 12288,12288, 0, 2, 1, 12288, 12288, 12288, 12287, 1, 1, 2, 12288, 2, 1, 12288, 1, 0,12287, 0, 0, 12287, 3, 3, 1, 1, 2, 12288, 12288, 3, 0, 0, 1, 12288, 12286, 1, 0,0, 0, 12287, 0, 4, 2, 1, 12288, 3, 3, 0, 12288, 0, 1, 12286, 12287, 1, 12286, 3,3, 12288, 2, 2, 12288, 12287, 12287, 12287, 4, 12288, 5, 3, 1, 0, 12285, 12286,12287, 12287, 12287, 12288, 12287, 5, 12287, 12288, 12288, 12285, 12286, 12288,2, 12287, 3, 12287, 12287, 0, 12286, 0, 12286, 0, 12288, 1, 2, 2, 1, 12287, 3,12288, 2, 1, 12286, 0, 12287, 0, 12287, 12286, 6, 0, 1, 1, 0, 4, 12286, 1,12288, 2, 0, 1, 4, 2, 2, 12288, 0, 1, 1, 0, 12288, 1, 3, 3, 12288, 0, 2, 0,12288, 1, 5, 4, 3, 4, 0, 12287, 12286, 1, 2, 2, 0, 12286, 2, 12288, 0, 12288,12288, 12288, 4, 2, 1, 0, 3, 0, 1, 2, 0, 12288, 1, 12287, 3, 1, 12286, 12288,12287, 12287, 0, 12288, 4, 0, 1, 12286, 12288, 12288, 2, 12287, 12288, 12288,12288, 12287, 3, 12286, 12287, 12288, 12287, 1, 1}
    };

    printf("sks raw:[");
    for (int i = 0; i < NEWHOPE_N; ++i) {
        if(shat.coeffs[i] >= NEWHOPE_Q){
            shat.coeffs[i] -= NEWHOPE_Q;
        }
//        printf("%d,",((sks.coeffs[i])));
        printf("%d,",shat.coeffs[i]);
    }
    printf("]\n");
//
    poly_ntt(&shat);
    poly_invntt(&shat);
//    poly_ntt(&shat);
//    poly_invntt(&shat);
//
//    printf("sk  raw:[");
//    for (int i = 0; i < NEWHOPE_N; ++i) {
//        printf("%d,",shat.coeffs[i]);
//    }
//    printf("]\n");
    //END DEBUG

  poly_ntt(&shat);

  poly_sample(&ehat, noiseseed, 1);
  poly_ntt(&ehat);

  poly_mul_pointwise(&ahat_shat, &shat, &ahat);
  poly_add(&bhat, &ehat, &ahat_shat);

  poly_tobytes(sk, &shat);
  encode_pk(pk, &bhat, publicseed);
}

/*************************************************
* Name:        cpapke_enc
* 
* Description: Encryption function of
*              the CPA public-key encryption scheme underlying
*              the NewHope KEMs
*
* Arguments:   - unsigned char *c:          pointer to output ciphertext
*              - const unsigned char *m:    pointer to input message (of length NEWHOPE_SYMBYTES bytes)
*              - const unsigned char *pk:   pointer to input public key
*              - const unsigned char *coin: pointer to input random coins used as seed
*                                           to deterministically generate all randomness
**************************************************/
void cpapke_enc(unsigned char *c,
                const unsigned char *m,
                const unsigned char *pk,
                const unsigned char *coin)
{
  poly sprime, eprime, vprime, ahat, bhat, eprimeprime, uhat, v;
  unsigned char publicseed[NEWHOPE_SYMBYTES];

  poly_frommsg(&v, m);

  decode_pk(&bhat, publicseed, pk);
  gen_a(&ahat, publicseed);

  poly_sample(&sprime, coin, 0);
  poly_sample(&eprime, coin, 1);
  poly_sample(&eprimeprime, coin, 2);

  poly_ntt(&sprime);
  poly_ntt(&eprime);

  poly_mul_pointwise(&uhat, &ahat, &sprime);
  poly_add(&uhat, &uhat, &eprime);

  poly_mul_pointwise(&vprime, &bhat, &sprime);
  poly_invntt(&vprime);

  poly_add(&vprime, &vprime, &eprimeprime);
  poly_add(&vprime, &vprime, &v); // add message

  encode_c(c, &uhat, &vprime);
}


/*************************************************
* Name:        cpapke_dec
* 
* Description: Decryption function of
*              the CPA public-key encryption scheme underlying
*              the NewHope KEMs
*
* Arguments:   - unsigned char *m:        pointer to output decrypted message
*              - const unsigned char *c:  pointer to input ciphertext
*              - const unsigned char *sk: pointer to input secret key
**************************************************/
void cpapke_dec(unsigned char *m,
                const unsigned char *c,
                const unsigned char *sk)
{
  poly vprime, uhat, tmp, shat;

  poly_frombytes(&shat, sk);

  decode_c(&uhat, &vprime, c);
  poly_mul_pointwise(&tmp, &shat, &uhat);
  poly_invntt(&tmp);

    //DEBUG

    printf("\nvprime: [");
    for (int i = 0; i < NEWHOPE_N; ++i) {
        printf("%d,",vprime.coeffs[i]);
    }
    printf("] ");

    //DEBUG END

  poly_sub(&tmp, &tmp, &vprime);

    //DEBUG

    printf("\nk:   [");

    for (int i = 0; i < NEWHOPE_N; ++i) {
        printf("%d,",tmp.coeffs[i]);
    }
    printf("] \n");
    //DEBUG END

  poly_tomsg(m, &tmp);
}
