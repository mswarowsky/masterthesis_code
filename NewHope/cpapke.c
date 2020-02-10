#include "api.h"
#include "poly.h"
#include "randombytes.h"
#include "fips202.h"
#include <stdio.h>

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
                    unsigned char *sk) {
    poly ahat, ehat, ahat_shat, bhat; // shat;
    unsigned char z[2 * NEWHOPE_SYMBYTES];
    unsigned char *publicseed = z;
    unsigned char *noiseseed = z + NEWHOPE_SYMBYTES;

    randombytes(z, NEWHOPE_SYMBYTES);
    shake256(z, 2 * NEWHOPE_SYMBYTES, z, NEWHOPE_SYMBYTES);

    gen_a(&ahat, publicseed);

    //TODO get back to random shat
//  poly_sample(&shat, noiseseed, 0);

///DEBUG
    poly shat = {{12289, 12286, 12295, 12295, 12294, 12297, 12296, 12297, 12286, 12286, 12291, 12291, 12293, 12290, 12287, 12288, 12292, 12287, 12290, 12288, 12288, 12290, 12290, 12289, 12288, 12288, 12291, 12286, 12291, 12290, 12289, 12290, 12288, 12288, 12293, 12292, 12286, 12288, 12291, 12286, 12292, 12290, 12293, 12294, 12289, 12293, 12291, 12291, 12287, 12285, 12289, 12291, 12289, 12292, 12287, 12284, 12286, 12292, 12290, 12289, 12292, 12289, 12288, 12290, 12289, 12289, 12291, 12290, 12290, 12288, 12289, 12292, 12286, 12289, 12291, 12287, 12292, 12288, 12290, 12289, 12290, 12291, 12290, 12290, 12288, 12292, 12290, 12289, 12290, 12292, 12287, 12287, 12287, 12288, 12287, 12287, 12291, 12286, 12289, 12288, 12290, 12291, 12290, 12289, 12287, 12290, 12287, 12288, 12292, 12286, 12289, 12288, 12289, 12291, 12288, 12285, 12285, 12287, 12289, 12290, 12288, 12286, 12291, 12291, 12289, 12285, 12291, 12288, 12290, 12286, 12290, 12291, 12287, 12286, 12291, 12287, 12289, 12291, 12292, 12291, 12290, 12289, 12289, 12290, 12289, 12288, 12287, 12289, 12290, 12289, 12288, 12292, 12291, 12288, 12292, 12288, 12289, 12291, 12293, 12285, 12291, 12291, 12292, 12292, 12290, 12290, 12288, 12293, 12288, 12294, 12292, 12288, 12293, 12289, 12285, 12287, 12289, 12288, 12287, 12287, 12289, 12289, 12289, 12292, 12284, 12291, 12292, 12290, 12286, 12287, 12287, 12288, 12289, 12290, 12287, 12283, 12288, 12289, 12291, 12293, 12288, 12290, 12291, 12288, 12289, 12287, 12290, 12289, 12288, 12287, 12288, 12290, 12292, 12287, 12290, 12291, 12291, 12290, 12288, 12292, 12289, 12290, 12291, 12288, 12290, 12291, 12291, 12287, 12289, 12292, 12289, 12289, 12289, 12286, 12291, 12289, 12290, 12287, 12291, 12291, 12294, 12292, 12285, 12290, 12286, 12289, 12290, 12290, 12286, 12291, 12291, 12288, 12287, 12289, 12290, 12292, 12287, 12291, 12291, 12289, 12288, 12292, 12291, 12292, 12292, 12288, 12287, 12292, 12291, 12291, 12284, 12289, 12291, 12291, 12289, 12288, 12288, 12289, 12290, 12290, 12292, 12290, 12287, 12291, 12290, 12287, 12292, 12290, 12291, 12289, 12289, 12285, 12294, 12289, 12288, 12289, 12286, 12286, 12296, 12286, 12288, 12288, 12287, 12290, 12288, 12288, 12290, 12293, 12288, 12293, 12286, 12290, 12289, 12291, 12290, 12286, 12288, 12288, 12290, 12286, 12287, 12294, 12292, 12289, 12288, 12287, 12289, 12288, 12291, 12291, 12288, 12288, 12288, 12287, 12285, 12289, 12292, 12292, 12288, 12292, 12288, 12287, 12287, 12285, 12290, 12289, 12288, 12291, 12290, 12291, 12292, 12289, 12293, 12292, 12287, 12290, 12286, 12291, 12291, 12288, 12292, 12291, 12293, 12290, 12288, 12289, 12285, 12291, 12285, 12289, 12293, 12288, 12288, 12292, 12288, 12289, 12287, 12291, 12291, 12288, 12290, 12289, 12290, 12288, 12286, 12290, 12291, 12293, 12287, 12287, 12287, 12289, 12287, 12288, 12288, 12288, 12289, 12291, 12287, 12288, 12290, 12290, 12290, 12288, 12288, 12289, 12287, 12291, 12287, 12291, 12291, 12288, 12289, 12288, 12292, 12288, 12288, 12287, 12288, 12290, 12292, 12291, 12291, 12290, 12288, 12290, 12289, 12290, 12292, 12287, 12288, 12292, 12291, 12286, 12290, 12285, 12291, 12292, 12292, 12288, 12287, 12288, 12288, 12287, 12287, 12292, 12288, 12292, 12289, 12287, 12285, 12290, 12290, 12290, 12291, 12288, 12289, 12290, 12290, 12286, 12289, 12288, 12286, 12289, 12288, 12289, 12289, 12290, 12290, 12288, 12290, 12289, 12287, 12285, 12290, 12288, 12291, 12291, 12293, 12289, 12289, 12289, 12288, 12287, 12293, 12291, 12286, 12281, 12290, 12288, 12292, 12290, 12291, 12293, 12285, 12288, 12289, 12293, 12290, 12289, 12288, 12290, 12289, 12290, 12288, 12287, 12290, 12290, 12290, 12287, 12286, 12286, 12288, 12288, 12291, 12291, 12289, 12290, 12286, 12287, 12290, 12292, 12288, 12289, 12287, 12290, 12292, 12286, 12288, 12288, 12288, 12290, 12288, 12289, 12287, 12290, 12289, 12289, 12290, 12290, 12290, 12291, 12289, 12290, 12290, 12287, 12292, 12291, 12286, 12289, 12289, 12292, 12290, 12293, 12293, 12287, 12289, 12288, 12292, 12290, 12291, 12284, 12291, 12290, 12292, 12289, 12284, 12289, 12289, 12292, 12288, 12290, 12287, 12286, 12291, 12293, 12291, 12286, 12289, 12290, 12293, 12291, 12287, 12288, 12289, 12290, 12288, 12288, 12291, 12288, 12288, 12290, 12290, 12290, 12289, 12288, 12291, 12293, 12289, 12290, 12288, 12287, 12289, 12289, 12288, 12290, 12291, 12290, 12290, 12294, 12287, 12286, 12287, 12284, 12286, 12290, 12290, 12290, 12292, 12289, 12292, 12291, 12292, 12291, 12287, 12285, 12287, 12288, 12293, 12290, 12290, 12289, 12290, 12288, 12287, 12288, 12287, 12289, 12287, 12289, 12287, 12285, 12291, 12287, 12290, 12286, 12289, 12291, 12289, 12289, 12292, 12286, 12286, 12288, 12287, 12289, 12287, 12288, 12289, 12291, 12289, 12290, 12286, 12287, 12286, 12290, 12288, 12289, 12290, 12296, 12291, 12287, 12288, 12289, 12291, 12286, 12293, 12288, 12291, 12287, 12290, 12292, 12294, 12289, 12285, 12289, 12289, 12289, 12290, 12285, 12290, 12287, 12291, 12292, 12288, 12293, 12289, 12289, 12286, 12285, 12290, 12289, 12287, 12291, 12287, 12288, 12290, 12286, 12290, 12287, 12290, 12286, 12290, 12287, 12291, 12287, 12291, 12290, 12290, 12288, 12290, 12288, 12293, 12288, 12286, 12289, 12286, 12290, 12286, 12288, 12288, 12288, 12294, 12290, 12291, 12289, 12287, 12289, 12289, 12286, 12289, 12289, 12291, 12291, 12288, 12289, 12289, 12285, 12287, 12289, 12288, 12287, 12288, 12290, 12292, 12289, 12290, 12287, 12286, 12290, 12290, 12286, 12288, 12292, 12288, 12289, 12293, 12285, 12290, 12287, 12290, 12287, 12288, 12285, 12289, 12290, 12289, 12291, 12292, 12293, 12289, 12290, 12290, 12290, 12288, 12290, 12291, 12291, 12293, 12291, 12287, 12288, 12291, 12291, 12292, 12287, 12288, 12290, 12291, 12291, 12291, 12291, 12287, 12289, 12288, 12288, 12284, 12289, 12287, 12290, 12290, 12290, 12287, 12289, 12287, 12292, 12287, 12290, 12290, 12292, 12290, 12287, 12289, 12289, 12289, 12285, 12290, 12290, 12288, 12291, 12287, 12289, 12288, 12289, 12289, 12288, 12289, 12289, 12292, 12289, 12293, 12290, 12290, 12288, 12292, 12285, 12289, 12290, 12291, 12292, 12291, 12287, 12292, 12288, 12290, 12288, 12293, 12290, 12289, 12289, 12288, 12288, 12290, 12289, 12292, 12290, 12287, 12293, 12286, 12290, 12286, 12290, 12292, 12287, 12284, 12288, 12289, 12289, 12289, 12291, 12294, 12288, 12289, 12288, 12292, 12289, 12290, 12288, 12289, 12285, 12289, 12289, 12290, 12291, 12289, 12288, 12289, 12290, 12287, 12287, 12291, 12288, 12291, 12291, 12290, 12291, 12291, 12289, 12290, 12287, 12289, 12288, 12292, 12290, 12288, 12289, 12288, 12287, 12287, 12289, 12289, 12287, 12287, 12289, 12291, 12289, 12286, 12286, 12285, 12291, 12291, 12284, 12288, 12289, 12291, 12287, 12286, 12290, 12284, 12291, 12291, 12288, 12289, 12290, 12288, 12291, 12289, 12288, 12289, 12291, 12286, 12290, 12290, 12288, 12290, 12290, 12287, 12288, 12288, 12288, 12288, 12287, 12292, 12287, 12293, 12285, 12288, 12287, 12289, 12286, 12289, 12287, 12289, 12290, 12288, 12290, 12289, 12288, 12288, 12290, 12288, 12289, 12290, 12290, 12292, 12291, 12289, 12291, 12294, 12287, 12285, 12289, 12287, 12291, 12289, 12285, 12289, 12292, 12292, 12288, 12292, 12291, 12292, 12291, 12290, 12288, 12287, 12288, 12291, 12288, 12291, 12287, 12290, 12288, 12288, 12285, 12289, 12287, 12287, 12289, 12290, 12294, 12295, 12293}};
    printf("\n s: ");
    for (int i = 0; i < 1024; ++i) {
        printf("%d, ", shat.coeffs[i]);
    }
    printf("\n");

    //so get to right values of s
    poly_ntt(&shat);
    poly_invntt(&shat);
    // end cosmetics

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

///DEBUG
extern void zero(poly * p);
///END DEBUG

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

//  poly_sub(&tmp, &tmp, &vprime);
    poly_sub(&tmp, &vprime, &tmp);

  poly_tomsg(m, &tmp);
}
