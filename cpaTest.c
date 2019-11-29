#include <stdio.h>
#include "NewHope/api.h"
#include "printParamas.h"

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

unsigned char       ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss1[CRYPTO_BYTES];
unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];


int main(){

    int                 ret_val;


    // get some keys
    if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
        printf("crypto_kem_keypair returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }


    printf("The Alice keys are :\npk: ");
    printfPrams(pk, CRYPTO_PUBLICKEYBYTES);
    printf("\nsk: ");
    printfPrams(sk, CRYPTO_SECRETKEYBYTES);


    if ( (ret_val = crypto_kem_enc(ct, ss, pk)) != 0) {
        printf("crypto_kem_enc returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }

    printf("\n\nct is: ");
    printfPrams(ct, CRYPTO_CIPHERTEXTBYTES);


    if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) {
        printf("crypto_kem_dec returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }

    printf( "\nFinal shared keys are: \nBob:   ");
    printfPrams(ss, CRYPTO_BYTES);
    printf("\nAlice: ");
    printfPrams(ss1, CRYPTO_BYTES);

    return KAT_SUCCESS;
}
