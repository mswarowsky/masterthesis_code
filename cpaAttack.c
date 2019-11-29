#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include "NewHope/api.h"
#include "NewHope/poly.h"
#include "NewHope/cpapke.h"
#include "printParamas.h"

#define AT_SUCCESS          0
#define AT_FILE_OPEN_ERROR -1
#define AT_DATA_ERROR      -3
#define AT_CRYPTO_FAILURE  -4

/** q = 8s + 1 **/
#define S 1536

unsigned char       ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss1[CRYPTO_BYTES];
unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];

static void decode_pk(poly *pk, unsigned char *seed, const unsigned char *r);
static void gen_a(poly *a, const unsigned char *seed);
static void encode_c(unsigned char *r, const poly *b, const poly *v);

/***************************** Attack related *******************************/
#define SS_BITS (NEWHOPE_N/4)
#define MAX_TRIES 10
#define QUADRUPLET_SIZE 4
#define TEST_RANGE 8

typedef struct {
    int16_t l[QUADRUPLET_SIZE];
} quadruplet_t __attribute__ ((aligned (32)));

typedef struct {
    bool b[TEST_RANGE];
}oracle_bitmap_t;

typedef struct {
    unsigned char key[CRYPTO_BYTES];
} keyHypothesis_t;

unsigned  char attack_ct[CRYPTO_CIPHERTEXTBYTES];

void key_recovery(poly *sk_guess);

void sampleRandom(quadruplet_t * q, int16_t lower_bound, int16_t upper_bound);

void init(oracle_bitmap_t * b);

void create_attack_ct(const poly *Uhat, quadruplet_t *l, int16_t k, int16_t j);

bool checkAtBorders(quadruplet_t * l, int quadruplet_index, int16_t target_index, const poly * Uhat,
        keyHypothesis_t * k);

uint8_t testAndFindTau(int8_t * tau, quadruplet_t * l, int quadruplet_index, int16_t target_index, const poly * Uhat,
        keyHypothesis_t * k, oracle_bitmap_t * oracle_results);

bool mismatchOracle(const unsigned char * ciphertext, keyHypothesis_t * hypothesis);

int16_t find_s(const int8_t * tau);

void zero(poly * p);
/*****************************************************************************/


int main() {
    int ret_val;
    poly sk_guess;

    srand(time(0));


    // get some keys
    if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
        printf("crypto_kem_keypair returned <%d>\n", ret_val);
        return AT_CRYPTO_FAILURE;
    }

//    printf("The Alice keys are :\npk: ");
//    printfPrams(pk, CRYPTO_PUBLICKEYBYTES);
//    printf("\nsk: ");
//    printfPrams(sk, CRYPTO_SECRETKEYBYTES);
//    printf("\n");

    ///////////////////////////////////////////////
    /// DEBUG
    //////////////////////////////////////////////
//    poly shat;
//    poly_frombytes(&shat, sk);
//    poly_invntt(&shat);
//    printf("sk raw:[");
//    for (int i = 0; i < NEWHOPE_N; ++i) {
//        printf("%d,",((shat.coeffs[i] - NEWHOPE_Q) % NEWHOPE_Q));
//    }
//    printf("]\n");

    quadruplet_t l;
    sampleRandom(&l, -4, 3);
    printf("l:[%d ,%d, %d, %d]\n",l.l[0], l.l[1],l.l[2],l.l[3]);

    uint16_t  k = 0;
    poly Uhat;
    zero(&Uhat);
    Uhat.coeffs[NEWHOPE_N - k - 1] = S/2;  // U = (s/2) x^(-k)
    printf("U:[");
    for (int i = 0; i < NEWHOPE_N; ++i) {
        printf("%d,",Uhat.coeffs[i]);
    }
    printf("]\n");
    poly_ntt(&Uhat);    //directly convert into NTT domain

    create_attack_ct(&Uhat, &l, 0,0);
//    printf("ct is: ");
//    printfPrams(attack_ct, CRYPTO_CIPHERTEXTBYTES);
    cpapke_dec(ss, attack_ct, sk);
    printf("\nss: ");
    printfPrams(ss, CRYPTO_BYTES);

    ///////////////////////////////////////////////
    /// DEBUG
    //////////////////////////////////////////////

    // Attack starting here
//    key_recovery(&sk_guess);
//    printf("sk guess:[");
//    for (int i = 0; i < NEWHOPE_N; ++i) {
//        printf("%d,",sk_guess.coeffs[i]);
//    }
//    printf("]\n");



    return AT_SUCCESS;
}

void key_recovery(poly *sk_guess){
    int queries = 0;
    uint16_t n_not_recovered = 0;
    // creating the guessed key for the hacker \nu_E = (1,0,0,...,0)
    keyHypothesis_t attacker_key_hypotesis;
    for(int i = 0; i < CRYPTO_BYTES; i++){
        attacker_key_hypotesis.key[i] = 0;
    }
    attacker_key_hypotesis.key[0] = 1;

//    for(int k = 0; k < SS_BITS; k++){
    for(int k = 0; k < 2; k++){
        poly Uhat;
        zero(&Uhat);
        Uhat.coeffs[NEWHOPE_N - k - 1] = (S/2);  // U = (s/2) x^(-k)
        //directly convert into NTT domain
        poly_ntt(&Uhat);
        //setting U moved to create_attack_ct
        //target the coefficients in a quadruplet after each other
        for( int j = 0; j < 4; j++){
            bool not_found_yet = true;
            printf("Target index:%d quadruplet index: %d \n", k, j);
            //search for each index until we find it.
            while (not_found_yet == true) {
                int tries = 0;
                int8_t tau[2] = {-10, -10};

                while (tries <MAX_TRIES) {
                    quadruplet_t l;
                    oracle_bitmap_t oracleErrors;
                    init(&oracleErrors);
                    sampleRandom(&l, -4, 3); //l := drawl()

                    //Border check ???
                    if(checkAtBorders(&l, j,k, &Uhat,&attacker_key_hypotesis)){
                        printf("[+,");
                        //if the borders are ok then we have positive oracle result on the borders
                        oracleErrors.b[0] = oracleErrors.b[TEST_RANGE - 1] = true;
                        //this tries l_j \in [-3,2] and already fingers \tau_1 and \tau_2 out
                        queries +=testAndFindTau(tau, &l, j, k, &Uhat, &attacker_key_hypotesis, &oracleErrors);
                        tries++;
                        printf("+]   ");
                    }
                    //check borders uses 2 queries
                    queries +=2;
                }

                //check if we didn't manage to find something proper
                if(tries == MAX_TRIES){
                    printf("\nClould not find coefficient %d :(\n", k+(j * SS_BITS));
                    n_not_recovered++;
                    not_found_yet = false;
                } else {
                    // FindS
                    int16_t guess_for_s = find_s(tau);

                    //more complex checks here in magma but they are not executed...
                    // may be interesting for debug

//                    test_hypothesis(guess_for_s, k, j);

                    //saving the recovered coefficient
                    sk_guess->coeffs[k + (j * SS_BITS)] = guess_for_s;
                    not_found_yet = false;
                    printf("\n");
                }
            }
        }
    }

    printf("Finished hole attack took %d queries and could not find: %d coefficients\n",
            queries, n_not_recovered);
}

/**
 * Queries optimizations
 * Checks if we have postive result on the borders of l \in [-4,3] as this is needed for a favorable case
 * Uses two oracle queries
 * @param l the quadruplet values to test
 * @param quadruplet_index the target index of the the quadruplet
 * @param target_index the global target index in S
 * @param U Attacker (Bob) public key
 * @param k the guessed key
 * @return
 */
bool checkAtBorders(quadruplet_t * l, const int quadruplet_index, const int16_t target_index, const poly * Uhat, keyHypothesis_t * k){
    uint16_t backup;
    bool errorLowerBound;
    bool errorUpperBound;

    backup = l->l[quadruplet_index];
    l->l[quadruplet_index] = -4;
    create_attack_ct(Uhat, l, target_index, quadruplet_index);;
    errorLowerBound = mismatchOracle(attack_ct, k);
    l->l[quadruplet_index] = 3;
    create_attack_ct(Uhat, l, target_index, quadruplet_index);;
    errorUpperBound = mismatchOracle(attack_ct, k);

    //restoring the quadruplet
    l->l[quadruplet_index] = backup;
    return (errorLowerBound == true) && (errorUpperBound == true);
}

/**
 * Checks on the "quadruplet_index" of l in the range of [-3,2] and figures out the sign changes tau_1 and tau_2
 * This function assumes the borders of the quadruplet are already checked and oracle_results contains the correct
 * values
 * @param l current targeted quadruplet
 * @param quadruplet_index the index in the quadruplet that is targeted
 * @param target_index the global target index in S needed to create the ciphertext
 * @param U the public key from the attacker(Bob) needed to create the ciphertext
 * @param k the guessed shared secret key before hashing
 * @param oracle_results the bitmap with the orecle results for this targeted quadruplet
 * @return number of queries used
 */
uint8_t testAndFindTau(int8_t * tau, quadruplet_t * l, const int quadruplet_index, const int16_t target_index,
        const poly * Uhat, keyHypothesis_t * k, oracle_bitmap_t * oracle_results){
    uint8_t queries = 0;
    uint8_t sign_changes = 0;
    int16_t l_test_value = -3; //start with -3 as this

    for (int i = 1; i < TEST_RANGE - 1; ++i) {
        l->l[quadruplet_index] = l_test_value;
        create_attack_ct(Uhat, l, target_index, quadruplet_index);
        oracle_results->b[i] = mismatchOracle(attack_ct, k);
        oracle_results->b[i] == true ? printf("+,") : printf("-,");
        queries++;

        //check and set tau_2 from false(0) -> true(1)
        if (oracle_results->b[i-1] == false && oracle_results->b[i] == true) {
            sign_changes++;         //should always be 2 here but this is taken from the magma code
            tau[1] = l_test_value;  //using the test value as this closer to the paper instead of magma version
            //not fully necessary but again follow the magma code
            for (int r = i +1; r < TEST_RANGE - 1; ++r) {
                oracle_results->b[r] = true;
            }
        }

        //check and set tau_1 from true(1) -> false(0)
        if(oracle_results->b[i-1] == true && oracle_results->b[i] == false){
            sign_changes++;         //should be 1 here ...
            tau[0] = l_test_value;  //using the test value as this closer to the paper instead of magma version
        }

        //check if only have on time false(0) then this is the case at at i=6 under the assumtion that we stop after finding
        // tau_2 otherwise
        if(i == 6 && oracle_results->b[i-1] == true){
            sign_changes++;
            tau[1] = l_test_value;    //original is i but we are using indices starting form 0 instead of 1
        }

        // after 2 sign changes we have all information and can stop
        if(sign_changes > 1) break;
        //update test value for next run
        l_test_value++;
    }
    return queries;
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

/**
 * Fill the given quadruplet with random numbers in the given range
 * @param q
 * @param lower_bound
 * @param upper_bound
 */
void sampleRandom(quadruplet_t * q, int16_t lower_bound, int16_t upper_bound){
    assert(lower_bound < upper_bound);

    int16_t dist = upper_bound - lower_bound + 1;

    for (int i = 0; i < QUADRUPLET_SIZE; ++i) {
        q->l[i] = (rand() % dist) + lower_bound;
    }
}

void init(oracle_bitmap_t * b){
    for (int i = 0; i < TEST_RANGE; ++i) {
        b->b[i] = false;
    }
}

/**
 * Creates an ciphertext that can be used for the attack and stores it in the global attack_ct
 * @param Uhat
 * @param l
 * @param k
 * @param j
 */
void create_attack_ct(const poly * Uhat, quadruplet_t *l, int16_t k, int16_t j) {
    int16_t sum_quadruplet = 0;

    for (int i = 0; i < QUADRUPLET_SIZE; ++i) {
        if(i == j) continue;   //calculate the sum of l excluding the target index
        sum_quadruplet += (l->l[i] + 4 % 8);
    }

    poly c;
    zero(&c);
    c.coeffs[k + (j*SS_BITS)] = sum_quadruplet;

    encode_c(attack_ct, Uhat, &c);
}

/**
 * This takes a chiphertext and checks if this this ciphertext creates the same key than the given hypothesis
 * @param ciphertext
 * @param hypothesis
 * @return false(0) if the keys are the same otherwise true(1)
 */
bool mismatchOracle(const unsigned char * ciphertext, keyHypothesis_t * hypothesis){
    //first get the shared key from Alice
    cpapke_dec(ss, ciphertext, sk);

//    printf("compare ss: ");
//    printfPrams(ss, CRYPTO_BYTES);
//
//    printf("\ncompare hp: ");
//    printfPrams(hypothesis->key, CRYPTO_BYTES);
//    printf("\n");
    //now compare the hypothesis with the key from alice
    uint16_t errors = 0;
    for (int i = 0; i < CRYPTO_BYTES; ++i) {
        if (hypothesis->key[i] != ss[i]) {
            if(i != 0) printf("Something strange, error outside of index 0 - %d\n", i);
            errors++;
        }
    }
//    exit(1);
    return errors == 0 ? false : true;
}

/**
 * Takes tau_1 and tau_2 and creates a guess for the coefficient of s according to these tau's
 * This only the second half of the FindS algo from the paper
 * @param tau
 * @return
 */
int16_t find_s(const int8_t * tau_1_2){
    int16_t tau;
    int16_t guess_for_s;
    if(tau_1_2[0] == -10) {
        //we only got tau_2
        tau = tau_1_2[1];
    } else {
        //the normal case
        tau = tau_1_2[0] + tau_1_2[1];
    }

    if((tau % 2) == 0){
        guess_for_s = tau;
    } else {
        guess_for_s = (2*(tau/2)) + 1;
    }
    return tau;
}

/**
 * fills the polynom with zero coefficients
 * @param p
 */
void zero(poly * p){
    for (int i = 0; i < NEWHOPE_N; ++i) {
        p->coeffs[i] = 0;
    }
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

