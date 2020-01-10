#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <math.h>
#include "NewHope/api.h"
#include "NewHope/poly.h"
#include "NewHope/cpapke.h"
#include "printParamas.h"

#define AT_SUCCESS          0
#define AT_FILE_OPEN_ERROR -1
#define AT_DATA_ERROR      -3
#define AT_CRYPTO_FAILURE  -4

//#define printf //
#define DEV


static void encode_c(unsigned char *r, const poly *b, const poly *v);

// Multithreading stuff
pthread_mutex_t lock;

void *testRun(void *arg);


/***************************** Attack related *******************************/
#define SS_BITS (NEWHOPE_N/4)
#define MAX_TRIES 20
#define QUADRUPLET_SIZE 4
#define TEST_RANGE 8
#define S 1536  /** q = 8s + 1 **/
#define NOT_FOUND 2000

typedef struct {
    int16_t l[QUADRUPLET_SIZE];
} quadruplet_t __attribute__ ((aligned (32)));

typedef struct {
    bool b[TEST_RANGE];
}oracle_bitmap_t;

typedef struct {
    unsigned char key[CRYPTO_BYTES];
} keyHypothesis_t;

void full_attack();

int key_recovery(poly *sk_guess, unsigned char * sk, uint16_t  * n_not_recovered);

void sampleRandom(quadruplet_t * q, int16_t lower_bound, int16_t upper_bound);

void init(oracle_bitmap_t * b);

void create_attack_ct(const poly *Uhat, quadruplet_t *l, unsigned char * attack_ct);

bool checkAtBorders(quadruplet_t * l, int quadruplet_index, int16_t target_index, const poly * Uhat,
                    keyHypothesis_t * k,  unsigned char *sk);

uint8_t testAndFindTau(int8_t *tau, uint8_t *sign_changes, quadruplet_t *l, const int quadruplet_index,
                       const int16_t target_index, const poly *Uhat, keyHypothesis_t *k,
                       oracle_bitmap_t *oracle_results,  unsigned char * sk);

bool mismatchOracle(const unsigned char *ciphertext, keyHypothesis_t *hypothesis, unsigned char *sk);

int16_t find_s(const int8_t *tau);

void zero(poly *p);

void genfakeU(poly *U, int k);

void printPoly(poly *p);

int find_m_sum(int *m, unsigned char *sk, int16_t target_index);

int qin_recover(poly *s_so_far, unsigned char *sk, uint16_t *n_not_recovered);

/*****************************************************************************/


int main() {
#ifdef DEV
    FILE *log = fopen("attack_DEV.log", "a+");
    full_attack(log);
    fclose(log);
    return 0;
#endif

#ifndef DEV
    if (pthread_mutex_init(&lock, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        return 1;
    }

    pthread_t t1, t2,t3, t4;
    pthread_create(&t1, NULL, testRun, NULL);
    pthread_create(&t2, NULL, testRun, NULL);
    pthread_create(&t3, NULL, testRun, NULL);
    pthread_create(&t4, NULL, testRun, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
    pthread_join(t4, NULL);
#endif
}

void * testRun(void * arg) {
    pthread_mutex_lock(&lock);
    FILE *log = fopen("attack.log", "a+");
    pthread_mutex_unlock(&lock);

    if (log == NULL) {
        printf("File could not open: %s", strerror(errno));
        return NULL;
    }

    for (int i = 0; i < 250; ++i) {
        full_attack(log);
    }

    pthread_mutex_lock(&lock);
    fclose(log);
    pthread_mutex_unlock(&lock);

    return NULL;
}

void full_attack(FILE * log) {
    int ret_val;
    uint16_t n_not_recovered = 0;

//    unsigned char       ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss1[CRYPTO_BYTES];
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];


    poly sk_guess;
    zero(&sk_guess);

    srand(time(0));


    // get some keys
    if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
        printf("crypto_kem_keypair returned <%d>\n", ret_val);
        return;
    }


//    // Attack starting here
    int queries = key_recovery(&sk_guess, sk, &n_not_recovered);


    poly s;
    poly_frombytes(&s, sk);
    poly_invntt(&s);

    //recover rest



    // evaluation
    printf("guess :[");
    for (int i = 0; i < NEWHOPE_N; i++) {
        printf("%d, ", sk_guess.coeffs[i]);
    }
    printf("]\nreal s:[");
    for (int j = 0; j < NEWHOPE_N; j++) {
        printf("%d, ", s.coeffs[j] % NEWHOPE_Q);
    }
    printf("]\n");

    int not_findable = 0;
    int correct = 0;
    for (int j = 0; j < NEWHOPE_N; j++) {
        uint16_t real_coefficient = s.coeffs[j] % NEWHOPE_Q;
        if(real_coefficient > 4 && real_coefficient < 12283) {
            not_findable++;
        } else {
            if (sk_guess.coeffs[j] != real_coefficient) {
                printf("wrong at %d real: %d vs. %d\n", j, real_coefficient, sk_guess.coeffs[j]);
            } else {
                correct++;
            }
        }
    }

    printf("%d correct - %d wrong not possible: %d\n", correct, NEWHOPE_N - correct, not_findable);
    pthread_mutex_lock(&lock);
    fprintf(log, "%d; %d; %d; %d; %d\n", correct, NEWHOPE_N - correct, n_not_recovered, not_findable, queries);
    fflush(log);
    pthread_mutex_unlock(&lock);
}

int key_recovery(poly *sk_guess, unsigned char * sk, uint16_t  * n_not_recovered){
    int queries = 0;
    unsigned char attack_ct[CRYPTO_CIPHERTEXTBYTES];
    // creating the guessed key for the hacker \nu_E = (1,0,0,...,0)
    keyHypothesis_t attacker_key_hypotesis;
    for(int i = 0; i < CRYPTO_BYTES; i++){
        attacker_key_hypotesis.key[i] = 0;
    }
    attacker_key_hypotesis.key[0] = 1;

    for(int k = 0; k < SS_BITS; k++){
        poly Uhat;
        zero(&Uhat);
        genfakeU(&Uhat, k);
//        printf("U: ");printPoly(&Uhat); ///DEBUG

        //target the coefficients in a quadruplet after each other
        for( int j =  0; j < 4; ++j){
            bool not_found_yet = true;
            printf("Target index:%d quadruplet index: %d \n", k, j);
            //search for each index until we find it.
            while (not_found_yet == true) {
                int tries = 0;
                uint8_t sign_change = 0;
                int8_t tau[2] = {-10, -10};

                while (tries < MAX_TRIES && sign_change < 2) {
                    quadruplet_t l;
                    sign_change = 0;
                    oracle_bitmap_t oracleErrors;
                    init(&oracleErrors);
                    sampleRandom(&l, -4, 3); //l := drawl()

                    //Border check ???
                    if(checkAtBorders(&l, j,k, &Uhat,&attacker_key_hypotesis, sk)){
                        printf("l:[%d, %d, %d, %d] ", l.l[0], l.l[1], l.l[2],l.l[3]);
                        printf("[+,");
                        //if the borders are ok then we have positive oracle result on the borders
                        oracleErrors.b[0] = oracleErrors.b[TEST_RANGE - 1] = true;
                        //this tries l_j \in [-3,2] and already fingers \tau_1 and \tau_2 out
                        queries += testAndFindTau(tau, &sign_change, &l, j, k, &Uhat, &attacker_key_hypotesis,
                                &oracleErrors, sk);
                        tries++;
                        printf("+]   ");
                    }
                    //check borders uses 2 queries
                    queries +=2;
                }

                //check if we didn't manage to find something proper
                if (tries == MAX_TRIES && tau[1] == -10) {
                    printf("\nClould not find coefficient %d :(\n", k + (j * SS_BITS));
                    (*n_not_recovered)++;
                    not_found_yet = false;
                    //TODO find out sign for qin optimization
                    sk_guess->coeffs[k + (j * SS_BITS)] = NOT_FOUND;

                } else {
                    // FindS
                    int16_t guess_for_s = find_s(tau);

                    //more complex checks here in magma but they are not executed...
                    // may be interesting for debug

//                    test_hypothesis(guess_for_s, k, j);

                    //saving the recovered coefficient
                    sk_guess->coeffs[k + (j * SS_BITS)] = ((guess_for_s + NEWHOPE_Q) % NEWHOPE_Q);
                    printf("s[%d] = %d", k + (j * SS_BITS), guess_for_s);
                    not_found_yet = false;
                    printf("\n");
                }
            }
        }
    }

    //no applying the optimization from Qin et. al.
    int qin_queries = qin_recover(sk_guess, sk, n_not_recovered);

    printf("Finished hole attack took %d queries qin took %d queries and could not find: %d coefficients\n", queries,
           qin_queries, *n_not_recovered);
    return queries;
}

/**
 * Recover more coefficients with the method of Qin et al.
 * @param s_so_far          the so fare recovered secret key will also be used to write the new coefficients in
 * @param sk                real secrete key
 * @param n_not_recovered   the number of not yet recovered coefficients, will also be updated
 * @return                  Number of queries used
 */
int qin_recover(poly *s_so_far, unsigned char *sk, uint16_t *n_not_recovered) {
    int queries = 0;
    for (int i = 0; i < SS_BITS; ++i) {

        for (int j = 0; j < 4; ++j) {
            // TEST if already recovered
            if (s_so_far->coeffs[i + 256 * j] != NOT_FOUND) {
                break;
            }
            int m;
            queries += find_m_sum(&m, sk, (i + 256 * j));

            printf("The sum m is:%d\n", m);

            // Subtract the other three coefficients from the sum
            for (int k = 0; k < 4; ++k) {
                if (j != k) {
                    m -= abs(s_so_far->coeffs[i + 256 * k] - NEWHOPE_Q);
                }
            }

            ///assign the sign
            //TODO no sign form the previous run
            s_so_far->coeffs[i + 256 * j] = m;
            (*n_not_recovered)--;
        }
    }

    return queries;
}

int find_m_sum(int *m, unsigned char *sk, int16_t target_index) {
    unsigned char attack_ct[CRYPTO_CIPHERTEXTBYTES];
    for (int h = 0; h < NEWHOPE_Q - 1; ++h) {
        //setting U with U[512] = h rest 0
        poly Uhat;
        zero(&Uhat);
        Uhat.coeffs[512] = h;
        poly_ntt(&Uhat);

        //creating c with v[target_i] = 1 rest 0
        keyHypothesis_t k;
        memset(k.key, 0, 32);
        k.key[target_index / 8] = (1 << (target_index % 8));
        poly k_poly;
        poly_frommsg(&k_poly, k.key);

        //assemble the full ciphertext
        encode_c(attack_ct, &Uhat, &k_poly);

        // if the target index key first time changes from 1 to 0 then we have m
        if (mismatchOracle(attack_ct, &k, sk)) {
            *m = (int) (((NEWHOPE_Q + 2.0) / h) + 0.5);
            break;
        }
    }

    return 0;
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
bool checkAtBorders(quadruplet_t * l, const int quadruplet_index, const int16_t target_index, const poly * Uhat,
                    keyHypothesis_t * k, unsigned char * sk){
    uint16_t backup;
    bool errorLowerBound;
    bool errorUpperBound;
    unsigned char attack_ct[CRYPTO_CIPHERTEXTBYTES];

    backup = l->l[quadruplet_index];
    l->l[quadruplet_index] = -4;
    create_attack_ct(Uhat, l, attack_ct);
    errorLowerBound = mismatchOracle(attack_ct, k, sk);
    l->l[quadruplet_index] = 3;
    create_attack_ct(Uhat, l, attack_ct);
    errorUpperBound = mismatchOracle(attack_ct, k, sk);

    //restoring the quadruplet
    l->l[quadruplet_index] = backup;
    return (errorLowerBound == true) && (errorUpperBound == true);
}

/**
 * Checks on the "quadruplet_index" of l in the range of [-3,2] and figures out the sign changes tau_1 and tau_2
 * This function assumes the borders of the quadruplet are already checked and oracle_results contains the correct
 * values
 * @param tau OUTPUT tau_1 and tau_2
 * @param sign_changes how often a sign change was found
 * @param l current targeted quadruplet
 * @param quadruplet_index the index in the quadruplet that is targeted
 * @param target_index the global target index in S needed to create the ciphertext
 * @param U the public key from the attacker(Bob) needed to create the ciphertext
 * @param k the guessed shared secret key before hashing
 * @param oracle_results the bitmap with the orecle results for this targeted quadruplet
 * @return number of queries used
 */
uint8_t testAndFindTau(int8_t *tau, uint8_t *sign_changes, quadruplet_t *l, const int quadruplet_index,
                       const int16_t target_index, const poly *Uhat, keyHypothesis_t *k,
                       oracle_bitmap_t *oracle_results, unsigned char * sk) {
    uint8_t queries = 0;
    int16_t l_test_value = -3; //start with -3 as this
    unsigned char attack_ct[CRYPTO_CIPHERTEXTBYTES];

    for (int i = 1; i < TEST_RANGE - 1; ++i) {
        l->l[quadruplet_index] = l_test_value;
        create_attack_ct(Uhat, l, attack_ct);
        oracle_results->b[i] = mismatchOracle(attack_ct, k, sk);
//        printf("\n");
        oracle_results->b[i] == true ? printf("+,") : printf("-,");
        queries++;

        //check and set tau_2 from false(0) -> true(1)
        if (oracle_results->b[i-1] == false && oracle_results->b[i] == true) {
            (*sign_changes)++;         //should always be 2 here but this is taken from the magma code
            tau[1] = l_test_value - 1;  //using the test value as this closer to the paper instead of magma version
            //not fully necessary but again follow the magma code
            for (int r = i +1; r < TEST_RANGE - 1; ++r) {
                oracle_results->b[r] = true;
            }
        }

        //check and set tau_1 from true(1) -> false(0)
        if(oracle_results->b[i-1] == true && oracle_results->b[i] == false){
            (*sign_changes)++;         //should be 1 here ...
            tau[0] = l_test_value;  //using the test value as this closer to the paper instead of magma version
        }

        //check if only have on time false(0) then this is the case at at i=6 under the assumtion that we stop after finding
        // tau_2 otherwise
        if(i == 6 && oracle_results->b[i] == false){
            (*sign_changes)++;
            tau[1] = l_test_value;    //original is i but we are using indices starting form 0 instead of 1
        }

        // after 2 sign changes we have all information and can stop
//        if((*sign_changes) > 1) {
//            for (int j = i+1; j < TEST_RANGE - 1; ++j) {
//                oracle_results->b[i] = true;
//                printf("+,");
//            }
//            break;
//        }
        //update test value for next run
        l_test_value++;
    }
    return queries;
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
//    ///DEBUG
//    q->l[0] = 2;
//    q->l[1] = 2;
//    q->l[2] = 1;
//    q->l[3] = -2;
}

void init(oracle_bitmap_t * b){
    for (int i = 0; i < TEST_RANGE; ++i) {
        b->b[i] = false;
    }
}

/**
 * Gernerates the fake public key from the attacker(Bob) with
 * U = s/2 x^(-k)
 * and converts to ntt domain
 * @param output U
 * @param input k
 */
void genfakeU(poly * U, int k){
    zero(U);
    if(k == 0){
        U->coeffs[0] = S/2;
    } else{
        U->coeffs[NEWHOPE_N - k] = NEWHOPE_Q - (S/2);
    }
    poly_ntt(U);
    poly_invntt(U);
    poly_ntt(U);

}

/**
 * Creates an ciphertext that can be used for the attack and stores it in the global attack_ct
 * @param Uhat in NTT domain
 * @param l
 */
void create_attack_ct(const poly * uhat, quadruplet_t *l, unsigned char * attack_ct) {
    poly c;
    zero(&c);
    for (int i = 0; i < QUADRUPLET_SIZE; ++i) {
        //the paper only says (l->l[i] + 4 % 8) but as this gets compressed, we need to "decompress first"
        c.coeffs[i*SS_BITS] = ((l->l[i] + 4 % 8) * NEWHOPE_Q) / 8;
//        c.coeffs[i*SS_BITS] = (l->l[i] + 4 % 8);
    }

//    printf("C[768]:%d\n", c.coeffs[768]);

    encode_c(attack_ct, uhat, &c);

}

/**
 * This takes a chiphertext and checks if this this ciphertext creates the same key than the given hypothesis
 * @param ciphertext
 * @param hypothesis
 * @return false(0) if the keys are the same otherwise true(1)
 */
bool mismatchOracle(const unsigned char * ciphertext, keyHypothesis_t * hypothesis, unsigned char * sk){
    unsigned char ss[CRYPTO_BYTES];
    //first get the shared key from Alice
    cpapke_dec(ss, ciphertext, sk);

//    printf("compare ss: ");
//    printPrams(ss, CRYPTO_BYTES);
//
//    printf("\ncompare hp: ");
//    printPrams(hypothesis->key, CRYPTO_BYTES);
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
        guess_for_s = (2*(tau>>1)) + 1;
    }
    return guess_for_s;
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

/**
 * prints all coefficients of the polynom p
 * @param p
 */
void printPoly(poly * p){
    printf("[");
    for (int i= 0; i < NEWHOPE_N; ++i) {
        printf("%d:%d ,", i,p->coeffs[i]);
    }
    printf("]\n");
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


