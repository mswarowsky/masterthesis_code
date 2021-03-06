#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <math.h>
#include <float.h>
#include "NewHope/api.h"
#include "NewHope/poly.h"
#include "NewHope/cpapke.h"
#include "printParamas.h"

#define AT_SUCCESS          0
#define AT_FILE_OPEN_ERROR -1
#define AT_DATA_ERROR      -3
#define AT_CRYPTO_FAILURE  -4

#define printf //
//#define DEV


static void encode_c(unsigned char *r, const poly *b, const poly *v);

// Multithreading stuff
pthread_mutex_t lock;

void *testRun(void *arg);


/***************************** Attack related *******************************/
#define SS_BITS (NEWHOPE_N/4)
#define MAX_TRIES 30
#define QUADRUPLET_SIZE 4
#define TEST_RANGE 8
#define S 1536  /** q = 8s + 1 **/
#define NOT_FOUND 2000
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN2(x, y) (((x) < (y)) ? (x) : (y))
#define MIN3(x, y, z) MIN2(x , MIN2(y, z))

typedef struct {
    int16_t l[QUADRUPLET_SIZE];
} quadruplet_t __attribute__ ((aligned (32)));

typedef struct {
    bool b[TEST_RANGE];
} oracle_bitmap_t;

typedef struct {
    unsigned char key[CRYPTO_BYTES];
} keyHypothesis_t;

void full_attack();

int key_recovery(poly *sk_guess, unsigned char * sk, uint16_t  * n_not_recovered);

void sampleRandom(quadruplet_t * q, int16_t lower_bound, int16_t upper_bound);

void init(oracle_bitmap_t * b);

void create_attack_ct(const poly *Uhat, quadruplet_t *l, unsigned char *attack_ct);

bool checkAtBorders(quadruplet_t *l, int quadruplet_index, int16_t target_index, const poly *Uhat,
                    keyHypothesis_t *k, unsigned char *sk);

uint8_t testAndFindTau(int8_t *tau, uint8_t *sign_changes, quadruplet_t *l, const int quadruplet_index,
                       const int16_t target_index, const poly *Uhat, keyHypothesis_t *k,
                       oracle_bitmap_t *oracle_results, unsigned char *sk);

bool mismatchOracle(const unsigned char *ciphertext, keyHypothesis_t *hypothesis, unsigned char *sk, int target_index);

int16_t find_s(const int8_t *tau);

void zero(poly *p);

void genfakeU(poly *U, int k, uint16_t value);

void printPoly(poly *p);

int find_m_sum(int *m, unsigned char *sk, int16_t target_index);

int qin_recover(poly *s_so_far, unsigned char *sk, uint16_t *n_not_recovered);

int sum_recover(poly *s_so_far, unsigned char *sk, uint16_t *not_recovered);

float_t creat_v_sum(quadruplet_t *l, poly *s, int16_t target_sum, int target_index);

uint16_t coefficientAbs(uint16_t coefficient);

int16_t get_secret_coeffs_value_around_zero(uint16_t value);

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
    int sum_queries = sum_recover(&sk_guess, sk, &n_not_recovered);



    poly s;
    poly_frombytes(&s, sk);
    poly_invntt(&s);

    // evaluation
    printf("guess :[");
    for (int i = 0; i < NEWHOPE_N; i++) {
        printf("%d, ", get_secret_coeffs_value_around_zero(sk_guess.coeffs[i]));
    }
    printf("]\nreal s:[");
    for (int j = 0; j < NEWHOPE_N; j++) {
        printf("%d, ", get_secret_coeffs_value_around_zero(s.coeffs[j]));
    }
    printf("]\n");

    int not_findable = 0;
    int correct = 0;
    int narrowedDown = 0;
    for (int j = 0; j < NEWHOPE_N; j++) {
        uint16_t real_coefficient = s.coeffs[j] % NEWHOPE_Q;
        if (real_coefficient > 4 && real_coefficient < 12283) {
            not_findable++;
//            printf("Not findable at %d with %d %d \n", j, real_coefficient, s.coeffs[j]);
        }

        if ((sk_guess.coeffs[j] % NEWHOPE_Q) != real_coefficient) {
            printf("wrong at %d real: %d(%d) vs. %d\n", j, real_coefficient, s.coeffs[j], sk_guess.coeffs[j]);
            //check if it was at least narrowed down
            if((sk_guess.coeffs[j] % NEWHOPE_Q) == 567 || (sk_guess.coeffs[j] % NEWHOPE_Q) == 588 || (sk_guess.coeffs[j] % NEWHOPE_Q) == 78 )
                narrowedDown++;
        } else {
            correct++;
        }

    }
//
//    printf("%d correct - %d wrong not possible: %d\n", correct, NEWHOPE_N - correct, not_findable);
    pthread_mutex_lock(&lock);
    fprintf(log, "%d; %d; %d; %d; %d; %d; %d; %d\n",
            correct, NEWHOPE_N - correct, not_findable, narrowedDown, not_findable - narrowedDown - (NEWHOPE_N - correct),  queries, sum_queries , queries+ sum_queries);
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
//    for(int k = 2; k < 3; k++){
        poly Uhat;
        zero(&Uhat);
        genfakeU(&Uhat, k, S / 2);
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

                    //If we already know three coefficients, then we can set l to fit on the first try
                    if(j == 3 && sk_guess->coeffs[k] != NOT_FOUND &&
                                 sk_guess->coeffs[k + 256] != NOT_FOUND &&
                                 sk_guess->coeffs[k + 512] != NOT_FOUND){
                        creat_v_sum(&l, sk_guess, -1 * ((tries+1)%3), k + j * SS_BITS);
                    }

                    //Border check ???
                    if(checkAtBorders(&l, j,k, &Uhat,&attacker_key_hypotesis, sk)){
                        printf("l:[%d, %d, %d, %d] ", l.l[0], l.l[1], l.l[2],l.l[3]);
                        printf("[+,");
                        //if the borders are ok then we have positive oracle result on the borders
                        oracleErrors.b[0] = oracleErrors.b[TEST_RANGE - 1] = true;
                        //this tries l_j \in [-3,2] and already fingers \tau_1 and \tau_2 out
                        queries += testAndFindTau(tau, &sign_change, &l, j, k, &Uhat, &attacker_key_hypotesis,
                                &oracleErrors, sk);
                        printf("+]   ");
                    }
                    tries++;
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



    printf("Finished hole attack took %d queries and could not find: %d coefficients\n", queries, *n_not_recovered);
    return queries;
}

int16_t get_secret_coeffs_value_around_zero(uint16_t value) {
    int32_t final_value = value % NEWHOPE_Q;
    if (final_value > NEWHOPE_Q / 2) {
        final_value = final_value - NEWHOPE_Q;
    }

    return (int16_t) final_value;
}

bool check_other_coefficients_where_also_not_found(poly * s, int k){
    for (int j = k % SS_BITS; j < NEWHOPE_N; j += 256) {
        if((j != k) && (s->coeffs[j] == NOT_FOUND)){
            printf("The to connected indices %d %d are not bauer recoverable:(\n", k , j);
            return true;
        }
    }
    return false;
}

int sum_recover(poly *s_so_far, unsigned char *sk, uint16_t *not_recovered) {
    int queries = 0;
    uint8_t errors = 0; //bitmap
    unsigned char attack_ct[CRYPTO_CIPHERTEXTBYTES];
    keyHypothesis_t attacker_key_hypotesis;


    //creating key guess
    for (int i = 1; i < CRYPTO_BYTES; i++) {
        attacker_key_hypotesis.key[i] = 0;
    }
    attacker_key_hypotesis.key[0] = 1;

    for (int i = 0; i < SS_BITS * 4; ++i) {
//    for (int i = 3; i < 4; ++i) {
        if (s_so_far->coeffs[i] != NOT_FOUND) {
            continue;
        }

        //reset bitmap
        errors = 0;

        //check if we have the other three coefficients
        if(check_other_coefficients_where_also_not_found(s_so_far, i)){
            continue;
        }



        poly Uhat;
        quadruplet_t l;
        genfakeU(&Uhat, i % SS_BITS, S /2 );

        printf("----------------- Try to get index %d -------------- \n", i);

        //First test for -7, 5 and 6 so set v-8 = 0
        float_t v = creat_v_sum(&l, s_so_far, -1, i);

        //first see if we are in the -0.5 or -1.0 case
        printf("v: %f\n", v);


        for (int16_t l_0 = -4; l_0 < 4; l_0++) {
            l.l[i / SS_BITS] = l_0;
            create_attack_ct(&Uhat, &l, attack_ct);
            errors |= mismatchOracle(attack_ct, &attacker_key_hypotesis, sk, -1) << (l_0 + 4);
            queries++;
        }

        //Plot info
        printf("[");
        for (int i = 0; i < 8; i++) {
            if (errors & (0x1 << i)) {
                printf("+,");
            } else {
                printf("-,");
            }
        }
        printf("]\n");


        //for evaluation see what v we had
        if(fabs(v+0.5) < FLT_EPSILON){
            // v = -0.5 case, we can check for -7,5 and guess -8/8; 6/7
            if (errors == 0b11111100) {
                s_so_far->coeffs[i] = 12282;
                printf("Yeah -7 !!! \n");
                (*not_recovered)--;
            } else if (errors == 0b00111111){
                s_so_far->coeffs[i] = 12294;
                printf("Yeah 5 !!! \n");
                (*not_recovered)--;
            } else if (errors == 0b01111111){
                s_so_far->coeffs[i] = 500 + 60 + 7;    //code for 0.5 6 or 7
                printf("Maybe 6 or 7 \n");
            } else if (errors == 0b11111110){
                s_so_far->coeffs[i] = 500 + 80 + 8;    //code for 0.5 8 or -8
                printf("Maybe -8 or 8 \n");
            }
        } else {
            // v = 0.0 case, we can check for -8,-7,5.6 and guess 7/8
            if (errors == 0b11111100) { // -8 or -7
                v = creat_v_sum(&l, s_so_far, 0, i);
                printf("reset vor -8 or -7 with v: %f\n", v);
                l.l[i / SS_BITS] = -4;      // only test edge case
                create_attack_ct(&Uhat, &l, attack_ct);
                bool is_7 = mismatchOracle(attack_ct, &attacker_key_hypotesis, sk, -1);
                queries++;
                if(is_7 == true) {
                    s_so_far->coeffs[i] = 12282;
                    printf("Yeah -7 !!! \n");
                } else {
                    s_so_far->coeffs[i] = 12281;
                    printf("Yeah -8 !!! \n");
                }
                (*not_recovered)--;
            } else if (errors == 0b00111111){
                v = creat_v_sum(&l, s_so_far, 0, i);
                printf("reset vor 5 or 6 with v-8: %f\n", v);
                l.l[i / SS_BITS] = 3;      // only test edge case
                create_attack_ct(&Uhat, &l, attack_ct);
                bool is_5 = mismatchOracle(attack_ct, &attacker_key_hypotesis, sk, -1);
                queries++;
                if(is_5 == true) {
                    s_so_far->coeffs[i] = 12294;
                    printf("Yeah 5 !!! \n");
                }else {
                    s_so_far->coeffs[i] = 12295;
                    printf("Yeah 6 !!! \n");
                }
                (*not_recovered)--;
            } else { //only 7 or 8 left
                s_so_far->coeffs[i] = 70 + 8;    //code for 0.0 7 or 8
                printf("Maybe 7 or 8 \n");
            }
        }
    }

    return queries;
}

/**
 * creates ab quadrubel based on s that creates a v-8 = target_sum
 * @param l
 * @param s
 * @param target_sum
 * @param target_index [0, 1023]
 * @return v-8.f
 */
float_t creat_v_sum(quadruplet_t *l, poly *s, int16_t target_sum, int target_index) {
    //start with 0
    l->l[0] = 0;
    l->l[1] = 0;
    l->l[2] = 0;
    l->l[3] = 0;
    float l_j[4] = {0,0,0,0};
    int16_t s_c[4] = {0,0,0,0};

    int main_index = target_index % SS_BITS;
    int sub_index = target_index / SS_BITS;
    float sub_sum = (float) target_sum + 8;


    for (int i = 0; i < 4; ++i) {
        s_c[i] = get_secret_coeffs_value_around_zero(s->coeffs[main_index + i * SS_BITS]);
        if (i == sub_index) continue;        //we only what to use the other 3 ones
        l_j[i] = fabs((float)l->l[i] - ((float) get_secret_coeffs_value_around_zero(s->coeffs[main_index + i * SS_BITS]) / 2.0f));
    }

    float v = (l_j[0] + l_j[1] + l_j[2] +l_j[3]);
    sub_sum -= v;

    for (int i = 0; i < 4; ++i) {
        if (i == sub_index) continue;        //we only what to use the other 3 ones
        //        getting sign from s_j  invert sign   select the most feasible value within all constrains (l_j[i] <= 4 ; -4 <= l[i] <=3; and sum <- 0
        l->l[i] = ((s_c[i] >> 15) | 1)   *  -1      *  (int16_t) MIN3(4.f - l_j[i], sub_sum + 0.5, 3.f);
        //update sums
        sub_sum -= (float) abs(l->l[i]);
        l_j[i] = fabs((float) l->l[i] - ((float)get_secret_coeffs_value_around_zero(s->coeffs[main_index + i * SS_BITS]) / 2.0f));
    }
    printf("l: [ %d, %d , %d, %d ]\n", l->l[0], l->l[1], l->l[2], l->l[3]);
    v = l_j[0] + l_j[1] + l_j[2] +l_j[3];

    ///DEBUG
    printf("s: (%d ,%d,%d, %d)\n", s_c[0], s_c[1], s_c[2], s_c[3]);
    printf("|l_j - s_j/2|: %f , %f, %f, %f\n", l_j[0] , l_j[1] , l_j[2] ,l_j[3]);
    printf("v-8.f: %f v-8:%d\n", (v - 8.f), (int)v - 8);

    return v-8.f;
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
//    for (int i = 0; i < SS_BITS * 4; ++i) {
    for (int i = 169; i < 170; ++i) {
        // TEST if already recovered
        if (s_so_far->coeffs[i] != NOT_FOUND) {
            continue;
        }
        int m;
        queries += find_m_sum(&m, sk, (i % SS_BITS));

        printf("The index %d sum m is:%d ", (i), m);

        // Subtract the other three coefficients from the sum
        for (int k = 1; k < 4; ++k) {
            m -= coefficientAbs(s_so_far->coeffs[(i + 256 * k) % NEWHOPE_N]);
        }

        printf(" s[%d]: %d\n", (i), m);

        ///assign the sign
        //TODO no sign form the previous run
        s_so_far->coeffs[i] = m;
        (*n_not_recovered)--;
    }

    return queries;
}

int find_m_sum(int *m, unsigned char *sk, int16_t target_index) {
    unsigned char attack_ct[CRYPTO_CIPHERTEXTBYTES];
    int queries = 0;

    //creating c with v[target_i] = 1 rest 0
    keyHypothesis_t k;
    memset(k.key, 0, 32);
    k.key[target_index / 8] = (1 << (target_index % 8));
    poly k_poly;
    poly_frommsg(&k_poly, k.key);


    for (int h = 1117; h < NEWHOPE_Q - 1; ++h) {
        //setting U with U[512] = h rest 0
        poly Uhat;
        zero(&Uhat);
        Uhat.coeffs[512] = h;
        poly_ntt(&Uhat);
        poly_invntt(&Uhat);
        poly_ntt(&Uhat);

        //assemble the full ciphertext
        encode_c(attack_ct, &Uhat, &k_poly);

        // if the target index key first time changes from 1 to 0 then we have m
        queries++;
        if (mismatchOracle(attack_ct, &k, sk, (target_index / 8))) {
            *m = (int) (((NEWHOPE_Q + 2.0) / h) + 0.5);
            break;
        }
    }

    return queries;
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
    errorLowerBound = mismatchOracle(attack_ct, k, sk, -1);
    l->l[quadruplet_index] = 3;
    create_attack_ct(Uhat, l, attack_ct);
    errorUpperBound = mismatchOracle(attack_ct, k, sk, -1);

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
        oracle_results->b[i] = mismatchOracle(attack_ct, k, sk, -1);
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
 * @param input value should be S/2 for Bauer method, but can be different
 */
void genfakeU(poly *U, int k, uint16_t value) {
    zero(U);
    if (k == 0) {
        U->coeffs[0] = value;
    } else {
        U->coeffs[NEWHOPE_N - k] = NEWHOPE_Q - (value);
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
        c.coeffs[i * SS_BITS] =
                (uint16_t) (((l->l[i] + 4 % 8) * NEWHOPE_Q) / 8.0) + 0.5; // NOLINT(bugprone-incorrect-roundings)
    }
    encode_c(attack_ct, uhat, &c);
}

/**
 * This takes a chiphertext and checks if this this ciphertext creates the same key than the given hypothesis
 * @param ciphertext
 * @param hypothesis
 * @param target_index the index in the secret key to check, if < 0 check all
 * @return false(0) if the keys are the same otherwise true(1)
 */
bool mismatchOracle(const unsigned char *ciphertext, keyHypothesis_t *hypothesis, unsigned char *sk, int target_index) {
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
    if (target_index < 0) {
        for (int i = 0; i < CRYPTO_BYTES; ++i) {
            if (hypothesis->key[i] != ss[i]) {
//            if(i != 0) printf("Something strange, error outside of index 0 - %d\n", i); // only relevant for the Bauer method
                errors++;
            }
        }
    } else if (target_index < 32) {
        if (hypothesis->key[target_index] != ss[target_index]) {
            errors++;
        }
    } else {
        printf("Wrong target index %d", target_index);
        exit(0);
    }
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
static void encode_c(unsigned char *r, const poly *b, const poly *v) {
    poly_tobytes(r, b);
    poly_compress(r + NEWHOPE_POLYBYTES, v);
}

/***
 * Extracts the secrete coefficents from the secrete key and returns their abs value
 * @param coefficient
 * @return
 */
uint16_t coefficientAbs(uint16_t coefficient) {
    uint16_t v = coefficient % NEWHOPE_Q;
    if (v > (NEWHOPE_Q / 2)) {
        v = (v - NEWHOPE_Q) * -1;
    }
    return v;
}


