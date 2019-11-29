

#ifndef NH_FORK_PRINTPARAMAS_H
#define NH_FORK_PRINTPARAMAS_H

#include <stdio.h>

void printfPrams(unsigned char *A, unsigned long long L)
{
    unsigned long long  i;
    for ( i=0; i<L; i++ )
        printf("%02X", A[i]);

    if ( L == 0 )
        printf("00");
}



#endif //NH_FORK_PRINTPARAMAS_H
