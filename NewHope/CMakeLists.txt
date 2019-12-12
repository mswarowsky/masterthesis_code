set(COMMON_SOUCES poly.c reduce.c fips202.c verify.c cpapke.c ntt.c precomp.c)
set(HEADERS ${HEADERS} params.h poly.h randombytes.h ntt.h reduce.h verify.h cpapke.h)

# creating a libary to use the cpa scheme
add_library(cpakem512 STATIC ${COMMON_SOUCES} ${HEADERS} cpakem.c randombytes.c)
set_target_properties(cpakem512 PROPERTIES COMPILE_DEFINITIONS "NEWHOPE_N=512 ")
target_link_libraries(cpakem512 crypto)

add_library(cpakem1024 STATIC ${COMMON_SOUCES} ${HEADERS} cpakem.c randombytes.c)
set_target_properties(cpakem1024 PROPERTIES COMPILE_DEFINITIONS "NEWHOPE_N=1024 ")
target_link_libraries(cpakem1024 crypto)


# Set up for the different execuables
add_executable(PQCgenKAT_cpakem512 ${COMMON_SOUCES} ${HEADERS} PQCgenKAT_kem.c rng.c rng.h cpakem.c)
set_target_properties(PQCgenKAT_cpakem512 PROPERTIES COMPILE_DEFINITIONS "NEWHOPE_N=512 ")
target_link_libraries(PQCgenKAT_cpakem512 crypto)

add_executable(PQCgenKAT_cpakem1024 ${COMMON_SOUCES} ${HEADERS} PQCgenKAT_kem.c rng.c rng.h cpakem.c)
set_target_properties(PQCgenKAT_cpakem1024 PROPERTIES COMPILE_DEFINITIONS "NEWHOPE_N=1024 ")
target_link_libraries(PQCgenKAT_cpakem1024 crypto)


# Tests
add_executable(test_cpakem512 ${COMMON_SOUCES} ${HEADERS} test_newhope.c randombytes.c cpakem.c)
set_target_properties(test_cpakem512 PROPERTIES COMPILE_DEFINITIONS "NEWHOPE_N=512 ")
target_link_libraries(test_cpakem512 crypto)

add_executable(test_cpakem1024 ${COMMON_SOUCES} ${HEADERS} test_newhope.c randombytes.c cpakem.c)
set_target_properties(test_cpakem1024 PROPERTIES COMPILE_DEFINITIONS "NEWHOPE_N=1024 ")
target_link_libraries(test_cpakem1024 crypto)


# Speed mesuarments
add_executable(speed_cpakem512 ${COMMON_SOUCES} ${HEADERS} speed.c randombytes.c cpucycles.h cpucycles.c cpakem.c)
set_target_properties(speed_cpakem512 PROPERTIES COMPILE_DEFINITIONS "NEWHOPE_N=512 ")
target_link_libraries(speed_cpakem512 crypto)

add_executable(speed_cpakem1024 ${COMMON_SOUCES} ${HEADERS} speed.c randombytes.c cpucycles.h cpucycles.c cpakem.c)
set_target_properties(speed_cpakem1024 PROPERTIES COMPILE_DEFINITIONS "NEWHOPE_N=1024 ")
target_link_libraries(speed_cpakem1024 crypto)