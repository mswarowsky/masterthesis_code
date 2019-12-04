cmake_minimum_required (VERSION 2.8.11)
project(nh_fork)

enable_language(C)
enable_language(CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")

set(CMAKE_CXX_STANDARD 11)


# Use the nist flags
set(NIST_FLAGS "-O3 -fomit-frame-pointer -march=native -fPIC -no-pie")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NIST_FLAGS}")

add_subdirectory(NewHope)


# Test programms
add_executable(cpaTest1024 cpaTest.c printParamas.h)
target_link_libraries(cpaTest1024 cpakem1024)

# Attack prgoramms
add_executable(cpaAttack cpaAttack.c)
target_link_libraries(cpaAttack cpakem1024)