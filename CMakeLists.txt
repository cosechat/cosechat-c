cmake_minimum_required(VERSION 3.20)
project(cosechat VERSION 0.10.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(FetchContent)

# ---------------------------------------------------------------------------
# wolfCOSE — fetched from source (no upstream CMake, compile directly)
# ---------------------------------------------------------------------------
FetchContent_Declare(
    wolfcose_src
    GIT_REPOSITORY https://github.com/konsumer/wolfCOSE.git
    GIT_TAG        124ee3c
)
FetchContent_MakeAvailable(wolfcose_src)

# ---------------------------------------------------------------------------
# wolfssl — post-quantum build (ML-DSA-44 + ML-KEM-512)
# ---------------------------------------------------------------------------
set(WOLFSSL_MLKEM       ON  CACHE BOOL "" FORCE)
set(WOLFSSL_DILITHIUM   ON  CACHE BOOL "" FORCE)
set(WOLFSSL_AESGCM      ON  CACHE BOOL "" FORCE)
set(WOLFSSL_HKDF        ON  CACHE BOOL "" FORCE)
set(WOLFSSL_SHA256      ON  CACHE BOOL "" FORCE)
set(WOLFSSL_KEYGEN      ON  CACHE BOOL "" FORCE)
set(WOLFSSL_EXAMPLES    OFF CACHE BOOL "" FORCE)
set(WOLFSSL_TESTS       OFF CACHE BOOL "" FORCE)
set(WOLFSSL_BENCHMARKS  OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS   OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    wolfssl
    URL https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.9.0-stable.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    OVERRIDE_FIND_PACKAGE
)
FetchContent_MakeAvailable(wolfssl)

add_library(wolfcose STATIC
    ${wolfcose_src_SOURCE_DIR}/src/wolfcose_cbor.c
    ${wolfcose_src_SOURCE_DIR}/src/wolfcose.c
)
target_include_directories(wolfcose PUBLIC ${wolfcose_src_SOURCE_DIR}/include)
target_link_libraries(wolfcose PUBLIC wolfssl)

# ---------------------------------------------------------------------------
# cosechat library
# ---------------------------------------------------------------------------
add_library(cosechat STATIC src/cosechat.c src/cosechat_road.c)
target_include_directories(cosechat PUBLIC include)
target_link_libraries(cosechat PUBLIC wolfcose wolfssl)

# ---------------------------------------------------------------------------
# cosechat relay — multi-hop forwarding and path discovery
# ---------------------------------------------------------------------------
add_library(cosechat_relay STATIC src/cosechat_relay.c)
target_include_directories(cosechat_relay PUBLIC include)
target_link_libraries(cosechat_relay PUBLIC cosechat)

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------
foreach(ex keygen announce chat)
    add_executable(${ex} examples/${ex}.c)
    target_link_libraries(${ex} PRIVATE cosechat)
endforeach()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
enable_testing()

# The PoW difficulty is a compile-time knob of the library. Exercise both the
# default (2, from include/cosechat.h) and the firmware's (1, the monolithic
# build sets -DCC_POW_DIFFICULTY=1) so a build-configuration-dependent
# regression in the PoW path cannot ship unnoticed.
add_library(cosechat_pow1 STATIC src/cosechat.c src/cosechat_road.c)
target_include_directories(cosechat_pow1 PUBLIC include)
target_link_libraries(cosechat_pow1 PUBLIC wolfcose wolfssl)
target_compile_definitions(cosechat_pow1 PUBLIC CC_POW_DIFFICULTY=1)

# The suite's reentrancy test uses pthreads (one context per thread).
find_package(Threads REQUIRED)

add_executable(test_cosechat test/test_cosechat.c)
target_link_libraries(test_cosechat PRIVATE cosechat Threads::Threads)
add_test(NAME cosechat COMMAND test_cosechat) # default difficulty (2)

add_executable(test_cosechat_pow1 test/test_cosechat.c)
target_link_libraries(test_cosechat_pow1 PRIVATE cosechat_pow1 Threads::Threads)
add_test(NAME cosechat_pow1 COMMAND test_cosechat_pow1) # difficulty 1

# The road framing is part of the library (include/cosechat_road.h), so it is
# tested on the host rather than on hardware.
add_executable(test_road test/test_road.c src/cosechat_road.c)
target_include_directories(test_road PRIVATE include)
add_test(NAME cosechat_road COMMAND test_road)

# The relay (include/cosechat_relay.h) is host-testable for the same reason.
# Its tables are shrunk on this target so table pressure is cheap to reach, and
# its limits are retuned relative to the shipped defaults (three data packets,
# two posts per group, and pools of 40960/32768/2048 bytes per window) so that
# each limit can be reached and told apart with the packet sizes that class
# really has: an announce ~6.5 KB, a chat ~4.5 KB, a group post 588 B at the
# maximum (a 512-byte message, under 100 B for a short one), so the group pool
# is small on purpose: a synthetic ~70 B post can exhaust it. The capacities
# are compile-time by contract, and the shipped cosechat_relay library above
# uses the defaults. The library is the pow1 one on purpose: the relay prices
# forwarded data against that same build, so the difficulty cannot change a
# single expectation below, while mining the fixture's announcements at the
# default difficulty 2 would cost seconds of the suite for no added coverage
# (the one test that needs a higher price mines it with the library itself,
# which also pins the relay's own PoW digest).
add_executable(test_relay test/test_relay.c src/cosechat_relay.c)
target_include_directories(test_relay PRIVATE include)
target_link_libraries(test_relay PRIVATE cosechat_pow1)
target_compile_definitions(test_relay PRIVATE CC_RELAY_PATHS=4
                                             CC_RELAY_FWD_BUDGET=3
                                             CC_RELAY_GROUP_BUDGET=2
                                             CC_RELAY_GIDS=4
                                             CC_RELAY_AIRTIME_ANNOUNCE=40960
                                             CC_RELAY_AIRTIME_DATA=32768
                                             CC_RELAY_AIRTIME_GROUP=2048)
add_test(NAME cosechat_relay COMMAND test_relay)
