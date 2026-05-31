cmake_minimum_required(VERSION 3.20)
project(cosechat VERSION 0.2.0 LANGUAGES C)

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
add_library(cosechat STATIC src/cosechat.c)
target_include_directories(cosechat PUBLIC include)
target_link_libraries(cosechat PUBLIC wolfcose wolfssl)

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
add_executable(test_cosechat test/test_cosechat.c)
target_compile_definitions(test_cosechat PRIVATE CC_POW_DIFFICULTY=1)
target_link_libraries(test_cosechat PRIVATE cosechat)
add_test(NAME cosechat COMMAND test_cosechat)
