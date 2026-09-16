#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* Arduino ESP32: wolfSSL detects the platform itself. Do NOT define
 * WOLFSSL_ESPIDF here — wolfSSL rejects a build that is both ESP-IDF and
 * Arduino ("Found both ESPIDF and ARDUINO. Pick one.").
 *
 * PlatformIO always defines PLATFORMIO, and Arduino-ESP32 defines
 * ESP_PLATFORM, so wolfSSL's settings.h sets WOLFSSL_ESPIDF on its own
 * (settings.h:283) regardless. Drop it: this is an Arduino build. */
#undef WOLFSSL_ESPIDF

/* The post-quantum families the build needs are experimental in wolfSSL and
 * require this opt-in. These macros enable a whole family, not one parameter
 * set: the actual levels (currently ML-DSA-65 + ML-KEM-768) are chosen by
 * CC_SIGN_LEVEL / CC_KEM_LEVEL in include/cosechat.h, not here.
 *
 * UNDEF FIRST. Every macro below is also passed on the command line by this
 * repo's own library.json ("build.flags"), because the cosechat library must
 * configure wolfSSL for itself when PlatformIO builds it standalone -- and
 * that is what made that library's own TUs print "... redefined" nine times
 * over: `-DHAVE_DILITHIUM=` defines it as an empty value, `#define
 * HAVE_DILITHIUM` defines it as nothing at all, and gcc warns when the tokens
 * differ even though the meaning does not. Undef first is the same pattern
 * wolfSSL's own settings.h uses (settings.h:1874 and throughout), it keeps this
 * file's explicit opt-in, and it stops the collision at the definition instead
 * of leaving nine warnings in every build that recompiles the library. */
#define WOLFSSL_EXPERIMENTAL_SETTINGS

/* ML-DSA (Dilithium) — level set by CC_SIGN_LEVEL */
#undef HAVE_DILITHIUM
#define HAVE_DILITHIUM
#undef WOLFSSL_WC_DILITHIUM
#define WOLFSSL_WC_DILITHIUM

/* ML-KEM — level set by CC_KEM_LEVEL */
#undef WOLFSSL_HAVE_MLKEM
#define WOLFSSL_HAVE_MLKEM
#undef WOLFSSL_WC_MLKEM
#define WOLFSSL_WC_MLKEM

/* Primitives cosechat needs */
#undef HAVE_AESGCM
#define HAVE_AESGCM
#undef HAVE_HKDF
#define HAVE_HKDF
#undef WOLFSSL_SHA256
#define WOLFSSL_SHA256
#undef WOLFSSL_SHA3
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE256
#define WOLFSSL_SHAKE128
#undef WOLFSSL_KEY_GEN
#define WOLFSSL_KEY_GEN

/* Disable unused features to save flash */
#define NO_RSA
#define NO_DSA
#define NO_DH
#define NO_DES3
#define NO_RC4
#define NO_RABBIT
#define NO_HC128
#define NO_MD4
#define NO_MD5
/* NO_MD5 without this trips "old TLS requires MD5 and SHA" */
#define NO_OLD_TLS
/* NO_PWDBASED is deliberately NOT set here any more. The passphrase-encrypted
 * store (src/cc_store.c) derives its key with wc_PBKDF2, and NO_PWDBASED
 * compiles that function to nothing -- the whole of wolfcrypt/src/pwdbased.c
 * sits inside #ifndef NO_PWDBASED -- so removing the define is what turns on
 * HAVE_PBKDF2 through settings.h.
 *
 * What it costs, measured on this tree with `pio run -e lora` (S3, this env):
 *
 *   flash  662501 B before the store (tree as it was, NO_PWDBASED set)
 *          669649 B now ................................................ +7148
 *          and that delta is the whole feature: the KDF, the store module
 *          itself, and this sketch's wiring. The KDF's own share is NOT quoted
 *          as a byte count, because a map's per-object attribution is not
 *          stable: the helpers that object shares with others (min(),
 *          ForceZero(), its literal pools) get their own copy in each object
 *          that emits one, and which copy the map credits moves by tens of
 *          bytes between links. What is stable and worth knowing: the whole of
 *          wolfcrypt/src/pwdbased.c compiles to 2673 B of code, and the linker
 *          keeps only the PBKDF2 entry points out of it -- PBKDF1 and the
 *          PKCS#12 helpers come out again.
 *   RAM    219096 B before, 217800 B now .................... 1296 B LESS, not
 *          more: the store's two buffers are smaller than the scratch the old
 *          keyLoad/keySave kept (see src/main.cpp)
 *
 * Nothing else in the firmware calls into wolfCrypt's password-based KDFs:
 * scrypt stays off (HAVE_SCRYPT is never defined), and the PKCS#8/#12 code in
 * the same source file was already compiled in before this change. */
#define WOLFSSL_NO_SOCK
#define NO_WRITEV
#define WOLFSSL_SMALL_STACK

/* Single-threaded: we guard SPI externally */
#define SINGLE_THREADED

#endif
