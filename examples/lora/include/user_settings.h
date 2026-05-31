#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* ESP32 platform */
#define WOLFSSL_ESPIDF
#define WOLFSSL_ESP32

/* ML-DSA-44 (Dilithium) */
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM

/* ML-KEM-512 */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM

/* Primitives cosechat needs */
#define HAVE_AESGCM
#define HAVE_HKDF
#define WOLFSSL_SHA256
#define WOLFSSL_SHA3
#define HAVE_SHAKE256
#define HAVE_SHAKE128
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
#define NO_PWDBASED
#define WOLFSSL_NO_SOCK
#define NO_WRITEV
#define WOLFSSL_SMALL_STACK

/* Single-threaded: we guard SPI externally */
#define SINGLE_THREADED

#endif
