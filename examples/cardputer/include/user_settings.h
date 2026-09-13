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

/* ML-DSA-44 (Dilithium) and ML-KEM-512 are experimental in wolfSSL and
 * require this opt-in. */
#define WOLFSSL_EXPERIMENTAL_SETTINGS

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
#define WOLFSSL_SHAKE256
#define WOLFSSL_SHAKE128
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
#define NO_PWDBASED
#define WOLFSSL_NO_SOCK
#define NO_WRITEV
#define WOLFSSL_SMALL_STACK

/* Single-threaded: we guard SPI externally */
#define SINGLE_THREADED

#endif
