#ifndef COSECHAT_H
#define COSECHAT_H

#include <stddef.h>
#include <stdint.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CC_VERSION "0.2.0"

/* Algorithm selection (change here to upgrade security level) */
#define CC_SIGN_LEVEL 2 /* ML-DSA-44 (Dilithium level 2) */
#define CC_KEM_TYPE WC_ML_KEM_512

/* ML-DSA-44 sizes */
#define CC_SIGN_PUBKEY_SZ 1312
#define CC_SIGN_PRIVKEY_SZ 2560
#define CC_SIGN_SIG_SZ 2420

/* ML-KEM-512 sizes */
#define CC_KEM_PUBKEY_SZ 800
#define CC_KEM_PRIVKEY_SZ 1632
#define CC_KEM_CT_SZ 768
#define CC_KEM_SS_SZ 32

/* Derived sizes */
#define CC_ADDR_SZ 16
#define CC_MAX_NAME_LEN 63
#define CC_MAX_META_SZ 256
#define CC_MAX_MSG_SZ 512
#define CC_PRES_BUF_SZ     128   /* max presence wire packet */
#define CC_KEY_REQ_BUF_SZ  32    /* max key-request wire packet */

#ifndef CC_POW_DIFFICULTY
#define CC_POW_DIFFICULTY 2
#endif

#define CC_MSG_ANNOUNCE 0
#define CC_MSG_CHAT 1
#define CC_MSG_PRESENCE 2
#define CC_MSG_KEY_REQ  3

#define CC_OK 0
#define CC_E_ARG (-1)
#define CC_E_BUF (-2)
#define CC_E_CRYPTO (-3)
#define CC_E_FORMAT (-4)
#define CC_E_SIG (-5)
#define CC_E_POW (-6)
#define CC_E_DECRYPT (-7)

/*
 * cc_key_t embeds wolfSSL key structs directly (~13KB total).
 * On ESP32/embedded: DECLARE AS STATIC OR GLOBAL, never as a stack local.
 *
 * Identity = ML-DSA-44 signing key (address derived from sign pubkey).
 * Encryption = ML-KEM-512 key (used for key encapsulation in chat).
 */
typedef struct {
  dilithium_key sign;
  KyberKey kem;
} cc_key_t;

/*
 * cc_announce_t is ~2.5KB. Same rule: static/global on embedded.
 */
typedef struct {
  uint8_t addr[CC_ADDR_SZ];
  uint8_t sign_pubkey[CC_SIGN_PUBKEY_SZ];
  uint8_t kem_pubkey[CC_KEM_PUBKEY_SZ];
  char name[CC_MAX_NAME_LEN + 1];
  size_t name_len;
  uint8_t meta[CC_MAX_META_SZ];
  size_t meta_len;
  uint8_t hops;
} cc_announce_t;

/*
 * cc_presence_t is ~80 bytes — safe on stack.
 * Sent periodically instead of full announce; ~1 LoRa fragment.
 * No signature: addr authenticity is proven by cc_announce.
 * Receivers who lack the key for this addr send CC_MSG_KEY_REQ.
 */
typedef struct {
  uint8_t addr[CC_ADDR_SZ];
  char    name[CC_MAX_NAME_LEN + 1];
  size_t  name_len;
  uint8_t hops;
} cc_presence_t;

typedef struct {
  uint8_t sender_addr[CC_ADDR_SZ];
  uint8_t msg[CC_MAX_MSG_SZ];
  size_t msg_len;
  uint8_t hops;
} cc_chat_t;

/* Key management */
int cc_key_generate(cc_key_t* key, WC_RNG* rng);
int cc_key_import(cc_key_t* key, const uint8_t sign_priv[CC_SIGN_PRIVKEY_SZ],
                  const uint8_t sign_pub[CC_SIGN_PUBKEY_SZ],
                  const uint8_t kem_priv[CC_KEM_PRIVKEY_SZ]);
int cc_key_export_private(const cc_key_t* key,
                          uint8_t sign_priv[CC_SIGN_PRIVKEY_SZ],
                          uint8_t kem_priv[CC_KEM_PRIVKEY_SZ]);
int cc_key_export_public(const cc_key_t* key,
                         uint8_t sign_pub[CC_SIGN_PUBKEY_SZ],
                         uint8_t kem_pub[CC_KEM_PUBKEY_SZ]);
void cc_key_free(cc_key_t* key);

/* Address = SHA-256(sign_pubkey)[0:16] */
int cc_addr_from_sign_pubkey(const uint8_t pub[CC_SIGN_PUBKEY_SZ],
                             uint8_t addr[CC_ADDR_SZ]);
int cc_addr_from_key(const cc_key_t* key, uint8_t addr[CC_ADDR_SZ]);

/*
 * Wire format (CBOR arrays, hops excluded from PoW):
 *
 * Announce: [type=0, hops, pow_nonce, cose_sign1_bstr]
 *   COSE_Sign1 payload: [sign_pub_bstr(1312), kem_pub_bstr(800),
 *                         name_tstr, meta_bstr]
 *
 * Chat: [type=1, hops, recipient_addr_bstr(16), kem_ct_bstr(768),
 *         pow_nonce, cose_encrypt0_bstr]
 *   COSE_Encrypt0 plaintext: [sender_addr_bstr(16), message_bstr]
 *   Key = HKDF-SHA256(ML-KEM-512 shared secret, info="cosechat")
 *
 * Presence: [type=2, hops, pow_nonce, addr_bstr(16), name_tstr]
 *   PoW: SHA-256(type_byte || addr || name || nonce_le32)[0:CC_POW_DIFFICULTY]==0
 *   No signature — addr authenticity established by CC_MSG_ANNOUNCE.
 *
 * KeyReq: [type=3, hops, addr_bstr(16)]
 *   No PoW. Target responds with its CC_MSG_ANNOUNCE.
 *
 * PoW: SHA-256(type_byte || core_payload || nonce_le32)[0:CC_POW_DIFFICULTY]==0
 *   Announce core = sign1_bytes
 *   Chat core     = recipient_addr || kem_ct || encrypt0_bytes
 */

int cc_announce_build(const cc_key_t* key, const char* name, size_t name_len,
                      const uint8_t* meta, size_t meta_len, uint8_t* out,
                      size_t out_sz, size_t* out_len, WC_RNG* rng);
int cc_announce_parse(const uint8_t* in, size_t in_sz, cc_announce_t* ann);

int cc_chat_build(const cc_key_t* sender_key,
                  const uint8_t recipient_addr[CC_ADDR_SZ],
                  const uint8_t recipient_kem_pub[CC_KEM_PUBKEY_SZ],
                  const uint8_t* msg, size_t msg_len, uint8_t* out,
                  size_t out_sz, size_t* out_len, WC_RNG* rng);
int cc_chat_parse(const cc_key_t* my_key, const uint8_t* in, size_t in_sz,
                  cc_chat_t* chat);

/* Presence — lightweight periodic heartbeat (~1 LoRa fragment, no signature) */
int cc_presence_build(const cc_key_t* key, const char* name, size_t name_len,
                      uint8_t* out, size_t out_sz, size_t* out_len, WC_RNG* rng);
int cc_presence_parse(const uint8_t* in, size_t in_sz, cc_presence_t* p);

/* Key request — ask a node to re-send its full announce */
int cc_key_req_build(const uint8_t addr[CC_ADDR_SZ],
                     uint8_t* out, size_t out_sz, size_t* out_len);
int cc_key_req_parse(const uint8_t* in, size_t in_sz, uint8_t addr[CC_ADDR_SZ]);

/* Routing helpers */
int cc_msg_type(const uint8_t* pkt, size_t pkt_sz, uint8_t* type_out);
int cc_msg_hops(const uint8_t* pkt, size_t pkt_sz, uint8_t* hops_out);
int cc_msg_recipient(const uint8_t* pkt, size_t pkt_sz,
                     uint8_t addr[CC_ADDR_SZ]);
int cc_hops_increment(const uint8_t* in, size_t in_sz, uint8_t* out,
                      size_t out_sz, size_t* out_len);
int cc_pow_verify(const uint8_t* pkt, size_t pkt_sz);

#ifdef __cplusplus
}
#endif

#endif /* COSECHAT_H */
