#include "cosechat.h"

#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/misc.h>
#include <wolfssl/wolfcrypt/sha256.h>

/* Intermediate buffer sizes (used as statics to stay off the stack) */
#define CC_ANN_PAYLOAD_SZ \
  (CC_SIGN_PUBKEY_SZ + CC_KEM_PUBKEY_SZ + CC_MAX_NAME_LEN + CC_MAX_META_SZ + 32)
#define CC_SIGN1_SZ (CC_ANN_PAYLOAD_SZ + CC_SIGN_SIG_SZ + 128)

/* Scratch: wolfCOSE puts Sig_structure then signature back-to-back in scratch */
#define CC_SIGN_SCRATCH_SZ (CC_ANN_PAYLOAD_SZ + CC_SIGN_SIG_SZ + 256)
#define CC_ENC_SCRATCH_SZ 512
#define CC_CHAT_PT_SZ (CC_ADDR_SZ + CC_MAX_MSG_SZ + 8)
#define CC_ENC0_SZ (CC_CHAT_PT_SZ + 80)

/* ---- CBOR helpers ---- */

static void cbor_enc_init(WOLFCOSE_CBOR_CTX* ctx, uint8_t* buf, size_t sz) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->buf = buf;
  ctx->bufSz = sz;
}

static void cbor_dec_init(WOLFCOSE_CBOR_CTX* ctx, const uint8_t* buf,
                          size_t sz) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->cbuf = buf;
  ctx->bufSz = sz;
}

/* ---- PoW ---- */

static int pow_hash(uint8_t type_byte, const uint8_t* d1, size_t d1sz,
                    const uint8_t* d2, size_t d2sz, const uint8_t* d3,
                    size_t d3sz, uint32_t nonce, uint8_t hash[32]) {
  wc_Sha256 sha;
  uint8_t nle[4] = {(uint8_t)(nonce), (uint8_t)(nonce >> 8),
                    (uint8_t)(nonce >> 16), (uint8_t)(nonce >> 24)};
  int ret = wc_InitSha256(&sha);
  if (ret != 0)
    return CC_E_CRYPTO;
  wc_Sha256Update(&sha, &type_byte, 1);
  if (d1 && d1sz)
    wc_Sha256Update(&sha, d1, (word32)d1sz);
  if (d2 && d2sz)
    wc_Sha256Update(&sha, d2, (word32)d2sz);
  if (d3 && d3sz)
    wc_Sha256Update(&sha, d3, (word32)d3sz);
  wc_Sha256Update(&sha, nle, 4);
  ret = wc_Sha256Final(&sha, hash);
  wc_Sha256Free(&sha);
  return (ret == 0) ? CC_OK : CC_E_CRYPTO;
}

static int pow_check(const uint8_t hash[32]) {
  int i;
  for (i = 0; i < CC_POW_DIFFICULTY; i++) {
    if (hash[i] != 0)
      return CC_E_POW;
  }
  return CC_OK;
}

static int pow_find(uint8_t type_byte, const uint8_t* d1, size_t d1sz,
                    const uint8_t* d2, size_t d2sz, const uint8_t* d3,
                    size_t d3sz, uint32_t* nonce_out) {
  uint8_t hash[32];
  uint32_t n;
  for (n = 0; n < 0xFFFFFF00U; n++) {
    if (pow_hash(type_byte, d1, d1sz, d2, d2sz, d3, d3sz, n, hash) != CC_OK)
      return CC_E_CRYPTO;
    if (pow_check(hash) == CC_OK) {
      *nonce_out = n;
      return CC_OK;
    }
  }
  return CC_E_CRYPTO;
}

/* ---- CBOR outer packet encode/decode ---- */

static int enc_announce(uint8_t* buf, size_t sz, size_t* len, uint8_t hops,
                        uint32_t nonce, const uint8_t* sign1,
                        size_t sign1_len) {
  WOLFCOSE_CBOR_CTX c;
  cbor_enc_init(&c, buf, sz);
  if (wc_CBOR_EncodeArrayStart(&c, 4) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeUint(&c, CC_MSG_ANNOUNCE) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeUint(&c, hops) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeUint(&c, nonce) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeBstr(&c, sign1, sign1_len) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  *len = c.idx;
  return CC_OK;
}

static int dec_announce(const uint8_t* buf, size_t sz, uint8_t* hops,
                        uint32_t* nonce, const uint8_t** sign1,
                        size_t* sign1_len) {
  WOLFCOSE_CBOR_CTX c;
  size_t count;
  uint64_t val;
  cbor_dec_init(&c, buf, sz);
  if (wc_CBOR_DecodeArrayStart(&c, &count) != WOLFCOSE_SUCCESS || count != 4)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS ||
      val != CC_MSG_ANNOUNCE)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  *hops = (uint8_t)(val & 0xFF);
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  *nonce = (uint32_t)(val & 0xFFFFFFFF);
  if (wc_CBOR_DecodeBstr(&c, sign1, sign1_len) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  return CC_OK;
}

static int enc_chat(uint8_t* buf, size_t sz, size_t* len, uint8_t hops,
                    const uint8_t recip[CC_ADDR_SZ],
                    const uint8_t kem_ct[CC_KEM_CT_SZ], uint32_t nonce,
                    const uint8_t* enc0, size_t enc0_len) {
  WOLFCOSE_CBOR_CTX c;
  cbor_enc_init(&c, buf, sz);
  if (wc_CBOR_EncodeArrayStart(&c, 6) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeUint(&c, CC_MSG_CHAT) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeUint(&c, hops) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeBstr(&c, recip, CC_ADDR_SZ) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeBstr(&c, kem_ct, CC_KEM_CT_SZ) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeUint(&c, nonce) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeBstr(&c, enc0, enc0_len) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  *len = c.idx;
  return CC_OK;
}

static int dec_chat(const uint8_t* buf, size_t sz, uint8_t* hops,
                    uint8_t recip[CC_ADDR_SZ], const uint8_t** kem_ct,
                    size_t* kem_ct_len, uint32_t* nonce, const uint8_t** enc0,
                    size_t* enc0_len) {
  WOLFCOSE_CBOR_CTX c;
  size_t count;
  uint64_t val;
  const uint8_t* tmp;
  size_t tmp_len;
  cbor_dec_init(&c, buf, sz);
  if (wc_CBOR_DecodeArrayStart(&c, &count) != WOLFCOSE_SUCCESS || count != 6)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS || val != CC_MSG_CHAT)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  *hops = (uint8_t)(val & 0xFF);
  if (wc_CBOR_DecodeBstr(&c, &tmp, &tmp_len) != WOLFCOSE_SUCCESS ||
      tmp_len != CC_ADDR_SZ)
    return CC_E_FORMAT;
  memcpy(recip, tmp, CC_ADDR_SZ);
  if (wc_CBOR_DecodeBstr(&c, kem_ct, kem_ct_len) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  *nonce = (uint32_t)(val & 0xFFFFFFFF);
  if (wc_CBOR_DecodeBstr(&c, enc0, enc0_len) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  return CC_OK;
}

static int enc_presence(uint8_t* buf, size_t sz, size_t* len, uint8_t hops,
                        uint32_t nonce, const uint8_t* addr,
                        const char* name, size_t name_len) {
  WOLFCOSE_CBOR_CTX c;
  cbor_enc_init(&c, buf, sz);
  if (wc_CBOR_EncodeArrayStart(&c, 5) != WOLFCOSE_SUCCESS) return CC_E_BUF;
  if (wc_CBOR_EncodeUint(&c, CC_MSG_PRESENCE)  != WOLFCOSE_SUCCESS) return CC_E_BUF;
  if (wc_CBOR_EncodeUint(&c, hops)             != WOLFCOSE_SUCCESS) return CC_E_BUF;
  if (wc_CBOR_EncodeUint(&c, nonce)            != WOLFCOSE_SUCCESS) return CC_E_BUF;
  if (wc_CBOR_EncodeBstr(&c, addr, CC_ADDR_SZ) != WOLFCOSE_SUCCESS) return CC_E_BUF;
  if (wc_CBOR_EncodeTstr(&c, (const uint8_t*)name, name_len) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  *len = c.idx;
  return CC_OK;
}

static int dec_presence(const uint8_t* buf, size_t sz, uint8_t* hops,
                        uint32_t* nonce, const uint8_t** addr, size_t* addr_len,
                        const uint8_t** name, size_t* name_len) {
  WOLFCOSE_CBOR_CTX c;
  size_t count;
  uint64_t val;
  cbor_dec_init(&c, buf, sz);
  if (wc_CBOR_DecodeArrayStart(&c, &count) != WOLFCOSE_SUCCESS || count != 5)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS || val != CC_MSG_PRESENCE)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS) return CC_E_FORMAT;
  *hops = (uint8_t)(val & 0xFF);
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS) return CC_E_FORMAT;
  *nonce = (uint32_t)(val & 0xFFFFFFFF);
  if (wc_CBOR_DecodeBstr(&c, addr, addr_len) != WOLFCOSE_SUCCESS ||
      *addr_len != CC_ADDR_SZ)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeTstr(&c, name, name_len) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  return CC_OK;
}

static int enc_key_req(uint8_t* buf, size_t sz, size_t* len, uint8_t hops,
                       const uint8_t addr[CC_ADDR_SZ], uint32_t nonce) {
  WOLFCOSE_CBOR_CTX c;
  cbor_enc_init(&c, buf, sz);
  if (wc_CBOR_EncodeArrayStart(&c, 4) != WOLFCOSE_SUCCESS) return CC_E_BUF;
  if (wc_CBOR_EncodeUint(&c, CC_MSG_KEY_REQ)   != WOLFCOSE_SUCCESS) return CC_E_BUF;
  if (wc_CBOR_EncodeUint(&c, hops)             != WOLFCOSE_SUCCESS) return CC_E_BUF;
  if (wc_CBOR_EncodeBstr(&c, addr, CC_ADDR_SZ) != WOLFCOSE_SUCCESS) return CC_E_BUF;
  if (wc_CBOR_EncodeUint(&c, nonce)            != WOLFCOSE_SUCCESS) return CC_E_BUF;
  *len = c.idx;
  return CC_OK;
}

static int dec_key_req(const uint8_t* buf, size_t sz, uint8_t* hops,
                       uint8_t addr[CC_ADDR_SZ], uint32_t* nonce) {
  WOLFCOSE_CBOR_CTX c;
  size_t count;
  uint64_t val;
  const uint8_t* tmp;
  size_t tmp_len;
  cbor_dec_init(&c, buf, sz);
  if (wc_CBOR_DecodeArrayStart(&c, &count) != WOLFCOSE_SUCCESS || count != 4)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS || val != CC_MSG_KEY_REQ)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS) return CC_E_FORMAT;
  *hops = (uint8_t)(val & 0xFF);
  if (wc_CBOR_DecodeBstr(&c, &tmp, &tmp_len) != WOLFCOSE_SUCCESS ||
      tmp_len != CC_ADDR_SZ)
    return CC_E_FORMAT;
  memcpy(addr, tmp, CC_ADDR_SZ);
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS) return CC_E_FORMAT;
  *nonce = (uint32_t)(val & 0xFFFFFFFF);
  return CC_OK;
}

/* ---- Announce payload encode/decode ---- */

static int enc_ann_payload(uint8_t* buf, size_t sz, size_t* len,
                           const uint8_t sign_pub[CC_SIGN_PUBKEY_SZ],
                           const uint8_t kem_pub[CC_KEM_PUBKEY_SZ],
                           const char* name, size_t name_len,
                           const uint8_t* meta, size_t meta_len) {
  WOLFCOSE_CBOR_CTX c;
  cbor_enc_init(&c, buf, sz);
  if (wc_CBOR_EncodeArrayStart(&c, 4) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeBstr(&c, sign_pub, CC_SIGN_PUBKEY_SZ) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeBstr(&c, kem_pub, CC_KEM_PUBKEY_SZ) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeTstr(&c, (const uint8_t*)name, name_len) !=
      WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeBstr(&c, meta, meta_len) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  *len = c.idx;
  return CC_OK;
}

static int dec_ann_payload(const uint8_t* buf, size_t sz,
                           uint8_t sign_pub[CC_SIGN_PUBKEY_SZ],
                           uint8_t kem_pub[CC_KEM_PUBKEY_SZ], char* name,
                           size_t* name_len, uint8_t* meta, size_t* meta_len) {
  WOLFCOSE_CBOR_CTX c;
  size_t count;
  const uint8_t* tmp;
  size_t tmp_len;
  cbor_dec_init(&c, buf, sz);
  if (wc_CBOR_DecodeArrayStart(&c, &count) != WOLFCOSE_SUCCESS || count != 4)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeBstr(&c, &tmp, &tmp_len) != WOLFCOSE_SUCCESS ||
      tmp_len != CC_SIGN_PUBKEY_SZ)
    return CC_E_FORMAT;
  memcpy(sign_pub, tmp, CC_SIGN_PUBKEY_SZ);
  if (wc_CBOR_DecodeBstr(&c, &tmp, &tmp_len) != WOLFCOSE_SUCCESS ||
      tmp_len != CC_KEM_PUBKEY_SZ)
    return CC_E_FORMAT;
  memcpy(kem_pub, tmp, CC_KEM_PUBKEY_SZ);
  if (wc_CBOR_DecodeTstr(&c, &tmp, &tmp_len) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  if (tmp_len > CC_MAX_NAME_LEN)
    tmp_len = CC_MAX_NAME_LEN;
  memcpy(name, tmp, tmp_len);
  name[tmp_len] = '\0';
  *name_len = tmp_len;
  if (wc_CBOR_DecodeBstr(&c, &tmp, &tmp_len) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  if (tmp_len > CC_MAX_META_SZ)
    tmp_len = CC_MAX_META_SZ;
  if (meta && tmp_len)
    memcpy(meta, tmp, tmp_len);
  *meta_len = tmp_len;
  return CC_OK;
}

/* Extract payload from COSE_Sign1 without verifying (to get pubkeys first). */
static int sign1_payload(const uint8_t* in, size_t sz, const uint8_t** out,
                         size_t* out_len) {
  WOLFCOSE_CBOR_CTX c;
  uint64_t tag;
  size_t count;
  cbor_dec_init(&c, in, sz);
  if (c.idx < c.bufSz && wc_CBOR_PeekType(&c) == WOLFCOSE_CBOR_TAG) {
    if (wc_CBOR_DecodeTag(&c, &tag) != WOLFCOSE_SUCCESS)
      return CC_E_FORMAT;
    if (tag != WOLFCOSE_TAG_SIGN1)
      return CC_E_FORMAT;
  }
  if (wc_CBOR_DecodeArrayStart(&c, &count) != WOLFCOSE_SUCCESS || count != 4)
    return CC_E_FORMAT;
  if (wc_CBOR_Skip(&c) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  if (wc_CBOR_Skip(&c) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeBstr(&c, out, out_len) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  return CC_OK;
}

/* ---- Chat payload encode/decode ---- */

static int enc_chat_payload(uint8_t* buf, size_t sz, size_t* len,
                            const uint8_t sender[CC_ADDR_SZ],
                            const uint8_t* msg, size_t msg_len) {
  WOLFCOSE_CBOR_CTX c;
  cbor_enc_init(&c, buf, sz);
  if (wc_CBOR_EncodeArrayStart(&c, 2) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeBstr(&c, sender, CC_ADDR_SZ) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeBstr(&c, msg, msg_len) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  *len = c.idx;
  return CC_OK;
}

static int dec_chat_payload(const uint8_t* buf, size_t sz,
                            uint8_t sender[CC_ADDR_SZ], uint8_t* msg,
                            size_t* msg_len) {
  WOLFCOSE_CBOR_CTX c;
  size_t count;
  const uint8_t* tmp;
  size_t tmp_len;
  cbor_dec_init(&c, buf, sz);
  if (wc_CBOR_DecodeArrayStart(&c, &count) != WOLFCOSE_SUCCESS || count != 2)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeBstr(&c, &tmp, &tmp_len) != WOLFCOSE_SUCCESS ||
      tmp_len != CC_ADDR_SZ)
    return CC_E_FORMAT;
  memcpy(sender, tmp, CC_ADDR_SZ);
  if (wc_CBOR_DecodeBstr(&c, &tmp, &tmp_len) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  if (tmp_len > CC_MAX_MSG_SZ)
    return CC_E_BUF;
  memcpy(msg, tmp, tmp_len);
  *msg_len = tmp_len;
  return CC_OK;
}

/* ---- ML-KEM-512 key derivation for chat ---- */

/* Encapsulate: load recipient pub key, run KEM, HKDF shared secret → AES key.
 */
static int kem_encap(const uint8_t recip_pub[CC_KEM_PUBKEY_SZ],
                     uint8_t ct[CC_KEM_CT_SZ], uint8_t aes[32], WC_RNG* rng) {
  static KyberKey tmp;
  uint8_t ss[CC_KEM_SS_SZ];
  static const uint8_t info[] = "cosechat";
  int ret;
  ret = wc_KyberKey_Init(CC_KEM_TYPE, &tmp, NULL, INVALID_DEVID);
  if (ret != 0)
    return CC_E_CRYPTO;
  ret = wc_KyberKey_DecodePublicKey(&tmp, recip_pub, CC_KEM_PUBKEY_SZ);
  if (ret != 0) {
    wc_KyberKey_Free(&tmp);
    return CC_E_CRYPTO;
  }
  ret = wc_KyberKey_Encapsulate(&tmp, ct, ss, rng);
  wc_KyberKey_Free(&tmp);
  if (ret != 0)
    return CC_E_CRYPTO;
  ret = wc_HKDF(WC_HASH_TYPE_SHA256, ss, CC_KEM_SS_SZ, NULL, 0, info,
                (word32)(sizeof(info) - 1), aes, 32);
  wc_ForceZero(ss, CC_KEM_SS_SZ);
  return (ret == 0) ? CC_OK : CC_E_CRYPTO;
}

/* Decapsulate: use own private KEM key to recover shared secret → AES key. */
static int kem_decap(KyberKey* priv, const uint8_t* ct, size_t ct_len,
                     uint8_t aes[32]) {
  uint8_t ss[CC_KEM_SS_SZ];
  static const uint8_t info[] = "cosechat";
  int ret;
  if (ct_len != CC_KEM_CT_SZ)
    return CC_E_FORMAT;
  ret = wc_KyberKey_Decapsulate(priv, ss, ct, (word32)ct_len);
  if (ret != 0)
    return CC_E_CRYPTO;
  ret = wc_HKDF(WC_HASH_TYPE_SHA256, ss, CC_KEM_SS_SZ, NULL, 0, info,
                (word32)(sizeof(info) - 1), aes, 32);
  wc_ForceZero(ss, CC_KEM_SS_SZ);
  return (ret == 0) ? CC_OK : CC_E_CRYPTO;
}

/* ---- Public API ---- */

int cc_key_generate(cc_key_t* key, WC_RNG* rng) {
  int ret;
  if (!key || !rng)
    return CC_E_ARG;
  wc_dilithium_init(&key->sign);
  ret = wc_dilithium_set_level(&key->sign, CC_SIGN_LEVEL);
  if (ret != 0)
    return CC_E_CRYPTO;
  ret = wc_dilithium_make_key(&key->sign, rng);
  if (ret != 0)
    return CC_E_CRYPTO;
  ret = wc_KyberKey_Init(CC_KEM_TYPE, &key->kem, NULL, INVALID_DEVID);
  if (ret != 0)
    return CC_E_CRYPTO;
  ret = wc_KyberKey_MakeKey(&key->kem, rng);
  return (ret == 0) ? CC_OK : CC_E_CRYPTO;
}

int cc_key_import(cc_key_t* key, const uint8_t sign_priv[CC_SIGN_PRIVKEY_SZ],
                  const uint8_t sign_pub[CC_SIGN_PUBKEY_SZ],
                  const uint8_t kem_priv[CC_KEM_PRIVKEY_SZ]) {
  int ret;
  if (!key || !sign_priv || !sign_pub || !kem_priv)
    return CC_E_ARG;
  wc_dilithium_init(&key->sign);
  ret = wc_dilithium_set_level(&key->sign, CC_SIGN_LEVEL);
  if (ret != 0)
    return CC_E_CRYPTO;
  ret = wc_dilithium_import_key(sign_priv, CC_SIGN_PRIVKEY_SZ,
                                sign_pub, CC_SIGN_PUBKEY_SZ, &key->sign);
  if (ret != 0)
    return CC_E_CRYPTO;
  ret = wc_KyberKey_Init(CC_KEM_TYPE, &key->kem, NULL, INVALID_DEVID);
  if (ret != 0)
    return CC_E_CRYPTO;
  ret = wc_KyberKey_DecodePrivateKey(&key->kem, kem_priv, CC_KEM_PRIVKEY_SZ);
  return (ret == 0) ? CC_OK : CC_E_CRYPTO;
}

int cc_key_export_private(const cc_key_t* key,
                          uint8_t sign_priv[CC_SIGN_PRIVKEY_SZ],
                          uint8_t kem_priv[CC_KEM_PRIVKEY_SZ]) {
  word32 sz;
  int ret;
  if (!key || !sign_priv || !kem_priv)
    return CC_E_ARG;
  sz = CC_SIGN_PRIVKEY_SZ;
  ret = wc_dilithium_export_private((dilithium_key*)&key->sign, sign_priv, &sz);
  if (ret != 0)
    return CC_E_CRYPTO;
  sz = CC_KEM_PRIVKEY_SZ;
  ret = wc_KyberKey_EncodePrivateKey((KyberKey*)&key->kem, kem_priv, sz);
  return (ret == 0) ? CC_OK : CC_E_CRYPTO;
}

int cc_key_export_public(const cc_key_t* key,
                         uint8_t sign_pub[CC_SIGN_PUBKEY_SZ],
                         uint8_t kem_pub[CC_KEM_PUBKEY_SZ]) {
  word32 sz;
  int ret;
  if (!key || !sign_pub || !kem_pub)
    return CC_E_ARG;
  sz = CC_SIGN_PUBKEY_SZ;
  ret = wc_dilithium_export_public((dilithium_key*)&key->sign, sign_pub, &sz);
  if (ret != 0)
    return CC_E_CRYPTO;
  sz = CC_KEM_PUBKEY_SZ;
  ret = wc_KyberKey_EncodePublicKey((KyberKey*)&key->kem, kem_pub, sz);
  return (ret == 0) ? CC_OK : CC_E_CRYPTO;
}

void cc_key_free(cc_key_t* key) {
  if (key) {
    wc_dilithium_free(&key->sign);
    wc_KyberKey_Free(&key->kem);
  }
}

int cc_addr_from_sign_pubkey(const uint8_t pub[CC_SIGN_PUBKEY_SZ],
                             uint8_t addr[CC_ADDR_SZ]) {
  uint8_t hash[32];
  if (!pub || !addr)
    return CC_E_ARG;
  if (wc_Sha256Hash(pub, CC_SIGN_PUBKEY_SZ, hash) != 0)
    return CC_E_CRYPTO;
  memcpy(addr, hash, CC_ADDR_SZ);
  return CC_OK;
}

int cc_addr_from_key(const cc_key_t* key, uint8_t addr[CC_ADDR_SZ]) {
  uint8_t pub[CC_SIGN_PUBKEY_SZ];
  word32 sz = CC_SIGN_PUBKEY_SZ;
  int ret;
  if (!key || !addr)
    return CC_E_ARG;
  ret = wc_dilithium_export_public((dilithium_key*)&key->sign, pub, &sz);
  if (ret != 0)
    return CC_E_CRYPTO;
  return cc_addr_from_sign_pubkey(pub, addr);
}

int cc_announce_build(const cc_key_t* key, const char* name, size_t name_len,
                      const uint8_t* meta, size_t meta_len, uint8_t* out,
                      size_t out_sz, size_t* out_len, WC_RNG* rng) {
  static uint8_t payload_buf[CC_ANN_PAYLOAD_SZ];
  static uint8_t sign1_buf[CC_SIGN1_SZ];
  static uint8_t scratch[CC_SIGN_SCRATCH_SZ];
  uint8_t sign_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t kem_pub[CC_KEM_PUBKEY_SZ];
  size_t payload_len = 0, sign1_len = 0;
  WOLFCOSE_KEY cose_key;
  uint32_t nonce = 0;
  word32 sz;
  int ret;

  if (!key || !out || !out_len || !rng)
    return CC_E_ARG;
  if (name_len > CC_MAX_NAME_LEN || meta_len > CC_MAX_META_SZ)
    return CC_E_ARG;

  sz = CC_SIGN_PUBKEY_SZ;
  ret = wc_dilithium_export_public((dilithium_key*)&key->sign, sign_pub, &sz);
  if (ret != 0)
    return CC_E_CRYPTO;
  sz = CC_KEM_PUBKEY_SZ;
  ret = wc_KyberKey_EncodePublicKey((KyberKey*)&key->kem, kem_pub, sz);
  if (ret != 0)
    return CC_E_CRYPTO;

  ret = enc_ann_payload(payload_buf, sizeof(payload_buf), &payload_len,
                        sign_pub, kem_pub, name ? name : "",
                        name ? name_len : 0, meta, meta_len);
  if (ret != CC_OK)
    return ret;

  wc_CoseKey_Init(&cose_key);
  ret = wc_CoseKey_SetDilithium(&cose_key, WOLFCOSE_ALG_ML_DSA_44,
                                (dilithium_key*)&key->sign);
  if (ret != WOLFCOSE_SUCCESS)
    return CC_E_CRYPTO;

  ret =
      wc_CoseSign1_Sign(&cose_key, WOLFCOSE_ALG_ML_DSA_44, NULL, 0, payload_buf,
                        payload_len, NULL, 0, NULL, 0, scratch, sizeof(scratch),
                        sign1_buf, sizeof(sign1_buf), &sign1_len, rng);
  wc_CoseKey_Free(&cose_key);
  if (ret != WOLFCOSE_SUCCESS)
    return CC_E_CRYPTO;

  ret =
      pow_find(CC_MSG_ANNOUNCE, sign1_buf, sign1_len, NULL, 0, NULL, 0, &nonce);
  if (ret != CC_OK)
    return ret;

  return enc_announce(out, out_sz, out_len, 0, nonce, sign1_buf, sign1_len);
}

int cc_announce_parse(const uint8_t* in, size_t in_sz, cc_announce_t* ann) {
  static dilithium_key tmp_sign;
  static uint8_t scratch[CC_SIGN_SCRATCH_SZ];
  uint8_t hops;
  uint32_t nonce;
  const uint8_t* sign1;
  size_t sign1_len;
  const uint8_t* payload;
  size_t payload_len;
  uint8_t hash[32];
  WOLFCOSE_HDR hdr;
  WOLFCOSE_KEY cose_key;
  const uint8_t* vp;
  size_t vp_len;
  word32 sz;
  int ret;

  if (!in || !ann)
    return CC_E_ARG;
  memset(ann, 0, sizeof(*ann));

  ret = dec_announce(in, in_sz, &hops, &nonce, &sign1, &sign1_len);
  if (ret != CC_OK)
    return ret;

  ret = pow_hash(CC_MSG_ANNOUNCE, sign1, sign1_len, NULL, 0, NULL, 0, nonce,
                 hash);
  if (ret != CC_OK)
    return ret;
  if (pow_check(hash) != CC_OK)
    return CC_E_POW;

  ret = sign1_payload(sign1, sign1_len, &payload, &payload_len);
  if (ret != CC_OK)
    return ret;

  ret = dec_ann_payload(payload, payload_len, ann->sign_pubkey, ann->kem_pubkey,
                        ann->name, &ann->name_len, ann->meta, &ann->meta_len);
  if (ret != CC_OK)
    return ret;

  /* Import sign pubkey for verification */
  wc_dilithium_init(&tmp_sign);
  ret = wc_dilithium_set_level(&tmp_sign, CC_SIGN_LEVEL);
  if (ret != 0) {
    wc_dilithium_free(&tmp_sign);
    return CC_E_CRYPTO;
  }
  sz = CC_SIGN_PUBKEY_SZ;
  ret = wc_dilithium_import_public(ann->sign_pubkey, sz, &tmp_sign);
  if (ret != 0) {
    wc_dilithium_free(&tmp_sign);
    return CC_E_CRYPTO;
  }

  wc_CoseKey_Init(&cose_key);
  ret = wc_CoseKey_SetDilithium(&cose_key, WOLFCOSE_ALG_ML_DSA_44, &tmp_sign);
  if (ret != WOLFCOSE_SUCCESS) {
    wc_dilithium_free(&tmp_sign);
    return CC_E_CRYPTO;
  }

  ret = wc_CoseSign1_Verify(&cose_key, sign1, sign1_len, NULL, 0, NULL, 0,
                            scratch, sizeof(scratch), &hdr, &vp, &vp_len);
  wc_CoseKey_Free(&cose_key);
  wc_dilithium_free(&tmp_sign);
  if (ret != WOLFCOSE_SUCCESS)
    return CC_E_SIG;

  ret = cc_addr_from_sign_pubkey(ann->sign_pubkey, ann->addr);
  if (ret != CC_OK)
    return ret;

  ann->hops = hops;
  return CC_OK;
}

int cc_chat_build(const cc_key_t* sender_key,
                  const uint8_t recipient_addr[CC_ADDR_SZ],
                  const uint8_t recipient_kem_pub[CC_KEM_PUBKEY_SZ],
                  const uint8_t* msg, size_t msg_len, uint8_t* out,
                  size_t out_sz, size_t* out_len, WC_RNG* rng) {
  static uint8_t payload_buf[CC_CHAT_PT_SZ];
  static uint8_t enc0_buf[CC_ENC0_SZ];
  uint8_t kem_ct[CC_KEM_CT_SZ];
  uint8_t aes_key[32];
  uint8_t iv[12];
  uint8_t sender_addr[CC_ADDR_SZ];
  uint8_t scratch[CC_ENC_SCRATCH_SZ];
  WOLFCOSE_KEY cose_sym;
  size_t payload_len = 0, enc0_len = 0;
  uint32_t nonce = 0;
  int ret;

  if (!sender_key || !recipient_addr || !recipient_kem_pub || !msg || !out ||
      !out_len || !rng)
    return CC_E_ARG;
  if (msg_len > CC_MAX_MSG_SZ)
    return CC_E_ARG;

  ret = cc_addr_from_key(sender_key, sender_addr);
  if (ret != CC_OK)
    return ret;

  /* KEM encapsulate → ciphertext + AES key */
  ret = kem_encap(recipient_kem_pub, kem_ct, aes_key, rng);
  if (ret != CC_OK)
    return ret;

  ret = enc_chat_payload(payload_buf, sizeof(payload_buf), &payload_len,
                         sender_addr, msg, msg_len);
  if (ret != CC_OK) {
    wc_ForceZero(aes_key, 32);
    return ret;
  }

  ret = wc_RNG_GenerateBlock(rng, iv, sizeof(iv));
  if (ret != 0) {
    wc_ForceZero(aes_key, 32);
    return CC_E_CRYPTO;
  }

  wc_CoseKey_Init(&cose_sym);
  ret = wc_CoseKey_SetSymmetric(&cose_sym, aes_key, 32);
  if (ret != WOLFCOSE_SUCCESS) {
    wc_ForceZero(aes_key, 32);
    return CC_E_CRYPTO;
  }

  ret = wc_CoseEncrypt0_Encrypt(&cose_sym, WOLFCOSE_ALG_A256GCM, iv, sizeof(iv),
                                payload_buf, payload_len, NULL, 0, NULL, NULL,
                                0, scratch, sizeof(scratch), enc0_buf,
                                sizeof(enc0_buf), &enc0_len);
  wc_CoseKey_Free(&cose_sym);
  wc_ForceZero(aes_key, 32);
  if (ret != WOLFCOSE_SUCCESS)
    return CC_E_CRYPTO;

  ret = pow_find(CC_MSG_CHAT, recipient_addr, CC_ADDR_SZ, kem_ct, CC_KEM_CT_SZ,
                 enc0_buf, enc0_len, &nonce);
  if (ret != CC_OK)
    return ret;

  return enc_chat(out, out_sz, out_len, 0, recipient_addr, kem_ct, nonce,
                  enc0_buf, enc0_len);
}

int cc_chat_parse(const cc_key_t* my_key, const uint8_t* in, size_t in_sz,
                  cc_chat_t* chat) {
  static uint8_t plaintext[CC_CHAT_PT_SZ];
  uint8_t recip_addr[CC_ADDR_SZ];
  const uint8_t* kem_ct;
  size_t kem_ct_len;
  uint32_t nonce;
  const uint8_t* enc0;
  size_t enc0_len;
  uint8_t hash[32];
  uint8_t aes_key[32];
  uint8_t scratch[CC_ENC_SCRATCH_SZ];
  WOLFCOSE_KEY cose_sym;
  WOLFCOSE_HDR hdr;
  size_t pt_len = 0;
  int ret;

  if (!my_key || !in || !chat)
    return CC_E_ARG;
  memset(chat, 0, sizeof(*chat));

  ret = dec_chat(in, in_sz, &chat->hops, recip_addr, &kem_ct, &kem_ct_len,
                 &nonce, &enc0, &enc0_len);
  if (ret != CC_OK)
    return ret;

  ret = pow_hash(CC_MSG_CHAT, recip_addr, CC_ADDR_SZ, kem_ct, kem_ct_len, enc0,
                 enc0_len, nonce, hash);
  if (ret != CC_OK)
    return ret;
  if (pow_check(hash) != CC_OK)
    return CC_E_POW;

  /* KEM decapsulate → AES key */
  ret = kem_decap((KyberKey*)&my_key->kem, kem_ct, kem_ct_len, aes_key);
  if (ret != CC_OK)
    return ret;

  wc_CoseKey_Init(&cose_sym);
  ret = wc_CoseKey_SetSymmetric(&cose_sym, aes_key, 32);
  if (ret != WOLFCOSE_SUCCESS) {
    wc_ForceZero(aes_key, 32);
    return CC_E_CRYPTO;
  }

  ret = wc_CoseEncrypt0_Decrypt(&cose_sym, enc0, enc0_len, NULL, 0, NULL, 0,
                                scratch, sizeof(scratch), &hdr, plaintext,
                                sizeof(plaintext), &pt_len);
  wc_CoseKey_Free(&cose_sym);
  wc_ForceZero(aes_key, 32);
  if (ret != WOLFCOSE_SUCCESS)
    return CC_E_DECRYPT;

  ret = dec_chat_payload(plaintext, pt_len, chat->sender_addr, chat->msg,
                         &chat->msg_len);
  return ret;
}

int cc_presence_build(const cc_key_t* key, const char* name, size_t name_len,
                      uint8_t* out, size_t out_sz, size_t* out_len, WC_RNG* rng) {
  uint8_t addr[CC_ADDR_SZ];
  uint32_t nonce = 0;
  int ret;
  if (!key || !out || !out_len || !rng) return CC_E_ARG;
  if (name_len > CC_MAX_NAME_LEN) return CC_E_ARG;
  ret = cc_addr_from_key(key, addr);
  if (ret != CC_OK) return ret;
  ret = pow_find(CC_MSG_PRESENCE, addr, CC_ADDR_SZ,
                 (const uint8_t*)(name ? name : ""), name ? name_len : 0,
                 NULL, 0, &nonce);
  if (ret != CC_OK) return ret;
  return enc_presence(out, out_sz, out_len, 0, nonce, addr,
                      name ? name : "", name ? name_len : 0);
}

int cc_presence_parse(const uint8_t* in, size_t in_sz, cc_presence_t* p) {
  uint8_t hops;
  uint32_t nonce;
  const uint8_t* addr;
  size_t addr_len;
  const uint8_t* name;
  size_t name_len;
  uint8_t hash[32];
  int ret;
  if (!in || !p) return CC_E_ARG;
  memset(p, 0, sizeof(*p));
  ret = dec_presence(in, in_sz, &hops, &nonce, &addr, &addr_len, &name, &name_len);
  if (ret != CC_OK) return ret;
  ret = pow_hash(CC_MSG_PRESENCE, addr, CC_ADDR_SZ, name, name_len, NULL, 0,
                 nonce, hash);
  if (ret != CC_OK) return ret;
  if (pow_check(hash) != CC_OK) return CC_E_POW;
  memcpy(p->addr, addr, CC_ADDR_SZ);
  if (name_len > CC_MAX_NAME_LEN) name_len = CC_MAX_NAME_LEN;
  memcpy(p->name, name, name_len);
  p->name[name_len] = '\0';
  p->name_len = name_len;
  p->hops = hops;
  return CC_OK;
}

int cc_key_req_build(const uint8_t addr[CC_ADDR_SZ],
                     uint8_t* out, size_t out_sz, size_t* out_len) {
  uint32_t nonce = 0;
  int ret;
  if (!addr || !out || !out_len) return CC_E_ARG;
  ret = pow_find(CC_MSG_KEY_REQ, addr, CC_ADDR_SZ, NULL, 0, NULL, 0, &nonce);
  if (ret != CC_OK) return ret;
  return enc_key_req(out, out_sz, out_len, 0, addr, nonce);
}

int cc_key_req_parse(const uint8_t* in, size_t in_sz, uint8_t addr[CC_ADDR_SZ]) {
  uint8_t hops;
  uint32_t nonce;
  uint8_t hash[32];
  int ret;
  if (!in || !addr) return CC_E_ARG;
  ret = dec_key_req(in, in_sz, &hops, addr, &nonce);
  if (ret != CC_OK) return ret;
  ret = pow_hash(CC_MSG_KEY_REQ, addr, CC_ADDR_SZ, NULL, 0, NULL, 0, nonce, hash);
  if (ret != CC_OK) return ret;
  return pow_check(hash);
}

int cc_msg_type(const uint8_t* pkt, size_t pkt_sz, uint8_t* type_out) {
  WOLFCOSE_CBOR_CTX c;
  size_t count;
  uint64_t val;
  if (!pkt || !type_out || pkt_sz < 2)
    return CC_E_ARG;
  cbor_dec_init(&c, pkt, pkt_sz);
  if (wc_CBOR_DecodeArrayStart(&c, &count) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  *type_out = (uint8_t)(val & 0xFF);
  return CC_OK;
}

int cc_msg_hops(const uint8_t* pkt, size_t pkt_sz, uint8_t* hops_out) {
  WOLFCOSE_CBOR_CTX c;
  size_t count;
  uint64_t val;
  if (!pkt || !hops_out)
    return CC_E_ARG;
  cbor_dec_init(&c, pkt, pkt_sz);
  if (wc_CBOR_DecodeArrayStart(&c, &count) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  *hops_out = (uint8_t)(val & 0xFF);
  return CC_OK;
}

int cc_msg_recipient(const uint8_t* pkt, size_t pkt_sz,
                     uint8_t addr[CC_ADDR_SZ]) {
  WOLFCOSE_CBOR_CTX c;
  size_t count;
  uint64_t val;
  const uint8_t* tmp;
  size_t tmp_len;
  uint8_t type;
  int ret;
  if (!pkt || !addr)
    return CC_E_ARG;
  ret = cc_msg_type(pkt, pkt_sz, &type);
  if (ret != CC_OK)
    return ret;
  if (type != CC_MSG_CHAT)
    return CC_E_FORMAT;
  cbor_dec_init(&c, pkt, pkt_sz);
  if (wc_CBOR_DecodeArrayStart(&c, &count) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeUint(&c, &val) != WOLFCOSE_SUCCESS)
    return CC_E_FORMAT;
  if (wc_CBOR_DecodeBstr(&c, &tmp, &tmp_len) != WOLFCOSE_SUCCESS ||
      tmp_len != CC_ADDR_SZ)
    return CC_E_FORMAT;
  memcpy(addr, tmp, CC_ADDR_SZ);
  return CC_OK;
}

int cc_hops_increment(const uint8_t* in, size_t in_sz, uint8_t* out,
                      size_t out_sz, size_t* out_len) {
  uint8_t type;
  int ret;
  if (!in || !out || !out_len)
    return CC_E_ARG;
  ret = cc_msg_type(in, in_sz, &type);
  if (ret != CC_OK)
    return ret;

  if (type == CC_MSG_ANNOUNCE) {
    uint8_t hops;
    uint32_t nonce;
    const uint8_t* sign1;
    size_t sign1_len;
    ret = dec_announce(in, in_sz, &hops, &nonce, &sign1, &sign1_len);
    if (ret != CC_OK)
      return ret;
    if (hops == 255)
      return CC_E_ARG;
    return enc_announce(out, out_sz, out_len, (uint8_t)(hops + 1), nonce, sign1,
                        sign1_len);
  }
  if (type == CC_MSG_CHAT) {
    uint8_t hops;
    uint8_t recip[CC_ADDR_SZ];
    const uint8_t* kem_ct;
    size_t kem_ct_len;
    uint32_t nonce;
    const uint8_t* enc0;
    size_t enc0_len;
    ret = dec_chat(in, in_sz, &hops, recip, &kem_ct, &kem_ct_len, &nonce, &enc0,
                   &enc0_len);
    if (ret != CC_OK)
      return ret;
    if (hops == 255)
      return CC_E_ARG;
    return enc_chat(out, out_sz, out_len, (uint8_t)(hops + 1), recip, kem_ct,
                    nonce, enc0, enc0_len);
  }
  if (type == CC_MSG_PRESENCE) {
    uint8_t hops;
    uint32_t nonce;
    const uint8_t* addr;
    size_t addr_len;
    const uint8_t* name;
    size_t name_len;
    ret = dec_presence(in, in_sz, &hops, &nonce, &addr, &addr_len, &name, &name_len);
    if (ret != CC_OK) return ret;
    if (hops == 255) return CC_E_ARG;
    return enc_presence(out, out_sz, out_len, (uint8_t)(hops + 1), nonce, addr,
                        (const char*)name, name_len);
  }
  if (type == CC_MSG_KEY_REQ) {
    uint8_t hops;
    uint8_t req_addr[CC_ADDR_SZ];
    uint32_t nonce;
    ret = dec_key_req(in, in_sz, &hops, req_addr, &nonce);
    if (ret != CC_OK) return ret;
    if (hops == 255) return CC_E_ARG;
    return enc_key_req(out, out_sz, out_len, (uint8_t)(hops + 1), req_addr, nonce);
  }
  return CC_E_FORMAT;
}

int cc_pow_verify(const uint8_t* pkt, size_t pkt_sz) {
  uint8_t type;
  uint8_t hash[32];
  int ret;
  if (!pkt)
    return CC_E_ARG;
  ret = cc_msg_type(pkt, pkt_sz, &type);
  if (ret != CC_OK)
    return ret;

  if (type == CC_MSG_ANNOUNCE) {
    uint8_t hops;
    uint32_t nonce;
    const uint8_t* sign1;
    size_t sign1_len;
    ret = dec_announce(pkt, pkt_sz, &hops, &nonce, &sign1, &sign1_len);
    if (ret != CC_OK)
      return ret;
    ret = pow_hash(CC_MSG_ANNOUNCE, sign1, sign1_len, NULL, 0, NULL, 0, nonce,
                   hash);
    if (ret != CC_OK)
      return ret;
    return pow_check(hash);
  }
  if (type == CC_MSG_CHAT) {
    uint8_t hops;
    uint8_t recip[CC_ADDR_SZ];
    const uint8_t* kem_ct;
    size_t kem_ct_len;
    uint32_t nonce;
    const uint8_t* enc0;
    size_t enc0_len;
    ret = dec_chat(pkt, pkt_sz, &hops, recip, &kem_ct, &kem_ct_len, &nonce,
                   &enc0, &enc0_len);
    if (ret != CC_OK)
      return ret;
    ret = pow_hash(CC_MSG_CHAT, recip, CC_ADDR_SZ, kem_ct, kem_ct_len, enc0,
                   enc0_len, nonce, hash);
    if (ret != CC_OK)
      return ret;
    return pow_check(hash);
  }
  if (type == CC_MSG_PRESENCE) {
    uint8_t hops;
    uint32_t nonce;
    const uint8_t* addr;
    size_t addr_len;
    const uint8_t* name;
    size_t name_len;
    ret = dec_presence(pkt, pkt_sz, &hops, &nonce, &addr, &addr_len, &name, &name_len);
    if (ret != CC_OK) return ret;
    ret = pow_hash(CC_MSG_PRESENCE, addr, CC_ADDR_SZ, name, name_len, NULL, 0,
                   nonce, hash);
    if (ret != CC_OK) return ret;
    return pow_check(hash);
  }
  if (type == CC_MSG_KEY_REQ) {
    uint8_t hops;
    uint8_t addr[CC_ADDR_SZ];
    uint32_t nonce;
    ret = dec_key_req(pkt, pkt_sz, &hops, addr, &nonce);
    if (ret != CC_OK) return ret;
    ret = pow_hash(CC_MSG_KEY_REQ, addr, CC_ADDR_SZ, NULL, 0, NULL, 0, nonce, hash);
    if (ret != CC_OK) return ret;
    return pow_check(hash);
  }
  return CC_E_FORMAT;
}
