/* cc_store.c — see cc_store.h for the container layout, the choices and the
 * failure taxonomy. This file is the implementation: buffers in, buffers out,
 * no heap, no medium, no global state. */

#include "cc_store.h"

#include <string.h>

/* cc_store.h has already selected the wolfSSL configuration (options.h on a
 * host build, user_settings.h on the firmware), so these see the same view as
 * the library they link against. */
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hmac.h>   /* wc_HKDF */
#include <wolfssl/wolfcrypt/memory.h> /* wc_ForceZero */
#include <wolfssl/wolfcrypt/pwdbased.h>

/* The firmware builds wolfSSL with NO_PWDBASED (user_settings.h), which
 * compiles wc_PBKDF2 to nothing. That define is the only reason this module
 * cannot use it, so fail loudly at the definition rather than at the link,
 * where the reason would be invisible. The host suite has PBKDF2 enabled. */
#ifdef NO_PWDBASED
#error \
    "cc_store needs wc_PBKDF2: remove NO_PWDBASED from examples/cardputer/include/user_settings.h"
#endif

static const uint8_t CC_STORE_MAGIC[4] = {'C', 'C', 'S', 'P'};

/* ---------------------------------------------------------------------------
 * Small helpers
 * ------------------------------------------------------------------------- */
static void wipe(void* p, size_t n) { wc_ForceZero(p, n); }

static void put_be32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Usable context length, or 0 if the context is missing, empty or longer than
 * CC_STORE_CTX_MAX. The scan is bounded, so an unterminated caller buffer
 * cannot walk off the end, and the caller only ever needs "usable or not". */
static size_t ctx_len(const char* ctx) {
  size_t n = 0;
  if (ctx == NULL)
    return 0;
  while (n <= CC_STORE_CTX_MAX && ctx[n] != '\0') n++;
  return (n == 0 || n > CC_STORE_CTX_MAX) ? 0 : n;
}

/* Does this passphrase length look callable at all? Zero is refused on
 * purpose: see CC_STORE_PASS_MAX in the header. */
static int pass_ok(const uint8_t* pass, size_t pass_len) {
  return pass != NULL && pass_len > 0 && pass_len <= CC_STORE_PASS_MAX;
}

/* Parse the public header. Everything this decides is decided by the bytes
 * alone: no key, no passphrase, no crypto. That is why its failures are
 * CC_STORE_E_DAMAGE / CC_STORE_E_VERSION and never CC_STORE_E_AUTH. */
static int parse(const uint8_t* c, size_t n, cc_store_info_t* info) {
  uint32_t plen, iters;

  if (c == NULL)
    return CC_STORE_E_ARG;
  if (n < CC_STORE_HDR_SZ + CC_STORE_TAG_SZ)
    return CC_STORE_E_DAMAGE; /* too short to hold a header and a tag */
  if (memcmp(c + CC_STORE_OFF_MAGIC, CC_STORE_MAGIC, sizeof(CC_STORE_MAGIC)) !=
      0)
    return CC_STORE_E_DAMAGE; /* not one of ours */
  if (c[CC_STORE_OFF_VERSION] != CC_STORE_VERSION)
    return CC_STORE_E_VERSION;
  /* The algorithm ids are fixed inside a format version: a change that alters
   * how the header is read MUST bump CC_STORE_VERSION, so a container that
   * names an algorithm this build does not know is damaged, not "newer". */
  if (c[CC_STORE_OFF_KDF] != CC_STORE_KDF_PBKDF2_SHA256 ||
      c[CC_STORE_OFF_AEAD] != CC_STORE_AEAD_AES256GCM)
    return CC_STORE_E_DAMAGE;

  iters = get_be32(c + CC_STORE_OFF_ITERS);
  if (iters < CC_STORE_KDF_MIN_ITERS || iters > CC_STORE_KDF_MAX_ITERS)
    return CC_STORE_E_DAMAGE; /* a forged cheap store, or a DoS knob */
  plen = get_be32(c + CC_STORE_OFF_PLEN);
  /* Exact length, with no size_t arithmetic that could wrap: the plaintext
   * length must account for every byte after the header and the tag. This is
   * what rejects a truncated or extended container before a key is derived. */
  if (plen != (uint32_t)(n - CC_STORE_HDR_SZ - CC_STORE_TAG_SZ))
    return CC_STORE_E_DAMAGE;

  if (info != NULL) {
    info->version = CC_STORE_VERSION;
    info->kdf_id = CC_STORE_KDF_PBKDF2_SHA256;
    info->aead_id = CC_STORE_AEAD_AES256GCM;
    info->iterations = iters;
    info->plain_len = plen;
  }
  return CC_STORE_OK;
}

/* Write the header. salt and iterations belong to the STORE (one salt per
 * card, see the header), so they are passed in, not drawn here. */
static void write_header(uint8_t* h, uint32_t iters, const uint8_t* salt,
                         const uint8_t* nonce, uint32_t plain_len) {
  memcpy(h + CC_STORE_OFF_MAGIC, CC_STORE_MAGIC, sizeof(CC_STORE_MAGIC));
  h[CC_STORE_OFF_VERSION] = CC_STORE_VERSION;
  h[CC_STORE_OFF_KDF] = CC_STORE_KDF_PBKDF2_SHA256;
  put_be32(h + CC_STORE_OFF_ITERS, iters);
  memcpy(h + CC_STORE_OFF_SALT, salt, CC_STORE_SALT_SZ);
  h[CC_STORE_OFF_AEAD] = CC_STORE_AEAD_AES256GCM;
  memcpy(h + CC_STORE_OFF_NONCE, nonce, CC_STORE_NONCE_SZ);
  put_be32(h + CC_STORE_OFF_PLEN, plain_len);
}

/* AAD = the header verbatim, then the context string. Both are authenticated,
 * so a moved container, a changed work factor and a forged length all fail the
 * tag check. */
static void build_aad(uint8_t* aad, const uint8_t* hdr, const char* ctx,
                      size_t clen) {
  memcpy(aad, hdr, CC_STORE_HDR_SZ);
  memcpy(aad + CC_STORE_HDR_SZ, ctx, clen);
}

/* master = PBKDF2-HMAC-SHA256(passphrase, salt, iterations). */
static int derive_master(uint8_t* master, const uint8_t* pass, size_t pass_len,
                         const uint8_t* salt, uint32_t iters) {
  if (wc_PBKDF2(master, pass, (int)pass_len, salt, CC_STORE_SALT_SZ, (int)iters,
                CC_STORE_KEY_SZ, WC_HASH_TYPE_SHA256) != 0) {
    wipe(master, CC_STORE_KEY_SZ);
    return CC_STORE_E_CRYPTO;
  }
  return CC_STORE_OK;
}

/* file key = HKDF-SHA256(ikm = master, salt = store salt, info = context). */
static int file_key(const cc_store_key_t* k, const char* ctx, size_t clen,
                    uint8_t* fk) {
  if (wc_HKDF(WC_HASH_TYPE_SHA256, k->master, CC_STORE_KEY_SZ, k->salt,
              CC_STORE_SALT_SZ, (const byte*)ctx, (word32)clen, fk,
              CC_STORE_KEY_SZ) != 0) {
    wipe(fk, CC_STORE_KEY_SZ);
    return CC_STORE_E_CRYPTO;
  }
  return CC_STORE_OK;
}

/* Seal into out, which the caller has already proved large enough. The header
 * is written from the store's salt/work factor and a fresh nonce. */
static int seal_blob(const uint8_t* fk, uint32_t iters, const uint8_t* salt,
                     WC_RNG* rng, const char* ctx, size_t clen,
                     const uint8_t* plain, size_t plain_len, uint8_t* out,
                     size_t* out_len) {
  uint8_t nonce[CC_STORE_NONCE_SZ];
  uint8_t aad[CC_STORE_HDR_SZ + CC_STORE_CTX_MAX];
  Aes aes;
  int ret;

  if (wc_RNG_GenerateBlock(rng, nonce, CC_STORE_NONCE_SZ) != 0)
    return CC_STORE_E_RNG; /* nothing written to out */

  write_header(out, iters, salt, nonce, (uint32_t)plain_len);
  build_aad(aad, out, ctx, clen);

  /* The tag lands in out[plain_len] and travels with the ciphertext. */
  ret = wc_AesGcmSetKey(&aes, fk, CC_STORE_KEY_SZ);
  if (ret == 0)
    ret = wc_AesGcmEncrypt(&aes, out + CC_STORE_OFF_CT, plain,
                           (word32)plain_len, nonce, CC_STORE_NONCE_SZ,
                           out + CC_STORE_OFF_CT + plain_len, CC_STORE_TAG_SZ,
                           aad, (word32)(CC_STORE_HDR_SZ + clen));
  /* The expanded round keys are as sensitive as the key: wipe the struct. */
  wipe(&aes, sizeof(aes));
  if (ret != 0)
    return CC_STORE_E_CRYPTO;
  *out_len = CC_STORE_SEALED_SZ(plain_len);
  return CC_STORE_OK;
}

/* Open a container the caller has already parsed and sized. On any failure the
 * plaintext region is zeroized: GCM writes the plaintext it computes before it
 * decides whether the tag matches, and an unverified plaintext must never be
 * left where a caller could read it. */
static int open_blob(const uint8_t* fk, const uint8_t* container, uint32_t plen,
                     const char* ctx, size_t clen, uint8_t* out) {
  const uint8_t* ct = container + CC_STORE_OFF_CT;
  uint8_t aad[CC_STORE_HDR_SZ + CC_STORE_CTX_MAX];
  Aes aes;
  int ret;

  build_aad(aad, container, ctx, clen);
  ret = wc_AesGcmSetKey(&aes, fk, CC_STORE_KEY_SZ);
  if (ret == 0)
    ret = wc_AesGcmDecrypt(&aes, out, ct, (word32)plen,
                           container + CC_STORE_OFF_NONCE, CC_STORE_NONCE_SZ,
                           ct + plen, CC_STORE_TAG_SZ, aad,
                           (word32)(CC_STORE_HDR_SZ + clen));
  wipe(&aes, sizeof(aes));
  if (ret != 0) {
    wipe(out, plen);
    return (ret == AES_GCM_AUTH_E) ? CC_STORE_E_AUTH : CC_STORE_E_CRYPTO;
  }
  return CC_STORE_OK;
}

/* ---------------------------------------------------------------------------
 * API
 * ------------------------------------------------------------------------- */
int cc_store_probe(const uint8_t* container, size_t container_len,
                   cc_store_info_t* info) {
  return parse(container, container_len, info);
}

void cc_store_lock(cc_store_key_t* k) {
  if (k == NULL)
    return;
  wipe(k->master, CC_STORE_KEY_SZ);
  k->unlocked = 0;
  /* salt and iterations are public header values: no need to wipe them, and
   * leaving them readable lets a status line still report what the store was
   * sealed with. */
}

int cc_store_new_key(cc_store_key_t* k, WC_RNG* rng, uint32_t iterations,
                     const uint8_t* pass, size_t pass_len) {
  int ret;

  if (k == NULL)
    return CC_STORE_E_ARG;
  /* Whatever happens next, this object ends up either holding the NEW key or
   * holding nothing: a caller that ignores an error must not be able to seal
   * with the previous key believing it re-keyed. */
  cc_store_lock(k);
  if (rng == NULL || !pass_ok(pass, pass_len))
    return CC_STORE_E_ARG;
  if (iterations == 0)
    iterations = (uint32_t)CC_STORE_KDF_DEFAULT_ITERS;
  if (iterations < CC_STORE_KDF_MIN_ITERS ||
      iterations > CC_STORE_KDF_MAX_ITERS)
    return CC_STORE_E_ARG;

  if (wc_RNG_GenerateBlock(rng, k->salt, CC_STORE_SALT_SZ) != 0)
    return CC_STORE_E_RNG;
  ret = derive_master(k->master, pass, pass_len, k->salt, iterations);
  if (ret != CC_STORE_OK) {
    cc_store_lock(k);
    return ret;
  }
  k->iterations = iterations;
  k->unlocked = 1;
  return CC_STORE_OK;
}

int cc_store_unlock(cc_store_key_t* k, const char* ctx,
                    const uint8_t* container, size_t container_len,
                    const uint8_t* pass, size_t pass_len, uint8_t* out,
                    size_t out_cap, size_t* out_len) {
  cc_store_info_t info;
  uint8_t fk[CC_STORE_KEY_SZ];
  size_t clen;
  int ret;

  if (k == NULL || container == NULL || out == NULL || out_len == NULL ||
      !pass_ok(pass, pass_len))
    return CC_STORE_E_ARG;
  clen = ctx_len(ctx);
  if (clen == 0)
    return CC_STORE_E_ARG;

  cc_store_lock(k); /* never inherit a previous key, however this returns */

  ret = parse(container, container_len, &info);
  if (ret != CC_STORE_OK)
    return ret;
  if (out_cap < info.plain_len)
    return CC_STORE_E_SIZE;

  memcpy(k->salt, container + CC_STORE_OFF_SALT, CC_STORE_SALT_SZ);
  k->iterations = info.iterations;
  ret = derive_master(k->master, pass, pass_len, k->salt, k->iterations);
  if (ret != CC_STORE_OK) {
    cc_store_lock(k);
    return ret;
  }
  k->unlocked = 1;

  /* Prove the passphrase by opening the container it came with, and hand its
   * plaintext back: one KDF run covers the whole card. A tag failure here is
   * the wrong passphrase (or a damaged file) and MUST leave no key behind. */
  ret = file_key(k, ctx, clen, fk);
  if (ret == CC_STORE_OK)
    ret = open_blob(fk, container, info.plain_len, ctx, clen, out);
  wipe(fk, sizeof(fk));
  if (ret != CC_STORE_OK) {
    cc_store_lock(k);
    return ret;
  }
  *out_len = info.plain_len;
  return CC_STORE_OK;
}

int cc_store_seal(const cc_store_key_t* k, WC_RNG* rng, const char* ctx,
                  const uint8_t* plain, size_t plain_len, uint8_t* out,
                  size_t out_cap, size_t* out_len) {
  uint8_t fk[CC_STORE_KEY_SZ];
  size_t clen;
  int ret;

  if (k == NULL || rng == NULL || out == NULL || out_len == NULL)
    return CC_STORE_E_ARG;
  if (plain == NULL && plain_len > 0)
    return CC_STORE_E_ARG;
  if (plain_len > CC_STORE_PLAIN_MAX)
    return CC_STORE_E_ARG;
  clen = ctx_len(ctx);
  if (clen == 0)
    return CC_STORE_E_ARG;
  if (!k->unlocked)
    return CC_STORE_E_LOCKED;
  if (out_cap < CC_STORE_SEALED_SZ(plain_len))
    return CC_STORE_E_SIZE;

  ret = file_key(k, ctx, clen, fk);
  if (ret == CC_STORE_OK)
    ret = seal_blob(fk, k->iterations, k->salt, rng, ctx, clen, plain,
                    plain_len, out, out_len);
  wipe(fk, sizeof(fk));
  return ret;
}

int cc_store_unseal(const cc_store_key_t* k, const char* ctx,
                    const uint8_t* container, size_t container_len,
                    uint8_t* out, size_t out_cap, size_t* out_len) {
  cc_store_info_t info;
  uint8_t fk[CC_STORE_KEY_SZ];
  size_t clen;
  int ret;

  if (k == NULL || container == NULL || out == NULL || out_len == NULL)
    return CC_STORE_E_ARG;
  clen = ctx_len(ctx);
  if (clen == 0)
    return CC_STORE_E_ARG;
  if (!k->unlocked)
    return CC_STORE_E_LOCKED;

  ret = parse(container, container_len, &info);
  if (ret != CC_STORE_OK)
    return ret;
  if (out_cap < info.plain_len)
    return CC_STORE_E_SIZE;
  /* The salt/work factor in the header must be the ones this key was derived
   * with. A container from another store (or from before a re-key) is not
   * "nearly right": this key does not open it. */
  if (info.iterations != k->iterations ||
      memcmp(container + CC_STORE_OFF_SALT, k->salt, CC_STORE_SALT_SZ) != 0)
    return CC_STORE_E_AUTH;

  ret = file_key(k, ctx, clen, fk);
  if (ret == CC_STORE_OK) {
    ret = open_blob(fk, container, info.plain_len, ctx, clen, out);
    if (ret == CC_STORE_OK)
      *out_len = info.plain_len;
  }
  wipe(fk, sizeof(fk));
  return ret;
}

int cc_store_seal_new(WC_RNG* rng, uint32_t iterations, const uint8_t* pass,
                      size_t pass_len, const char* ctx, const uint8_t* plain,
                      size_t plain_len, uint8_t* out, size_t out_cap,
                      size_t* out_len) {
  cc_store_key_t k;
  int ret;

  /* The key is local: it is wiped on every path out of here, so a one-shot
   * seal leaves no unlocked state behind. */
  memset(&k, 0, sizeof(k));
  ret = cc_store_new_key(&k, rng, iterations, pass, pass_len);
  if (ret == CC_STORE_OK)
    ret = cc_store_seal(&k, rng, ctx, plain, plain_len, out, out_cap, out_len);
  cc_store_lock(&k);
  wipe(&k, sizeof(k));
  return ret;
}

int cc_store_reseal(const uint8_t* container, size_t container_len,
                    const uint8_t* old_pass, size_t old_pass_len,
                    const uint8_t* new_pass, size_t new_pass_len,
                    uint32_t iterations, WC_RNG* rng, const char* ctx,
                    uint8_t* scratch, size_t scratch_cap, uint8_t* out,
                    size_t out_cap, size_t* out_len) {
  cc_store_key_t old_key, new_key;
  cc_store_info_t info;
  size_t clen, plen = 0;
  int ret;

  if (container == NULL || scratch == NULL || out == NULL || out_len == NULL ||
      rng == NULL || !pass_ok(old_pass, old_pass_len) ||
      !pass_ok(new_pass, new_pass_len))
    return CC_STORE_E_ARG;
  clen = ctx_len(ctx);
  if (clen == 0)
    return CC_STORE_E_ARG;

  ret = parse(container, container_len, &info);
  if (ret != CC_STORE_OK)
    return ret;
  if (out_cap < CC_STORE_SEALED_SZ(info.plain_len))
    return CC_STORE_E_SIZE;
  /* scratch is the caller's, because the module has no heap and an
   * identity-sized plaintext (8 KB, expanded form) has no business on an ESP32
   * task stack. It must hold the plaintext this container carries. */
  if (scratch_cap < info.plain_len)
    return CC_STORE_E_SIZE;

  memset(&old_key, 0, sizeof(old_key));
  memset(&new_key, 0, sizeof(new_key));

  /* Open with the passphrase the container was sealed with. */
  ret = cc_store_unlock(&old_key, ctx, container, container_len, old_pass,
                        old_pass_len, scratch, scratch_cap, &plen);
  if (ret == CC_STORE_OK) {
    /* Seal again under a fresh salt and the new passphrase. */
    ret = cc_store_new_key(&new_key, rng, iterations, new_pass, new_pass_len);
    if (ret == CC_STORE_OK)
      ret = cc_store_seal(&new_key, rng, ctx, scratch, plen, out, out_cap,
                          out_len);
  }
  cc_store_lock(&old_key);
  cc_store_lock(&new_key);
  wipe(&old_key, sizeof(old_key));
  wipe(&new_key, sizeof(new_key));
  wipe(scratch,
       plen); /* the plaintext was the caller's to hand over, not to keep */
  return ret;
}
