/* test_store.c — host tests for the Cardputer example's passphrase-encrypted
 * store (examples/cardputer/src/cc_store.c).
 *
 * The module exists as a medium-free buffer API precisely so this can run off
 * the board: no SD card, no Arduino, no hardware. What this suite therefore
 * does NOT cover is on the module header's own list — the card, the keyboard
 * entry and the on-device timing of the KDF.
 *
 * Every case asserts observable behaviour: the code a caller gets and the
 * bytes a caller can see. Nothing here reaches into the implementation. */

#include <stdio.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/random.h>

#include "cc_store.h"
#include "cosechat.h" /* the identity file's size, as main.cpp computes it */

static int g_passed = 0, g_failed = 0;

#define T(name, cond)               \
  do {                              \
    if (cond) {                     \
      printf("  pass: %s\n", name); \
      g_passed++;                   \
    } else {                        \
      printf("  FAIL: %s\n", name); \
      g_failed++;                   \
    }                               \
  } while (0)

/* ---------------------------------------------------------------------------
 * The file sizes main.cpp actually writes, in the terms main.cpp builds them
 * from: a 9-byte CCFS envelope, then a payload version byte, then the keys.
 * Taking them from the library's own size macros means a change of ML-DSA /
 * ML-KEM level moves this test with it instead of leaving a stale number
 * behind. The identity file is the one that matters: it is the secret, and the
 * expanded form is the largest blob the store ever holds.
 * ------------------------------------------------------------------------- */
#define ENV_HDR_SZ 9
#define KEY_FILE_SZ /* the seed form this build writes */ \
  (ENV_HDR_SZ + 1 + CC_SIGN_SEED_SZ + CC_KEM_SEED_SZ + CC_SIGN_PUBKEY_SZ)
#define KEY_FILE_EXP_SZ /* the expanded form it still reads */ \
  (ENV_HDR_SZ + 1 + CC_SIGN_PRIVKEY_SZ + CC_SIGN_PUBKEY_SZ + CC_KEM_PRIVKEY_SZ)

#define PT_SZ KEY_FILE_EXP_SZ             /* biggest plaintext in the test */
#define CONT_SZ CC_STORE_SEALED_SZ(PT_SZ) /* its container, exactly */

/* The suite is single-threaded and this is a host test: static buffers keep
 * the stack small, exactly as the module's callers must on the device. */
static uint8_t pt[PT_SZ];
static uint8_t pt2[PT_SZ];
static uint8_t cont[CONT_SZ];
static uint8_t out[CONT_SZ];
static uint8_t scratch[CONT_SZ];
static uint8_t tamper[CONT_SZ];
static uint8_t small[64];
static WC_RNG rng;

/* Contexts. The two "wrong context" cases are the SAME LENGTH on purpose: the
 * binding must not depend on a length check. */
static const char CTX_KEY[] = "/cc/aaaaa.bin";
static const char CTX_OTHER[] = "/cc/bbbbb.bin";
static const char PASS[] = "correct-horse-battery-staple";
static const char PASS_SAME_LEN[] =
    "correct-horse-battery-staplX"; /* last byte */
static const char PASS_NEW[] = "another-horse-battery-staple";

/* Deterministic fill: reproducible, and never the zero page, so a buffer that
 * the module failed to write cannot pass a comparison by accident. */
static void fill(uint8_t* p, size_t n, uint32_t seed) {
  uint32_t x = seed ? seed : 1u;
  size_t i;
  for (i = 0; i < n; i++) {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    p[i] = (uint8_t)(x >> 24);
  }
}

/* memmem with no portability caveat. */
static const uint8_t* find(const uint8_t* hay, size_t n, const uint8_t* needle,
                           size_t m) {
  size_t i;
  if (m == 0 || n < m)
    return NULL;
  for (i = 0; i + m <= n; i++)
    if (memcmp(hay + i, needle, m) == 0)
      return hay + i;
  return NULL;
}

static int all_zero(const uint8_t* p, size_t n) {
  size_t i;
  for (i = 0; i < n; i++)
    if (p[i] != 0)
      return 0;
  return 1;
}

/* A container the tests tamper with: seal a fresh one with the good passphrase
 * and hand it over. Returns the length, or 0 if the seal failed (the caller's
 * T() cases then fail loudly rather than passing on stale bytes). */
static size_t good_container(size_t plain_len) {
  cc_store_key_t k;
  size_t n = 0;
  memset(&k, 0, sizeof(k));
  if (cc_store_new_key(&k, &rng, 0, (const uint8_t*)PASS, sizeof(PASS) - 1) !=
      CC_STORE_OK) {
    cc_store_lock(&k);
    return 0;
  }
  if (cc_store_seal(&k, &rng, CTX_KEY, pt, plain_len, cont, sizeof(cont), &n) !=
      CC_STORE_OK)
    n = 0;
  cc_store_lock(&k);
  return n;
}

/* ---------------------------------------------------------------------------
 * Sizes and the plaintext-length contract
 * ------------------------------------------------------------------------- */
static void test_sizes(void) {
  cc_store_info_t info;
  size_t n;

  fill(pt, KEY_FILE_SZ, 11);
  n = good_container(KEY_FILE_SZ);

  T("a sealed container is exactly plaintext + overhead",
    n == CC_STORE_SEALED_SZ(KEY_FILE_SZ));
  T("the overhead is the documented 59 bytes",
    CC_STORE_OVERHEAD == 59 && n - KEY_FILE_SZ == 59);
  T("the container parses as this format",
    cc_store_probe(cont, n, &info) == CC_STORE_OK);
  T("the header carries the real identity size",
    info.plain_len == KEY_FILE_SZ && KEY_FILE_SZ == 2090);
  T("the header carries the work factor it was sealed with",
    info.iterations == CC_STORE_KDF_DEFAULT_ITERS);
  T("sealing is deterministic in size", n == good_container(KEY_FILE_SZ));
  printf("  info: identity file %u B, expanded %u B, container %u B\n",
         (unsigned)KEY_FILE_SZ, (unsigned)KEY_FILE_EXP_SZ,
         (unsigned)CC_STORE_SEALED_SZ(KEY_FILE_SZ));
}

/* ---------------------------------------------------------------------------
 * Round trip
 * ------------------------------------------------------------------------- */
static void test_roundtrip(void) {
  cc_store_key_t k;
  size_t n = 0, m = 0;

  memset(&k, 0, sizeof(k));
  fill(pt, 32, 1);
  T("a locked key refuses to seal",
    cc_store_seal(&k, &rng, CTX_KEY, pt, 32, out, sizeof(out), &n) ==
        CC_STORE_E_LOCKED);
  T("a locked key refuses to unseal",
    cc_store_unseal(&k, CTX_KEY, cont, CONT_SZ, out, sizeof(out), &n) ==
        CC_STORE_E_LOCKED);

  T("a new key unlocks", cc_store_new_key(&k, &rng, 0, (const uint8_t*)PASS,
                                          sizeof(PASS) - 1) == CC_STORE_OK);
  T("seal succeeds", cc_store_seal(&k, &rng, CTX_KEY, pt, 32, cont,
                                   sizeof(cont), &n) == CC_STORE_OK);
  T("sealed length is plaintext + 59", n == 32 + 59);
  T("unseal succeeds",
    cc_store_unseal(&k, CTX_KEY, cont, n, out, sizeof(out), &m) == CC_STORE_OK);
  T("the plaintext comes back byte for byte",
    m == 32 && memcmp(out, pt, 32) == 0);
  cc_store_lock(&k);
}

/* A container sealed by one key object opens with the same object, and a key
 * unlocked from ONE container opens the rest of the card: that is the boot
 * flow, and it is the reason the KDF runs once rather than per file. */
static void test_one_unlock_per_card(void) {
  cc_store_key_t k;
  cc_store_info_t ki;
  size_t n = 0, m = 0, c = 0;

  memset(&k, 0, sizeof(k));
  fill(pt, KEY_FILE_SZ, 2);      /* key.bin, the secret */
  fill(pt + KEY_FILE_SZ, 20, 3); /* counter.bin, 20 B file */
  T("identity-size seal succeeds",
    cc_store_seal_new(&rng, 0, (const uint8_t*)PASS, sizeof(PASS) - 1, CTX_KEY,
                      pt, KEY_FILE_SZ, cont, sizeof(cont), &n) == CC_STORE_OK);
  T("unlock proves the passphrase by opening that container",
    cc_store_unlock(&k, CTX_KEY, cont, n, (const uint8_t*)PASS,
                    sizeof(PASS) - 1, out, sizeof(out), &m) == CC_STORE_OK);
  T("unlock hands back the identity bytes",
    m == KEY_FILE_SZ && memcmp(out, pt, KEY_FILE_SZ) == 0);
  T("the unlocked key seals the next file",
    cc_store_seal(&k, &rng, CTX_OTHER, pt + KEY_FILE_SZ, 20, scratch,
                  sizeof(scratch), &c) == CC_STORE_OK);
  T("and opens it again", cc_store_unseal(&k, CTX_OTHER, scratch, c, out,
                                          sizeof(out), &m) == CC_STORE_OK);
  T("with the right bytes", m == 20 && memcmp(out, pt + KEY_FILE_SZ, 20) == 0);
  T("the same key still opens the first container",
    cc_store_unseal(&k, CTX_KEY, cont, n, out, sizeof(out), &m) ==
            CC_STORE_OK &&
        m == KEY_FILE_SZ);
  T("both containers carry one store's parameters",
    cc_store_probe(scratch, c, &ki) == CC_STORE_OK &&
        ki.iterations == CC_STORE_KDF_DEFAULT_ITERS);
  cc_store_lock(&k);

  /* The expanded form is the largest blob the store ever holds: 8394 bytes of
   * plaintext into 8453, statically sized. */
  memset(&k, 0, sizeof(k));
  fill(pt, KEY_FILE_EXP_SZ, 4);
  T("expanded-identity-size seal succeeds",
    cc_store_seal_new(&rng, 0, (const uint8_t*)PASS, sizeof(PASS) - 1, CTX_KEY,
                      pt, KEY_FILE_EXP_SZ, cont, sizeof(cont),
                      &n) == CC_STORE_OK);
  T("expanded-identity-size round trip",
    cc_store_unlock(&k, CTX_KEY, cont, n, (const uint8_t*)PASS,
                    sizeof(PASS) - 1, out, sizeof(out), &m) == CC_STORE_OK &&
        m == KEY_FILE_EXP_SZ && memcmp(out, pt, KEY_FILE_EXP_SZ) == 0);
  cc_store_lock(&k);
}

/* ---------------------------------------------------------------------------
 * Wrong passphrase
 * ------------------------------------------------------------------------- */
static void test_wrong_passphrase(void) {
  cc_store_key_t k;
  size_t n = good_container(KEY_FILE_SZ);
  size_t m = 0;

  memset(&k, 0, sizeof(k));
  memset(out, 0xAA, sizeof(out));
  T("a wrong passphrase is rejected",
    cc_store_unlock(&k, CTX_KEY, cont, n, (const uint8_t*)PASS_SAME_LEN,
                    sizeof(PASS_SAME_LEN) - 1, out, sizeof(out),
                    &m) == CC_STORE_E_AUTH);
  T("the failed unlock leaves no key behind", k.unlocked == 0);
  T("and its master key is wiped", all_zero(k.master, sizeof(k.master)));
  T("no unverified plaintext is left in the caller's buffer",
    all_zero(out, KEY_FILE_SZ));

  T("the right passphrase still works afterwards",
    cc_store_unlock(&k, CTX_KEY, cont, n, (const uint8_t*)PASS,
                    sizeof(PASS) - 1, out, sizeof(out), &m) == CC_STORE_OK &&
        m == KEY_FILE_SZ && memcmp(out, pt, KEY_FILE_SZ) == 0);
  cc_store_lock(&k);
}

/* ---------------------------------------------------------------------------
 * Wrong context
 * ------------------------------------------------------------------------- */
static void test_wrong_context(void) {
  cc_store_key_t k;
  size_t n = good_container(KEY_FILE_SZ);
  size_t m = 0;

  memset(&k, 0, sizeof(k));
  T("a container unlocks under its own file name",
    cc_store_unlock(&k, CTX_KEY, cont, n, (const uint8_t*)PASS,
                    sizeof(PASS) - 1, out, sizeof(out), &m) == CC_STORE_OK);
  T("the same container does not open under another file name",
    cc_store_unseal(&k, CTX_OTHER, cont, n, out, sizeof(out), &m) ==
        CC_STORE_E_AUTH);
  T("and it opens under its own name",
    cc_store_unseal(&k, CTX_KEY, cont, n, out, sizeof(out), &m) ==
            CC_STORE_OK &&
        m == KEY_FILE_SZ && memcmp(out, pt, KEY_FILE_SZ) == 0);
  T("unlocking under the wrong name fails too",
    cc_store_unlock(&k, CTX_OTHER, cont, n, (const uint8_t*)PASS,
                    sizeof(PASS) - 1, out, sizeof(out), &m) == CC_STORE_E_AUTH);
  /* A container sealed under one name does not open under a name of a
   * DIFFERENT length either: the context is authenticated whole, not hashed
   * into a fixed-size slot or reduced to its length. */
  T("a longer foreign file name fails as well",
    cc_store_unlock(&k, "/cc/peers/0123456789abcdef.bin", cont, n,
                    (const uint8_t*)PASS, sizeof(PASS) - 1, out, sizeof(out),
                    &m) == CC_STORE_E_AUTH);
  cc_store_lock(&k);
}

/* ---------------------------------------------------------------------------
 * Tampering: what the key decides vs what the bytes decide
 *
 * A flipped byte in an authenticated field fails the tag -> E_AUTH. A byte
 * that breaks the PUBLIC structure (length, range, algorithm id) is E_DAMAGE,
 * which anyone holding the file could have worked out anyway.
 * ------------------------------------------------------------------------- */
static void test_tamper(void) {
  cc_store_key_t k;
  size_t n = good_container(KEY_FILE_SZ);
  size_t m = 0;

  memset(&k, 0, sizeof(k));
  T("the good container opens",
    cc_store_unlock(&k, CTX_KEY, cont, n, (const uint8_t*)PASS,
                    sizeof(PASS) - 1, out, sizeof(out), &m) == CC_STORE_OK);

  memcpy(tamper, cont, n);
  tamper[CC_STORE_OFF_CT + 3] ^= 0x01;
  T("a flipped ciphertext byte is rejected",
    cc_store_unseal(&k, CTX_KEY, tamper, n, out, sizeof(out), &m) ==
        CC_STORE_E_AUTH);

  memcpy(tamper, cont, n);
  tamper[n - 1] ^= 0x80; /* the GCM tag */
  T("a flipped tag byte is rejected",
    cc_store_unseal(&k, CTX_KEY, tamper, n, out, sizeof(out), &m) ==
        CC_STORE_E_AUTH);

  memcpy(tamper, cont, n);
  tamper[CC_STORE_OFF_NONCE] ^= 0x01;
  T("a flipped nonce is rejected",
    cc_store_unseal(&k, CTX_KEY, tamper, n, out, sizeof(out), &m) ==
        CC_STORE_E_AUTH);

  memcpy(tamper, cont, n);
  tamper[CC_STORE_OFF_SALT] ^= 0x01;
  T("a flipped salt is rejected",
    cc_store_unseal(&k, CTX_KEY, tamper, n, out, sizeof(out), &m) ==
        CC_STORE_E_AUTH);

  memcpy(tamper, cont, n);
  tamper[CC_STORE_OFF_VERSION] = 2;
  T("a newer format version is reported as such",
    cc_store_unseal(&k, CTX_KEY, tamper, n, out, sizeof(out), &m) ==
        CC_STORE_E_VERSION);

  memcpy(tamper, cont, n);
  tamper[CC_STORE_OFF_MAGIC] = 'X';
  T("a broken magic is damage",
    cc_store_probe(tamper, n, NULL) == CC_STORE_E_DAMAGE);

  memcpy(tamper, cont, n);
  tamper[CC_STORE_OFF_KDF] = 2;
  T("an unknown KDF id is damage",
    cc_store_probe(tamper, n, NULL) == CC_STORE_E_DAMAGE);

  memcpy(tamper, cont, n);
  tamper[CC_STORE_OFF_AEAD] = 2;
  T("an unknown AEAD id is damage",
    cc_store_probe(tamper, n, NULL) == CC_STORE_E_DAMAGE);

  /* A forged length: the length rule is exact, so a container that claims more
   * plaintext than it carries is damage, not a wrong passphrase. */
  memcpy(tamper, cont, n);
  tamper[CC_STORE_OFF_PLEN + 3] += 1;
  T("a forged plaintext length is damage",
    cc_store_unseal(&k, CTX_KEY, tamper, n, out, sizeof(out), &m) ==
        CC_STORE_E_DAMAGE);

  /* A forged work factor: inside the accepted range it changes the key, so it
   * cannot decrypt what it claims to have sealed; below the floor it is
   * refused outright, so nobody can hand this node a cheap store. */
  memcpy(tamper, cont, n);
  tamper[CC_STORE_OFF_ITERS] = 0;
  tamper[CC_STORE_OFF_ITERS + 1] = 0;
  tamper[CC_STORE_OFF_ITERS + 2] = 0x01;
  tamper[CC_STORE_OFF_ITERS + 3] = 0xF4; /* 500 */
  T("a work factor below the floor is damage",
    cc_store_unseal(&k, CTX_KEY, tamper, n, out, sizeof(out), &m) ==
        CC_STORE_E_DAMAGE);

  memcpy(tamper, cont, n);
  tamper[CC_STORE_OFF_ITERS + 2] = 0x42;
  T("a forged work factor inside the range cannot decrypt",
    cc_store_unseal(&k, CTX_KEY, tamper, n, out, sizeof(out), &m) ==
        CC_STORE_E_AUTH);

  /* And the honest container still opens: none of the above damaged it. */
  T("the untampered container still opens",
    cc_store_unseal(&k, CTX_KEY, cont, n, out, sizeof(out), &m) ==
            CC_STORE_OK &&
        m == KEY_FILE_SZ);
  cc_store_lock(&k);
}

/* ---------------------------------------------------------------------------
 * Truncated, extended, and not-a-container
 * ------------------------------------------------------------------------- */
static void test_lengths(void) {
  cc_store_key_t k;
  size_t n = good_container(KEY_FILE_SZ);
  size_t m = 0;
  uint8_t legacy[KEY_FILE_SZ];

  memset(&k, 0, sizeof(k));
  T("unlocked for the length cases",
    cc_store_unlock(&k, CTX_KEY, cont, n, (const uint8_t*)PASS,
                    sizeof(PASS) - 1, out, sizeof(out), &m) == CC_STORE_OK);

  T("a truncated container is damage",
    cc_store_unseal(&k, CTX_KEY, cont, n - 1, out, sizeof(out), &m) ==
        CC_STORE_E_DAMAGE);
  T("a container cut before its tag is damage",
    cc_store_unseal(&k, CTX_KEY, cont, n - CC_STORE_TAG_SZ, out, sizeof(out),
                    &m) == CC_STORE_E_DAMAGE);
  T("a container cut before its ciphertext is damage",
    cc_store_unseal(&k, CTX_KEY, cont, CC_STORE_HDR_SZ, out, sizeof(out), &m) ==
        CC_STORE_E_DAMAGE);
  T("an extended container is damage",
    cc_store_unseal(&k, CTX_KEY, cont, n + 1, out, sizeof(out), &m) ==
        CC_STORE_E_DAMAGE);
  T("a three-byte file is damage",
    cc_store_unseal(&k, CTX_KEY, cont, 3, out, sizeof(out), &m) ==
        CC_STORE_E_DAMAGE);
  T("an empty buffer is damage",
    cc_store_unseal(&k, CTX_KEY, cont, 0, out, sizeof(out), &m) ==
        CC_STORE_E_DAMAGE);
  T("no container at all is an argument error",
    cc_store_unseal(&k, CTX_KEY, NULL, n, out, sizeof(out), &m) ==
        CC_STORE_E_ARG);

  /* A card written by the firmware before this module existed: the plaintext
   * CCFS-envelope file. The app must be able to tell that apart from a wrong
   * passphrase, and it can: the magic check is public. */
  memcpy(legacy, "CCFS", 4);
  legacy[4] = 1;
  fill(legacy + 9, sizeof(legacy) - 9, 5);
  T("a legacy plaintext file is damage, not a bad passphrase",
    cc_store_probe(legacy, sizeof(legacy), NULL) == CC_STORE_E_DAMAGE);
  T("and unlocking it says the same",
    cc_store_unlock(&k, CTX_KEY, legacy, sizeof(legacy), (const uint8_t*)PASS,
                    sizeof(PASS) - 1, out, sizeof(out),
                    &m) == CC_STORE_E_DAMAGE);
  cc_store_lock(&k);
}

/* ---------------------------------------------------------------------------
 * Caller buffers
 * ------------------------------------------------------------------------- */
static void test_buffers(void) {
  cc_store_key_t k;
  size_t n = good_container(KEY_FILE_SZ);
  size_t m = 0;
  uint8_t before[64];

  memset(&k, 0, sizeof(k));
  T("unlocked for the buffer cases",
    cc_store_unlock(&k, CTX_KEY, cont, n, (const uint8_t*)PASS,
                    sizeof(PASS) - 1, out, sizeof(out), &m) == CC_STORE_OK);

  memset(out, 0x5A, sizeof(out));
  memcpy(before, out, sizeof(before));
  T("an undersized output buffer is refused",
    cc_store_unseal(&k, CTX_KEY, cont, n, out, KEY_FILE_SZ - 1, &m) ==
        CC_STORE_E_SIZE);
  T("and nothing was written to it", memcmp(before, out, sizeof(before)) == 0);

  memset(out, 0x5A, sizeof(out));
  fill(pt2, KEY_FILE_SZ, 6);
  T("an undersized output buffer is refused by seal too",
    cc_store_seal(&k, &rng, CTX_KEY, pt2, KEY_FILE_SZ, out,
                  CC_STORE_SEALED_SZ(KEY_FILE_SZ) - 1, &m) == CC_STORE_E_SIZE);
  T("and nothing was written to it",
    out[0] == 0x5A && out[sizeof(out) - 1] == 0x5A);

  T("an exactly-sized output buffer is accepted",
    cc_store_unseal(&k, CTX_KEY, cont, n, out, KEY_FILE_SZ, &m) ==
            CC_STORE_OK &&
        m == KEY_FILE_SZ);
  T("an exactly-sized container buffer is accepted",
    cc_store_seal(&k, &rng, CTX_KEY, pt2, KEY_FILE_SZ, cont,
                  CC_STORE_SEALED_SZ(KEY_FILE_SZ), &m) == CC_STORE_OK &&
        m == CC_STORE_SEALED_SZ(KEY_FILE_SZ));
  cc_store_lock(&k);
}

/* ---------------------------------------------------------------------------
 * Arguments, and what zero or out-of-range values mean
 * ------------------------------------------------------------------------- */
static void test_args(void) {
  cc_store_key_t k;
  char longctx[CC_STORE_CTX_MAX + 2];
  size_t m = 0, i;

  memset(&k, 0, sizeof(k));
  for (i = 0; i < CC_STORE_CTX_MAX + 1; i++) longctx[i] = 'a';
  longctx[CC_STORE_CTX_MAX + 1] = '\0';

  T("a NULL context is an argument error",
    cc_store_new_key(&k, &rng, 0, (const uint8_t*)PASS, sizeof(PASS) - 1) ==
            CC_STORE_OK &&
        cc_store_seal(&k, &rng, NULL, pt, 32, out, sizeof(out), &m) ==
            CC_STORE_E_ARG);
  T("an empty context is an argument error",
    cc_store_seal(&k, &rng, "", pt, 32, out, sizeof(out), &m) ==
        CC_STORE_E_ARG);
  T("an over-long context is an argument error",
    cc_store_seal(&k, &rng, longctx, pt, 32, out, sizeof(out), &m) ==
        CC_STORE_E_ARG);
  T("a short context is fine",
    cc_store_seal(&k, &rng, "k", pt, 32, out, sizeof(out), &m) == CC_STORE_OK);
  T("a NULL plaintext with a length is an argument error",
    cc_store_seal(&k, &rng, CTX_KEY, NULL, 32, out, sizeof(out), &m) ==
        CC_STORE_E_ARG);
  T("a NULL output is an argument error",
    cc_store_seal(&k, &rng, CTX_KEY, pt, 32, NULL, sizeof(out), &m) ==
        CC_STORE_E_ARG);
  T("a NULL key is an argument error",
    cc_store_seal(NULL, &rng, CTX_KEY, pt, 32, out, sizeof(out), &m) ==
        CC_STORE_E_ARG);
  T("an empty passphrase is an argument error",
    cc_store_new_key(&k, &rng, 0, (const uint8_t*)PASS, 0) == CC_STORE_E_ARG);
  T("an over-long passphrase is an argument error",
    cc_store_new_key(&k, &rng, 0, (const uint8_t*)PASS,
                     CC_STORE_PASS_MAX + 1) == CC_STORE_E_ARG);
  T("a NULL passphrase is an argument error",
    cc_store_new_key(&k, &rng, 0, NULL, 8) == CC_STORE_E_ARG);
  T("a work factor below the floor is an argument error",
    cc_store_new_key(&k, &rng, CC_STORE_KDF_MIN_ITERS - 1, (const uint8_t*)PASS,
                     sizeof(PASS) - 1) == CC_STORE_E_ARG);
  T("a work factor above the ceiling is an argument error",
    cc_store_new_key(&k, &rng, CC_STORE_KDF_MAX_ITERS + 1, (const uint8_t*)PASS,
                     sizeof(PASS) - 1) == CC_STORE_E_ARG);
  T("a failed new_key left the key locked", k.unlocked == 0);
  T("a probe may omit the info struct",
    cc_store_probe(out, m, NULL) == CC_STORE_OK);
  T("a NULL probe buffer is an argument error",
    cc_store_probe(NULL, m, NULL) == CC_STORE_E_ARG);
  cc_store_lock(&k);
}

/* ---------------------------------------------------------------------------
 * Locking and wiping
 * ------------------------------------------------------------------------- */
static void test_lock(void) {
  cc_store_key_t k;
  size_t n = good_container(KEY_FILE_SZ);
  size_t m = 0;

  memset(&k, 0, sizeof(k));
  T("unlock for the lock cases",
    cc_store_unlock(&k, CTX_KEY, cont, n, (const uint8_t*)PASS,
                    sizeof(PASS) - 1, out, sizeof(out), &m) == CC_STORE_OK);
  T("the key is unlocked before the lock", k.unlocked == 1);
  cc_store_lock(&k);
  T("lock marks the key locked", k.unlocked == 0);
  T("lock zeroizes the master key", all_zero(k.master, sizeof(k.master)));
  T("a locked key cannot seal",
    cc_store_seal(&k, &rng, CTX_KEY, pt, 32, out, sizeof(out), &m) ==
        CC_STORE_E_LOCKED);
  T("a locked key cannot unseal",
    cc_store_unseal(&k, CTX_KEY, cont, n, out, sizeof(out), &m) ==
        CC_STORE_E_LOCKED);
  cc_store_lock(NULL); /* documented as safe */
  T("unlocking again after a lock works",
    cc_store_unlock(&k, CTX_KEY, cont, n, (const uint8_t*)PASS,
                    sizeof(PASS) - 1, out, sizeof(out), &m) == CC_STORE_OK);
  cc_store_lock(&k);
}

/* ---------------------------------------------------------------------------
 * Re-encrypt under a new passphrase
 * ------------------------------------------------------------------------- */
static void test_reseal(void) {
  cc_store_key_t k;
  cc_store_info_t info;
  size_t n = good_container(KEY_FILE_SZ);
  size_t r = 0, m = 0;
  uint8_t before[64];

  memset(&k, 0, sizeof(k));
  fill(pt2, KEY_FILE_SZ, 7);
  memset(out, 0x33, sizeof(out));
  memcpy(before, out, sizeof(before));
  T("a wrong old passphrase cannot re-encrypt",
    cc_store_reseal(cont, n, (const uint8_t*)PASS_SAME_LEN,
                    sizeof(PASS_SAME_LEN) - 1, (const uint8_t*)PASS_NEW,
                    sizeof(PASS_NEW) - 1, 0, &rng, CTX_KEY, scratch,
                    sizeof(scratch), out, sizeof(out), &r) == CC_STORE_E_AUTH);
  T("and it wrote nothing to the caller's output",
    memcmp(before, out, sizeof(before)) == 0);

  T("re-encrypt under a new passphrase succeeds",
    cc_store_reseal(cont, n, (const uint8_t*)PASS, sizeof(PASS) - 1,
                    (const uint8_t*)PASS_NEW, sizeof(PASS_NEW) - 1, 0, &rng,
                    CTX_KEY, scratch, sizeof(scratch), out, sizeof(out),
                    &r) == CC_STORE_OK);
  T("the new container is the same size", r == n);
  T("and carries a fresh salt (the bytes differ)", memcmp(cont, out, n) != 0);
  T("the old passphrase no longer opens it",
    cc_store_unlock(&k, CTX_KEY, out, r, (const uint8_t*)PASS, sizeof(PASS) - 1,
                    scratch, sizeof(scratch), &m) == CC_STORE_E_AUTH);
  T("the new passphrase does",
    cc_store_unlock(&k, CTX_KEY, out, r, (const uint8_t*)PASS_NEW,
                    sizeof(PASS_NEW) - 1, scratch, sizeof(scratch),
                    &m) == CC_STORE_OK);
  T("and the plaintext survived the re-encryption",
    m == KEY_FILE_SZ && memcmp(scratch, pt, KEY_FILE_SZ) == 0);
  T("the re-encrypted container still reports its work factor",
    cc_store_probe(out, r, &info) == CC_STORE_OK &&
        info.iterations == CC_STORE_KDF_DEFAULT_ITERS);
  cc_store_lock(&k);

  /* An explicit work factor at re-encryption time is honoured: this is what
   * lets a node raise the cost when a passphrase is changed. */
  T("re-encrypt at a chosen work factor",
    cc_store_reseal(cont, n, (const uint8_t*)PASS, sizeof(PASS) - 1,
                    (const uint8_t*)PASS_NEW, sizeof(PASS_NEW) - 1, 20000, &rng,
                    CTX_KEY, scratch, sizeof(scratch), out, sizeof(out),
                    &r) == CC_STORE_OK);
  T("the container carries the chosen work factor",
    cc_store_probe(out, r, &info) == CC_STORE_OK && info.iterations == 20000);
  memset(&k, 0, sizeof(k));
  T("a container sealed at 20000 iterations still opens",
    cc_store_unlock(&k, CTX_KEY, out, r, (const uint8_t*)PASS_NEW,
                    sizeof(PASS_NEW) - 1, scratch, sizeof(scratch),
                    &m) == CC_STORE_OK &&
        m == KEY_FILE_SZ && memcmp(scratch, pt, KEY_FILE_SZ) == 0);
  cc_store_lock(&k);

  /* The same knob on a first seal, including the "0 means the default" rule. */
  T("a first seal at an explicit work factor",
    cc_store_seal_new(&rng, CC_STORE_KDF_MIN_ITERS, (const uint8_t*)PASS,
                      sizeof(PASS) - 1, CTX_KEY, pt, KEY_FILE_SZ, out,
                      sizeof(out), &r) == CC_STORE_OK &&
        cc_store_probe(out, r, &info) == CC_STORE_OK &&
        info.iterations == CC_STORE_KDF_MIN_ITERS);
  T("a first seal with 0 uses the default",
    cc_store_seal_new(&rng, 0, (const uint8_t*)PASS, sizeof(PASS) - 1, CTX_KEY,
                      pt, KEY_FILE_SZ, out, sizeof(out), &r) == CC_STORE_OK &&
        cc_store_probe(out, r, &info) == CC_STORE_OK &&
        info.iterations == CC_STORE_KDF_DEFAULT_ITERS);
}

/* ---------------------------------------------------------------------------
 * Nothing secret in the container
 * ------------------------------------------------------------------------- */
static void test_no_plaintext_leak(void) {
  static const uint8_t MARKER[80] =
      "SENTINEL: no plaintext byte of this blob "
      "may appear in the container bytes!";
  size_t n, m, off;
  size_t windows = 0;
  const uint8_t* at;

  /* A small blob first, so every 16-byte window of the plaintext can be
   * scanned for: the strongest form of the check at a cost the suite can
   * afford. */
  memcpy(pt, MARKER, sizeof(MARKER));
  fill(pt + sizeof(MARKER), 192, 8);
  n = good_container(256);
  T("the small blob sealed", n == CC_STORE_SEALED_SZ(256));

  at = find(cont, n, MARKER, sizeof(MARKER));
  T("the plaintext marker is not in the container", at == NULL);
  at = find(cont, n, pt, 256);
  T("the whole plaintext is not in the container", at == NULL);
  at = find(cont, n, (const uint8_t*)PASS, sizeof(PASS) - 1);
  T("the passphrase is not in the container", at == NULL);
  for (off = 0; off + 16 <= 256; off += 16) {
    if (find(cont, n, pt + off, 16) != NULL)
      windows++;
  }
  T("no 16-byte window of the plaintext is in the container", windows == 0);

  /* And an identity-sized blob, the one that matters. */
  memcpy(pt, MARKER, sizeof(MARKER));
  fill(pt + sizeof(MARKER), KEY_FILE_SZ - sizeof(MARKER), 9);
  n = good_container(KEY_FILE_SZ);
  T("the identity-size blob sealed", n == CC_STORE_SEALED_SZ(KEY_FILE_SZ));
  T("its marker is not in the container",
    find(cont, n, MARKER, sizeof(MARKER)) == NULL);
  T("its whole plaintext is not in the container",
    find(cont, n, pt, KEY_FILE_SZ) == NULL);
  {
    cc_store_key_t k;
    memset(&k, 0, sizeof(k));
    T("the key opens it, so the container is a real seal",
      cc_store_unlock(&k, CTX_KEY, cont, n, (const uint8_t*)PASS,
                      sizeof(PASS) - 1, scratch, sizeof(scratch),
                      &m) == CC_STORE_OK &&
          m == KEY_FILE_SZ);
    T("the derived master key is not in the container",
      find(cont, n, k.master, sizeof(k.master)) == NULL);
    cc_store_lock(&k);
  }
}

int main(void) {
  if (wc_InitRng(&rng) != 0) {
    printf("  FAIL: RNG init\n");
    printf("\n0 passed, 1 failed\n");
    return 1;
  }

  test_sizes();
  test_roundtrip();
  test_one_unlock_per_card();
  test_wrong_passphrase();
  test_wrong_context();
  test_tamper();
  test_lengths();
  test_buffers();
  test_args();
  test_lock();
  test_reseal();
  test_no_plaintext_leak();

  wc_FreeRng(&rng);
  printf("\n%d passed, %d failed\n", g_passed, g_failed);
  return g_failed == 0 ? 0 : 1;
}
