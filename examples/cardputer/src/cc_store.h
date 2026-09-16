/* cc_store.h — passphrase-encrypted store for the Cardputer node's SD files.
 *
 * This is APPLICATION policy, not part of the cosechat library: the library
 * stays storage-agnostic and knows nothing about it. The module is here, next
 * to main.cpp, so the sketch builds it and the host test can too.
 *
 * NO MEDIUM. Every call takes and returns byte buffers. There is no SD.h, no
 * Arduino, no file path and no file I/O in this module: the sketch reads and
 * writes the files and hands the bytes over. That split is what makes the
 * crypto testable off-hardware, and it is deliberate.
 *
 * NO HEAP. All sizes are compile-time constants and every buffer is the
 * caller's. The module itself never allocates; the only state it keeps is the
 * unlocked key the caller holds (see cc_store_key_t).
 *
 * NO RECOVERY, BY DESIGN. The key comes from the passphrase and the salt and
 * from nothing else. There is no recovery phrase, no escrow, no hint, no
 * second path, and no key derived from the hardware. Forget the passphrase and
 * the files are unrecoverable: the only way back is to wipe the card and mint
 * a new identity. Nothing in this API may be extended to change that.
 *
 * ---------------------------------------------------------------------------
 * CONTAINER LAYOUT (format version 1)
 * ---------------------------------------------------------------------------
 * One flat little-endian-free (big-endian field) image; the sketch writes the
 * whole thing to one file:
 *
 *   off  size  field              notes
 *   ---  ----  -----------------  -------------------------------------------
 *   0    4     magic = "CCSP"     identifies the container, not the file kind
 *   4    1     format version = 1
 *   5    1     kdf id = 1         PBKDF2-HMAC-SHA256
 *   6    4     kdf iterations     work factor, big-endian uint32
 *   10   16    salt               RNG, per store (not per file: see below)
 *   26   1     aead id = 1        AES-256-GCM
 *   27   12    nonce              RNG, fresh for every seal, never reused
 *   39   4     plaintext length   big-endian uint32, authenticated
 *   43   N     ciphertext         N = plaintext length
 *   43+N 16    tag                GCM tag
 *
 *   header = 43 bytes, tag = 16 bytes, so N bytes of plaintext become exactly
 *   N + 59 bytes on disk: CC_STORE_OVERHEAD, a compile-time constant, so the
 *   sketch can size every buffer statically. The exact-length rule is part of
 *   the format: a container MUST be exactly header + plaintext + tag bytes, so
 *   a truncated or extended file is rejected before any crypto runs.
 *
 * The header is authenticated as AEAD associated data, together with a
 * caller-supplied CONTEXT string (the logical file name, e.g. "/cc/key.bin").
 * AAD = header (43 bytes) || context (0..CC_STORE_CTX_MAX bytes). That is what
 * stops a container being moved between file names, downgraded to an older
 * work factor, or given a forged length: all of those change the AAD, so the
 * tag check fails. The per-file key is context-bound too (see the KDF note),
 * so a moved container does not merely fail to authenticate, it decrypts under
 * the wrong key.
 *
 * The context is the path and NOT the node's address: the address changes when
 * the identity is rotated or revoked, and a container sealed under the old
 * address would then be unreadable by the node that legitimately owns it. The
 * path alone is the binding the requirement asks for.
 *
 * ---------------------------------------------------------------------------
 * KDF / AEAD CHOICES
 * ---------------------------------------------------------------------------
 * PBKDF2-HMAC-SHA256, 16-byte RNG salt, 32-byte output, work factor carried in
 * the container header so an old store stays readable if the knob changes.
 * wc_PBKDF2 is compiled out of the firmware build by NO_PWDBASED, which this
 * module needs removed (see user_settings.h); the host build has it.
 *
 * The unlocked key holds the PBKDF2 output (the master key). Each container is
 * sealed under a per-file key derived from it:
 *
 *   master (32 B) = PBKDF2-SHA256(passphrase, salt, iterations)
 *   file key (32 B) = HKDF-SHA256(ikm = master, salt = salt, info = context)
 *
 * One KDF run per unlock, not one per file: counter.bin is rewritten every few
 * seconds, so deriving per file would put a PBKDF2 in the write path. HKDF is
 * a few microseconds; PBKDF2 is not.
 *
 * AES-256-GCM: 12-byte RNG nonce, 16-byte tag, nonce fresh for every seal and
 * never reused under a key (random 96-bit nonces; a store is written a bounded
 * number of times in a device's life, nowhere near the 2^32 birthday bound).
 * The GCM tag is what makes the header, the context and the ciphertext
 * tamper-evident.
 *
 * ONE SALT PER CARD. cc_store_seal() writes the salt the unlocked key was
 * derived with, so every container on a card shares one salt in the steady
 * state: that is what lets one unlock serve every file, and what makes a
 * container whose salt differs a clear "this key does not open it" (E_AUTH)
 * rather than a silent decryption under some other key.
 *
 * ---------------------------------------------------------------------------
 * FAILURE TAXONOMY — WHAT IT DISTINGUISHES, AND TO WHOM
 * ---------------------------------------------------------------------------
 * CC_STORE_E_DAMAGE is decided by PUBLIC STRUCTURE alone: not a container,
 * unparsable header, a length that is not exactly header + plaintext + tag (so
 * truncated and extended files land here), a work factor outside the accepted
 * range, or an unknown algorithm id. Anyone holding the bytes can classify
 * them the same way, so returning it reveals nothing that was not already
 * visible in the file.
 *
 * CC_STORE_E_AUTH is decided by the KEY: the AEAD tag did not verify. Wrong
 * passphrase, wrong context, or a bit flipped inside the header/salt/nonce/
 * ciphertext/tag all return this one code, and they are INDISTINGUISHABLE BY
 * CONSTRUCTION — a tag is one bit, and nothing can tell "wrong key" from
 * "right key, wrong ciphertext" without the key. Do not build a UI that claims
 * to know the difference; "wrong passphrase or damaged file" is the truth.
 *
 * CC_STORE_E_VERSION is reported separately (magic present, format version not
 * understood) so a firmware upgrade can say "this store is newer than I am".
 * That, plus E_DAMAGE, is the whole public side of the taxonomy.
 */

#ifndef CC_STORE_H
#define CC_STORE_H

#include <stddef.h>
#include <stdint.h>

/* The API hands out a caller-owned WC_RNG, so this header needs a wolfCrypt
 * type, and that means the build's configuration has to be picked BEFORE any
 * wolfSSL header is read — the same guard the library's own sources use, in
 * the only place that can guarantee the order. The firmware defines
 * WOLFSSL_USER_SETTINGS (platformio.ini) and gets user_settings.h instead. */
#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/random.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Format constants
 * ------------------------------------------------------------------------- */
#define CC_STORE_VERSION 1
#define CC_STORE_KDF_PBKDF2_SHA256 1
#define CC_STORE_AEAD_AES256GCM 1

#define CC_STORE_SALT_SZ 16
#define CC_STORE_NONCE_SZ 12
#define CC_STORE_KEY_SZ 32
#define CC_STORE_TAG_SZ 16

/* Offsets of the header fields, from the layout table above. Written as
 * additions so the table and the code cannot drift apart. */
#define CC_STORE_OFF_MAGIC 0
#define CC_STORE_OFF_VERSION (CC_STORE_OFF_MAGIC + 4)              /* 4 */
#define CC_STORE_OFF_KDF (CC_STORE_OFF_VERSION + 1)                /* 5 */
#define CC_STORE_OFF_ITERS (CC_STORE_OFF_KDF + 1)                  /* 6 */
#define CC_STORE_OFF_SALT (CC_STORE_OFF_ITERS + 4)                 /* 10 */
#define CC_STORE_OFF_AEAD (CC_STORE_OFF_SALT + CC_STORE_SALT_SZ)   /* 26 */
#define CC_STORE_OFF_NONCE (CC_STORE_OFF_AEAD + 1)                 /* 27 */
#define CC_STORE_OFF_PLEN (CC_STORE_OFF_NONCE + CC_STORE_NONCE_SZ) /* 39 */
#define CC_STORE_HDR_SZ (CC_STORE_OFF_PLEN + 4)                    /* 43 */
#define CC_STORE_OFF_CT CC_STORE_HDR_SZ                            /* 43 */
/* The tag is the last CC_STORE_TAG_SZ bytes, so its offset depends on the
 * plaintext length: use container_len - CC_STORE_TAG_SZ, never a constant. */
#define CC_STORE_OVERHEAD (CC_STORE_HDR_SZ + CC_STORE_TAG_SZ) /* 59 */

/* Bytes on disk for a plaintext of n bytes. The sketch sizes its output
 * buffers with this; it is exact, not an estimate. The caller must keep n
 * small enough that the sum cannot wrap (CC_STORE_PLAIN_MAX is the limit the
 * seal path enforces). */
#define CC_STORE_SEALED_SZ(n) ((n) + CC_STORE_OVERHEAD)

/* Work factor. 0 passed to a creating call means CC_STORE_KDF_DEFAULT_ITERS.
 * The accepted range is enforced on read too: a container claiming a count
 * outside it is damage, so an attacker cannot forge a cheap store, and a
 * store written with a high count cannot become a denial of service. Raise
 * CC_STORE_KDF_MAX_ITERS deliberately if the default ever passes it. */
#define CC_STORE_KDF_DEFAULT_ITERS 100000UL
#define CC_STORE_KDF_MIN_ITERS 10000UL
#define CC_STORE_KDF_MAX_ITERS 2000000UL

/* Longest context string (logical file name) accepted. The real paths are
 * "/cc/key.bin" (11), "/cc/counter.bin" (15), "/cc/revoked.bin" (15) and
 * "/cc/peers/<32 hex>.bin|.rp" (46), so 64 leaves room for a peer directory
 * per identity without ever truncating one. */
#define CC_STORE_CTX_MAX 64

/* Passphrase bounds. Zero length is refused: an "empty passphrase" is exactly
 * the property this module exists to remove, and a caller that has no
 * passphrase has a bug, not a policy. The module never copies the passphrase,
 * so nothing of it is left in the module's stack frames. */
#define CC_STORE_PASS_MAX 128

/* Largest plaintext a container can describe (the length is a uint32). */
#define CC_STORE_PLAIN_MAX (0xFFFFFFFFUL - CC_STORE_OVERHEAD)

/* ---------------------------------------------------------------------------
 * Result codes. What separates them, in one place (the taxonomy above has the
 * reasoning):
 *
 *   CC_STORE_E_ARG      a caller bug or caller policy: NULL pointer, an empty
 *                       or over-long passphrase, a context that is missing or
 *                       longer than CC_STORE_CTX_MAX, a work factor out of
 *                       range, a plaintext larger than CC_STORE_PLAIN_MAX
 *   CC_STORE_E_AUTH     the AEAD tag did not verify: wrong passphrase, wrong
 *                       context, or a flipped byte in an authenticated field
 *   CC_STORE_E_DAMAGE   the public structure is wrong: not a container, an
 *                       unparsable header, a length that is not exactly
 *                       header + plaintext + tag, an unknown algorithm id, or
 *                       a work factor outside the accepted range
 *   CC_STORE_E_SIZE     a caller buffer is too small; nothing was written
 *   CC_STORE_E_RNG      the RNG failed; nothing was sealed
 *   CC_STORE_E_CRYPTO   a wolfCrypt call failed for a reason that is not
 *                       authentication
 *   CC_STORE_E_VERSION  a container whose format version this build does not
 *                       know
 *   CC_STORE_E_LOCKED   the key is not unlocked (locked or wiped)
 * ------------------------------------------------------------------------- */
#define CC_STORE_OK 0
#define CC_STORE_E_ARG (-1)
#define CC_STORE_E_AUTH (-2)
#define CC_STORE_E_DAMAGE (-3)
#define CC_STORE_E_SIZE (-4)
#define CC_STORE_E_RNG (-5)
#define CC_STORE_E_CRYPTO (-6)
#define CC_STORE_E_VERSION (-7)
#define CC_STORE_E_LOCKED (-8)

/* ---------------------------------------------------------------------------
 * Parameters, as read back from a container (never secret: this is the header)
 * ------------------------------------------------------------------------- */
typedef struct {
  uint8_t version;
  uint8_t kdf_id;
  uint8_t aead_id;
  uint32_t iterations;
  uint32_t plain_len; /* the length the container authenticates */
} cc_store_info_t;

/* ---------------------------------------------------------------------------
 * The unlocked key: the only state the caller holds, and it is wipeable
 * ------------------------------------------------------------------------- */
typedef struct {
  uint8_t master[CC_STORE_KEY_SZ]; /* PBKDF2 output; secret, wc_ForceZero'd */
  uint8_t salt[CC_STORE_SALT_SZ];  /* public: the salt of this store */
  uint32_t iterations;             /* public: this store's work factor */
  uint8_t unlocked;                /* 1 between unlock and lock */
} cc_store_key_t;

/* ---------------------------------------------------------------------------
 * API
 * ------------------------------------------------------------------------- */

/* Derive a fresh store key from a passphrase (a card with no sealed store
 * yet, or a fresh passphrase for one being re-keyed): draws a new 16-byte salt
 * and derives the master key. iterations == 0 means
 * CC_STORE_KDF_DEFAULT_ITERS. On success *k is unlocked and ready to seal; on
 * ANY failure *k is left locked, so a caller that ignores the error cannot go
 * on sealing with a previous key believing it re-keyed. There is no way for
 * this call to fail "open": it returns the key the caller asked for, or it
 * returns a code and no key. */
int cc_store_new_key(cc_store_key_t* k, WC_RNG* rng, uint32_t iterations,
                     const uint8_t* pass, size_t pass_len);

/* Unlock a store with a passphrase, proving the passphrase is right by
 * decrypting one container with it (normally the identity file), and hand back
 * that container's plaintext. This is the boot call: one passphrase, one KDF
 * run, then cc_store_unseal() for the rest of the card.
 *
 * k must start locked. On ANY failure *k is left locked, so a wrong passphrase
 * cannot leave a wrong key behind for a later seal to use. A wrong passphrase
 * and a damaged-but-parsable container are both CC_STORE_E_AUTH; a container
 * whose salt or work factor is not the one the derived key came from is
 * CC_STORE_E_AUTH too (that key does not open it). */
int cc_store_unlock(cc_store_key_t* k, const char* ctx,
                    const uint8_t* container, size_t container_len,
                    const uint8_t* pass, size_t pass_len, uint8_t* out,
                    size_t out_cap, size_t* out_len);

/* Forget the key: the master key is zeroized with wc_ForceZero and the object
 * is marked locked. The salt and work factor are public header values and are
 * left readable, so a status line can still report what the store was sealed
 * with. Safe on an already-locked key and on NULL. After this call, seal and
 * unseal return CC_STORE_E_LOCKED until the next unlock. */
void cc_store_lock(cc_store_key_t* k);

/* Seal one plaintext under the unlocked key. The container carries the key's
 * salt and work factor, a fresh nonce, and the plaintext length; out receives
 * exactly CC_STORE_SEALED_SZ(plain_len) bytes and nothing else is touched
 * (*out_len is written only on success). out must not overlap plain. */
int cc_store_seal(const cc_store_key_t* k, WC_RNG* rng, const char* ctx,
                  const uint8_t* plain, size_t plain_len, uint8_t* out,
                  size_t out_cap, size_t* out_len);

/* Open one container under the unlocked key with the context it was sealed
 * with. The container must be exactly CC_STORE_SEALED_SZ(info.plain_len)
 * bytes, and its salt and work factor must be the ones this key was derived
 * with: a container from another store, or from before a re-key, is
 * CC_STORE_E_AUTH — this key does not open it, and there is no halfway
 * result. On CC_STORE_OK, out receives exactly info.plain_len bytes; on any
 * other failure the first info.plain_len bytes of out are zeroized, so an
 * unverified plaintext is never left where a caller could read it. When
 * CC_STORE_E_SIZE is returned out is not touched at all. */
int cc_store_unseal(const cc_store_key_t* k, const char* ctx,
                    const uint8_t* container, size_t container_len,
                    uint8_t* out, size_t out_cap, size_t* out_len);

/* One-shot seal with a passphrase: derive (fresh salt) and seal, wiping the
 * key before returning. For a caller that has exactly one blob to write.
 * iterations == 0 means CC_STORE_KDF_DEFAULT_ITERS. */
int cc_store_seal_new(WC_RNG* rng, uint32_t iterations, const uint8_t* pass,
                      size_t pass_len, const char* ctx, const uint8_t* plain,
                      size_t plain_len, uint8_t* out, size_t out_cap,
                      size_t* out_len);

/* Re-encrypt one container under a new passphrase: open it with old_pass and
 * seal the plaintext again with a FRESH salt under new_pass (iterations == 0
 * means CC_STORE_KDF_DEFAULT_ITERS). scratch is the caller's working buffer
 * for the intermediate plaintext — the module has no heap and an
 * identity-sized plaintext has no business on an ESP32 task stack — and must
 * hold at least the container's plaintext length, i.e. container_len minus
 * CC_STORE_OVERHEAD; the plaintext region of scratch is zeroized once it has
 * held plaintext (a failure before decryption leaves it untouched, because
 * nothing secret was written to it). out must not overlap container or
 * scratch, and it holds a container only when CC_STORE_OK is returned.
 *
 * This costs two KDF runs. A passphrase change over a whole card is better
 * done as cc_store_new_key() (new passphrase, one KDF run) followed by
 * cc_store_seal() per file: same result, one derivation, and one salt for
 * every file. After either path the caller must unlock again, because the
 * containers are now sealed under a key the in-RAM one is not. */
int cc_store_reseal(const uint8_t* container, size_t container_len,
                    const uint8_t* old_pass, size_t old_pass_len,
                    const uint8_t* new_pass, size_t new_pass_len,
                    uint32_t iterations, WC_RNG* rng, const char* ctx,
                    uint8_t* scratch, size_t scratch_cap, uint8_t* out,
                    size_t out_cap, size_t* out_len);

/* Read a container's public header. No KDF, no crypto, no secrets: this is
 * how the sketch tells "sealed store" from "legacy plaintext file" (it gets
 * CC_STORE_E_DAMAGE, whose magic check is public) and how it checks the
 * plaintext length it is about to accept against the size the file kind
 * requires before decrypting anything. info may be NULL. Returns CC_STORE_OK,
 * CC_STORE_E_ARG, CC_STORE_E_DAMAGE or CC_STORE_E_VERSION. */
int cc_store_probe(const uint8_t* container, size_t container_len,
                   cc_store_info_t* info);

#ifdef __cplusplus
}
#endif

#endif /* CC_STORE_H */
