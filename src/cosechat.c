#include "cosechat.h"

#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/misc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

/* Chat plaintext bound and COSE ciphertext bound. Everything else the library
   needs is either on the stack or in the caller's cc_work_t, whose sizes come
   from the header (CC_PRE_SZ, CC_WORK_*) and follow the parameter macros. */
#define CC_CHAT_PT_SZ (CC_ADDR_SZ + CC_MAX_MSG_SZ + 8)
#define CC_ENC0_SZ (CC_CHAT_PT_SZ + 80)

/* The two per-role maxima of the working context, named for the link paths
   that dominate them. */
#define CC_LINK_PT_SZ CC_WORK_PT_SZ
/* Ciphertext bound for one link record, derived from the DESTINATION buffer
   (w->pt), not from the spare room in cc_work_t: GCM writes the plaintext
   before it verifies the tag, so a longer record is an out-of-bounds write on
   input that needs no key at all. */
#define CC_LINK_REC_SZ (CC_LINK_PT_SZ + 16)
_Static_assert(CC_LINK_REC_SZ == CC_WORK_PT_SZ + 16, "link record bound");
_Static_assert(CC_LINK_REC_SZ <= CC_WORK_CT_SZ,
               "a sealed record must fit w->ct");

/* Zeroise a working buffer: plaintext and AEAD state must not linger. */
static void wipe(void* p, size_t n) { wc_ForceZero(p, n); }

static void put_le32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static void put_le64(uint8_t* p, uint64_t v) {
  put_le32(p, (uint32_t)v);
  put_le32(p + 4, (uint32_t)(v >> 32));
}

/* ---- CBOR ---- */

/* The writers are wolfCOSE's: they were checked and already emit minimal,
   definite-length form, which is why only the reader below is ours. */
static void cbor_enc_init(WOLFCOSE_CBOR_CTX* ctx, uint8_t* buf, size_t sz) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->buf = buf;
  ctx->bufSz = sz;
}

/* ---- Canonical CBOR reader (RFC 8949 §4.2, deterministic form) ---- */

static int cb_head(const uint8_t* p, size_t avail, uint8_t* major,
                   uint64_t* val, size_t* hdr) {
  uint8_t ib, ai;
  uint64_t v;
  size_t need;

  if (avail < 1)
    return CC_E_FORMAT;
  ib = p[0];
  ai = (uint8_t)(ib & 0x1F);
  if (ai < 24) {
    v = ai;
    need = 1;
  } else if (ai == 24) {
    if (avail < 2)
      return CC_E_FORMAT;
    v = p[1];
    if (v < 24)
      return CC_E_FORMAT;
    need = 2;
  } else if (ai == 25) {
    if (avail < 3)
      return CC_E_FORMAT;
    v = ((uint64_t)p[1] << 8) | p[2];
    if (v < 256)
      return CC_E_FORMAT;
    need = 3;
  } else if (ai == 26) {
    if (avail < 5)
      return CC_E_FORMAT;
    v = ((uint64_t)p[1] << 24) | ((uint64_t)p[2] << 16) |
        ((uint64_t)p[3] << 8) | p[4];
    if (v < 65536)
      return CC_E_FORMAT;
    need = 5;
  } else {
    return CC_E_FORMAT;
  }
  *major = (uint8_t)(ib >> 5);
  *val = v;
  *hdr = need;
  return CC_OK;
}

static int cb_item(const uint8_t* p, size_t avail, uint8_t want, uint64_t* val,
                   size_t* used) {
  uint8_t major;
  uint64_t v;
  size_t hdr;
  int ret = cb_head(p, avail, &major, &v, &hdr);

  if (ret != CC_OK)
    return ret;
  if (major != want)
    return CC_E_FORMAT;
  if (want == 0) {
    *used = hdr;
  } else {
    if (v > (uint64_t)(avail - hdr))
      return CC_E_FORMAT;
    *used = hdr + (size_t)v;
  }
  *val = v;
  return CC_OK;
}

/* ---- Packet view and the normative wire layout ---- */

#define CC_EL_VERSION 0
#define CC_EL_TYPE 1
#define CC_EL_HOPS 2
#define CC_EL_COUNTER 3
#define CC_EL_NONCE 4
#define CC_EL_SUITE 5
#define CC_EL_SEQ 6
#define CC_EL_EXPIRY 7
#define CC_EL_F1 8
#define CC_EL_F2 9
#define CC_EL_F3 10
#define CC_EL_F4 11
#define CC_EL_F5 12
#define CC_EL_F6 13
#define CC_EL_F7 14

#define CC_PKT_MAX_FIELDS 7
#define CC_PKT_MAX_ELEMS 13

/* Set of element codes, one bit per code. */
#define CC_SK(code) ((uint32_t)(1u << (code)))

#define CC_POW_SKIP (CC_SK(CC_EL_HOPS) | CC_SK(CC_EL_NONCE))

#define CC_F_BSTR 0
#define CC_F_ADDR 1
#define CC_F_TSTR 2

typedef struct {
  uint8_t kind;
  uint16_t exact;
  uint16_t maxlen;
} cc_field_spec_t;

typedef struct {
  const uint8_t* p;
  size_t len;
} cc_field_t;

typedef struct {
  uint16_t off;
  uint16_t len;
} cc_range_t;

typedef struct {
  uint8_t type;
  uint8_t hops;
  uint8_t suite;
  uint32_t counter;
  uint32_t nonce;
  uint32_t seq;
  uint32_t expiry;
  uint8_t n;
  uint8_t hdr_len;
  const uint8_t* pkt;
  size_t pkt_len;
  cc_field_t f[CC_PKT_MAX_FIELDS];
  uint8_t code[CC_PKT_MAX_ELEMS];
  cc_range_t r[CC_PKT_MAX_ELEMS];
} cc_pkt_view_t;

/* Field roles, in the sequences below. */
enum {
  CC_ANN_SIGN_PUB = 0,
  CC_ANN_KEM_PUB = 1,
  CC_ANN_NAME = 2,
  CC_ANN_META = 3,
  CC_ANN_ADMIT = 4, /* the 3-byte declared PoW cost */
  CC_ANN_SIG = 5,
  CC_CHAT_SENDER = 0,
  CC_CHAT_RECIPIENT = 1,
  CC_CHAT_KEM_CT = 2,
  CC_CHAT_ENCRYPT0 = 3,
  CC_CHAT_SIG = 4,
  CC_PRES_ADDR = 0,
  CC_PRES_NAME_HASH = 1,
  CC_REQ_ADDR = 0,
  CC_LINK_ID = 0,
  CC_LINK_KEM_CT = 1,
  CC_LINK_SIG = 1,
  CC_LINK_ENC0 = 1,
  CC_ROT_SIGN_PUB = 0,
  CC_ROT_KEM_PUB = 1,
  CC_ROT_NAME = 2,
  CC_ROT_META = 3,
  CC_ROT_PREV_ADDR = 4,
  CC_ROT_SIG = 5,
  CC_ROT_CONT = 6,
  CC_REV_ADDR = 0,
  CC_REV_SIG = 1,
  CC_GRP_GID = 0,
  CC_GRP_POSTER = 1,
  CC_GRP_ENC0 = 2
};

typedef struct {
  const uint8_t* seq;
  uint8_t n;
  cc_field_spec_t f[CC_PKT_MAX_FIELDS];
  uint32_t sign_skip;
  uint32_t aad_skip;
  uint8_t pow; /* 1 if the type carries a PoW nonce */
} cc_pkt_layout_t;

static const uint8_t CC_SEQ_ANNOUNCE[] = {
    CC_EL_VERSION, CC_EL_TYPE, CC_EL_HOPS, CC_EL_NONCE, CC_EL_F1,     CC_EL_F2,
    CC_EL_F3,      CC_EL_F4,   CC_EL_F5,   CC_EL_SEQ,   CC_EL_EXPIRY, CC_EL_F6};
static const uint8_t CC_SEQ_CHAT[] = {
    CC_EL_VERSION, CC_EL_TYPE,    CC_EL_HOPS,  CC_EL_F1, CC_EL_F2,
    CC_EL_F3,      CC_EL_COUNTER, CC_EL_NONCE, CC_EL_F4, CC_EL_F5};
static const uint8_t CC_SEQ_PRESENCE[] = {
    CC_EL_VERSION, CC_EL_TYPE, CC_EL_HOPS, CC_EL_SEQ,
    CC_EL_NONCE,   CC_EL_F1,   CC_EL_F2};
static const uint8_t CC_SEQ_KEY_REQ[] = {
    CC_EL_VERSION, CC_EL_TYPE, CC_EL_HOPS, CC_EL_F1, CC_EL_SEQ, CC_EL_NONCE};
static const uint8_t CC_SEQ_LINK_REQ[] = {
    CC_EL_VERSION, CC_EL_TYPE, CC_EL_HOPS, CC_EL_NONCE,
    CC_EL_SUITE,   CC_EL_F1,   CC_EL_F2};
static const uint8_t CC_SEQ_LINK_PROOF[] = {
    CC_EL_VERSION, CC_EL_TYPE, CC_EL_HOPS, CC_EL_NONCE,
    CC_EL_SUITE,   CC_EL_F1,   CC_EL_F2};
static const uint8_t CC_SEQ_LINK_DATA[] = {
    CC_EL_VERSION, CC_EL_TYPE, CC_EL_HOPS, CC_EL_F1, CC_EL_SEQ, CC_EL_F2};
static const uint8_t CC_SEQ_IDENTIFY[] = {CC_EL_VERSION, CC_EL_TYPE, CC_EL_HOPS,
                                          CC_EL_F1,      CC_EL_SEQ,  CC_EL_F2};
static const uint8_t CC_SEQ_LINK_CLOSE[] = {
    CC_EL_VERSION, CC_EL_TYPE, CC_EL_HOPS, CC_EL_F1, CC_EL_SEQ, CC_EL_F2};
static const uint8_t CC_SEQ_ROTATE[] = {
    CC_EL_VERSION, CC_EL_TYPE, CC_EL_HOPS, CC_EL_NONCE, CC_EL_F1,
    CC_EL_F2,      CC_EL_F3,   CC_EL_F4,   CC_EL_F5,    CC_EL_SEQ,
    CC_EL_EXPIRY,  CC_EL_F6,   CC_EL_F7};
static const uint8_t CC_SEQ_REVOKE[] = {CC_EL_VERSION, CC_EL_TYPE, CC_EL_HOPS,
                                        CC_EL_NONCE,   CC_EL_F1,   CC_EL_SEQ,
                                        CC_EL_EXPIRY,  CC_EL_F2};
/* group_data: gid, poster, seq and the sealed message. No signature: the PoW
   covers everything but hops and the nonce, and the tag covers everything but
   hops, the nonce and the ciphertext. */
static const uint8_t CC_SEQ_GROUP_DATA[] = {
    CC_EL_VERSION, CC_EL_TYPE, CC_EL_HOPS,  CC_EL_F1,
    CC_EL_F2,      CC_EL_SEQ,  CC_EL_NONCE, CC_EL_F3};

static const cc_pkt_layout_t CC_PKT_LAYOUT[CC_MSG_COUNT] = {
    /* announce: sign_pub, kem_pub, name, meta, admit, signature
       (+seq, expiry). admit is inside the signed coverage: it is skipped by
       neither the PoW nor the signature. */
    {CC_SEQ_ANNOUNCE,
     12,
     {{CC_F_BSTR, CC_SIGN_PUBKEY_SZ, 0},
      {CC_F_BSTR, CC_KEM_PUBKEY_SZ, 0},
      {CC_F_TSTR, 0, CC_MAX_NAME_LEN},
      {CC_F_BSTR, 0, CC_MAX_META_SZ},
      {CC_F_BSTR, CC_ADMIT_SZ, 0},
      {CC_F_BSTR, CC_SIGN_SIG_SZ, 0}},
     (uint32_t)(CC_POW_SKIP | CC_SK(CC_EL_F6)),
     0,
     1},
    /* chat */
    {CC_SEQ_CHAT,
     10,
     {{CC_F_ADDR, CC_ADDR_SZ, 0},
      {CC_F_ADDR, CC_ADDR_SZ, 0},
      {CC_F_BSTR, CC_KEM_CT_SZ, 0},
      {CC_F_BSTR, 0, CC_ENC0_SZ},
      {CC_F_BSTR, CC_SIGN_SIG_SZ, 0}},
     (uint32_t)(CC_POW_SKIP | CC_SK(CC_EL_F5)),
     (uint32_t)(CC_POW_SKIP | CC_SK(CC_EL_F4) | CC_SK(CC_EL_F5)),
     1},
    /* presence: addr, name_hash */
    {CC_SEQ_PRESENCE,
     7,
     {{CC_F_ADDR, CC_ADDR_SZ, 0}, {CC_F_BSTR, CC_PRES_NAME_HASH_SZ, 0}},
     0,
     0,
     1},
    /* key_req */
    {CC_SEQ_KEY_REQ, 6, {{CC_F_ADDR, CC_ADDR_SZ, 0}}, 0, 0, 1},
    /* link_req: link_id, kem_ct (unsigned; the responder proves identity) */
    {CC_SEQ_LINK_REQ,
     7,
     {{CC_F_BSTR, CC_LINK_ID_SZ, 0}, {CC_F_BSTR, CC_KEM_CT_SZ, 0}},
     0,
     0,
     1},
    /* link_proof: link_id, signature (over the handshake transcript hash) */
    {CC_SEQ_LINK_PROOF,
     7,
     {{CC_F_BSTR, CC_LINK_ID_SZ, 0}, {CC_F_BSTR, CC_SIGN_SIG_SZ, 0}},
     0,
     0,
     1},
    /* link_data: link_id, encrypt0 — no PoW, no signature */
    {CC_SEQ_LINK_DATA,
     6,
     {{CC_F_BSTR, CC_LINK_ID_SZ, 0}, {CC_F_BSTR, 0, CC_LINK_REC_SZ}},
     0,
     0,
     0},
    /* identify: link_id, encrypt0 */
    {CC_SEQ_IDENTIFY,
     6,
     {{CC_F_BSTR, CC_LINK_ID_SZ, 0}, {CC_F_BSTR, 0, CC_LINK_REC_SZ}},
     0,
     0,
     0},
    /* link_close: link_id, encrypt0 */
    {CC_SEQ_LINK_CLOSE,
     6,
     {{CC_F_BSTR, CC_LINK_ID_SZ, 0}, {CC_F_BSTR, 0, CC_LINK_REC_SZ}},
     0,
     0,
     0},
    /* rotate: new keys, name, meta, prev_addr, new signature, continuity
       signature (+seq, expiry) — 13 elements, the envelope maximum */
    {CC_SEQ_ROTATE,
     13,
     {{CC_F_BSTR, CC_SIGN_PUBKEY_SZ, 0},
      {CC_F_BSTR, CC_KEM_PUBKEY_SZ, 0},
      {CC_F_TSTR, 0, CC_MAX_NAME_LEN},
      {CC_F_BSTR, 0, CC_MAX_META_SZ},
      {CC_F_ADDR, CC_ADDR_SZ, 0},
      {CC_F_BSTR, CC_SIGN_SIG_SZ, 0},
      {CC_F_BSTR, CC_SIGN_SIG_SZ, 0}},
     /* Both signatures are skipped: each authenticates itself (new_sig by
        verifying against the packet's own new key, cont_sig against the
        statement), and skipping them keeps the covered bytes inside
        CC_PRE_SZ. Everything the signatures are ABOUT is covered. */
     (uint32_t)(CC_POW_SKIP | CC_SK(CC_EL_F6) | CC_SK(CC_EL_F7)),
     0,
     1},
    /* revoke: the address being retired, signed by the key that hashes to it
       (+seq, expiry) */
    {CC_SEQ_REVOKE,
     8,
     {{CC_F_ADDR, CC_ADDR_SZ, 0}, {CC_F_BSTR, CC_SIGN_SIG_SZ, 0}},
     (uint32_t)(CC_POW_SKIP | CC_SK(CC_EL_F2)),
     0,
     1},
    /* group_data: gid, poster, encrypt0 (+seq). Unsigned by design; the poster
       is a self-claimed label the tag covers, not an identity. */
    {CC_SEQ_GROUP_DATA,
     8,
     {{CC_F_BSTR, CC_GROUP_GID_SZ, 0},
      {CC_F_ADDR, CC_ADDR_SZ, 0},
      {CC_F_BSTR, 0, CC_GROUP_ENC0_SZ}},
     0,
     (uint32_t)(CC_POW_SKIP | CC_SK(CC_EL_F3)),
     1},
};

/* The continuity statement and the old key's signature share w->scratch. */
_Static_assert(32 + CC_SIGN_SIG_SZ <= CC_WORK_SCRATCH_SZ,
               "rotation scratch must fit the statement and its signature");

static const uint8_t CC_POW_MIN[CC_MSG_COUNT] = {
    CC_POW_DIFFICULTY_ANNOUNCE,
    CC_POW_DIFFICULTY_CHAT,
    CC_POW_DIFFICULTY_PRESENCE,
    CC_POW_DIFFICULTY_KEY_REQ,
    CC_POW_DIFFICULTY_LINK_REQ,
    CC_POW_DIFFICULTY_LINK_PROOF,
    0, /* link_data: no PoW */
    0, /* identify: no PoW */
    0, /* link_close: no PoW */
    CC_POW_DIFFICULTY_ROTATE,
    CC_POW_DIFFICULTY_REVOKE,
    CC_POW_DIFFICULTY_GROUP,
};

/* ---- PoW ---- */

#if (CC_POW_DIFFICULTY_ANNOUNCE < 1 || CC_POW_DIFFICULTY_ANNOUNCE > 32) ||     \
    (CC_POW_DIFFICULTY_CHAT < 1 || CC_POW_DIFFICULTY_CHAT > 32) ||             \
    (CC_POW_DIFFICULTY_PRESENCE < 1 || CC_POW_DIFFICULTY_PRESENCE > 32) ||     \
    (CC_POW_DIFFICULTY_KEY_REQ < 1 || CC_POW_DIFFICULTY_KEY_REQ > 32) ||       \
    (CC_POW_DIFFICULTY_LINK_REQ < 1 || CC_POW_DIFFICULTY_LINK_REQ > 32) ||     \
    (CC_POW_DIFFICULTY_LINK_PROOF < 1 || CC_POW_DIFFICULTY_LINK_PROOF > 32) || \
    (CC_POW_DIFFICULTY_ROTATE < 1 || CC_POW_DIFFICULTY_ROTATE > 32) ||         \
    (CC_POW_DIFFICULTY_REVOKE < 1 || CC_POW_DIFFICULTY_REVOKE > 32) ||         \
    (CC_POW_DIFFICULTY_GROUP < 1 || CC_POW_DIFFICULTY_GROUP > 32)
#error "CC_POW_DIFFICULTY[_TYPE] must each be in 1..32 (bytes of a digest)"
#endif

static int pow_check(const uint8_t hash[32], uint8_t difficulty) {
  int i;
  for (i = 0; i < difficulty; i++) {
    if (hash[i] != 0)
      return CC_E_POW;
  }
  return CC_OK;
}

static int pow_hash(const cc_pkt_view_t* v, uint32_t nonce, uint8_t hash[32]) {
  uint8_t nle[4];
  wc_Sha256 sha;
  uint8_t i;
  int ret;

  if (v->pkt == NULL || v->hdr_len > v->pkt_len)
    return CC_E_FORMAT;
  put_le32(nle, nonce);
  ret = wc_InitSha256(&sha);
  if (ret != 0)
    return CC_E_CRYPTO;
  wc_Sha256Update(&sha, v->pkt, v->hdr_len);
  for (i = 0; i < v->n; i++) {
    if (CC_POW_SKIP & CC_SK(v->code[i]))
      continue;
    wc_Sha256Update(&sha, v->pkt + v->r[i].off, v->r[i].len);
  }
  wc_Sha256Update(&sha, nle, 4);
  ret = wc_Sha256Final(&sha, hash);
  wc_Sha256Free(&sha);
  return (ret == 0) ? CC_OK : CC_E_CRYPTO;
}

static int pkt_copy_covered(const cc_pkt_view_t* v, uint32_t skip, uint8_t* buf,
                            size_t buf_sz, size_t* len) {
  size_t o = 0;
  uint8_t i;

  if (!v || !buf || !len || v->pkt == NULL)
    return CC_E_ARG;
  if ((size_t)v->hdr_len > buf_sz)
    return CC_E_FORMAT;
  memcpy(buf, v->pkt, v->hdr_len);
  o = v->hdr_len;
  for (i = 0; i < v->n; i++) {
    if (skip & CC_SK(v->code[i]))
      continue;
    if ((size_t)v->r[i].len > buf_sz - o)
      return CC_E_FORMAT;
    memcpy(buf + o, v->pkt + v->r[i].off, v->r[i].len);
    o += v->r[i].len;
  }
  *len = o;
  return CC_OK;
}

/* difficulty 0 means "this build's own requirement for the type": the sender
   mines at the receiver-published cost it was handed, or at its own policy. */
static int pkt_pow_find(const cc_pkt_view_t* v, uint8_t difficulty,
                        uint32_t* nonce_out) {
  uint8_t hash[32];
  uint32_t n;
  if (!v || !nonce_out || v->type >= CC_MSG_COUNT)
    return CC_E_ARG;
  if (difficulty == 0)
    difficulty = CC_POW_MIN[v->type];
  if (difficulty > CC_POW_MAX)
    return CC_E_ARG; /* a digest is 32 bytes */
  if (!CC_PKT_LAYOUT[v->type].pow) {
    *nonce_out = 0;
    return CC_OK;
  }
  for (n = 0; n < 0xFFFFFF00U; n++) {
    if (pow_hash(v, n, hash) != CC_OK)
      return CC_E_CRYPTO;
    if (pow_check(hash, difficulty) == CC_OK) {
      *nonce_out = n;
      return CC_OK;
    }
  }
  return CC_E_POW;
}

/* The one place the PoW rule lives: the preimage is the encoded envelope minus
   hops and the nonce (pow_hash), and the difficulty is either the caller's
   (a peer's published price) or this build's own for the type (0). */
static int pkt_pow_check_at(const cc_pkt_view_t* v, uint8_t difficulty) {
  uint8_t hash[32];
  int ret;
  if (!v || v->type >= CC_MSG_COUNT)
    return CC_E_ARG;
  if (difficulty == 0)
    difficulty = CC_POW_MIN[v->type];
  if (difficulty > CC_POW_MAX)
    return CC_E_ARG; /* a digest is 32 bytes */
  if (!CC_PKT_LAYOUT[v->type].pow)
    return CC_OK; /* no nonce on this type: nothing to check */
  ret = pow_hash(v, v->nonce, hash);
  return (ret != CC_OK) ? ret : pow_check(hash, difficulty);
}

static int pkt_pow_check(const cc_pkt_view_t* v) {
  return pkt_pow_check_at(v, 0);
}

/* ---- Outer packet encode/decode ---- */

static int field_size_ok(const cc_field_spec_t* spec, size_t len) {
  if (spec->exact)
    return (len == spec->exact) ? CC_OK : CC_E_FORMAT;
  if (spec->maxlen && len > spec->maxlen)
    return CC_E_FORMAT;
  return CC_OK;
}

static int pkt_put_field(WOLFCOSE_CBOR_CTX* c, const cc_field_spec_t* spec,
                         const uint8_t* d, size_t len) {
  int ret = field_size_ok(spec, len);
  if (ret != CC_OK)
    return ret;
  if (spec->kind == CC_F_TSTR)
    return wc_CBOR_EncodeTstr(c, d, len) == WOLFCOSE_SUCCESS ? CC_OK : CC_E_BUF;
  return wc_CBOR_EncodeBstr(c, d, len) == WOLFCOSE_SUCCESS ? CC_OK : CC_E_BUF;
}

static int pkt_decode(const uint8_t* in, size_t in_sz, cc_pkt_view_t* v) {
  const cc_pkt_layout_t* lay;
  uint8_t major;
  uint64_t val;
  size_t hdr = 0, off, used;
  uint8_t i, fi = 0;

  if (!in || !v)
    return CC_E_ARG;
  memset(v, 0, sizeof(*v));
  v->pkt = in;
  v->pkt_len = in_sz;
  if (in_sz == 0)
    return CC_E_FORMAT;

  if (cb_head(in, in_sz, &major, &val, &hdr) != CC_OK || major != 4)
    return CC_E_FORMAT;
  if (val > CC_PKT_MAX_ELEMS || val < 3)
    return CC_E_FORMAT;
  v->n = (uint8_t)val;
  v->hdr_len = (uint8_t)hdr;
  off = hdr;

  if (cb_item(in + off, in_sz - off, 0, &val, &used) != CC_OK)
    return CC_E_FORMAT;
  if (val != CC_WIRE_VERSION)
    return CC_E_VERSION;
  v->code[0] = CC_EL_VERSION;
  v->r[0].off = (uint16_t)off;
  v->r[0].len = (uint16_t)used;
  off += used;

  if (cb_item(in + off, in_sz - off, 0, &val, &used) != CC_OK ||
      val >= CC_MSG_COUNT)
    return CC_E_FORMAT;
  v->type = (uint8_t)val;
  v->code[1] = CC_EL_TYPE;
  v->r[1].off = (uint16_t)off;
  v->r[1].len = (uint16_t)used;
  off += used;

  lay = &CC_PKT_LAYOUT[v->type];
  if (v->n != lay->n)
    return CC_E_FORMAT;

  for (i = 2; i < v->n; i++) {
    uint8_t el = lay->seq[i];
    v->code[i] = el;
    v->r[i].off = (uint16_t)off;
    if (el >= CC_EL_F1) {
      const cc_field_spec_t* spec = &lay->f[el - CC_EL_F1];
      if (cb_item(in + off, in_sz - off,
                  (uint8_t)(spec->kind == CC_F_TSTR ? 3 : 2), &val,
                  &used) != CC_OK)
        return CC_E_FORMAT;
      if (field_size_ok(spec, (size_t)val) != CC_OK)
        return CC_E_FORMAT;
      v->f[fi].p = in + off + (used - (size_t)val);
      v->f[fi].len = (size_t)val;
      fi++;
    } else {
      if (cb_item(in + off, in_sz - off, 0, &val, &used) != CC_OK)
        return CC_E_FORMAT;
      if (el == CC_EL_HOPS)
        v->hops = (uint8_t)(val & 0xFF);
      else if (el == CC_EL_COUNTER)
        v->counter = (uint32_t)(val & 0xFFFFFFFF);
      else if (el == CC_EL_NONCE)
        v->nonce = (uint32_t)(val & 0xFFFFFFFF);
      else if (el == CC_EL_SUITE)
        v->suite = (uint8_t)(val & 0xFF);
      else if (el == CC_EL_SEQ)
        v->seq = (uint32_t)(val & 0xFFFFFFFF);
      else
        v->expiry = (uint32_t)(val & 0xFFFFFFFF);
    }
    v->r[i].len = (uint16_t)used;
    off += used;
  }

  if (off != in_sz)
    return CC_E_FORMAT;
  v->pkt_len = off;
  return CC_OK;
}

static int pkt_encode(cc_pkt_view_t* v, uint8_t hops, uint32_t nonce,
                      uint8_t* out, size_t out_sz, size_t* out_len) {
  const cc_pkt_layout_t* lay;
  WOLFCOSE_CBOR_CTX c;
  size_t start;
  uint8_t i, fi = 0;

  if (!v || !out || !out_len || v->type >= CC_MSG_COUNT)
    return CC_E_ARG;
  lay = &CC_PKT_LAYOUT[v->type];
  cbor_enc_init(&c, out, out_sz);
  if (wc_CBOR_EncodeArrayStart(&c, lay->n) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  v->n = lay->n;
  v->hdr_len = (uint8_t)c.idx;

  for (i = 0; i < lay->n; i++) {
    uint8_t el = lay->seq[i];
    start = c.idx;
    v->code[i] = el;
    if (el >= CC_EL_F1) {
      int ret =
          pkt_put_field(&c, &lay->f[el - CC_EL_F1], v->f[fi].p, v->f[fi].len);
      if (ret != CC_OK)
        return ret;
      fi++;
    } else {
      uint64_t val = 0;
      switch (el) {
        case CC_EL_VERSION:
          val = CC_WIRE_VERSION;
          break;
        case CC_EL_TYPE:
          val = v->type;
          break;
        case CC_EL_HOPS:
          val = hops;
          break;
        case CC_EL_COUNTER:
          val = v->counter;
          break;
        case CC_EL_NONCE:
          val = nonce;
          break;
        case CC_EL_SUITE:
          val = v->suite;
          break;
        case CC_EL_SEQ:
          val = v->seq;
          break;
        default:
          val = v->expiry;
          break;
      }
      if (wc_CBOR_EncodeUint(&c, val) != WOLFCOSE_SUCCESS)
        return CC_E_BUF;
    }
    v->r[i].off = (uint16_t)start;
    v->r[i].len = (uint16_t)(c.idx - start);
  }

  v->pkt = out;
  v->pkt_len = c.idx;
  *out_len = c.idx;
  return CC_OK;
}

static int pkt_accept(const uint8_t* in, size_t in_sz, uint8_t want_type,
                      cc_pkt_view_t* v) {
  int ret = pkt_decode(in, in_sz, v);
  if (ret != CC_OK)
    return ret;
  if (v->type != want_type)
    return CC_E_FORMAT;
  return pkt_pow_check(v);
}

static int pkt_finish(cc_pkt_view_t* v, uint8_t difficulty, uint8_t* out,
                      size_t out_sz, size_t* out_len) {
  uint32_t nonce = 0;
  size_t n = 0;
  int ret = pkt_encode(v, 0, 0, out, out_sz, &n);
  if (ret != CC_OK)
    return ret;
  ret = pkt_pow_find(v, difficulty, &nonce);
  if (ret != CC_OK)
    return ret;
  return pkt_encode(v, 0, nonce, out, out_sz, out_len);
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
  uint8_t major;
  uint64_t count, val;
  size_t hdr, off, used;

  if (cb_head(buf, sz, &major, &count, &hdr) != CC_OK || major != 4 ||
      count != 2)
    return CC_E_FORMAT;
  off = hdr;
  if (cb_item(buf + off, sz - off, 2, &val, &used) != CC_OK ||
      val != CC_ADDR_SZ)
    return CC_E_FORMAT;
  memcpy(sender, buf + off + (used - (size_t)val), CC_ADDR_SZ);
  off += used;
  if (cb_item(buf + off, sz - off, 2, &val, &used) != CC_OK)
    return CC_E_FORMAT;
  if (val > CC_MAX_MSG_SZ)
    return CC_E_BUF;
  memcpy(msg, buf + off + (used - (size_t)val), (size_t)val);
  *msg_len = (size_t)val;
  off += used;
  return (off == sz) ? CC_OK : CC_E_FORMAT;
}

/* ---- ML-KEM shared secrets ---- */

static int kem_encap_ss(cc_work_t* w, const uint8_t recip_pub[CC_KEM_PUBKEY_SZ],
                        uint8_t ct[CC_KEM_CT_SZ], uint8_t ss[CC_KEM_SS_SZ],
                        WC_RNG* rng) {
  int ret;
  ret = wc_KyberKey_Init(CC_KEM_TYPE, &w->kem_tmp, NULL, INVALID_DEVID);
  if (ret != 0)
    return CC_E_CRYPTO;
  ret = wc_KyberKey_DecodePublicKey(&w->kem_tmp, recip_pub, CC_KEM_PUBKEY_SZ);
  if (ret != 0) {
    wc_KyberKey_Free(&w->kem_tmp);
    return CC_E_CRYPTO;
  }
  ret = wc_KyberKey_Encapsulate(&w->kem_tmp, ct, ss, rng);
  wc_KyberKey_Free(&w->kem_tmp);
  if (ret != 0) {
    wipe(ss, CC_KEM_SS_SZ);
    return CC_E_CRYPTO;
  }
  return CC_OK;
}

static int kem_decap_ss(KyberKey* priv, const uint8_t* ct, size_t ct_len,
                        uint8_t ss[CC_KEM_SS_SZ]) {
  if (ct_len != CC_KEM_CT_SZ)
    return CC_E_FORMAT;
  if (wc_KyberKey_Decapsulate(priv, ss, ct, (word32)ct_len) != 0) {
    wipe(ss, CC_KEM_SS_SZ);
    return CC_E_CRYPTO;
  }
  return CC_OK;
}

/* Both directions of the opportunistic chat derive the same AES key:
   HKDF-SHA256 over the shared secret. */
static int kem_kdf(uint8_t ss[CC_KEM_SS_SZ], uint8_t aes[32]) {
  static const uint8_t info[] = "cosechat";
  int ret = wc_HKDF(WC_HASH_TYPE_SHA256, ss, CC_KEM_SS_SZ, NULL, 0, info,
                    (word32)(sizeof(info) - 1), aes, 32);
  wc_ForceZero(ss, CC_KEM_SS_SZ);
  return (ret == 0) ? CC_OK : CC_E_CRYPTO;
}

static int kem_encap(cc_work_t* w, const uint8_t recip_pub[CC_KEM_PUBKEY_SZ],
                     uint8_t ct[CC_KEM_CT_SZ], uint8_t aes[32], WC_RNG* rng) {
  uint8_t ss[CC_KEM_SS_SZ];
  int ret = kem_encap_ss(w, recip_pub, ct, ss, rng);
  if (ret != CC_OK)
    return ret;
  return kem_kdf(ss, aes);
}

static int kem_decap(KyberKey* priv, const uint8_t* ct, size_t ct_len,
                     uint8_t aes[32]) {
  uint8_t ss[CC_KEM_SS_SZ];
  int ret = kem_decap_ss(priv, ct, ct_len, ss);
  if (ret != CC_OK)
    return ret;
  return kem_kdf(ss, aes);
}

/* ---- Replay window ---- */

static int replay_step(cc_replay_t* st, uint8_t cls, const uint8_t* addr,
                       uint32_t counter, int commit) {
  uint32_t d;
  if (!st || !addr)
    return CC_E_ARG;
  if (st->cls != cls)
    return CC_E_ARG;
  if (memcmp(st->addr, addr, CC_ADDR_SZ) != 0)
    return CC_E_ARG;

  if (!st->used) {
    if (commit) {
      st->used = 1;
      st->high = counter;
      st->seen = 1;
    }
    return CC_OK;
  }
  if (counter > st->high) {
    if (commit) {
      uint32_t shift = counter - st->high;
      st->seen = (shift >= CC_REPLAY_WINDOW) ? 1 : ((st->seen << shift) | 1);
      st->high = counter;
    }
    return CC_OK;
  }
  d = st->high - counter;
  if (d >= CC_REPLAY_WINDOW)
    return CC_E_STALE;
  if (st->seen & ((uint64_t)1 << d))
    return CC_E_REPLAY;
  if (commit)
    st->seen |= (uint64_t)1 << d;
  return CC_OK;
}

/* ---- Links: RFC 9180 section 5.1 key schedule ---- */

#define CC_SUITE_ID "cosechat"
#define CC_SUITE_ID_SZ (sizeof(CC_SUITE_ID) - 1)
#define CC_LINK_WINDOW 64

/* HPKE labelled Extract/Expand, with the "HPKE-v1" prefix and this protocol's
   suite_id, applied to the ML-KEM shared secret as if it were a DH secret
   (there is no registered HPKE ML-KEM KEM ID, so the suite byte travels in the
   handshake instead). */
static int hpke_extract_labeled(cc_work_t* w, const uint8_t* salt,
                                size_t salt_sz, const char* label,
                                const uint8_t* ikm, size_t ikm_sz,
                                uint8_t out[32]) {
  uint8_t* ikey = w->pre; /* scratch: the labelled input, built in place */
  size_t n = 0;
  static const uint8_t hp[] = "HPKE-v1";
  memcpy(ikey, hp, 7);
  n = 7;
  memcpy(ikey + n, CC_SUITE_ID, CC_SUITE_ID_SZ);
  n += CC_SUITE_ID_SZ;
  ikey[n++] = CC_SUITE;
  memcpy(ikey + n, label, strlen(label));
  n += strlen(label);
  memcpy(ikey + n, ikm, ikm_sz);
  n += ikm_sz;
  return wc_HKDF_Extract(WC_HASH_TYPE_SHA256, salt, (word32)salt_sz, ikey,
                         (word32)n, out) == 0
             ? CC_OK
             : CC_E_CRYPTO;
}

static int hpke_expand_labeled(cc_work_t* w, const uint8_t prk[32],
                               const char* label, const uint8_t* info,
                               size_t info_sz, uint8_t* out, size_t out_sz) {
  uint8_t* ikey = w->pre;
  size_t n = 0;
  static const uint8_t hp[] = "HPKE-v1";
  /* The scratch is a fixed buffer, so its bound comes from the arguments. */
  if (2 + sizeof(hp) - 1 + CC_SUITE_ID_SZ + 1 + strlen(label) + info_sz >
      CC_PRE_SZ)
    return CC_E_ARG;
  ikey[n++] = (uint8_t)(out_sz >> 8);
  ikey[n++] = (uint8_t)(out_sz & 0xFF);
  memcpy(ikey + n, hp, 7);
  n += 7;
  memcpy(ikey + n, CC_SUITE_ID, CC_SUITE_ID_SZ);
  n += CC_SUITE_ID_SZ;
  ikey[n++] = CC_SUITE;
  memcpy(ikey + n, label, strlen(label));
  n += strlen(label);
  memcpy(ikey + n, info, info_sz);
  n += info_sz;
  return wc_HKDF_Expand(WC_HASH_TYPE_SHA256, prk, 32, ikey, (word32)n, out,
                        (word32)out_sz) == 0
             ? CC_OK
             : CC_E_CRYPTO;
}

/* The handshake transcript, hashed: SHA-256("cosechat/link" ‖ suite ‖
   link_id ‖ kem_ct ‖ responder_addr). Both sides hash the same bytes, the
   responder signs the hash, and the hash is the RFC 9180 `info`. */
static int link_transcript_hash(cc_work_t* w, uint8_t suite,
                                const uint8_t link_id[8], const uint8_t* kem_ct,
                                size_t kem_ct_sz, const uint8_t* responder_addr,
                                uint8_t out[32]) {
  uint8_t* t = w->pre;
  static const uint8_t label[] = "cosechat/link";
  size_t n = 0;
  if (sizeof(label) - 1 + 1 + CC_LINK_ID_SZ + kem_ct_sz + CC_ADDR_SZ >
      CC_PRE_SZ)
    return CC_E_ARG; /* the scratch bound, from the arguments */
  memcpy(t + n, label, sizeof(label) - 1);
  n += sizeof(label) - 1;
  t[n++] = suite;
  memcpy(t + n, link_id, CC_LINK_ID_SZ);
  n += CC_LINK_ID_SZ;
  memcpy(t + n, kem_ct, kem_ct_sz);
  n += kem_ct_sz;
  memcpy(t + n, responder_addr, CC_ADDR_SZ);
  n += CC_ADDR_SZ;
  return wc_Sha256Hash(t, (word32)n, out) == 0 ? CC_OK : CC_E_CRYPTO;
}

/* The identify binding: SHA-256("cosechat/identify" ‖ suite ‖ link_id ‖
   initiator_addr), signed by the initiator to prove its identity. */
static int link_identify_msg(uint8_t suite, const uint8_t link_id[8],
                             const uint8_t* initiator_addr, uint8_t out[32]) {
  uint8_t t[64]; /* small enough for the stack */
  static const uint8_t label[] = "cosechat/identify";
  size_t n = 0;
  memcpy(t + n, label, sizeof(label) - 1);
  n += sizeof(label) - 1;
  t[n++] = suite;
  memcpy(t + n, link_id, CC_LINK_ID_SZ);
  n += CC_LINK_ID_SZ;
  memcpy(t + n, initiator_addr, CC_ADDR_SZ);
  n += CC_ADDR_SZ;
  return wc_Sha256Hash(t, (word32)n, out) == 0 ? CC_OK : CC_E_CRYPTO;
}

/* Derive the per-direction keys and salts (mode_base, no PSK). */
static int link_derive(cc_work_t* w, cc_link_t* l,
                       const uint8_t ss[CC_KEM_SS_SZ], const uint8_t* kem_ct,
                       size_t kem_ct_sz, const uint8_t info[32]) {
  uint8_t eae_prk[32], shared[32], secret[32], psk_id_hash[32], info_hash[32];
  uint8_t ks_ctx[65];
  uint8_t i2r_key[32], r2i_key[32], i2r_salt[3], r2i_salt[3];
  int ret;

  ret = hpke_extract_labeled(w, NULL, 0, "eae_prk", ss, CC_KEM_SS_SZ, eae_prk);
  if (ret != CC_OK)
    return ret;
  ret = hpke_expand_labeled(w, eae_prk, "shared_secret", kem_ct, kem_ct_sz,
                            shared, 32);
  if (ret != CC_OK)
    return ret;
  ret = hpke_extract_labeled(w, shared, 32, "secret", (const uint8_t*)"", 0,
                             secret);
  if (ret != CC_OK)
    return ret;
  ret = hpke_extract_labeled(w, NULL, 0, "psk_id_hash", (const uint8_t*)"", 0,
                             psk_id_hash);
  if (ret != CC_OK)
    return ret;
  ret = hpke_extract_labeled(w, NULL, 0, "info_hash", info, 32, info_hash);
  if (ret != CC_OK)
    return ret;

  ks_ctx[0] = 0x00; /* mode_base */
  memcpy(ks_ctx + 1, psk_id_hash, 32);
  memcpy(ks_ctx + 33, info_hash, 32);

  ret = hpke_expand_labeled(w, secret, "key_i2r", ks_ctx, sizeof(ks_ctx),
                            i2r_key, 32);
  if (ret == CC_OK)
    ret = hpke_expand_labeled(w, secret, "salt_i2r", ks_ctx, sizeof(ks_ctx),
                              i2r_salt, 3);
  if (ret == CC_OK)
    ret = hpke_expand_labeled(w, secret, "key_r2i", ks_ctx, sizeof(ks_ctx),
                              r2i_key, 32);
  if (ret == CC_OK)
    ret = hpke_expand_labeled(w, secret, "salt_r2i", ks_ctx, sizeof(ks_ctx),
                              r2i_salt, 3);

  wipe(eae_prk, sizeof(eae_prk));
  wipe(shared, sizeof(shared));
  wipe(secret, sizeof(secret));
  if (ret != CC_OK)
    return CC_E_CRYPTO;

  if (l->role == CC_LINK_ROLE_INITIATOR) {
    memcpy(l->tx_key, i2r_key, 32);
    memcpy(l->rx_key, r2i_key, 32);
    memcpy(l->tx_salt, i2r_salt, 3);
    memcpy(l->rx_salt, r2i_salt, 3);
  } else {
    memcpy(l->tx_key, r2i_key, 32);
    memcpy(l->rx_key, i2r_key, 32);
    memcpy(l->tx_salt, r2i_salt, 3);
    memcpy(l->rx_salt, i2r_salt, 3);
  }
  wipe(i2r_key, sizeof(i2r_key));
  wipe(r2i_key, sizeof(r2i_key));
  return CC_OK;
}

/* Link record plaintext framing. */
static int link_record_enc(uint8_t kind, const uint8_t* payload,
                           size_t payload_len, uint8_t* out, size_t out_sz,
                           size_t* out_len) {
  WOLFCOSE_CBOR_CTX c;
  cbor_enc_init(&c, out, out_sz);
  if (wc_CBOR_EncodeArrayStart(&c, 2) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeUint(&c, kind) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  if (wc_CBOR_EncodeBstr(&c, payload ? payload : (const uint8_t*)"",
                         payload_len) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  *out_len = c.idx;
  return CC_OK;
}

static int link_record_dec(const uint8_t* in, size_t in_sz, uint8_t* kind,
                           const uint8_t** payload, size_t* payload_len) {
  uint8_t major;
  uint64_t count, val;
  size_t hdr, off, used;

  if (cb_head(in, in_sz, &major, &count, &hdr) != CC_OK || major != 4 ||
      count != 2)
    return CC_E_FORMAT;
  off = hdr;
  if (cb_item(in + off, in_sz - off, 0, &val, &used) != CC_OK)
    return CC_E_FORMAT;
  *kind = (uint8_t)(val & 0xFF);
  off += used;
  if (cb_item(in + off, in_sz - off, 2, &val, &used) != CC_OK)
    return CC_E_FORMAT;
  *payload = in + off + (used - (size_t)val);
  *payload_len = (size_t)val;
  off += used;
  return (off == in_sz) ? CC_OK : CC_E_FORMAT;
}

/* AEAD: nonce = direction(1) ‖ salt(3) ‖ sequence(8 LE); the link key is the
   authentication, the sequence is the replay defence. */
static void link_nonce(const cc_link_t* l, uint8_t tx, uint64_t seq,
                       uint8_t out[12]) {
  /* Direction byte: 0 for initiator->responder, 1 for responder->initiator,
     of the packet being sent (tx) or received (rx). */
  if (tx)
    out[0] = (uint8_t)(l->role == CC_LINK_ROLE_RESPONDER);
  else
    out[0] = (uint8_t)(l->role != CC_LINK_ROLE_RESPONDER);
  if (tx)
    memcpy(out + 1, l->tx_salt, 3);
  else
    memcpy(out + 1, l->rx_salt, 3);
  put_le64(out + 4, seq);
}

static int link_seal(cc_link_t* l, const uint8_t* pt, size_t pt_len,
                     uint8_t* ct /* pt_len + 16 */) {
  Aes aes;
  uint8_t nonce[12];
  uint8_t tag[16];
  int ret;
  link_nonce(l, 1, l->tx_seq, nonce);
  ret = wc_AesGcmSetKey(&aes, l->tx_key, 32);
  if (ret != 0)
    return CC_E_CRYPTO;
  ret = wc_AesGcmEncrypt(&aes, ct, pt, (word32)pt_len, nonce, 12, tag,
                         sizeof(tag), NULL, 0);
  if (ret != 0)
    return CC_E_CRYPTO;
  memcpy(ct + pt_len, tag, sizeof(tag)); /* tag travels with the ciphertext */
  return CC_OK;
}

static int link_open(cc_link_t* l, const uint8_t* ct, size_t ct_len,
                     uint64_t seq, uint8_t* pt /* CC_LINK_PT_SZ bytes */) {
  Aes aes;
  uint8_t nonce[12];
  int ret;
  /* Bound the copy from the arguments, so the destination is provably big
     enough even if a caller reaches here without the layout check. */
  if (ct_len < 16 || ct_len - 16 > CC_LINK_PT_SZ)
    return CC_E_FORMAT;
  link_nonce(l, 0, seq, nonce);
  ret = wc_AesGcmSetKey(&aes, l->rx_key, 32);
  if (ret != 0)
    return CC_E_CRYPTO;
  ret = wc_AesGcmDecrypt(&aes, pt, ct, (word32)(ct_len - 16), nonce, 12,
                         ct + ct_len - 16, 16, NULL, 0);
  return (ret == 0) ? CC_OK : CC_E_DECRYPT;
}

/* Idle check as a signed age: `now` is the caller's clock and tx/rx may use
   different ones, so a `now` that is behind last_seen must read as fresh
   rather than wrapping into "long expired". */
static int link_idle(const cc_link_t* l, uint32_t now) {
  return (int32_t)(now - l->last_seen) > (int32_t)l->expiry;
}

/* 64-bit sequence window, same shape as the chat replay window. */
static int link_seq_step(cc_link_t* l, uint64_t seq, int commit) {
  uint64_t d;
  if (!l)
    return CC_E_ARG;
  if (l->rx_seen == 0) { /* nothing received yet: the first packet sets it */
    if (commit) {
      l->rx_seq = seq;
      l->rx_seen = 1;
    }
    return CC_OK;
  }
  if (seq > l->rx_seq) {
    if (commit) {
      uint64_t shift = seq - l->rx_seq;
      l->rx_seen = (shift >= CC_LINK_WINDOW) ? 1 : ((l->rx_seen << shift) | 1);
      l->rx_seq = seq;
    }
    return CC_OK;
  }
  d = l->rx_seq - seq;
  if (d >= CC_LINK_WINDOW)
    return CC_E_STALE;
  if (l->rx_seen & ((uint64_t)1 << d))
    return CC_E_REPLAY;
  if (commit)
    l->rx_seen |= (uint64_t)1 << d;
  return CC_OK;
}

/* ---- Public API ---- */

/* A failed seed import must not leave the seeds behind: they are the secret. */
static int key_seed_fail(cc_key_t* key) {
  wipe(key->sign_seed, CC_SIGN_SEED_SZ);
  wipe(key->kem_seed, CC_KEM_SEED_SZ);
  key->has_seed = 0;
  return CC_E_CRYPTO;
}

int cc_key_import_seed(cc_key_t* key, const uint8_t sign_seed[CC_SIGN_SEED_SZ],
                       const uint8_t kem_seed[CC_KEM_SEED_SZ]) {
  int ret;
  if (!key || !sign_seed || !kem_seed)
    return CC_E_ARG;
  /* cc_key_generate() drives this function with the key's own seed fields as
     the input, so the copy has to tolerate aliasing. */
  if (key->sign_seed != sign_seed)
    memcpy(key->sign_seed, sign_seed, CC_SIGN_SEED_SZ);
  if (key->kem_seed != kem_seed)
    memcpy(key->kem_seed, kem_seed, CC_KEM_SEED_SZ);
  key->has_seed = 1;

  wc_dilithium_init(&key->sign);
  ret = wc_dilithium_set_level(&key->sign, CC_SIGN_LEVEL);
  if (ret == 0)
    ret = wc_dilithium_make_key_from_seed(&key->sign, key->sign_seed);
  if (ret != 0) {
    wc_dilithium_free(&key->sign);
    return key_seed_fail(key);
  }
  ret = wc_KyberKey_Init(CC_KEM_TYPE, &key->kem, NULL, INVALID_DEVID);
  if (ret == 0)
    ret =
        wc_KyberKey_MakeKeyWithRandom(&key->kem, key->kem_seed, CC_KEM_SEED_SZ);
  if (ret != 0) {
    wc_KyberKey_Free(&key->kem);
    wc_dilithium_free(&key->sign);
    return key_seed_fail(key);
  }
  return CC_OK;
}

int cc_key_export_seed(const cc_key_t* key, uint8_t sign_seed[CC_SIGN_SEED_SZ],
                       uint8_t kem_seed[CC_KEM_SEED_SZ]) {
  if (!key || !sign_seed || !kem_seed)
    return CC_E_ARG;
  if (!key->has_seed)
    return CC_E_NOKEY; /* expanded import: the seed is unknowable, not zero */
  memcpy(sign_seed, key->sign_seed, CC_SIGN_SEED_SZ);
  memcpy(kem_seed, key->kem_seed, CC_KEM_SEED_SZ);
  return CC_OK;
}

int cc_key_generate(cc_key_t* key, WC_RNG* rng) {
  if (!key || !rng)
    return CC_E_ARG;
  /* Generate is all-or-nothing, and the object must never claim a seed it does
     not have: a caller that reuses a cc_key_t and hits a failure here would
     otherwise export the PREVIOUS identity's seed (or a half-drawn one) as
     CC_OK, and come back from a reboot as a different node. Clearing first
     makes the failure path indistinguishable from "no seed", which is what it
     is. */
  wipe(key->sign_seed, CC_SIGN_SEED_SZ);
  wipe(key->kem_seed, CC_KEM_SEED_SZ);
  key->has_seed = 0;
  /* The seeds come first: they are what a caller stores, and what the keys are
     derived from. Generating the seeds and deriving through the seed path
     means a generated key is always seed-exportable. Both draws happen before
     any key object is touched, so an RNG failure leaves an existing key intact
     (key_seed_fail only clears the seeds). */
  if (wc_RNG_GenerateBlock(rng, key->sign_seed, CC_SIGN_SEED_SZ) != 0)
    return key_seed_fail(key);
  if (wc_RNG_GenerateBlock(rng, key->kem_seed, CC_KEM_SEED_SZ) != 0)
    return key_seed_fail(key);
  return cc_key_import_seed(key, key->sign_seed, key->kem_seed);
}

int cc_key_import(cc_key_t* key, const uint8_t sign_priv[CC_SIGN_PRIVKEY_SZ],
                  const uint8_t sign_pub[CC_SIGN_PUBKEY_SZ],
                  const uint8_t kem_priv[CC_KEM_PRIVKEY_SZ]) {
  int ret;
  if (!key || !sign_priv || !sign_pub || !kem_priv)
    return CC_E_ARG;
  /* The expanded form carries no seed, and none can be derived from it, so
     this key cannot be re-exported in seed form. */
  wipe(key->sign_seed, CC_SIGN_SEED_SZ);
  wipe(key->kem_seed, CC_KEM_SEED_SZ);
  key->has_seed = 0;
  wc_dilithium_init(&key->sign);
  ret = wc_dilithium_set_level(&key->sign, CC_SIGN_LEVEL);
  if (ret != 0)
    return CC_E_CRYPTO;
  ret = wc_dilithium_import_key(sign_priv, CC_SIGN_PRIVKEY_SZ, sign_pub,
                                CC_SIGN_PUBKEY_SZ, &key->sign);
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
    /* wolfSSL zeroizes the expanded material itself: wc_dilithium_free ends in
       ForceZero(key, sizeof(*key)), and wc_MlKemKey_Free zeroes the PRF, hash,
       priv and z members. The seeds are ours, so we wipe them here. */
    wc_dilithium_free(&key->sign);
    wc_KyberKey_Free(&key->kem);
    wipe(key->sign_seed, CC_SIGN_SEED_SZ);
    wipe(key->kem_seed, CC_KEM_SEED_SZ);
    key->has_seed = 0;
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

/* Length of one definite-length CBOR item, or CC_E_FORMAT. Depth-capped: the
   metadata map is application data that arrives from the network, and a
   decoder that recurses without a bound is a stack-overflow target. Follows
   the same minimal-head subset as the envelope (cb_head), so an item that
   would be non-canonical there is refused here too. */
#define CC_META_MAX_DEPTH 4
static int meta_item_span(const uint8_t* p, size_t avail, size_t* span,
                          int depth) {
  uint8_t major;
  uint64_t count;
  size_t hdr, off, sub;
  int ret;

  if (depth > CC_META_MAX_DEPTH)
    return CC_E_FORMAT;
  if (cb_head(p, avail, &major, &count, &hdr) != CC_OK)
    return CC_E_FORMAT;
  switch (major) {
    case 0: /* unsigned integer */
    case 1: /* negative integer */
    case 7: /* simple value / float: the head is the whole item */
      off = hdr;
      break;
    case 2: /* byte string */
    case 3: /* text string */
      if (count > avail - hdr)
        return CC_E_FORMAT;
      off = hdr + (size_t)count;
      break;
    case 4: /* array */
    case 5: /* map */
      off = hdr;
      for (uint64_t i = 0; i < count; i++) {
        ret = meta_item_span(p + off, avail - off, &sub, depth + 1);
        if (ret != CC_OK)
          return ret;
        off += sub;
      }
      break;
    case 6: /* tag: head plus one tagged item */
      ret = meta_item_span(p + hdr, avail - hdr, &sub, depth + 1);
      if (ret != CC_OK)
        return ret;
      off = hdr + sub;
      break;
    default:
      return CC_E_FORMAT;
  }
  *span = off;
  return CC_OK;
}

/* The announce metadata is a CBOR map that is signed and propagated, so a
   malformed one is every receiver's problem, not just the sender's: validate
   the whole map, both when it is built and when it is parsed.

   Enforced: a definite-length map head, definite-length items only, keys in
   canonical order (RFC 8949 section 4.2.1: shorter encoded key first, then
   bytewise, which also rules out duplicate keys), every key paired with a
   value, and no trailing bytes. What the keys mean is the app's business. */
static int meta_map_ok(const uint8_t* meta, size_t meta_len) {
  uint8_t major;
  uint64_t count;
  size_t hdr, off, klen, vlen, prev_len = 0;
  const uint8_t* prev_key = NULL;
  int ret;

  if (meta_len == 0)
    return CC_OK; /* absent is the normal case */
  if (meta_len > CC_MAX_META_SZ)
    return CC_E_FORMAT;
  if (cb_head(meta, meta_len, &major, &count, &hdr) != CC_OK || major != 5)
    return CC_E_FORMAT; /* must be a definite-length CBOR map */
  off = hdr;
  for (uint64_t i = 0; i < count; i++) {
    const uint8_t* key;
    if (off >= meta_len)
      return CC_E_FORMAT; /* a map head claiming pairs it does not carry */
    key = meta + off;
    ret = meta_item_span(key, meta_len - off, &klen, 0);
    if (ret != CC_OK)
      return ret;
    if (prev_key != NULL) { /* canonical order; equal spans are duplicates */
      if (prev_len > klen ||
          (prev_len == klen && memcmp(prev_key, key, klen) >= 0))
        return CC_E_FORMAT;
    }
    prev_key = key;
    prev_len = klen;
    off += klen;
    if (off >= meta_len)
      return CC_E_FORMAT; /* a key with no value */
    ret = meta_item_span(meta + off, meta_len - off, &vlen, 0);
    if (ret != CC_OK)
      return ret;
    off += vlen;
  }
  return (off == meta_len) ? CC_OK : CC_E_FORMAT; /* no trailing bytes */
}

int cc_announce_build(cc_work_t* w, const cc_key_t* key, const char* name,
                      size_t name_len, const uint8_t* meta, size_t meta_len,
                      const uint8_t* admit, uint32_t seq, uint32_t expiry,
                      uint8_t* out, size_t out_sz, size_t* out_len,
                      WC_RNG* rng) {
  if (!w)
    return CC_E_ARG;
  uint8_t sign_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t kem_pub[CC_KEM_PUBKEY_SZ];
  uint8_t price[CC_ADMIT_SZ];
  cc_pkt_view_t view = {0};
  size_t n = 0, pre_len = 0, i;
  word32 sig_len = CC_SIGN_SIG_SZ;
  int ret;

  if (!key || !out || !out_len || !rng)
    return CC_E_ARG;
  if (name_len > CC_MAX_NAME_LEN || meta_len > CC_MAX_META_SZ)
    return CC_E_ARG;
  if (meta_map_ok(meta, meta_len) != CC_OK)
    return CC_E_ARG;
  /* No declaration given: publish this build's own requirements, which is what
     a receiver of this node's traffic would have to satisfy anyway. */
  if (admit) {
    for (i = 0; i < CC_ADMIT_SZ; i++) {
      if (admit[i] > CC_POW_MAX)
        return CC_E_ARG;
      price[i] = admit[i];
    }
  } else {
    cc_admit_default(price);
  }

  ret = cc_key_export_public(key, sign_pub, kem_pub);
  if (ret != CC_OK)
    return ret;

  view.type = CC_MSG_ANNOUNCE;
  view.seq = seq;
  view.expiry = expiry;
  view.f[CC_ANN_SIGN_PUB].p = sign_pub;
  view.f[CC_ANN_SIGN_PUB].len = CC_SIGN_PUBKEY_SZ;
  view.f[CC_ANN_KEM_PUB].p = kem_pub;
  view.f[CC_ANN_KEM_PUB].len = CC_KEM_PUBKEY_SZ;
  view.f[CC_ANN_NAME].p = (const uint8_t*)(name ? name : "");
  view.f[CC_ANN_NAME].len = name ? name_len : 0;
  view.f[CC_ANN_META].p = meta;
  view.f[CC_ANN_META].len = meta_len;
  view.f[CC_ANN_ADMIT].p = price;
  view.f[CC_ANN_ADMIT].len = CC_ADMIT_SZ;
  view.f[CC_ANN_SIG].p = w->sig;
  view.f[CC_ANN_SIG].len = CC_SIGN_SIG_SZ;

  ret = pkt_encode(&view, 0, 0, out, out_sz, &n);
  if (ret != CC_OK)
    return ret;
  ret = pkt_copy_covered(&view, CC_PKT_LAYOUT[CC_MSG_ANNOUNCE].sign_skip,
                         w->pre, sizeof(w->pre), &pre_len);
  if (ret != CC_OK)
    return ret;
  if (wc_dilithium_sign_msg(w->pre, (word32)pre_len, w->sig, &sig_len,
                            (dilithium_key*)&key->sign, rng) != 0)
    return CC_E_CRYPTO;
  wipe(w->pre, sizeof(w->pre));
  view.f[CC_ANN_SIG].len = sig_len;

  return pkt_finish(&view, 0, out, out_sz, out_len);
}

int cc_announce_parse(cc_work_t* w, const uint8_t* in, size_t in_sz,
                      cc_announce_t* ann) {
  if (!w)
    return CC_E_ARG;
  cc_pkt_view_t view;
  size_t pre_len = 0;
  int verified = 0;
  int ret;

  if (!in || !ann)
    return CC_E_ARG;
  memset(ann, 0, sizeof(*ann));

  ret = pkt_accept(in, in_sz, CC_MSG_ANNOUNCE, &view);
  if (ret != CC_OK)
    return ret;
  ann->hops = view.hops;
  ann->seq = view.seq;
  ann->expiry = view.expiry;

  memcpy(ann->sign_pubkey, view.f[CC_ANN_SIGN_PUB].p, CC_SIGN_PUBKEY_SZ);
  memcpy(ann->kem_pubkey, view.f[CC_ANN_KEM_PUB].p, CC_KEM_PUBKEY_SZ);
  memcpy(ann->name, view.f[CC_ANN_NAME].p, view.f[CC_ANN_NAME].len);
  ann->name[view.f[CC_ANN_NAME].len] = '\0';
  ann->name_len = view.f[CC_ANN_NAME].len;
  ret = meta_map_ok(view.f[CC_ANN_META].p, view.f[CC_ANN_META].len);
  if (ret != CC_OK)
    return ret; /* structural refusal, before any signature work */
  memcpy(ann->meta, view.f[CC_ANN_META].p, view.f[CC_ANN_META].len);
  ann->meta_len = view.f[CC_ANN_META].len;
  memcpy(ann->admit, view.f[CC_ANN_ADMIT].p, CC_ADMIT_SZ);
  for (ret = 0; ret < CC_ADMIT_SZ; ret++) {
    if (ann->admit[ret] > CC_POW_MAX)
      return CC_E_FORMAT; /* a signed price above the digest width */
  }

  ret = pkt_copy_covered(&view, CC_PKT_LAYOUT[CC_MSG_ANNOUNCE].sign_skip,
                         w->pre, sizeof(w->pre), &pre_len);
  if (ret != CC_OK)
    return ret;

  wc_dilithium_init(&w->verify_key);
  ret = wc_dilithium_set_level(&w->verify_key, CC_SIGN_LEVEL);
  if (ret == 0)
    ret = wc_dilithium_import_public(ann->sign_pubkey, CC_SIGN_PUBKEY_SZ,
                                     &w->verify_key);
  if (ret == 0) {
    ret = wc_dilithium_verify_msg(view.f[CC_ANN_SIG].p,
                                  (word32)view.f[CC_ANN_SIG].len, w->pre,
                                  (word32)pre_len, &verified, &w->verify_key);
  }
  wc_dilithium_free(&w->verify_key);
  wipe(w->pre, sizeof(w->pre));
  if (ret != 0 || !verified)
    return CC_E_SIG;

  /* Only now is anything in this packet trustworthy, the declaration
     included: cc_admit_for() insists on this flag. */
  ann->verified = 1;
  return cc_addr_from_sign_pubkey(ann->sign_pubkey, ann->addr);
}

void cc_admit_default(uint8_t admit[CC_ADMIT_SZ]) {
  if (!admit)
    return;
  admit[CC_ADMIT_CHAT] = CC_POW_DIFFICULTY_CHAT;
  admit[CC_ADMIT_LINK_REQ] = CC_POW_DIFFICULTY_LINK_REQ;
  admit[CC_ADMIT_KEY_REQ] = CC_POW_DIFFICULTY_KEY_REQ;
}

int cc_admit_for(const cc_announce_t* ann, uint8_t type,
                 uint8_t* difficulty_out) {
  uint8_t slot, mine;

  if (!difficulty_out)
    return CC_E_ARG;
  switch (type) {
    case CC_MSG_CHAT:
      slot = CC_ADMIT_CHAT;
      break;
    case CC_MSG_LINK_REQ:
      slot = CC_ADMIT_LINK_REQ;
      break;
    case CC_MSG_KEY_REQ:
      slot = CC_ADMIT_KEY_REQ;
      break;
    default:
      return CC_E_ARG; /* broadcast: nobody to ask, mine your own way */
  }
  /* The declaration is only usable out of a struct a parser filled in: it sits
     inside the signed coverage, so it is worthless before that signature
     verified. */
  if (ann && !ann->verified)
    return CC_E_SIG;

  mine = CC_POW_MIN[type];
  if (!ann)
    *difficulty_out = mine;
  else if (ann->admit[slot] > CC_POW_MAX)
    return CC_E_FORMAT;
  else
    *difficulty_out = (ann->admit[slot] > mine) ? ann->admit[slot] : mine;
  return CC_OK;
}

int cc_announce_fresh(const cc_announce_t* known, const cc_announce_t* fresh,
                      uint32_t now) {
  if (!fresh)
    return CC_E_ARG;
  if (known && known->seq >= fresh->seq)
    return CC_E_STALE; /* not newer than what we already stored */
  if (fresh->expiry != 0 && now >= fresh->expiry)
    return CC_E_STALE; /* expired */
  return CC_OK;
}

/* ---- Identity lifecycle: rotation and revocation (revision 8) ---- */

/* SHA-256 over the domain-separated continuity preimage. This is the only
   thing the old key ever signs, and it is what ties a new signing key to an
   old address in both directions: the address the old key vouched for is the
   one the new key hashes to. */
static int rotate_statement(cc_work_t* w, const uint8_t prev_addr[CC_ADDR_SZ],
                            const uint8_t new_addr[CC_ADDR_SZ],
                            const uint8_t new_sign_pub[CC_SIGN_PUBKEY_SZ],
                            const uint8_t new_kem_pub[CC_KEM_PUBKEY_SZ],
                            uint8_t out[32]) {
  uint8_t* buf = w->pre;
  static const uint8_t label[] = "cosechat/rotate";
  size_t need = sizeof(label) - 1 + 1 + CC_ADDR_SZ + CC_ADDR_SZ +
                CC_SIGN_PUBKEY_SZ + CC_KEM_PUBKEY_SZ;
  size_t n = 0;
  int ret;

  if (need > CC_PRE_SZ)
    return CC_E_ARG;
  memcpy(buf + n, label, sizeof(label) - 1);
  n += sizeof(label) - 1;
  buf[n++] = CC_SUITE;
  memcpy(buf + n, prev_addr, CC_ADDR_SZ);
  n += CC_ADDR_SZ;
  memcpy(buf + n, new_addr, CC_ADDR_SZ);
  n += CC_ADDR_SZ;
  memcpy(buf + n, new_sign_pub, CC_SIGN_PUBKEY_SZ);
  n += CC_SIGN_PUBKEY_SZ;
  memcpy(buf + n, new_kem_pub, CC_KEM_PUBKEY_SZ);
  n += CC_KEM_PUBKEY_SZ;
  ret = (wc_Sha256Hash(buf, (word32)n, out) == 0) ? CC_OK : CC_E_CRYPTO;
  wipe(buf, sizeof(w->pre));
  return ret;
}

int cc_rotate_prev_addr(const uint8_t* pkt, size_t pkt_sz,
                        uint8_t prev_addr[CC_ADDR_SZ]) {
  cc_pkt_view_t view;
  int ret;
  if (!pkt || !prev_addr)
    return CC_E_ARG;
  ret = pkt_decode(pkt, pkt_sz, &view);
  if (ret != CC_OK)
    return ret;
  if (view.type != CC_MSG_ROTATE)
    return CC_E_FORMAT;
  memcpy(prev_addr, view.f[CC_ROT_PREV_ADDR].p, CC_ADDR_SZ);
  return CC_OK;
}

int cc_rotate_build(cc_work_t* w, const cc_key_t* new_key,
                    const cc_key_t* old_key, const char* name, size_t name_len,
                    const uint8_t* meta, size_t meta_len, uint32_t seq,
                    uint32_t expiry, uint8_t* out, size_t out_sz,
                    size_t* out_len, WC_RNG* rng) {
  if (!w)
    return CC_E_ARG;
  uint8_t new_sign[CC_SIGN_PUBKEY_SZ], new_kem[CC_KEM_PUBKEY_SZ];
  uint8_t prev_addr[CC_ADDR_SZ], new_addr[CC_ADDR_SZ];
  uint8_t* csig = w->scratch + 32; /* the statement lives at the front */
  cc_pkt_view_t view = {0};
  size_t n = 0, pre_len = 0;
  word32 csig_len = CC_SIGN_SIG_SZ, sig_len = CC_SIGN_SIG_SZ;
  int ret;

  if (!new_key || !old_key || !out || !out_len || !rng)
    return CC_E_ARG;
  if (name_len > CC_MAX_NAME_LEN || meta_len > CC_MAX_META_SZ)
    return CC_E_ARG;
  if (meta_map_ok(meta, meta_len) != CC_OK)
    return CC_E_ARG;

  ret = cc_key_export_public(new_key, new_sign, new_kem);
  if (ret != CC_OK)
    return ret;
  ret = cc_addr_from_key(old_key, prev_addr);
  if (ret != CC_OK)
    return ret;
  ret = cc_addr_from_sign_pubkey(new_sign, new_addr);
  if (ret != CC_OK)
    return ret;

  /* The old key vouches for the successor, once, over the statement. */
  ret = rotate_statement(w, prev_addr, new_addr, new_sign, new_kem, w->scratch);
  if (ret != CC_OK)
    return ret;
  if (wc_dilithium_sign_msg(w->scratch, 32, csig, &csig_len,
                            (dilithium_key*)&old_key->sign, rng) != 0) {
    wipe(w->scratch, sizeof(w->scratch));
    return CC_E_CRYPTO;
  }

  view.type = CC_MSG_ROTATE;
  view.seq = seq;
  view.expiry = expiry;
  view.f[CC_ROT_SIGN_PUB].p = new_sign;
  view.f[CC_ROT_SIGN_PUB].len = CC_SIGN_PUBKEY_SZ;
  view.f[CC_ROT_KEM_PUB].p = new_kem;
  view.f[CC_ROT_KEM_PUB].len = CC_KEM_PUBKEY_SZ;
  view.f[CC_ROT_NAME].p = (const uint8_t*)(name ? name : "");
  view.f[CC_ROT_NAME].len = name ? name_len : 0;
  view.f[CC_ROT_META].p = meta;
  view.f[CC_ROT_META].len = meta_len;
  view.f[CC_ROT_PREV_ADDR].p = prev_addr;
  view.f[CC_ROT_PREV_ADDR].len = CC_ADDR_SZ;
  view.f[CC_ROT_SIG].p = w->sig;
  view.f[CC_ROT_SIG].len = CC_SIGN_SIG_SZ;
  view.f[CC_ROT_CONT].p = csig;
  view.f[CC_ROT_CONT].len = csig_len;

  ret = pkt_encode(&view, 0, 0, out, out_sz, &n);
  if (ret != CC_OK) {
    wipe(w->scratch, sizeof(w->scratch));
    return ret;
  }
  ret = pkt_copy_covered(&view, CC_PKT_LAYOUT[CC_MSG_ROTATE].sign_skip, w->pre,
                         sizeof(w->pre), &pre_len);
  if (ret != CC_OK) {
    wipe(w->scratch, sizeof(w->scratch));
    return ret;
  }
  /* The new key owns the packet: the ordinary coverage rule, which includes
     the continuity signature. */
  if (wc_dilithium_sign_msg(w->pre, (word32)pre_len, w->sig, &sig_len,
                            (dilithium_key*)&new_key->sign, rng) != 0) {
    wipe(w->pre, sizeof(w->pre));
    wipe(w->scratch, sizeof(w->scratch));
    return CC_E_CRYPTO;
  }
  wipe(w->pre, sizeof(w->pre));
  view.f[CC_ROT_SIG].len = sig_len;
  ret = pkt_finish(&view, 0, out, out_sz, out_len); /* needs csig alive */
  wipe(w->scratch, sizeof(w->scratch));
  return ret;
}

int cc_rotate_parse(cc_work_t* w, const uint8_t* in, size_t in_sz,
                    const uint8_t old_sign_pub[CC_SIGN_PUBKEY_SZ],
                    cc_announce_t* ann, uint8_t prev_addr[CC_ADDR_SZ]) {
  if (!w)
    return CC_E_ARG;
  cc_pkt_view_t view;
  uint8_t old_addr[CC_ADDR_SZ], new_addr[CC_ADDR_SZ];
  size_t pre_len = 0;
  int verified = 0;
  int ret;

  if (!in || !old_sign_pub || !ann || !prev_addr)
    return CC_E_ARG;
  memset(ann, 0, sizeof(*ann));

  ret = pkt_accept(in, in_sz, CC_MSG_ROTATE, &view);
  if (ret != CC_OK)
    return ret;
  ann->hops = view.hops;
  ann->seq = view.seq;
  ann->expiry = view.expiry;
  memcpy(ann->sign_pubkey, view.f[CC_ROT_SIGN_PUB].p, CC_SIGN_PUBKEY_SZ);
  memcpy(ann->kem_pubkey, view.f[CC_ROT_KEM_PUB].p, CC_KEM_PUBKEY_SZ);
  memcpy(ann->name, view.f[CC_ROT_NAME].p, view.f[CC_ROT_NAME].len);
  ann->name[view.f[CC_ROT_NAME].len] = '\0';
  ann->name_len = view.f[CC_ROT_NAME].len;
  ret = meta_map_ok(view.f[CC_ROT_META].p, view.f[CC_ROT_META].len);
  if (ret != CC_OK)
    return ret;
  memcpy(ann->meta, view.f[CC_ROT_META].p, view.f[CC_ROT_META].len);
  ann->meta_len = view.f[CC_ROT_META].len;
  memcpy(ann->prev_addr, view.f[CC_ROT_PREV_ADDR].p, CC_ADDR_SZ);
  memcpy(prev_addr, ann->prev_addr, CC_ADDR_SZ);

  /* The key the caller holds for prev_addr must really hash to prev_addr: a
     stale cache entry must not be able to vouch for someone else. */
  ret = cc_addr_from_sign_pubkey(old_sign_pub, old_addr);
  if (ret != CC_OK)
    return ret;
  if (memcmp(old_addr, prev_addr, CC_ADDR_SZ) != 0)
    return CC_E_NOKEY;

  /* And the old key must have signed for the address the new key hashes to. */
  ret = cc_addr_from_sign_pubkey(ann->sign_pubkey, new_addr);
  if (ret != CC_OK)
    return ret;
  ret = rotate_statement(w, prev_addr, new_addr, ann->sign_pubkey,
                         ann->kem_pubkey, w->scratch);
  if (ret != CC_OK)
    return ret;

  wc_dilithium_init(&w->verify_key);
  ret = wc_dilithium_set_level(&w->verify_key, CC_SIGN_LEVEL);
  if (ret == 0)
    ret = wc_dilithium_import_public((uint8_t*)old_sign_pub, CC_SIGN_PUBKEY_SZ,
                                     &w->verify_key);
  if (ret == 0)
    ret = wc_dilithium_verify_msg(view.f[CC_ROT_CONT].p,
                                  (word32)view.f[CC_ROT_CONT].len, w->scratch,
                                  32, &verified, &w->verify_key);
  wc_dilithium_free(&w->verify_key);
  wipe(w->scratch, sizeof(w->scratch));
  if (ret != 0 || !verified)
    return CC_E_SIG;

  /* Then the new key owns the packet, by the ordinary coverage rule. */
  ret = pkt_copy_covered(&view, CC_PKT_LAYOUT[CC_MSG_ROTATE].sign_skip, w->pre,
                         sizeof(w->pre), &pre_len);
  if (ret != CC_OK)
    return ret;
  verified = 0;
  wc_dilithium_init(&w->verify_key);
  ret = wc_dilithium_set_level(&w->verify_key, CC_SIGN_LEVEL);
  if (ret == 0)
    ret = wc_dilithium_import_public(ann->sign_pubkey, CC_SIGN_PUBKEY_SZ,
                                     &w->verify_key);
  if (ret == 0)
    ret = wc_dilithium_verify_msg(view.f[CC_ROT_SIG].p,
                                  (word32)view.f[CC_ROT_SIG].len, w->pre,
                                  (word32)pre_len, &verified, &w->verify_key);
  wc_dilithium_free(&w->verify_key);
  wipe(w->pre, sizeof(w->pre));
  if (ret != 0 || !verified)
    return CC_E_SIG;

  ann->verified = 1;
  memcpy(ann->addr, new_addr, CC_ADDR_SZ);
  return CC_OK;
}

int cc_rotate_accept(const cc_announce_t* have, const cc_announce_t* rot,
                     const cc_revoked_t* revoked, uint32_t now) {
  if (!rot)
    return CC_E_ARG;
  /* A retired predecessor cannot vouch for a successor: this is the leaked-key
     case, checked first so a caller can count it. A revocation ends the
     identity chain, so a revoked node continues with a fresh identity rather
     than a successor. */
  if (revoked && cc_revoked_check(revoked, rot->prev_addr, now) != CC_OK)
    return CC_E_REVOKED;
  if (have) {
    /* It must be the successor of the identity we cached, and strictly newer
       than what we already moved to: the same rule as an announce, extended
       across the address change, so a replay is idempotent and a re-ordered
       rotation cannot downgrade. */
    if (memcmp(rot->prev_addr, have->addr, CC_ADDR_SZ) != 0)
      return CC_E_STALE;
    if (have->seq >= rot->seq)
      return CC_E_STALE;
  }
  if (rot->expiry != 0 && now >= rot->expiry)
    return CC_E_STALE;
  return CC_OK;
}

int cc_revoke_build(cc_work_t* w, const cc_key_t* key, uint32_t seq,
                    uint32_t expiry, uint8_t* out, size_t out_sz,
                    size_t* out_len, WC_RNG* rng) {
  if (!w)
    return CC_E_ARG;
  uint8_t addr[CC_ADDR_SZ];
  cc_pkt_view_t view = {0};
  size_t n = 0, pre_len = 0;
  word32 sig_len = CC_SIGN_SIG_SZ;
  int ret;

  if (!key || !out || !out_len || !rng)
    return CC_E_ARG;
  ret = cc_addr_from_key(key, addr);
  if (ret != CC_OK)
    return ret;

  view.type = CC_MSG_REVOKE;
  view.seq = seq;
  view.expiry = expiry;
  view.f[CC_REV_ADDR].p = addr;
  view.f[CC_REV_ADDR].len = CC_ADDR_SZ;
  view.f[CC_REV_SIG].p = w->sig;
  view.f[CC_REV_SIG].len = CC_SIGN_SIG_SZ;

  ret = pkt_encode(&view, 0, 0, out, out_sz, &n);
  if (ret != CC_OK)
    return ret;
  ret = pkt_copy_covered(&view, CC_PKT_LAYOUT[CC_MSG_REVOKE].sign_skip, w->pre,
                         sizeof(w->pre), &pre_len);
  if (ret != CC_OK)
    return ret;
  if (wc_dilithium_sign_msg(w->pre, (word32)pre_len, w->sig, &sig_len,
                            (dilithium_key*)&key->sign, rng) != 0) {
    wipe(w->pre, sizeof(w->pre));
    return CC_E_CRYPTO;
  }
  wipe(w->pre, sizeof(w->pre));
  view.f[CC_REV_SIG].len = sig_len;
  return pkt_finish(&view, 0, out, out_sz, out_len);
}

int cc_revoke_parse(cc_work_t* w, const uint8_t* in, size_t in_sz,
                    const uint8_t sign_pub[CC_SIGN_PUBKEY_SZ],
                    uint8_t addr[CC_ADDR_SZ], uint32_t* seq_out,
                    uint32_t* expiry_out) {
  if (!w)
    return CC_E_ARG;
  cc_pkt_view_t view;
  uint8_t claimed[CC_ADDR_SZ];
  size_t pre_len = 0;
  int verified = 0;
  int ret;

  if (!in || !sign_pub || !addr || !seq_out || !expiry_out)
    return CC_E_ARG;
  ret = pkt_accept(in, in_sz, CC_MSG_REVOKE, &view);
  if (ret != CC_OK)
    return ret;

  /* Only the identity can retire itself: the address in the packet must be the
     one the verifying key hashes to. */
  ret = cc_addr_from_sign_pubkey(sign_pub, claimed);
  if (ret != CC_OK)
    return ret;
  if (memcmp(claimed, view.f[CC_REV_ADDR].p, CC_ADDR_SZ) != 0)
    return CC_E_NOKEY;

  ret = pkt_copy_covered(&view, CC_PKT_LAYOUT[CC_MSG_REVOKE].sign_skip, w->pre,
                         sizeof(w->pre), &pre_len);
  if (ret != CC_OK)
    return ret;
  wc_dilithium_init(&w->verify_key);
  ret = wc_dilithium_set_level(&w->verify_key, CC_SIGN_LEVEL);
  if (ret == 0)
    ret = wc_dilithium_import_public((uint8_t*)sign_pub, CC_SIGN_PUBKEY_SZ,
                                     &w->verify_key);
  if (ret == 0)
    ret = wc_dilithium_verify_msg(view.f[CC_REV_SIG].p,
                                  (word32)view.f[CC_REV_SIG].len, w->pre,
                                  (word32)pre_len, &verified, &w->verify_key);
  wc_dilithium_free(&w->verify_key);
  wipe(w->pre, sizeof(w->pre));
  if (ret != 0 || !verified)
    return CC_E_SIG;

  memcpy(addr, view.f[CC_REV_ADDR].p, CC_ADDR_SZ);
  *seq_out = view.seq;
  *expiry_out = view.expiry;
  return CC_OK;
}

int cc_revoked_init(cc_revoked_t* rv) {
  if (!rv)
    return CC_E_ARG;
  memset(rv, 0, sizeof(*rv));
  return CC_OK;
}

int cc_revoked_take(cc_revoked_t* rv, const uint8_t addr[CC_ADDR_SZ],
                    uint32_t seq, uint32_t expiry) {
  if (!rv || !addr)
    return CC_E_ARG;
  memcpy(rv->addr, addr, CC_ADDR_SZ);
  rv->seq = seq;
  rv->expiry = expiry;
  rv->used = 1;
  return CC_OK;
}

int cc_revoked_check(const cc_revoked_t* rv, const uint8_t addr[CC_ADDR_SZ],
                     uint32_t now) {
  if (!rv || !addr)
    return CC_E_ARG;
  if (!rv->used)
    return CC_OK; /* nothing retired */
  if (memcmp(rv->addr, addr, CC_ADDR_SZ) != 0)
    return CC_OK; /* a different peer */
  if (rv->expiry != 0 && now > rv->expiry)
    return CC_OK;      /* the caller's horizon for remembering it has passed */
  return CC_E_REVOKED; /* drop the peer, refuse links and rotations from it */
}

int cc_revoked_forget(cc_revoked_t* rv) {
  if (!rv)
    return CC_E_ARG;
  wipe(rv, sizeof(*rv));
  return CC_OK;
}

int cc_replay_move(cc_replay_t* st, const uint8_t addr[CC_ADDR_SZ],
                   uint32_t floor, uint8_t continues) {
  if (!st || !addr)
    return CC_E_ARG;
  if (st->cls != CC_REPLAY_AUTHED && st->cls != CC_REPLAY_UNSIGNED)
    return CC_E_ARG;
  if (continues != CC_REPLAY_CONTINUES && continues != CC_REPLAY_RESTARTS)
    return CC_E_ARG; /* the caller must say which counter space this is */
  memcpy(st->addr, addr, CC_ADDR_SZ);
  if (continues == CC_REPLAY_RESTARTS) {
    /* Fresh state at the new address: no counter to carry, so the next packet
       sets the window. The caller has accepted one replay opportunity. */
    st->used = 0;
    st->high = 0;
    st->seen = 0;
    return CC_OK;
  }
  if (st->used) {
    /* The high-water comes along, and counts as seen: the node's last message
       cannot be replayed into the new address. */
    st->high = floor;
    st->seen = 1;
  }
  return CC_OK;
}

int cc_chat_build(cc_work_t* w, const cc_key_t* sender_key,
                  const uint8_t recipient_addr[CC_ADDR_SZ],
                  const uint8_t recipient_kem_pub[CC_KEM_PUBKEY_SZ],
                  uint32_t counter, const uint8_t* msg, size_t msg_len,
                  uint8_t difficulty, uint8_t* out, size_t out_sz,
                  size_t* out_len, WC_RNG* rng) {
  if (!w)
    return CC_E_ARG;
  uint8_t aes_key[32];
  uint8_t iv[12];
  uint8_t sender_addr[CC_ADDR_SZ];
  cc_pkt_view_t view = {0};
  WOLFCOSE_KEY cose_sym;
  size_t payload_len = 0, enc0_len = 0, aad_len = 0, pre_len = 0, n = 0;
  word32 sig_len = CC_SIGN_SIG_SZ;
  int ret;

  if (!sender_key || !recipient_addr || !recipient_kem_pub || !msg || !out ||
      !out_len || !rng)
    return CC_E_ARG;
  if (msg_len > CC_MAX_MSG_SZ || difficulty > CC_POW_MAX)
    return CC_E_ARG;

  ret = cc_addr_from_key(sender_key, sender_addr);
  if (ret != CC_OK)
    return ret;

  ret = kem_encap(w, recipient_kem_pub, w->kem_ct, aes_key, rng);
  if (ret != CC_OK)
    return ret;

  ret = enc_chat_payload(w->pt, sizeof(w->pt), &payload_len, sender_addr, msg,
                         msg_len);
  if (ret != CC_OK) {
    wc_ForceZero(aes_key, 32);
    return ret;
  }

  ret = wc_RNG_GenerateBlock(rng, iv, sizeof(iv));
  if (ret != 0) {
    wc_ForceZero(aes_key, 32);
    return CC_E_CRYPTO;
  }

  view.type = CC_MSG_CHAT;
  view.counter = counter;
  view.f[CC_CHAT_SENDER].p = sender_addr;
  view.f[CC_CHAT_SENDER].len = CC_ADDR_SZ;
  view.f[CC_CHAT_RECIPIENT].p = recipient_addr;
  view.f[CC_CHAT_RECIPIENT].len = CC_ADDR_SZ;
  view.f[CC_CHAT_KEM_CT].p = w->kem_ct;
  view.f[CC_CHAT_KEM_CT].len = CC_KEM_CT_SZ;
  view.f[CC_CHAT_ENCRYPT0].p = w->ct;
  view.f[CC_CHAT_ENCRYPT0].len = 0;
  view.f[CC_CHAT_SIG].p = w->sig;
  view.f[CC_CHAT_SIG].len = CC_SIGN_SIG_SZ;

  ret = pkt_encode(&view, 0, 0, out, out_sz, &n);
  if (ret != CC_OK) {
    wc_ForceZero(aes_key, 32);
    return ret;
  }
  ret = pkt_copy_covered(&view, CC_PKT_LAYOUT[CC_MSG_CHAT].aad_skip, w->pre,
                         sizeof(w->pre), &aad_len);
  if (ret != CC_OK) {
    wc_ForceZero(aes_key, 32);
    return ret;
  }

  wc_CoseKey_Init(&cose_sym);
  ret = wc_CoseKey_SetSymmetric(&cose_sym, aes_key, 32);
  if (ret != WOLFCOSE_SUCCESS) {
    wc_ForceZero(aes_key, 32);
    return CC_E_CRYPTO;
  }
  ret = wc_CoseEncrypt0_Encrypt(&cose_sym, WOLFCOSE_ALG_A256GCM, iv, sizeof(iv),
                                w->pt, payload_len, NULL, 0, NULL, w->pre,
                                aad_len, w->scratch, sizeof(w->scratch), w->ct,
                                sizeof(w->ct), &enc0_len);
  wc_CoseKey_Free(&cose_sym);
  wc_ForceZero(aes_key, 32);
  wipe(w->scratch, sizeof(w->scratch));
  wipe(w->pt, sizeof(w->pt));
  if (ret != WOLFCOSE_SUCCESS)
    return CC_E_CRYPTO;

  view.f[CC_CHAT_ENCRYPT0].len = enc0_len;
  ret = pkt_encode(&view, 0, 0, out, out_sz, &n);
  if (ret != CC_OK)
    return ret;
  ret = pkt_copy_covered(&view, CC_PKT_LAYOUT[CC_MSG_CHAT].sign_skip, w->pre,
                         sizeof(w->pre), &pre_len);
  if (ret != CC_OK)
    return ret;
  if (wc_dilithium_sign_msg(w->pre, (word32)pre_len, w->sig, &sig_len,
                            (dilithium_key*)&sender_key->sign, rng) != 0)
    return CC_E_CRYPTO;
  wipe(w->pre, sizeof(w->pre));
  view.f[CC_CHAT_SIG].len = sig_len;

  return pkt_finish(&view, difficulty, out, out_sz, out_len);
}

int cc_chat_parse(cc_work_t* w, const cc_key_t* my_key,
                  const uint8_t sender_sign_pub[CC_SIGN_PUBKEY_SZ],
                  cc_replay_t* replay, const uint8_t* in, size_t in_sz,
                  cc_chat_t* chat) {
  if (!w)
    return CC_E_ARG;
  cc_pkt_view_t view;
  uint8_t aes_key[32];
  uint8_t claimed[CC_ADDR_SZ];
  uint8_t inner_sender[CC_ADDR_SZ];
  WOLFCOSE_KEY cose_sym;
  WOLFCOSE_HDR hdr;
  size_t pt_len = 0, aad_len = 0, pre_len = 0;
  int verified = 0;
  int ret;

  if (!my_key || !replay || !in || !chat)
    return CC_E_ARG;
  memset(chat, 0, sizeof(*chat));

  ret = pkt_accept(in, in_sz, CC_MSG_CHAT, &view);
  if (ret != CC_OK)
    return ret;
  chat->hops = view.hops;
  chat->counter = view.counter;

  if (!sender_sign_pub)
    return CC_E_NOKEY;
  ret = cc_addr_from_sign_pubkey(sender_sign_pub, claimed);
  if (ret != CC_OK)
    return ret;
  if (memcmp(claimed, view.f[CC_CHAT_SENDER].p, CC_ADDR_SZ) != 0)
    return CC_E_NOKEY;

  ret = pkt_copy_covered(&view, CC_PKT_LAYOUT[CC_MSG_CHAT].sign_skip, w->pre,
                         sizeof(w->pre), &pre_len);
  if (ret != CC_OK)
    return ret;
  wc_dilithium_init(&w->verify_key);
  ret = wc_dilithium_set_level(&w->verify_key, CC_SIGN_LEVEL);
  if (ret == 0)
    ret = wc_dilithium_import_public((uint8_t*)sender_sign_pub,
                                     CC_SIGN_PUBKEY_SZ, &w->verify_key);
  if (ret == 0) {
    ret = wc_dilithium_verify_msg(view.f[CC_CHAT_SIG].p,
                                  (word32)view.f[CC_CHAT_SIG].len, w->pre,
                                  (word32)pre_len, &verified, &w->verify_key);
  }
  wc_dilithium_free(&w->verify_key);
  wipe(w->pre, sizeof(w->pre));
  if (ret != 0 || !verified)
    return CC_E_SIG;

  ret = replay_step(replay, CC_REPLAY_AUTHED, view.f[CC_CHAT_SENDER].p,
                    view.counter, 0);
  if (ret != CC_OK)
    return ret;

  ret = pkt_copy_covered(&view, CC_PKT_LAYOUT[CC_MSG_CHAT].aad_skip, w->pre,
                         sizeof(w->pre), &aad_len);
  if (ret != CC_OK)
    return ret;

  ret = kem_decap((KyberKey*)&my_key->kem, view.f[CC_CHAT_KEM_CT].p,
                  view.f[CC_CHAT_KEM_CT].len, aes_key);
  if (ret != CC_OK)
    return ret;

  wc_CoseKey_Init(&cose_sym);
  ret = wc_CoseKey_SetSymmetric(&cose_sym, aes_key, 32);
  if (ret != WOLFCOSE_SUCCESS) {
    wc_ForceZero(aes_key, 32);
    return CC_E_CRYPTO;
  }

  ret = wc_CoseEncrypt0_Decrypt(&cose_sym, view.f[CC_CHAT_ENCRYPT0].p,
                                view.f[CC_CHAT_ENCRYPT0].len, NULL, 0, w->pre,
                                aad_len, w->scratch, sizeof(w->scratch), &hdr,
                                w->pt, sizeof(w->pt), &pt_len);
  wc_CoseKey_Free(&cose_sym);
  wc_ForceZero(aes_key, 32);
  wipe(w->pre, sizeof(w->pre));
  if (ret != WOLFCOSE_SUCCESS) {
    wipe(w->scratch, sizeof(w->scratch));
    return CC_E_DECRYPT;
  }

  ret =
      dec_chat_payload(w->pt, pt_len, inner_sender, chat->msg, &chat->msg_len);
  wipe(w->pt, sizeof(w->pt));
  wipe(w->scratch, sizeof(w->scratch));
  if (ret != CC_OK)
    return ret;
  if (memcmp(inner_sender, view.f[CC_CHAT_SENDER].p, CC_ADDR_SZ) != 0)
    return CC_E_DECRYPT;

  memcpy(chat->sender_addr, inner_sender, CC_ADDR_SZ);
  return replay_step(replay, CC_REPLAY_AUTHED, view.f[CC_CHAT_SENDER].p,
                     view.counter, 1);
}

int cc_presence_build(cc_work_t* w, const cc_key_t* key, const char* name,
                      size_t name_len, uint32_t seq, uint8_t* out,
                      size_t out_sz, size_t* out_len, WC_RNG* rng) {
  if (!w)
    return CC_E_ARG;
  uint8_t addr[CC_ADDR_SZ];
  uint8_t name_hash[CC_PRES_NAME_HASH_SZ];
  cc_pkt_view_t view = {0};
  int ret;
  if (!key || !out || !out_len || !rng)
    return CC_E_ARG;
  if (name_len > CC_MAX_NAME_LEN)
    return CC_E_ARG;
  ret = cc_addr_from_key(key, addr);
  if (ret != CC_OK)
    return ret;
  ret = cc_name_hash(name ? name : "", name ? name_len : 0, name_hash);
  if (ret != CC_OK)
    return ret;
  view.type = CC_MSG_PRESENCE;
  view.seq = seq;
  view.f[CC_PRES_ADDR].p = addr;
  view.f[CC_PRES_ADDR].len = CC_ADDR_SZ;
  view.f[CC_PRES_NAME_HASH].p = name_hash;
  view.f[CC_PRES_NAME_HASH].len = CC_PRES_NAME_HASH_SZ;
  return pkt_finish(&view, 0, out, out_sz, out_len); /* broadcast: own policy */
}

int cc_presence_parse(cc_work_t* w, const uint8_t* in, size_t in_sz,
                      cc_presence_t* p) {
  if (!w)
    return CC_E_ARG;
  cc_pkt_view_t view;
  int ret;
  if (!in || !p)
    return CC_E_ARG;
  memset(p, 0, sizeof(*p));

  ret = pkt_accept(in, in_sz, CC_MSG_PRESENCE, &view);
  if (ret != CC_OK)
    return ret;
  p->hops = view.hops;
  p->seq = view.seq;

  memcpy(p->addr, view.f[CC_PRES_ADDR].p, CC_ADDR_SZ);
  memcpy(p->name_hash, view.f[CC_PRES_NAME_HASH].p, CC_PRES_NAME_HASH_SZ);
  return CC_OK;
}

int cc_name_hash(const char* name, size_t name_len, uint8_t out[8]) {
  uint8_t h[32];
  if (!name || !out)
    return CC_E_ARG;
  if (wc_Sha256Hash((const uint8_t*)name, (word32)name_len, h) != 0)
    return CC_E_CRYPTO;
  memcpy(out, h, CC_PRES_NAME_HASH_SZ);
  return CC_OK;
}

int cc_presence_matches_announce(const cc_presence_t* p,
                                 const cc_announce_t* ann) {
  uint8_t h[CC_PRES_NAME_HASH_SZ];
  if (!p || !ann)
    return CC_E_ARG;
  if (memcmp(p->addr, ann->addr, CC_ADDR_SZ) != 0)
    return CC_E_STALE;
  if (cc_name_hash(ann->name, ann->name_len, h) != CC_OK)
    return CC_E_CRYPTO;
  return (memcmp(p->name_hash, h, CC_PRES_NAME_HASH_SZ) == 0) ? CC_OK
                                                              : CC_E_STALE;
}

int cc_key_req_build(cc_work_t* w, const uint8_t addr[CC_ADDR_SZ],
                     uint32_t counter, uint8_t difficulty, uint8_t* out,
                     size_t out_sz, size_t* out_len) {
  if (!w)
    return CC_E_ARG;
  cc_pkt_view_t view = {0};
  if (!addr || !out || !out_len || difficulty > CC_POW_MAX)
    return CC_E_ARG;
  view.type = CC_MSG_KEY_REQ;
  view.seq = counter;
  view.f[CC_REQ_ADDR].p = addr;
  view.f[CC_REQ_ADDR].len = CC_ADDR_SZ;
  return pkt_finish(&view, difficulty, out, out_sz, out_len);
}

int cc_key_req_parse(cc_work_t* w, const uint8_t* in, size_t in_sz,
                     uint8_t addr[CC_ADDR_SZ], uint32_t* counter_out) {
  if (!w)
    return CC_E_ARG;
  cc_pkt_view_t view;
  int ret;
  if (!in || !addr || !counter_out)
    return CC_E_ARG;

  ret = pkt_accept(in, in_sz, CC_MSG_KEY_REQ, &view);
  if (ret != CC_OK)
    return ret;

  memcpy(addr, view.f[CC_REQ_ADDR].p, CC_ADDR_SZ);
  *counter_out = view.seq;
  return CC_OK;
}

int cc_replay_init(cc_replay_t* st, const uint8_t addr[CC_ADDR_SZ],
                   uint8_t cls) {
  if (!st || !addr || (cls != CC_REPLAY_AUTHED && cls != CC_REPLAY_UNSIGNED))
    return CC_E_ARG;
  memset(st, 0, sizeof(*st));
  memcpy(st->addr, addr, CC_ADDR_SZ);
  st->cls = cls;
  return CC_OK;
}

int cc_replay_check(cc_replay_t* st, const uint8_t addr[CC_ADDR_SZ],
                    uint32_t counter) {
  return replay_step(st, CC_REPLAY_UNSIGNED, addr, counter, 1);
}

/* ---- Links ---- */

uint8_t cc_suite(void) { return CC_SUITE; }

void cc_work_free(cc_work_t* w) {
  if (w)
    wipe(w, sizeof(*w));
}

int cc_link_start(cc_work_t* w, cc_link_t* l,
                  const uint8_t peer_addr[CC_ADDR_SZ],
                  const uint8_t peer_kem_pub[CC_KEM_PUBKEY_SZ], uint32_t now,
                  uint32_t idle_timeout, uint8_t difficulty, uint8_t* out,
                  size_t out_sz, size_t* out_len, WC_RNG* rng) {
  if (!w)
    return CC_E_ARG;
  uint8_t ss[CC_KEM_SS_SZ];
  uint8_t th[32];
  cc_pkt_view_t view = {0};
  int ret;

  if (!l || !peer_addr || !peer_kem_pub || !out || !out_len || !rng)
    return CC_E_ARG;
  if (difficulty > CC_POW_MAX)
    return CC_E_ARG;
  memset(l, 0, sizeof(*l));

  ret = kem_encap_ss(w, peer_kem_pub, w->kem_ct, ss, rng);
  if (ret != CC_OK)
    return ret;

  ret = wc_RNG_GenerateBlock(rng, l->id, CC_LINK_ID_SZ);
  if (ret != 0) {
    wipe(ss, CC_KEM_SS_SZ);
    return CC_E_CRYPTO;
  }
  memcpy(l->peer, peer_addr, CC_ADDR_SZ);
  l->role = CC_LINK_ROLE_INITIATOR;
  l->state = CC_LINK_STATE_PENDING;
  l->suite = CC_SUITE;
  l->used = 1;
  l->last_seen = now;
  l->expiry = idle_timeout;

  ret = link_transcript_hash(w, CC_SUITE, l->id, w->kem_ct, CC_KEM_CT_SZ,
                             peer_addr, th);
  if (ret != CC_OK)
    return ret;
  ret = link_derive(w, l, ss, w->kem_ct, CC_KEM_CT_SZ, th);
  wipe(ss, CC_KEM_SS_SZ);
  if (ret != CC_OK)
    return ret;
  /* Kept so cc_link_confirm can check the proof without retaining kem_ct. */
  memcpy(l->th, th, 32);

  view.type = CC_MSG_LINK_REQ;
  view.suite = CC_SUITE;
  view.f[CC_LINK_ID].p = l->id;
  view.f[CC_LINK_ID].len = CC_LINK_ID_SZ;
  view.f[CC_LINK_KEM_CT].p = w->kem_ct;
  view.f[CC_LINK_KEM_CT].len = CC_KEM_CT_SZ;
  return pkt_finish(&view, difficulty, out, out_sz, out_len);
}

int cc_link_accept(cc_work_t* w, cc_link_t* l, const cc_key_t* my_key,
                   uint32_t now, uint32_t idle_timeout, const uint8_t* req,
                   size_t req_sz, uint8_t* out, size_t out_sz, size_t* out_len,
                   WC_RNG* rng) {
  if (!w)
    return CC_E_ARG;
  cc_pkt_view_t view;
  uint8_t ss[CC_KEM_SS_SZ];
  uint8_t th[32];
  uint8_t my_addr[CC_ADDR_SZ];
  word32 sig_len = CC_SIGN_SIG_SZ;
  int ret;

  if (!l || !my_key || !req || !out || !out_len || !rng)
    return CC_E_ARG;
  memset(l, 0, sizeof(*l));

  ret = pkt_accept(req, req_sz, CC_MSG_LINK_REQ, &view);
  if (ret != CC_OK)
    return ret;
  if (view.suite != CC_SUITE)
    return CC_E_SUITE;

  ret = cc_addr_from_key(my_key, my_addr);
  if (ret != CC_OK)
    return ret;

  memcpy(l->id, view.f[CC_LINK_ID].p, CC_LINK_ID_SZ);
  l->role = CC_LINK_ROLE_RESPONDER;
  l->state =
      CC_LINK_STATE_OPEN; /* open to the responder the moment it proves */
  l->suite = CC_SUITE;
  l->used = 1;
  l->last_seen = now;
  l->expiry = idle_timeout;

  ret = kem_decap_ss((KyberKey*)&my_key->kem, view.f[CC_LINK_KEM_CT].p,
                     view.f[CC_LINK_KEM_CT].len, ss);
  if (ret != CC_OK)
    return ret;
  ret = link_transcript_hash(w, CC_SUITE, l->id, view.f[CC_LINK_KEM_CT].p,
                             view.f[CC_LINK_KEM_CT].len, my_addr, th);
  if (ret != CC_OK) {
    wipe(ss, CC_KEM_SS_SZ);
    return ret;
  }
  ret = link_derive(w, l, ss, view.f[CC_LINK_KEM_CT].p,
                    view.f[CC_LINK_KEM_CT].len, th);
  wipe(ss, CC_KEM_SS_SZ);
  if (ret != CC_OK)
    return ret;

  /* The proof signs the transcript hash with the responder's ML-DSA key. */
  if (wc_dilithium_sign_msg(th, 32, w->sig, &sig_len,
                            (dilithium_key*)&my_key->sign, rng) != 0)
    return CC_E_CRYPTO;

  {
    cc_pkt_view_t pv = {0};
    pv.type = CC_MSG_LINK_PROOF;
    pv.suite = CC_SUITE;
    pv.f[CC_LINK_ID].p = l->id;
    pv.f[CC_LINK_ID].len = CC_LINK_ID_SZ;
    pv.f[CC_LINK_SIG].p = w->sig;
    pv.f[CC_LINK_SIG].len = sig_len;
    ret = pkt_finish(&pv, 0, out, out_sz, out_len);
  }
  return ret;
}

int cc_link_confirm(cc_work_t* w, cc_link_t* l,
                    const uint8_t peer_addr[CC_ADDR_SZ],
                    const uint8_t peer_sign_pub[CC_SIGN_PUBKEY_SZ],
                    const uint8_t* proof, size_t proof_sz) {
  if (!w)
    return CC_E_ARG;
  cc_pkt_view_t view;
  uint8_t claimed[CC_ADDR_SZ];
  int verified = 0;
  int ret;

  if (!l || !peer_addr || !peer_sign_pub || !proof)
    return CC_E_ARG;
  if (!l->used || l->role != CC_LINK_ROLE_INITIATOR)
    return CC_E_NOLINK;

  ret = pkt_accept(proof, proof_sz, CC_MSG_LINK_PROOF, &view);
  if (ret != CC_OK)
    return ret;
  if (view.suite != CC_SUITE)
    return CC_E_SUITE;
  if (view.f[CC_LINK_ID].len != CC_LINK_ID_SZ ||
      memcmp(view.f[CC_LINK_ID].p, l->id, CC_LINK_ID_SZ) != 0)
    return CC_E_SIG; /* a proof for a different link */

  ret = cc_addr_from_sign_pubkey(peer_sign_pub, claimed);
  if (ret != CC_OK)
    return ret;
  if (memcmp(claimed, peer_addr, CC_ADDR_SZ) != 0)
    return CC_E_NOKEY; /* the supplied key is not this peer's */

  /* The proof signs the transcript hash the initiator computed at start time
     and stored in l->th, so the kem_ct does not have to be retained. */
  ret = 0;

  wc_dilithium_init(&w->verify_key);
  ret = wc_dilithium_set_level(&w->verify_key, CC_SIGN_LEVEL);
  if (ret == 0)
    ret = wc_dilithium_import_public((uint8_t*)peer_sign_pub, CC_SIGN_PUBKEY_SZ,
                                     &w->verify_key);
  if (ret == 0) {
    ret = wc_dilithium_verify_msg(view.f[CC_LINK_SIG].p,
                                  (word32)view.f[CC_LINK_SIG].len, l->th, 32,
                                  &verified, &w->verify_key);
  }
  wc_dilithium_free(&w->verify_key);
  if (ret != 0 || !verified)
    return CC_E_SIG;

  l->state = CC_LINK_STATE_OPEN;
  return CC_OK;
}

int cc_link_send(cc_work_t* w, cc_link_t* l, uint8_t kind,
                 const uint8_t* payload, size_t payload_len, uint32_t now,
                 uint8_t* out, size_t out_sz, size_t* out_len) {
  if (!w)
    return CC_E_ARG;
  cc_pkt_view_t view = {0};
  size_t pt_len = 0;
  int ret;

  if (!l || !out || !out_len)
    return CC_E_ARG;
  if (l->state != CC_LINK_STATE_OPEN || !l->used)
    return CC_E_NOLINK;
  if (link_idle(l, now))
    return CC_E_NOLINK;
  if (payload_len > CC_LINK_PT_SZ - 8)
    return CC_E_ARG;

  ret = link_record_enc(kind, payload, payload_len, w->pt, sizeof(w->pt),
                        &pt_len);
  if (ret != CC_OK)
    return ret;

  /* Seal the record: the ciphertext is pt_len + 16 bytes in w->ct. */
  ret = link_seal(l, w->pt, pt_len, w->ct);
  if (ret != CC_OK) {
    wipe(w->pt, sizeof(w->pt));
    return ret;
  }

  view.type = (kind == CC_LINK_KIND_CLOSE)      ? CC_MSG_LINK_CLOSE
              : (kind == CC_LINK_KIND_IDENTIFY) ? CC_MSG_IDENTIFY
                                                : CC_MSG_LINK_DATA;
  view.seq = l->tx_seq;
  /* The nonce was spent by the seal above, so the sequence advances now: a
     failed encode may waste a sequence, but must never let a (key, nonce)
     pair be used twice. */
  l->tx_seq++;
  view.f[CC_LINK_ID].p = l->id;
  view.f[CC_LINK_ID].len = CC_LINK_ID_SZ;
  view.f[CC_LINK_ENC0].p = w->ct;
  view.f[CC_LINK_ENC0].len = pt_len + 16;
  ret = pkt_encode(&view, 0, 0, out, out_sz, out_len);
  if (ret == CC_OK)
    l->last_seen = now;
  wipe(w->pt, sizeof(w->pt));
  return ret;
}

int cc_link_identify(cc_work_t* w, cc_link_t* l, const cc_key_t* my_key,
                     uint32_t now, uint8_t* out, size_t out_sz, size_t* out_len,
                     WC_RNG* rng) {
  if (!w)
    return CC_E_ARG;
  uint8_t* payload = w->id;
  uint8_t imsg[32];
  uint8_t addr[CC_ADDR_SZ];
  word32 sig_len = CC_SIGN_SIG_SZ;
  int ret;

  if (!l || !my_key || !out || !out_len || !rng)
    return CC_E_ARG;
  if (l->state != CC_LINK_STATE_OPEN || !l->used)
    return CC_E_NOLINK;
  ret = cc_addr_from_key(my_key, addr);
  if (ret != CC_OK)
    return ret;
  ret = link_identify_msg(CC_SUITE, l->id, addr, imsg);
  if (ret != CC_OK)
    return ret;
  if (wc_dilithium_sign_msg(imsg, 32, payload + CC_ADDR_SZ, &sig_len,
                            (dilithium_key*)&my_key->sign, rng) != 0)
    return CC_E_CRYPTO;
  memcpy(payload, addr, CC_ADDR_SZ);
  return cc_link_send(w, l, CC_LINK_KIND_IDENTIFY, payload,
                      CC_ADDR_SZ + sig_len, now, out, out_sz, out_len);
}

int cc_identify_verify(cc_work_t* w, const cc_link_t* l, const uint8_t* payload,
                       size_t payload_len,
                       const uint8_t peer_sign_pub[CC_SIGN_PUBKEY_SZ],
                       uint8_t addr_out[CC_ADDR_SZ]) {
  if (!w)
    return CC_E_ARG;
  uint8_t imsg[32];
  uint8_t claimed[CC_ADDR_SZ];
  int verified = 0;
  int ret;

  if (!l || !payload || !peer_sign_pub || !addr_out)
    return CC_E_ARG;
  if (payload_len != CC_ADDR_SZ + CC_SIGN_SIG_SZ)
    return CC_E_FORMAT;

  ret = cc_addr_from_sign_pubkey(peer_sign_pub, claimed);
  if (ret != CC_OK)
    return ret;
  if (memcmp(claimed, payload, CC_ADDR_SZ) != 0)
    return CC_E_NOKEY;

  ret = link_identify_msg(CC_SUITE, l->id, payload, imsg);
  if (ret != CC_OK)
    return ret;
  wc_dilithium_init(&w->verify_key);
  ret = wc_dilithium_set_level(&w->verify_key, CC_SIGN_LEVEL);
  if (ret == 0)
    ret = wc_dilithium_import_public((uint8_t*)peer_sign_pub, CC_SIGN_PUBKEY_SZ,
                                     &w->verify_key);
  if (ret == 0) {
    ret = wc_dilithium_verify_msg(payload + CC_ADDR_SZ, CC_SIGN_SIG_SZ, imsg,
                                  32, &verified, &w->verify_key);
  }
  wc_dilithium_free(&w->verify_key);
  if (ret != 0 || !verified)
    return CC_E_SIG;

  memcpy(addr_out, payload, CC_ADDR_SZ);
  return CC_OK;
}

int cc_link_close(cc_work_t* w, cc_link_t* l, uint32_t now, uint8_t* out,
                  size_t out_sz, size_t* out_len) {
  if (!w)
    return CC_E_ARG;
  int ret = cc_link_send(w, l, CC_LINK_KIND_CLOSE, NULL, 0, now, out, out_sz,
                         out_len);
  if (ret == CC_OK)
    cc_link_forget(l);
  return ret;
}

void cc_link_forget(cc_link_t* l) {
  if (l)
    wipe(l, sizeof(*l));
}

int cc_link_active(const cc_link_t* l, uint32_t now) {
  if (!l)
    return 0;
  return l->used && l->state == CC_LINK_STATE_OPEN && !link_idle(l, now);
}

int cc_link_recv(cc_work_t* w, cc_link_t* l, const uint8_t* in, size_t in_sz,
                 uint32_t now, uint8_t* kind_out, uint8_t* payload,
                 size_t payload_sz, size_t* payload_len) {
  if (!w)
    return CC_E_ARG;
  cc_pkt_view_t view;
  const uint8_t* rec;
  size_t rec_len;
  int ret;

  if (!l || !in || !kind_out || !payload_len)
    return CC_E_ARG;
  if (!l->used)
    return CC_E_NOLINK;
  if (l->state != CC_LINK_STATE_OPEN)
    return CC_E_NOLINK;
  if (link_idle(l, now)) {
    cc_link_forget(l);
    return CC_E_NOLINK;
  }

  ret = pkt_decode(in, in_sz, &view);
  if (ret != CC_OK)
    return ret;
  if (view.type != CC_MSG_LINK_DATA && view.type != CC_MSG_IDENTIFY &&
      view.type != CC_MSG_LINK_CLOSE)
    return CC_E_FORMAT;
  if (view.f[CC_LINK_ID].len != CC_LINK_ID_SZ ||
      memcmp(view.f[CC_LINK_ID].p, l->id, CC_LINK_ID_SZ) != 0)
    return CC_E_NOLINK;

  /* Sequence peek: reject replays for free, before the AEAD. */
  ret = link_seq_step(l, view.seq, 0);
  if (ret != CC_OK)
    return ret;

  ret = link_open(l, view.f[CC_LINK_ENC0].p, view.f[CC_LINK_ENC0].len, view.seq,
                  w->pt);
  if (ret != CC_OK)
    return ret; /* wrong key / tampered seq: the tag fails */
  ret = link_record_dec(w->pt, view.f[CC_LINK_ENC0].len - 16, kind_out, &rec,
                        &rec_len);
  if (ret != CC_OK) {
    wipe(w->pt, sizeof(w->pt));
    return ret;
  }

  if (*kind_out == CC_LINK_KIND_CLOSE) {
    wipe(w->pt, sizeof(w->pt));
    cc_link_forget(l);
    return CC_OK; /* kind_out == CLOSE; the caller forgets its side too */
  }
  if (rec_len > payload_sz) {
    wipe(w->pt, sizeof(w->pt));
    return CC_E_BUF;
  }
  memcpy(payload, rec, rec_len);
  *payload_len = rec_len;
  /* Fully authenticated: commit the sequence and touch last_seen. */
  link_seq_step(l, view.seq, 1);
  l->last_seen = now;
  wipe(w->pt, sizeof(w->pt));
  return CC_OK;
}

/* ---- Group destinations (a new type inside revision 9) ---- */

/* The gid is derived from the secret and from nothing else: no membership, no
   epoch, no identity. Removal is a new secret, hence a new gid. */
static int group_gid_from_secret(const uint8_t secret[CC_GROUP_SECRET_SZ],
                                 uint8_t gid[CC_GROUP_GID_SZ]) {
  static const uint8_t label[] = "cosechat/group gid";
  uint8_t h[32];
  wc_Sha256 sha;
  int ret = wc_InitSha256(&sha);
  if (ret != 0)
    return CC_E_CRYPTO;
  wc_Sha256Update(&sha, label, (word32)(sizeof(label) - 1));
  wc_Sha256Update(&sha, secret, CC_GROUP_SECRET_SZ);
  ret = wc_Sha256Final(&sha, h);
  wc_Sha256Free(&sha);
  if (ret != 0)
    return CC_E_CRYPTO;
  memcpy(gid, h, CC_GROUP_GID_SZ);
  wipe(h, sizeof(h));
  return CC_OK;
}

/* One key per group, from the secret and the gid, through the same labelled
   Extract/Expand construction as the link with labels of its own. */
static int group_key(cc_work_t* w, const uint8_t gid[CC_GROUP_GID_SZ],
                     const uint8_t secret[CC_GROUP_SECRET_SZ],
                     uint8_t out[CC_GROUP_KEY_SZ]) {
  uint8_t prk[32];
  int ret;
  ret = hpke_extract_labeled(w, gid, CC_GROUP_GID_SZ, "cosechat/group prk",
                             secret, CC_GROUP_SECRET_SZ, prk);
  if (ret != CC_OK)
    return ret;
  ret = hpke_expand_labeled(w, prk, "cosechat/group key", gid, CC_GROUP_GID_SZ,
                            out, CC_GROUP_KEY_SZ);
  wipe(prk, sizeof(prk));
  return ret;
}

/* The provisioning record, carried as one link record: [gid, secret]. */
static int group_secrec_enc(uint8_t* buf, size_t sz, size_t* len,
                            const uint8_t gid[CC_GROUP_GID_SZ],
                            const uint8_t secret[CC_GROUP_SECRET_SZ]) {
  WOLFCOSE_CBOR_CTX c;
  cbor_enc_init(&c, buf, sz);
  if (wc_CBOR_EncodeArrayStart(&c, 2) != WOLFCOSE_SUCCESS ||
      wc_CBOR_EncodeBstr(&c, gid, CC_GROUP_GID_SZ) != WOLFCOSE_SUCCESS ||
      wc_CBOR_EncodeBstr(&c, secret, CC_GROUP_SECRET_SZ) != WOLFCOSE_SUCCESS)
    return CC_E_BUF;
  *len = c.idx;
  return CC_OK;
}

static int group_secrec_dec(const uint8_t* buf, size_t sz,
                            uint8_t gid[CC_GROUP_GID_SZ],
                            uint8_t secret[CC_GROUP_SECRET_SZ]) {
  uint8_t major;
  uint64_t count, val;
  size_t hdr, off, used;

  if (cb_head(buf, sz, &major, &count, &hdr) != CC_OK || major != 4 ||
      count != 2)
    return CC_E_FORMAT;
  off = hdr;
  if (cb_item(buf + off, sz - off, 2, &val, &used) != CC_OK ||
      val != CC_GROUP_GID_SZ)
    return CC_E_FORMAT;
  memcpy(gid, buf + off + (used - (size_t)val), CC_GROUP_GID_SZ);
  off += used;
  if (cb_item(buf + off, sz - off, 2, &val, &used) != CC_OK ||
      val != CC_GROUP_SECRET_SZ)
    return CC_E_FORMAT;
  memcpy(secret, buf + off + (used - (size_t)val), CC_GROUP_SECRET_SZ);
  off += used;
  return (off == sz) ? CC_OK : CC_E_FORMAT;
}

int cc_group_create(cc_group_t* g, WC_RNG* rng) {
  int ret;
  if (!g || !rng)
    return CC_E_ARG;
  memset(g, 0, sizeof(*g));
  if (wc_RNG_GenerateBlock(rng, g->secret, CC_GROUP_SECRET_SZ) != 0) {
    cc_group_free(g);
    return CC_E_CRYPTO;
  }
  ret = group_gid_from_secret(g->secret, g->gid);
  if (ret != CC_OK) {
    cc_group_free(g);
    return ret;
  }
  g->used = 1;
  return CC_OK;
}

int cc_group_secret_export(const cc_group_t* g,
                           uint8_t out[CC_GROUP_SECRET_SZ]) {
  if (!g || !out)
    return CC_E_ARG;
  if (!g->used)
    return CC_E_ARG;
  memcpy(out, g->secret, CC_GROUP_SECRET_SZ);
  return CC_OK;
}

int cc_group_join(cc_group_t* g, const uint8_t secret[CC_GROUP_SECRET_SZ]) {
  int ret;
  if (!g || !secret)
    return CC_E_ARG;
  memset(g, 0, sizeof(*g));
  memcpy(g->secret, secret, CC_GROUP_SECRET_SZ);
  ret = group_gid_from_secret(g->secret, g->gid);
  if (ret != CC_OK) {
    cc_group_free(g);
    return ret;
  }
  g->used = 1;
  return CC_OK;
}

int cc_group_free(cc_group_t* g) {
  if (!g)
    return CC_E_ARG;
  wipe(g, sizeof(*g));
  return CC_OK;
}

int cc_group_secret_send(cc_work_t* w, const cc_group_t* g, cc_link_t* l,
                         uint32_t now, uint8_t* out, size_t out_sz,
                         size_t* out_len) {
  if (!w)
    return CC_E_ARG;
  uint8_t rec[CC_GROUP_SECREC_BUF_SZ];
  size_t rec_len = 0;
  int ret;
  if (!g || !l || !out || !out_len)
    return CC_E_ARG;
  if (!g->used)
    return CC_E_ARG;
  ret = group_secrec_enc(rec, sizeof(rec), &rec_len, g->gid, g->secret);
  if (ret != CC_OK)
    return ret;
  /* A link, or nothing: cc_link_send enforces the link's state, and there is
     no unauthenticated path to a group secret. */
  ret = cc_link_send(w, l, CC_LINK_KIND_GROUP_KEY, rec, rec_len, now, out,
                     out_sz, out_len);
  wipe(rec, sizeof(rec));
  return ret;
}

int cc_group_secret_recv(cc_work_t* w, cc_group_t* g, const cc_link_t* l,
                         const uint8_t* payload, size_t payload_len) {
  if (!w)
    return CC_E_ARG;
  uint8_t gid[CC_GROUP_GID_SZ], secret[CC_GROUP_SECRET_SZ];
  int ret;
  if (!g || !l || !payload)
    return CC_E_ARG;
  if (!l->used || l->state != CC_LINK_STATE_OPEN)
    return CC_E_NOLINK;
  memset(secret, 0, sizeof(secret));
  ret = group_secrec_dec(payload, payload_len, gid, secret);
  if (ret != CC_OK) {
    wipe(secret, sizeof(secret));
    return ret;
  }
  /* The carried gid has to be the one the carried secret produces: a record
     whose halves disagree is not a group we can join. */
  {
    uint8_t check[CC_GROUP_GID_SZ];
    ret = group_gid_from_secret(secret, check);
    if (ret == CC_OK && memcmp(check, gid, CC_GROUP_GID_SZ) != 0)
      ret = CC_E_SIG;
  }
  if (ret == CC_OK)
    ret = cc_group_join(g, secret);
  wipe(secret, sizeof(secret));
  return ret;
}

int cc_group_win_init(cc_group_win_t* win, const uint8_t gid[CC_GROUP_GID_SZ],
                      const uint8_t poster[CC_ADDR_SZ]) {
  if (!win || !gid || !poster)
    return CC_E_ARG;
  memset(win, 0, sizeof(*win)); /* last_seen 0: never verified, evict first */
  memcpy(win->gid, gid, CC_GROUP_GID_SZ);
  memcpy(win->poster, poster, CC_ADDR_SZ);
  return cc_replay_init(&win->seq, poster, CC_REPLAY_AUTHED);
}

int cc_group_win_stale(const cc_group_win_t* win, uint32_t now,
                       uint32_t horizon) {
  /* A window that has never carried a verified post (last_seen 0) ages out
     first, which is what a caller wants when a label flood is filling its
     table. Evicting a window gives up replay protection for that label, so the
     horizon is the caller's trade and this is only the predicate. */
  if (!win)
    return 1;
  return (int32_t)(now - win->last_seen) > (int32_t)horizon;
}

int cc_group_win_forget(cc_group_win_t* win) {
  if (!win)
    return CC_E_ARG;
  wipe(win, sizeof(*win));
  return CC_OK;
}

int cc_group_post_build(cc_work_t* w, const cc_group_t* g,
                        const uint8_t poster[CC_ADDR_SZ], uint32_t seq,
                        const uint8_t* msg, size_t msg_len, uint8_t* out,
                        size_t out_sz, size_t* out_len, WC_RNG* rng) {
  if (!w)
    return CC_E_ARG;
  uint8_t key[CC_GROUP_KEY_SZ], iv[12];
  cc_pkt_view_t view = {0};
  WOLFCOSE_KEY cose_sym;
  size_t aad_len = 0, enc0_len = 0, n = 0;
  int ret;

  if (!g || !poster || !msg || !out || !out_len || !rng)
    return CC_E_ARG;
  if (!g->used)
    return CC_E_ARG;
  if (msg_len > CC_GROUP_PT_SZ)
    return CC_E_ARG;

  /* The key first: the derivation uses w->pre as scratch, and w->pre holds the
     AAD a few lines below. */
  ret = group_key(w, g->gid, g->secret, key);
  if (ret != CC_OK)
    return ret;
  /* A random 96-bit IV, carried inside the COSE structure, and NOT the link's
     direction|salt|sequence construction. The reason is not an attacker: one
     group key carries one counter space PER MEMBER, so two honest members both
     at seq 1 would collide SYSTEMATICALLY under a deterministic nonce, which is
     a guaranteed catastrophic GCM reuse rather than an unlucky one. A malicious
     member can also force a collision with a random IV — it reads the IV off
     the wire and reuses it — but it buys them nothing: a key holder can already
     decrypt every post and seal any poster label, so no IV scheme defends
     against one, and none needs to. The sequence stays bound in the AAD, so
     replay and ordering are unaffected, and "seq never repeats for a label" is
     the caller's documented duty. */
  if (wc_RNG_GenerateBlock(rng, iv, sizeof(iv)) != 0) {
    wipe(key, sizeof(key));
    return CC_E_CRYPTO;
  }

  view.type = CC_MSG_GROUP_DATA;
  view.seq = seq;
  view.f[CC_GRP_GID].p = g->gid;
  view.f[CC_GRP_GID].len = CC_GROUP_GID_SZ;
  view.f[CC_GRP_POSTER].p = poster;
  view.f[CC_GRP_POSTER].len = CC_ADDR_SZ;
  view.f[CC_GRP_ENC0].p = w->ct;
  view.f[CC_GRP_ENC0].len = 0;

  ret = pkt_encode(&view, 0, 0, out, out_sz, &n);
  if (ret != CC_OK) {
    wipe(key, sizeof(key));
    return ret;
  }
  ret = pkt_copy_covered(&view, CC_PKT_LAYOUT[CC_MSG_GROUP_DATA].aad_skip,
                         w->pre, sizeof(w->pre), &aad_len);
  if (ret != CC_OK) {
    wipe(key, sizeof(key));
    return ret;
  }
  /* The tag covers gid, poster and seq: the label a member reads is the one
     the sealer committed to (which is not the same as who the sealer is). */
  wc_CoseKey_Init(&cose_sym);
  ret = wc_CoseKey_SetSymmetric(&cose_sym, key, CC_GROUP_KEY_SZ);
  if (ret == WOLFCOSE_SUCCESS) {
    ret = wc_CoseEncrypt0_Encrypt(
        &cose_sym, WOLFCOSE_ALG_A256GCM, iv, sizeof(iv), (uint8_t*)msg,
        (word32)msg_len, NULL, 0, NULL, w->pre, (word32)aad_len, w->scratch,
        sizeof(w->scratch), w->ct, sizeof(w->ct), &enc0_len);
  }
  wc_CoseKey_Free(&cose_sym);
  wipe(key, sizeof(key));
  wipe(w->pre, sizeof(w->pre));
  wipe(w->scratch, sizeof(w->scratch));
  if (ret != WOLFCOSE_SUCCESS)
    return CC_E_CRYPTO;

  view.f[CC_GRP_ENC0].len = enc0_len;
  ret = pkt_encode(&view, 0, 0, out, out_sz, &n);
  if (ret != CC_OK)
    return ret;
  return pkt_finish(&view, 0, out, out_sz, out_len);
}

int cc_group_post_parse(cc_work_t* w, const cc_group_t* g, cc_group_win_t* win,
                        const uint8_t* in, size_t in_sz, uint32_t now,
                        cc_group_msg_t* out) {
  if (!w)
    return CC_E_ARG;
  cc_pkt_view_t view;
  uint8_t key[CC_GROUP_KEY_SZ], poster[CC_ADDR_SZ];
  WOLFCOSE_KEY cose_sym;
  WOLFCOSE_HDR hdr;
  size_t aad_len = 0, pt_len = 0;
  int ret;

  if (!g || !win || !in || !out)
    return CC_E_ARG;
  if (!g->used)
    return CC_E_ARG;
  memset(out, 0, sizeof(*out));

  ret = pkt_accept(in, in_sz, CC_MSG_GROUP_DATA, &view);
  if (ret != CC_OK)
    return ret;
  if (view.f[CC_GRP_GID].len != CC_GROUP_GID_SZ ||
      memcmp(view.f[CC_GRP_GID].p, g->gid, CC_GROUP_GID_SZ) != 0)
    return CC_E_GROUP; /* not this group's post */
  memcpy(poster, view.f[CC_GRP_POSTER].p, CC_ADDR_SZ);
  if (memcmp(win->gid, g->gid, CC_GROUP_GID_SZ) != 0 ||
      memcmp(win->poster, poster, CC_ADDR_SZ) != 0)
    return CC_E_ARG; /* the window is for another label or another group */

  /* Peek before the expensive work: a post that fails the tag must not move
     any window. */
  ret = replay_step(&win->seq, CC_REPLAY_AUTHED, poster, view.seq, 0);
  if (ret != CC_OK)
    return ret;

  ret = group_key(w, g->gid, g->secret, key);
  if (ret != CC_OK)
    return ret;
  ret = pkt_copy_covered(&view, CC_PKT_LAYOUT[CC_MSG_GROUP_DATA].aad_skip,
                         w->pre, sizeof(w->pre), &aad_len);
  if (ret != CC_OK) {
    wipe(key, sizeof(key));
    return ret;
  }
  wc_CoseKey_Init(&cose_sym);
  ret = wc_CoseKey_SetSymmetric(&cose_sym, key, CC_GROUP_KEY_SZ);
  if (ret == WOLFCOSE_SUCCESS) {
    ret = wc_CoseEncrypt0_Decrypt(
        &cose_sym, view.f[CC_GRP_ENC0].p, view.f[CC_GRP_ENC0].len, NULL, 0,
        w->pre, (word32)aad_len, w->scratch, sizeof(w->scratch), &hdr, w->pt,
        sizeof(w->pt), &pt_len);
  }
  wc_CoseKey_Free(&cose_sym);
  wipe(key, sizeof(key));
  wipe(w->pre, sizeof(w->pre));
  wipe(w->scratch, sizeof(w->scratch));
  if (ret != WOLFCOSE_SUCCESS)
    return CC_E_DECRYPT; /* the window is untouched */
  if (pt_len > CC_GROUP_PT_SZ) {
    wipe(w->pt, sizeof(w->pt));
    return CC_E_FORMAT;
  }

  memcpy(out->poster, poster, CC_ADDR_SZ);
  memcpy(out->gid, g->gid, CC_GROUP_GID_SZ);
  memcpy(out->msg, w->pt, pt_len);
  out->msg_len = pt_len;
  out->seq = view.seq;
  out->hops = view.hops;
  wipe(w->pt, sizeof(w->pt));
  /* Authenticated: only now does the sequence count as seen, and only now is
     this window known to belong to a label that actually posts. */
  ret = replay_step(&win->seq, CC_REPLAY_AUTHED, poster, view.seq, 1);
  if (ret == CC_OK)
    win->last_seen = now;
  return ret;
}

int cc_group_poster(const uint8_t* pkt, size_t pkt_sz,
                    uint8_t addr[CC_ADDR_SZ]) {
  cc_pkt_view_t view;
  int ret;
  if (!pkt || !addr)
    return CC_E_ARG;
  ret = pkt_decode(pkt, pkt_sz, &view);
  if (ret != CC_OK)
    return ret;
  if (view.type != CC_MSG_GROUP_DATA)
    return CC_E_FORMAT;
  memcpy(addr, view.f[CC_GRP_POSTER].p, CC_ADDR_SZ);
  return CC_OK;
}

int cc_group_gid(const uint8_t* pkt, size_t pkt_sz,
                 uint8_t gid[CC_GROUP_GID_SZ]) {
  cc_pkt_view_t view;
  int ret;
  if (!pkt || !gid)
    return CC_E_ARG;
  ret = pkt_decode(pkt, pkt_sz, &view);
  if (ret != CC_OK)
    return ret;
  if (view.type != CC_MSG_GROUP_DATA)
    return CC_E_FORMAT;
  memcpy(gid, view.f[CC_GRP_GID].p, CC_GROUP_GID_SZ);
  return CC_OK;
}

int cc_msg_type(const uint8_t* pkt, size_t pkt_sz, uint8_t* type_out) {
  uint8_t major;
  uint64_t val;
  size_t hdr, off, used;

  if (!pkt || !type_out)
    return CC_E_ARG;
  if (cb_head(pkt, pkt_sz, &major, &val, &hdr) != CC_OK || major != 4)
    return CC_E_FORMAT;
  off = hdr;
  if (cb_item(pkt + off, pkt_sz - off, 0, &val, &used) != CC_OK)
    return CC_E_FORMAT;
  if (val != CC_WIRE_VERSION)
    return CC_E_VERSION;
  off += used;
  if (cb_item(pkt + off, pkt_sz - off, 0, &val, &used) != CC_OK)
    return CC_E_FORMAT;
  *type_out = (uint8_t)(val & 0xFF);
  return CC_OK;
}

int cc_msg_hops(const uint8_t* pkt, size_t pkt_sz, uint8_t* hops_out) {
  uint8_t major;
  uint64_t val;
  size_t hdr, off, used;

  if (!pkt || !hops_out)
    return CC_E_ARG;
  if (cb_head(pkt, pkt_sz, &major, &val, &hdr) != CC_OK || major != 4)
    return CC_E_FORMAT;
  off = hdr;
  if (cb_item(pkt + off, pkt_sz - off, 0, &val, &used) != CC_OK)
    return CC_E_FORMAT;
  if (val != CC_WIRE_VERSION)
    return CC_E_VERSION;
  off += used;
  if (cb_item(pkt + off, pkt_sz - off, 0, &val, &used) != CC_OK)
    return CC_E_FORMAT;
  off += used;
  if (cb_item(pkt + off, pkt_sz - off, 0, &val, &used) != CC_OK)
    return CC_E_FORMAT;
  *hops_out = (uint8_t)(val & 0xFF);
  return CC_OK;
}

int cc_msg_recipient(const uint8_t* pkt, size_t pkt_sz,
                     uint8_t addr[CC_ADDR_SZ]) {
  cc_pkt_view_t view;
  int ret;
  if (!pkt || !addr)
    return CC_E_ARG;
  ret = pkt_decode(pkt, pkt_sz, &view);
  if (ret != CC_OK)
    return ret;
  if (view.type != CC_MSG_CHAT)
    return CC_E_FORMAT;
  memcpy(addr, view.f[CC_CHAT_RECIPIENT].p, CC_ADDR_SZ);
  return CC_OK;
}

int cc_chat_sender(const uint8_t* pkt, size_t pkt_sz,
                   uint8_t addr[CC_ADDR_SZ]) {
  cc_pkt_view_t view;
  int ret;
  if (!pkt || !addr)
    return CC_E_ARG;
  ret = pkt_decode(pkt, pkt_sz, &view);
  if (ret != CC_OK)
    return ret;
  if (view.type != CC_MSG_CHAT)
    return CC_E_FORMAT;
  memcpy(addr, view.f[CC_CHAT_SENDER].p, CC_ADDR_SZ);
  return CC_OK;
}

int cc_link_id(const uint8_t* pkt, size_t pkt_sz, uint8_t out[CC_LINK_ID_SZ]) {
  cc_pkt_view_t view;
  int ret;
  if (!pkt || !out)
    return CC_E_ARG;
  ret = pkt_decode(pkt, pkt_sz, &view);
  if (ret != CC_OK)
    return ret;
  if (view.type < CC_MSG_LINK_REQ)
    return CC_E_FORMAT;
  memcpy(out, view.f[CC_LINK_ID].p, CC_LINK_ID_SZ);
  return CC_OK;
}

int cc_hops_increment(const uint8_t* in, size_t in_sz, uint8_t* out,
                      size_t out_sz, size_t* out_len) {
  cc_pkt_view_t view;
  int ret;
  if (!in || !out || !out_len)
    return CC_E_ARG;
  if (out == in)
    return CC_E_ARG;
  ret = pkt_decode(in, in_sz, &view);
  if (ret != CC_OK)
    return ret;
  if (view.hops == 255)
    return CC_E_ARG;
  return pkt_encode(&view, (uint8_t)(view.hops + 1), view.nonce, out, out_sz,
                    out_len);
}

int cc_pow_verify_at(const uint8_t* pkt, size_t pkt_sz, uint8_t difficulty) {
  cc_pkt_view_t view;
  int ret;
  if (!pkt || difficulty > CC_POW_MAX)
    return CC_E_ARG;
  ret = pkt_decode(pkt, pkt_sz, &view);
  if (ret != CC_OK)
    return ret; /* CC_E_VERSION for another revision, CC_E_FORMAT otherwise */
  return pkt_pow_check_at(&view, difficulty);
}

int cc_pow_verify(const uint8_t* pkt, size_t pkt_sz) {
  return cc_pow_verify_at(pkt, pkt_sz, 0);
}
