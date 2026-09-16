/* test_relay.c — the relay's contract (path learning, forwarding, refusals,
 * and the adversarial cases the module exists to survive).
 *
 * The relay is part of the library (include/cosechat_relay.h), so it is
 * exercised on the host rather than on hardware. Every case here is a
 * behaviour: a packet goes in, a decision comes out, and the table, the
 * counters and the bytes of the forwarded packet are what is asserted. Where
 * a real packet is needed the library builds and parses it (a verified
 * announce, a signed and encapsulated chat); where only the relay's own
 * decision is under test a synthetic but structurally valid chat is minted
 * locally and mined with the same PoW rule the library applies, because the
 * relay is deliberately not an authenticator.
 *
 * Target configuration (CMakeLists.txt): CC_RELAY_PATHS=4 so table pressure is
 * cheap to reach, and CC_RELAY_FWD_BUDGET=3 with pools of 32768 B (announce)
 * and 28672 B (data) so that each limit can be reached and told apart with the
 * packet sizes a chat really has (~4.5 KB) and an announce really has (~6.5
 * KB). The shipped defaults are documented in the header; they are sized for
 * one SF7 channel across a one-minute window. The library the fixture uses is
 * built at the firmware's PoW difficulty (1, cosechat_pow1) rather than the
 * default (2), which keeps the suite fast; the one test that needs a higher
 * price mines it with the library itself, which also pins the relay's own PoW
 * digest against the library's.
 */
#include <stdio.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "cosechat.h"
#include "cosechat_relay.h"

static int g_passed = 0, g_failed = 0;
static cc_work_t g_w;

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

/* One node per distinct origin: the table holds CC_RELAY_PATHS entries, so
 * CC_RELAY_PATHS + 1 origins force an eviction. [0] is alice, the chat
 * sender/destination the tests route to; [1] is her usual next hop. */
#define NDEST (CC_RELAY_PATHS + 1)

typedef struct {
  cc_key_t key;
  uint8_t addr[CC_ADDR_SZ];
  uint8_t sign_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t kem_pub[CC_KEM_PUBKEY_SZ];
  uint8_t ann[CC_ANN_BUF_SZ]; /* announce with hops = 0 */
  size_t ann_len;
} t_node_t;

static t_node_t g_node[NDEST];
static t_node_t g_carol;    /* the far end of the chain */
static t_node_t g_alice2;   /* [0]'s key, announce seq 2 */
static t_node_t g_alice3;   /* [0]'s key, announce seq 3 */
static t_node_t g_alice_hi; /* [0]'s key, declaring chat difficulty 2 */

/* Fixture announce lifetime: absolute, beyond every `now` below except the
 * deliberate expiry case. */
#define T_EXPIRY 100000u

static uint8_t g_out[CC_ANN_BUF_SZ];   /* forwarding scratch */
static uint8_t g_ann_a[CC_ANN_BUF_SZ]; /* hop-counting scratch */
static uint8_t g_ann_b[CC_ANN_BUF_SZ];
static uint8_t g_ann_saved[CC_ANN_BUF_SZ]; /* bytes before a call */
static uint8_t g_chat[CC_CHAT_BUF_SZ];     /* a synthetic chat under test */
static uint8_t g_chat_saved[CC_CHAT_BUF_SZ];
/* The chain forwards both kinds through these two: an announce is larger than
 * a chat, so they are sized for the announce (t_feed() promises
 * CC_ANN_BUF_SZ to the relay). */
static uint8_t g_fwd[CC_ANN_BUF_SZ];  /* one relay's output */
static uint8_t g_fwd2[CC_ANN_BUF_SZ]; /* the next relay's output */

/* ---------------------------------------------------------------------------
 * Test-local CBOR: a canonical writer for the synthetic packets, and a walker
 * that finds one element's span (so a re-stamp can be proven byte-wise and the
 * PoW preimage can be rebuilt).
 * ------------------------------------------------------------------------- */

typedef struct {
  uint8_t* p;
  size_t n;
  size_t cap;
  int over;
} t_w;

static void t_put(t_w* w, uint8_t b) {
  if (w->n >= w->cap) {
    w->over = 1;
    return;
  }
  w->p[w->n++] = b;
}

static void t_put_head(t_w* w, uint8_t major, uint64_t v) {
  uint8_t h = (uint8_t)(major << 5);
  unsigned i;
  if (v < 24) {
    t_put(w, (uint8_t)(h | v));
  } else if (v < 256) {
    t_put(w, (uint8_t)(h | 24));
    t_put(w, (uint8_t)v);
  } else if (v < 65536) {
    t_put(w, (uint8_t)(h | 25));
    t_put(w, (uint8_t)(v >> 8));
    t_put(w, (uint8_t)v);
  } else {
    t_put(w, (uint8_t)(h | 26));
    for (i = 0; i < 4; i++) t_put(w, (uint8_t)(v >> (24 - 8 * i)));
  }
}

static void t_put_fill(t_w* w, uint8_t v, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) t_put(w, v);
}

static int t_head(const uint8_t* p, size_t len, uint8_t* major, uint64_t* val,
                  size_t* used) {
  uint8_t ib, ai;
  if (len < 1)
    return -1;
  ib = p[0];
  *major = (uint8_t)(ib >> 5);
  ai = (uint8_t)(ib & 0x1F);
  if (ai < 24) {
    *val = ai;
    *used = 1;
  } else if (ai == 24) {
    if (len < 2)
      return -1;
    *val = p[1];
    *used = 2;
  } else if (ai == 25) {
    if (len < 3)
      return -1;
    *val = ((uint64_t)p[1] << 8) | p[2];
    *used = 3;
  } else if (ai == 26) {
    if (len < 5)
      return -1;
    *val = ((uint64_t)p[1] << 24) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 8) | p[4];
    *used = 5;
  } else {
    return -1;
  }
  return 0;
}

/* Span of one item: the uints and strings the envelopes start with. */
static int t_item(const uint8_t* p, size_t len, uint64_t* val, size_t* used) {
  uint8_t major;
  uint64_t v;
  size_t hdr;
  if (t_head(p, len, &major, &v, &hdr) != 0)
    return -1;
  if (major == 2 || major == 3) {
    if (len < hdr + (size_t)v)
      return -1;
    *used = hdr + (size_t)v;
  } else if (major == 0) {
    *used = hdr;
  } else {
    return -1;
  }
  *val = v;
  return 0;
}

/* Offset and span of element `idx` of the outer array. */
static int t_el_span(const uint8_t* p, size_t len, unsigned idx, size_t* off,
                     size_t* elen) {
  uint8_t major;
  uint64_t v;
  size_t hdr, pos, used;
  unsigned i;

  if (t_head(p, len, &major, &v, &hdr) != 0 || major != 4 || v <= idx)
    return -1;
  pos = hdr;
  for (i = 0; i <= idx; i++) {
    if (i == idx)
      *off = pos;
    if (t_item(p + pos, len - pos, &v, &used) != 0)
      return -1;
    if (i == idx) {
      *elen = used;
      return 0;
    }
    pos += used;
  }
  return -1;
}

/* Element count of the outer array. */
static int t_elems(const uint8_t* p, size_t len, unsigned* n) {
  uint8_t major;
  uint64_t v;
  size_t hdr;
  if (t_head(p, len, &major, &v, &hdr) != 0 || major != 4)
    return -1;
  *n = (unsigned)v;
  return 0;
}

#define T_EL_HOPS 2
#define T_EL_CHAT_NONCE 7

static int t_hops(const uint8_t* pkt, size_t len) {
  uint8_t hops = 0xFF;
  if (cc_msg_hops(pkt, len, &hops) != CC_OK)
    return -1;
  return hops;
}

/* True when two whole packets differ in the hops element and nowhere else. */
static int t_only_hops_differs(const uint8_t* a, size_t alen, const uint8_t* b,
                               size_t blen) {
  size_t ao, al, bo, bl;
  if (t_el_span(a, alen, T_EL_HOPS, &ao, &al) != 0)
    return 0;
  if (t_el_span(b, blen, T_EL_HOPS, &bo, &bl) != 0)
    return 0;
  if (ao != bo || alen - ao - al != blen - bo - bl)
    return 0;
  if (memcmp(a, b, ao) != 0)
    return 0;
  return memcmp(a + ao + al, b + bo + bl, alen - ao - al) == 0;
}

static int t_all_zero(const uint8_t* p, size_t n) {
  size_t i;
  for (i = 0; i < n; i++)
    if (p[i])
      return 0;
  return 1;
}

/* Replace the wire revision (element 0, always a one-byte uint here). */
static int t_patch_version(uint8_t* pkt, size_t len, uint64_t ver) {
  size_t off, elen;
  if (ver > 23 || t_el_span(pkt, len, 0, &off, &elen) != 0 || elen != 1)
    return -1;
  pkt[off] = (uint8_t)ver;
  return 0;
}

/* ---------------------------------------------------------------------------
 * Proof of work, the test's own miner
 *
 * The preimage is the packet's bytes with the hops and nonce elements removed
 * (the same byte range the library's pow_hash() uses, minus the nonce
 * trailer), followed by the nonce little-endian. The synthetic packets carry
 * the nonce as a four-byte uint, so a mined value always has the same
 * canonical head and the element is a fixed-width slot to write into.
 * ------------------------------------------------------------------------- */

static uint32_t t_nonce_placeholder(void) { return 65536u; }

static size_t t_pow_preimage(const uint8_t* pkt, size_t len, unsigned nonce_idx,
                             uint8_t* out, size_t cap, uint32_t nonce) {
  unsigned n = 0, i;
  size_t off, elen, hdr, o = 0;
  uint8_t major;
  uint64_t v;

  if (t_elems(pkt, len, &n) != 0)
    return 0;
  if (t_head(pkt, len, &major, &v, &hdr) != 0 || hdr + 4 > cap)
    return 0;
  memcpy(out, pkt, hdr);
  o = hdr;
  for (i = 0; i < n; i++) {
    if (t_el_span(pkt, len, i, &off, &elen) != 0)
      return 0;
    if (i == T_EL_HOPS || i == nonce_idx)
      continue;
    if (o + elen > cap)
      return 0;
    memcpy(out + o, pkt + off, elen);
    o += elen;
  }
  if (o + 4 > cap)
    return 0;
  out[o++] = (uint8_t)nonce;
  out[o++] = (uint8_t)(nonce >> 8);
  out[o++] = (uint8_t)(nonce >> 16);
  out[o++] = (uint8_t)(nonce >> 24);
  return o;
}

/* Mine `pkt` in place at `difficulty` leading zero bytes. 0 on success. */
static int t_mine_at(uint8_t* pkt, size_t len, unsigned nonce_idx,
                     uint8_t difficulty) {
  static uint8_t pre[CC_CHAT_BUF_SZ];
  uint8_t hash[32];
  size_t off, elen, plen = 0;
  uint32_t n;
  unsigned i;

  if (t_el_span(pkt, len, nonce_idx, &off, &elen) != 0 || elen != 5)
    return -1;
  plen = t_pow_preimage(pkt, len, nonce_idx, pre, sizeof(pre), 0);
  if (plen == 0)
    return -1;
  for (n = 0x10000u; n != 0xFFFFFFFFu; n++) {
    pre[plen - 4] = (uint8_t)n;
    pre[plen - 3] = (uint8_t)(n >> 8);
    pre[plen - 2] = (uint8_t)(n >> 16);
    pre[plen - 1] = (uint8_t)(n >> 24);
    if (wc_Sha256Hash(pre, (word32)plen, hash) != 0)
      return -1;
    for (i = 0; i < difficulty; i++)
      if (hash[i] != 0)
        break;
    if (i == difficulty) {
      pkt[off + 1] = (uint8_t)(n >> 24);
      pkt[off + 2] = (uint8_t)(n >> 16);
      pkt[off + 3] = (uint8_t)(n >> 8);
      pkt[off + 4] = (uint8_t)n;
      return 0;
    }
  }
  return -1;
}

/* An addressable chat, structurally valid but authenticating nothing and
 * paying nothing: [ver, type=1, hops, sender, recipient, kem_ct, counter,
 * nonce, encrypt0, sig]. `counter` and `tag` make two of them differ in
 * bytes. */
static size_t t_mint_chat_body(uint8_t* out, size_t cap, uint8_t hops,
                               const uint8_t sender[CC_ADDR_SZ],
                               const uint8_t dest[CC_ADDR_SZ], uint32_t counter,
                               uint8_t tag, size_t body) {
  t_w w;
  size_t i;
  w.p = out;
  w.n = 0;
  w.cap = cap;
  w.over = 0;

  t_put_head(&w, 4, 10);
  t_put_head(&w, 0, CC_WIRE_VERSION);
  t_put_head(&w, 0, CC_MSG_CHAT);
  t_put_head(&w, 0, hops);
  t_put_head(&w, 2, CC_ADDR_SZ);
  for (i = 0; i < CC_ADDR_SZ; i++) t_put(&w, sender[i]);
  t_put_head(&w, 2, CC_ADDR_SZ);
  for (i = 0; i < CC_ADDR_SZ; i++) t_put(&w, dest[i]);
  t_put_head(&w, 2, CC_KEM_CT_SZ);
  t_put_fill(&w, tag, CC_KEM_CT_SZ);
  t_put_head(&w, 0, counter);
  t_put_head(&w, 0, t_nonce_placeholder()); /* fixed-width nonce slot */
  t_put_head(&w, 2, body);
  t_put_fill(&w, (uint8_t)(tag ^ 0x5A), body);
  t_put_head(&w, 2, CC_SIGN_SIG_SZ);
  t_put_fill(&w, (uint8_t)(tag ^ 0xFF), CC_SIGN_SIG_SZ);
  return w.over ? 0 : w.n;
}

static size_t t_mint_chat_raw(uint8_t* out, size_t cap, uint8_t hops,
                              const uint8_t sender[CC_ADDR_SZ],
                              const uint8_t dest[CC_ADDR_SZ], uint32_t counter,
                              uint8_t tag) {
  return t_mint_chat_body(out, cap, hops, sender, dest, counter, tag, 32);
}

/* A mined chat, optionally padded to `body` bytes of payload and mined at
 * `difficulty`: a bigger packet is a bigger share of the data pool, and a
 * higher difficulty is what a peer that declares a higher price asks for. */
static size_t t_mint_chat_mined(uint8_t* out, size_t cap, uint8_t hops,
                                const uint8_t sender[CC_ADDR_SZ],
                                const uint8_t dest[CC_ADDR_SZ],
                                uint32_t counter, uint8_t tag, size_t body,
                                uint8_t difficulty) {
  size_t len =
      t_mint_chat_body(out, cap, hops, sender, dest, counter, tag, body);
  if (len == 0 || t_mine_at(out, len, T_EL_CHAT_NONCE, difficulty) != 0)
    return 0;
  return len;
}

/* The common case: mined at this build's own chat difficulty. */
static size_t t_mint_chat(uint8_t* out, size_t cap, uint8_t hops,
                          const uint8_t sender[CC_ADDR_SZ],
                          const uint8_t dest[CC_ADDR_SZ], uint32_t counter,
                          uint8_t tag) {
  return t_mint_chat_mined(out, cap, hops, sender, dest, counter, tag, 32,
                           CC_POW_DIFFICULTY_CHAT);
}

#define T_EL_POST_NONCE                                 \
  6 /* [ver, type, hops, gid, poster, seq, nonce, enc0] \
     */

/* A group post, structurally valid but authenticating nothing and paying
 * nothing: [ver, type=11, hops, gid(8), poster(16), seq, nonce, encrypt0]. */
static size_t t_mint_post_raw(uint8_t* out, size_t cap, uint8_t hops,
                              const uint8_t gid[CC_GROUP_GID_SZ],
                              const uint8_t poster[CC_ADDR_SZ], uint32_t seq,
                              uint8_t tag) {
  t_w w;
  size_t i;
  w.p = out;
  w.n = 0;
  w.cap = cap;
  w.over = 0;

  t_put_head(&w, 4, 8);
  t_put_head(&w, 0, CC_WIRE_VERSION);
  t_put_head(&w, 0, CC_MSG_GROUP_DATA);
  t_put_head(&w, 0, hops);
  t_put_head(&w, 2, CC_GROUP_GID_SZ);
  for (i = 0; i < CC_GROUP_GID_SZ; i++) t_put(&w, gid[i]);
  t_put_head(&w, 2, CC_ADDR_SZ);
  for (i = 0; i < CC_ADDR_SZ; i++) t_put(&w, poster[i]);
  t_put_head(&w, 0, seq);
  t_put_head(&w, 0, t_nonce_placeholder());
  t_put_head(&w, 2, 32);
  t_put_fill(&w, tag, 32);
  return w.over ? 0 : w.n;
}

/* The same, mined at this build's group difficulty: what a sender pays. */
static size_t t_mint_post(uint8_t* out, size_t cap, uint8_t hops,
                          const uint8_t gid[CC_GROUP_GID_SZ],
                          const uint8_t poster[CC_ADDR_SZ], uint32_t seq,
                          uint8_t tag) {
  size_t len = t_mint_post_raw(out, cap, hops, gid, poster, seq, tag);
  if (len == 0 ||
      t_mine_at(out, len, T_EL_POST_NONCE, CC_POW_DIFFICULTY_GROUP) != 0)
    return 0;
  return len;
}

/* A link_req (which carries no destination on the wire at all) and a
 * link_data record (which carries only a link_id): the traffic a relay must
 * not carry. */
static size_t t_mint_link_req(uint8_t* out, size_t cap, uint8_t tag) {
  t_w w;
  w.p = out;
  w.n = 0;
  w.cap = cap;
  w.over = 0;
  t_put_head(&w, 4, 7);
  t_put_head(&w, 0, CC_WIRE_VERSION);
  t_put_head(&w, 0, CC_MSG_LINK_REQ);
  t_put_head(&w, 0, 0);
  t_put_head(&w, 0, 1);
  t_put_head(&w, 0, CC_SUITE);
  t_put_head(&w, 2, CC_LINK_ID_SZ);
  t_put_fill(&w, tag, CC_LINK_ID_SZ);
  t_put_head(&w, 2, CC_KEM_CT_SZ);
  t_put_fill(&w, tag, CC_KEM_CT_SZ);
  return w.over ? 0 : w.n;
}

static size_t t_mint_link_data(uint8_t* out, size_t cap, uint8_t tag) {
  t_w w;
  w.p = out;
  w.n = 0;
  w.cap = cap;
  w.over = 0;
  t_put_head(&w, 4, 6);
  t_put_head(&w, 0, CC_WIRE_VERSION);
  t_put_head(&w, 0, CC_MSG_LINK_DATA);
  t_put_head(&w, 0, 0);
  t_put_head(&w, 2, CC_LINK_ID_SZ);
  t_put_fill(&w, tag, CC_LINK_ID_SZ);
  t_put_head(&w, 0, 1);
  t_put_head(&w, 2, 64);
  t_put_fill(&w, tag, 64);
  return w.over ? 0 : w.n;
}

/* Feed an announcement the way an application does: parse it (PoW, signature,
 * address derivation all happen there), then decide. `from` is the link-layer
 * source, or NULL for a medium that does not attribute senders. `out` MUST be
 * at least CC_ANN_BUF_SZ bytes: that is the size promised to the relay. */
static int t_feed(cc_relay_t* r, const uint8_t* pkt, size_t len,
                  const uint8_t* from, uint8_t quality, uint32_t now,
                  uint8_t* out, size_t* out_len) {
  cc_announce_t ann;
  if (cc_announce_parse(&g_w, pkt, len, &ann) != CC_OK)
    return 0x7FFFFFFF; /* a broken fixture must fail the assertion loudly */
  return cc_relay_announce(r, &ann, from, quality, now, pkt, len, out,
                           CC_ANN_BUF_SZ, out_len);
}

/* The same announcement `n` relays further along the wire, in buf_a. */
static size_t t_hop_up(const uint8_t* in, size_t in_len, size_t n,
                       uint8_t* buf_a, uint8_t* buf_b) {
  size_t len = in_len, out_len = 0;
  size_t i;
  memcpy(buf_a, in, in_len);
  for (i = 0; i < n; i++) {
    if (cc_hops_increment(buf_a, len, buf_b, CC_ANN_BUF_SZ, &out_len) != CC_OK)
      return 0;
    memcpy(buf_a, buf_b, out_len);
    len = out_len;
  }
  return len;
}

/* ---------------------------------------------------------------------------
 * Fixture
 * ------------------------------------------------------------------------- */

static int t_node_init(t_node_t* n, const char* name, uint32_t seq,
                       uint32_t expiry, const uint8_t* admit, WC_RNG* rng) {
  size_t name_len = strlen(name);
  if (cc_key_generate(&n->key, rng) != CC_OK)
    return -1;
  if (cc_key_export_public(&n->key, n->sign_pub, n->kem_pub) != CC_OK)
    return -1;
  if (cc_addr_from_key(&n->key, n->addr) != CC_OK)
    return -1;
  if (cc_announce_build(&g_w, &n->key, name, name_len, NULL, 0, admit, seq,
                        expiry, n->ann, sizeof(n->ann), &n->ann_len,
                        rng) != CC_OK)
    return -1;
  return 0;
}

/* A second announcement from an identity already in the fixture. */
static int t_node_again(t_node_t* n, const t_node_t* from, uint32_t seq,
                        const uint8_t* admit, WC_RNG* rng) {
  memcpy(&n->key, &from->key, sizeof(cc_key_t));
  memcpy(n->sign_pub, from->sign_pub, CC_SIGN_PUBKEY_SZ);
  memcpy(n->kem_pub, from->kem_pub, CC_KEM_PUBKEY_SZ);
  memcpy(n->addr, from->addr, CC_ADDR_SZ);
  return cc_announce_build(&g_w, &n->key, "node0", 5, NULL, 0, admit, seq,
                           T_EXPIRY, n->ann, sizeof(n->ann), &n->ann_len,
                           rng) == CC_OK
             ? 0
             : -1;
}

static void t_fixture(WC_RNG* rng) {
  static const uint8_t hi[CC_ADMIT_SZ] = {2, CC_POW_NONE, CC_POW_NONE};
  char name[16];
  int i;

  for (i = 0; i < NDEST; i++) {
    snprintf(name, sizeof(name), "node%d", i);
    if (t_node_init(&g_node[i], name, 1, T_EXPIRY, NULL, rng) != 0) {
      printf("  FAIL: fixture node %d\n", i);
      g_failed++;
    }
  }
  if (t_node_again(&g_alice2, &g_node[0], 2, NULL, rng) != 0 ||
      t_node_again(&g_alice3, &g_node[0], 3, NULL, rng) != 0 ||
      t_node_again(&g_alice_hi, &g_node[0], 1, hi, rng) != 0) {
    printf("  FAIL: fixture announcements\n");
    g_failed++;
  }
  if (t_node_init(&g_carol, "carol", 1, T_EXPIRY, NULL, rng) != 0) {
    printf("  FAIL: fixture carol\n");
    g_failed++;
  }
}

/* ---------------------------------------------------------------------------
 * Sizes and accessors
 * ------------------------------------------------------------------------- */

static void test_sizes(void) {
  static cc_relay_t r;
  static cc_relay_stats_t st;
  cc_relay_budget_t b;
  cc_relay_gid_t gg;
  uint8_t gid_probe[CC_GROUP_GID_SZ] = {0};
  size_t bytes;
  cc_relay_path_t p;

  printf("state, sizes and accessors:\n");
  T("path_entry_bytes", sizeof(cc_relay_path_t) == 48);
  T("dup_slot_bytes", sizeof(cc_relay_dup_t) == 20);
  T("budget_slot_bytes", sizeof(cc_relay_budget_t) == 24);
  T("init", cc_relay_init(&r) == CC_OK);
  T("capacity", cc_relay_capacity(&r) == CC_RELAY_PATHS);
  T("empty", cc_relay_paths(&r, 0) == 0);
  bytes = cc_relay_bytes();
  T("bytes",
    bytes == sizeof(cc_relay_t) &&
        bytes == (size_t)CC_RELAY_PATHS * sizeof(cc_relay_path_t) +
                     (size_t)CC_RELAY_DUP * sizeof(cc_relay_dup_t) +
                     (size_t)CC_RELAY_BUDGETS * sizeof(cc_relay_budget_t) +
                     (size_t)CC_RELAY_GIDS * sizeof(cc_relay_gid_t) +
                     4 * sizeof(uint32_t) + sizeof(cc_relay_stats_t));
  printf(
      "  (relay %zu bytes: %d paths x %zu B, %d dup x %zu B, %d budgets x "
      "%zu B, %d gids x %zu B, pools+window %zu B, stats %zu B)\n",
      bytes, (int)CC_RELAY_PATHS, sizeof(cc_relay_path_t), (int)CC_RELAY_DUP,
      sizeof(cc_relay_dup_t), (int)CC_RELAY_BUDGETS, sizeof(cc_relay_budget_t),
      (int)CC_RELAY_GIDS, sizeof(cc_relay_gid_t), 4 * sizeof(uint32_t),
      sizeof(cc_relay_stats_t));

  memset(&st, 0xA5, sizeof(st));
  T("stats_copy",
    cc_relay_stats(&r, &st) == CC_OK && st.rx == 0 && st.forwarded == 0);
  T("unknown_lookup",
    cc_relay_path_lookup(&r, g_node[0].addr, 0, &p) == CC_RELAY_E_UNKNOWN);
  T("unknown_budget",
    cc_relay_budget_get(&r, g_node[0].addr, 0, &b) == CC_RELAY_E_UNKNOWN);
  T("null_init", cc_relay_init(NULL) == CC_RELAY_E_ARG);
  T("null_stats", cc_relay_stats(NULL, &st) == CC_RELAY_E_ARG);
  T("null_stats_out", cc_relay_stats(&r, NULL) == CC_RELAY_E_ARG);
  T("null_gid", cc_relay_gid_get(NULL, gid_probe, 0, &gg) == CC_RELAY_E_ARG &&
                    cc_relay_gid_get(&r, NULL, 0, &gg) == CC_RELAY_E_ARG &&
                    cc_relay_gid_get(&r, gid_probe, 0, NULL) == CC_RELAY_E_ARG);
  T("null_budget",
    cc_relay_budget_get(NULL, g_node[0].addr, 0, &b) == CC_RELAY_E_ARG &&
        cc_relay_budget_get(&r, NULL, 0, &b) == CC_RELAY_E_ARG &&
        cc_relay_budget_get(&r, g_node[0].addr, 0, NULL) == CC_RELAY_E_ARG);
  T("null_capacity", cc_relay_capacity(NULL) == CC_RELAY_E_ARG);
  T("null_paths", cc_relay_paths(NULL, 0) == CC_RELAY_E_ARG);
  T("null_lookup", cc_relay_path_lookup(&r, NULL, 0, &p) == CC_RELAY_E_ARG);
  T("null_lookup_out",
    cc_relay_path_lookup(&r, g_node[0].addr, 0, NULL) == CC_RELAY_E_ARG);
  T("null_forward", cc_relay_forward(NULL, g_chat, 1, 0, g_out, sizeof(g_out),
                                     NULL) == CC_RELAY_E_ARG);
}

/* ---------------------------------------------------------------------------
 * Announce learning: content age decides, and the origin may always speak
 * ------------------------------------------------------------------------- */

static void test_announce(void) {
  static cc_relay_t r;
  static cc_relay_stats_t st;
  cc_relay_path_t p;
  size_t pkt_len = g_node[0].ann_len, out_len = 0, up_len;
  const uint8_t* pkt = g_node[0].ann;
  uint32_t now = 100;

  printf("announce learning and forwarding:\n");
  cc_relay_init(&r);
  memcpy(g_ann_saved, pkt, pkt_len);

  /* alice announces to a node in range: hops 0, and it arrives from alice */
  T("direct_forward", t_feed(&r, pkt, pkt_len, g_node[0].addr, 7, now, g_out,
                             &out_len) == CC_RELAY_FWD);
  T("hops_one", t_hops(g_out, out_len) == 1);
  T("only_hops_changed", t_only_hops_differs(pkt, pkt_len, g_out, out_len));
  T("input_untouched", memcmp(g_ann_saved, pkt, pkt_len) == 0);
  T("learned", cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK &&
                   memcmp(p.next_hop, g_node[0].addr, CC_ADDR_SZ) == 0 &&
                   p.hops == 0 && p.quality == 7 && p.ann_seq == 1 &&
                   p.used == 1 &&
                   p.admit[CC_ADMIT_CHAT] == CC_POW_DIFFICULTY_CHAT);
  T("count", cc_relay_paths(&r, now) == 1);
  T("stats", cc_relay_stats(&r, &st) == CC_OK && st.rx == 1 &&
                 st.forwarded == 1 && st.learned == 1 && st.airtime == out_len);

  /* the same bytes again: a replay, not a second broadcast */
  T("replay_dup", t_feed(&r, pkt, pkt_len, g_node[0].addr, 7, now, g_out,
                         &out_len) == CC_RELAY_E_DUP &&
                      out_len == 0);
  T("replay_not_forwarded",
    cc_relay_stats(&r, &st) == CC_OK && st.forwarded == 1 && st.e_dup == 1);

  /* a re-stamped copy of what this relay already forwarded is the same
   * announcement: the digest ignores the hop count, so it is a duplicate */
  up_len = t_hop_up(pkt, pkt_len, 1, g_ann_a, g_ann_b);
  T("restamp_dup", t_feed(&r, g_ann_a, up_len, g_node[1].addr, 0, now, g_out,
                          &out_len) == CC_RELAY_E_DUP);

  /* past the duplicate TTL the same announcement may be relayed again: the
   * origin speaking for itself always wins, so its direct announcement goes
   * out ("I still have alice in range") */
  now += CC_RELAY_DUP_TTL + 1;
  T("origin_again_forwarded", t_feed(&r, pkt, pkt_len, g_node[0].addr, 7, now,
                                     g_out, &out_len) == CC_RELAY_FWD);
  T("liveness_refreshed",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK &&
        p.last_seen == now);
  /* the same content relayed by a neighbour is nothing new: the sequence is
   * already held, so it may neither move the route nor be re-broadcast */
  now += CC_RELAY_DUP_TTL + 1;
  up_len = t_hop_up(pkt, pkt_len, 1, g_ann_a, g_ann_b);
  T("relayed_same_seq_noimprove",
    t_feed(&r, g_ann_a, up_len, g_node[1].addr, 3, now, g_out, &out_len) ==
        CC_RELAY_E_NOIMPROVE);
  T("noimprove_not_forwarded", cc_relay_stats(&r, &st) == CC_OK &&
                                   st.forwarded == 2 && st.e_noimprove == 1);

  /*
   * Route age is the signed sequence number, not the hop count and not who is
   * talking. Start from a 3-hop route learned from alice's second
   * announcement.
   */
  cc_relay_init(&r);
  now = 200;
  up_len = t_hop_up(g_alice2.ann, g_alice2.ann_len, 2, g_ann_a, g_ann_b);
  T("far_learn", t_feed(&r, g_ann_a, up_len, g_node[1].addr, 1, now, g_out,
                        &out_len) == CC_RELAY_FWD);
  T("far_route",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK && p.hops == 2 &&
        memcmp(p.next_hop, g_node[1].addr, CC_ADDR_SZ) == 0 && p.ann_seq == 2);

  /* an OLDER announcement, one hop closer, from another neighbour: the hop
   * count is a claim, the sequence is a fact, and the claim may not win */
  up_len = t_hop_up(pkt, pkt_len, 1, g_ann_a, g_ann_b);
  T("older_content_refused", t_feed(&r, g_ann_a, up_len, g_node[2].addr, 1, now,
                                    g_out, &out_len) == CC_RELAY_E_NOIMPROVE);
  T("older_route_unchanged",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK && p.hops == 2 &&
        memcmp(p.next_hop, g_node[1].addr, CC_ADDR_SZ) == 0);

  /* newer content may come from any neighbour and move the route there: a
   * route is never stuck on a neighbour that went away */
  up_len = t_hop_up(g_alice3.ann, g_alice3.ann_len, 1, g_ann_a, g_ann_b);
  T("newer_content_moves", t_feed(&r, g_ann_a, up_len, g_node[2].addr, 3, now,
                                  g_out, &out_len) == CC_RELAY_FWD);
  T("newer_route",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK && p.hops == 1 &&
        memcmp(p.next_hop, g_node[2].addr, CC_ADDR_SZ) == 0 && p.ann_seq == 3);

  /* the same sequence from a stranger cannot move it back (after the dup TTL,
   * so it is judged by the table and not by the cache) */
  now += CC_RELAY_DUP_TTL + 1;
  T("same_seq_stranger_refused",
    t_feed(&r, g_ann_a, up_len, g_node[1].addr, 1, now, g_out, &out_len) ==
        CC_RELAY_E_NOIMPROVE);
  T("same_seq_route_unchanged",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK &&
        memcmp(p.next_hop, g_node[2].addr, CC_ADDR_SZ) == 0);

  /* ... but the origin speaking for itself always wins, at any sequence: that
   * is how an owner takes its own route back */
  T("origin_reclaims", t_feed(&r, pkt, pkt_len, g_node[0].addr, 4, now, g_out,
                              &out_len) == CC_RELAY_FWD);
  T("origin_route",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK && p.hops == 0 &&
        memcmp(p.next_hop, g_node[0].addr, CC_ADDR_SZ) == 0 && p.ann_seq == 3);
}

/* ---------------------------------------------------------------------------
 * The hijack the sequence rules close (R1), and the reclaim they allow (F1)
 * ------------------------------------------------------------------------- */

static void test_hijack(void) {
  static cc_relay_t r;
  static cc_relay_stats_t st;
  cc_relay_path_t p;
  uint32_t now = 300;
  size_t len, out_len = 0;

  printf("route hijack attempts:\n");
  cc_relay_init(&r);
  /* a route to alice through node1, three hops out, learned from her second
   * announcement */
  len = t_hop_up(g_alice2.ann, g_alice2.ann_len, 2, g_ann_a, g_ann_b);
  T("learn_far", t_feed(&r, g_ann_a, len, g_node[1].addr, 1, now, g_out,
                        &out_len) == CC_RELAY_FWD);

  /*
   * The attack: replay the announcement with hops rewritten lower, from your
   * own address. hops is outside the PoW, the signature and the tag, so the
   * packet stays valid (the next assertion proves it), and the relay's rules
   * are what stop it.
   */
  memcpy(g_ann_a, g_alice2.ann, g_alice2.ann_len); /* hops 0: one byte */
  T("forgery_still_pows", cc_pow_verify(g_ann_a, g_alice2.ann_len) == CC_OK);
  T("hijack_origin", t_feed(&r, g_ann_a, g_alice2.ann_len, g_node[2].addr, 0,
                            now, g_out, &out_len) == CC_RELAY_E_ORIGIN);
  T("origin_route_unchanged",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK && p.hops == 2 &&
        memcmp(p.next_hop, g_node[1].addr, CC_ADDR_SZ) == 0);

  /* the same content one hop up: a re-stamp of what this relay already
   * forwarded, so the duplicate digest catches it */
  len = t_hop_up(g_alice2.ann, g_alice2.ann_len, 1, g_ann_a, g_ann_b);
  T("hijack_restamp_dup", t_feed(&r, g_ann_a, len, g_node[2].addr, 0, now,
                                 g_out, &out_len) == CC_RELAY_E_DUP);

  /* once the cache has moved on, the same rewrite is judged by the table, and
   * an equal sequence still cannot move the route */
  now += CC_RELAY_DUP_TTL + 1;
  T("hijack_same_seq_refused", t_feed(&r, g_ann_a, len, g_node[2].addr, 0, now,
                                      g_out, &out_len) == CC_RELAY_E_NOIMPROVE);
  T("foreign_route_still_unchanged",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK && p.hops == 2 &&
        memcmp(p.next_hop, g_node[1].addr, CC_ADDR_SZ) == 0);

  /* an OLDER announcement replayed with a shorter claim: never, for anyone */
  len = t_hop_up(g_node[0].ann, g_node[0].ann_len, 1, g_ann_a, g_ann_b);
  T("hijack_older_refused", t_feed(&r, g_ann_a, len, g_node[2].addr, 0, now,
                                   g_out, &out_len) == CC_RELAY_E_NOIMPROVE);
  T("older_route_still_unchanged",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK && p.hops == 2 &&
        memcmp(p.next_hop, g_node[1].addr, CC_ADDR_SZ) == 0);

  /* the legitimate owner returns and announces from its own address: the
   * shortest claim there is, and it always wins */
  T("owner_reclaims",
    t_feed(&r, g_node[0].ann, g_node[0].ann_len, g_node[0].addr, 0, now, g_out,
           &out_len) == CC_RELAY_FWD);
  T("owner_route",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK && p.hops == 0 &&
        memcmp(p.next_hop, g_node[0].addr, CC_ADDR_SZ) == 0 && p.ann_seq == 2);
  cc_relay_stats(&r, &st);
  T("owner_forwarded", st.forwarded == 2 && st.e_origin == 1);
}

/* ---------------------------------------------------------------------------
 * A road that cannot attribute senders
 * ------------------------------------------------------------------------- */

static void test_unattributed(void) {
  static cc_relay_t r;
  cc_relay_path_t p;
  uint32_t now = 400;
  size_t len, out_len = 0;

  printf("a road that does not attribute senders (from == NULL):\n");
  cc_relay_init(&r);

  /* hops 0 is accepted (there is nothing to check it against), and the entry
   * records the claim without pretending to know where to send */
  T("hops0_accepted", t_feed(&r, g_node[0].ann, g_node[0].ann_len, NULL, 0, now,
                             g_out, &out_len) == CC_RELAY_FWD);
  T("no_origin_refusal_here",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK);
  T("next_hop_is_none", t_all_zero(p.next_hop, CC_ADDR_SZ));

  /* newer content moves the entry, because there is no neighbour to ask */
  len = t_hop_up(g_alice2.ann, g_alice2.ann_len, 1, g_ann_a, g_ann_b);
  T("newer_content_moves",
    t_feed(&r, g_ann_a, len, NULL, 0, now, g_out, &out_len) == CC_RELAY_FWD);
  T("moved", cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK &&
                 p.hops == 1 && p.ann_seq == 2 &&
                 t_all_zero(p.next_hop, CC_ADDR_SZ));

  /* and the sequence rules are what protect the table: a re-stamped replay of
   * the content already held cannot take it, whatever it claims */
  len = t_hop_up(g_alice2.ann, g_alice2.ann_len, 2, g_ann_a, g_ann_b);
  T("restamp_without_attribution_refused",
    t_feed(&r, g_ann_a, len, NULL, 0, now, g_out, &out_len) == CC_RELAY_E_DUP);
  now += CC_RELAY_DUP_TTL + 1;
  len = t_hop_up(g_alice2.ann, g_alice2.ann_len, 2, g_ann_a, g_ann_b);
  T("same_seq_without_attribution_refused",
    t_feed(&r, g_ann_a, len, NULL, 0, now, g_out, &out_len) ==
        CC_RELAY_E_NOIMPROVE);
  T("unattributed_route_kept",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK && p.hops == 1);

  /* data still forwards toward the entry */
  len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr, g_node[0].addr,
                    1, 0x11);
  T("data_forwards", cc_relay_forward(&r, g_chat, len, now, g_out,
                                      sizeof(g_out), &out_len) == CC_RELAY_FWD);
}

/* ---------------------------------------------------------------------------
 * Announce refusals: each distinct, and none of them touching the table
 * ------------------------------------------------------------------------- */

static void test_announce_refusals(void) {
  static cc_relay_t r;
  static uint8_t tmp[CC_ANN_BUF_SZ], short_pkt[CC_ANN_BUF_SZ];
  cc_announce_t ann;
  const uint8_t* pkt = g_node[0].ann;
  size_t pkt_len = g_node[0].ann_len, out_len = 0, hops_len, chat_len;
  uint32_t now = 100;

  printf("announce refusals:\n");
  cc_relay_init(&r);

  /* the fixture announcement's expiry is absolute: at it, the packet is stale
   */
  T("expired", t_feed(&r, pkt, pkt_len, g_node[0].addr, 0, T_EXPIRY, g_out,
                      &out_len) == CC_RELAY_E_EXPIRED);
  T("expired_untouched",
    cc_relay_paths(&r, T_EXPIRY) == 0 &&
        t_feed(&r, pkt, pkt_len, g_node[0].addr, 0, T_EXPIRY, g_out,
               &out_len) == CC_RELAY_E_EXPIRED);

  /* an announcement at hops 0 that did not come from the address it names */
  T("origin", t_feed(&r, pkt, pkt_len, g_node[2].addr, 0, now, g_out,
                     &out_len) == CC_RELAY_E_ORIGIN &&
                  out_len == 0);
  T("origin_untouched", cc_relay_paths(&r, now) == 0 &&
                            t_feed(&r, pkt, pkt_len, g_node[2].addr, 0, now,
                                   g_out, &out_len) == CC_RELAY_E_ORIGIN);

  /* hops at the maximum: the second copy is refused again rather than cached */
  hops_len = t_hop_up(pkt, pkt_len, CC_RELAY_MAX_HOPS, g_ann_a, g_ann_b);
  T("max_hops_ready",
    hops_len > 0 && t_hops(g_ann_a, hops_len) == CC_RELAY_MAX_HOPS);
  T("max_hops", t_feed(&r, g_ann_a, hops_len, g_node[0].addr, 0, now, g_out,
                       &out_len) == CC_RELAY_E_MAXHOPS);
  T("max_hops_untouched",
    cc_relay_paths(&r, now) == 0 &&
        t_feed(&r, g_ann_a, hops_len, g_node[0].addr, 0, now, g_out,
               &out_len) == CC_RELAY_E_MAXHOPS);

  /* another wire revision, refused on the first element */
  T("parse_fixture", cc_announce_parse(&g_w, pkt, pkt_len, &ann) == CC_OK);
  memcpy(tmp, pkt, pkt_len);
  T("patch", t_patch_version(tmp, pkt_len, (uint64_t)CC_WIRE_VERSION ^ 1) == 0);
  T("version",
    cc_relay_announce(&r, &ann, g_node[0].addr, 0, now, tmp, pkt_len, g_out,
                      CC_ANN_BUF_SZ, &out_len) == CC_RELAY_E_VERSION &&
        out_len == 0);
  T("version_untouched",
    cc_relay_announce(&r, &ann, g_node[0].addr, 0, now, tmp, pkt_len, g_out,
                      CC_ANN_BUF_SZ, &out_len) == CC_RELAY_E_VERSION);

  /* not an announcement at all: the caller parsed something else */
  chat_len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[0].addr,
                         g_node[1].addr, 7, 0x77);
  T("chat_minted", chat_len > 0);
  memcpy(g_chat_saved, g_chat, chat_len);
  T("not_an_announce",
    cc_relay_announce(&r, &ann, g_node[0].addr, 0, now, g_chat, chat_len, g_out,
                      CC_ANN_BUF_SZ, &out_len) == CC_RELAY_E_ARG);
  T("not_an_announce_untouched", memcmp(g_chat_saved, g_chat, chat_len) == 0);

  /* a truncated envelope cannot even be told what it is: no type, no hops */
  memcpy(short_pkt, pkt, pkt_len);
  T("truncated",
    cc_relay_announce(&r, &ann, g_node[0].addr, 0, now, short_pkt, 1, g_out,
                      CC_ANN_BUF_SZ, &out_len) == CC_RELAY_E_FORMAT);
  T("truncated_untouched",
    cc_relay_announce(&r, &ann, g_node[0].addr, 0, now, short_pkt, 1, g_out,
                      CC_ANN_BUF_SZ, &out_len) == CC_RELAY_E_FORMAT);

  /* an envelope that starts well — version, type and hops all parse — but is
   * not a complete packet: the re-stamp step is the full structural check, so
   * it is refused there, before the table can learn anything from it */
  T("cut_envelope",
    cc_relay_announce(&r, &ann, g_node[0].addr, 0, now, short_pkt, pkt_len / 2,
                      g_out, CC_ANN_BUF_SZ, &out_len) == CC_RELAY_E_FORMAT &&
        out_len == 0);
  T("cut_envelope_no_learn", cc_relay_paths(&r, now) == 0);

  T("nothing_learned", cc_relay_paths(&r, now) == 0);
}

/* ---------------------------------------------------------------------------
 * Data forwarding: price, duplicates, hops, buffers
 * ------------------------------------------------------------------------- */

static void test_forward(WC_RNG* rng) {
  static cc_relay_t r;
  static cc_relay_stats_t st;
  cc_relay_budget_t b;
  cc_relay_path_t p;
  uint8_t dest[CC_ADDR_SZ], hop1[CC_ADDR_SZ];
  size_t len, out_len = 0, unpaid_len, fwd_len = 0, cheap_len = 0,
              paid2_len = 0;
  uint32_t now = 200;
  int i, ret;

  printf("data forwarding:\n");
  cc_relay_init(&r);
  T("learn", t_feed(&r, g_node[0].ann, g_node[0].ann_len, g_node[0].addr, 5,
                    now, g_out, &out_len) == CC_RELAY_FWD);

  /* unknown destination */
  memcpy(dest, g_node[2].addr, CC_ADDR_SZ);
  len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr, dest, 1, 0x11);
  T("mint", len > 0);
  memcpy(g_chat_saved, g_chat, len);
  T("unknown_dest", cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out),
                                     &out_len) == CC_RELAY_E_UNKNOWN &&
                        out_len == 0);
  T("unknown_untouched", memcmp(g_chat_saved, g_chat, len) == 0);
  T("unknown_not_cached",
    cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out), &out_len) ==
        CC_RELAY_E_UNKNOWN);

  /* another revision, and a truncated envelope: both refused, and neither
   * touches the table (the repeat call gets the same code, so it did not enter
   * the duplicate cache either) */
  len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr, g_node[0].addr,
                    2, 0x21);
  T("chat_version_patched",
    t_patch_version(g_chat, len, (uint64_t)CC_WIRE_VERSION ^ 1) == 0);
  T("chat_version", cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out),
                                     &out_len) == CC_RELAY_E_VERSION);
  T("chat_version_again",
    cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out), &out_len) ==
        CC_RELAY_E_VERSION);
  len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr, g_node[0].addr,
                    3, 0x22);
  T("chat_truncated",
    cc_relay_forward(&r, g_chat, 40, now, g_out, sizeof(g_out), &out_len) ==
            CC_RELAY_E_FORMAT &&
        out_len == 0);
  T("chat_table_untouched", cc_relay_paths(&r, now) == 1);

  /*
   * Price of admission: a chat that never mined anything is refused, and
   * refused *before* any budget or cache slot is spent, so four of them cannot
   * silence the relay for a destination.
   */
  unpaid_len = t_mint_chat_raw(g_chat, sizeof(g_chat), 0, g_node[1].addr,
                               g_node[0].addr, 4, 0x30);
  T("unpaid_minted",
    unpaid_len > 0 && cc_pow_verify(g_chat, unpaid_len) != CC_OK);
  cc_relay_stats(&r, &st);
  {
    uint32_t data_before = st.window_data, fwd_before = st.forwarded;
    for (i = 0; i < 4; i++) {
      ret = cc_relay_forward(&r, g_chat, unpaid_len, now, g_out, sizeof(g_out),
                             &out_len);
      T(i == 0 ? "unpaid_refused" : "unpaid_refused_again",
        ret == CC_RELAY_E_POW && out_len == 0);
    }
    cc_relay_stats(&r, &st);
    T("unpaid_costs_nothing",
      st.window_data == data_before && st.forwarded == fwd_before);
  }

  /* a paid packet to a real destination: forwarded, and only the hops element
   * changed */
  len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr, g_node[0].addr,
                    5, 0x31);
  memcpy(g_chat_saved, g_chat, len);
  T("forward", cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out),
                                &out_len) == CC_RELAY_FWD);
  fwd_len = out_len; /* the refusals below clear out_len, so keep the length */
  T("forward_hops", t_hops(g_out, out_len) == 1);
  T("forward_only_hops", t_only_hops_differs(g_chat, len, g_out, out_len));
  T("forward_input_untouched", memcmp(g_chat_saved, g_chat, len) == 0);
  T("data_budget_charged",
    cc_relay_budget_get(&r, g_node[0].addr, now, &b) == CC_OK && b.count == 1);

  /* a duplicate inside the TTL, whatever its hop count */
  T("dup", cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out),
                            &out_len) == CC_RELAY_E_DUP);
  T("restamped_dup",
    cc_relay_forward(&r, g_out, fwd_len, now, g_fwd, sizeof(g_fwd), &out_len) ==
        CC_RELAY_E_DUP);

  /* hops at the maximum refuses; one below it is the last forwardable value */
  now += CC_RELAY_DUP_TTL + 1;
  T("refresh", t_feed(&r, g_node[0].ann, g_node[0].ann_len, g_node[0].addr, 5,
                      now, g_out, &out_len) == CC_RELAY_FWD);
  len = t_mint_chat(g_chat, sizeof(g_chat), CC_RELAY_MAX_HOPS, g_node[1].addr,
                    g_node[0].addr, 6, 0x32);
  T("max_hops", cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out),
                                 &out_len) == CC_RELAY_E_MAXHOPS);
  len = t_mint_chat(g_chat, sizeof(g_chat), CC_RELAY_MAX_HOPS - 1,
                    g_node[1].addr, g_node[0].addr, 7, 0x33);
  T("one_below_max",
    cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out), &out_len) ==
            CC_RELAY_FWD &&
        t_hops(g_out, out_len) == CC_RELAY_MAX_HOPS);

  /* out too small, and an overlapping out */
  len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr, g_node[0].addr,
                    8, 0x34);
  T("buf_too_small", cc_relay_forward(&r, g_chat, len, now, g_out, len,
                                      &out_len) == CC_RELAY_E_BUF);
  T("overlapping_out",
    cc_relay_forward(&r, g_chat, len, now, g_chat, sizeof(g_chat), &out_len) ==
        CC_RELAY_E_ARG);

  /* a stale route is not used, and is not counted as a live path either */
  now += CC_RELAY_PATH_TTL + 1;
  len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr, g_node[0].addr,
                    400, 0x52);
  T("stale_route", cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out),
                                    &out_len) == CC_RELAY_E_EXPIRED &&
                       out_len == 0);
  T("stale_not_counted", cc_relay_paths(&r, now) == 0 &&
                             cc_relay_path_lookup(&r, g_node[0].addr, now,
                                                  &p) == CC_RELAY_E_UNKNOWN);
  T("relearn", t_feed(&r, g_node[0].ann, g_node[0].ann_len, g_node[0].addr, 5,
                      now, g_out, &out_len) == CC_RELAY_FWD);
  memcpy(hop1, g_node[0].addr, CC_ADDR_SZ);
  T("relearned_route",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK &&
        memcmp(p.next_hop, hop1, CC_ADDR_SZ) == 0);

  /*
   * The destination's own published price. alice's fixture announcement asks
   * for this build's floor; g_alice_hi asks for two leading zero bytes, and a
   * relay must charge what the peer declared.
   */
  cc_relay_init(&r);
  now = 300;
  T("hi_learn", t_feed(&r, g_alice_hi.ann, g_alice_hi.ann_len, g_node[0].addr,
                       0, now, g_out, &out_len) == CC_RELAY_FWD);
  T("hi_price_stored",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_OK &&
        p.admit[CC_ADMIT_CHAT] == 2);
  /*
   * A chat built by the library, paying the build's own price (one byte) and
   * certainly not the two alice asks for: a packet mined at one leading zero
   * byte has a 1-in-256 chance of having two by luck, so this mints until it
   * has one that really is cheap rather than occasionally passing by accident.
   */
  for (i = 0; i < 8; i++) {
    cheap_len = 0;
    if (cc_chat_build(&g_w, &g_node[1].key, g_node[0].addr, g_node[0].kem_pub,
                      (uint32_t)(10 + i), (const uint8_t*)"hi", 2,
                      CC_POW_DIFFICULTY_CHAT, g_chat, sizeof(g_chat),
                      &cheap_len, rng) != CC_OK)
      break;
    if (cc_pow_verify_at(g_chat, cheap_len, 2) != CC_OK)
      break;
  }
  T("cheap_build", cheap_len > 0 && cc_pow_verify(g_chat, cheap_len) == CC_OK &&
                       cc_pow_verify_at(g_chat, cheap_len, 2) != CC_OK);
  T("declared_price_refuses_cheap",
    cc_relay_forward(&r, g_chat, cheap_len, now, g_out, sizeof(g_out),
                     &out_len) == CC_RELAY_E_POW &&
        out_len == 0);
  /* and one paying the two bytes alice's own announcement asks for */
  paid2_len = 0;
  T("paid2_build",
    cc_chat_build(&g_w, &g_node[1].key, g_node[0].addr, g_node[0].kem_pub, 11,
                  (const uint8_t*)"hi", 2, 2, g_chat, sizeof(g_chat),
                  &paid2_len, rng) == CC_OK);
  T("paid2_pow", cc_pow_verify_at(g_chat, paid2_len, 2) == CC_OK);
  T("declared_price_accepts_paid",
    cc_relay_forward(&r, g_chat, paid2_len, now, g_out, sizeof(g_out),
                     &out_len) == CC_RELAY_FWD);
}

/* ---------------------------------------------------------------------------
 * Pools: announcements may not starve data, and a conversation fits (F2/F4)
 * ------------------------------------------------------------------------- */

static void test_pools(void) {
  static cc_relay_t r;
  static cc_relay_stats_t st;
  cc_relay_budget_t b;
  size_t len, out_len = 0;
  uint32_t now = 4000;
  int i, ret, refused = 0;

  printf("the announce and data pools are separate:\n");
  cc_relay_init(&r);

  /*
   * Spend the announce pool: one announcement per distinct destination (the
   * table evicts the oldest, which is fine — this is about the pool), then one
   * newer announcement, until the relay refuses.
   */
  for (i = 0; i < NDEST; i++) {
    ret = t_feed(&r, g_node[i].ann, g_node[i].ann_len, g_node[i].addr, 0, now,
                 g_out, &out_len);
    if (ret != CC_RELAY_FWD)
      break;
  }
  T("distinct_announcements_forwarded", i == NDEST);
  ret = t_feed(&r, g_alice2.ann, g_alice2.ann_len, g_node[0].addr, 0, now,
               g_out, &out_len);
  T("newer_announcement_forwarded", ret == CC_RELAY_FWD);
  ret = t_feed(&r, g_alice3.ann, g_alice3.ann_len, g_node[0].addr, 0, now,
               g_out, &out_len);
  cc_relay_stats(&r, &st);
  refused = (ret == CC_RELAY_E_BUDGET);
  T("announce_pool_spent", refused && st.e_budget >= 1);
  T("announce_pool_is_the_cause",
    st.window_announce > 0 && st.window_data == 0);

  /* ... and data still forwards, even though the announce pool is gone: with
   * one shared pool the announcements above would have silenced this */
  len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr,
                    g_node[NDEST - 2].addr, 100, 0x70);
  T("data_survives_a_full_announce_pool",
    cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out), &out_len) ==
        CC_RELAY_FWD);

  /* a conversation through the relay: two messages out and one back is three
   * data packets for one destination inside the window */
  T("conversation_1",
    (len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr,
                       g_node[NDEST - 3].addr, 101, 0x71)) > 0 &&
        cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out),
                         &out_len) == CC_RELAY_FWD);
  T("conversation_2",
    (len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr,
                       g_node[NDEST - 3].addr, 102, 0x72)) > 0 &&
        cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out),
                         &out_len) == CC_RELAY_FWD);
  T("conversation_3",
    (len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr,
                       g_node[NDEST - 3].addr, 103, 0x73)) > 0 &&
        cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out),
                         &out_len) == CC_RELAY_FWD);
  T("conversation_budget_spent",
    cc_relay_budget_get(&r, g_node[NDEST - 3].addr, now, &b) == CC_OK &&
        b.count == CC_RELAY_FWD_BUDGET);
  T("conversation_stops_at_budget",
    (len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr,
                       g_node[NDEST - 3].addr, 104, 0x74)) > 0 &&
        cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out),
                         &out_len) == CC_RELAY_E_BUDGET);

  /* the window rolls: both pools and the counters come back */
  now += CC_RELAY_WINDOW + 1;
  T("pools_recover",
    (len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr,
                       g_node[NDEST - 3].addr, 105, 0x75)) > 0 &&
        cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out),
                         &out_len) == CC_RELAY_FWD);
}

/* ---------------------------------------------------------------------------
 * The data pool, and the per-destination budget inside it
 * ------------------------------------------------------------------------- */

static void test_data_budget(void) {
  static cc_relay_t r;
  static cc_relay_stats_t st;
  cc_relay_budget_t b;
  size_t len = 0, out_len = 0;
  uint32_t now = 5000;
  int i, ret = -1, dests = 0, refused_at = 0;

  printf("the data pool and the per-destination budget:\n");

  /* one destination: its own packet budget refuses while the pool has room */
  cc_relay_init(&r);
  T("learn", t_feed(&r, g_node[0].ann, g_node[0].ann_len, g_node[0].addr, 1,
                    now, g_out, &out_len) == CC_RELAY_FWD);
  for (i = 0; i < CC_RELAY_FWD_BUDGET + 2; i++) {
    len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr, g_node[0].addr,
                      (uint32_t)(200 + i), (uint8_t)(0x80 + i));
    ret =
        cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out), &out_len);
    if (ret != CC_RELAY_FWD)
      break;
  }
  cc_relay_stats(&r, &st);
  T("per_dest_budget", ret == CC_RELAY_E_BUDGET && out_len == 0);
  T("per_dest_budget_reason",
    cc_relay_budget_get(&r, g_node[0].addr, now, &b) == CC_OK &&
        b.count == CC_RELAY_FWD_BUDGET &&
        st.window_data + (uint32_t)len <= CC_RELAY_AIRTIME_DATA);

  /* the pool itself: many destinations, no destination at its own limit */
  cc_relay_init(&r);
  for (dests = 0; dests < NDEST - 1; dests++) {
    if (t_feed(&r, g_node[dests].ann, g_node[dests].ann_len, g_node[dests].addr,
               1, now, g_out, &out_len) != CC_RELAY_FWD)
      break;
  }
  T("dests_learned", dests == NDEST - 1);
  for (i = 0; i < 64; i++) {
    refused_at = i % dests;
    len = t_mint_chat_mined(g_chat, sizeof(g_chat), 0, g_node[NDEST - 1].addr,
                            g_node[refused_at].addr, (uint32_t)(1000 + i),
                            (uint8_t)(0x60 + i), CC_MAX_MSG_SZ,
                            CC_POW_DIFFICULTY_CHAT);
    ret =
        cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out), &out_len);
    if (ret != CC_RELAY_FWD)
      break;
  }
  cc_relay_stats(&r, &st);
  T("data_pool_refuses", ret == CC_RELAY_E_BUDGET && out_len == 0);
  T("data_pool_reason",
    st.window_data + (uint32_t)len > CC_RELAY_AIRTIME_DATA &&
        cc_relay_budget_get(&r, g_node[refused_at].addr, now, &b) == CC_OK &&
        b.count < CC_RELAY_FWD_BUDGET);
}

/* ---------------------------------------------------------------------------
 * Table pressure, and what it may not cost (R4)
 * ------------------------------------------------------------------------- */

static void test_eviction(void) {
  static cc_relay_t r;
  static cc_relay_stats_t st;
  cc_relay_budget_t b;
  cc_relay_path_t p;
  size_t out_len = 0;
  uint32_t now = 6000;
  int i, filled = 0;

  printf("table pressure:\n");
  cc_relay_init(&r);
  for (i = 0; i < CC_RELAY_PATHS; i++) {
    if (t_feed(&r, g_node[i].ann, g_node[i].ann_len, g_node[i].addr, 1, now,
               g_out, &out_len) != CC_RELAY_FWD)
      break;
    filled++;
    now += CC_RELAY_WINDOW + 1; /* a fresh announce pool per learn */
  }
  T("filled",
    filled == CC_RELAY_PATHS && cc_relay_paths(&r, now) == CC_RELAY_PATHS);

  /* one more origin evicts the least recently seen, not the newest */
  T("evicting_forward",
    t_feed(&r, g_node[CC_RELAY_PATHS].ann, g_node[CC_RELAY_PATHS].ann_len,
           g_node[CC_RELAY_PATHS].addr, 1, now, g_out,
           &out_len) == CC_RELAY_FWD);
  T("capacity_held", cc_relay_paths(&r, now) == CC_RELAY_PATHS);
  T("lru_evicted",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_RELAY_E_UNKNOWN);
  T("others_kept", cc_relay_path_lookup(&r, g_node[1].addr, now, &p) == CC_OK &&
                       memcmp(p.next_hop, g_node[1].addr, CC_ADDR_SZ) == 0);
  T("evictee_replaced",
    cc_relay_path_lookup(&r, g_node[CC_RELAY_PATHS].addr, now, &p) == CC_OK &&
        memcmp(p.next_hop, g_node[CC_RELAY_PATHS].addr, CC_ADDR_SZ) == 0);
  T("eviction_counted", cc_relay_stats(&r, &st) == CC_OK && st.evicted == 1 &&
                            st.learned == CC_RELAY_PATHS + 1);

  /*
   * An eviction storm must not hand a destination a fresh forwarding budget.
   * alice is the oldest entry (learned first) so the storm evicts her first;
   * her counter lives in the budget table, keyed by address, and survives.
   */
  cc_relay_init(&r);
  now = 7000;
  T("storm_learn_victim",
    t_feed(&r, g_node[0].ann, g_node[0].ann_len, g_node[0].addr, 1, now, g_out,
           &out_len) == CC_RELAY_FWD);
  {
    int k, ok = 1;
    for (k = 0; k < CC_RELAY_FWD_BUDGET; k++) {
      size_t len =
          t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr, g_node[0].addr,
                      (uint32_t)(5000 + k), (uint8_t)(0x90 + k));
      if (cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out),
                           &out_len) != CC_RELAY_FWD)
        ok = 0;
    }
    T("storm_spend_victim", ok);
  }
  T("victim_spent", cc_relay_budget_get(&r, g_node[0].addr, now, &b) == CC_OK &&
                        b.count == CC_RELAY_FWD_BUDGET);
  for (i = 1; i <= CC_RELAY_PATHS; i++) {
    if (t_feed(&r, g_node[i].ann, g_node[i].ann_len, g_node[i].addr, 1, now,
               g_out, &out_len) != CC_RELAY_FWD)
      break;
  }
  T("storm_filled", i == CC_RELAY_PATHS + 1);
  T("storm_evicted_victim",
    cc_relay_path_lookup(&r, g_node[0].addr, now, &p) == CC_RELAY_E_UNKNOWN);
  T("storm_kept_budget",
    cc_relay_budget_get(&r, g_node[0].addr, now, &b) == CC_OK &&
        b.count == CC_RELAY_FWD_BUDGET);

  /* the counter still binds, not just reads right: alice's own newest
   * announcement re-learns her route (the origin always wins), and the data
   * packet that follows is refused by the budget she already spent */
  T("storm_relearn", t_feed(&r, g_alice3.ann, g_alice3.ann_len, g_node[0].addr,
                            0, now, g_out, &out_len) == CC_RELAY_FWD);
  {
    size_t len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr,
                             g_node[0].addr, 5010, 0x9F);
    T("storm_budget_still_binds",
      cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out), &out_len) ==
          CC_RELAY_E_BUDGET);
  }
}

/* ---------------------------------------------------------------------------
 * Group posts: a broadcast class of their own
 * ------------------------------------------------------------------------- */

static void test_group(WC_RNG* rng) {
  static cc_relay_t r, r2;
  static cc_relay_stats_t st;
  cc_relay_gid_t g;
  static uint8_t post[CC_GROUP_BUF_SZ * 2];
  static uint8_t f1[CC_GROUP_BUF_SZ * 2], f2[CC_GROUP_BUF_SZ * 2];
  uint8_t gid1[CC_GROUP_GID_SZ], gid2[CC_GROUP_GID_SZ], poster[CC_ADDR_SZ];
  uint8_t type = 0, hops = 0;
  size_t len, out_len = 0, f1_len = 0, unpaid, chat_len = 0;
  uint32_t now = 20000;
  uint16_t g_count_before;
  int i, ret;

  printf("group posts (type 11, broadcast):\n");
  cc_relay_init(&r);
  memset(gid1, 0xA1, sizeof(gid1));
  memset(gid2, 0xB2, sizeof(gid2));
  memset(poster, 0xC3, CC_ADDR_SZ);

  /* the other two entry points stay closed to a post, and this one to them */
  len = t_mint_post(post, sizeof(post), 0, gid1, poster, 1, 0x01);
  T("post_minted", len > 0);
  chat_len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr,
                         g_node[0].addr, 1, 0x0F);
  T("chat_minted", chat_len > 0);
  T("forward_refuses_a_post",
    cc_relay_forward(&r, post, len, now, f1, sizeof(f1), &out_len) ==
        CC_RELAY_E_TYPE);
  T("group_refuses_a_chat",
    cc_relay_group(&r, g_chat, chat_len, now, f1, sizeof(f1), &out_len) ==
        CC_RELAY_E_TYPE);
  T("group_refuses_an_announce",
    cc_relay_group(&r, g_node[0].ann, g_node[0].ann_len, now, f1, sizeof(f1),
                   &out_len) == CC_RELAY_E_TYPE);

  /* a valid mined post is forwarded, and only its hops element changed */
  memcpy(g_fwd, post, len);
  T("forward", cc_relay_group(&r, post, len, now, f1, sizeof(f1), &out_len) ==
                   CC_RELAY_FWD);
  f1_len = out_len;
  T("hops_one", cc_msg_hops(f1, f1_len, &hops) == CC_OK && hops == 1);
  T("only_hops_changed", t_only_hops_differs(post, len, f1, f1_len));
  T("input_untouched", memcmp(g_fwd, post, len) == 0);
  T("type_kept",
    cc_msg_type(f1, f1_len, &type) == CC_OK && type == CC_MSG_GROUP_DATA);
  {
    uint8_t seen[CC_GROUP_GID_SZ];
    T("gid_kept", cc_group_gid(f1, f1_len, seen) == CC_OK &&
                      memcmp(seen, gid1, CC_GROUP_GID_SZ) == 0);
  }
  T("gid_budget_charged",
    cc_relay_gid_get(&r, gid1, now, &g) == CC_OK && g.count == 1);

  /* a duplicate inside the TTL, whatever its hop count */
  T("dup", cc_relay_group(&r, post, len, now, f1, sizeof(f1), &out_len) ==
               CC_RELAY_E_DUP);
  T("restamped_dup", cc_relay_group(&r, f1, f1_len, now, f2, sizeof(f2),
                                    &out_len) == CC_RELAY_E_DUP);

  /* an unmined post is refused, and refused before anything is spent */
  unpaid = t_mint_post_raw(post, sizeof(post), 0, gid2, poster, 2, 0x02);
  T("unpaid_minted", unpaid > 0 && cc_pow_verify_at(post, unpaid, 0) != CC_OK);
  cc_relay_stats(&r, &st);
  {
    size_t group_before = st.window_group, fwd_before = st.forwarded;
    for (i = 0; i < 4; i++) {
      ret = cc_relay_group(&r, post, unpaid, now, f1, sizeof(f1), &out_len);
      T(i == 0 ? "unpaid_refused" : "unpaid_refused_again",
        ret == CC_RELAY_E_POW && out_len == 0);
    }
    cc_relay_stats(&r, &st);
    T("unpaid_costs_nothing",
      st.window_group == group_before && st.forwarded == fwd_before);
  }
  T("unpaid_left_no_gid_budget",
    cc_relay_gid_get(&r, gid2, now, &g) == CC_RELAY_E_UNKNOWN);

  /* the per-group budget: one group cannot take the whole pool */
  for (i = 1; i < CC_RELAY_GROUP_BUDGET; i++) {
    len = t_mint_post(post, sizeof(post), 0, gid1, poster, (uint32_t)(10 + i),
                      (uint8_t)(0x10 + i));
    ret = cc_relay_group(&r, post, len, now, f1, sizeof(f1), &out_len);
    T(i == 1 ? "second_post_forwarded" : "third_post_forwarded",
      ret == CC_RELAY_FWD);
  }
  len = t_mint_post(post, sizeof(post), 0, gid1, poster, 20, 0x20);
  cc_relay_stats(&r, &st);
  T("gid_budget_refuses", cc_relay_group(&r, post, len, now, f1, sizeof(f1),
                                         &out_len) == CC_RELAY_E_BUDGET &&
                              out_len == 0);
  T("gid_budget_reason",
    cc_relay_gid_get(&r, gid1, now, &g) == CC_OK &&
        g.count == CC_RELAY_GROUP_BUDGET &&
        st.window_group + (uint32_t)len <= CC_RELAY_AIRTIME_GROUP);
  /* another group still posts in the same window */
  len = t_mint_post(post, sizeof(post), 0, gid2, poster, 21, 0x21);
  T("another_gid_posts", cc_relay_group(&r, post, len, now, f1, sizeof(f1),
                                        &out_len) == CC_RELAY_FWD);

  /* the hop cap, and one below it */
  len = t_mint_post(post, sizeof(post), CC_RELAY_MAX_HOPS_GROUP, gid2, poster,
                    22, 0x22);
  T("max_hops", cc_relay_group(&r, post, len, now, f1, sizeof(f1), &out_len) ==
                    CC_RELAY_E_MAXHOPS);
  len = t_mint_post(post, sizeof(post), CC_RELAY_MAX_HOPS_GROUP - 1, gid2,
                    poster, 23, 0x23);
  T("one_below_max", cc_relay_group(&r, post, len, now, f1, sizeof(f1),
                                    &out_len) == CC_RELAY_FWD &&
                         cc_msg_hops(f1, out_len, &hops) == CC_OK &&
                         hops == CC_RELAY_MAX_HOPS_GROUP);

  /* malformed, another revision and a wrong type: refused, nothing changes */
  T("gid_count_before_refusals",
    cc_relay_gid_get(&r, gid2, now, &g) == CC_OK && g.count == 2);
  g_count_before = g.count;
  len = t_mint_post(post, sizeof(post), 0, gid2, poster, 30, 0x30);
  T("cut_envelope", cc_relay_group(&r, post, len / 2, now, f1, sizeof(f1),
                                   &out_len) == CC_RELAY_E_FORMAT &&
                        out_len == 0);
  T("truncated", cc_relay_group(&r, post, 1, now, f1, sizeof(f1), &out_len) ==
                     CC_RELAY_E_FORMAT);
  {
    uint8_t* copy = f2;
    memcpy(copy, post, len);
    T("patch", t_patch_version(copy, len, (uint64_t)CC_WIRE_VERSION ^ 1) == 0);
    T("version", cc_relay_group(&r, copy, len, now, f1, sizeof(f1), &out_len) ==
                         CC_RELAY_E_VERSION &&
                     out_len == 0);
    T("version_again", cc_relay_group(&r, copy, len, now, f1, sizeof(f1),
                                      &out_len) == CC_RELAY_E_VERSION);
  }
  T("state_unchanged_by_refusals",
    cc_relay_gid_get(&r, gid2, now, &g) == CC_OK && g.count == g_count_before);

  /* ---- the pools are three, and none can starve another ---- */
  cc_relay_init(&r);
  now = 21000;
  for (i = 0; i < 40; i++) { /* exhaust the group pool */
    uint8_t g3[CC_GROUP_GID_SZ];
    memset(g3, (uint8_t)(0x40 + i), sizeof(g3));
    len = t_mint_post(post, sizeof(post), 0, g3, poster, (uint32_t)(40 + i),
                      (uint8_t)(0x40 + i));
    ret = cc_relay_group(&r, post, len, now, f1, sizeof(f1), &out_len);
    if (ret != CC_RELAY_FWD)
      break;
  }
  cc_relay_stats(&r, &st);
  T("group_pool_spent", i < 40 && st.e_budget >= 1);
  T("announce_still_flows",
    t_feed(&r, g_node[0].ann, g_node[0].ann_len, g_node[0].addr, 0, now, g_out,
           &out_len) == CC_RELAY_FWD);
  len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[1].addr, g_node[0].addr,
                    50, 0x50);
  T("data_still_flows",
    cc_relay_forward(&r, g_chat, len, now, g_out, sizeof(g_out), &out_len) ==
        CC_RELAY_FWD);
  {
    /* ... and a post still flows when data is the class that ran out */
    int dests = 0, chats = 0;
    cc_relay_init(&r2);
    for (dests = 0; dests < NDEST - 1; dests++) {
      if (t_feed(&r2, g_node[dests].ann, g_node[dests].ann_len,
                 g_node[dests].addr, 0, now, g_out, &out_len) != CC_RELAY_FWD)
        break;
    }
    T("storm_dests_learned", dests == NDEST - 1);
    for (chats = 0; chats < 16; chats++) {
      len = t_mint_chat(g_chat, sizeof(g_chat), 0, g_node[NDEST - 1].addr,
                        g_node[chats % dests].addr, (uint32_t)(100 + chats),
                        (uint8_t)(0x70 + chats));
      if (cc_relay_forward(&r2, g_chat, len, now, g_out, sizeof(g_out),
                           &out_len) != CC_RELAY_FWD)
        break;
    }
    cc_relay_stats(&r2, &st);
    T("data_storm_spent", chats < 16 && st.e_budget >= 1);
    len = t_mint_post(post, sizeof(post), 0, gid1, poster, 60, 0x60);
    T("post_flows_after_a_data_storm",
      cc_relay_group(&r2, post, len, now, f2, sizeof(f2), &out_len) ==
              CC_RELAY_FWD &&
          cc_relay_stats(&r2, &st) == CC_OK && st.window_group == out_len);
  }

  /* the window rolls: group budgets and pools come back */
  now += CC_RELAY_WINDOW + 1;
  len = t_mint_post(post, sizeof(post), 0, gid1, poster, 61, 0x61);
  T("group_recovers", cc_relay_group(&r2, post, len, now, f1, sizeof(f1),
                                     &out_len) == CC_RELAY_FWD);

  /*
   * End to end: a real group post crosses two relays and the far end decrypts
   * it. The sealer's own AEAD covers gid, poster, seq and the ciphertext, so a
   * relay that re-stamped anything but hops would break it.
   */
  {
    static cc_group_t grp;
    static cc_work_t w;
    static cc_group_win_t win;
    static cc_group_msg_t msg;
    static uint8_t chat_pkt[CC_GROUP_BUF_SZ];
    size_t chat_len = 0, l1 = 0, l2 = 0;
    const char* text = "hello, group";
    cc_relay_t ra, rb;

    cc_relay_init(&ra);
    cc_relay_init(&rb);
    T("group_create", cc_group_create(&grp, rng) == CC_OK);
    T("post_build",
      cc_group_post_build(&w, &grp, g_node[0].addr, 1, (const uint8_t*)text,
                          strlen(text), chat_pkt, sizeof(chat_pkt), &chat_len,
                          rng) == CC_OK);
    T("post_paid", cc_pow_verify_at(chat_pkt, chat_len, 0) == CC_OK);
    T("relay_one", cc_relay_group(&ra, chat_pkt, chat_len, now, f1, sizeof(f1),
                                  &l1) == CC_RELAY_FWD &&
                       cc_msg_hops(f1, l1, &hops) == CC_OK && hops == 1);
    T("relay_two",
      cc_relay_group(&rb, f1, l1, now, f2, sizeof(f2), &l2) == CC_RELAY_FWD &&
          cc_msg_hops(f2, l2, &hops) == CC_OK && hops == 2);
    T("chain_only_hops_changed",
      t_only_hops_differs(chat_pkt, chat_len, f2, l2));
    T("win_init", cc_group_win_init(&win, grp.gid, g_node[0].addr) == CC_OK);
    ret = cc_group_post_parse(&w, &grp, &win, f2, l2, now, &msg);
    T("member_decrypts", ret == CC_OK);
    T("member_message", ret == CC_OK && msg.msg_len == strlen(text) &&
                            memcmp(msg.msg, text, msg.msg_len) == 0 &&
                            msg.hops == 2);
    cc_group_free(&grp);
  }
}

/* ---------------------------------------------------------------------------
 * Types a relay does not carry
 * ------------------------------------------------------------------------- */

static void test_types(void) {
  static cc_relay_t r;
  static cc_relay_stats_t st;
  static uint8_t pkt[CC_LINK_REQ_BUF_SZ];
  size_t len, out_len = 0;
  uint32_t now = 8000;

  printf("types the relay does not carry:\n");
  cc_relay_init(&r);
  T("learn", t_feed(&r, g_node[0].ann, g_node[0].ann_len, g_node[0].addr, 1,
                    now, g_out, &out_len) == CC_RELAY_FWD);

  /* an announcement belongs in cc_relay_announce() */
  T("announce_via_forward",
    cc_relay_forward(&r, g_node[0].ann, g_node[0].ann_len, now, g_out,
                     sizeof(g_out), &out_len) == CC_RELAY_E_TYPE);

  /* link traffic: no destination on the wire, and a link only ever exists
   * between two nodes that completed a handshake over one road */
  len = t_mint_link_req(pkt, sizeof(pkt), 0xEE);
  T("link_req_minted", len > 0);
  T("link_req", cc_relay_forward(&r, pkt, len, now, g_out, sizeof(g_out),
                                 &out_len) == CC_RELAY_E_TYPE &&
                    out_len == 0);
  len = t_mint_link_data(pkt, sizeof(pkt), 0xEF);
  T("link_data_minted", len > 0);
  T("link_data", cc_relay_forward(&r, pkt, len, now, g_out, sizeof(g_out),
                                  &out_len) == CC_RELAY_E_TYPE);
  /* and neither of them entered the duplicate cache */
  T("link_data_again", cc_relay_forward(&r, pkt, len, now, g_out, sizeof(g_out),
                                        &out_len) == CC_RELAY_E_TYPE);
  T("types_counted",
    cc_relay_stats(&r, &st) == CC_OK && st.e_type == 4 && st.forwarded == 1);
}

/* ---------------------------------------------------------------------------
 * The chain: A -> B -> C
 * ------------------------------------------------------------------------- */

static void test_chain(WC_RNG* rng) {
  static cc_relay_t ra, rb, rc;
  static cc_relay_stats_t sa, sb, sc;
  cc_relay_path_t p;
  cc_announce_t ann_c;
  cc_replay_t replay;
  cc_chat_t chat;
  static uint8_t chat_pkt[CC_CHAT_BUF_SZ];
  static uint8_t za[CC_ADDR_SZ], zb[CC_ADDR_SZ];
  size_t chat_len = 0, out_len = 0, f1_len = 0, f2_len = 0;
  uint8_t hop_b[CC_ADDR_SZ], difficulty = 0;
  const char* msg = "hello carol, through bob";
  uint32_t now = 9000;
  int ret;

  printf("chain A -> B -> C:\n");
  cc_relay_init(&ra);
  cc_relay_init(&rb);
  cc_relay_init(&rc);
  memcpy(hop_b, g_node[1].addr, CC_ADDR_SZ);
  if (cc_announce_parse(&g_w, g_carol.ann, g_carol.ann_len, &ann_c) != CC_OK) {
    T("chain_fixture", 0);
    return;
  }

  /* A announces: B hears it from A itself, learns A is one hop away and
   * re-broadcasts; C hears that re-broadcast from B and learns A through B. */
  T("b_learns_a", t_feed(&rb, g_node[0].ann, g_node[0].ann_len, g_node[0].addr,
                         4, now, g_out, &out_len) == CC_RELAY_FWD &&
                      t_hops(g_out, out_len) == 1);
  T("c_learns_a_via_b", t_feed(&rc, g_out, out_len, hop_b, 3, now, g_fwd,
                               &f1_len) == CC_RELAY_FWD &&
                            t_hops(g_fwd, f1_len) == 2);
  T("c_route_to_a",
    cc_relay_path_lookup(&rc, g_node[0].addr, now, &p) == CC_OK &&
        memcmp(p.next_hop, hop_b, CC_ADDR_SZ) == 0 && p.hops == 1);

  /* C announces: B hears it directly, re-broadcasts, and A learns C via B */
  T("b_learns_c", t_feed(&rb, g_carol.ann, g_carol.ann_len, g_carol.addr, 4,
                         now, g_out, &out_len) == CC_RELAY_FWD);
  T("a_learns_c_via_b",
    t_feed(&ra, g_out, out_len, hop_b, 3, now, g_fwd, &f1_len) == CC_RELAY_FWD);
  T("a_route_to_c", cc_relay_path_lookup(&ra, g_carol.addr, now, &p) == CC_OK &&
                        memcmp(p.next_hop, hop_b, CC_ADDR_SZ) == 0 &&
                        p.hops == 1);

  /* A sends a real, signed and encapsulated chat to C, mined at the price
   * carol's own announcement asks senders to pay. It leaves A with hops = 1
   * (the relay at A, toward B) and reaches C with hops = 2, and C decrypts
   * it. */
  T("admit_for_peer", cc_admit_for(&ann_c, CC_MSG_CHAT, &difficulty) == CC_OK &&
                          difficulty >= CC_POW_DIFFICULTY_CHAT);
  T("chat_build",
    cc_chat_build(&g_w, &g_node[0].key, g_carol.addr, g_carol.kem_pub, 1,
                  (const uint8_t*)msg, strlen(msg), difficulty, chat_pkt,
                  sizeof(chat_pkt), &chat_len, rng) == CC_OK);
  T("chat_paid", cc_pow_verify(chat_pkt, chat_len) == CC_OK);
  T("chat_relayed_by_a",
    cc_relay_forward(&ra, chat_pkt, chat_len, now, g_fwd, sizeof(g_fwd),
                     &f1_len) == CC_RELAY_FWD &&
        t_hops(g_fwd, f1_len) == 1);
  T("chat_relayed_by_b",
    cc_relay_forward(&rb, g_fwd, f1_len, now, g_fwd2, sizeof(g_fwd2),
                     &f2_len) == CC_RELAY_FWD &&
        t_hops(g_fwd2, f2_len) == 2);
  T("chat_only_hops_changed",
    t_only_hops_differs(chat_pkt, chat_len, g_fwd2, f2_len));
  T("pow_survives_two_relays", cc_pow_verify(g_fwd2, f2_len) == CC_OK);
  T("recipient_survives", cc_msg_recipient(g_fwd2, f2_len, za) == CC_OK &&
                              memcmp(za, g_carol.addr, CC_ADDR_SZ) == 0);
  T("sender_survives", cc_chat_sender(g_fwd2, f2_len, zb) == CC_OK &&
                           memcmp(zb, g_node[0].addr, CC_ADDR_SZ) == 0);

  cc_replay_init(&replay, g_node[0].addr, CC_REPLAY_AUTHED);
  ret = cc_chat_parse(&g_w, &g_carol.key, g_node[0].sign_pub, &replay, g_fwd2,
                      f2_len, &chat);
  T("carol_decrypts", ret == CC_OK);
  T("carol_message", ret == CC_OK && chat.msg_len == strlen(msg) &&
                         memcmp(chat.msg, msg, chat.msg_len) == 0 &&
                         chat.hops == 2);

  /* the counters an app would show */
  cc_relay_stats(&ra, &sa);
  cc_relay_stats(&rb, &sb);
  cc_relay_stats(&rc, &sc);
  printf("  (announce %zu B, chat %zu B)\n", g_node[0].ann_len, chat_len);
  printf(
      "  (A: rx=%u fwd=%u learned=%u unknown=%u dup=%u | "
      "B: rx=%u fwd=%u learned=%u unknown=%u dup=%u | "
      "C: rx=%u fwd=%u learned=%u unknown=%u dup=%u)\n",
      sa.rx, sa.forwarded, sa.learned, sa.e_unknown, sa.e_dup, sb.rx,
      sb.forwarded, sb.learned, sb.e_unknown, sb.e_dup, sc.rx, sc.forwarded,
      sc.learned, sc.e_unknown, sc.e_dup);
  T("counters", sa.rx == 2 && sa.forwarded == 2 && sa.learned == 1 &&
                    sb.rx == 3 && sb.forwarded == 3 && sb.learned == 2 &&
                    sc.rx == 1 && sc.forwarded == 1 && sc.learned == 1);
}

int main(void) {
  WC_RNG rng;

  wc_InitRng(&rng);
  printf(
      "cosechat relay  (paths %d, dup %d, budgets %d, gids %d; max hops "
      "%d/%d; TTLs %d/%d; window %d; %d data per dest, %d posts per group; "
      "pools %d announce / %d data / %d group B; require pow %d)\n\n",
      (int)CC_RELAY_PATHS, (int)CC_RELAY_DUP, (int)CC_RELAY_BUDGETS,
      (int)CC_RELAY_GIDS, (int)CC_RELAY_MAX_HOPS, (int)CC_RELAY_MAX_HOPS_GROUP,
      (int)CC_RELAY_DUP_TTL, (int)CC_RELAY_PATH_TTL, (int)CC_RELAY_WINDOW,
      (int)CC_RELAY_FWD_BUDGET, (int)CC_RELAY_GROUP_BUDGET,
      (int)CC_RELAY_AIRTIME_ANNOUNCE, (int)CC_RELAY_AIRTIME_DATA,
      (int)CC_RELAY_AIRTIME_GROUP, (int)CC_RELAY_REQUIRE_POW);

  t_fixture(&rng);

  test_sizes();
  printf("\n");
  test_announce();
  printf("\n");
  test_hijack();
  printf("\n");
  test_unattributed();
  printf("\n");
  test_announce_refusals();
  printf("\n");
  test_forward(&rng);
  printf("\n");
  test_pools();
  printf("\n");
  test_data_budget();
  printf("\n");
  test_eviction();
  printf("\n");
  test_types();
  printf("\n");
  test_group(&rng);
  printf("\n");
  test_chain(&rng);

  wc_FreeRng(&rng);
  printf("\n%d passed, %d failed\n", g_passed, g_failed);
  return g_failed > 0 ? 1 : 0;
}
