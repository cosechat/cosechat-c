#include <pthread.h>
#include <stdio.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/random.h>

#include "cosechat.h"

static int g_passed = 0, g_failed = 0;

/* The suite is single-threaded, so one working context serves it; the
   reentrancy test declares its own pair. */
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

/* ---------------------------------------------------------------------------
 * Test-local wire helpers — the adversary side of the tests. Element indices
 * follow the sequences documented in include/cosechat.h, and every packet the
 * helpers build is canonical CBOR, because nothing else is accepted.
 * ------------------------------------------------------------------------- */
#define EL_ANN_NONCE 3
#define EL_ANN_SIGN_PUB 4
#define EL_ANN_KEM_PUB 5
#define EL_ANN_NAME 6
#define EL_ANN_META 7
#define EL_ANN_ADMIT 8
#define EL_ANN_SIG                                           \
  11 /* the signature is element 11: ver, type, hops, nonce, \
        sign_pub, kem_pub, name, meta, admit, seq, expiry, sig */
#define EL_CHAT_SENDER 3
#define EL_CHAT_RECIPIENT 4
#define EL_CHAT_KEM_CT 5
#define EL_CHAT_COUNTER 6
#define EL_CHAT_NONCE 7
#define EL_CHAT_ENCRYPT0 8
#define EL_CHAT_SIG 9
#define EL_PRES_NONCE 4
#define EL_REQ_NONCE 5

#define T_MAX_ELEMS 13 /* CC_PKT_MAX_ELEMS: a rotation fills the array */

static uint8_t t_tmp[CC_ROTATE_BUF_SZ];

/* Spans (offset and length) of the outer array's elements. */
static int t_spans(const uint8_t* pkt, size_t len, size_t* off, size_t* elen,
                   size_t* count) {
  size_t pos = 1, i;
  uint8_t ib, ai, major;
  uint64_t v;

  if (len < 2 || (pkt[0] >> 5) != 4 || (pkt[0] & 0x1F) > 23)
    return -1;
  *count = (size_t)(pkt[0] & 0x1F);
  if (*count > T_MAX_ELEMS)
    return -1; /* never write past the caller's arrays */
  for (i = 0; i < *count; i++) {
    size_t start = pos;
    if (pos >= len)
      return -1;
    ib = pkt[pos++];
    major = (uint8_t)(ib >> 5);
    ai = (uint8_t)(ib & 0x1F);
    if (ai < 24) {
      v = ai;
    } else if (ai == 24) {
      v = pkt[pos];
      pos += 1;
    } else if (ai == 25) {
      v = ((uint64_t)pkt[pos] << 8) | pkt[pos + 1];
      pos += 2;
    } else if (ai == 26) {
      v = ((uint64_t)pkt[pos] << 24) | ((uint64_t)pkt[pos + 1] << 16) |
          ((uint64_t)pkt[pos + 2] << 8) | pkt[pos + 3];
      pos += 4;
    } else {
      return -1;
    }
    if (major == 2 || major == 3)
      pos += (size_t)v;
    else if (major != 0)
      return -1;
    if (pos > len)
      return -1;
    off[i] = start;
    elen[i] = pos - start;
  }
  return 0;
}

/* Start of an element (its CBOR head). For a small uint the head is the value,
   so this is the byte to edit; t_body() would point past it. */
static size_t t_head(const uint8_t* pkt, size_t len, size_t elem) {
  size_t off[T_MAX_ELEMS], elen[T_MAX_ELEMS], n = 0;
  if (t_spans(pkt, len, off, elen, &n) != 0 || elem >= n)
    return 0;
  return off[elem];
}

/* First content byte of an element (past its CBOR header). */
static size_t t_body(const uint8_t* pkt, size_t len, size_t elem) {
  size_t off[T_MAX_ELEMS], elen[T_MAX_ELEMS], n = 0;
  uint8_t ai;
  size_t hdr;
  if (t_spans(pkt, len, off, elen, &n) != 0 || elem >= n)
    return 0;
  ai = (uint8_t)(pkt[off[elem]] & 0x1F);
  hdr = (ai < 24) ? 1 : ((ai == 24) ? 2 : ((ai == 25) ? 3 : 5));
  return off[elem] + hdr;
}

/* Span of one definite-length CBOR item of any major type. t_spans (above)
   only walks uints and strings, which is not enough for an envelope that
   carries a map, so the metadata tests need their own walker. */
static size_t t_item_end(const uint8_t* p, size_t len) {
  uint8_t major, ai;
  uint64_t v;
  size_t pos, n, i;

  if (len < 1)
    return 0;
  major = (uint8_t)(p[0] >> 5);
  ai = (uint8_t)(p[0] & 0x1F);
  if (ai < 24) {
    v = ai;
    pos = 1;
  } else if (ai == 24) {
    if (len < 2)
      return 0;
    v = p[1];
    pos = 2;
  } else if (ai == 25) {
    if (len < 3)
      return 0;
    v = ((uint64_t)p[1] << 8) | p[2];
    pos = 3;
  } else if (ai == 26) {
    if (len < 5)
      return 0;
    v = ((uint64_t)p[1] << 24) | ((uint64_t)p[2] << 16) |
        ((uint64_t)p[3] << 8) | p[4];
    pos = 5;
  } else {
    return 0;
  }
  if (major == 2 || major == 3) {
    if (v > len - pos)
      return 0;
    return pos + (size_t)v;
  }
  if (major == 0 || major == 1 || major == 7)
    return pos;
  if (major == 4 || major == 5) {
    for (i = 0; i < (size_t)v; i++) {
      for (size_t pair = 0; pair < ((major == 5) ? 2u : 1u); pair++) {
        n = t_item_end(p + pos, len - pos);
        if (n == 0)
          return 0;
        pos += n;
      }
    }
    return pos;
  }
  return 0; /* tags and indefinite lengths are not in this subset */
}

/* Offset of element elem's head in an envelope that may contain a map. */
static size_t t_elem_off(const uint8_t* pkt, size_t len, size_t elem) {
  size_t pos = 1, n, i;
  uint8_t count;

  if (len < 2 || (pkt[0] >> 5) != 4 || (pkt[0] & 0x1F) > 23)
    return 0;
  count = (uint8_t)(pkt[0] & 0x1F);
  for (i = 0; i < count; i++) {
    if (i == elem)
      return pos;
    n = t_item_end(pkt + pos, len - pos);
    if (n == 0)
      return 0;
    pos += n;
  }
  return 0;
}

/* Defined further down with the other helpers; declared here because the
   PoW-retry search is used by sections that are defined before it. */
static size_t t_mine_below(cc_work_t* w, int kind, const cc_key_t* key,
                           const uint8_t addr[CC_ADDR_SZ],
                           const uint8_t kem[CC_KEM_PUBKEY_SZ],
                           uint32_t counter, uint8_t mine_at, uint8_t bar,
                           uint8_t* out, size_t out_sz, WC_RNG* rng);

/* Every byte of buf must still be val: the non-ASan way to catch a write that
   lands in a neighbouring member of a struct. */
static int t_canary(const uint8_t* buf, size_t len, uint8_t val) {
  size_t i;
  for (i = 0; i < len; i++) {
    if (buf[i] != val)
      return 0;
  }
  return 1;
}

/* Rebuild pkt with element elem (a byte string) replaced by arbitrary bytes,
   keeping the rest of the envelope. This is how a valid packet is turned into
   a hostile one whose bytes no longer match any signature. */
static uint8_t t_swap_body[CC_WORK_CT_SZ];
static uint8_t t_swap_buf[CC_ROTATE_BUF_SZ];

static size_t t_swap_bstr(const uint8_t* pkt, size_t len, size_t elem,
                          const uint8_t* body, size_t body_len) {
  size_t off[T_MAX_ELEMS], elen[T_MAX_ELEMS], n = 0, o;
  uint8_t hdr[3];
  size_t hlen;

  if (t_spans(pkt, len, off, elen, &n) != 0 || elem >= n)
    return 0;
  if (body_len < 24) {
    hdr[0] = (uint8_t)(0x40 | body_len);
    hlen = 1;
  } else if (body_len < 256) {
    hdr[0] = 0x58;
    hdr[1] = (uint8_t)body_len;
    hlen = 2;
  } else if (body_len < 65536) {
    hdr[0] = 0x59;
    hdr[1] = (uint8_t)(body_len >> 8);
    hdr[2] = (uint8_t)body_len;
    hlen = 3;
  } else {
    return 0;
  }
  o = len - off[elem] - elen[elem]; /* tail after the old element */
  if (off[elem] + hlen + body_len + o > sizeof(t_swap_buf))
    return 0;
  memcpy(t_swap_buf, pkt, off[elem]);
  memcpy(t_swap_buf + off[elem], hdr, hlen);
  memcpy(t_swap_buf + off[elem] + hlen, body, body_len);
  memcpy(t_swap_buf + off[elem] + hlen + body_len, pkt + off[elem] + elen[elem],
         o);
  return off[elem] + hlen + body_len + o;
}

/* The bytes a signature covers: the whole envelope minus the listed elements.
   A rotation's new-key signature skips hops, the nonce and its own element, so
   this is also nonce-independent — the nonce can be re-mined afterwards
   without invalidating the signature. */
static uint8_t t_cov[CC_ROTATE_BUF_SZ];
static uint8_t t_rsig[CC_SIGN_SIG_SZ];

static size_t t_covered(const uint8_t* pkt, size_t len, const size_t* skip,
                        size_t nskip, uint8_t* out, size_t out_sz) {
  size_t pos, n = 1, i, j;
  uint8_t count;

  if (len < 2 || (pkt[0] >> 5) != 4 || (pkt[0] & 0x1F) > 23 || out_sz < 1)
    return 0;
  count = (uint8_t)(pkt[0] & 0x1F);
  out[0] = pkt[0];
  pos = 1;
  for (i = 0; i < count; i++) {
    size_t span = t_item_end(pkt + pos, len - pos);
    int drop = 0;
    if (span == 0 || n + span > out_sz)
      return 0;
    for (j = 0; j < nskip; j++) {
      if (skip[j] == i)
        drop = 1;
    }
    if (!drop) {
      memcpy(out + n, pkt + pos, span);
      n += span;
    }
    pos += span;
  }
  return n;
}

/* The caller's policy, in the one line a caller writes: before trusting an
   announce, starting or accepting a link, or parsing traffic from an address,
   ask whether that address is retired. */
static int t_trust(const cc_revoked_t* rv, const uint8_t addr[CC_ADDR_SZ],
                   uint32_t now) {
  return cc_revoked_check(rv, addr, now) == CC_OK;
}

/* A caller-shaped announce path, for testing that a retired address cannot be
   resurrected by replaying its announce. */
static int t_accept_announce(const cc_revoked_t* rv, cc_work_t* w,
                             const uint8_t* pkt, size_t len, uint32_t now) {
  cc_announce_t ann;
  if (cc_announce_parse(w, pkt, len, &ann) != CC_OK)
    return 0;
  if (!t_trust(rv, ann.addr, now))
    return 0;
  return cc_announce_fresh(NULL, &ann, now) == CC_OK;
}

/* Give the nonce element room for a 5-byte encoding, so a tampered packet can
   be re-mined in place whatever the original nonce width was. */
static size_t t_pad_nonce(const uint8_t* pkt, size_t len, size_t nonce_elem,
                          uint8_t* out) {
  static const uint8_t five[5] = {0x1a, 0, 0, 0, 0};
  size_t off[T_MAX_ELEMS], elen[T_MAX_ELEMS], n = 0, i, o = 0;
  if (t_spans(pkt, len, off, elen, &n) != 0 || nonce_elem >= n ||
      n > T_MAX_ELEMS)
    return 0;
  out[o++] = pkt[0];
  for (i = 0; i < n; i++) {
    if (i == nonce_elem) {
      memcpy(out + o, five, sizeof(five));
      o += sizeof(five);
    } else {
      memcpy(out + o, pkt + off[i], elen[i]);
      o += elen[i];
    }
  }
  return o;
}

/* Re-mine the PoW after tampering, using the library's own verifier as the
   oracle, so the test does not need to know the configured difficulty. */
static int t_remine(uint8_t* pkt, size_t* len, size_t nonce_elem) {
  size_t off[T_MAX_ELEMS], elen[T_MAX_ELEMS], n = 0, k;
  uint32_t cand;
  size_t padded = t_pad_nonce(pkt, *len, nonce_elem, t_tmp);
  if (padded == 0 || t_spans(t_tmp, padded, off, elen, &n) != 0)
    return -1;
  memcpy(pkt, t_tmp, padded);
  *len = padded;
  /* The padded slot is a 5-byte head, which is only canonical for values that
     need 5 bytes, so the search starts at 2^16. */
  for (cand = 0x10000u; cand < 0xFFFFFF00U; cand++) {
    for (k = 0; k < 4; k++)
      pkt[off[nonce_elem] + 1 + k] = (uint8_t)(cand >> (8 * k));
    if (cc_pow_verify(pkt, *len) == CC_OK)
      return 0;
  }
  return -1;
}

/* ---- adversary packet minting (tests only) ---- */

static size_t put_hdr(uint8_t* p, uint8_t major, size_t v) {
  if (v < 24) {
    p[0] = (uint8_t)((major << 5) | v);
    return 1;
  }
  if (v < 256) {
    p[0] = (uint8_t)((major << 5) | 24);
    p[1] = (uint8_t)v;
    return 2;
  }
  if (v < 65536) {
    p[0] = (uint8_t)((major << 5) | 25);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
    return 3;
  }
  p[0] = (uint8_t)((major << 5) | 26);
  p[1] = (uint8_t)(v >> 24);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 8);
  p[4] = (uint8_t)v;
  return 5;
}

static size_t put_uint(uint8_t* p, uint32_t v) { return put_hdr(p, 0, v); }

static size_t put_bstr(uint8_t* p, const uint8_t* d, size_t n) {
  size_t o = put_hdr(p, 2, n);
  if (d != NULL && n != 0)
    memcpy(p + o, d, n);
  return o + n;
}

/* Assemble a chat packet with arbitrary field contents and lengths, signing
   honestly over the covered envelope — the array head plus every element
   except hops, the nonce and the signature, i.e. ver, type, sender, recipient,
   kem_ct, counter, encrypt0 — unless a substitute signature is supplied.
   Returns the packet length, or 0. This is the attacker capability the field
   size contracts exist to bound. */
static size_t mint_chat(const cc_key_t* key, WC_RNG* rng, const uint8_t* sender,
                        const uint8_t* recipient, const uint8_t* kem,
                        size_t kem_len, const uint8_t* enc0, size_t enc0_len,
                        uint32_t counter, const uint8_t* sig_override,
                        size_t sig_override_len, uint32_t nonce, uint8_t* out,
                        size_t out_sz) {
  static uint8_t pre[4096];
  static uint8_t sig[CC_SIGN_SIG_SZ];
  size_t pl = 0, o = 0;
  word32 sl = sizeof(sig);

  if (32 + 2 * CC_ADDR_SZ + CC_KEM_CT_SZ + 4 + enc0_len > sizeof(pre))
    return 0;
  pl += put_hdr(pre + pl, 4, 10); /* the array head is inside the coverage */
  pl += put_uint(pre + pl, CC_WIRE_VERSION);
  pl += put_uint(pre + pl, CC_MSG_CHAT);
  pl += put_bstr(pre + pl, sender, CC_ADDR_SZ);
  pl += put_bstr(pre + pl, recipient, CC_ADDR_SZ);
  pl += put_bstr(pre + pl, kem, kem_len);
  pl += put_uint(pre + pl, counter);
  pl += put_bstr(pre + pl, enc0, enc0_len);

  if (sig_override == NULL) {
    if (wc_dilithium_sign_msg(pre, (word32)pl, sig, &sl,
                              (dilithium_key*)&key->sign, rng) != 0)
      return 0;
  } else {
    memcpy(sig, sig_override, sig_override_len);
    sl = (word32)sig_override_len;
  }

  if (o + 3 > out_sz)
    return 0;
  o += put_hdr(out + o, 4, 10);
  o += put_uint(out + o, CC_WIRE_VERSION);
  o += put_uint(out + o, CC_MSG_CHAT);
  o += put_uint(out + o, 0); /* hops */
  o += put_bstr(out + o, sender, CC_ADDR_SZ);
  o += put_bstr(out + o, recipient, CC_ADDR_SZ);
  o += put_bstr(out + o, kem, kem_len);
  o += put_uint(out + o, counter);
  nonce |= 0x01000000u; /* keep the nonce in its 5-byte encoding, so a test can
                           mine it in place */
  o += put_uint(out + o, nonce);
  o += put_bstr(out + o, enc0, enc0_len);
  o += put_bstr(out + o, sig, sl);
  if (o + 5 > out_sz)
    return 0;
  return o;
}

/* Splice: `pa` with element `ea` replaced by element `eb` of `pb`, then
   re-mined. Element sizes must match, so the swap exercises the crypto
   coverage instead of the field size contracts. Returns 0 when nothing would
   change (the packet would be the original) or when the mine fails. */
static size_t t_splice(const uint8_t* pa, size_t la, size_t ea,
                       const uint8_t* pb, size_t lb, size_t eb, uint8_t* out,
                       size_t out_sz, size_t nonce_elem) {
  size_t off[T_MAX_ELEMS], elen[T_MAX_ELEMS], n = 0;
  size_t boff[T_MAX_ELEMS], belen[T_MAX_ELEMS], bn = 0;
  size_t o = 0, i;

  if (t_spans(pa, la, off, elen, &n) != 0 ||
      t_spans(pb, lb, boff, belen, &bn) != 0)
    return 0;
  if (ea >= n || eb >= bn || elen[ea] != belen[eb])
    return 0;
  if (memcmp(pa + off[ea], pb + boff[eb], elen[ea]) == 0)
    return 0; /* equal bytes: not a splice, the packet would be unchanged */
  if (la + 5 > out_sz)
    return 0;
  out[o++] = pa[0]; /* one element for one: the array head count is unchanged */
  for (i = 0; i < n; i++) {
    if (i == ea) {
      memcpy(out + o, pb + boff[eb], belen[eb]);
      o += belen[eb];
    } else {
      memcpy(out + o, pa + off[i], elen[i]);
      o += elen[i];
    }
  }
  if (t_remine(out, &o, nonce_elem) != 0)
    return 0;
  return o;
}

/* ------------------------------------------------------------------------- */

static void test_keys(WC_RNG* rng) {
  /* static: cc_key_t ~13KB, too large for embedded stack */
  static cc_key_t key, imported;
  uint8_t sign_priv[CC_SIGN_PRIVKEY_SZ];
  uint8_t kem_priv[CC_KEM_PRIVKEY_SZ];
  uint8_t sign_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t kem_pub[CC_KEM_PUBKEY_SZ];
  uint8_t addr[CC_ADDR_SZ], addr2[CC_ADDR_SZ], addr3[CC_ADDR_SZ];
  printf("keys:\n");

  T("generate", cc_key_generate(&key, rng) == CC_OK);
  T("export_private",
    cc_key_export_private(&key, sign_priv, kem_priv) == CC_OK);
  T("export_public", cc_key_export_public(&key, sign_pub, kem_pub) == CC_OK);
  T("addr_from_key", cc_addr_from_key(&key, addr) == CC_OK);
  T("addr_from_sign_pubkey",
    cc_addr_from_sign_pubkey(sign_pub, addr2) == CC_OK);
  T("addr_consistent", memcmp(addr, addr2, CC_ADDR_SZ) == 0);
  T("import", cc_key_import(&imported, sign_priv, sign_pub, kem_priv) == CC_OK);
  cc_addr_from_key(&imported, addr3);
  T("import_addr_match", memcmp(addr, addr3, CC_ADDR_SZ) == 0);
  T("null_arg", cc_key_generate(NULL, rng) == CC_E_ARG);
  T("replay_state_fits_mcu_budget", sizeof(cc_replay_t) <= 32);

  cc_key_free(&key);
  cc_key_free(&imported);
}

/* Sliding-window semantics, exercised without packets. */
static void test_replay_unit(void) {
  cc_replay_t st;
  uint8_t peer[CC_ADDR_SZ], other[CC_ADDR_SZ];
  memset(peer, 0x11, sizeof(peer));
  memset(other, 0x22, sizeof(other));
  printf("replay window:\n");

  T("init", cc_replay_init(&st, peer, CC_REPLAY_UNSIGNED) == CC_OK);
  T("init_null", cc_replay_init(NULL, peer, CC_REPLAY_UNSIGNED) == CC_E_ARG);
  T("wrong_state_arg", cc_replay_check(&st, other, 1) == CC_E_ARG);
  T("first_fresh", cc_replay_check(&st, peer, 5) == CC_OK);
  T("duplicate_replay", cc_replay_check(&st, peer, 5) == CC_E_REPLAY);
  T("reordered_fresh", cc_replay_check(&st, peer, 3) == CC_OK);
  T("reordered_again_replay", cc_replay_check(&st, peer, 3) == CC_E_REPLAY);
  T("higher_fresh", cc_replay_check(&st, peer, 7) == CC_OK);
  T("gap_inside_window", cc_replay_check(&st, peer, 6) == CC_OK);
  T("null_state", cc_replay_check(NULL, peer, 1) == CC_E_ARG);
  T("null_addr", cc_replay_check(&st, NULL, 1) == CC_E_ARG);

  /* 5 is 195 behind after this jump: outside the window */
  T("big_jump_fresh", cc_replay_check(&st, peer, 200) == CC_OK);
  T("behind_window_stale", cc_replay_check(&st, peer, 5) == CC_E_STALE);
  T("window_edge_stale",
    cc_replay_check(&st, peer, 200 - CC_REPLAY_WINDOW) == CC_E_STALE);
  T("window_edge_minus_one_ok",
    cc_replay_check(&st, peer, 200 - CC_REPLAY_WINDOW + 1) == CC_OK);
}

/* Authenticated and unsigned traffic must not share a window, or a spoofed
   heartbeat could age out a peer's chat stream for free. */
static void test_replay_classes(WC_RNG* rng) {
  static cc_key_t alice, bob;
  uint8_t alice_sign_pub[CC_SIGN_PUBKEY_SZ];
  /* throwaway, and large enough for either key type */
  uint8_t tmp_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t bob_kem_pub[CC_KEM_PUBKEY_SZ];
  uint8_t alice_addr[CC_ADDR_SZ], bob_addr[CC_ADDR_SZ];
  static uint8_t pkt[CC_CHAT_BUF_SZ];
  static cc_chat_t chat;
  cc_replay_t chat_st, pres_st, bob_chat_st, bad;
  size_t len = 0;
  static const char msg[] = "still fresh";
  printf("replay traffic classes:\n");

  cc_key_generate(&alice, rng);
  cc_key_generate(&bob, rng);
  cc_key_export_public(&alice, alice_sign_pub, tmp_pub);
  cc_key_export_public(&bob, tmp_pub, bob_kem_pub);
  cc_addr_from_key(&alice, alice_addr);
  cc_addr_from_key(&bob, bob_addr);

  T("class_init",
    cc_replay_init(&chat_st, alice_addr, CC_REPLAY_AUTHED) == CC_OK &&
        cc_replay_init(&pres_st, alice_addr, CC_REPLAY_UNSIGNED) == CC_OK &&
        cc_replay_init(&bob_chat_st, bob_addr, CC_REPLAY_AUTHED) == CC_OK);
  T("unknown_class_rejected", cc_replay_init(&bad, alice_addr, 7) == CC_E_ARG);

  /* An authenticated window is not reachable through the unsigned API, so a
     spoofed presence counter cannot move it. */
  T("unsigned_api_refuses_authed_state",
    cc_replay_check(&chat_st, alice_addr, 5) == CC_E_ARG);
  T("spoofed_heartbeat_advances_unsigned_only",
    cc_replay_check(&pres_st, alice_addr, 0xFFFFFFFFu) == CC_OK);
  T("unsigned_window_still_dedups",
    cc_replay_check(&pres_st, alice_addr, 0xFFFFFFFFu) == CC_E_REPLAY);

  /* ... and the peer's chat stream is unaffected by that spoofed heartbeat,
     even though its counter is far below the spoofed one. */
  T("chat_build",
    cc_chat_build(&g_w, &alice, bob_addr, bob_kem_pub, 100, (const uint8_t*)msg,
                  strlen(msg), 0, pkt, sizeof(pkt), &len, rng) == CC_OK);
  T("chat_not_stale_after_spoof",
    cc_chat_parse(&g_w, &bob, alice_sign_pub, &chat_st, pkt, len, &chat) ==
        CC_OK);
  T("chat_replay_still_caught",
    cc_chat_parse(&g_w, &bob, alice_sign_pub, &chat_st, pkt, len, &chat) ==
        CC_E_REPLAY);

  /* Chat refuses an unsigned state, so chat traffic cannot be recorded in the
     heartbeat window either — and that window is left untouched. */
  T("chat_refuses_unsigned_state",
    cc_chat_parse(&g_w, &bob, alice_sign_pub, &pres_st, pkt, len, &chat) ==
        CC_E_ARG);
  T("unsigned_state_untouched_by_chat",
    cc_replay_check(&pres_st, alice_addr, 0xFFFFFFFFu) == CC_E_REPLAY);

  /* Wrong peer state is refused in both classes. */
  T("wrong_peer_state", cc_chat_parse(&g_w, &bob, alice_sign_pub, &bob_chat_st,
                                      pkt, len, &chat) == CC_E_ARG &&
                            cc_replay_check(&pres_st, bob_addr, 1) == CC_E_ARG);
}

static void test_announce(WC_RNG* rng) {
  static cc_key_t key;
  static cc_announce_t ann, ann2, ann3;
  static uint8_t pkt[CC_ANN_BUF_SZ], pkt2[CC_ANN_BUF_SZ], pkt3[CC_ANN_BUF_SZ];
  size_t pkt_len = 0, pkt2_len = 0, pkt3_len = 0;
  uint8_t expected_addr[CC_ADDR_SZ];
  uint8_t corrupt[CC_ANN_BUF_SZ];
  uint8_t meta_buf[] = {0xa1, 0x01, 0x02}; /* CBOR {1: 2} */
  uint8_t type, hops;
  printf("announce:\n");

  cc_key_generate(&key, rng);

  T("build", cc_announce_build(&g_w, &key, "Alice", 5, NULL, 0, NULL, 1, 0, pkt,
                               sizeof(pkt), &pkt_len, rng) == CC_OK);
  T("pkt_fits", pkt_len > 0 && pkt_len <= CC_ANN_BUF_SZ);
  printf("  (announce packet %zu bytes)\n", pkt_len);

  cc_msg_type(pkt, pkt_len, &type);
  T("msg_type", type == CC_MSG_ANNOUNCE);

  T("parse", cc_announce_parse(&g_w, pkt, pkt_len, &ann) == CC_OK);
  T("name", ann.name_len == 5 && memcmp(ann.name, "Alice", 5) == 0);
  T("hops_zero", ann.hops == 0);

  cc_addr_from_key(&key, expected_addr);
  T("addr_match", memcmp(ann.addr, expected_addr, CC_ADDR_SZ) == 0);

  T("pow_ok", cc_pow_verify(pkt, pkt_len) == CC_OK);

  /* Hop increment */
  T("hops_inc",
    cc_hops_increment(pkt, pkt_len, pkt2, sizeof(pkt2), &pkt2_len) == CC_OK);
  cc_msg_hops(pkt2, pkt2_len, &hops);
  T("hops_value", hops == 1);
  T("parse_after_hop", cc_announce_parse(&g_w, pkt2, pkt2_len, &ann2) == CC_OK);
  T("hops_after_hop", ann2.hops == 1);

  /* Metadata */
  cc_announce_build(&g_w, &key, "Bob", 3, meta_buf, sizeof(meta_buf), NULL, 1,
                    0, pkt3, sizeof(pkt3), &pkt3_len, rng);
  T("meta_parse", cc_announce_parse(&g_w, pkt3, pkt3_len, &ann3) == CC_OK);
  T("meta_len", ann3.meta_len == sizeof(meta_buf));
  T("meta_content", memcmp(ann3.meta, meta_buf, sizeof(meta_buf)) == 0);

  /* Corrupted signature rejected */
  memcpy(corrupt, pkt, pkt_len);
  corrupt[pkt_len - 10] ^= 0xFF;
  T("bad_sig_rejected",
    cc_announce_parse(&g_w, corrupt, pkt_len, &ann) != CC_OK);

  /* Over-long name/meta refused on the way in, never truncated on the way out
   */
  T("long_name_rejected_at_build",
    cc_announce_build(&g_w, &key, "x", CC_MAX_NAME_LEN + 1, NULL, 0, NULL, 1, 0,
                      pkt3, sizeof(pkt3), &pkt3_len, rng) == CC_E_ARG);
  T("long_meta_rejected_at_build",
    cc_announce_build(&g_w, &key, "x", 1, meta_buf, CC_MAX_META_SZ + 1, NULL, 1,
                      0, pkt3, sizeof(pkt3), &pkt3_len, rng) == CC_E_ARG);

  cc_key_free(&key);
}

static void test_chat(WC_RNG* rng) {
  static cc_key_t alice, bob;
  uint8_t alice_sign_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t bob_sign_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t alice_kem_pub[CC_KEM_PUBKEY_SZ];
  uint8_t bob_kem_pub[CC_KEM_PUBKEY_SZ];
  uint8_t alice_addr[CC_ADDR_SZ], bob_addr[CC_ADDR_SZ];
  uint8_t recip[CC_ADDR_SZ], sender[CC_ADDR_SZ];
  static uint8_t chat_pkt[CC_CHAT_BUF_SZ], routed[CC_CHAT_BUF_SZ];
  size_t chat_len = 0, routed_len = 0, corrupt_len = 0;
  static cc_chat_t chat, chat2;
  cc_replay_t st;
  static const char msg[] = "Hello Bob!";
  uint8_t corrupt[CC_CHAT_BUF_SZ];
  uint8_t type, hops;
  int ret, flip;
  printf("chat:\n");

  cc_key_generate(&alice, rng);
  cc_key_generate(&bob, rng);
  cc_key_export_public(&alice, alice_sign_pub, alice_kem_pub);
  cc_key_export_public(&bob, bob_sign_pub, bob_kem_pub);
  cc_addr_from_key(&alice, alice_addr);
  cc_addr_from_key(&bob, bob_addr);

  T("build", cc_chat_build(&g_w, &alice, bob_addr, bob_kem_pub, 100,
                           (const uint8_t*)msg, strlen(msg), 0, chat_pkt,
                           sizeof(chat_pkt), &chat_len, rng) == CC_OK);
  T("pkt_fits", chat_len > 0 && chat_len <= CC_CHAT_BUF_SZ);
  printf("  (chat packet %zu bytes)\n", chat_len);

  cc_msg_type(chat_pkt, chat_len, &type);
  T("msg_type", type == CC_MSG_CHAT);
  T("recipient_helper", cc_msg_recipient(chat_pkt, chat_len, recip) == CC_OK &&
                            memcmp(recip, bob_addr, CC_ADDR_SZ) == 0);
  T("sender_helper", cc_chat_sender(chat_pkt, chat_len, sender) == CC_OK &&
                         memcmp(sender, alice_addr, CC_ADDR_SZ) == 0);
  T("pow_ok", cc_pow_verify(chat_pkt, chat_len) == CC_OK);

  cc_replay_init(&st, alice_addr, CC_REPLAY_AUTHED);
  ret =
      cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, chat_pkt, chat_len, &chat);
  if (ret != CC_OK)
    printf("  bob parse ret=%d\n", ret);
  T("bob_decrypt", ret == CC_OK);
  T("msg_match", ret == CC_OK && chat.msg_len == strlen(msg) &&
                     memcmp(chat.msg, msg, chat.msg_len) == 0);
  T("sender_addr",
    ret == CC_OK && memcmp(chat.sender_addr, alice_addr, CC_ADDR_SZ) == 0);
  T("counter", ret == CC_OK && chat.counter == 100);

  /* The identical packet again: replay, not a second delivery */
  T("replay_rejected", cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, chat_pkt,
                                     chat_len, &chat) == CC_E_REPLAY);

  /* Unknown sender key is distinct from a bad signature */
  T("unknown_sender_nokey", cc_chat_parse(&g_w, &bob, NULL, &st, chat_pkt,
                                          chat_len, &chat) == CC_E_NOKEY);
  T("wrong_sender_key_nokey",
    cc_chat_parse(&g_w, &bob, bob_sign_pub, &st, chat_pkt, chat_len, &chat) ==
        CC_E_NOKEY);
  T("null_replay_state", cc_chat_parse(&g_w, &bob, alice_sign_pub, NULL,
                                       chat_pkt, chat_len, &chat) == CC_E_ARG);

  /* Wrong recipient key */
  cc_replay_init(&st, alice_addr, CC_REPLAY_AUTHED);
  T("wrong_key", cc_chat_parse(&g_w, &alice, alice_sign_pub, &st, chat_pkt,
                               chat_len, &chat2) != CC_OK);

  /* Corrupted signature, nonce not re-mined: the PoW gate catches it first,
   * which is what "the PoW covers every element" buys. Flipping one byte of a
   * 4.5 KB preimage leaves a 1-in-65536 chance that the digest still clears
   * the bar, so the corruption is searched for rather than hoped for: this
   * check is about the gate, not about the draw. */
  for (flip = 0; flip < 8; flip++) {
    memcpy(corrupt, chat_pkt, chat_len);
    corrupt[t_body(corrupt, chat_len, EL_CHAT_SIG) + 3 + flip] ^= 0xFF;
    corrupt_len = chat_len;
    if (cc_pow_verify(corrupt, corrupt_len) != CC_OK)
      break;
  }
  cc_replay_init(&st, alice_addr, CC_REPLAY_AUTHED);
  T("tampered_sig_caught_by_pow",
    flip < 8 && cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, corrupt,
                              corrupt_len, &chat2) == CC_E_POW);

  /* Same tamper, mined again (an attacker can afford that): now the signature
   * is what rejects it, and only a valid signature moves the replay window. */
  T("bad_sig_remined", t_remine(corrupt, &corrupt_len, EL_CHAT_NONCE) == 0);
  T("bad_sig_survives_pow_gate", cc_pow_verify(corrupt, corrupt_len) == CC_OK);
  cc_replay_init(&st, alice_addr, CC_REPLAY_AUTHED);
  T("bad_sig_rejected", cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, corrupt,
                                      corrupt_len, &chat2) == CC_E_SIG);
  /* A packet that failed the signature must not have moved the window: the
   * genuine packet carrying the same counter still parses. */
  T("bad_sig_counter_not_recorded",
    cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, chat_pkt, chat_len,
                  &chat2) == CC_OK);

  /* Hops routing keeps the packet valid and decryptable */
  cc_replay_init(&st, alice_addr, CC_REPLAY_AUTHED);
  T("hops_inc", cc_hops_increment(chat_pkt, chat_len, routed, sizeof(routed),
                                  &routed_len) == CC_OK);
  cc_msg_hops(routed, routed_len, &hops);
  T("hops_value", hops == 1);
  T("pow_after_hop", cc_pow_verify(routed, routed_len) == CC_OK);
  ret = cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, routed, routed_len,
                      &chat2);
  T("decrypt_after_hop", ret == CC_OK && chat2.msg_len == strlen(msg) &&
                             memcmp(chat2.msg, msg, chat2.msg_len) == 0);

  cc_key_free(&alice);
  cc_key_free(&bob);
}

/* Replay window and authenticity attacks, with real packets. */
static void test_chat_security(WC_RNG* rng) {
  static cc_key_t alice, bob, mallory;
  uint8_t alice_sign_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t bob_kem_pub[CC_KEM_PUBKEY_SZ];
  /* throwaway, and large enough for either key type */
  uint8_t tmp_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t alice_addr[CC_ADDR_SZ], bob_addr[CC_ADDR_SZ];
  uint8_t recip[CC_ADDR_SZ], claim[CC_ADDR_SZ];
  static uint8_t p5[CC_CHAT_BUF_SZ], p3[CC_CHAT_BUF_SZ], p100[CC_CHAT_BUF_SZ];
  static uint8_t forged[CC_CHAT_BUF_SZ], tampered[CC_CHAT_BUF_SZ];
  size_t l5 = 0, l3 = 0, l100 = 0, lforged = 0, ltampered = 0;
  static cc_chat_t chat;
  cc_replay_t st;
  static const char msg[] = "reorder me";
  int ret;
  printf("chat replay and forgery:\n");

  cc_key_generate(&alice, rng);
  cc_key_generate(&bob, rng);
  cc_key_generate(&mallory, rng);
  cc_key_export_public(&alice, alice_sign_pub, tmp_pub);
  cc_key_export_public(&bob, tmp_pub, bob_kem_pub);
  cc_addr_from_key(&alice, alice_addr);
  cc_addr_from_key(&bob, bob_addr);

  T("build_c5",
    cc_chat_build(&g_w, &alice, bob_addr, bob_kem_pub, 5, (const uint8_t*)msg,
                  strlen(msg), 0, p5, sizeof(p5), &l5, rng) == CC_OK);
  T("build_c3",
    cc_chat_build(&g_w, &alice, bob_addr, bob_kem_pub, 3, (const uint8_t*)msg,
                  strlen(msg), 0, p3, sizeof(p3), &l3, rng) == CC_OK);
  T("build_c100",
    cc_chat_build(&g_w, &alice, bob_addr, bob_kem_pub, 100, (const uint8_t*)msg,
                  strlen(msg), 0, p100, sizeof(p100), &l100, rng) == CC_OK);

  /* Different counters must give different packets (freshness is in the
   * content, since the nonce search is deterministic). */
  T("counters_change_the_wire", l5 != l3 || memcmp(p5, p3, l5) != 0);

  cc_replay_init(&st, alice_addr, CC_REPLAY_AUTHED);
  T("c5_accepted",
    cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, p5, l5, &chat) == CC_OK);
  T("c3_reordered_but_fresh",
    cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, p3, l3, &chat) == CC_OK);
  T("c5_again_is_replay", cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, p5, l5,
                                        &chat) == CC_E_REPLAY);
  T("c100_fresh",
    cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, p100, l100, &chat) == CC_OK);
  T("c3_now_stale", cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, p3, l3,
                                  &chat) == CC_E_STALE);

  /* (1) A relay rewrites the recipient address and re-mines the PoW: the AEAD
   * tag binds the routing metadata, so decryption fails. */
  memcpy(tampered, p5, l5);
  ltampered = l5;
  tampered[t_body(tampered, ltampered, EL_CHAT_RECIPIENT)] ^= 0xFF;
  T("tamper_remined", t_remine(tampered, &ltampered, EL_CHAT_NONCE) == 0);
  T("tamper_survives_pow_gate", cc_pow_verify(tampered, ltampered) == CC_OK);
  cc_replay_init(&st, alice_addr, CC_REPLAY_AUTHED);
  ret = cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, tampered, ltampered,
                      &chat);
  printf("  (relay tamper rc=%d, recipient seen by the relay: ", ret);
  if (cc_msg_recipient(tampered, ltampered, recip) == CC_OK)
    printf("%02x%02x...)\n", recip[0], recip[1]);
  else
    printf("unreadable)\n");
  /* In this revision the signature covers the routing fields too, so a
     re-mined recipient rewrite is caught by CC_E_SIG before the tag is
     reached. Either code is a rejection; what matters is that a relay can
     never get it accepted. */
  T("aad_tamper_rejected", ret == CC_E_SIG || ret == CC_E_DECRYPT);

  /* (2) A node that holds Bob's announced KEM key (so it can produce a valid
   * tag) but not Alice's signing key cannot mint a packet that claims Alice:
   * it can only patch the claimed sender address, and the signature over
   * sender_addr then fails. */
  T("forge_build", cc_chat_build(&g_w, &mallory, bob_addr, bob_kem_pub, 5000,
                                 (const uint8_t*)msg, strlen(msg), 0, forged,
                                 sizeof(forged), &lforged, rng) == CC_OK);
  memcpy(claim, alice_addr, CC_ADDR_SZ);
  memcpy(forged + t_body(forged, lforged, EL_CHAT_SENDER), claim, CC_ADDR_SZ);
  T("forge_remined", t_remine(forged, &lforged, EL_CHAT_NONCE) == 0);
  T("forge_claims_alice", cc_chat_sender(forged, lforged, claim) == CC_OK &&
                              memcmp(claim, alice_addr, CC_ADDR_SZ) == 0);
  T("forge_survives_pow_gate", cc_pow_verify(forged, lforged) == CC_OK);
  cc_replay_init(&st, alice_addr, CC_REPLAY_AUTHED);
  ret = cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, forged, lforged, &chat);
  printf("  (forged chat rc=%d)\n", ret);
  T("forged_chat_rejected_as_bad_signature", ret == CC_E_SIG);
  T("forged_chat_not_nokey", ret != CC_E_NOKEY);
  /* The forged counter (5000) is far above the genuine stream, so had it been
   * recorded the genuine 100 would be stale rather than fresh. */
  T("forged_counter_not_recorded",
    cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, p100, l100, &chat) == CC_OK);

  /* (3) The same forged packet, but the receiver has not learned Alice's key
   * yet: a distinct, cheap answer so the app can send a key_req. */
  cc_replay_init(&st, alice_addr, CC_REPLAY_AUTHED);
  T("unknown_sender_distinct",
    cc_chat_parse(&g_w, &bob, NULL, &st, forged, lforged, &chat) == CC_E_NOKEY);

  cc_key_free(&alice);
  cc_key_free(&bob);
  cc_key_free(&mallory);
}

/* Regression tests for the two v0.5 P0s: unbounded field lengths reaching a
   fixed buffer, and a partially authenticated packet consuming a replay window
   slot. The first group mints packets with an honest signature and arbitrary
   field lengths (the attacker capability the size contracts exist to bound);
   the second uses real packets with one byte flipped and the nonce re-mined. */
static void test_chat_field_limits(WC_RNG* rng) {
  static cc_key_t alice, bob;
  uint8_t alice_sign_pub[CC_SIGN_PUBKEY_SZ];
  /* throwaway, and large enough for either key type */
  uint8_t tmp_kem[CC_SIGN_PUBKEY_SZ];
  uint8_t bob_kem_pub[CC_KEM_PUBKEY_SZ];
  uint8_t alice_addr[CC_ADDR_SZ], bob_addr[CC_ADDR_SZ];
  static uint8_t pkt[CC_CHAT_BUF_SZ];
  static uint8_t big[8192];
  static uint8_t kem[1600], enc0[2048], short_sig[100];
  static cc_chat_t chat;
  cc_replay_t st;
  size_t len = 0, blen = 0;
  static const char msg[] = "field limits";
  size_t i;
  struct {
    const char* what;
    size_t kem_len;
    size_t enc0_len;
    int short_sig;
  } cases[4] = {{"kem_ct longer than CC_KEM_CT_SZ", 1600, 60, 0},
                {"kem_ct shorter than CC_KEM_CT_SZ", 100, 60, 0},
                {"encrypt0 larger than CC_ENC0_SZ", CC_KEM_CT_SZ, 2048, 0},
                {"signature not CC_SIGN_SIG_SZ", CC_KEM_CT_SZ, 60, 1}};
  printf("chat field size contracts:\n");

  cc_key_generate(&alice, rng);
  cc_key_generate(&bob, rng);
  cc_key_export_public(&alice, alice_sign_pub, tmp_kem);
  cc_key_export_public(&bob, tmp_kem, bob_kem_pub);
  cc_addr_from_key(&alice, alice_addr);
  cc_addr_from_key(&bob, bob_addr);
  memset(kem, 0x33, sizeof(kem));
  memset(enc0, 0x41, sizeof(enc0));
  memset(short_sig, 0x55, sizeof(short_sig));

  T("build",
    cc_chat_build(&g_w, &alice, bob_addr, bob_kem_pub, 1, (const uint8_t*)msg,
                  strlen(msg), 0, pkt, sizeof(pkt), &len, rng) == CC_OK);
  cc_replay_init(&st, alice_addr, CC_REPLAY_AUTHED);
  T("genuine_parses",
    cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, pkt, len, &chat) == CC_OK);

  /* A field whose length breaks its contract is refused at decode, i.e. before
     the signature, the replay window and any crypto. These packets carry a
     valid signature over the fields the signature covers, so the contract is
     the only thing standing in the way. */
  for (i = 0; i < 4; i++) {
    size_t n = mint_chat(
        &alice, rng, alice_addr, bob_addr, kem, cases[i].kem_len, enc0,
        cases[i].enc0_len, 1, cases[i].short_sig ? short_sig : NULL,
        cases[i].short_sig ? sizeof(short_sig) : 0, 0, big, sizeof(big));
    cc_replay_init(&st, alice_addr, CC_REPLAY_AUTHED);
    T(cases[i].what, n > 0 && cc_chat_parse(&g_w, &bob, alice_sign_pub, &st,
                                            big, n, &chat) == CC_E_FORMAT);
    /* the genuine packet written over the same counter still parses, i.e. the
       rejected packet consumed nothing */
    T("...window untouched",
      cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, pkt, len, &chat) == CC_OK);
  }

  /* A packet that authenticates partially (valid signature, failing tag) must
     not consume the counter: the genuine packet with the same counter still
     parses afterwards, whatever order they arrive in. */
  {
    struct {
      const char* what;
      size_t elem;
      size_t byte;
    } cases3[3] = {{"kem_ct tampered", EL_CHAT_KEM_CT, 5},
                   {"recipient tampered", EL_CHAT_RECIPIENT, 0},
                   {"encrypt0 tampered", EL_CHAT_ENCRYPT0, 7}};
    for (i = 0; i < 3; i++) {
      cc_chat_build(&g_w, &alice, bob_addr, bob_kem_pub, 1, (const uint8_t*)msg,
                    strlen(msg), 0, pkt, sizeof(pkt), &len, rng);
      memcpy(big, pkt, len);
      blen = len;
      big[t_body(big, blen, cases3[i].elem) + cases3[i].byte] ^= 0xFF;
      if (t_remine(big, &blen, EL_CHAT_NONCE) != 0) {
        printf("  (could not re-mine %s)\n", cases3[i].what);
        continue;
      }
      cc_replay_init(&st, alice_addr, CC_REPLAY_AUTHED);
      printf("  %s: rc=%d\n", cases3[i].what,
             cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, big, blen, &chat));
      T(cases3[i].what, cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, pkt, len,
                                      &chat) == CC_OK);
    }
  }

  cc_key_free(&alice);
  cc_key_free(&bob);
}

/* Independent canonical-form validator (RFC 8949 4.2), written from the spec
   rather than from the library, so "our encoder is canonical" is checked by
   something else. Returns 1 when `pkt` is one definite-length array of
   minimally-encoded uints/bstrs/tstrs that exactly fills the buffer. */
static int t_canonical_ok(const uint8_t* pkt, size_t len) {
  size_t pos = 0, i, count;
  uint8_t ib, ai, major;
  uint64_t v;

  if (len < 1)
    return 0;
  ib = pkt[pos++];
  if ((ib >> 5) != 4 || (ib & 0x1F) > 23)
    return 0; /* must be a definite-length array of at most 23 elements */
  count = (size_t)(ib & 0x1F);
  for (i = 0; i < count; i++) {
    if (pos >= len)
      return 0;
    ib = pkt[pos++];
    major = (uint8_t)(ib >> 5);
    ai = (uint8_t)(ib & 0x1F);
    if (ai < 24) {
      v = ai;
    } else if (ai == 24) {
      if (pos + 1 > len)
        return 0;
      v = pkt[pos];
      if (v < 24)
        return 0; /* not minimal */
      pos += 1;
    } else if (ai == 25) {
      if (pos + 2 > len)
        return 0;
      v = ((uint64_t)pkt[pos] << 8) | pkt[pos + 1];
      if (v < 256)
        return 0;
      pos += 2;
    } else if (ai == 26) {
      if (pos + 4 > len)
        return 0;
      v = ((uint64_t)pkt[pos] << 24) | ((uint64_t)pkt[pos + 1] << 16) |
          ((uint64_t)pkt[pos + 2] << 8) | pkt[pos + 3];
      if (v < 65536)
        return 0;
      pos += 4;
    } else {
      return 0; /* 8-byte form is never needed, 28..31 reserved/indefinite */
    }
    if (major == 2 || major == 3) {
      if (v > (uint64_t)(len - pos))
        return 0;
      pos += (size_t)v;
    } else if (major != 0) {
      return 0;
    }
  }
  return pos == len; /* nothing trailing */
}

/* Malleability: a value-equivalent but non-canonical encoding of the same
   packet. The type element (a one-byte uint) is rewritten in its 2-byte form
   and everything after it shifted, so the parsed meaning is unchanged. */
static size_t t_reencode_type_nonminimal(const uint8_t* pkt, size_t len,
                                         uint8_t* out) {
  size_t off[T_MAX_ELEMS], elen[T_MAX_ELEMS], n = 0, o = 0, i;
  if (t_spans(pkt, len, off, elen, &n) != 0 || n < 3 || elen[1] != 1)
    return 0;
  out[o++] = pkt[0];
  memcpy(out + o, pkt + off[0], elen[0]);
  o += elen[0];
  out[o++] = 0x18; /* uint, 1-byte argument: non-minimal for a small value */
  out[o++] = pkt[off[1]];
  for (i = 2; i < n; i++) {
    memcpy(out + o, pkt + off[i], elen[i]);
    o += elen[i];
  }
  return o;
}

/* An indefinite-length array: 0x9f ... 0xff instead of the definite head. */
static size_t t_indefinite_array(const uint8_t* pkt, size_t len, uint8_t* out) {
  if (len < 2 || (pkt[0] >> 5) != 4)
    return 0;
  out[0] = 0x9f;
  memcpy(out + 1, pkt + 1, len - 1);
  out[len] = 0xff;
  return len + 1;
}

/* An indefinite-length byte string for element `elem`, holding one chunk. */
static size_t t_indefinite_bstr(const uint8_t* pkt, size_t len, size_t elem,
                                uint8_t* out) {
  size_t off[T_MAX_ELEMS], elen[T_MAX_ELEMS], n = 0, o = 0, i;
  size_t body, paylen;

  if (t_spans(pkt, len, off, elen, &n) != 0 || elem >= n)
    return 0;
  if ((pkt[off[elem]] >> 5) != 2)
    return 0;
  body = t_body(pkt, len, elem);
  paylen = elen[elem] - (body - off[elem]);
  out[o++] = pkt[0];
  for (i = 0; i < n; i++) {
    if (i == elem) {
      out[o++] = 0x5f; /* indefinite-length byte string */
      o += put_hdr(out + o, 2, paylen);
      memcpy(out + o, pkt + body, paylen);
      o += paylen;
      out[o++] = 0xff; /* break */
    } else {
      memcpy(out + o, pkt + off[i], elen[i]);
      o += elen[i];
    }
  }
  return o;
}

static void test_canonical(WC_RNG* rng) {
  static cc_key_t alice, bob;
  uint8_t alice_sign_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t tmp_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t bob_kem_pub[CC_KEM_PUBKEY_SZ];
  uint8_t alice_addr[CC_ADDR_SZ], bob_addr[CC_ADDR_SZ];
  static uint8_t pkt[CC_CHAT_BUF_SZ], mut[CC_CHAT_BUF_SZ + 8];
  static cc_chat_t chat;
  cc_replay_t st;
  uint8_t type_out = 0;
  size_t len = 0, mlen;
  static const char msg[] = "canonical";
  printf("canonical form:\n");

  cc_key_generate(&alice, rng);
  cc_key_generate(&bob, rng);
  cc_key_export_public(&alice, alice_sign_pub, tmp_pub);
  cc_key_export_public(&bob, tmp_pub, bob_kem_pub);
  cc_addr_from_key(&alice, alice_addr);
  cc_addr_from_key(&bob, bob_addr);

  T("build",
    cc_chat_build(&g_w, &alice, bob_addr, bob_kem_pub, 1, (const uint8_t*)msg,
                  strlen(msg), 0, pkt, sizeof(pkt), &len, rng) == CC_OK);
  T("built_packet_is_canonical", t_canonical_ok(pkt, len));
  cc_replay_init(&st, alice_addr, CC_REPLAY_AUTHED);
  T("genuine_parses",
    cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, pkt, len, &chat) == CC_OK);

  /* Value-equivalent, non-canonical: same fields, different bytes. */
  mlen = t_reencode_type_nonminimal(pkt, len, mut);
  T("nonminimal_reencoded", mlen == len + 1);
  T("nonminimal_rejected", cc_pow_verify(mut, mlen) == CC_E_FORMAT);
  cc_replay_init(&st, alice_addr, CC_REPLAY_AUTHED);
  T("nonminimal_rejected_by_parse",
    cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, mut, mlen, &chat) ==
        CC_E_FORMAT);
  T("nonminimal_rejected_by_type_reader",
    cc_msg_type(mut, mlen, &type_out) == CC_E_FORMAT);

  /* Trailing bytes after the array, and a truncated tail. */
  memcpy(mut, pkt, len);
  mut[len] = 0x00;
  T("trailing_rejected", cc_pow_verify(mut, len + 1) == CC_E_FORMAT);
  cc_replay_init(&st, alice_addr, CC_REPLAY_AUTHED);
  T("trailing_rejected_by_parse",
    cc_chat_parse(&g_w, &bob, alice_sign_pub, &st, mut, len + 1, &chat) ==
        CC_E_FORMAT);
  T("truncated_rejected", cc_pow_verify(pkt, len - 1) == CC_E_FORMAT);

  /* Indefinite lengths. */
  mlen = t_indefinite_array(pkt, len, mut);
  T("indefinite_array_rejected",
    mlen > 0 && cc_pow_verify(mut, mlen) == CC_E_FORMAT);
  mlen = t_indefinite_bstr(pkt, len, EL_CHAT_KEM_CT, mut);
  T("indefinite_bstr_rejected",
    mlen > 0 && cc_pow_verify(mut, mlen) == CC_E_FORMAT);

  cc_key_free(&alice);
  cc_key_free(&bob);
}

/* Every packet the library builds must satisfy the canonical form and re-parse
   unchanged, for all four types. */
static void test_canonical_build(WC_RNG* rng) {
  static cc_key_t key;
  cc_announce_t ann;
  cc_presence_t pres;
  uint8_t addr[CC_ADDR_SZ], sign_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t kem_pub[CC_KEM_PUBKEY_SZ];
  static uint8_t ann_pkt[CC_ANN_BUF_SZ];
  static uint8_t chat_pkt[CC_CHAT_BUF_SZ];
  static uint8_t pres_pkt[CC_PRES_BUF_SZ];
  static uint8_t req_pkt[CC_KEY_REQ_BUF_SZ];
  size_t ann_len = 0, chat_len = 0, pres_len = 0, req_len = 0;
  uint8_t counter_out = 0;
  uint32_t c = 0;
  uint8_t meta[] = {0xa1, 0x01, 0x02};
  printf("canonical form of everything we build:\n");

  cc_key_generate(&key, rng);
  cc_key_export_public(&key, sign_pub, kem_pub);
  cc_addr_from_key(&key, addr);

  T("announce",
    cc_announce_build(&g_w, &key, "Alice", 5, meta, sizeof(meta), NULL, 1, 0,
                      ann_pkt, sizeof(ann_pkt), &ann_len, rng) == CC_OK &&
        t_canonical_ok(ann_pkt, ann_len) &&
        cc_pow_verify(ann_pkt, ann_len) == CC_OK &&
        cc_announce_parse(&g_w, ann_pkt, ann_len, &ann) == CC_OK);
  T("announce_nonempty_meta", ann.meta_len == sizeof(meta));
  T("chat",
    cc_chat_build(&g_w, &key, addr, kem_pub, 1, (const uint8_t*)"hello", 5, 0,
                  chat_pkt, sizeof(chat_pkt), &chat_len, rng) == CC_OK &&
        t_canonical_ok(chat_pkt, chat_len) &&
        cc_pow_verify(chat_pkt, chat_len) == CC_OK);
  T("chat_msg_len",
    cc_chat_build(&g_w, &key, addr, kem_pub, 1, (const uint8_t*)"hi", 2, 0,
                  chat_pkt, sizeof(chat_pkt), &chat_len, rng) == CC_OK &&
        t_canonical_ok(chat_pkt, chat_len));
  T("presence",
    cc_presence_build(&g_w, &key, "Alice", 5, 7, pres_pkt, sizeof(pres_pkt),
                      &pres_len, rng) == CC_OK &&
        t_canonical_ok(pres_pkt, pres_len) &&
        cc_pow_verify(pres_pkt, pres_len) == CC_OK &&
        cc_presence_parse(&g_w, pres_pkt, pres_len, &pres) == CC_OK &&
        pres.seq == 7);
  T("key_req",
    cc_key_req_build(&g_w, addr, 9, 0, req_pkt, sizeof(req_pkt), &req_len) ==
            CC_OK &&
        t_canonical_ok(req_pkt, req_len) &&
        cc_pow_verify(req_pkt, req_len) == CC_OK &&
        cc_key_req_parse(&g_w, req_pkt, req_len, addr, &c) == CC_OK && c == 9);
  (void)counter_out;
  (void)sign_pub;
  (void)addr[0];

  cc_key_free(&key);
}

/* Splice tests: take two valid packets of the same type and length, swap a
   field between them, re-mine the PoW (the module of the old test suite), and
   require that nothing ever parses. The PoW covers the spliced field too, so
   re-mining is what isolates the signature and the tag. */
static void test_splice(WC_RNG* rng) {
  static cc_key_t a, b;
  uint8_t a_sign_pub[CC_SIGN_PUBKEY_SZ], b_sign_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t a_kem_pub[CC_KEM_PUBKEY_SZ], b_kem_pub[CC_KEM_PUBKEY_SZ];
  uint8_t a_addr[CC_ADDR_SZ], b_addr[CC_ADDR_SZ];
  static uint8_t pa[CC_CHAT_BUF_SZ], pb[CC_CHAT_BUF_SZ];
  static uint8_t spliced[CC_CHAT_BUF_SZ];
  static cc_chat_t chat;
  static const char msg[] = "splice me";
  static const size_t chat_fields[5] = {EL_CHAT_SENDER, EL_CHAT_RECIPIENT,
                                        EL_CHAT_KEM_CT, EL_CHAT_COUNTER,
                                        EL_CHAT_ENCRYPT0};
  size_t la = 0, lb = 0, slen, i, j;
  cc_replay_t st;
  int ret, bad;
  printf("splices:\n");

  cc_key_generate(&a, rng);
  cc_key_generate(&b, rng);
  cc_key_export_public(&a, a_sign_pub, a_kem_pub);
  cc_key_export_public(&b, b_sign_pub, b_kem_pub);
  cc_addr_from_key(&a, a_addr);
  cc_addr_from_key(&b, b_addr);

  T("two_valid_chats",
    cc_chat_build(&g_w, &a, b_addr, b_kem_pub, 3, (const uint8_t*)msg,
                  strlen(msg), 0, pa, sizeof(pa), &la, rng) == CC_OK &&
        cc_chat_build(&g_w, &b, a_addr, a_kem_pub, 4, (const uint8_t*)msg,
                      strlen(msg), 0, pb, sizeof(pb), &lb, rng) == CC_OK);
  /* every unordered pair of covered fields, and every field on its own */
  for (i = 0; i < 5; i++) {
    for (j = i; j < 5; j++) {
      size_t ea = chat_fields[i], eb = chat_fields[j];
      char label[64];

      slen = t_splice(pa, la, ea, pb, lb, eb, spliced, sizeof(spliced),
                      EL_CHAT_NONCE);
      if (slen == 0)
        continue;
      cc_replay_init(&st, a_addr, CC_REPLAY_AUTHED);
      ret = cc_chat_parse(&g_w, &b, a_sign_pub, &st, spliced, slen, &chat);
      /* Replacing the sender makes the caller's key lookup mismatch, which is
         CC_E_NOKEY by design; everything else is inside the signature. */
      bad = !(ret == CC_E_SIG || ret == CC_E_DECRYPT ||
              (ea == EL_CHAT_SENDER && ret == CC_E_NOKEY));
      snprintf(label, sizeof(label), "chat fields %zu<-%zu -> %s", ea, eb,
               bad ? "ACCEPTED/OTHER" : "rejected");
      T(label, !bad);
      printf("    (rc=%d)\n", ret);
    }
  }

  /* announce: swap each covered field between two valid announces */
  {
    static uint8_t qa[CC_ANN_BUF_SZ], qb[CC_ANN_BUF_SZ];
    static uint8_t qs[CC_ANN_BUF_SZ];
    cc_announce_t ann;
    static const size_t ann_fields[5] = {EL_ANN_SIGN_PUB, EL_ANN_KEM_PUB,
                                         EL_ANN_NAME, EL_ANN_META,
                                         EL_ANN_ADMIT};
    static const uint8_t declare_b[CC_ADMIT_SZ] = {1, 1, 1};
    size_t qla = 0, qlb = 0, qslen;
    /* CBOR maps: meta is a namespaced map now, not opaque bytes. */
    static const uint8_t meta_a[] = {0xa1, 0x61, 0x61, 0x01}; /* {"a":1} */
    static const uint8_t meta_b[] = {0xa1, 0x61, 0x62, 0x01}; /* {"b":1} */
    T("two_valid_announces",
      cc_announce_build(&g_w, &a, "Alice", 5, meta_a, sizeof(meta_a), NULL, 1,
                        0, qa, sizeof(qa), &qla, rng) == CC_OK &&
          cc_announce_build(&g_w, &b, "Bobby", 5, meta_b, sizeof(meta_b),
                            declare_b, 1, 0, qb, sizeof(qb), &qlb,
                            rng) == CC_OK);
    for (i = 0; i < 5; i++) {
      char label[64];
      qslen = t_splice(qa, qla, ann_fields[i], qb, qlb, ann_fields[i], qs,
                       sizeof(qs), EL_ANN_NONCE);
      if (qslen == 0)
        continue;
      ret = cc_announce_parse(&g_w, qs, qslen, &ann);
      bad = (ret != CC_E_SIG);
      snprintf(label, sizeof(label), "announce field %zu -> %s", ann_fields[i],
               bad ? "ACCEPTED/OTHER" : "rejected");
      T(label, !bad);
      printf("    (rc=%d)\n", ret);
    }
  }

  cc_key_free(&a);
  cc_key_free(&b);
}

static void test_presence(WC_RNG* rng) {
  static cc_key_t key;
  cc_presence_t p, p2;
  static uint8_t pkt[CC_PRES_BUF_SZ], pkt2[CC_PRES_BUF_SZ];
  size_t pkt_len = 0, pkt2_len = 0;
  uint8_t expected_addr[CC_ADDR_SZ];
  cc_replay_t st;
  uint8_t type, hops;
  printf("presence:\n");

  cc_key_generate(&key, rng);
  T("build", cc_presence_build(&g_w, &key, "Alice", 5, 77, pkt, sizeof(pkt),
                               &pkt_len, rng) == CC_OK);
  T("nonempty", pkt_len > 0 && pkt_len <= CC_PRES_BUF_SZ);
  printf("  (presence packet %zu bytes)\n", pkt_len);
  cc_msg_type(pkt, pkt_len, &type);
  T("msg_type", type == CC_MSG_PRESENCE);
  T("parse", cc_presence_parse(&g_w, pkt, pkt_len, &p) == CC_OK);
  {
    uint8_t nh[CC_PRES_NAME_HASH_SZ];
    cc_name_hash("Alice", 5, nh);
    T("name_hash", memcmp(p.name_hash, nh, CC_PRES_NAME_HASH_SZ) == 0);
  }
  T("hops_zero", p.hops == 0);
  T("seq", p.seq == 77);
  cc_addr_from_key(&key, expected_addr);
  T("addr_match", memcmp(p.addr, expected_addr, CC_ADDR_SZ) == 0);
  T("pow_ok", cc_pow_verify(pkt, pkt_len) == CC_OK);

  T("hops_inc",
    cc_hops_increment(pkt, pkt_len, pkt2, sizeof(pkt2), &pkt2_len) == CC_OK);
  cc_msg_hops(pkt2, pkt2_len, &hops);
  T("hops_value", hops == 1);
  T("parse_after_hop", cc_presence_parse(&g_w, pkt2, pkt2_len, &p2) == CC_OK);
  T("addr_after_hop", memcmp(p2.addr, expected_addr, CC_ADDR_SZ) == 0);
  T("pow_after_hop", cc_pow_verify(pkt2, pkt2_len) == CC_OK);

  /* The same presence packet twice: the counter is what makes it dedupable */
  cc_replay_init(&st, expected_addr, CC_REPLAY_UNSIGNED);
  T("first_accepted", cc_replay_check(&st, expected_addr, p.seq) == CC_OK);
  T("identical_packet_replayed",
    cc_replay_check(&st, expected_addr, p.seq) == CC_E_REPLAY);

  /* Corrupt → rejected */
  pkt[pkt_len - 3] ^= 0xFF;
  T("corrupt_rejected", cc_presence_parse(&g_w, pkt, pkt_len, &p) != CC_OK);

  cc_key_free(&key);
}

static void test_key_req(void) {
  static cc_key_t key;
  uint8_t addr[CC_ADDR_SZ], parsed_addr[CC_ADDR_SZ];
  static uint8_t pkt[CC_KEY_REQ_BUF_SZ], pkt2[CC_KEY_REQ_BUF_SZ];
  size_t pkt_len = 0, pkt2_len = 0;
  uint32_t counter = 0, counter2 = 0;
  cc_replay_t st;
  uint8_t type, hops;
  WC_RNG rng;
  wc_InitRng(&rng);
  cc_key_generate(&key, &rng);
  wc_FreeRng(&rng);
  cc_addr_from_key(&key, addr);
  printf("key_req:\n");

  T("build",
    cc_key_req_build(&g_w, addr, 9, 0, pkt, sizeof(pkt), &pkt_len) == CC_OK);
  T("nonempty", pkt_len > 0 && pkt_len <= CC_KEY_REQ_BUF_SZ);
  printf("  (key_req packet %zu bytes)\n", pkt_len);
  cc_msg_type(pkt, pkt_len, &type);
  T("msg_type", type == CC_MSG_KEY_REQ);
  T("parse",
    cc_key_req_parse(&g_w, pkt, pkt_len, parsed_addr, &counter) == CC_OK);
  T("addr_match", memcmp(addr, parsed_addr, CC_ADDR_SZ) == 0);
  T("counter", counter == 9);
  T("pow_ok", cc_pow_verify(pkt, pkt_len) == CC_OK);

  T("hops_inc",
    cc_hops_increment(pkt, pkt_len, pkt2, sizeof(pkt2), &pkt2_len) == CC_OK);
  cc_msg_hops(pkt2, pkt2_len, &hops);
  T("hops_value", hops == 1);
  T("parse_after_hop",
    cc_key_req_parse(&g_w, pkt2, pkt2_len, parsed_addr, &counter2) == CC_OK);
  T("addr_after_hop", memcmp(addr, parsed_addr, CC_ADDR_SZ) == 0);
  T("counter_after_hop", counter2 == 9);
  T("pow_after_hop", cc_pow_verify(pkt2, pkt2_len) == CC_OK);

  cc_replay_init(&st, addr, CC_REPLAY_UNSIGNED);
  T("first_accepted", cc_replay_check(&st, addr, counter2) == CC_OK);
  T("identical_packet_replayed",
    cc_replay_check(&st, addr, counter2) == CC_E_REPLAY);

  /* Corrupt counter → PoW fails */
  pkt[pkt_len - 1] ^= 0xFF;
  T("corrupt_rejected",
    cc_key_req_parse(&g_w, pkt, pkt_len, parsed_addr, &counter) != CC_OK);

  T("null_arg",
    cc_key_req_build(&g_w, NULL, 1, 0, pkt, sizeof(pkt), &pkt_len) == CC_E_ARG);
  cc_key_free(&key);
}

/* A v0.4 packet has no version element, so its first element is its type;
   every shape must be refused as a revision mismatch, before any other work. */
static void test_version_rejection(void) {
  static const uint8_t v04_announce[] = {0x84, 0x00, 0x00};
  static const uint8_t v04_chat[] = {0x86, 0x01, 0x00};
  static const uint8_t v04_presence[] = {0x85, 0x02, 0x00};
  static const uint8_t v04_key_req[] = {0x84, 0x03, 0x00};
  static const uint8_t bad_arity[] = {0x84, CC_WIRE_VERSION, 0x00};
  static cc_announce_t ann;
  cc_presence_t pres;
  uint8_t addr[CC_ADDR_SZ];
  uint8_t out[64];
  size_t out_len = 0;
  uint32_t counter = 0;
  uint8_t type = 0xEE, hops = 0xEE;
  printf("wire revision:\n");

  T("v04_announce_msg_type",
    cc_msg_type(v04_announce, sizeof(v04_announce), &type) == CC_E_VERSION &&
        type == 0xEE);
  T("v04_announce_msg_hops",
    cc_msg_hops(v04_announce, sizeof(v04_announce), &hops) == CC_E_VERSION &&
        hops == 0xEE);
  T("v04_announce_parse",
    cc_announce_parse(&g_w, v04_announce, sizeof(v04_announce), &ann) ==
        CC_E_VERSION);
  T("v04_announce_pow",
    cc_pow_verify(v04_announce, sizeof(v04_announce)) == CC_E_VERSION);
  T("v04_announce_hops_increment",
    cc_hops_increment(v04_announce, sizeof(v04_announce), out, sizeof(out),
                      &out_len) == CC_E_VERSION);

  T("v04_chat_msg_type",
    cc_msg_type(v04_chat, sizeof(v04_chat), &type) == CC_E_VERSION);
  T("v04_chat_parse",
    cc_msg_recipient(v04_chat, sizeof(v04_chat), addr) == CC_E_VERSION);
  T("v04_presence_msg_type",
    cc_msg_type(v04_presence, sizeof(v04_presence), &type) == CC_E_VERSION);
  T("v04_presence_parse",
    cc_presence_parse(&g_w, v04_presence, sizeof(v04_presence), &pres) ==
        CC_E_VERSION);
  T("v04_key_req_msg_type",
    cc_msg_type(v04_key_req, sizeof(v04_key_req), &type) == CC_E_VERSION);
  T("v04_key_req_parse",
    cc_key_req_parse(&g_w, v04_key_req, sizeof(v04_key_req), addr, &counter) ==
        CC_E_VERSION);

  /* A plausible version with the wrong arity is a format error instead */
  T("right_version_wrong_arity",
    cc_pow_verify(bad_arity, sizeof(bad_arity)) == CC_E_FORMAT);
}

/* ---- v7: links ---- */

/* Bring one link up end to end: initiator -> responder -> proof -> confirm. */
static int link_pair(cc_link_t* li, cc_link_t* lr, const cc_key_t* ini,
                     const cc_key_t* res, WC_RNG* rng, uint32_t idle) {
  static uint8_t req[CC_LINK_REQ_BUF_SZ], proof[CC_LINK_PROOF_BUF_SZ];
  uint8_t res_sign[CC_SIGN_PUBKEY_SZ], res_kem[CC_KEM_PUBKEY_SZ];
  uint8_t res_addr[CC_ADDR_SZ];
  size_t rl = 0, pl = 0;
  int ret;

  (void)ini;
  cc_key_export_public(res, res_sign, res_kem);
  cc_addr_from_key(res, res_addr);
  ret = cc_link_start(&g_w, li, res_addr, res_kem, 0, idle, 0, req, sizeof(req),
                      &rl, rng);
  if (ret != CC_OK)
    return ret;
  ret = cc_link_accept(&g_w, lr, res, 0, idle, req, rl, proof, sizeof(proof),
                       &pl, rng);
  if (ret != CC_OK)
    return ret;
  return cc_link_confirm(&g_w, li, res_addr, res_sign, proof, pl);
}

static void test_link_handshake(WC_RNG* rng) {
  static cc_key_t ini, res;
  uint8_t ini_sign[CC_SIGN_PUBKEY_SZ], ini_kem[CC_KEM_PUBKEY_SZ];
  uint8_t res_sign[CC_SIGN_PUBKEY_SZ], res_kem[CC_KEM_PUBKEY_SZ];
  uint8_t ini_addr[CC_ADDR_SZ], res_addr[CC_ADDR_SZ], claimed[CC_ADDR_SZ];
  static uint8_t req[CC_LINK_REQ_BUF_SZ], proof[CC_LINK_PROOF_BUF_SZ];
  static uint8_t pa[CC_LINK_DATA_BUF_SZ], pb[CC_LINK_DATA_BUF_SZ];
  static uint8_t idp[CC_LINK_IDENTIFY_BUF_SZ];
  static uint8_t tampered[CC_LINK_PROOF_BUF_SZ];
  size_t rl = 0, pl = 0, la = 0, lb = 0, il = 0, tl;
  cc_link_t li, lr;
  uint8_t kind = 0xFF;
  static uint8_t payload[CC_MAX_MSG_SZ + CC_SIGN_SIG_SZ + 32];
  size_t plen = 0;
  int ret;
  printf("links: handshake:\n");

  cc_key_generate(&ini, rng);
  cc_key_generate(&res, rng);
  cc_key_export_public(&ini, ini_sign, ini_kem);
  cc_key_export_public(&res, res_sign, res_kem);
  cc_addr_from_key(&ini, ini_addr);
  cc_addr_from_key(&res, res_addr);

  T("suite_is_1", cc_suite() == CC_SUITE);
  T("state_fits_mcu_budget", sizeof(cc_link_t) <= 176);
  printf("  (cc_link_t = %zu bytes)\n", sizeof(cc_link_t));

  ret = cc_link_start(&g_w, &li, res_addr, res_kem, 0, 1000, 0, req,
                      sizeof(req), &rl, rng);
  T("start", ret == CC_OK);
  T("req_fits", rl > 0 && rl <= CC_LINK_REQ_BUF_SZ);
  T("req_type",
    cc_msg_type(req, rl, &kind) == CC_OK && kind == CC_MSG_LINK_REQ);
  T("req_pow", cc_pow_verify(req, rl) == CC_OK);
  T("pending_not_active", cc_link_active(&li, 0) == 0);
  T("req_has_link_id", cc_link_id(req, rl, claimed) == CC_OK &&
                           memcmp(claimed, li.id, CC_LINK_ID_SZ) == 0);

  ret = cc_link_accept(&g_w, &lr, &res, 0, 1000, req, rl, proof, sizeof(proof),
                       &pl, rng);
  T("accept", ret == CC_OK);
  T("proof_fits", pl > 0 && pl <= CC_LINK_PROOF_BUF_SZ);
  T("proof_type",
    cc_msg_type(proof, pl, &kind) == CC_OK && kind == CC_MSG_LINK_PROOF);
  T("proof_pow", cc_pow_verify(proof, pl) == CC_OK);
  T("responder_open", cc_link_active(&lr, 0) != 0);

  /* The initiator is anonymous: the responder knows no address for it yet. */
  T("initiator_anonymous", memcmp(lr.peer, ini_addr, CC_ADDR_SZ) != 0);

  /* A proof checked against the wrong peer's key is refused. */
  T("confirm_wrong_key",
    cc_link_confirm(&g_w, &li, res_addr, ini_sign, proof, pl) == CC_E_NOKEY);
  T("confirm",
    cc_link_confirm(&g_w, &li, res_addr, res_sign, proof, pl) == CC_OK);
  T("initiator_open", cc_link_active(&li, 0) != 0);

  /* A tampered proof signature (PoW re-mined) is refused. */
  memcpy(tampered, proof, pl);
  tl = pl;
  tampered[t_body(tampered, tl, 6) + 5] ^=
      0xFF; /* element 6 is the signature */
  T("proof_tamper_remined", t_remine(tampered, &tl, 3) == 0);
  T("proof_tamper_pow", cc_pow_verify(tampered, tl) == CC_OK);
  T("proof_tamper_refused",
    cc_link_confirm(&g_w, &li, res_addr, res_sign, tampered, tl) == CC_E_SIG);

  /* A handshake under another suite byte is refused (PoW re-mined). */
  {
    static uint8_t rq[CC_LINK_REQ_BUF_SZ];
    cc_link_t tmp;
    memcpy(rq, req, rl);
    tl = rl;
    rq[t_head(rq, tl, 4)] =
        (uint8_t)(CC_SUITE + 1); /* element 4 is the suite */
    T("req_suite_remined", t_remine(rq, &tl, 3) == 0);
    T("req_suite_pow", cc_pow_verify(rq, tl) == CC_OK);
    T("suite_mismatch_refused",
      cc_link_accept(&g_w, &tmp, &res, 0, 1000, rq, tl, proof, sizeof(proof),
                     &pl, rng) == CC_E_SUITE);
  }

  /* Data both ways, on distinct direction keys. */
  T("send_i2r",
    cc_link_send(&g_w, &li, CC_LINK_KIND_DATA, (const uint8_t*)"ping", 4, 1, pa,
                 sizeof(pa), &la) == CC_OK);
  T("data_fits", la > 0 && la <= CC_LINK_DATA_BUF_SZ);
  T("send_r2i",
    cc_link_send(&g_w, &lr, CC_LINK_KIND_DATA, (const uint8_t*)"pong", 4, 2, pb,
                 sizeof(pb), &lb) == CC_OK);
  /* The responder's own packet must not decrypt under its rx key. */
  T("directions_distinct",
    cc_link_recv(&g_w, &lr, pb, lb, 2, &kind, payload, sizeof(payload),
                 &plen) == CC_E_DECRYPT);
  T("recv_i2r", cc_link_recv(&g_w, &lr, pa, la, 3, &kind, payload,
                             sizeof(payload), &plen) == CC_OK &&
                    kind == CC_LINK_KIND_DATA && plen == 4 &&
                    memcmp(payload, "ping", 4) == 0);
  T("recv_r2i", cc_link_recv(&g_w, &li, pb, lb, 4, &kind, payload,
                             sizeof(payload), &plen) == CC_OK &&
                    plen == 4 && memcmp(payload, "pong", 4) == 0);

  /* Identify: the initiator proves who it is, inside the link. */
  T("identify",
    cc_link_identify(&g_w, &li, &ini, 5, idp, sizeof(idp), &il, rng) == CC_OK);
  T("identify_fits", il <= CC_LINK_IDENTIFY_BUF_SZ);
  T("recv_identify", cc_link_recv(&g_w, &lr, idp, il, 6, &kind, payload,
                                  sizeof(payload), &plen) == CC_OK &&
                         kind == CC_LINK_KIND_IDENTIFY);
  T("verify_identify",
    cc_identify_verify(&g_w, &lr, payload, plen, ini_sign, claimed) == CC_OK &&
        memcmp(claimed, ini_addr, CC_ADDR_SZ) == 0);
  T("identify_wrong_key", cc_identify_verify(&g_w, &lr, payload, plen, res_sign,
                                             claimed) == CC_E_NOKEY);
  payload[CC_ADDR_SZ + 3] ^= 0xFF;
  T("identify_tampered", cc_identify_verify(&g_w, &lr, payload, plen, ini_sign,
                                            claimed) == CC_E_SIG);

  /* Type 7 is the identify record, and the encoder must actually emit it: a
     receiver takes the authenticated record kind as the meaning, but a
     documented wire type that nothing produces is a trap for other
     implementations. Data records stay type 6. */
  T("identify_wire_type",
    cc_msg_type(idp, il, &kind) == CC_OK && kind == CC_MSG_IDENTIFY);
  T("data_wire_type",
    cc_msg_type(pa, la, &kind) == CC_OK && kind == CC_MSG_LINK_DATA);

  /* A type-6 packet carrying the SAME kind of record still decodes: the
     authenticated record kind decides the meaning, not the packet type, so a
     peer that emits the old type is not refused. Only the type element is
     rewritten, so the nonce and the tag stay valid. */
  {
    static uint8_t as_data[CC_LINK_IDENTIFY_BUF_SZ];
    size_t second = 0;
    T("identify_again",
      cc_link_identify(&g_w, &li, &ini, 7, as_data, sizeof(as_data), &second,
                       rng) == CC_OK);
    T("identify_again_type",
      cc_msg_type(as_data, second, &kind) == CC_OK && kind == CC_MSG_IDENTIFY);
    as_data[t_head(as_data, second, 1)] =
        CC_MSG_LINK_DATA; /* element 1: type */
    T("old_type_still_decodes",
      cc_link_recv(&g_w, &lr, as_data, second, 8, &kind, payload,
                   sizeof(payload), &plen) == CC_OK &&
          kind == CC_LINK_KIND_IDENTIFY);
  }

  /* The sequence is spent with the seal, not with the encode: a failed encode
     burns a sequence rather than freeing a (key, nonce) pair for reuse. */
  {
    cc_link_t tmp;
    uint8_t tiny[8];
    size_t n = 0;
    memcpy(&tmp, &li, sizeof(tmp));
    T("tiny_encode_refused",
      cc_link_send(&g_w, &tmp, CC_LINK_KIND_DATA, (const uint8_t*)"x", 1, 9,
                   tiny, sizeof(tiny), &n) == CC_E_BUF);
    T("seq_burned_with_the_seal", tmp.tx_seq == li.tx_seq + 1);
  }

  /* A maximal ciphertext (the largest the old bound allowed, CC_WORK_CT_SZ)
     must be refused structurally, and must not touch the receiver's buffers:
     GCM writes the plaintext before it checks the tag, so a record longer than
     the destination was an out-of-bounds write on input that needs no key. */
  {
    static cc_work_t zw;
    size_t el;
    memset(t_swap_body, 0x11, sizeof(t_swap_body));
    memset(zw.pt, 0xA5, sizeof(zw.pt));
    memset(zw.ct, 0x5A, sizeof(zw.ct));
    el = t_swap_bstr(pa, la, 5, t_swap_body, CC_WORK_CT_SZ);
    T("max_record_built", el > 0 && el <= sizeof(t_swap_buf));
    t_swap_buf[t_head(t_swap_buf, el, 4)] = 5; /* a fresh sequence, or the
                                                  window answers instead */
    T("max_record_rejected",
      cc_link_recv(&zw, &lr, t_swap_buf, el, 7, &kind, payload, sizeof(payload),
                   &plen) == CC_E_FORMAT);
    T("max_record_no_write", t_canary(zw.pt, sizeof(zw.pt), 0xA5) &&
                                 t_canary(zw.ct, sizeof(zw.ct), 0x5A));
    /* Exactly at the bound the record is structurally legal: the tag, and not
       the length, is what refuses it. The sequence has to be fresh, or the
       replay window answers first and the AEAD is never reached. */
    el = t_swap_bstr(pa, la, 5, t_swap_body, CC_WORK_PT_SZ + 16);
    T("bound_record_built", el > 0);
    t_swap_buf[t_head(t_swap_buf, el, 4)] = 6; /* element 4 is the sequence */
    T("bound_record_reaches_the_aead",
      cc_link_recv(&zw, &lr, t_swap_buf, el, 8, &kind, payload, sizeof(payload),
                   &plen) == CC_E_DECRYPT);
  }

  cc_key_free(&ini);
  cc_key_free(&res);
}

/* Sequence window, link_id splicing and teardown. */
static void test_link_window(WC_RNG* rng) {
  static cc_key_t ini1, ini2, res;
  cc_link_t i1, r1, i2, r2;
  static uint8_t seq_pkts[6][CC_LINK_DATA_BUF_SZ];
  size_t seq_len[6] = {0}, tl;
  uint8_t kind, payload[128], l1[CC_LINK_ID_SZ];
  size_t plen;
  size_t i;
  (void)l1;
  printf("links: sequence window and splicing:\n");

  cc_key_generate(&ini1, rng);
  cc_key_generate(&ini2, rng);
  cc_key_generate(&res, rng);

  T("pair1", link_pair(&i1, &r1, &ini1, &res, rng, 10000) == CC_OK);
  T("pair2", link_pair(&i2, &r2, &ini2, &res, rng, 10000) == CC_OK);
  T("distinct_link_ids", memcmp(i1.id, i2.id, CC_LINK_ID_SZ) != 0);

  /* Three packets in order, then a replay, then out-of-order arrivals. */
  for (i = 0; i < 4; i++) {
    T("send", cc_link_send(&g_w, &i1, CC_LINK_KIND_DATA, (const uint8_t*)"x", 1,
                           (uint32_t)(1 + i), seq_pkts[i], sizeof(seq_pkts[i]),
                           &seq_len[i]) == CC_OK);
  }
  T("recv_0", cc_link_recv(&g_w, &r1, seq_pkts[0], seq_len[0], 1, &kind,
                           payload, sizeof(payload), &plen) == CC_OK);
  T("recv_1", cc_link_recv(&g_w, &r1, seq_pkts[1], seq_len[1], 1, &kind,
                           payload, sizeof(payload), &plen) == CC_OK);
  T("replay_1", cc_link_recv(&g_w, &r1, seq_pkts[1], seq_len[1], 1, &kind,
                             payload, sizeof(payload), &plen) == CC_E_REPLAY);
  T("recv_3_first", cc_link_recv(&g_w, &r1, seq_pkts[3], seq_len[3], 1, &kind,
                                 payload, sizeof(payload), &plen) == CC_OK);
  T("recv_2_reordered",
    cc_link_recv(&g_w, &r1, seq_pkts[2], seq_len[2], 1, &kind, payload,
                 sizeof(payload), &plen) == CC_OK);
  T("replay_3", cc_link_recv(&g_w, &r1, seq_pkts[3], seq_len[3], 1, &kind,
                             payload, sizeof(payload), &plen) == CC_E_REPLAY);

  /* An old sequence far outside the window is stale, not a replay. */
  {
    static uint8_t far[CC_LINK_DATA_BUF_SZ];
    size_t fl = 0;
    int all_ok = 1;
    /* push the sequence forward: deliver only the last of a hundred, so
       everything more than CC_LINK_WINDOW behind it falls out of the window */
    for (i = 0; i < 100; i++) {
      if (cc_link_send(&g_w, &i1, CC_LINK_KIND_DATA, NULL, 0,
                       (uint32_t)(10 + i), far, sizeof(far), &fl) != CC_OK)
        all_ok = 0;
    }
    T("send_many", all_ok);
    T("recv_far", cc_link_recv(&g_w, &r1, far, fl, 1, &kind, payload,
                               sizeof(payload), &plen) == CC_OK);
    T("old_seq_is_stale",
      cc_link_recv(&g_w, &r1, seq_pkts[0], seq_len[0], 1, &kind, payload,
                   sizeof(payload), &plen) == CC_E_STALE);
  }

  /* The clear sequence is bound by the AEAD nonce: editing it fails the tag. */
  {
    static uint8_t edited[CC_LINK_DATA_BUF_SZ];
    cc_link_t ix, rx;
    static cc_key_t ik;
    cc_key_generate(&ik, rng);
    T("pair3", link_pair(&ix, &rx, &ik, &res, rng, 10000) == CC_OK);
    {
      size_t el = 0;
      T("send3", cc_link_send(&g_w, &ix, CC_LINK_KIND_DATA, (const uint8_t*)"y",
                              1, 1, edited, sizeof(edited), &el) == CC_OK);
      tl = el;
    }
    {
      /* element 4 is the sequence; its first packet is seq 0, a one-byte
         uint, so flipping the value stays canonical and only the nonce
         changes: the tag must fail. */
      edited[t_head(edited, tl, 4)] ^= 0x01;
      T("seq_edit_refused",
        cc_link_recv(&g_w, &rx, edited, tl, 1, &kind, payload, sizeof(payload),
                     &plen) == CC_E_DECRYPT);
    }
  }

  /* link_id splice between two live links. A fresh pair, so the sequence
     window cannot answer before the crypto does. */
  {
    static uint8_t cross[CC_LINK_DATA_BUF_SZ];
    static cc_key_t ck;
    cc_link_t ci, cr;
    size_t cl = 0;
    cc_key_generate(&ck, rng);
    T("pair5", link_pair(&ci, &cr, &ck, &res, rng, 10000) == CC_OK);
    T("send_cross",
      cc_link_send(&g_w, &i2, CC_LINK_KIND_DATA, (const uint8_t*)"z", 1, 1,
                   cross, sizeof(cross), &cl) == CC_OK);
    /* its own id -> the wrong link names it */
    T("cross_not_this_link",
      cc_link_recv(&g_w, &cr, cross, cl, 1, &kind, payload, sizeof(payload),
                   &plen) == CC_E_NOLINK);
    /* rewrite the id to the other link's: the key still does not match */
    memcpy(cross + t_body(cross, cl, 3), cr.id, CC_LINK_ID_SZ);
    T("cross_id_swapped_refused",
      cc_link_recv(&g_w, &cr, cross, cl, 1, &kind, payload, sizeof(payload),
                   &plen) == CC_E_DECRYPT);
  }

  /* Teardown: unknown or forgotten links answer CC_E_NOLINK. */
  {
    cc_link_t empty;
    memset(&empty, 0, sizeof(empty));
    T("zeroed_link_recv",
      cc_link_recv(&g_w, &empty, seq_pkts[0], seq_len[0], 1, &kind, payload,
                   sizeof(payload), &plen) == CC_E_NOLINK);
    T("zeroed_link_not_active", cc_link_active(&empty, 0) == 0);
  }
  T("idle_timeout",
    cc_link_recv(&g_w, &r2, seq_pkts[3], seq_len[3], 100000, &kind, payload,
                 sizeof(payload), &plen) == CC_E_NOLINK);
  T("forgotten_after_timeout", cc_link_active(&r2, 100000) == 0);
  cc_link_forget(&i1);
  T("forget", cc_link_active(&i1, 1) == 0);
  T("forgotten_recv",
    cc_link_recv(&g_w, &i1, seq_pkts[0], seq_len[0], 1, &kind, payload,
                 sizeof(payload), &plen) == CC_E_NOLINK);

  /* Explicit close: the caller keeps sending until the peer is told. */
  {
    static uint8_t cl[CC_LINK_DATA_BUF_SZ];
    size_t cll = 0;
    cc_link_t a, b;
    static cc_key_t ak;
    cc_key_generate(&ak, rng);
    T("pair4", link_pair(&a, &b, &ak, &res, rng, 10000) == CC_OK);
    T("close", cc_link_close(&g_w, &a, 5, cl, sizeof(cl), &cll) == CC_OK);
    T("close_closed_local", cc_link_active(&a, 5) == 0);
    T("close_type",
      cc_msg_type(cl, cll, &kind) == CC_OK && kind == CC_MSG_LINK_CLOSE);
    T("recv_close", cc_link_recv(&g_w, &b, cl, cll, 5, &kind, payload,
                                 sizeof(payload), &plen) == CC_OK &&
                        kind == CC_LINK_KIND_CLOSE);
    T("close_forgets_peer", cc_link_active(&b, 5) == 0);
  }
}

/* ---- v7: announce and presence lifecycle ---- */

static void test_announce_lifecycle(WC_RNG* rng) {
  static cc_key_t key;
  cc_announce_t a1, a2, a3, a4;
  static uint8_t pkt1[CC_ANN_BUF_SZ], pkt2[CC_ANN_BUF_SZ], pkt3[CC_ANN_BUF_SZ];
  static uint8_t pkt4[CC_ANN_BUF_SZ];
  size_t l1 = 0, l2 = 0, l3 = 0, l4 = 0;
  static const uint8_t meta_a[] = {0xa1, 0x61, 0x61, 0x01};
  static const uint8_t not_a_map[] = {0x61, 0x61, 0x01};
  printf("announce lifecycle:\n");

  cc_key_generate(&key, rng);
  T("build_seq1",
    cc_announce_build(&g_w, &key, "Alice", 5, meta_a, sizeof(meta_a), NULL, 1,
                      100, pkt1, sizeof(pkt1), &l1, rng) == CC_OK);
  T("build_seq2",
    cc_announce_build(&g_w, &key, "Alice", 5, meta_a, sizeof(meta_a), NULL, 2,
                      200, pkt2, sizeof(pkt2), &l2, rng) == CC_OK);
  T("build_seq3",
    cc_announce_build(&g_w, &key, "Alice", 5, NULL, 0, NULL, 3, 300, pkt3,
                      sizeof(pkt3), &l3, rng) == CC_OK);

  T("parse_seq1", cc_announce_parse(&g_w, pkt1, l1, &a1) == CC_OK &&
                      a1.seq == 1 && a1.expiry == 100);
  T("parse_seq2", cc_announce_parse(&g_w, pkt2, l2, &a2) == CC_OK &&
                      a2.seq == 2 && a2.expiry == 200);
  T("parse_seq3", cc_announce_parse(&g_w, pkt3, l3, &a3) == CC_OK &&
                      a3.seq == 3 && a3.meta_len == 0);
  T("meta_roundtrip", cc_announce_parse(&g_w, pkt1, l1, &a1) == CC_OK &&
                          a1.meta_len == sizeof(meta_a) &&
                          memcmp(a1.meta, meta_a, sizeof(meta_a)) == 0);
  T("meta_must_be_a_map",
    cc_announce_build(&g_w, &key, "Alice", 5, not_a_map, sizeof(not_a_map),
                      NULL, 4, 0, pkt1, sizeof(pkt1), &l3, rng) == CC_E_ARG);

  /* The body is validated, not just the head, because the map is signed and
     propagated: a malformed one is every receiver's liability. A map head that
     claims 65535 pairs and carries none is the cheapest such forgery. */
  {
    static const uint8_t dangling[] = {0xB9, 0xFF, 0xFF};
    static const uint8_t unsorted[] = {0xA2, 0x61, 0x62, 0x01,
                                       0x61, 0x61, 0x01};
    static const uint8_t duplicate[] = {0xA2, 0x61, 0x61, 0x01,
                                        0x61, 0x61, 0x02};
    static const uint8_t indefinite[] = {0xBF, 0xFF};
    static const uint8_t trailing[] = {0xA1, 0x61, 0x61, 0x01, 0x00};
    static const uint8_t key_no_value[] = {0xA1, 0x61, 0x61};
    static const uint8_t value_truncated[] = {0xA1, 0x61, 0x61, 0x43, 0x01};
    static const uint8_t nested_ok[] = {0xA1, 0x61, 0x61, 0x82, 0x01, 0x02};
    static const uint8_t ordered_ok[] = {0xA2, 0x61, 0x61, 0x01,
                                         0x61, 0x62, 0x02};
    static cc_announce_t a9;
    static uint8_t pkt9[CC_ANN_BUF_SZ];
    size_t l9 = 0;
    cc_key_t k9;

    cc_key_generate(&k9, rng);
    T("meta_dangling_head_rejected",
      cc_announce_build(&g_w, &k9, "n", 1, dangling, sizeof(dangling), NULL, 5,
                        0, pkt9, sizeof(pkt9), &l9, rng) == CC_E_ARG);
    T("meta_unsorted_rejected",
      cc_announce_build(&g_w, &k9, "n", 1, unsorted, sizeof(unsorted), NULL, 5,
                        0, pkt9, sizeof(pkt9), &l9, rng) == CC_E_ARG);
    T("meta_duplicate_key_rejected",
      cc_announce_build(&g_w, &k9, "n", 1, duplicate, sizeof(duplicate), NULL,
                        5, 0, pkt9, sizeof(pkt9), &l9, rng) == CC_E_ARG);
    T("meta_indefinite_rejected",
      cc_announce_build(&g_w, &k9, "n", 1, indefinite, sizeof(indefinite), NULL,
                        5, 0, pkt9, sizeof(pkt9), &l9, rng) == CC_E_ARG);
    T("meta_trailing_bytes_rejected",
      cc_announce_build(&g_w, &k9, "n", 1, trailing, sizeof(trailing), NULL, 5,
                        0, pkt9, sizeof(pkt9), &l9, rng) == CC_E_ARG);
    T("meta_key_without_value_rejected",
      cc_announce_build(&g_w, &k9, "n", 1, key_no_value, sizeof(key_no_value),
                        NULL, 5, 0, pkt9, sizeof(pkt9), &l9, rng) == CC_E_ARG);
    T("meta_truncated_value_rejected",
      cc_announce_build(&g_w, &k9, "n", 1, value_truncated,
                        sizeof(value_truncated), NULL, 5, 0, pkt9, sizeof(pkt9),
                        &l9, rng) == CC_E_ARG);
    /* Valid maps still go through: nested definite items, canonical order. */
    T("meta_nested_ok",
      cc_announce_build(&g_w, &k9, "n", 1, nested_ok, sizeof(nested_ok), NULL,
                        5, 0, pkt9, sizeof(pkt9), &l9, rng) == CC_OK &&
          cc_announce_parse(&g_w, pkt9, l9, &a9) == CC_OK &&
          a9.meta_len == sizeof(nested_ok) &&
          memcmp(a9.meta, nested_ok, sizeof(nested_ok)) == 0);
    T("meta_ordered_ok",
      cc_announce_build(&g_w, &k9, "n", 1, ordered_ok, sizeof(ordered_ok), NULL,
                        5, 0, pkt9, sizeof(pkt9), &l9, rng) == CC_OK &&
          cc_announce_parse(&g_w, pkt9, l9, &a9) == CC_OK &&
          a9.meta_len == sizeof(ordered_ok));

    /* And a hostile sender cannot smuggle a malformed map past the parser
       either. The map element of a valid announce is rewritten in place with an
       equal-length non-canonical map (unsorted keys), so the envelope stays
       canonical and the only thing wrong is the signed metadata. The gate is
       structural and runs before the signature, so it is refused cheaply even
       though the bytes no longer verify. */
    T("meta_roundtrip_again",
      cc_announce_build(&g_w, &k9, "n", 1, ordered_ok, sizeof(ordered_ok), NULL,
                        6, 0, pkt9, sizeof(pkt9), &l9, rng) == CC_OK);
    T("meta_swap_located", t_elem_off(pkt9, l9, 7) != 0);
    memcpy(pkt9 + t_elem_off(pkt9, l9, 7), unsorted, sizeof(unsorted));
    T("meta_parse_unsorted_rejected",
      cc_announce_parse(&g_w, pkt9, l9, &a9) == CC_E_FORMAT);
    memcpy(pkt9 + t_elem_off(pkt9, l9, 7), duplicate, sizeof(duplicate));
    T("meta_parse_duplicate_rejected",
      cc_announce_parse(&g_w, pkt9, l9, &a9) == CC_E_FORMAT);
    cc_key_free(&k9);
  }

  /* Freshness: strictly newer sequence, and not expired. */
  T("first_unknown_peer", cc_announce_fresh(NULL, &a2, 0) == CC_OK);
  T("newer_accepted", cc_announce_fresh(&a1, &a2, 0) == CC_OK);
  T("replay_dropped", cc_announce_fresh(&a2, &a1, 0) == CC_E_STALE);
  T("same_seq_dropped", cc_announce_fresh(&a2, &a2, 0) == CC_E_STALE);
  T("expired_dropped", cc_announce_fresh(&a1, &a2, 200) == CC_E_STALE);
  T("unexpired_accepted", cc_announce_fresh(&a1, &a2, 199) == CC_OK);
  /* expiry 0 means "no expiry declared": it is never stale for age alone. */
  T("build_no_expiry",
    cc_announce_build(&g_w, &key, "Alice", 5, NULL, 0, NULL, 4, 0, pkt4,
                      sizeof(pkt4), &l4, rng) == CC_OK);
  T("parse_no_expiry", cc_announce_parse(&g_w, pkt4, l4, &a4) == CC_OK &&
                           a4.seq == 4 && a4.expiry == 0);
  T("no_expiry_never_expires",
    cc_announce_fresh(&a1, &a4, 4000000000u) == CC_OK);
  T("expired_announce_dropped", cc_announce_fresh(&a1, &a3, 300) == CC_E_STALE);

  /* A replayed identical announce no longer re-seeds a stale view. */
  T("identical_replay_dropped", cc_announce_fresh(&a2, &a2, 0) == CC_E_STALE);

  cc_key_free(&key);
}

static void test_presence_hint(WC_RNG* rng) {
  static cc_key_t key;
  cc_announce_t ann = {0}, other = {0};
  cc_presence_t p;
  static uint8_t ann_pkt[CC_ANN_BUF_SZ], pkt[CC_PRES_BUF_SZ];
  size_t al = 0, pl = 0;
  uint8_t nh[CC_PRES_NAME_HASH_SZ];
  cc_replay_t st;
  printf("presence hint:\n");

  cc_key_generate(&key, rng);
  T("announce",
    cc_announce_build(&g_w, &key, "Alice", 5, NULL, 0, NULL, 1, 0, ann_pkt,
                      sizeof(ann_pkt), &al, rng) == CC_OK &&
        cc_announce_parse(&g_w, ann_pkt, al, &ann) == CC_OK);
  T("presence", cc_presence_build(&g_w, &key, "Alice", 5, 7, pkt, sizeof(pkt),
                                  &pl, rng) == CC_OK);
  T("fits_one_fragment", pl <= CC_PRES_BUF_SZ);
  printf("  (presence packet %zu bytes)\n", pl);
  T("parse", cc_presence_parse(&g_w, pkt, pl, &p) == CC_OK && p.seq == 7);
  T("carries_hash_not_name",
    cc_name_hash("Alice", 5, nh) == CC_OK &&
        memcmp(p.name_hash, nh, CC_PRES_NAME_HASH_SZ) == 0);
  T("matches_announce", cc_presence_matches_announce(&p, &ann) == CC_OK);

  /* The same address claiming a different name is ignored, not trusted. */
  other = ann;
  memcpy(other.name, "Mallory", 7);
  other.name_len = 7;
  T("name_mismatch_ignored",
    cc_presence_matches_announce(&p, &other) == CC_E_STALE);

  /* A different address is ignored too. */
  other = ann;
  other.addr[0] ^= 0xFF;
  T("addr_mismatch_ignored",
    cc_presence_matches_announce(&p, &other) == CC_E_STALE);

  /* Its seq is deduped like the old counter, in an UNSIGNED window. */
  cc_replay_init(&st, ann.addr, CC_REPLAY_UNSIGNED);
  T("first_accepted", cc_replay_check(&st, p.addr, p.seq) == CC_OK);
  T("replay_dropped", cc_replay_check(&st, p.addr, p.seq) == CC_E_REPLAY);

  cc_key_free(&key);
}

/* Reentrancy: the library keeps no mutable global state, so two working
   contexts are independent. The interleaved half proves it for a multi-step
   protocol (one link handshake split across two contexts); the threaded half
   proves it under actual concurrency, which is what a surviving static buffer
   would break — with the old file-scope buffers the two threads share
   pt/ct/pre/sig and their packets come out corrupt. */
typedef struct {
  cc_work_t* w;
  cc_key_t alice,
      bob; /* one per thread: keys, RNG and packets are caller state */
  uint8_t pkt[CC_CHAT_BUF_SZ];
  WC_RNG rng;
  int rounds;
  int ok;
} re_thread_t;

static void* re_worker(void* arg) {
  re_thread_t* t = (re_thread_t*)arg;
  static const char msg[] = "concurrent";
  cc_key_t* alice = &t->alice;
  cc_key_t* bob = &t->bob;
  uint8_t a_addr[CC_ADDR_SZ], b_addr[CC_ADDR_SZ];
  uint8_t a_sign[CC_SIGN_PUBKEY_SZ];
  uint8_t tmp[CC_SIGN_PUBKEY_SZ], b_kem[CC_KEM_PUBKEY_SZ];
  cc_replay_t st;
  cc_chat_t chat;
  int i;

  /* each thread owns its keys, so the only thing shared is the library */
  if (wc_InitRng(&t->rng) != 0)
    return NULL;
  if (cc_key_generate(alice, &t->rng) != CC_OK ||
      cc_key_generate(bob, &t->rng) != CC_OK)
    return NULL;
  if (cc_key_export_public(alice, a_sign, tmp) != CC_OK ||
      cc_key_export_public(bob, tmp, b_kem) != CC_OK)
    return NULL;
  cc_addr_from_key(alice, a_addr);
  cc_addr_from_key(bob, b_addr);

  t->ok = 1;
  for (i = 0; i < t->rounds; i++) {
    size_t len = 0;
    if (cc_chat_build(t->w, alice, b_addr, b_kem, (uint32_t)(1 + i),
                      (const uint8_t*)msg, strlen(msg), 0, t->pkt,
                      sizeof(t->pkt), &len, &t->rng) != CC_OK) {
      t->ok = 0;
      break;
    }
    cc_replay_init(&st, a_addr, CC_REPLAY_AUTHED);
    if (cc_chat_parse(t->w, bob, a_sign, &st, t->pkt, len, &chat) != CC_OK ||
        chat.msg_len != strlen(msg) ||
        memcmp(chat.msg, msg, chat.msg_len) != 0 ||
        memcmp(chat.sender_addr, a_addr, CC_ADDR_SZ) != 0) {
      t->ok = 0;
      break;
    }
  }
  cc_key_free(alice);
  cc_key_free(bob);
  wc_FreeRng(&t->rng);
  return NULL;
}

/* ---- group destinations (a new type inside revision 9) ---- */

/* An open link between two nodes, set up the way a caller does. Not needed to
   be in a group; it is only one way to deliver the secret. */
static int t_link_pair(WC_RNG* rng, const cc_key_t* ini, const cc_key_t* res,
                       cc_link_t* li, cc_link_t* lr, uint32_t now) {
  static uint8_t req[CC_LINK_REQ_BUF_SZ], proof[CC_LINK_PROOF_BUF_SZ];
  uint8_t i_sign[CC_SIGN_PUBKEY_SZ], i_kem[CC_KEM_PUBKEY_SZ];
  uint8_t r_sign[CC_SIGN_PUBKEY_SZ], r_kem[CC_KEM_PUBKEY_SZ];
  uint8_t r_addr[CC_ADDR_SZ];
  size_t rl = 0, pl = 0;
  uint32_t idle = 100000;

  cc_key_export_public(ini, i_sign, i_kem);
  cc_key_export_public(res, r_sign, r_kem);
  cc_addr_from_key(res, r_addr);
  if (cc_link_start(&g_w, li, r_addr, r_kem, now, idle, 0, req, sizeof(req),
                    &rl, rng) != CC_OK)
    return 0;
  if (cc_link_accept(&g_w, lr, res, now, idle, req, rl, proof, sizeof(proof),
                     &pl, rng) != CC_OK)
    return 0;
  return cc_link_confirm(&g_w, li, r_addr, r_sign, proof, pl) == CC_OK;
}

static void test_group(WC_RNG* rng) {
  static cc_key_t ka, kb, kc;
  static cc_group_t ga, gb, gc, gx, gy;
  static cc_group_win_t wa_a, wa_b, wa_c, wb, wc_a, wc_b, wx;
  static cc_link_t lab_a, lab_b;
  static uint8_t post[CC_GROUP_BUF_SZ], post2[CC_GROUP_BUF_SZ];
  static uint8_t post3[CC_GROUP_BUF_SZ], badd[CC_GROUP_BUF_SZ];
  static uint8_t krec[CC_LINK_DATA_BUF_SZ], payload[CC_LINK_DATA_BUF_SZ];
  static uint8_t
      big_body[CC_GROUP_ENC0_SZ + 32]; /* for over-long field bodies */
  static cc_group_msg_t m;
  uint8_t addr_a[CC_ADDR_SZ], addr_b[CC_ADDR_SZ], addr_c[CC_ADDR_SZ];
  uint8_t secret[CC_GROUP_SECRET_SZ], gid[CC_GROUP_GID_SZ], who[CC_ADDR_SZ];
  size_t nl = 0, n2 = 0, n3 = 0, bl = 0, rl = 0, plen = 0, el;
  uint8_t kind = 0, hop = 0;
  int i;
  printf("group destinations:\n");

  cc_key_generate(&ka, rng);
  cc_key_generate(&kb, rng);
  cc_key_generate(&kc, rng);
  cc_addr_from_key(&ka, addr_a);
  cc_addr_from_key(&kb, addr_b);
  cc_addr_from_key(&kc, addr_c);

  /* One secret per group, shared out of band. */
  T("group_create", cc_group_create(&ga, rng) == CC_OK && ga.used == 1);
  T("group_secret_export",
    cc_group_secret_export(&ga, secret) == CC_OK &&
        memcmp(secret, ga.secret, CC_GROUP_SECRET_SZ) == 0);
  T("group_join_b", cc_group_join(&gb, secret) == CC_OK);
  T("group_join_c", cc_group_join(&gc, secret) == CC_OK);
  T("group_gid_matches_for_every_member",
    memcmp(ga.gid, gb.gid, CC_GROUP_GID_SZ) == 0 &&
        memcmp(ga.gid, gc.gid, CC_GROUP_GID_SZ) == 0);
  T("group_gid_is_not_the_secret",
    memcmp(ga.gid, ga.secret, CC_GROUP_GID_SZ) != 0);
  T("group_gid_survives_export_import",
    cc_group_create(&gx, rng) == CC_OK &&
        cc_group_secret_export(&gx, secret) == CC_OK &&
        cc_group_join(&gy, secret) == CC_OK &&
        memcmp(gx.gid, gy.gid, CC_GROUP_GID_SZ) == 0);
  T("group_different_secrets_different_gids",
    memcmp(gx.gid, ga.gid, CC_GROUP_GID_SZ) != 0);
  T("group_export_needs_state",
    cc_group_free(&gy) == CC_OK &&
        cc_group_secret_export(&gy, secret) == CC_E_ARG);

  /* Windows are per (gid, poster label). */
  T("group_win_init_a_a", cc_group_win_init(&wa_a, ga.gid, addr_a) == CC_OK);
  T("group_win_init_a_b", cc_group_win_init(&wa_b, ga.gid, addr_a) == CC_OK);
  T("group_win_init_a_c", cc_group_win_init(&wa_c, ga.gid, addr_a) == CC_OK);
  T("group_win_init_b", cc_group_win_init(&wb, ga.gid, addr_b) == CC_OK);
  T("group_win_init_c_a", cc_group_win_init(&wc_a, ga.gid, addr_c) == CC_OK);
  T("group_win_init_c_b", cc_group_win_init(&wc_b, ga.gid, addr_c) == CC_OK);
  T("group_win_is_bound_to_the_composite",
    memcmp(wb.gid, ga.gid, CC_GROUP_GID_SZ) == 0 &&
        memcmp(wb.poster, addr_b, CC_ADDR_SZ) == 0);

  /* A post from each of two members, read by the other two: a two-member and a
     three-member round trip. */
  T("group_post_build_a",
    cc_group_post_build(&g_w, &ga, addr_a, 1, (const uint8_t*)"one", 3, post,
                        sizeof(post), &nl, rng) == CC_OK);
  T("group_post_fits", nl > 0 && nl <= CC_GROUP_BUF_SZ);
  T("group_post_type",
    cc_msg_type(post, nl, &kind) == CC_OK && kind == CC_MSG_GROUP_DATA);
  T("group_post_pow", cc_pow_verify(post, nl) == CC_OK);
  T("group_post_hops", cc_msg_hops(post, nl, &hop) == CC_OK && hop == 0);
  T("group_post_accessors", cc_group_gid(post, nl, gid) == CC_OK &&
                                memcmp(gid, ga.gid, CC_GROUP_GID_SZ) == 0 &&
                                cc_group_poster(post, nl, who) == CC_OK &&
                                memcmp(who, addr_a, CC_ADDR_SZ) == 0);
  T("group_post_read_by_b",
    cc_group_post_parse(&g_w, &gb, &wa_b, post, nl, 100, &m) == CC_OK &&
        m.msg_len == 3 && memcmp(m.msg, "one", 3) == 0 && m.seq == 1 &&
        memcmp(m.poster, addr_a, CC_ADDR_SZ) == 0 &&
        memcmp(m.gid, ga.gid, CC_GROUP_GID_SZ) == 0);
  T("group_post_read_by_c",
    cc_group_post_parse(&g_w, &gc, &wa_c, post, nl, 100, &m) == CC_OK &&
        m.msg_len == 3 && memcmp(m.msg, "one", 3) == 0);
  T("group_post_build_c",
    cc_group_post_build(&g_w, &gc, addr_c, 1, (const uint8_t*)"three", 5, post3,
                        sizeof(post3), &n3, rng) == CC_OK);
  T("group_post_c_read_by_a_and_b",
    cc_group_post_parse(&g_w, &ga, &wc_a, post3, n3, 100, &m) == CC_OK &&
        memcmp(m.msg, "three", 5) == 0 &&
        cc_group_post_parse(&g_w, &gb, &wc_b, post3, n3, 100, &m) == CC_OK &&
        m.msg_len == 5);

  /* A NON-member: its group key is different, so it cannot read a post, and a
     post of its own is not ours at all. */
  T("group_nonmember_cannot_read",
    cc_group_post_parse(&g_w, &gx, &wx, post, nl, 100, &m) == CC_E_GROUP ||
        cc_group_post_parse(&g_w, &gx, &wx, post, nl, 100, &m) == CC_E_ARG);
  T("group_stranger_post_refused_by_gid",
    cc_group_post_build(&g_w, &gx, addr_a, 1, (const uint8_t*)"mine", 4, post2,
                        sizeof(post2), &n2, rng) == CC_OK &&
        cc_group_post_parse(&g_w, &ga, &wa_b, post2, n2, 100, &m) ==
            CC_E_GROUP);
  T("group_wrong_label_window_refused",
    cc_group_post_parse(&g_w, &gb, &wb, post, nl, 100, &m) == CC_E_ARG);

  /* THE DOCUMENTED LIMIT, PINNED AS A TEST: the poster field is a label, not an
     identity. B holds the group key, so B can seal a post that any member reads
     as coming from A. The suite asserts this rather than leaving it to prose.
   */
  T("group_member_can_forge_another_label",
    cc_group_post_build(&g_w, &gb, addr_a, 9, (const uint8_t*)"not a", 5, post2,
                        sizeof(post2), &n2, rng) == CC_OK &&
        cc_group_post_parse(&g_w, &ga, &wa_a, post2, n2, 100, &m) == CC_OK &&
        memcmp(m.poster, addr_a, CC_ADDR_SZ) == 0 &&
        memcmp(m.msg, "not a", 5) == 0);
  T("group_forged_label_moves_that_window",
    cc_group_post_parse(&g_w, &ga, &wa_a, post2, n2, 100, &m) == CC_E_REPLAY);

  /* Replay and reordering, one window per label. */
  T("group_replay_refused",
    cc_group_post_parse(&g_w, &gb, &wa_b, post, nl, 100, &m) == CC_E_REPLAY);
  T("group_out_of_order_accepted",
    cc_group_post_build(&g_w, &ga, addr_a, 20, (const uint8_t*)"twenty", 6,
                        post2, sizeof(post2), &n2, rng) == CC_OK &&
        cc_group_post_parse(&g_w, &gb, &wa_b, post2, n2, 100, &m) == CC_OK &&
        m.seq == 20);
  T("group_gap_inside_window_accepted",
    cc_group_post_build(&g_w, &ga, addr_a, 10, (const uint8_t*)"ten", 3, post3,
                        sizeof(post3), &n3, rng) == CC_OK &&
        cc_group_post_parse(&g_w, &gb, &wa_b, post3, n3, 100, &m) == CC_OK &&
        m.seq == 10);
  T("group_gap_repeated_refused",
    cc_group_post_parse(&g_w, &gb, &wa_b, post3, n3, 100, &m) == CC_E_REPLAY);
  T("group_far_past_refused",
    cc_group_post_build(&g_w, &ga, addr_a, 300, (const uint8_t*)"far", 3, badd,
                        sizeof(badd), &bl, rng) == CC_OK &&
        cc_group_post_parse(&g_w, &gb, &wa_b, badd, bl, 100, &m) == CC_OK &&
        cc_group_post_build(&g_w, &ga, addr_a, 30, (const uint8_t*)"old", 3,
                            post2, sizeof(post2), &n2, rng) == CC_OK &&
        cc_group_post_parse(&g_w, &gb, &wa_b, post2, n2, 100, &m) ==
            CC_E_STALE);

  /* PEEK BEFORE THE TAG, COMMIT AFTER IT: a post that fails the tag must not
     move the window, so the honest post that shares its sequence still lands.
   */
  T("group_tampered_post_ready",
    cc_group_post_build(&g_w, &ga, addr_a, 400, (const uint8_t*)"real", 4,
                        post2, sizeof(post2), &n2, rng) == CC_OK);
  memcpy(badd, post2, n2);
  bl = n2;
  {
    /* corrupt the ciphertext and re-mine, so the PoW passes and the tag is what
       rejects it */
    size_t co = t_body(badd, bl, 7);
    badd[co + 1] ^= 0xFF;
    T("group_tampered_post_remined", t_remine(badd, &bl, 6) == 0);
  }
  T("group_tampered_post_refused_without_moving_the_window",
    cc_group_post_parse(&g_w, &gb, &wa_b, badd, bl, 100, &m) == CC_E_DECRYPT &&
        cc_group_post_parse(&g_w, &gb, &wa_b, post2, n2, 100, &m) == CC_OK &&
        m.seq == 400);

  /* The window stamps itself when a post verifies, so a caller can bound its
     table: a window that never carried a verified post ages out first. */
  {
    static cc_group_win_t ws;
    T("group_win_last_seen_starts_at_zero",
      cc_group_win_init(&ws, ga.gid, addr_a) == CC_OK && ws.last_seen == 0);
    T("group_win_never_verified_evicts_first",
      cc_group_win_stale(&ws, 1000, 100) == 1);
    T("group_stamp_post_built",
      cc_group_post_build(&g_w, &ga, addr_a, 900, (const uint8_t*)"stamp", 5,
                          post2, sizeof(post2), &n2, rng) == CC_OK);
    T("group_win_stamp_on_a_verified_post",
      cc_group_post_parse(&g_w, &gb, &ws, post2, n2, 500, &m) == CC_OK &&
          ws.last_seen == 500);
    T("group_win_fresh_inside_the_horizon",
      cc_group_win_stale(&ws, 600, 100) == 0);
    T("group_win_stale_after_the_horizon",
      cc_group_win_stale(&ws, 601, 100) == 1);
    T("group_win_failed_tag_does_not_stamp",
      cc_group_win_forget(&ws) == CC_OK &&
          cc_group_win_init(&ws, ga.gid, addr_a) == CC_OK &&
          cc_group_post_parse(&g_w, &gb, &ws, badd, bl, 700, &m) ==
              CC_E_DECRYPT &&
          ws.last_seen == 0);
    T("group_win_stale_on_null", cc_group_win_stale(NULL, 0, 0) == 1);
  }

  /* The type obeys the house rules: field contracts, canonical heads, PoW. */
  {
    static const uint8_t cnt[CC_ADDR_SZ] = {9};
    el = t_swap_bstr(post, nl, 3, cnt, CC_GROUP_GID_SZ - 1);
    T("group_field_contract_gid",
      el > 0 && cc_group_post_parse(&g_w, &gb, &wa_b, t_swap_buf, el, 100,
                                    &m) == CC_E_FORMAT);
    el = t_swap_bstr(post, nl, 7, big_body, CC_GROUP_ENC0_SZ + 1);
    T("group_field_contract_ciphertext",
      el > 0 && cc_group_post_parse(&g_w, &gb, &wa_b, t_swap_buf, el, 100,
                                    &m) == CC_E_FORMAT);
    /* A hand-built post with a non-minimal array head: 0x98 0x08 for array(8).
     */
    for (i = 0; i < (int)sizeof(badd); i++) badd[i] = 0;
    bl = 0;
    badd[bl++] = 0x98;
    badd[bl++] = 0x08;
    badd[bl++] = CC_WIRE_VERSION;
    badd[bl++] = CC_MSG_GROUP_DATA;
    badd[bl++] = 0x00; /* hops */
    badd[bl++] = 0x48;
    memcpy(badd + bl, ga.gid, CC_GROUP_GID_SZ);
    bl += CC_GROUP_GID_SZ;
    badd[bl++] = 0x50;
    memcpy(badd + bl, addr_a, CC_ADDR_SZ);
    bl += CC_ADDR_SZ;
    badd[bl++] = 0x01; /* seq */
    badd[bl++] = 0x00; /* nonce */
    badd[bl++] = 0x40; /* empty ciphertext */
    T("group_noncanonical_head_refused",
      cc_group_post_parse(&g_w, &gb, &wa_b, badd, bl, 100, &m) == CC_E_FORMAT);
    T("group_trailing_bytes_refused",
      cc_group_post_parse(&g_w, &gb, &wa_b, badd, bl + 1, 100, &m) ==
          CC_E_FORMAT);
    T("group_empty_ciphertext_refused",
      cc_group_post_parse(&g_w, &gb, &wa_b, badd, bl, 100, &m) == CC_E_FORMAT);
  }

  /* Provisioning over an existing link, and the record's own checks. */
  T("group_link_pair", t_link_pair(rng, &ka, &kb, &lab_a, &lab_b, 2));
  T("group_secret_send", cc_group_secret_send(&g_w, &ga, &lab_a, 3, krec,
                                              sizeof(krec), &rl) == CC_OK);
  T("group_secret_recv_is_a_link_record",
    cc_link_recv(&g_w, &lab_b, krec, rl, 3, &kind, payload, sizeof(payload),
                 &plen) == CC_OK &&
        kind == CC_LINK_KIND_GROUP_KEY);
  T("group_secret_recv_joins",
    cc_group_join(&gy, (const uint8_t[CC_GROUP_SECRET_SZ]){1}) == CC_OK &&
        memcmp(gy.gid, ga.gid, CC_GROUP_GID_SZ) != 0 &&
        cc_group_secret_recv(&g_w, &gy, &lab_b, payload, plen) == CC_OK &&
        memcmp(gy.gid, ga.gid, CC_GROUP_GID_SZ) == 0);
  {
    /* A record whose gid and secret disagree is not a group we can join. */
    static uint8_t bad_rec[CC_GROUP_SECREC_BUF_SZ];
    size_t badl = payload[0] == 0x82 ? 0 : 0;
    (void)badl;
    memcpy(bad_rec, payload, plen);
    bad_rec[plen - 1] ^= 0xFF; /* break the secret, keep the framing */
    T("group_secret_recv_mismatch_refused",
      cc_group_secret_recv(&g_w, &gy, &lab_b, bad_rec, plen) == CC_E_SIG);
    T("group_secret_recv_truncated_refused",
      cc_group_secret_recv(&g_w, &gy, &lab_b, payload, plen - 1) ==
          CC_E_FORMAT);
  }
  {
    cc_link_t dead;
    memset(&dead, 0, sizeof(dead));
    T("group_secret_recv_closed_link_refused",
      cc_group_secret_recv(&g_w, &gy, &dead, payload, plen) == CC_E_NOLINK);
  }

  /* Accessors refuse the wrong type, and free wipes. */
  T("group_accessor_wrong_type", cc_group_poster(post3, n3, who) == CC_OK &&
                                     cc_group_gid(post, 1, gid) == CC_E_FORMAT);
  T("group_free_wipes", cc_group_free(&gx) == CC_OK && gx.used == 0 &&
                            memcmp(gx.gid, ga.gid, CC_GROUP_GID_SZ) != 0);
  T("group_win_forget_wipes", cc_group_win_forget(&wx) == CC_OK &&
                                  memcmp(wx.poster, addr_c, CC_ADDR_SZ) != 0);
  cc_group_free(&ga);
  cc_group_free(&gb);
  cc_group_free(&gc);
  cc_group_free(&gy);
}

/* ---- one PoW rule, exposed for other modules (revision 9) ---- */

/* The suite prices every PoW type at its configured value plus one, so that
   value has to leave room in the digest. */
_Static_assert(CC_POW_DIFFICULTY_ANNOUNCE < CC_POW_MAX &&
                   CC_POW_DIFFICULTY_CHAT < CC_POW_MAX &&
                   CC_POW_DIFFICULTY_PRESENCE < CC_POW_MAX &&
                   CC_POW_DIFFICULTY_KEY_REQ < CC_POW_MAX &&
                   CC_POW_DIFFICULTY_LINK_REQ < CC_POW_MAX &&
                   CC_POW_DIFFICULTY_LINK_PROOF < CC_POW_MAX &&
                   CC_POW_DIFFICULTY_ROTATE < CC_POW_MAX &&
                   CC_POW_DIFFICULTY_REVOKE < CC_POW_MAX,
               "configured difficulties must stay below CC_POW_MAX for +1");

static void test_pow_verify_at(WC_RNG* rng) {
  static cc_key_t key, other, bob;
  static uint8_t ann[CC_ANN_BUF_SZ], chat[CC_CHAT_BUF_SZ];
  static uint8_t pres[CC_PRES_BUF_SZ], req[CC_KEY_REQ_BUF_SZ];
  static uint8_t lreq[CC_LINK_REQ_BUF_SZ], proof[CC_LINK_PROOF_BUF_SZ];
  static uint8_t rot[CC_ROTATE_BUF_SZ], rev[CC_REVOKE_BUF_SZ];
  static uint8_t data[CC_LINK_DATA_BUF_SZ], broken[CC_ANN_BUF_SZ];
  uint8_t addr[CC_ADDR_SZ], kem[CC_KEM_PUBKEY_SZ];
  uint8_t parsed_addr[CC_ADDR_SZ];
  uint32_t counter_out = 0;
  size_t al = 0, cl = 0, pl = 0, rl = 0, ll = 0, prl = 0, rol = 0, vl = 0;
  size_t dl = 0, bl;
  cc_link_t li, lr;
  struct {
    const char* name;
    const uint8_t* pkt;
    size_t len;
    uint8_t configured;
  } t[8];
  int i;
  printf("PoW verification at an explicit difficulty:\n");

  cc_key_generate(&key, rng);
  cc_key_generate(&other, rng);
  cc_key_generate(&bob, rng);
  {
    static uint8_t sign_pub[CC_SIGN_PUBKEY_SZ], kem_pub[CC_KEM_PUBKEY_SZ];
    T("pow_at_keys_exported",
      cc_key_export_public(&key, sign_pub, kem_pub) == CC_OK &&
          cc_addr_from_sign_pubkey(sign_pub, addr) == CC_OK);
    memcpy(kem, kem_pub, CC_KEM_PUBKEY_SZ);
  }

  /* One packet of every type that carries a nonce. */
  T("pow_at_announce_built",
    cc_announce_build(&g_w, &key, "n", 1, NULL, 0, NULL, 1, 0, ann, sizeof(ann),
                      &al, rng) == CC_OK);
  T("pow_at_chat_built",
    cc_chat_build(&g_w, &key, addr, kem, 1, (const uint8_t*)"hi", 2, 0, chat,
                  sizeof(chat), &cl, rng) == CC_OK);
  T("pow_at_presence_built",
    cc_presence_build(&g_w, &key, "n", 1, 1, pres, sizeof(pres), &pl, rng) ==
        CC_OK);
  T("pow_at_key_req_built",
    cc_key_req_build(&g_w, addr, 1, 0, req, sizeof(req), &rl) == CC_OK);
  T("pow_at_link_req_built",
    cc_link_start(&g_w, &li, addr, kem, 0, 1000, 0, lreq, sizeof(lreq), &ll,
                  rng) == CC_OK);
  T("pow_at_link_proof_built",
    cc_link_accept(&g_w, &lr, &key, 0, 1000, lreq, ll, proof, sizeof(proof),
                   &prl, rng) == CC_OK);
  T("pow_at_rotate_built",
    cc_rotate_build(&g_w, &other, &key, "n", 1, NULL, 0, 1, 0, rot, sizeof(rot),
                    &rol, rng) == CC_OK);
  T("pow_at_revoke_built",
    cc_revoke_build(&g_w, &key, 1, 0, rev, sizeof(rev), &vl, rng) == CC_OK);

#define POW_AT_CASE(k, nm, pk, ln, cf) \
  do {                                 \
    t[k].name = nm;                    \
    t[k].pkt = pk;                     \
    t[k].len = ln;                     \
    t[k].configured = (cf);            \
  } while (0)
  POW_AT_CASE(0, "announce", ann, al, CC_POW_DIFFICULTY_ANNOUNCE);
  POW_AT_CASE(1, "chat", chat, cl, CC_POW_DIFFICULTY_CHAT);
  POW_AT_CASE(2, "presence", pres, pl, CC_POW_DIFFICULTY_PRESENCE);
  POW_AT_CASE(3, "key_req", req, rl, CC_POW_DIFFICULTY_KEY_REQ);
  POW_AT_CASE(4, "link_req", lreq, ll, CC_POW_DIFFICULTY_LINK_REQ);
  POW_AT_CASE(5, "link_proof", proof, prl, CC_POW_DIFFICULTY_LINK_PROOF);
  POW_AT_CASE(6, "rotate", rot, rol, CC_POW_DIFFICULTY_ROTATE);
  POW_AT_CASE(7, "revoke", rev, vl, CC_POW_DIFFICULTY_REVOKE);
#undef POW_AT_CASE

  for (i = 0; i < 8; i++) {
    char label[96];
    snprintf(label, sizeof(label), "pow_at_%s_zero_is_the_build_default",
             t[i].name);
    T(label, cc_pow_verify_at(t[i].pkt, t[i].len, 0) == CC_OK &&
                 cc_pow_verify(t[i].pkt, t[i].len) ==
                     cc_pow_verify_at(t[i].pkt, t[i].len, 0));
    snprintf(label, sizeof(label), "pow_at_%s_verifies_at_its_own", t[i].name);
    T(label, cc_pow_verify_at(t[i].pkt, t[i].len, t[i].configured) == CC_OK);
    /* Refused at a bar above the one it was mined for. The bar is CC_POW_MAX
       rather than configured + 1 deliberately: mining at d says nothing about
       byte d, so "fails at d + 1" holds only 255 times in 256 and writing it
       that way is what made this suite flaky. The exact +1 case is pinned
       below, where the packet can be mined at a chosen difficulty through the
       API and the refusal is therefore constructed rather than hoped for. */
    snprintf(label, sizeof(label), "pow_at_%s_refused_above_its_own",
             t[i].name);
    T(label, cc_pow_verify_at(t[i].pkt, t[i].len, CC_POW_MAX) == CC_E_POW);
  }

  /* A type with no nonce verifies trivially, whatever bar is asked for. */
  T("pow_at_link_data_has_no_pow",
    cc_link_send(&g_w, &lr, CC_LINK_KIND_DATA, (const uint8_t*)"x", 1, 1, data,
                 sizeof(data), &dl) == CC_OK &&
        cc_pow_verify_at(data, dl, 0) == CC_OK &&
        cc_pow_verify_at(data, dl, CC_POW_MAX) == CC_OK);

  /* Argument validation and the same failure codes cc_pow_verify reports. */
  T("pow_at_bad_arg", cc_pow_verify_at(ann, al, CC_POW_MAX + 1) == CC_E_ARG &&
                          cc_pow_verify_at(NULL, 0, 1) == CC_E_ARG);
  memcpy(broken, ann, al);
  bl = al;
  broken[t_head(broken, bl, 0)] = CC_WIRE_VERSION - 1;
  T("pow_at_version_matches_cc_pow_verify",
    cc_pow_verify_at(broken, bl, 0) == CC_E_VERSION &&
        cc_pow_verify(broken, bl) == CC_E_VERSION);
  T("pow_at_format_matches_cc_pow_verify",
    cc_pow_verify_at(ann, al - 1, 0) == CC_E_FORMAT &&
        cc_pow_verify(ann, al - 1) == CC_E_FORMAT);

#if CC_POW_DIFFICULTY_CHAT > 1
  /* The relay's case: a packet mined below this build's own bar, priced by
     someone else's declaration. It must be refused at this build's bar and
     accepted at the difficulty it was actually mined at — and "below the bar"
     is established by the search, not by hoping the draw went our way. */
  {
    static uint8_t low_chat[CC_CHAT_BUF_SZ], low_req[CC_KEY_REQ_BUF_SZ];
    static uint8_t low_lreq[CC_LINK_REQ_BUF_SZ];
    static uint8_t low_proof[CC_LINK_PROOF_BUF_SZ];
    static uint8_t b_sign[CC_SIGN_PUBKEY_SZ], b_kem[CC_KEM_PUBKEY_SZ];
    static uint8_t key_sign[CC_SIGN_PUBKEY_SZ];
    uint8_t b_addr[CC_ADDR_SZ];
    cc_replay_t st;
    cc_chat_t c;
    cc_link_t lr2;
    size_t lcl, lrl, lll, lpl;

    cc_key_export_public(&bob, b_sign, b_kem);
    cc_addr_from_sign_pubkey(b_sign, b_addr);
    cc_key_export_public(&key, key_sign, kem);
    cc_addr_from_sign_pubkey(key_sign, addr);

    lcl = t_mine_below(&g_w, 0, &key, b_addr, b_kem, 100, 1,
                       CC_POW_DIFFICULTY_CHAT, low_chat, sizeof(low_chat), rng);
    T("pow_at_low_chat_built", lcl > 0);
    T("pow_at_low_chat_refused_at_our_bar",
      cc_pow_verify_at(low_chat, lcl, 0) == CC_E_POW &&
          cc_pow_verify(low_chat, lcl) == CC_E_POW &&
          cc_replay_init(&st, addr, CC_REPLAY_AUTHED) == CC_OK &&
          cc_chat_parse(&g_w, &bob, key_sign, &st, low_chat, lcl, &c) ==
              CC_E_POW);
    T("pow_at_low_chat_accepted_at_its_own",
      cc_pow_verify_at(low_chat, lcl, 1) == CC_OK);

#if CC_POW_DIFFICULTY_KEY_REQ > 1
    lrl =
        t_mine_below(&g_w, 1, &key, b_addr, b_kem, 200, 1,
                     CC_POW_DIFFICULTY_KEY_REQ, low_req, sizeof(low_req), rng);
    T("pow_at_low_key_req_built", lrl > 0);
    T("pow_at_low_key_req_refused_at_our_bar",
      cc_pow_verify_at(low_req, lrl, 0) == CC_E_POW &&
          cc_key_req_parse(&g_w, low_req, lrl, parsed_addr, &counter_out) ==
              CC_E_POW);
    T("pow_at_low_key_req_accepted_at_its_own",
      cc_pow_verify_at(low_req, lrl, 1) == CC_OK);
#endif

#if CC_POW_DIFFICULTY_LINK_REQ > 1
    lll = t_mine_below(&g_w, 2, &key, b_addr, b_kem, 300, 1,
                       CC_POW_DIFFICULTY_LINK_REQ, low_lreq, sizeof(low_lreq),
                       rng);
    T("pow_at_low_link_req_built", lll > 0);
    T("pow_at_low_link_req_refused_at_our_bar",
      cc_pow_verify_at(low_lreq, lll, 0) == CC_E_POW &&
          cc_link_accept(&g_w, &lr2, &bob, 0, 1000, low_lreq, lll, low_proof,
                         sizeof(low_proof), &lpl, rng) == CC_E_POW);
    T("pow_at_low_link_req_accepted_at_its_own",
      cc_pow_verify_at(low_lreq, lll, 1) == CC_OK);
#endif
  }
#else
  printf(
      "  (build requires difficulty 1: a packet mined below it cannot "
      "exist)\n");
#endif
}

/* ---- identity lifecycle: rotation ---- */

/* Doctor a rotation the way its own successor's key holder could: replace one
   element, re-sign the envelope with the key whose public half the packet now
   carries, and re-mine the PoW (the nonce is outside the signature preimage,
   so mining afterwards leaves the signature valid). */
static size_t t_doctor_rotation(const uint8_t* rot, size_t rl, size_t elem,
                                const uint8_t* body, size_t body_len,
                                const cc_key_t* signer, WC_RNG* rng) {
  static const size_t skip[] = {2, 3, 11, 12}; /* hops, nonce, both sigs */
  size_t el = t_swap_bstr(rot, rl, elem, body, body_len);
  size_t cl = 0;
  word32 sl = CC_SIGN_SIG_SZ;

  if (el == 0)
    return 0;
  cl = t_covered(t_swap_buf, el, skip, 4, t_cov, sizeof(t_cov));
  if (cl == 0)
    return 0;
  if (wc_dilithium_sign_msg(t_cov, (word32)cl, t_rsig, &sl,
                            (dilithium_key*)&signer->sign, rng) != 0)
    return 0;
  memcpy(t_swap_buf + t_body(t_swap_buf, el, 11), t_rsig, sl);
  if (t_remine(t_swap_buf, &el, 3) != 0)
    return 0;
  return el;
}

static void test_rotation(WC_RNG* rng) {
  static cc_key_t alice_old, alice_new, alice_third, mallory_old, mallory_new;
  static cc_key_t bob;
  static uint8_t rot[CC_ROTATE_BUF_SZ], older[CC_ROTATE_BUF_SZ];
  static uint8_t m_rot[CC_ROTATE_BUF_SZ];
  static uint8_t a_old_sign[CC_SIGN_PUBKEY_SZ], a_old_kem[CC_KEM_PUBKEY_SZ];
  static uint8_t a_new_sign[CC_SIGN_PUBKEY_SZ], a_new_kem[CC_KEM_PUBKEY_SZ];
  static uint8_t a_third_sign[CC_SIGN_PUBKEY_SZ], a_third_kem[CC_KEM_PUBKEY_SZ];
  static uint8_t m_old_sign[CC_SIGN_PUBKEY_SZ], m_old_kem[CC_KEM_PUBKEY_SZ];
  static uint8_t m_new_sign[CC_SIGN_PUBKEY_SZ], m_new_kem[CC_KEM_PUBKEY_SZ];
  static uint8_t b_sign[CC_SIGN_PUBKEY_SZ], b_kem[CC_KEM_PUBKEY_SZ];
  static uint8_t ann_pkt[CC_ANN_BUF_SZ], chat[CC_CHAT_BUF_SZ];
  static uint8_t chat2[CC_CHAT_BUF_SZ], chat3[CC_CHAT_BUF_SZ];
  static cc_announce_t before, after, older_ann, tmp;
  static const uint8_t meta[] = {0xA1, 0x61, 0x61, 0x01};
  static const uint8_t zero_addr[CC_ADDR_SZ];
  uint8_t prev[CC_ADDR_SZ], m_prev[CC_ADDR_SZ], a_old_addr[CC_ADDR_SZ];
  uint8_t b_addr[CC_ADDR_SZ];
  size_t rl = 0, al = 0, ol = 0, ml = 0, el, cl = 0, c2 = 0, c3 = 0;
  cc_replay_t rp, rp2;
  cc_chat_t c;
  uint8_t kind = 0;
  printf("rotation:\n");

  cc_key_generate(&alice_old, rng);
  cc_key_generate(&alice_new, rng);
  cc_key_generate(&alice_third, rng);
  cc_key_generate(&mallory_old, rng);
  cc_key_generate(&mallory_new, rng);
  cc_key_generate(&bob, rng);
  cc_key_export_public(&alice_old, a_old_sign, a_old_kem);
  cc_key_export_public(&alice_new, a_new_sign, a_new_kem);
  cc_key_export_public(&alice_third, a_third_sign, a_third_kem);
  cc_key_export_public(&mallory_old, m_old_sign, m_old_kem);
  cc_key_export_public(&mallory_new, m_new_sign, m_new_kem);
  cc_key_export_public(&bob, b_sign, b_kem);
  cc_addr_from_key(&alice_old, a_old_addr);
  cc_addr_from_key(&bob, b_addr);

  printf("  (cc_announce_t = %zu bytes, cc_revoked_t = %zu bytes)\n",
         sizeof(cc_announce_t), sizeof(cc_revoked_t));

  /* What the peer has cached for Alice, before she rotates. */
  T("rotate_cached_announce",
    cc_announce_build(&g_w, &alice_old, "Alice", 5, meta, sizeof(meta), NULL, 7,
                      900, ann_pkt, sizeof(ann_pkt), &al, rng) == CC_OK &&
        cc_announce_parse(&g_w, ann_pkt, al, &before) == CC_OK &&
        memcmp(before.addr, a_old_addr, CC_ADDR_SZ) == 0);
  T("rotate_cached_has_no_predecessor",
    memcmp(before.prev_addr, zero_addr, CC_ADDR_SZ) == 0);

  T("rotate_build",
    cc_rotate_build(&g_w, &alice_new, &alice_old, "Alice", 5, meta,
                    sizeof(meta), 8, 900, rot, sizeof(rot), &rl, rng) == CC_OK);
  T("rotate_fits", rl > 0 && rl <= CC_ROTATE_BUF_SZ);
  T("rotate_type",
    cc_msg_type(rot, rl, &kind) == CC_OK && kind == CC_MSG_ROTATE);
  T("rotate_pow", cc_pow_verify(rot, rl) == CC_OK);
  T("rotate_prev_addr_peek", cc_rotate_prev_addr(rot, rl, prev) == CC_OK &&
                                 memcmp(prev, a_old_addr, CC_ADDR_SZ) == 0);
  T("rotate_prev_addr_needs_a_rotation",
    cc_rotate_prev_addr(ann_pkt, al, prev) == CC_E_FORMAT);

  /* Both signatures valid, against the key the peer holds for prev_addr. */
  T("rotate_parse",
    cc_rotate_parse(&g_w, rot, rl, a_old_sign, &after, prev) == CC_OK);
  T("rotate_parse_new_keys",
    memcmp(after.sign_pubkey, a_new_sign, CC_SIGN_PUBKEY_SZ) == 0 &&
        memcmp(after.kem_pubkey, a_new_kem, CC_KEM_PUBKEY_SZ) == 0);
  T("rotate_parse_new_address",
    cc_addr_from_sign_pubkey(a_new_sign, prev) == CC_OK &&
        memcmp(after.addr, prev, CC_ADDR_SZ) == 0 &&
        memcmp(after.addr, a_old_addr, CC_ADDR_SZ) != 0);
  T("rotate_parse_statement", after.name_len == 5 &&
                                  memcmp(after.name, "Alice", 5) == 0 &&
                                  after.meta_len == sizeof(meta) &&
                                  after.seq == 8 && after.expiry == 900);
  T("rotate_parse_prev_addr",
    memcmp(after.prev_addr, a_old_addr, CC_ADDR_SZ) == 0);

  /* The acceptance rule: strictly newer, in the identity's own sequence
     space, so a replay is idempotent and an older one cannot downgrade. */
  T("rotate_accept", cc_rotate_accept(&before, &after, NULL, 0) == CC_OK);
  T("rotate_accept_expired",
    cc_rotate_accept(&before, &after, NULL, 900) == CC_E_STALE);
  T("rotate_accept_replay_is_idempotent",
    cc_rotate_accept(&after, &after, NULL, 0) == CC_E_STALE);
  T("rotate_older_build",
    cc_rotate_build(&g_w, &alice_third, &alice_old, "Alice", 5, meta,
                    sizeof(meta), 6, 900, older, sizeof(older), &ol,
                    rng) == CC_OK);
  T("rotate_older_parses",
    cc_rotate_parse(&g_w, older, ol, a_old_sign, &older_ann, prev) == CC_OK);
  T("rotate_accept_older_refused",
    cc_rotate_accept(&after, &older_ann, NULL, 0) == CC_E_STALE);
  /* The same sequence number, chained from the identity we already moved to:
     the predecessor matches, so the seq rule is what refuses it. This is the
     replay case — the rule is "strictly newer", not "not older". */
  {
    static uint8_t same[CC_ROTATE_BUF_SZ];
    static cc_announce_t same_ann;
    size_t sl = 0;
    uint8_t p2[CC_ADDR_SZ];
    T("rotate_same_seq_build",
      cc_rotate_build(&g_w, &alice_third, &alice_new, "Alice", 5, meta,
                      sizeof(meta), 8, 900, same, sizeof(same), &sl,
                      rng) == CC_OK);
    T("rotate_same_seq_parses",
      cc_rotate_parse(&g_w, same, sl, a_new_sign, &same_ann, p2) == CC_OK &&
          memcmp(p2, after.addr, CC_ADDR_SZ) == 0);
    T("rotate_accept_same_seq_refused",
      cc_rotate_accept(&after, &same_ann, NULL, 0) == CC_E_STALE);
  }

  /* Rejected: no continuity signature at all. */
  el = t_swap_bstr(rot, rl, 12, NULL, 0);
  T("rotate_continuity_missing_refused",
    el > 0 && cc_rotate_parse(&g_w, t_swap_buf, el, a_old_sign, &tmp, prev) ==
                  CC_E_FORMAT);

  /* Rejected: the caller's key for prev_addr is not prev_addr's key. */
  T("rotate_wrong_old_key",
    cc_rotate_parse(&g_w, rot, rl, m_old_sign, &tmp, prev) == CC_E_NOKEY);

  /* Rejected: tampered bytes, with the PoW re-mined, since the PoW covers
     them. The continuity signature, the new key's signature, and a covered
     field all have to hold. */
  memcpy(t_swap_buf, rot, rl);
  el = rl;
  t_swap_buf[t_body(t_swap_buf, el, 12) + 7] ^= 0xFF;
  T("rotate_tampered_continuity_remined", t_remine(t_swap_buf, &el, 3) == 0);
  T("rotate_tampered_continuity_refused",
    cc_rotate_parse(&g_w, t_swap_buf, el, a_old_sign, &tmp, prev) == CC_E_SIG);
  memcpy(t_swap_buf, rot, rl);
  el = rl;
  t_swap_buf[t_body(t_swap_buf, el, 11) + 7] ^= 0xFF;
  T("rotate_tampered_new_sig_remined", t_remine(t_swap_buf, &el, 3) == 0);
  T("rotate_tampered_new_sig_refused",
    cc_rotate_parse(&g_w, t_swap_buf, el, a_old_sign, &tmp, prev) == CC_E_SIG);
  memcpy(t_swap_buf, rot, rl);
  el = rl;
  t_swap_buf[t_body(t_swap_buf, el, 6)] = 'B';
  T("rotate_tampered_name_remined", t_remine(t_swap_buf, &el, 3) == 0);
  T("rotate_tampered_name_refused",
    cc_rotate_parse(&g_w, t_swap_buf, el, a_old_sign, &tmp, prev) == CC_E_SIG);

  /* Rejected: the new key does not hash to the address the old key vouched
     for, even with the envelope re-signed by that key. */
  el = t_doctor_rotation(rot, rl, 4, m_new_sign, CC_SIGN_PUBKEY_SZ,
                         &mallory_new, rng);
  T("rotate_substituted_key_built", el > 0);
  T("rotate_substituted_key_refused",
    cc_rotate_parse(&g_w, t_swap_buf, el, a_old_sign, &tmp, prev) == CC_E_SIG);

  /* Rejected: the KEM key is part of the continuity statement too, so
     swapping it while keeping the old key's proof fails even with the
     envelope re-signed by the (now honest) new key. */
  el = t_doctor_rotation(rot, rl, 5, m_new_kem, CC_KEM_PUBKEY_SZ, &alice_new,
                         rng);
  T("rotate_substituted_kem_built", el > 0);
  T("rotate_substituted_kem_refused",
    cc_rotate_parse(&g_w, t_swap_buf, el, a_old_sign, &tmp, prev) == CC_E_SIG);

  /* Rejected in the other direction: a third party cannot claim someone
     else's address as its predecessor. */
  T("rotate_mallory_build",
    cc_rotate_build(&g_w, &mallory_new, &mallory_old, "M", 1, NULL, 0, 5, 900,
                    m_rot, sizeof(m_rot), &ml, rng) == CC_OK);
  T("rotate_mallory_predecessor_is_hers",
    cc_rotate_prev_addr(m_rot, ml, m_prev) == CC_OK &&
        memcmp(m_prev, a_old_addr, CC_ADDR_SZ) != 0);
  el = t_doctor_rotation(m_rot, ml, 8, a_old_addr, CC_ADDR_SZ, &mallory_new,
                         rng);
  T("rotate_claimed_address_built", el > 0);
  T("rotate_claimed_address_refused",
    cc_rotate_parse(&g_w, t_swap_buf, el, a_old_sign, &tmp, prev) == CC_E_SIG);

  /* The state transfer a caller does when it accepts a rotation: the replay
     window moves to the new address carrying its high-water, so the node's
     last message cannot be replayed into the new identity. */
  T("move_window_init",
    cc_replay_init(&rp, a_old_addr, CC_REPLAY_AUTHED) == CC_OK);
  T("move_chat_from_old_identity",
    cc_chat_build(&g_w, &alice_old, b_addr, b_kem, 20, (const uint8_t*)"hi", 2,
                  0, chat, sizeof(chat), &cl, rng) == CC_OK &&
        cc_chat_parse(&g_w, &bob, a_old_sign, &rp, chat, cl, &c) == CC_OK);
  T("move_window_transfer",
    cc_replay_move(&rp, after.addr, 20, CC_REPLAY_CONTINUES) == CC_OK);
  T("move_chat_from_new_identity",
    cc_chat_build(&g_w, &alice_new, b_addr, b_kem, 20, (const uint8_t*)"hi", 2,
                  0, chat2, sizeof(chat2), &c2, rng) == CC_OK);
  T("move_last_counter_cannot_replay",
    cc_chat_parse(&g_w, &bob, a_new_sign, &rp, chat2, c2, &c) == CC_E_REPLAY);
  T("move_high_water_again",
    cc_replay_move(&rp, after.addr, 100, CC_REPLAY_CONTINUES) == CC_OK);
  T("move_chat_well_below_the_water",
    cc_chat_build(&g_w, &alice_new, b_addr, b_kem, 30, (const uint8_t*)"hi", 2,
                  0, chat3, sizeof(chat3), &c3, rng) == CC_OK &&
        cc_chat_parse(&g_w, &bob, a_new_sign, &rp, chat3, c3, &c) ==
            CC_E_STALE);
  T("move_fresh_window_is_untouched",
    cc_replay_init(&rp2, a_old_addr, CC_REPLAY_AUTHED) == CC_OK &&
        cc_replay_move(&rp2, after.addr, 0, CC_REPLAY_CONTINUES) == CC_OK &&
        cc_chat_parse(&g_w, &bob, a_new_sign, &rp2, chat3, c3, &c) == CC_OK);

  /* Composition: a rotation must not launder a retired key into a trusted
     successor. The rule is in cc_rotate_accept, not in prose. */
  {
    static cc_revoked_t rv;
    T("compose_accept_with_an_empty_record",
      cc_revoked_init(&rv) == CC_OK &&
          cc_rotate_accept(&before, &after, &rv, 0) == CC_OK);
    T("compose_accept_without_a_record",
      cc_rotate_accept(&before, &after, NULL, 0) == CC_OK); /* weaker config */
    T("compose_retire_the_predecessor",
      cc_revoked_take(&rv, a_old_addr, 7, 0) == CC_OK &&
          cc_revoked_check(&rv, a_old_addr, 0) == CC_E_REVOKED);
    T("compose_rotation_from_retired_refused",
      cc_rotate_accept(&before, &after, &rv, 0) == CC_E_REVOKED);
    T("compose_refusal_is_countable",
      cc_rotate_accept(&before, &after, &rv, 0) != CC_E_STALE);
    /* The horizon is the documented cost of a bounded record. */
    T("compose_after_the_horizon",
      cc_revoked_take(&rv, a_old_addr, 7, 500) == CC_OK &&
          cc_rotate_accept(&before, &after, &rv, 501) == CC_OK);
    /* Late revocation (the caller got the order wrong): the successor was
       accepted, and prev_addr is what lets the caller find and drop it. */
    T("compose_late_revocation_finds_the_successor",
      cc_revoked_init(&rv) == CC_OK &&
          cc_rotate_accept(&before, &after, &rv, 0) == CC_OK &&
          cc_revoked_take(&rv, a_old_addr, 7, 0) == CC_OK &&
          cc_revoked_check(&rv, after.prev_addr, 0) == CC_E_REVOKED &&
          cc_revoked_check(&rv, after.addr, 0) == CC_OK);
  }

  /* Counter space across a move: the caller has to say which one it is. */
  {
    static uint8_t c1[CC_CHAT_BUF_SZ];
    cc_replay_t rs;
    size_t c1l = 0;
    T("move_needs_an_explicit_choice",
      cc_replay_init(&rs, a_old_addr, CC_REPLAY_AUTHED) == CC_OK &&
          cc_replay_move(&rs, after.addr, 0, 7) == CC_E_ARG);
    T("move_chat_from_the_restarted_successor",
      cc_chat_build(&g_w, &alice_new, b_addr, b_kem, 1, (const uint8_t*)"hi", 2,
                    0, c1, sizeof(c1), &c1l, rng) == CC_OK);
    /* A successor that kept counting is held to the old high-water... */
    T("move_continues_holds_the_water",
      cc_replay_init(&rs, a_old_addr, CC_REPLAY_AUTHED) == CC_OK &&
          /* the floor only means something once the old identity was heard
             from: a window that has seen nothing carries nothing */
          cc_chat_parse(&g_w, &bob, a_old_sign, &rs, chat, cl, &c) == CC_OK &&
          cc_replay_move(&rs, after.addr, 100, CC_REPLAY_CONTINUES) == CC_OK &&
          cc_chat_parse(&g_w, &bob, a_new_sign, &rs, c1, c1l, &c) ==
              CC_E_STALE);
    /* ...and one that restarted is accepted, which is the one-replay cost the
       caller took on deliberately. */
    T("move_restarts_accepts_the_first_counter",
      cc_replay_move(&rs, after.addr, 0, CC_REPLAY_RESTARTS) == CC_OK &&
          cc_chat_parse(&g_w, &bob, a_new_sign, &rs, c1, c1l, &c) == CC_OK);
    /* The old address's traffic now fails on the address, not the window. */
    T("move_old_address_is_a_mismatch",
      cc_chat_parse(&g_w, &bob, a_old_sign, &rs, chat, cl, &c) == CC_E_ARG);
  }
}

/* ---- receiver-published PoW cost (revision 9) ---- */

/* A packet that is PROVABLY below `bar`, built through the documented
   difficulty parameter (kind 0 = chat, 1 = key_req, 2 = link_req).
 *
 * Mining stops at the first nonce that clears the difficulty it was asked for,
 * so the next digest byte is a fresh draw: about one packet in 256 mined at d
 * also happens to clear d+1. A check that asserts "this packet is refused at
 * bar" must therefore not be written against a single build of the default
 * path — that is flaky by construction (it was: one run in ~23 of the
 * difficulty-2 suite). This searches for a packet the bar really refuses and
 * asserts the property it found, so the assertion below it cannot fail by
 * luck. Not finding one in 16 tries has probability 256^-16. */
static size_t t_mine_below(cc_work_t* w, int kind, const cc_key_t* key,
                           const uint8_t addr[CC_ADDR_SZ],
                           const uint8_t kem[CC_KEM_PUBKEY_SZ],
                           uint32_t counter, uint8_t mine_at, uint8_t bar,
                           uint8_t* out, size_t out_sz, WC_RNG* rng) {
  size_t len = 0;
  int i;
  for (i = 0; i < 16; i++) {
    if (kind == 0) {
      if (cc_chat_build(w, key, addr, kem, counter + (uint32_t)i,
                        (const uint8_t*)"hi", 2, mine_at, out, out_sz, &len,
                        rng) != CC_OK)
        return 0;
    } else if (kind == 1) {
      if (cc_key_req_build(w, addr, counter + (uint32_t)i, mine_at, out, out_sz,
                           &len) != CC_OK)
        return 0;
    } else {
      cc_link_t l;
      if (cc_link_start(w, &l, addr, kem, 0, 1000, mine_at, out, out_sz, &len,
                        rng) != CC_OK)
        return 0;
    }
    if (cc_pow_verify_at(out, len, mine_at) == CC_OK &&
        cc_pow_verify_at(out, len, bar) == CC_E_POW)
      return len;
  }
  return 0;
}

static void test_admit(WC_RNG* rng) {
  static cc_key_t alice, bob;
  static uint8_t a_sign[CC_SIGN_PUBKEY_SZ], a_kem[CC_KEM_PUBKEY_SZ];
  static uint8_t b_sign[CC_SIGN_PUBKEY_SZ], b_kem[CC_KEM_PUBKEY_SZ];
  static uint8_t pkt[CC_ANN_BUF_SZ], chat[CC_CHAT_BUF_SZ];
  static uint8_t req[CC_KEY_REQ_BUF_SZ];
  static uint8_t lreq[CC_LINK_REQ_BUF_SZ];
  static cc_announce_t ann, hand;
  static const uint8_t meta[] = {0xA1, 0x61, 0x61, 0x01};
  static const uint8_t declare[CC_ADMIT_SZ] = {3, 4, 5};
  static const uint8_t high[CC_ADMIT_SZ] = {CC_POW_DIFFICULTY_CHAT + 2,
                                            CC_POW_DIFFICULTY_LINK_REQ + 2,
                                            CC_POW_DIFFICULTY_KEY_REQ + 2};
  static const uint8_t low[CC_ADMIT_SZ] = {1, 1, 1};
  static const uint8_t none[CC_ADMIT_SZ] = {CC_POW_NONE, CC_POW_NONE,
                                            CC_POW_NONE};
  static const uint8_t too_big[CC_ADMIT_SZ] = {CC_POW_MAX + 1, 0, 0};
  uint8_t b_addr[CC_ADDR_SZ], a_addr[CC_ADDR_SZ], addr_out[CC_ADDR_SZ];
  uint8_t price[CC_ADMIT_SZ], d = 0, kind = 0;
  size_t al = 0, cl = 0, rl = 0, ll = 0, el;
  cc_chat_t c;
  cc_replay_t rp;
  cc_link_t lr;
  uint32_t counter = 0;
  printf("admit (receiver-published PoW cost):\n");

  /* The declaration is a fixed three bytes; anything above the digest width is
     nonsense and is refused on both sides. */
  _Static_assert(CC_POW_DIFFICULTY_CHAT + 2 <= CC_POW_MAX,
                 "the test's declared price must stay inside the digest");

  cc_key_generate(&alice, rng);
  cc_key_generate(&bob, rng);
  cc_key_export_public(&alice, a_sign, a_kem);
  cc_key_export_public(&bob, b_sign, b_kem);
  cc_addr_from_key(&bob, b_addr);
  cc_addr_from_key(&alice, a_addr);

  /* Round trip, inside the signed coverage. */
  T("admit_roundtrip",
    cc_announce_build(&g_w, &bob, "Bob", 3, meta, sizeof(meta), declare, 1, 0,
                      pkt, sizeof(pkt), &al, rng) == CC_OK &&
        cc_announce_parse(&g_w, pkt, al, &ann) == CC_OK &&
        memcmp(ann.admit, declare, CC_ADMIT_SZ) == 0 && ann.verified == 1);
  T("admit_type_is_still_announce",
    cc_msg_type(pkt, al, &kind) == CC_OK && kind == CC_MSG_ANNOUNCE);
  T("admit_null_declares_the_build_policy",
    cc_announce_build(&g_w, &bob, "Bob", 3, meta, sizeof(meta), NULL, 2, 0, pkt,
                      sizeof(pkt), &al, rng) == CC_OK &&
        cc_announce_parse(&g_w, pkt, al, &ann) == CC_OK &&
        ann.admit[CC_ADMIT_CHAT] == CC_POW_DIFFICULTY_CHAT &&
        ann.admit[CC_ADMIT_LINK_REQ] == CC_POW_DIFFICULTY_LINK_REQ &&
        ann.admit[CC_ADMIT_KEY_REQ] == CC_POW_DIFFICULTY_KEY_REQ);

  /* Inside the coverage: changing the declaration after signing breaks the
     signature, PoW re-mined. */
  el = t_swap_bstr(pkt, al, EL_ANN_ADMIT, high, CC_ADMIT_SZ);
  T("admit_tamper_built",
    el > 0 && t_remine(t_swap_buf, &el, EL_ANN_NONCE) == 0);
  T("admit_tamper_refused",
    cc_announce_parse(&g_w, t_swap_buf, el, &ann) == CC_E_SIG);

  /* A signed but impossible price (above the digest width) is refused before
     any signature work, like a malformed metadata map. */
  T("admit_above_the_digest_refused_at_build",
    cc_announce_build(&g_w, &bob, "Bob", 3, meta, sizeof(meta), too_big, 3, 0,
                      pkt, sizeof(pkt), &al, rng) == CC_E_ARG);
  el = t_swap_bstr(pkt, al, EL_ANN_ADMIT, too_big, CC_ADMIT_SZ);
  T("admit_above_the_digest_built",
    el > 0 && t_remine(t_swap_buf, &el, EL_ANN_NONCE) == 0);
  T("admit_above_the_digest_refused_at_parse",
    cc_announce_parse(&g_w, t_swap_buf, el, &ann) == CC_E_FORMAT);

  /* The helper's rule: max(peer declared, this build's own requirement). */
  T("admit_default_is_the_build_policy",
    (cc_admit_default(price),
     price[CC_ADMIT_CHAT] == CC_POW_DIFFICULTY_CHAT &&
         price[CC_ADMIT_LINK_REQ] == CC_POW_DIFFICULTY_LINK_REQ &&
         price[CC_ADMIT_KEY_REQ] == CC_POW_DIFFICULTY_KEY_REQ));
  T("admit_for_no_peer_is_own_policy",
    cc_admit_for(NULL, CC_MSG_CHAT, &d) == CC_OK &&
        d == CC_POW_DIFFICULTY_CHAT);
  T("admit_for_peer_asks_more",
    cc_announce_build(&g_w, &bob, "Bob", 3, meta, sizeof(meta), high, 4, 0, pkt,
                      sizeof(pkt), &al, rng) == CC_OK &&
        cc_announce_parse(&g_w, pkt, al, &ann) == CC_OK &&
        cc_admit_for(&ann, CC_MSG_CHAT, &d) == CC_OK &&
        d == (uint8_t)(CC_POW_DIFFICULTY_CHAT + 2) &&
        cc_admit_for(&ann, CC_MSG_LINK_REQ, &d) == CC_OK &&
        d == (uint8_t)(CC_POW_DIFFICULTY_LINK_REQ + 2) &&
        cc_admit_for(&ann, CC_MSG_KEY_REQ, &d) == CC_OK &&
        d == (uint8_t)(CC_POW_DIFFICULTY_KEY_REQ + 2));
  T("admit_for_peer_asks_less",
    cc_announce_build(&g_w, &bob, "Bob", 3, meta, sizeof(meta), low, 5, 0, pkt,
                      sizeof(pkt), &al, rng) == CC_OK &&
        cc_announce_parse(&g_w, pkt, al, &ann) == CC_OK &&
        cc_admit_for(&ann, CC_MSG_CHAT, &d) == CC_OK &&
        d == CC_POW_DIFFICULTY_CHAT);
  T("admit_for_peer_declares_none",
    cc_announce_build(&g_w, &bob, "Bob", 3, meta, sizeof(meta), none, 6, 0, pkt,
                      sizeof(pkt), &al, rng) == CC_OK &&
        cc_announce_parse(&g_w, pkt, al, &ann) == CC_OK &&
        cc_admit_for(&ann, CC_MSG_CHAT, &d) == CC_OK &&
        d == CC_POW_DIFFICULTY_CHAT);
  T("admit_for_broadcast_types_refused",
    cc_admit_for(&ann, CC_MSG_ANNOUNCE, &d) == CC_E_ARG &&
        cc_admit_for(&ann, CC_MSG_PRESENCE, &d) == CC_E_ARG &&
        cc_admit_for(&ann, CC_MSG_LINK_DATA, &d) == CC_E_ARG &&
        cc_admit_for(&ann, CC_MSG_ROTATE, &d) == CC_E_ARG &&
        cc_admit_for(&ann, CC_MSG_REVOKE, &d) == CC_E_ARG);
  T("admit_for_bad_args", cc_admit_for(&ann, CC_MSG_CHAT, NULL) == CC_E_ARG);
  /* The declaration is only usable once the signature verified: a struct that
     no parser filled in must not be able to drive anyone's mining. */
  memset(&hand, 0, sizeof(hand));
  memcpy(hand.admit, high, CC_ADMIT_SZ);
  T("admit_for_unverified_refused",
    cc_admit_for(&hand, CC_MSG_CHAT, &d) == CC_E_SIG);

  /* Sending: 0 keeps this build's own policy (the compatibility path), and a
     peer's price is what cc_admit_for() hands the builder. */
  T("directed_default_path",
    cc_announce_build(&g_w, &bob, "Bob", 3, meta, sizeof(meta), NULL, 7, 0, pkt,
                      sizeof(pkt), &al, rng) == CC_OK &&
        cc_announce_parse(&g_w, pkt, al, &ann) == CC_OK &&
        cc_chat_build(&g_w, &alice, b_addr, b_kem, 1, (const uint8_t*)"hi", 2,
                      0, chat, sizeof(chat), &cl, rng) == CC_OK &&
        cc_replay_init(&rp, a_addr, CC_REPLAY_AUTHED) == CC_OK &&
        cc_chat_parse(&g_w, &bob, a_sign, &rp, chat, cl, &c) == CC_OK);
  T("pay_the_peers_price",
    cc_announce_build(&g_w, &bob, "Bob", 3, meta, sizeof(meta), none, 8, 0, pkt,
                      sizeof(pkt), &al, rng) == CC_OK &&
        cc_announce_parse(&g_w, pkt, al, &ann) == CC_OK &&
        cc_admit_for(&ann, CC_MSG_CHAT, &d) == CC_OK &&
        cc_chat_build(&g_w, &alice, b_addr, b_kem, 2, (const uint8_t*)"hi", 2,
                      d, chat, sizeof(chat), &cl, rng) == CC_OK &&
        cc_chat_parse(&g_w, &bob, a_sign, &rp, chat, cl, &c) == CC_OK);
  /* key_req and link_req take the same parameter. */
  T("key_req_at_the_declared_price",
    cc_key_req_build(&g_w, b_addr, 9, CC_POW_DIFFICULTY_KEY_REQ, req,
                     sizeof(req), &rl) == CC_OK &&
        cc_key_req_parse(&g_w, req, rl, addr_out, &counter) == CC_OK &&
        memcmp(addr_out, b_addr, CC_ADDR_SZ) == 0);
  T("link_req_at_the_declared_price",
    cc_link_start(&g_w, &lr, b_addr, b_kem, 0, 1000, CC_POW_DIFFICULTY_LINK_REQ,
                  lreq, sizeof(lreq), &ll, rng) == CC_OK &&
        cc_pow_verify(lreq, ll) == CC_OK);
  T("link_req_difficulty_above_the_digest_refused",
    cc_link_start(&g_w, &lr, b_addr, b_kem, 0, 1000, CC_POW_MAX + 1, lreq,
                  sizeof(lreq), &ll, rng) == CC_E_ARG &&
        cc_key_req_build(&g_w, b_addr, 9, CC_POW_MAX + 1, req, sizeof(req),
                         &rl) == CC_E_ARG);

#if CC_POW_DIFFICULTY_CHAT > 1
  /* A sender that pays less than this receiver's own bar is refused, whatever
     anyone declared: a chat mined at 1 against a build that requires 2. The
     packet is found by search, so the refusal is a property of the packet and
     not of a lucky digest byte. */
  cl = t_mine_below(&g_w, 0, &alice, b_addr, b_kem, 3, 1,
                    CC_POW_DIFFICULTY_CHAT, chat, sizeof(chat), rng); /* its
                    own type's bar, and the guard above is that same macro */
  T("below_the_receivers_bar_mined",
    cl > 0 && cc_pow_verify(chat, cl) == CC_E_POW);
  T("below_the_receivers_bar_refused",
    cc_chat_parse(&g_w, &bob, a_sign, &rp, chat, cl, &c) == CC_E_POW);
#else
  printf(
      "  (build requires difficulty 1: the below-the-bar case needs a "
      "stricter receiver)\n");
#endif
}

/* ---- identity lifecycle: revocation ---- */

static void test_revocation(WC_RNG* rng) {
  static cc_key_t peer, other;
  static uint8_t rev[CC_REVOKE_BUF_SZ];
  static uint8_t ps[CC_SIGN_PUBKEY_SZ], pk[CC_KEM_PUBKEY_SZ];
  static uint8_t os[CC_SIGN_PUBKEY_SZ], ok2[CC_KEM_PUBKEY_SZ];
  static uint8_t ann_pkt[CC_ANN_BUF_SZ], link_pkt[CC_LINK_REQ_BUF_SZ];
  static cc_revoked_t rv, free_rv;
  static const uint8_t meta[] = {0xA1, 0x61, 0x61, 0x01};
  uint8_t got[CC_ADDR_SZ], peer_addr[CC_ADDR_SZ], other_addr[CC_ADDR_SZ];
  uint32_t seq = 0, expiry = 0;
  cc_link_t li;
  size_t rl = 0, el, al = 0, ll = 0;
  uint8_t kind = 0;
  printf("revocation:\n");

  cc_key_generate(&peer, rng);
  cc_key_generate(&other, rng);
  cc_key_export_public(&peer, ps, pk);
  cc_key_export_public(&other, os, ok2);
  cc_addr_from_key(&peer, peer_addr);
  cc_addr_from_key(&other, other_addr);

  T("revoke_build",
    cc_revoke_build(&g_w, &peer, 9, 500, rev, sizeof(rev), &rl, rng) == CC_OK);
  T("revoke_fits", rl > 0 && rl <= CC_REVOKE_BUF_SZ);
  T("revoke_type",
    cc_msg_type(rev, rl, &kind) == CC_OK && kind == CC_MSG_REVOKE);
  T("revoke_pow", cc_pow_verify(rev, rl) == CC_OK);
  T("revoke_parse",
    cc_revoke_parse(&g_w, rev, rl, ps, got, &seq, &expiry) == CC_OK &&
        memcmp(got, peer_addr, CC_ADDR_SZ) == 0 && seq == 9 && expiry == 500);
  /* Only the identity can retire itself: another peer's key does not match the
     address in the packet. */
  T("revoke_other_key_refused",
    cc_revoke_parse(&g_w, rev, rl, os, got, &seq, &expiry) == CC_E_NOKEY);
  /* Tampered: rewrite the address it retires, re-mined. */
  el = t_swap_bstr(rev, rl, 4, other_addr, CC_ADDR_SZ);
  T("revoke_addr_swap_remined", el > 0 && t_remine(t_swap_buf, &el, 3) == 0);
  T("revoke_addr_swap_refused", cc_revoke_parse(&g_w, t_swap_buf, el, ps, got,
                                                &seq, &expiry) == CC_E_NOKEY);
  /* Tampered: a byte of the signature, re-mined. */
  memcpy(t_swap_buf, rev, rl);
  el = rl;
  t_swap_buf[t_body(t_swap_buf, el, 7) + 5] ^= 0xFF;
  T("revoke_tampered_sig_remined", t_remine(t_swap_buf, &el, 3) == 0);
  T("revoke_tampered_sig_refused",
    cc_revoke_parse(&g_w, t_swap_buf, el, ps, got, &seq, &expiry) == CC_E_SIG);

  /* The caller-side record: one rule, and it is the whole policy surface. */
  T("revoke_record_init", cc_revoked_init(&rv) == CC_OK);
  T("revoke_record_free_before", cc_revoked_check(&rv, peer_addr, 0) == CC_OK);
  T("revoke_record_take", cc_revoked_take(&rv, peer_addr, 9, 500) == CC_OK);
  T("revoke_record_retired",
    cc_revoked_check(&rv, peer_addr, 10) == CC_E_REVOKED);
  T("revoke_record_other_peer_free",
    cc_revoked_check(&rv, other_addr, 10) == CC_OK);
  T("revoke_record_horizon_passed",
    cc_revoked_check(&rv, peer_addr, 501) == CC_OK);
  T("revoke_record_expiry_zero_is_forever",
    cc_revoked_take(&rv, peer_addr, 9, 0) == CC_OK &&
        cc_revoked_check(&rv, peer_addr, 1000000) == CC_E_REVOKED);
  T("revoke_record_forget", cc_revoked_forget(&rv) == CC_OK &&
                                cc_revoked_check(&rv, peer_addr, 10) == CC_OK);

  /* A revoked identity cannot be resurrected by replaying its announce, and a
     rotation from it is not accepted either: both gates are the same line. */
  T("revoke_announce_build",
    cc_announce_build(&g_w, &peer, "Peer", 4, meta, sizeof(meta), NULL, 9, 500,
                      ann_pkt, sizeof(ann_pkt), &al, rng) == CC_OK);
  T("revoke_record_take_again",
    cc_revoked_take(&rv, peer_addr, 9, 500) == CC_OK);
  T("revoke_announce_replay_refused",
    t_accept_announce(&rv, &g_w, ann_pkt, al, 10) == 0);
  T("revoke_record_clear", cc_revoked_init(&free_rv) == CC_OK);
  T("revoke_announce_accepted_when_free",
    t_accept_announce(&free_rv, &g_w, ann_pkt, al, 10) == 1);
  T("revoke_rotation_from_retired_refused",
    t_trust(&rv, peer_addr, 10) == 0 && t_trust(&free_rv, peer_addr, 10) == 1);
  /* Traffic and new links are gated by the same predicate. */
  T("revoke_traffic_gate", !t_trust(&rv, peer_addr, 10));
  T("revoke_link_gate",
    !t_trust(&rv, peer_addr, 10) && t_trust(&free_rv, peer_addr, 10) &&
        cc_link_start(&g_w, &li, peer_addr, pk, 0, 1000, 0, link_pkt,
                      sizeof(link_pkt), &ll, rng) == CC_OK);
}

/* ---- key storage: the seed form (FIPS 204 / FIPS 203) ---- */

static void test_key_seeds(WC_RNG* rng) {
  static cc_key_t a, b, c, imp;
  static uint8_t sign_seed[CC_SIGN_SEED_SZ], kem_seed[CC_KEM_SEED_SZ];
  static uint8_t sign_seed2[CC_SIGN_SEED_SZ], kem_seed2[CC_KEM_SEED_SZ];
  static uint8_t sign_seed3[CC_SIGN_SEED_SZ], kem_seed3[CC_KEM_SEED_SZ];
  static uint8_t p1[CC_SIGN_PUBKEY_SZ], p1k[CC_KEM_PUBKEY_SZ];
  static uint8_t a_sign[CC_SIGN_PUBKEY_SZ], a_kem[CC_KEM_PUBKEY_SZ];
  static uint8_t c_sign[CC_SIGN_PUBKEY_SZ], c_kem[CC_KEM_PUBKEY_SZ];
  static uint8_t imp_sign[CC_SIGN_PUBKEY_SZ], imp_kem[CC_KEM_PUBKEY_SZ];
  static uint8_t priv_s[CC_SIGN_PRIVKEY_SZ], priv_k[CC_KEM_PRIVKEY_SZ];
  static uint8_t chat[CC_CHAT_BUF_SZ];
  uint8_t a_addr[CC_ADDR_SZ], b_addr[CC_ADDR_SZ], c_addr[CC_ADDR_SZ];
  size_t cl = 0;
  cc_replay_t rp;
  cc_chat_t got;
  int i, zero;
  printf("key seeds:\n");

  T("seed_sizes", CC_SIGN_SEED_SZ == 64 && CC_KEM_SEED_SZ == 64);
  T("seed_generate", cc_key_generate(&a, rng) == CC_OK);
  T("seed_generate_exportable",
    cc_key_export_seed(&a, sign_seed, kem_seed) == CC_OK);
  T("seed_import", cc_key_import_seed(&b, sign_seed, kem_seed) == CC_OK);
  T("seed_import_same_address", cc_addr_from_key(&a, a_addr) == CC_OK &&
                                    cc_addr_from_key(&b, b_addr) == CC_OK &&
                                    memcmp(a_addr, b_addr, CC_ADDR_SZ) == 0);
  T("seed_import_same_public_keys",
    cc_key_export_public(&a, a_sign, a_kem) == CC_OK &&
        cc_key_export_public(&b, imp_sign, imp_kem) == CC_OK &&
        memcmp(a_sign, imp_sign, CC_SIGN_PUBKEY_SZ) == 0 &&
        memcmp(a_kem, imp_kem, CC_KEM_PUBKEY_SZ) == 0);

  /* Two keys from one seed interoperate: a chat encapsulated to the identity's
     public key is decrypted by the other copy of the same identity. */
  cc_key_generate(&c, rng);
  cc_key_export_public(&c, c_sign, c_kem);
  cc_addr_from_key(&c, c_addr);
  T("seed_interop_chat_built",
    cc_chat_build(&g_w, &c, a_addr, a_kem, 1, (const uint8_t*)"seeded", 6, 0,
                  chat, sizeof(chat), &cl, rng) == CC_OK);
  T("seed_interop_chat_parsed",
    cc_replay_init(&rp, c_addr, CC_REPLAY_AUTHED) == CC_OK &&
        cc_chat_parse(&g_w, &b, c_sign, &rp, chat, cl, &got) == CC_OK &&
        got.msg_len == 6 && memcmp(got.msg, "seeded", 6) == 0 &&
        memcmp(got.sender_addr, c_addr, CC_ADDR_SZ) == 0);

  /* import -> export -> import is stable. */
  T("seed_re_export", cc_key_export_seed(&b, sign_seed2, kem_seed2) == CC_OK &&
                          memcmp(sign_seed, sign_seed2, CC_SIGN_SEED_SZ) == 0 &&
                          memcmp(kem_seed, kem_seed2, CC_KEM_SEED_SZ) == 0);
  T("seed_re_import",
    cc_key_import_seed(&imp, sign_seed2, kem_seed2) == CC_OK &&
        cc_addr_from_key(&imp, b_addr) == CC_OK &&
        memcmp(b_addr, a_addr, CC_ADDR_SZ) == 0);

  /* The expanded form has no knowable seed, and says so. The failure must not
     write a partial or invented seed into the caller's buffers either. */
  memset(sign_seed2, 0xA5, sizeof(sign_seed2));
  memset(kem_seed2, 0xA5, sizeof(kem_seed2));
  T("seed_expanded_export",
    cc_key_export_private(&a, priv_s, priv_k) == CC_OK &&
        cc_key_import(&imp, priv_s, a_sign, priv_k) == CC_OK &&
        cc_key_export_seed(&imp, sign_seed2, kem_seed2) == CC_E_NOKEY);
  zero = 1;
  for (i = 0; i < CC_SIGN_SEED_SZ; i++) {
    if (sign_seed2[i] != 0xA5)
      zero = 0;
  }
  T("seed_expanded_export_no_partial_write", zero);
  T("seed_expanded_import_still_works",
    cc_key_export_public(&imp, imp_sign, imp_kem) == CC_OK &&
        memcmp(imp_sign, a_sign, CC_SIGN_PUBKEY_SZ) == 0);

  /* Arguments. */
  T("seed_export_bad_args",
    cc_key_export_seed(NULL, sign_seed, kem_seed) == CC_E_ARG &&
        cc_key_export_seed(&a, NULL, kem_seed) == CC_E_ARG &&
        cc_key_export_seed(&a, sign_seed, NULL) == CC_E_ARG);
  T("seed_import_bad_args",
    cc_key_import_seed(NULL, sign_seed, kem_seed) == CC_E_ARG &&
        cc_key_import_seed(&imp, NULL, kem_seed) == CC_E_ARG &&
        cc_key_import_seed(&imp, sign_seed, NULL) == CC_E_ARG);

  /* cc_key_free wipes the seeds it holds (the library's own contract), and the
     caller's staging buffers are the caller's to wipe. */
  cc_key_import_seed(&imp, sign_seed, kem_seed);
  cc_key_free(&imp);
  zero = 1;
  for (i = 0; i < CC_SIGN_SEED_SZ; i++) {
    if (imp.sign_seed[i] != 0)
      zero = 0;
  }
  T("seed_free_wipes", imp.has_seed == 0 && zero);
  /* Invariant: a successful generate exports seeds that reproduce the key it
     just made, and generating twice on one object replaces the identity rather
     than leaving a mix of the two. */
  T("seed_generate_twice_replaces_identity",
    cc_key_generate(&imp, rng) == CC_OK &&
        cc_key_export_seed(&imp, sign_seed2, kem_seed2) == CC_OK &&
        cc_key_generate(&imp, rng) == CC_OK &&
        cc_key_export_seed(&imp, sign_seed3, kem_seed3) == CC_OK &&
        memcmp(sign_seed2, sign_seed3, CC_SIGN_SEED_SZ) != 0 &&
        cc_key_import_seed(&a, sign_seed3, kem_seed3) == CC_OK &&
        cc_key_export_public(&a, imp_sign, imp_kem) == CC_OK &&
        cc_key_export_public(&imp, p1, p1k) == CC_OK &&
        memcmp(p1, imp_sign, CC_SIGN_PUBKEY_SZ) == 0 &&
        memcmp(p1k, imp_kem, CC_KEM_PUBKEY_SZ) == 0);

  /* A generate that fails must not leave the previous identity's seed
     exportable. The failing RNG is a zeroed WC_RNG that was never wc_InitRng'd:
     every draw from it fails (wc_RNG_GenerateBlock -> -199), so this drives the
     real public failure path (the cleanup helper is static and cannot be called
     from here). The precondition is asserted, not assumed. */
  {
    WC_RNG dead;
    uint8_t dmy[8];
    memset(&dead, 0, sizeof(dead));
    T("seed_dead_rng_fails",
      wc_RNG_GenerateBlock(&dead, dmy, sizeof(dmy)) != 0);
    T("seed_failed_generate_refused", cc_key_generate(&imp, &dead) != CC_OK);
    zero = 1;
    for (i = 0; i < CC_SIGN_SEED_SZ; i++) {
      if (imp.sign_seed[i] != 0)
        zero = 0;
    }
    T("seed_failed_generate_not_exportable",
      zero && imp.has_seed == 0 &&
          cc_key_export_seed(&imp, sign_seed2, kem_seed2) == CC_E_NOKEY);
    /* The identity the failed generate was asked to replace survives: the key
       objects are not touched until both draws succeed. */
    T("seed_failed_generate_keeps_identity",
      cc_key_export_public(&imp, p1, p1k) == CC_OK &&
          memcmp(p1, imp_sign, CC_SIGN_PUBKEY_SZ) == 0 &&
          memcmp(p1k, imp_kem, CC_KEM_PUBKEY_SZ) == 0);
    /* And a later generate makes the object exportable again, as a new
       identity. */
    T("seed_generate_recovers",
      cc_key_generate(&imp, rng) == CC_OK &&
          cc_key_export_seed(&imp, sign_seed2, kem_seed2) == CC_OK &&
          cc_key_export_public(&imp, p1, p1k) == CC_OK &&
          memcmp(p1, imp_sign, CC_SIGN_PUBKEY_SZ) != 0);
  }

  memset(priv_s, 0, sizeof(priv_s));
  memset(priv_k, 0, sizeof(priv_k));
  memset(sign_seed, 0, sizeof(sign_seed));
  memset(kem_seed, 0, sizeof(kem_seed));
  cc_key_free(&a);
  cc_key_free(&b);
  cc_key_free(&c);
}

static void test_reentrancy(WC_RNG* rng) {
  static cc_work_t wa, wb;
  static cc_key_t alice, bob;
  uint8_t a_addr[CC_ADDR_SZ], b_addr[CC_ADDR_SZ];
  uint8_t a_sign[CC_SIGN_PUBKEY_SZ], a_kem[CC_KEM_PUBKEY_SZ];
  uint8_t b_sign[CC_SIGN_PUBKEY_SZ], b_kem[CC_KEM_PUBKEY_SZ];
  static uint8_t ann_pkt[CC_ANN_BUF_SZ], chat_pkt[CC_CHAT_BUF_SZ];
  static uint8_t req[CC_LINK_REQ_BUF_SZ], proof[CC_LINK_PROOF_BUF_SZ];
  static uint8_t d1[CC_LINK_DATA_BUF_SZ], idp[CC_LINK_IDENTIFY_BUF_SZ];
  cc_announce_t ann_a, ann_b;
  cc_chat_t chat;
  cc_presence_t pres;
  cc_link_t li, lr;
  cc_replay_t st;
  static uint8_t payload[CC_MAX_MSG_SZ + CC_SIGN_SIG_SZ];
  size_t ann_len = 0, chat_len = 0, rl = 0, pl = 0, dl = 0, il = 0, plen = 0;
  uint8_t kind = 0;
  static const char msg[] = "interleaved";
  pthread_t th[2];
  re_thread_t args[2];
  int i;
  printf("reentrancy:\n");

  T("work_context_budget", sizeof(cc_work_t) <= 36864);
  printf("  (cc_work_t = %zu bytes, %.2fx cc_key_t)\n", sizeof(cc_work_t),
         (double)sizeof(cc_work_t) / (double)sizeof(cc_key_t));

  cc_key_generate(&alice, rng);
  cc_key_generate(&bob, rng);
  cc_key_export_public(&alice, a_sign, a_kem);
  cc_key_export_public(&bob, b_sign, b_kem);
  cc_addr_from_key(&alice, a_addr);
  cc_addr_from_key(&bob, b_addr);

  /* (a) contexts interleaved between calls, and across a whole handshake */
  T("announce_build_A",
    cc_announce_build(&wa, &alice, "Alice", 5, NULL, 0, NULL, 1, 0, ann_pkt,
                      sizeof(ann_pkt), &ann_len, rng) == CC_OK);
  T("announce_parse_A",
    cc_announce_parse(&wa, ann_pkt, ann_len, &ann_a) == CC_OK);
  T("announce_parse_B",
    cc_announce_parse(&wb, ann_pkt, ann_len, &ann_b) == CC_OK);
  T("contexts_agree", memcmp(&ann_a, &ann_b, sizeof(ann_a)) == 0);

  /* a chat built with B, between two builds with A, parsed with A */
  T("chat_build_B", cc_chat_build(&wb, &alice, b_addr, b_kem, 1,
                                  (const uint8_t*)msg, strlen(msg), 0, chat_pkt,
                                  sizeof(chat_pkt), &chat_len, rng) == CC_OK);
  T("announce_build_A_again",
    cc_announce_build(&wa, &alice, "Alice", 5, NULL, 0, NULL, 2, 0, ann_pkt,
                      sizeof(ann_pkt), &ann_len, rng) == CC_OK);
  cc_replay_init(&st, a_addr, CC_REPLAY_AUTHED);
  T("chat_parse_A",
    cc_chat_parse(&wa, &bob, a_sign, &st, chat_pkt, chat_len, &chat) == CC_OK &&
        chat.msg_len == strlen(msg) &&
        memcmp(chat.msg, msg, chat.msg_len) == 0);
  T("announce_parse_B_again",
    cc_announce_parse(&wb, ann_pkt, ann_len, &ann_b) == CC_OK &&
        ann_b.seq == 2);

  /* one handshake, its two endpoints on different contexts */
  {
    T("link_start_A", cc_link_start(&wa, &li, b_addr, b_kem, 0, 300, 0, req,
                                    sizeof(req), &rl, rng) == CC_OK);
    T("link_accept_B", cc_link_accept(&wb, &lr, &bob, 0, 300, req, rl, proof,
                                      sizeof(proof), &pl, rng) == CC_OK);
    T("link_confirm_A",
      cc_link_confirm(&wa, &li, b_addr, b_sign, proof, pl) == CC_OK);
    T("link_send_B",
      cc_link_send(&wb, &lr, CC_LINK_KIND_DATA, (const uint8_t*)"pong", 4, 1,
                   d1, sizeof(d1), &dl) == CC_OK);
    T("link_recv_A", cc_link_recv(&wa, &li, d1, dl, 1, &kind, payload,
                                  sizeof(payload), &plen) == CC_OK &&
                         plen == 4 && memcmp(payload, "pong", 4) == 0);
    T("identify_B",
      cc_link_identify(&wb, &lr, &bob, 2, idp, sizeof(idp), &il, rng) == CC_OK);
    T("identify_recv_A", cc_link_recv(&wa, &li, idp, il, 2, &kind, payload,
                                      sizeof(payload), &plen) == CC_OK &&
                             kind == CC_LINK_KIND_IDENTIFY);
  }

  /* (b) two threads, one context each, concurrently */
  for (i = 0; i < 2; i++) {
    args[i].w = (i == 0) ? &wa : &wb;
    args[i].rounds = 2;
    args[i].ok = 0;
  }
  T("threads_start",
    pthread_create(&th[0], NULL, re_worker, &args[0]) == 0 &&
        pthread_create(&th[1], NULL, re_worker, &args[1]) == 0);
  pthread_join(th[0], NULL);
  pthread_join(th[1], NULL);
  T("context_0_thread_ok", args[0].ok);
  T("context_1_thread_ok", args[1].ok);

  /* the contexts still work after all of that */
  cc_replay_init(&st, a_addr, CC_REPLAY_AUTHED);
  T("still_works_after",
    cc_chat_build(&wa, &alice, b_addr, b_kem, 3, (const uint8_t*)msg,
                  strlen(msg), 0, chat_pkt, sizeof(chat_pkt), &chat_len,
                  rng) == CC_OK &&
        cc_chat_parse(&wb, &bob, a_sign, &st, chat_pkt, chat_len, &chat) ==
            CC_OK);
  T("presence_after",
    cc_presence_build(&wb, &bob, "Bob", 3, 5, d1, sizeof(d1), &dl, rng) ==
            CC_OK &&
        cc_presence_parse(&wa, d1, dl, &pres) == CC_OK && pres.seq == 5);
}

int main(void) {
  WC_RNG rng;
  wc_InitRng(&rng);

  printf("cosechat v%s  (wire %d, POW_DIFFICULTY=%d, replay window %d)\n\n",
         CC_VERSION, CC_WIRE_VERSION, (int)CC_POW_DIFFICULTY, CC_REPLAY_WINDOW);

  test_keys(&rng);
  printf("\n");
  test_key_seeds(&rng);
  printf("\n");
  test_replay_unit();
  printf("\n");
  test_replay_classes(&rng);
  printf("\n");
  test_announce(&rng);
  printf("\n");
  test_chat(&rng);
  printf("\n");
  test_chat_security(&rng);
  printf("\n");
  test_chat_field_limits(&rng);
  printf("\n");
  test_presence(&rng);
  printf("\n");
  test_key_req();
  printf("\n");
  test_version_rejection();
  printf("\n");
  test_canonical(&rng);
  printf("\n");
  test_canonical_build(&rng);
  printf("\n");
  test_splice(&rng);
  printf("\n");
  test_link_handshake(&rng);
  printf("\n");
  test_link_window(&rng);
  printf("\n");
  test_announce_lifecycle(&rng);
  printf("\n");
  test_presence_hint(&rng);
  printf("\n");
  test_rotation(&rng);
  printf("\n");
  test_revocation(&rng);
  printf("\n");
  test_admit(&rng);
  printf("\n");
  test_pow_verify_at(&rng);
  printf("\n");
  test_group(&rng);
  printf("\n");
  test_reentrancy(&rng);

  wc_FreeRng(&rng);
  printf("\n%d passed, %d failed\n", g_passed, g_failed);
  return g_failed > 0 ? 1 : 0;
}
