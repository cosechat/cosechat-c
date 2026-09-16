/*
 * cosechat_relay.c — multi-hop forwarding and path discovery.
 *
 * See include/cosechat_relay.h for the contract. Everything here is a pure
 * function of the caller's cc_relay_t and its arguments: no allocation, no
 * globals, no platform headers, and the only byte of a packet that is ever
 * written is the hops element, by cc_hops_increment().
 */
#include "cosechat_relay.h"

#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/sha256.h>

_Static_assert(CC_RELAY_PATHS >= 1, "at least one path entry");
_Static_assert(CC_RELAY_DUP >= 1, "at least one duplicate slot");
_Static_assert(CC_RELAY_BUDGETS >= 1, "at least one budget slot");
_Static_assert(CC_RELAY_MAX_HOPS >= 1 && CC_RELAY_MAX_HOPS <= 254,
               "a usable hop limit");
_Static_assert(CC_RELAY_DUP_TTL >= 1, "a non-zero duplicate TTL");
_Static_assert(CC_RELAY_WINDOW >= 1, "a non-zero budget window");
_Static_assert(CC_RELAY_FWD_BUDGET >= 1, "a per-destination budget");
_Static_assert(CC_RELAY_AIRTIME_ANNOUNCE >= 1, "an announce airtime budget");
_Static_assert(CC_RELAY_AIRTIME_DATA >= 1, "a data airtime budget");

/* The hops element's position in every layout (include/cosechat.h). The relay
 * needs it for one thing only: the duplicate digest leaves hops out, because
 * hops is the element no sender committed to. The PoW rule is the library's
 * (cc_pow_verify_at) and is never rebuilt here. */
#define RELAY_EL_HOPS 2

/* ---------------------------------------------------------------------------
 * Small helpers
 * ------------------------------------------------------------------------- */

/* Wrap-safe "a is at or after b" for a monotonic caller clock. */
static int tick_at_or_after(uint32_t now, uint32_t then) {
  return (int32_t)(now - then) >= 0;
}

static int relay_fail(cc_relay_t* r, int code) {
  switch (code) {
    case CC_RELAY_E_ARG:
      r->stats.e_arg++;
      break;
    case CC_RELAY_E_BUF:
      r->stats.e_buf++;
      break;
    case CC_RELAY_E_FORMAT:
      r->stats.e_format++;
      break;
    case CC_RELAY_E_VERSION:
      r->stats.e_version++;
      break;
    case CC_RELAY_E_UNKNOWN:
      r->stats.e_unknown++;
      break;
    case CC_RELAY_E_MAXHOPS:
      r->stats.e_maxhops++;
      break;
    case CC_RELAY_E_EXPIRED:
      r->stats.e_expired++;
      break;
    case CC_RELAY_E_DUP:
      r->stats.e_dup++;
      break;
    case CC_RELAY_E_BUDGET:
      r->stats.e_budget++;
      break;
    case CC_RELAY_E_NOIMPROVE:
      r->stats.e_noimprove++;
      break;
    case CC_RELAY_E_TYPE:
      r->stats.e_type++;
      break;
    case CC_RELAY_E_ORIGIN:
      r->stats.e_origin++;
      break;
    case CC_RELAY_E_POW:
      r->stats.e_pow++;
      break;
    default:
      break;
  }
  return code;
}

/* Map a library decode error onto this module's codes. */
static int relay_fail_decode(cc_relay_t* r, int ret) {
  return relay_fail(
      r, (ret == CC_E_VERSION) ? CC_RELAY_E_VERSION : CC_RELAY_E_FORMAT);
}

static int path_is_stale(const cc_relay_path_t* e, uint32_t now) {
  return (uint32_t)(now - e->last_seen) > CC_RELAY_PATH_TTL;
}

/* The entry for `addr` whatever its age, or NULL: the caller decides whether
 * a stale entry is a refusal (data) or irrelevant (an announcement is judged
 * by its sequence, not by the clock). */
static cc_relay_path_t* path_any(cc_relay_t* r,
                                 const uint8_t addr[CC_ADDR_SZ]) {
  int i;
  for (i = 0; i < CC_RELAY_PATHS; i++) {
    cc_relay_path_t* e = &r->paths[i];
    if (e->used && memcmp(e->addr, addr, CC_ADDR_SZ) == 0)
      return e;
  }
  return NULL;
}

/*
 * A slot to learn into: the first free one, else the least recently seen.
 * Evicting an entry costs its route but no budget: the per-destination
 * counters live in their own table (see cc_relay_budget_t), so an eviction
 * storm cannot hand a destination a fresh forwarding budget.
 */
static cc_relay_path_t* path_alloc(cc_relay_t* r) {
  cc_relay_path_t* victim = NULL;
  int i;

  for (i = 0; i < CC_RELAY_PATHS; i++) {
    cc_relay_path_t* e = &r->paths[i];
    if (!e->used)
      return e;
    if (!victim || (int32_t)(e->last_seen - victim->last_seen) < 0)
      victim = e;
  }
  r->stats.evicted++;
  memset(victim, 0, sizeof(*victim));
  return victim;
}

/* `next_hop` is NULL for a road that does not attribute senders: the entry
 * then has no next hop (all zero) and the app broadcasts, which is all such a
 * road can do. */
static void path_learn(cc_relay_path_t* e, const uint8_t addr[CC_ADDR_SZ],
                       const uint8_t* next_hop, uint8_t hops, uint32_t seq,
                       const uint8_t admit[CC_ADMIT_SZ], uint8_t quality,
                       uint32_t now) {
  uint32_t keep_seq = e->used ? e->ann_seq : 0;

  memset(e, 0, sizeof(*e));
  memcpy(e->addr, addr, CC_ADDR_SZ);
  if (next_hop)
    memcpy(e->next_hop, next_hop, CC_ADDR_SZ);
  e->hops = hops;
  e->quality = quality;
  e->last_seen = now;
  e->used = 1;
  /* A route claim never ages its content backwards: an older announcement can
   * re-point a route (only the origin may do that) but cannot make the relay
   * forget which sequence it has already seen. */
  e->ann_seq = (seq > keep_seq) ? seq : keep_seq;
  if (admit)
    memcpy(e->admit, admit, CC_ADMIT_SZ);
}

/* The two kinds of traffic a relay carries, each with its own pool. */
#define RELAY_CLS_ANNOUNCE 0
#define RELAY_CLS_DATA 1

/* ---- the per-destination budget table ---- */

/*
 * The counter for `addr`, claimed if this address has none yet. Slots are
 * reused in this order: a free one, one whose window has rolled over (its
 * count is dead), then the oldest, then the least used. The two airtime pools
 * are what bound how many slots can be live at once, which is why
 * CC_RELAY_BUDGETS can be small (see the header).
 */
static cc_relay_budget_t* budget_slot(cc_relay_t* r,
                                      const uint8_t addr[CC_ADDR_SZ]) {
  cc_relay_budget_t* free_slot = NULL;
  cc_relay_budget_t* dead_slot = NULL;
  cc_relay_budget_t* oldest = NULL;
  int i;

  for (i = 0; i < CC_RELAY_BUDGETS; i++) {
    cc_relay_budget_t* b = &r->budget[i];
    if (b->used && memcmp(b->addr, addr, CC_ADDR_SZ) == 0)
      return b;
    if (!b->used) {
      if (!free_slot)
        free_slot = b;
      continue;
    }
    if (b->window != r->window) {
      if (!dead_slot)
        dead_slot = b;
      continue;
    }
    if (!oldest || (int32_t)(b->window - oldest->window) < 0 ||
        (b->window == oldest->window && b->count < oldest->count))
      oldest = b;
  }
  if (!free_slot)
    free_slot = dead_slot ? dead_slot : oldest;
  memset(free_slot, 0, sizeof(*free_slot));
  memcpy(free_slot->addr, addr, CC_ADDR_SZ);
  free_slot->used = 1;
  free_slot->window = r->window;
  return free_slot;
}

/*
 * Charge a forward against the window that matches its kind, rolling the window
 * over first. Each kind has its own pool, because one pool lets the bulk class
 * starve the other: announcements are bulk and rare, and data is what a relay
 * exists for. Data also has a per-destination packet budget, so one peer cannot
 * take the whole data pool. Returns 0 when something is spent (and changes
 * nothing else).
 */
static int budget_take(cc_relay_t* r, const uint8_t* key, uint32_t now,
                       size_t bytes, int cls) {
  uint32_t* pool;

  if ((uint32_t)(now - r->window) >= CC_RELAY_WINDOW) {
    r->window = now;
    r->airtime_announce = 0;
    r->airtime_data = 0;
  }

  if (cls == RELAY_CLS_ANNOUNCE) {
    if (r->airtime_announce + bytes > CC_RELAY_AIRTIME_ANNOUNCE)
      return 0;
    r->airtime_announce += (uint32_t)bytes;
    return 1;
  }

  {
    cc_relay_budget_t* b = budget_slot(r, key);
    pool = &r->airtime_data;
    if (b->window != r->window) {
      b->window = r->window;
      b->count = 0;
    }
    if (b->count >= CC_RELAY_FWD_BUDGET)
      return 0;
    if (*pool + bytes > CC_RELAY_AIRTIME_DATA)
      return 0;
    b->count++;
    *pool += (uint32_t)bytes;
  }
  return 1;
}

/* ---------------------------------------------------------------------------
 * Envelope walker, and the one digest this module computes
 *
 * The duplicate digest skips the hops element on purpose: hops is the one
 * element the sender did not commit to (it is outside the PoW, the signature
 * and the tag), so hashing it would let a re-stamped copy of a packet this
 * relay already forwarded walk straight past the cache. Pricing is not done
 * here: the PoW rule lives in the library (cc_pow_verify_at) and the relay
 * calls it rather than rebuilding the preimage.
 * ------------------------------------------------------------------------- */

/* Canonical CBOR head (minimal-length, definite): the subset the envelopes are
 * made of, and all this module needs to walk one. */
static int cb_read_head(const uint8_t* p, size_t avail, uint8_t* major,
                        uint64_t* val, size_t* hdr) {
  uint8_t ib, ai;
  if (avail < 1)
    return 0;
  ib = p[0];
  ai = (uint8_t)(ib & 0x1F);
  if (ai < 24) {
    *val = ai;
    *hdr = 1;
  } else if (ai == 24) {
    if (avail < 2 || p[1] < 24)
      return 0;
    *val = p[1];
    *hdr = 2;
  } else if (ai == 25) {
    if (avail < 3)
      return 0;
    *val = ((uint64_t)p[1] << 8) | p[2];
    if (*val < 256)
      return 0;
    *hdr = 3;
  } else if (ai == 26) {
    if (avail < 5)
      return 0;
    *val = ((uint64_t)p[1] << 24) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 8) | p[4];
    if (*val < 65536)
      return 0;
    *hdr = 5;
  } else {
    return 0;
  }
  *major = (uint8_t)(ib >> 5);
  return 1;
}

/* Offset and span of element `idx` of the outer array. */
static int elem_span(const uint8_t* pkt, size_t pkt_sz, unsigned idx,
                     size_t* off, size_t* len) {
  uint8_t major;
  uint64_t v;
  size_t hdr, pos, used;
  unsigned i, n;

  if (!cb_read_head(pkt, pkt_sz, &major, &v, &hdr) || major != 4 || v < 3)
    return 0;
  n = (unsigned)v;
  if (idx >= n)
    return 0;
  pos = hdr;
  for (i = 0; i <= idx; i++) {
    if (!cb_read_head(pkt + pos, pkt_sz - pos, &major, &v, &hdr))
      return 0;
    if (major == 2 || major == 3) { /* a bstr or a tstr */
      if (v > (uint64_t)(pkt_sz - pos - hdr))
        return 0;
      used = hdr + (size_t)v;
    } else if (major == 0) { /* a uint */
      used = hdr;
    } else {
      return 0;
    }
    if (i == idx) {
      *off = pos;
      *len = used;
      return 1;
    }
    pos += used;
  }
  return 0;
}

static void dup_digest(const uint8_t* pkt, size_t pkt_sz, uint8_t out[16]) {
  uint8_t major, hash[32];
  uint64_t v;
  size_t hdr, off, len, i;
  unsigned n;
  wc_Sha256 sha;

  if (!cb_read_head(pkt, pkt_sz, &major, &v, &hdr) || major != 4 || v < 3)
    goto fallback; /* not an envelope: hash it as it came */
  n = (unsigned)v;
  if (wc_InitSha256(&sha) != 0)
    goto fallback;
  wc_Sha256Update(&sha, pkt, (word32)hdr); /* the array head is part of it */
  for (i = 0; i < n; i++) {
    if (!elem_span(pkt, pkt_sz, (unsigned)i, &off, &len)) {
      wc_Sha256Free(&sha);
      goto fallback;
    }
    if (i == RELAY_EL_HOPS)
      continue;
    wc_Sha256Update(&sha, pkt + off, (word32)len);
  }
  if (wc_Sha256Final(&sha, hash) != 0) {
    wc_Sha256Free(&sha);
    goto fallback;
  }
  wc_Sha256Free(&sha);
  memcpy(out, hash, 16);
  return;

fallback:
  if (wc_Sha256Hash(pkt, (word32)pkt_sz, hash) == 0)
    memcpy(out, hash, 16);
  else
    memset(out, 0, 16);
}

/* 1 when this packet (whatever its hop count) was re-broadcast inside the
 * TTL. Only packets the relay actually re-broadcast are recorded, so a
 * refusal never changes the cache and repeating a refused packet gets the
 * same answer instead of a misleading CC_RELAY_E_DUP. */
static int dup_find(const cc_relay_t* r, const uint8_t* pkt, size_t pkt_sz,
                    uint32_t now) {
  cc_relay_dup_t want;
  int i;

  dup_digest(pkt, pkt_sz, want.hash);
  for (i = 0; i < CC_RELAY_DUP; i++) {
    const cc_relay_dup_t* d = &r->dup[i];
    if (d->expires != 0 && !tick_at_or_after(now, d->expires) &&
        memcmp(d->hash, want.hash, sizeof(d->hash)) == 0)
      return 1;
  }
  return 0;
}

/* Record a packet that has just been re-broadcast. */
static void dup_add(cc_relay_t* r, const uint8_t* pkt, size_t pkt_sz,
                    uint32_t now) {
  cc_relay_dup_t* slot = NULL;
  cc_relay_dup_t* oldest = NULL;
  uint8_t digest[16];
  int i;

  dup_digest(pkt, pkt_sz, digest);
  for (i = 0; i < CC_RELAY_DUP; i++) {
    cc_relay_dup_t* d = &r->dup[i];
    if (d->expires == 0 || tick_at_or_after(now, d->expires)) {
      slot = d; /* free, or expired and therefore free again */
      break;
    }
    if (!oldest || (int32_t)(d->expires - oldest->expires) < 0)
      oldest = d;
  }
  if (!slot)
    slot = oldest; /* CC_RELAY_DUP >= 1, so this is never NULL */
  memcpy(slot->hash, digest, sizeof(slot->hash));
  slot->expires = now + CC_RELAY_DUP_TTL;
}

/* ---------------------------------------------------------------------------
 * Re-stamp, price and commit
 * ------------------------------------------------------------------------- */

/*
 * Re-stamp the hops element into `out`: the one place a packet is rewritten,
 * and also the only structural validation available without keys, because
 * cc_hops_increment() fully decodes and re-encodes the envelope (canonical
 * form, arity, per-field sizes, no trailing bytes). Nothing here touches the
 * relay's state, so a malformed or truncated packet is refused before the
 * table or the cache can learn anything from it. CC_RELAY_FWD on success.
 */
static int relay_restamp(const uint8_t* pkt, size_t pkt_sz, uint8_t* out,
                         size_t out_sz, size_t* n_out) {
  int ret = cc_hops_increment(pkt, pkt_sz, out, out_sz, n_out);
  if (ret == CC_OK)
    return CC_RELAY_FWD;
  if (ret == CC_E_BUF)
    return CC_RELAY_E_BUF;
  return (ret == CC_E_VERSION) ? CC_RELAY_E_VERSION : CC_RELAY_E_FORMAT;
}

/*
 * Charge the window, remember the packet as re-broadcast, and hand it back.
 * `n` is what the medium pays (the outgoing length); `key` is the destination
 * (16 bytes) that pays in the packet counter, or NULL for an announcement,
 * which is broadcast and has none; `cls` picks the pool.
 */
static int relay_commit(cc_relay_t* r, const uint8_t* key, const uint8_t* pkt,
                        size_t pkt_sz, size_t n, uint32_t now, int cls,
                        size_t* out_len) {
  if (!budget_take(r, key, now, n, cls))
    return relay_fail(r, CC_RELAY_E_BUDGET);

  dup_add(r, pkt, pkt_sz, now);
  *out_len = n;
  r->stats.forwarded++;
  r->stats.airtime += (uint32_t)n;
  return CC_RELAY_FWD;
}

/*
 * The price this relay charges for data: what the destination's own announce
 * declared it asks senders to mine (its admit field, carried inside the
 * announce signature), with this build's own floor applied when
 * CC_RELAY_REQUIRE_POW is on. A relay needs no key to check either: the check
 * is cc_pow_verify_at(), the library's own rule at the difficulty asked for.
 */
static uint8_t relay_price(const cc_relay_path_t* e) {
  uint8_t price = e->admit[CC_ADMIT_CHAT]; /* 0 = the peer asks for nothing */

#if CC_RELAY_REQUIRE_POW
  if (price < CC_POW_DIFFICULTY_CHAT) /* this build's own floor */
    price = CC_POW_DIFFICULTY_CHAT;
#endif
  return price;
}

/* CC_RELAY_FWD when the packet paid `price`. `price == 0` means there is
 * nothing to enforce (the knob is off and the destination declared nothing),
 * which is deliberately not the same call as passing 0 to the library: 0 there
 * means "this build's own difficulty", which is exactly what the knob turns
 * off. The preimage rule stays in the library. */
static int relay_pow_ok(const uint8_t* pkt, size_t pkt_sz, uint8_t price) {
  int ret;

  if (price == 0)
    return CC_RELAY_FWD;
  ret = cc_pow_verify_at(pkt, pkt_sz, price);
  if (ret == CC_OK)
    return CC_RELAY_FWD;
  if (ret == CC_E_POW)
    return CC_RELAY_E_POW;
  if (ret == CC_E_ARG)
    return CC_RELAY_E_POW; /* an unsatisfiable price cannot be paid */
  return (ret == CC_E_VERSION) ? CC_RELAY_E_VERSION : CC_RELAY_E_FORMAT;
}

/* ---------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

int cc_relay_init(cc_relay_t* r) {
  if (!r)
    return CC_RELAY_E_ARG;
  memset(r, 0, sizeof(*r));
  return CC_OK;
}

int cc_relay_announce(cc_relay_t* r, const cc_announce_t* ann,
                      const uint8_t* from, uint8_t quality, uint32_t now,
                      const uint8_t* pkt, size_t pkt_sz, uint8_t* out,
                      size_t out_sz, size_t* out_len) {
  cc_relay_path_t* e;
  uint8_t type = 0, hops = 0;
  size_t n = 0;
  int ret, self_origin;

  if (!r)
    return CC_RELAY_E_ARG;
  if (!ann || !pkt || !out || !out_len || out == pkt)
    return relay_fail(r, CC_RELAY_E_ARG);
  *out_len = 0;
  r->stats.rx++;

  /* Structure first, so nothing below touches state for a packet that is not
   * a canonical announce, and so `ann` cannot disagree with `pkt` (the caller
   * parsed this packet; a mismatch is a caller bug, not a packet). */
  ret = cc_msg_type(pkt, pkt_sz, &type);
  if (ret != CC_OK)
    return relay_fail_decode(r, ret);
  if (type != CC_MSG_ANNOUNCE)
    return relay_fail(r, CC_RELAY_E_ARG);
  ret = cc_msg_hops(pkt, pkt_sz, &hops);
  if (ret != CC_OK)
    return relay_fail_decode(r, ret);
  if (hops != ann->hops)
    return relay_fail(r, CC_RELAY_E_ARG);

  /* Attribution. hops 0 claims to be one hop from your own origin, and the
   * only evidence for that claim is the road that handed the packet over: a
   * road that attributes senders hands us the address it came from, a road
   * that cannot attribute hands us NULL (see the header). */
  self_origin = (from != NULL) && ann->hops == 0 &&
                memcmp(from, ann->addr, CC_ADDR_SZ) == 0;
  if (from != NULL && ann->hops == 0 && !self_origin)
    return relay_fail(r, CC_RELAY_E_ORIGIN);

  if (ann->expiry != 0 && tick_at_or_after(now, ann->expiry))
    return relay_fail(r, CC_RELAY_E_EXPIRED);
  if (ann->hops >= CC_RELAY_MAX_HOPS)
    return relay_fail(r, CC_RELAY_E_MAXHOPS);
  if (dup_find(r, pkt, pkt_sz, now))
    return relay_fail(r, CC_RELAY_E_DUP);

  if (out_sz < pkt_sz + 1)
    return relay_fail(r, CC_RELAY_E_BUF);

  /* Re-stamp first: an envelope that is not a complete canonical packet is
   * refused here, before the table or the cache can learn anything. */
  ret = relay_restamp(pkt, pkt_sz, out, out_sz, &n);
  if (ret != CC_RELAY_FWD)
    return relay_fail(r, ret);

  if (self_origin) {
    /*
     * The origin itself, and the road says so: the shortest claim there is,
     * and the one claim that cannot be pointed at somebody else, so it always
     * wins whatever the table held (which is also how an owner reclaims its
     * route after anything else has taken it). It is still content: the
     * sequence recorded never goes backwards.
     */
    e = path_any(r, ann->addr);
    if (!e) {
      e = path_alloc(r);
      r->stats.learned++;
    } else if (memcmp(e->next_hop, ann->addr, CC_ADDR_SZ) != 0 ||
               e->hops != 0) {
      r->stats.improved++;
    } else {
      r->stats.refreshed++;
    }
    path_learn(e, ann->addr, ann->addr, 0, ann->seq, ann->admit, quality, now);
    return relay_commit(r, NULL, pkt, pkt_sz, n, now, RELAY_CLS_ANNOUNCE,
                        out_len);
  }

  e = path_any(r, ann->addr);
  if (!e) {
    e = path_alloc(r);
    path_learn(e, ann->addr, from, ann->hops, ann->seq, ann->admit, quality,
               now);
    r->stats.learned++;
    return relay_commit(r, NULL, pkt, pkt_sz, n, now, RELAY_CLS_ANNOUNCE,
                        out_len);
  }

  /*
   * Content age decides, not who is talking. The sequence number is covered by
   * the signature, so "newer than what I hold" is a fact, while the hop count
   * is not covered by anything and stays a claim. That makes an announcement
   * the relay has already seen — a replay, however its hops were rewritten —
   * unable to move or resurrect a route, and it lets a genuine update come
   * from any neighbour, so a route is never stuck on one that went away.
   */
  if (ann->seq > e->ann_seq) {
    uint8_t hops_claim = ann->hops;
    if (hops_claim < e->hops)
      r->stats.improved++;
    else
      r->stats.refreshed++;
    path_learn(e, ann->addr, from, hops_claim, ann->seq, ann->admit, quality,
               now);
    return relay_commit(r, NULL, pkt, pkt_sz, n, now, RELAY_CLS_ANNOUNCE,
                        out_len);
  }

  if (ann->seq == e->ann_seq && from != NULL &&
      memcmp(e->next_hop, from, CC_ADDR_SZ) == 0) {
    /* the same content from the neighbour the route points at: liveness */
    e->last_seen = now;
    e->quality = quality;
    r->stats.refreshed++;
  }
  return relay_fail(r, CC_RELAY_E_NOIMPROVE);
}

int cc_relay_forward(cc_relay_t* r, const uint8_t* pkt, size_t pkt_sz,
                     uint32_t now, uint8_t* out, size_t out_sz,
                     size_t* out_len) {
  cc_relay_path_t* e;
  uint8_t dest[CC_ADDR_SZ], type = 0, hops = 0;
  size_t n = 0;
  int ret;

  if (!r)
    return CC_RELAY_E_ARG;
  if (!pkt || !out || !out_len || out == pkt)
    return relay_fail(r, CC_RELAY_E_ARG);
  *out_len = 0;
  r->stats.rx++;

  ret = cc_msg_type(pkt, pkt_sz, &type);
  if (ret != CC_OK)
    return relay_fail_decode(r, ret);
  if (type != CC_MSG_CHAT)
    return relay_fail(r, CC_RELAY_E_TYPE);

  /* The full envelope decode, before any state moves: a malformed packet is
   * refused without touching the table or the cache. */
  ret = cc_msg_recipient(pkt, pkt_sz, dest);
  if (ret != CC_OK)
    return relay_fail_decode(r, ret);
  ret = cc_msg_hops(pkt, pkt_sz, &hops);
  if (ret != CC_OK)
    return relay_fail_decode(r, ret);

  if (hops >= CC_RELAY_MAX_HOPS)
    return relay_fail(r, CC_RELAY_E_MAXHOPS);

  e = path_any(r, dest);
  if (!e)
    return relay_fail(r, CC_RELAY_E_UNKNOWN);
  if (path_is_stale(e, now))
    return relay_fail(r, CC_RELAY_E_EXPIRED);

  /* Price before anything is written: the destination's own declared cost, or
   * this build's floor, whichever is higher. A packet that did not pay spends
   * no cache slot and no budget. */
  ret = relay_pow_ok(pkt, pkt_sz, relay_price(e));
  if (ret != CC_RELAY_FWD)
    return relay_fail(r, ret);

  if (dup_find(r, pkt, pkt_sz, now))
    return relay_fail(r, CC_RELAY_E_DUP);

  if (out_sz < pkt_sz + 1)
    return relay_fail(r, CC_RELAY_E_BUF);

  ret = relay_restamp(pkt, pkt_sz, out, out_sz, &n);
  if (ret != CC_RELAY_FWD)
    return relay_fail(r, ret);

  return relay_commit(r, e->addr, pkt, pkt_sz, n, now, RELAY_CLS_DATA, out_len);
}

int cc_relay_path_lookup(const cc_relay_t* r, const uint8_t addr[CC_ADDR_SZ],
                         uint32_t now, cc_relay_path_t* out) {
  int i;
  if (!r || !addr || !out)
    return CC_RELAY_E_ARG;
  for (i = 0; i < CC_RELAY_PATHS; i++) {
    const cc_relay_path_t* e = &r->paths[i];
    if (e->used && memcmp(e->addr, addr, CC_ADDR_SZ) == 0 &&
        !path_is_stale(e, now)) {
      *out = *e;
      return CC_OK;
    }
  }
  return CC_RELAY_E_UNKNOWN;
}

int cc_relay_paths(const cc_relay_t* r, uint32_t now) {
  int i, n = 0;
  if (!r)
    return CC_RELAY_E_ARG;
  for (i = 0; i < CC_RELAY_PATHS; i++) {
    const cc_relay_path_t* e = &r->paths[i];
    if (e->used && !path_is_stale(e, now))
      n++;
  }
  return n;
}

int cc_relay_capacity(const cc_relay_t* r) {
  return r ? CC_RELAY_PATHS : CC_RELAY_E_ARG;
}

int cc_relay_budget_get(const cc_relay_t* r, const uint8_t addr[CC_ADDR_SZ],
                        uint32_t now, cc_relay_budget_t* out) {
  int i;
  if (!r || !addr || !out)
    return CC_RELAY_E_ARG;
  for (i = 0; i < CC_RELAY_BUDGETS; i++) {
    const cc_relay_budget_t* b = &r->budget[i];
    if (b->used && memcmp(b->addr, addr, CC_ADDR_SZ) == 0) {
      *out = *b;
      /* What this destination has spent *in the window `now` falls in*: a
       * window that has rolled over has spent nothing yet. */
      if (out->window != r->window ||
          (uint32_t)(now - r->window) >= CC_RELAY_WINDOW)
        out->count = 0;
      return CC_OK;
    }
  }
  return CC_RELAY_E_UNKNOWN;
}

int cc_relay_stats(const cc_relay_t* r, cc_relay_stats_t* out) {
  if (!r || !out)
    return CC_RELAY_E_ARG;
  *out = r->stats;
  out->window_announce = r->airtime_announce;
  out->window_data = r->airtime_data;
  return CC_OK;
}

size_t cc_relay_bytes(void) { return sizeof(cc_relay_t); }
