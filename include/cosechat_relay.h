#ifndef COSECHAT_RELAY_H
#define COSECHAT_RELAY_H

/*
 * Relay — multi-hop forwarding and path discovery for cosechat.
 *
 * A relay sits between the road (include/cosechat_road.h) and the application:
 * the app receives a whole packet from a road, hands it to the relay, and
 * sends whatever comes back with CC_RELAY_FWD. It answers two questions:
 *
 *   "should I re-broadcast this, and with which hops?"
 *   "which neighbour do I send a packet addressed to X to?"
 *
 * WHAT IT IS NOT, deliberately:
 *
 *   - Not a routing protocol. There are no metrics, no advertisements of its
 *     own, no cost, no per-destination queues and no retransmission: a learned,
 *     best-effort, LRU-ish next-hop table filled from announces that other
 *     nodes already broadcast.
 *   - No keys, and nothing but hops rewritten. It never needs or holds a key,
 *     never decrypts, never signs and never verifies a signature or a tag: a
 *     relay spends airtime on traffic it cannot read, which is the whole point
 *     of an opportunistic mesh. The only cryptography it performs is the
 *     key-free PoW check on forwarded data (cc_pow_verify), because paying
 *     that price is the condition for spending other people's airtime. It
 *     follows that the ONLY byte of a packet it ever changes is the hops
 *     element, re-stamped with cc_hops_increment() (verified byte-wise by the
 *     tests: PoW, signature and AEAD tag survive).
 *   - Not an authenticator. hops is outside the PoW, the signature and the
 *     tag by design (see include/cosechat.h), so it is a mutable,
 *     unauthenticated claim: anyone on the path can rewrite it without
 *     invalidating anything. The relay therefore never trusts it as evidence
 *     about the world — it is a hint whose every use is subject to the rules
 *     below (an origin check, an incumbent-only route move, a cap, and a
 *     digest that ignores it entirely). Verifying an announce
 *     (cc_announce_parse: PoW, signature, address derivation) is the
 *     APPLICATION's job; the relay does re-price forwarded data itself
 *     (cc_pow_verify, key-free) because paying that price is the condition
 *     for spending other people's airtime.
 *   - Not a link-layer bridge. Link traffic is not relayed; see
 *     "Link traffic" below.
 *
 * Path learning is ANNOUNCE-ONLY, on purpose. A cc_announce_t handed to
 * cc_relay_announce() has been through cc_announce_parse(), so its addr is
 * derived from a signature that verified: the table cannot be filled with a
 * forged origin. A data packet's sender field is not verifiable by a node that
 * cannot decrypt it, so a table learned from data traffic could be poisoned by
 * any unsigned packet. Data packets therefore consume the table and never
 * change it (no reverse-path learning), and the packet's own sender is not
 * used at all.
 *
 * ATTRIBUTION — what `from` is, and what it is not. `from` is evidence only
 * if the medium attributes senders: the caller passes the LINK-LAYER source
 * address of the packet (a MAC, a UDP peer, a per-link identity the app
 * verified out of band), and never the address the announcement names, which
 * would make every check below vacuous. Where a medium cannot attribute
 * (anonymous BLE advertising, plain LoRa broadcast), the caller passes NULL
 * and the relay treats every announcement as a relayed one: the origin rule is
 * unavailable, no neighbour is trusted as an incumbent, no route points
 * anywhere, and the sequence rules below are what protect the table.
 *
 * How the hops claim is used, precisely. Route age is decided by the
 * announcement's SEQUENCE NUMBER, which the signature covers, and never by the
 * hop count, which nothing covers:
 *
 *   - An announcement the relay has already seen cannot move or resurrect
 *     anything: if its sequence is not newer than the entry's, it is
 *     CC_RELAY_E_NOIMPROVE, whatever hop count it claims and whoever relays it.
 *     A replay with a rewritten hops is therefore a no-op — this is what closes
 *     the hijack, and it closes it without making a live route sticky.
 *   - A genuinely newer announcement may come from any neighbour and move the
 *     route there, so a route is never stuck on a neighbour that went away.
 *     Its hop count is still an unauthenticated claim, so the relay re-stamps
 *     the value it accepted plus one (cc_hops_increment) and trusts it for
 *     nothing else; a node that relays an announcement the relay has *never*
 *     seen can still advertise a shorter path than it has, and the only way to
 *     close that is authenticated distance, i.e. a different protocol.
 *   - On an attributing medium, hops == 0 is a claim to be one hop from your
 *     own origin, and the only evidence for it is that the packet arrived from
 *     the address it announces; otherwise it is refused (CC_RELAY_E_ORIGIN).
 *     An announcement that *does* arrive from its own address at hops 0 is the
 *     origin speaking for itself — the shortest claim there is, and one it
 *     cannot point at anybody else — so it always wins, whatever the table
 *     held. That is also how an owner reclaims its own route after anything
 *     else has taken it, and it is the only case where a route may move on
 *     equal sequence (the recorded sequence itself never goes backwards).
 *   - The duplicate digest deliberately ignores the hops element, so a
 *     re-stamped copy of a packet this relay already forwarded is recognised
 *     as the duplicate it is (see the duplicate-cache note below).
 *
 * On a medium that cannot attribute senders (anonymous BLE, plain LoRa — the
 * caller passes NULL), the self-origin shortcut above is inert: nothing in the
 * packet can say who sent it, so the relay never grants it. A hops == 0
 * announcement is neither refused nor privileged there — it is one more
 * relayed announcement, and the only protections on a live route are the
 * hops-excluded duplicate digest, the sequence rules and the airtime pools
 * (with the per-destination data budget inside the data one).
 * Because the newest announcement wins whatever relayed it, an attacker in
 * range must re-race each announcement to hold a route rather than take it
 * once and keep it. That trade is deliberate: recoverability (a route always
 * follows the newest signed content, and an owner reaching its own neighbours
 * always reclaims its own) over stickiness (an incumbent that cannot be
 * displaced). Anything stronger needs a road that attributes its senders, or
 * authenticated distance, which is a protocol change and not something this
 * module can invent.
 *
 * Link traffic. Links are NOT relayed:
 *   - a link_req carries nonce, suite, link_id and kem_ct and NO destination
 *     on the wire — the responder is whoever's long-term ML-KEM key was
 *     encapsulated to, and only it can tell by decapsulating. A relay has
 *     nothing to route on, and cannot learn a {link_id -> next hop} entry from
 *     a packet that names nobody;
 *   - link_data / identify / close carry a link_id alone, and by construction
 *     a link only exists between two nodes whose handshake completed, i.e.
 *     between direct peers of one road. There is no such thing as a link
 *     record that needs a second hop;
 *   - so the relay exposes no link API and keeps no link table. An app that
 *     wants a conversation across a mesh uses chat (addressed, relayable) or
 *     runs its own multi-hop link rendezvous; the relay stays out of it.
 *
 * Reentrancy: caller-owned state, no allocation, no globals, no platform
 * headers, no threads. One cc_relay_t per thread or per concurrent caller.
 *
 * Duplicates and budgets. A packet re-broadcast inside CC_RELAY_DUP_TTL is
 * refused as CC_RELAY_E_DUP, whatever its hop count: chats and announcements
 * carry an authenticated freshness value (a monotonic counter, a sequence
 * number) that a sender never legitimately repeats byte-for-byte, so a repeat
 * can only be a replay, and the window is long (half
 * CC_RELAY_PATH_TTL) so a captured packet cannot be re-injected once per short
 * TTL forever. The trade is cache pressure: the cache holds CC_RELAY_DUP
 * digests and evicts the oldest when full, so under heavy traffic the effective
 * window is shorter than the TTL — size CC_RELAY_DUP to the packet rate of the
 * window you want to cover. Only packets the relay actually re-broadcasts enter
 * the cache, so a refusal never changes the state it was refused by, and asking
 * twice gets the same answer twice.
 *
 * The traffic a relay carries comes in two classes — announcements (bulk,
 * rare) and unicast data — and each has its own airtime pool, because one pool
 * makes one class starve the other: an announcement is ~6.5 KB, so a window
 * sized for one channel admits an announcement OR some data, and a shared pool
 * would refuse every data packet of that window after a single announcement
 * was relayed — one announce per window, from anyone, blacked out relayed data
 * mesh-wide. The data class also has a per-destination packet budget on top of
 * its pool, so one peer cannot take the whole data pool. Three limits in all,
 * all per CC_RELAY_WINDOW ticks, all refusing with CC_RELAY_E_BUDGET and all
 * recovering on the next window: the announce pool, the data pool and the
 * per-destination data budget. The per-destination counters live in a table
 * keyed by address (not in the path table), so losing a route to table pressure
 * does not hand a destination a fresh budget.
 *
 * Traffic is priced on the way through, and a relay needs no keys to do it: the
 * check is one call into the library's own PoW rule (cc_pow_verify_at, which
 * takes the difficulty as a parameter). Unicast data is charged what the
 * destination's own announcement declares it asks senders to mine for chat
 * (its signed admit field), with this build's CC_POW_DIFFICULTY_CHAT as a
 * floor unless CC_RELAY_REQUIRE_POW is off. The check happens before any budget
 * or cache slot is spent, so unpaid traffic consumes nothing — and a sender's
 * effective price is the strictest relay on its path, because every relay
 * re-prices. Anything else — link traffic, presence, key_req, or a type from
 * another revision of the protocol that this build does not carry — is refused
 * with CC_RELAY_E_TYPE and forwarded nowhere.
 *
 * A refusal never modifies the packet, the table or the cache; it only moves
 * that refusal's own counter, which is what makes the reasons countable.
 */

#include <stddef.h>
#include <stdint.h>

#include "cosechat.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Capacities and policy defaults. All are compile-time knobs (override on the
 * build line); every byte the relay uses follows from them, and the tests
 * print and assert the resulting sizes.
 *
 * `now` is a caller clock in ticks throughout this API: monotonic, wrapping
 * (unsigned arithmetic), and the same clock for every call. The defaults read
 * as one tick = one second (the reference app ticks its main loop); a node
 * with a different clock passes its own CC_RELAY_*_TTL / _WINDOW.
 * ------------------------------------------------------------------------- */

/* Path table entries. 64 entries cost 3 KiB (48 B each, measured and asserted
 * by the tests) and cover a mesh of that many distinct origins; a caller with
 * a tiny MCU budget drops this to 8 or 16 without touching the code. */
#ifndef CC_RELAY_PATHS
#define CC_RELAY_PATHS 64
#endif

/* Duplicate-cache slots (16-byte packet digests). 32 slots cost 640 B. */
#ifndef CC_RELAY_DUP
#define CC_RELAY_DUP 32
#endif

/* Per-destination budget slots (address plus a window counter). 16 slots cost
 * 384 B. Small on purpose: the airtime pools bound how many distinct
 * destinations can spend anything in one window, so at the default byte
 * budgets the table cannot be thrashed. A build that raises the pools for a
 * fast road raises this with them (see cc_relay_budget_t). */
#ifndef CC_RELAY_BUDGETS
#define CC_RELAY_BUDGETS 16
#endif

/* A relay never re-broadcasts a packet whose hops would exceed this. The
 * library imposes no hop limit (see include/cosechat.h); this is receiver
 * policy, and a relay is a receiver that pays airtime. 8 hops is ~4x the
 * diameter of a dense LoRa mesh and 8 fragments of overhead at most. */
#ifndef CC_RELAY_MAX_HOPS
#define CC_RELAY_MAX_HOPS 8
#endif

/* Duplicate-cache TTL: a packet seen again inside this window is a replay and
 * is not re-broadcast, whatever its hop count. Long on purpose. Chats and
 * announces both carry an authenticated freshness value that a sender never
 * legitimately repeats byte-for-byte (a monotonic counter, a sequence number),
 * so a repeat can only be a replay: a short TTL would let one captured packet
 * be re-injected once per TTL for as long as its sender is alive, re-broadcast
 * up to a destination's whole budget each window at every relay it passes.
 * Half CC_RELAY_PATH_TTL keeps the cache a forwarding memory rather than a
 * lifetime, and the tests pin the pairing. Cache pressure is the cost: the
 * cache evicts its oldest digest when full, so a very busy window shortens the
 * effective window — size CC_RELAY_DUP to the packet rate you want to cover. */
#ifndef CC_RELAY_DUP_TTL
#define CC_RELAY_DUP_TTL 300
#endif

/* A path entry not refreshed for this long is stale: it is not used to forward
 * data (CC_RELAY_E_EXPIRED) and the next announce for that destination
 * re-learns it from whoever is heard first. This is also the only way a live
 * route moves to a different neighbour (see cc_relay_announce), so it is the
 * convergence time of the table. */
#ifndef CC_RELAY_PATH_TTL
#define CC_RELAY_PATH_TTL 600
#endif

/* Budget window, in the same ticks. Every pool below resets every window: one
 * minute is long enough to hold a full announcement (6.5 KB is ~9 s of SF7 air
 * time) plus a few chats, so a window can carry a mix instead of one packet,
 * and short enough that a burst cannot be repeated indefinitely. */
#ifndef CC_RELAY_WINDOW
#define CC_RELAY_WINDOW 60
#endif

/* Per-destination data budget: at most this many data packets per window are
 * re-broadcast for any one destination — fairness, so that one destination
 * cannot take the whole data pool. Three is a conversation: two messages out
 * and one back through this relay in a minute, with the byte pool as the real
 * bound (three ~4.5 KB chats are well under it). One, the earlier default, made
 * an honest two-way conversation through a relay impossible. A fast road
 * raises this with the pools. */
#ifndef CC_RELAY_FWD_BUDGET
#define CC_RELAY_FWD_BUDGET 3
#endif

/*
 * Airtime pools, in bytes per window, ONE PER CLASS of traffic — announcements
 * and unicast data — because a shared pool lets one class starve the other (see
 * the header's "two classes" note): exhausting either leaves the other flowing.
 *
 * Sized from the packet mix and the road, one channel's worth in total. An SF7
 * / 125 kHz LoRa channel carries ~683 B/s of payload (preamble and framing
 * included), so a 60-tick window is ~40960 B; the split gives announcements
 * 16384 B, which carries ~2.5 of them (~6.5 KB each — the bulk traffic a relay
 * exists to spread), and hands the rest, 24576 B, to data, ~5.4 chats (~4.5 KB
 * each). The per-destination budget (CC_RELAY_FWD_BUDGET, 3) is sized against
 * that pool: it bounds one peer to three packets, while sixteen peers all at
 * their budget would want ~216 KB, so the pool is the real bound and is reached
 * long before the counters are (a fast road raises both). A WiFi or Ethernet
 * road raises both pools by orders of magnitude, and CC_RELAY_BUDGETS with
 * them; the pools are the knobs to raise, because the split, not the total, is
 * what keeps announcements from silencing data and data from silencing
 * announcements.
 */
#ifndef CC_RELAY_AIRTIME_ANNOUNCE
#define CC_RELAY_AIRTIME_ANNOUNCE 16384
#endif
#ifndef CC_RELAY_AIRTIME_DATA
#define CC_RELAY_AIRTIME_DATA 24576
#endif

/* A relay refuses to re-broadcast data that did not pay for admission: every
 * forwarded chat must pass cc_pow_verify() — this build's own
 * CC_POW_DIFFICULTY_CHAT — before a budget or a cache slot is spent on it.
 * That check needs no keys, and without it four hand-crafted, never-mined
 * envelopes would burn a destination's whole window (and, on a fast road, the
 * global budget) for zero mining cost. Announcements are not re-checked here:
 * cc_announce_parse() already enforced their price before the caller handed
 * them over. A build that wants to forward other people's traffic for free
 * sets this to 0. */
#ifndef CC_RELAY_REQUIRE_POW
#define CC_RELAY_REQUIRE_POW 1
#endif

/* ---------------------------------------------------------------------------
 * Return codes. Every drop has its own code so the app can count them
 * (cc_relay_stats() keeps the same tally); the input packet is never modified
 * by a drop, and *out_len is set to 0 so a stale buffer cannot be forwarded by
 * accident. The values are distinct from the CC_E_* range so that a caller
 * cannot mistake one for the other.
 * ------------------------------------------------------------------------- */
#define CC_RELAY_FWD 0       /* forward: out/out_len hold the packet */
#define CC_RELAY_E_ARG (-20) /* a NULL or inconsistent argument */
#define CC_RELAY_E_BUF (-21) /* out is too small (needs input + 1 byte) */
#define CC_RELAY_E_FORMAT \
  (-22) /* malformed: not a complete canonical envelope */
#define CC_RELAY_E_VERSION (-23) /* another wire revision */
#define CC_RELAY_E_UNKNOWN (-24) /* no path to the destination */
#define CC_RELAY_E_MAXHOPS (-25) /* hops at CC_RELAY_MAX_HOPS */
#define CC_RELAY_E_EXPIRED (-26) /* announce expired, or path entry stale */
#define CC_RELAY_E_DUP (-27)     /* byte-identical packet inside the TTL */
#define CC_RELAY_E_BUDGET (-28)  /* per-destination or global budget spent */
#define CC_RELAY_E_NOIMPROVE \
  (-29) /* announce: nothing new (route and content already known) */
#define CC_RELAY_E_TYPE                           \
  (-30) /* well-formed, but not a packet this API \
           forwards (use cc_relay_announce for an \
           announce) */
#define CC_RELAY_E_ORIGIN                                                \
  (-31) /* an announce at hops 0 that did not arrive from the address it \
           announces: its origin claim has no evidence behind it */
#define CC_RELAY_E_POW                                        \
  (-32) /* data that did not pay this build's admission price \
           (CC_POW_DIFFICULTY_CHAT): not worth other people's airtime */

/* One path entry: the next hop toward `addr`, and the evidence for it.
 *
 * hops is the depth of the announce that established the entry, i.e. the
 * distance to `addr` minus one: 0 means `addr` is the neighbour itself, and a
 * re-broadcast of that announcement carries hops+1. last_seen is the `now` of
 * the announcement that created or refreshed the entry (the staleness test for
 * data), and ann_seq is its sequence number (the "is there newer content"
 * test, and the only authenticated thing about a route). admit is what that
 * address declares it asks senders to mine for chat — copied out of the signed
 * announce so that forwarding data toward it can charge the published price.
 * quality is caller-supplied signal information (a road's RSSI/SNR bucket),
 * stored and exposed but never part of a forwarding decision. next_hop is all
 * zero on a road that does not attribute senders (see the header's attribution
 * note): there is no unicast address to give, so the app broadcasts.
 * Budget accounting does NOT live here: see cc_relay_budget_t. 48 bytes. */
typedef struct {
  uint8_t addr[CC_ADDR_SZ];
  uint8_t next_hop[CC_ADDR_SZ];
  uint32_t last_seen;
  uint32_t ann_seq;
  uint8_t hops;
  uint8_t quality;
  uint8_t used;
  uint8_t admit[CC_ADMIT_SZ];
} cc_relay_path_t;

/* A duplicate-cache slot: the first 16 bytes of SHA-256 over the packet with
 * its hops element removed (the bytes the sender committed to), and when it
 * goes stale. expires == 0 means the slot is free. 20 bytes. */
typedef struct {
  uint8_t hash[16];
  uint32_t expires;
} cc_relay_dup_t;

/* One destination's window accounting, keyed by address rather than by path
 * entry, so that table pressure (an eviction storm) cannot hand a destination
 * a fresh budget: `count` is the *data* packets forwarded for `addr` in the
 * window it belongs to (announcements are broadcast, bounded by their pool,
 * and are not counted per destination), and a window that has rolled over has
 * spent nothing. 24 bytes; there are CC_RELAY_BUDGETS of them. */
typedef struct {
  uint8_t addr[CC_ADDR_SZ];
  uint32_t window;
  uint16_t count;
  uint8_t used;
} cc_relay_budget_t;

/* Counters, all monotonic since cc_relay_init() except `window_announce` and
 * `window_data`, which are the live figures the two pools test against and
 * reset every window. `forwarded` counts packets handed back for re-broadcast;
 * `airtime` their total bytes since init; `rx` every packet
 * offered to either entry point; `learned` routes established (a destination
 * that was unknown or stale); `improved` live entries moved to a shorter route;
 * `refreshed` live entries updated in place; `evicted` entries dropped for
 * capacity; `e_*` one counter per return code. */
typedef struct {
  uint32_t rx;
  uint32_t forwarded;
  uint32_t airtime;
  uint32_t window_announce;
  uint32_t window_data;
  uint32_t learned;
  uint32_t improved;
  uint32_t refreshed;
  uint32_t evicted;
  uint32_t e_arg;
  uint32_t e_buf;
  uint32_t e_format;
  uint32_t e_version;
  uint32_t e_unknown;
  uint32_t e_maxhops;
  uint32_t e_expired;
  uint32_t e_dup;
  uint32_t e_budget;
  uint32_t e_noimprove;
  uint32_t e_type;
  uint32_t e_origin;
  uint32_t e_pow;
} cc_relay_stats_t;

/*
 * Caller-owned relay state: the path table, the duplicate cache, the
 * per-destination budget table and the counters. Declare it static or global
 * on an MCU (a few kilobytes, see cc_relay_bytes()), never on a stack in a
 * deep call path.
 */
typedef struct {
  cc_relay_path_t paths[CC_RELAY_PATHS];
  cc_relay_dup_t dup[CC_RELAY_DUP];
  cc_relay_budget_t budget[CC_RELAY_BUDGETS];
  /* start of the current budget window and what each pool has spent in it */
  uint32_t window;
  uint32_t airtime_announce;
  uint32_t airtime_data;
  cc_relay_stats_t stats;
} cc_relay_t;

/* Zero the state (paths, cache, windows, counters). CC_OK, or
 * CC_RELAY_E_ARG for NULL. */
int cc_relay_init(cc_relay_t* r);

/*
 * Learn from a verified announce and decide whether to re-broadcast it.
 *
 * `ann` MUST be the parse of `pkt` (cc_announce_parse), which is where the
 * PoW, the signature and the address derivation happened. `from` is the
 * link-layer source the packet arrived from, or NULL when the medium does not
 * attribute senders — NEVER the address the announcement names (see the
 * ATTRIBUTION note above); an announcement that arrives at hops 0 from a
 * non-NULL `from` other than the address it announces is CC_RELAY_E_ORIGIN,
 * because that claim has no evidence behind it. `quality` is that road's
 * signal bucket (0 = unknown), stored for the app to read back.
 *
 * Decision, in order (every refusal leaves the table and the packet alone):
 *   CC_RELAY_E_ARG       NULL, or `pkt` is not the announce `ann` describes
 *                        (wrong type, or a hops element that disagrees)
 *   CC_RELAY_E_FORMAT    not a canonical, complete announce envelope (the
 *                        leading elements are checked on entry, the whole
 *                        envelope by the re-stamp below)
 *   CC_RELAY_E_VERSION   another wire revision
 *   CC_RELAY_E_ORIGIN    hops == 0 (a claim to be the origin's neighbour) but
 *                        the packet did not arrive from the address it
 *                        announces
 *   CC_RELAY_E_EXPIRED   ann->expiry != 0 and now >= ann->expiry
 *   CC_RELAY_E_MAXHOPS   ann->hops >= CC_RELAY_MAX_HOPS
 *   CC_RELAY_E_DUP       this announcement was already forwarded inside
 *                        CC_RELAY_DUP_TTL, whatever its hop count
 *   CC_RELAY_E_BUF       out is smaller than pkt + 1
 *   CC_RELAY_E_BUDGET    the announce pool is spent for this window
 *   CC_RELAY_E_NOIMPROVE nothing newer than what the table holds: the
 *                        announcement cannot move or resurrect a route
 *   CC_RELAY_FWD         re-broadcast out/out_len: pkt with hops+1
 *
 * The table is updated (and only then forwarded) when the destination is
 * unknown, when the announcement is strictly newer than the entry's sequence
 * (from any neighbour, since the sequence is signed and the hop count is not),
 * or when the origin speaks for itself — hops 0, arriving from the address it
 * announces, which always wins so that an owner can reclaim its own route. An
 * equal-sequence announcement from the neighbour the route points at refreshes
 * liveness without a forward; anything else leaves the table alone.
 * Staleness is not part of this decision: an announcement is judged by its
 * content age, which is authenticated, not by the clock, which is not.
 *
 * `out` must have room for one byte MORE than pkt and must not overlap pkt,
 * exactly like cc_hops_increment(); a caller that shares one buffer gets
 * CC_RELAY_E_ARG. The extra byte is for a hops CBOR head growing from one byte
 * to two (values 23 -> 24, unreachable at the default CC_RELAY_MAX_HOPS of 8
 * but reachable the moment a caller raises that limit past 23).
 *
 * The forwarded bytes are pkt with hops+1 (cc_hops_increment, which re-encodes
 * only that element, so the PoW, the signature and the tag survive). Nothing
 * re-signs, re-mines or re-encrypts anything.
 */
int cc_relay_announce(cc_relay_t* r, const cc_announce_t* ann,
                      const uint8_t from[CC_ADDR_SZ], uint8_t quality,
                      uint32_t now, const uint8_t* pkt, size_t pkt_sz,
                      uint8_t* out, size_t out_sz, size_t* out_len);

/*
 * Forward a data packet (chat) toward cc_msg_recipient()'s address.
 *
 * Decision, in order:
 *   CC_RELAY_E_ARG/CC_RELAY_E_FORMAT/CC_RELAY_E_VERSION  as above
 *   CC_RELAY_E_TYPE      well-formed, but not a chat: link traffic, presence,
 *                        key_req and unknown types are not relayed, and an
 *                        announce belongs in cc_relay_announce()
 *   CC_RELAY_E_MAXHOPS   hops at CC_RELAY_MAX_HOPS
 *   CC_RELAY_E_POW       the packet did not pay the price the destination's
 *                        own announcement declares (its signed admit field for
 *                        chat), or this build's CC_POW_DIFFICULTY_CHAT floor
 *                        while CC_RELAY_REQUIRE_POW is on (the default).
 *                        Checked before the duplicate cache and the budgets,
 *                        so unpaid traffic consumes nothing
 *   CC_RELAY_E_DUP       this packet was already forwarded inside
 *                        CC_RELAY_DUP_TTL, whatever its hop count
 *   CC_RELAY_E_UNKNOWN   no path entry for the recipient
 *   CC_RELAY_E_EXPIRED   the entry is older than CC_RELAY_PATH_TTL
 *   CC_RELAY_E_BUF       out is smaller than pkt + 1
 *   CC_RELAY_E_BUDGET    a budget is spent
 *   CC_RELAY_FWD         re-broadcast out/out_len: pkt with hops+1
 *
 * Nothing else about the input is trusted: the sender field is not read, the
 * payload is not inspected, and the hop claim is used only to refuse a packet
 * that has already spent the hop budget. There is deliberately no "hops
 * against the table" check here: hops sits outside the signature and the tag
 * by design (see include/cosechat.h), so for a packet this node cannot
 * authenticate it is a claim by whoever last re-stamped it, and a legitimate
 * message can arrive by a longer route than the best one in the table. Loop
 * suppression for data is therefore the hop cap, the price, the duplicate
 * cache (which ignores hop count, so a re-stamped replay is still a duplicate)
 * and the budgets — never the hop *value*.
 * An app that is also a destination MUST filter packets addressed to itself
 * before offering them here: a relay does not know its own address, and a
 * chat for a node that also relays should be delivered, not forwarded.
 *
 * `out` follows the same rule as cc_relay_announce(): one byte more room than
 * pkt, no overlap.
 */
int cc_relay_forward(cc_relay_t* r, const uint8_t* pkt, size_t pkt_sz,
                     uint32_t now, uint8_t* out, size_t out_sz,
                     size_t* out_len);

/* Copy the entry for `addr` into `out` (including the price that address
 * declares it asks senders to mine, so an app can pay it with cc_admit_for()).
 * CC_OK, or CC_RELAY_E_UNKNOWN when there is no live entry (`now` decides: a
 * stale entry is not live). */
int cc_relay_path_lookup(const cc_relay_t* r, const uint8_t addr[CC_ADDR_SZ],
                         uint32_t now, cc_relay_path_t* out);

/* Number of live (non-stale) entries, or CC_RELAY_E_ARG for NULL. */
int cc_relay_paths(const cc_relay_t* r, uint32_t now);

/* Table capacity in entries (CC_RELAY_PATHS). */
int cc_relay_capacity(const cc_relay_t* r);

/* What `addr` has spent of its per-destination *data* budget in the window
 * `now` falls in (a window that has rolled over has spent nothing), or
 * CC_RELAY_E_UNKNOWN when nothing was ever forwarded for that address. The
 * counters outlive a path entry, so a destination evicted for table pressure
 * still reports the budget it already spent. */
int cc_relay_budget_get(const cc_relay_t* r, const uint8_t addr[CC_ADDR_SZ],
                        uint32_t now, cc_relay_budget_t* out);

/* Copy the counters out. CC_OK, or CC_RELAY_E_ARG for NULL. */
int cc_relay_stats(const cc_relay_t* r, cc_relay_stats_t* out);

/* sizeof(cc_relay_t): the caller's byte budget, for a static_assert or a
 * printf at boot. */
size_t cc_relay_bytes(void);

#ifdef __cplusplus
}
#endif

#endif /* COSECHAT_RELAY_H */
