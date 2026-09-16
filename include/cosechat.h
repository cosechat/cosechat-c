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
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CC_VERSION "0.10.0"

/*
 * Wire revision, carried as the first element of every packet. A receiver
 * rejects anything else with CC_E_VERSION after reading that one element,
 * before any PoW, signature or decryption work, so a packet from another
 * revision is dropped loudly and cheaply. The arity check that follows is a
 * second line of defence.
 *
 * Revision 7 added a link (session) layer with forward secrecy, announce and
 * presence lifecycles, and the NIST category 3 parameter set.
 *
 * Revision 8 added identity lifecycle: a rotate type (a node proves that a new
 * signing key continues an old one) and a revoke type (a node retires its own
 * identity).
 *
 * Revision 9 adds receiver-published PoW cost: the announce carries a 3-byte
 * declaration of what this node asks senders to mine to reach it, one byte per
 * directed type, inside the signed coverage. That changes the announce's arity
 * (11 elements -> 12), so it is a wire revision rather than an addition to
 * revision 8: one revision, one wire shape.
 *
 * In every revision the envelope stays deterministic CBOR (RFC 8949 4.2), the
 * PoW stays committed to the encoded bytes, and the signature / AEAD AAD stay
 * over the whole envelope minus hops, the nonce and the signature element
 * itself (a signature cannot cover itself; on a rotation both signature
 * elements are outside the new key's coverage and each is verified on its own
 * terms).
 */
#define CC_WIRE_VERSION 9

/*
 * Algorithm selection. The defaults are NIST category 3: ML-DSA-65 and
 * ML-KEM-768. Override CC_SIGN_LEVEL (2/3/5) and CC_KEM_LEVEL (512/768/1024)
 * on the build line, e.g. -DCC_SIGN_LEVEL=2 -DCC_KEM_LEVEL=512; every size
 * below follows from them, so a bump is a two-line change and the tests' size
 * assertions fail loudly if a derived size is wrong. Both knobs are
 * #ifndef-guarded so a build-line value wins (an unguarded #define would
 * silently discard -DCC_SIGN_LEVEL=2 with a redefinition warning).
 * CC_KEM_TYPE is derived, because wolfSSL's ML-KEM types are enum values and
 * cannot be tested in a preprocessor conditional.
 *
 * COSE identifiers, documented rather than left floating in code:
 *   ML-DSA-65 is -49 (draft-ietf-cose-dilithium-11, in AUTH48 as RFC 9964);
 *   AES-256-GCM is 3 (RFC 9053); HKDF-SHA-256 is 5 (RFC 9053).
 * Where COSE is actually used, precisely: ONLY the opportunistic chat payload
 * is COSE-structured (a COSE_Encrypt0 message under the KEM-derived key, with
 * the routing fields as external_aad). Everything else is raw primitives over
 * the canonical envelope: the announce and link_proof signatures are plain
 * ML-DSA signatures (there is no COSE_Sign1 anywhere in this format), and the
 * link records are plain AES-256-GCM ciphertext (there is no COSE_Encrypt0 in
 * the link layer). The codepoints above are documented so an implementation
 * that does want to re-wrap these keys in COSE uses the right identifiers.
 * No ML-KEM KEM ID is registered in HPKE — the ML-KEM HPKE draft expired and
 * draft-ietf-jose-pqc-kem still has TBD values — so the link handshake carries
 * an explicit suite byte (CC_SUITE) rather than an invented codepoint; see the
 * suite notes below.
 */
#ifndef CC_SIGN_LEVEL
#define CC_SIGN_LEVEL 3 /* ML-DSA-65 (NIST category 3) */
#endif
#ifndef CC_KEM_LEVEL
#define CC_KEM_LEVEL 768 /* ML-KEM-768 */
#endif
/* CC_KEM_TYPE is derived from CC_KEM_LEVEL in the size block below. */

/* ML-DSA sizes, keyed by CC_SIGN_LEVEL. */
#if CC_SIGN_LEVEL == 2 /* ML-DSA-44 */
#define CC_SIGN_PUBKEY_SZ 1312
#define CC_SIGN_PRIVKEY_SZ 2560
#define CC_SIGN_SIG_SZ 2420
#elif CC_SIGN_LEVEL == 3 /* ML-DSA-65 */
#define CC_SIGN_PUBKEY_SZ 1952
#define CC_SIGN_PRIVKEY_SZ 4032
#define CC_SIGN_SIG_SZ 3309
#elif CC_SIGN_LEVEL == 5 /* ML-DSA-87 */
#define CC_SIGN_PUBKEY_SZ 2592
#define CC_SIGN_PRIVKEY_SZ 4896
#define CC_SIGN_SIG_SZ 4627
#else
#error "CC_SIGN_LEVEL must be 2, 3 or 5"
#endif

/* ML-KEM sizes, keyed by CC_KEM_LEVEL. The wolfSSL ML-KEM types are enum
   values, not preprocessor macros, so the selector is a plain number and
   CC_KEM_TYPE is derived from it. */
#if CC_KEM_LEVEL == 512
#define CC_KEM_TYPE WC_ML_KEM_512
#define CC_KEM_PUBKEY_SZ 800
#define CC_KEM_PRIVKEY_SZ 1632
#define CC_KEM_CT_SZ 768
#elif CC_KEM_LEVEL == 768
#define CC_KEM_TYPE WC_ML_KEM_768
#define CC_KEM_PUBKEY_SZ 1184
#define CC_KEM_PRIVKEY_SZ 2400
#define CC_KEM_CT_SZ 1088
#elif CC_KEM_LEVEL == 1024
#define CC_KEM_TYPE WC_ML_KEM_1024
#define CC_KEM_PUBKEY_SZ 1568
#define CC_KEM_PRIVKEY_SZ 3168
#define CC_KEM_CT_SZ 1568
#else
#error "CC_KEM_LEVEL must be 512, 768 or 1024"
#endif
#define CC_KEM_SS_SZ 32

/* Seed sizes. Both are derived from wolfSSL's own macros rather than written
   as literals, and both are level-independent in this wolfSSL version: the
   ML-DSA private-key seed is 64 bytes at every ML-DSA level
   (DILITHIUM_PRIV_SEED_SZ), and ML-KEM's is the FIPS 203 (d, z) pair, two
   32-byte values, i.e. 2 * WC_ML_KEM_SYM_SZ = 64 bytes. */
#define CC_SIGN_SEED_SZ DILITHIUM_PRIV_SEED_SZ
#define CC_KEM_SEED_SZ (2 * WC_ML_KEM_SYM_SZ)

/* Derived sizes. Every buffer bound is a function of the parameter sizes above
   plus the protocol's fixed limits; nothing here is a magic number. */
#define CC_ADDR_SZ 16
#define CC_MAX_NAME_LEN 63
#define CC_MAX_META_SZ 256
#define CC_MAX_MSG_SZ 512
#define CC_LINK_ID_SZ 8
#define CC_PRES_NAME_HASH_SZ 8
/* Receiver-published PoW cost: one byte per directed type, in this order. */
#define CC_ADMIT_SZ 3
#define CC_ADMIT_CHAT 0
#define CC_ADMIT_LINK_REQ 1
#define CC_ADMIT_KEY_REQ 2
#define CC_POW_MAX \
  32 /* a digest is 32 bytes: a difficulty above this is invalid */
#define CC_POW_NONE \
  0 /* declaration only: "no preference, use your own policy" */
#define CC_PRES_BUF_SZ 96 /* max presence wire packet */
#define CC_KEY_REQ_BUF_SZ 32
#define CC_ANN_BUF_SZ                                                        \
  (CC_SIGN_PUBKEY_SZ + CC_KEM_PUBKEY_SZ + CC_SIGN_SIG_SZ + CC_MAX_NAME_LEN + \
   CC_MAX_META_SZ + CC_ADMIT_SZ + 256)
#define CC_CHAT_BUF_SZ (CC_SIGN_SIG_SZ + CC_KEM_CT_SZ + CC_MAX_MSG_SZ + 512)
#define CC_LINK_REQ_BUF_SZ (CC_KEM_CT_SZ + 96)
#define CC_LINK_PROOF_BUF_SZ (CC_SIGN_SIG_SZ + 96)
#define CC_LINK_DATA_BUF_SZ (CC_MAX_MSG_SZ + 128)
#define CC_LINK_IDENTIFY_BUF_SZ (CC_SIGN_SIG_SZ + 128)
/* A rotation costs one extra address and one extra signature on top of an
   announce; a revocation is an address, two ticks and a signature. */
#define CC_ROTATE_BUF_SZ (CC_ANN_BUF_SZ + CC_ADDR_SZ + CC_SIGN_SIG_SZ + 32)
#define CC_REVOKE_BUF_SZ (CC_ADDR_SZ + CC_SIGN_SIG_SZ + 96)
/* Working-context sizes: each the largest use of that role. */
#define CC_WORK_PT_SZ (CC_ADDR_SZ + CC_SIGN_SIG_SZ + 32)
#define CC_WORK_CT_SZ (CC_SIGN_SIG_SZ + 128)
#define CC_WORK_ID_SZ (CC_ADDR_SZ + CC_SIGN_SIG_SZ)
#define CC_WORK_SCRATCH_SZ (CC_PRE_SZ + 64)
#define CC_PRE_SZ                                                            \
  (CC_SIGN_PUBKEY_SZ + CC_KEM_PUBKEY_SZ + CC_MAX_NAME_LEN + CC_MAX_META_SZ + \
   160)

/*
 * Crypto suite byte, carried by the link handshake because no ML-KEM KEM ID is
 * registered in HPKE (the ML-KEM HPKE draft expired; draft-ietf-jose-pqc-kem
 * still has TBD values). The value is PROVISIONAL and identifies the full set
 * this build speaks: ML-KEM + HKDF-SHA-256 + AES-256-GCM + ML-DSA for the
 * responder proof. A handshake whose suite byte does not equal cc_suite() is
 * CC_E_SUITE. Add suites by appending, never renumbering.
 */
#define CC_SUITE 1

/* Link record kinds, authenticated inside the link AEAD (a record's kind, not
   the packet type, is what decides its meaning — the packet type is a hint). */
#define CC_LINK_KIND_DATA 0
#define CC_LINK_KIND_CLOSE 1
#define CC_LINK_KIND_KEEPALIVE 2
#define CC_LINK_KIND_IDENTIFY 3

/*
 * Proof-of-work difficulty, in leading zero bytes of the SHA-256 preimage.
 *
 * CC_POW_DIFFICULTY is the default for every type; the per-type values are the
 * knob that prices a small packet differently from a 4.5 KB one. They are
 * RECEIVER policy, and each is overridable at build time:
 *   - a receiver mines nothing, it only checks, so raising its own value
 *     rejects packets a laxer sender produced (CC_E_POW);
 *   - a sender mines at its own table, which is therefore also its cost;
 *   - defaults equal CC_POW_DIFFICULTY, so a build that sets only
 *     CC_POW_DIFFICULTY behaves exactly as before this knob existed.
 * Mining cost is linear in difficulty multiples of the preimage size, and the
 * preimage is the whole packet minus hops, so the price paid per packet is
 * proportional to the air time it occupies.
 *
 * Receiver-published cost (revision 9). The table above is what a node
 * ENFORCES; the announce's admit field is what a node ASKS FOR. The two are
 * different things and both matter:
 *
 *   - Enforcement is local and stays local. A receiver always checks against
 *     CC_POW_DIFFICULTY_<TYPE> from its own build (CC_POW_MIN in the layout),
 *     never against what a packet's sender declared. A stricter receiver
 *     therefore rejects with CC_E_POW what a laxer sender produced, and no
 *     field in any packet can lower a receiver's own bar.
 *   - The declaration is what this node tells senders to aim at. It is three
 *     bytes, one per DIRECTED type — chat, link_req, key_req, in that order —
 *     each 1..32, or CC_POW_NONE (0) for "no declared preference, use your own
 *     policy". It lives inside the signed coverage, so a peer cannot have it
 *     altered in flight.
 *   - A sender's price is max(peer declared, its own requirement), which is
 *     exactly what cc_admit_for() returns: paying less than the peer asked
 *     wastes the packet, paying less than your own build requires contradicts
 *     your own policy, and paying more is allowed but pointless.
 *   - Broadcast types declare nothing and ask no one: an announce or a
 *     presence packet has no single receiver to please, so both are mined at
 *     the sender's own configured difficulty. That is why admit covers only
 *     chat, link_req and key_req.
 *
 * Honesty about what this buys: it lets a node price admission to itself and
 * lets a sender pay the asked price. It does NOT make PoW a flood defence
 * against a fast link — an attacker on a laptop or a base station mines orders
 * of magnitude faster than a LoRa node can transmit, and difficulty is a
 * function of the packet's own size, so the cheapest attack is still a small
 * packet. Treat the declaration as congestion pricing and a speed bump, not a
 * barrier.
 *
 * Trust order: admit is covered by the announce signature, but the signature
 * is checked LAST, after the PoW the packet itself carries. A declaration is
 * therefore trustworthy only once cc_announce_parse()/cc_rotate_parse() has
 * returned CC_OK, and cc_admit_for() refuses to read one out of an announce
 * whose signature has not verified (CC_E_SIG; the parsed struct carries a
 * verified flag that only those two parsers set). Verify first, then mine.
 */
#ifndef CC_POW_DIFFICULTY
#define CC_POW_DIFFICULTY 2
#endif
#ifndef CC_POW_DIFFICULTY_ANNOUNCE
#define CC_POW_DIFFICULTY_ANNOUNCE CC_POW_DIFFICULTY
#endif
#ifndef CC_POW_DIFFICULTY_CHAT
#define CC_POW_DIFFICULTY_CHAT CC_POW_DIFFICULTY
#endif
#ifndef CC_POW_DIFFICULTY_PRESENCE
#define CC_POW_DIFFICULTY_PRESENCE CC_POW_DIFFICULTY
#endif
#ifndef CC_POW_DIFFICULTY_KEY_REQ
#define CC_POW_DIFFICULTY_KEY_REQ CC_POW_DIFFICULTY
#endif
#ifndef CC_POW_DIFFICULTY_LINK_REQ
#define CC_POW_DIFFICULTY_LINK_REQ CC_POW_DIFFICULTY
#endif
#ifndef CC_POW_DIFFICULTY_LINK_PROOF
#define CC_POW_DIFFICULTY_LINK_PROOF CC_POW_DIFFICULTY
#endif
#ifndef CC_POW_DIFFICULTY_ROTATE
#define CC_POW_DIFFICULTY_ROTATE CC_POW_DIFFICULTY_ANNOUNCE
#endif
#ifndef CC_POW_DIFFICULTY_REVOKE
#define CC_POW_DIFFICULTY_REVOKE CC_POW_DIFFICULTY_ANNOUNCE
#endif
/* Link data/identify/close packets carry no PoW: the handshake prices the
   link, and per-message work is the AEAD alone. Rotation and revocation are
   rare and are priced like an announce, so flooding them costs an attacker
   what flooding the traffic they displace would. */

#define CC_MSG_ANNOUNCE 0
#define CC_MSG_CHAT 1
#define CC_MSG_PRESENCE 2
#define CC_MSG_KEY_REQ 3
#define CC_MSG_LINK_REQ 4
#define CC_MSG_LINK_PROOF 5
#define CC_MSG_LINK_DATA 6
#define CC_MSG_IDENTIFY 7
#define CC_MSG_LINK_CLOSE 8
#define CC_MSG_ROTATE 9  /* new signing key, the old key co-signs continuity */
#define CC_MSG_REVOKE 10 /* retire my own identity (terminal) */
#define CC_MSG_COUNT 11

#define CC_OK 0
#define CC_E_ARG (-1)
#define CC_E_BUF (-2)
#define CC_E_CRYPTO (-3)
#define CC_E_FORMAT (-4)
#define CC_E_SIG (-5)
#define CC_E_POW (-6)
#define CC_E_DECRYPT (-7)
/* v0.5 additions; each one is a distinct action for the caller. */
#define CC_E_NOKEY                                         \
  (-8) /* sender key unknown, or not the claimed sender's: \
          the caller should ask for an announce (key_req) */
#define CC_E_REPLAY                                                           \
  (-9)                   /* counter already accepted: drop, do not re-process \
                          */
#define CC_E_STALE (-10) /* counter older than the replay window: drop */
#define CC_E_REVOKED \
  (-14) /* this address is retired: drop it, refuse links and rotations */
#define CC_E_VERSION (-11) /* not CC_WIRE_VERSION: another revision */
#define CC_E_NOLINK \
  (-12) /* link id unknown, closed, or expired: re-handshake */
#define CC_E_SUITE                                         \
  (-13) /* handshake suite byte != cc_suite(): peer speaks \
           another algorithm set */

/*
 * Replay window: one cc_replay_t per peer *and per traffic class*, caller-owned
 * and caller-persisted (32 bytes each, see below). cc_replay_check() takes the
 * peer address as well as the state, so passing the wrong peer's state is
 * caught with CC_E_ARG instead of silently accepting replays.
 *
 * The two classes MUST NOT share state:
 *   CC_REPLAY_AUTHED   chat. Only a FULLY authenticated packet may advance it —
 *                      signature, then AEAD tag, then the inner-sender
 *                      consistency check, which is why cc_chat_parse() owns it
 *                      entirely.
 *   CC_REPLAY_UNSIGNED presence and key_req, which are unauthenticated by
 *                      design (addr authenticity comes from a separate
 *                      announce). Deduped with cc_replay_check().
 *
 * Why separation is structural and not a matter of taste: anyone can mint a
 * presence packet claiming Alice's address for the price of one PoW. If that
 * packet shared a window with Alice's chat stream, counter 0xFFFFFFFF would
 * push the window past every future genuine chat from Alice, which the
 * receiver would then drop as CC_E_STALE — a denial that needs no key at all.
 * With separate states a spoofed unsigned packet can only affect the unsigned
 * window, and each API accepts only its own class (CC_E_ARG otherwise), so the
 * mistake cannot be made silently.
 *
 * Consequence to build on: an unsigned window can only suppress duplicates of
 * unsigned traffic. CC_E_STALE from an unsigned state means "old or duplicate
 * heartbeat, drop quietly" and is never evidence about that peer's chat
 * stream; whether a heartbeat is too old to be useful is the app's liveness
 * policy, not the library's.
 *
 * A counter is fresh, a replay, or stale:
 *   counter > high                 -> fresh, window advances
 *   high - CC_REPLAY_WINDOW < c <= high -> fresh iff its window bit is clear
 *   c <= high - CC_REPLAY_WINDOW   -> CC_E_STALE
 * Reordering within the window is accepted; anything outside is not.
 *
 * cc_chat_parse() peeks the window before decapsulation (so replays still cost
 * no ML-KEM work) and commits the advance only once the packet is fully
 * authenticated. A captured packet that has been re-tagged, truncated or
 * otherwise made to fail the tag therefore cannot consume the counter of the
 * genuine packet: the window never moves on a partially authenticated packet.
 *
 * Counter wrap is the caller's problem, and the library deliberately has no
 * guard for it: every uint32 value is a legitimate counter, so there is no
 * value to reject. The sane policy for a sender that reaches the end of its
 * counter space is to retire that identity (announce a fresh key) rather than
 * wrap, because after a wrapped (small) counter every receiver that saw the
 * high values answers CC_E_STALE and would treat the peer as permanently old.
 * A receiver needs no guard either: a small counter after a large one is stale
 * by definition, which is exactly the CC_E_STALE path above.
 */
#define CC_REPLAY_WINDOW 64

#define CC_REPLAY_UNSIGNED 0 /* presence/key_req: unauthenticated by design */
#define CC_REPLAY_AUTHED 1   /* chat: advanced only from a verified signature */

typedef struct {
  uint8_t addr[CC_ADDR_SZ]; /* peer this state belongs to */
  uint8_t cls;              /* CC_REPLAY_AUTHED or CC_REPLAY_UNSIGNED */
  uint8_t used;             /* 0 until the first counter is accepted */
  uint32_t high;            /* highest counter accepted so far */
  uint64_t seen; /* bit i set = counter (high - i) already accepted */
} cc_replay_t;   /* 32 bytes: field order keeps the padding down */

/*
 * cc_key_t embeds wolfSSL key structs directly (~13KB at category 3). On MCUs
 * and other small-stack targets: DECLARE AS STATIC OR GLOBAL, never as a stack
 * local.
 *
 * Identity = ML-DSA signing key (address derived from sign pubkey).
 * Encryption = ML-KEM key (used for key encapsulation: opportunistic chat and
 * the link handshake's initiator side).
 */
typedef struct {
  dilithium_key sign;
  KyberKey kem;
  /* The seeds the keys were derived from. wolfSSL can GENERATE a key from a
     seed but cannot hand the seed back out of an expanded key, for either
     algorithm, so the seeds are kept here if a caller wants to store 128 bytes
     instead of ~6.4 KB of expanded private material.

     Invariant, and it holds after every path in this library that can touch a
     cc_key_t: has_seed is 1 exactly when sign_seed/kem_seed are the seeds that
     reproduce sign and kem, and 0 otherwise. So:
       - cc_key_generate()  leaves 1 on success, and 0 on any failure (the seed
         fields are wiped at entry, before the first draw, so a failed generate
         can never leave the previous identity's seed exportable);
       - cc_key_import_seed() leaves 1 on success, 0 on failure;
       - cc_key_import()  (expanded form) leaves 0: that key's seed is
         unknowable, and cc_key_export_seed() reports it as CC_E_NOKEY rather
         than inventing one;
       - cc_key_free() leaves 0.
     Only those three may set has_seed to 1, and a future path that installs a
     different key or wipes one must clear it. */
  uint8_t sign_seed[CC_SIGN_SEED_SZ];
  uint8_t kem_seed[CC_KEM_SEED_SZ];
  uint8_t has_seed;
} cc_key_t;

/*
 * cc_announce_t. Static/global on embedded. The announce carries the sign and
 * KEM public keys plus a monotonic sequence number and an absolute expiry,
 * both signed, so a receiver drops an announce that is not newer than the one
 * it stored (cc_announce_fresh): that is announce dedup, anti-replay, and the
 * freshness signal relaying will need. A replay of an old announce can no
 * longer re-seed a stale peer view.
 *
 * Rotation and revocation (revision 8): the address is SHA-256(sign_pub)[0:16]
 * and this struct is what a caller caches per peer, so it is also the state a
 * rotation moves. cc_rotate_parse() fills one of these from a rotation packet
 * (the new identity) and cc_rotate_accept() applies the acceptance rule
 * against the cached one. The identity keeps its announce sequence space
 * across the move — the rotation must carry a strictly greater seq — which is
 * what makes a replayed rotation idempotent and a re-ordered one harmless.
 * Revocation is terminal for an address: cc_revoke_parse() verifies it and the
 * caller records it in a cc_revoked_t.
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
  uint32_t seq;    /* monotonic per-identity announce sequence */
  uint32_t expiry; /* absolute time (caller clock) after which it is stale */
  uint8_t prev_addr[CC_ADDR_SZ]; /* the address this identity rotated FROM,
                                    zero for a plain announce; it is the one
                                    field a caller must keep to check a later
                                    rotation against this entry */
  uint8_t admit[CC_ADMIT_SZ]; /* what this peer asks senders to mine for chat,
                                 link_req and key_req (CC_POW_NONE = no
                                 preference) — read it with cc_admit_for() */
  uint8_t verified;           /* set by cc_announce_parse/cc_rotate_parse once
                                 the signature verified; a hand-filled struct
                                 has 0 and cc_admit_for() refuses to read a
                                 declaration out of one */
} cc_announce_t;

/*
 * cc_presence_t is a small liveness hint — safe on stack, ~1 LoRa fragment.
 *
 * IT ASSERTS NOTHING. It is unauthenticated by design, and its ONLY trusted
 * output is "an address I already hold a signed announce for is still
 * transmitting". It carries the address and a name_hash — SHA-256 of the name
 * in that announce, truncated to 8 bytes — so the receiver can check the claim
 * against its cached announce (cc_presence_matches_announce) instead of
 * trusting a name the packet cannot authenticate. It is a first-contact and
 * liveness hint for discovery (unknown address -> key_req -> announce), never
 * identity, and its seq is the same best-effort freshness signal the PoW
 * counters were: dedup it with a CC_REPLAY_UNSIGNED window.
 */
typedef struct {
  uint8_t addr[CC_ADDR_SZ];
  uint8_t name_hash[CC_PRES_NAME_HASH_SZ];
  uint8_t hops;
  uint32_t seq;
} cc_presence_t;

typedef struct {
  uint8_t sender_addr[CC_ADDR_SZ];
  uint8_t msg[CC_MAX_MSG_SZ];
  size_t msg_len;
  uint8_t hops;
  uint32_t counter;
} cc_chat_t;

/*
 * Per-link session state, caller-owned, heap-free, and caller-persisted if the
 * app wants links to survive a restart. 168 bytes at the category-3 default
 * (asserted by the tests).
 *
 * A link is bidirectional and forward-secret: the AES keys come from a fresh
 * ML-KEM encapsulation per link, derived per RFC 9180 section 5.1, and are
 * forgotten on close/idle-expiry, so a later compromise of the long-term key
 * does not decrypt recorded link traffic. tx_seq/rx_seq are the replay
 * defence (the AEAD nonce embeds them), rx_seen is a 64-slot window so modest
 * reordering is accepted; the link key is the authentication, so there is no
 * per-message signature and no per-message PoW.
 *
 * Sending invariant: tx_seq advances the moment a ciphertext exists (right
 * after the AEAD call), not after the envelope is encoded, so a failed encode
 * can waste a sequence but can never leave a (key, nonce) pair reusable. The
 * wire bound for a link record's ciphertext is derived from the RECEIVER's
 * plaintext buffer, not from the spare room in cc_work_t: GCM writes the
 * plaintext before it checks the tag, so a longer record would be an
 * out-of-bounds write on unauthenticated input.
 *
 * Capacity: 8 concurrent links ~ 1.1 KiB, 16 links ~ 2.2 KiB, 64 links ~ 8.7
 * KiB — trivial against the ~13 KB of one cc_key_t.
 */
typedef struct {
  uint8_t id[CC_LINK_ID_SZ];
  uint8_t peer[CC_ADDR_SZ];
  uint8_t tx_key[32];
  uint8_t rx_key[32];
  uint8_t tx_salt[3];
  uint8_t rx_salt[3];
  uint8_t role;  /* 0 initiator, 1 responder */
  uint8_t state; /* 0 pending, 1 open; anything else = forgotten */
  uint8_t suite;
  uint8_t used;
  uint8_t th[32]; /* handshake transcript hash: the initiator keeps it until a
                     proof verifies, so kem_ct need not be retained */
  uint32_t last_seen; /* caller clock ticks, set on every send/recv */
  uint32_t expiry;    /* idle timeout in ticks, caller policy */
  uint64_t tx_seq;
  uint64_t rx_seq;  /* highest accepted rx sequence */
  uint64_t rx_seen; /* bit i set = sequence (rx_seq - i) already accepted */
} cc_link_t;

#define CC_LINK_ROLE_INITIATOR 0
#define CC_LINK_ROLE_RESPONDER 1
#define CC_LINK_STATE_PENDING 0
#define CC_LINK_STATE_OPEN 1

/*
 * Caller-owned working context: every buffer and temporary the implementation
 * needs, so the library keeps NO mutable global state and is reentrant.
 *
 * OWNERSHIP AND THREADING: one context per thread or per concurrent caller
 * (declare it static or global on an MCU — never on a stack, it is tens of
 * kilobytes). Two contexts are completely independent: A can build a packet
 * while B parses one, or the same operations can be interleaved, with results
 * identical to sequential use. Nothing in the library is shared between calls
 * once a context is passed in, so the same context can also be used from
 * several call sites of one thread, one call at a time.
 *
 * The fields are sized from the parameter macros, so the context follows
 * CC_SIGN_LEVEL/CC_KEM_LEVEL with no edits of its own. Its contents are
 * scratch: the library wipes the parts that hold plaintext on the way out, and
 * cc_work_free() clears the whole thing at teardown.
 *
 * cc_key_t, cc_replay_t and cc_link_t remain caller-owned state, as before:
 * the context is scratch, those are the caller's durable objects.
 */
typedef struct {
  uint8_t pre[CC_PRE_SZ];       /* covered bytes: AEAD AAD, signature
                                   preimage, handshake transcript, and
                                   the HPKE labelled-construction
                                   scratch */
  uint8_t sig[CC_SIGN_SIG_SZ];  /* signature being built */
  uint8_t pt[CC_WORK_PT_SZ];    /* plaintext: chat payload or link record */
  uint8_t ct[CC_WORK_CT_SZ];    /* ciphertext: COSE Encrypt0 blob (chat) or
                                   raw AEAD link record */
  uint8_t id[CC_WORK_ID_SZ];    /* identify record payload: addr ‖ sig */
  uint8_t kem_ct[CC_KEM_CT_SZ]; /* handshake ciphertext, kept for the
                                   transcript until the proof is checked */
  uint8_t scratch[CC_WORK_SCRATCH_SZ]; /* wolfCOSE Enc_structure scratch */
  dilithium_key verify_key; /* ML-DSA key used to verify a signature */
  KyberKey kem_tmp;         /* ML-KEM temporary (decapsulate uses the
                               caller's own key) */
} cc_work_t;

/* Clear a context (call it at teardown, or after a key change). */
void cc_work_free(cc_work_t* w);

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
/* Seed form. The canonical FIPS 204 / FIPS 203 form of these keys is a seed
   that the key is re-derived from at load, not the expanded key material, and
   the reference firmware writes that: its identity file is a 1-byte form field,
   the two 64-byte seeds and the sign public key - 2081 bytes of payload, 2090
   bytes of file with its 9-byte envelope - keeping the expanded form only as
   the fallback for a seedless identity (an expanded cc_key_import(), or a file
   that predates the seed form): the same form byte plus CC_SIGN_PRIVKEY_SZ 4032
   + CC_SIGN_PUBKEY_SZ 1952 + CC_KEM_PRIVKEY_SZ 2400 = 8385 bytes of payload,
   8394 bytes of file. Both figures include the form byte; the key material
   alone is 2080 and 8384.

   What this library offers a caller is the key material. Measured at
   ML-DSA-65/ML-KEM-768 (CC_SIGN_SEED_SZ 64, CC_KEM_SEED_SZ 64):

     seeds + sign_pub                             2080 bytes  (the app's form)
     seeds + sign_pub + kem_priv                  4480 bytes  (-47% vs 8384)
     seeds + kem_priv, sign_pub re-derived        2528 bytes  (-70% vs 8384)

   The first is what the app's seed form carries. The other two are layouts a
   caller could choose instead: keeping kem_priv avoids re-deriving the KEM key
   on every load, and dropping sign_pub works because cc_key_export_public()
   recovers both public keys from a seed-imported key - but that gives up the
   cross-check that the seed still agrees with the signature key a peer has
   pinned, so a caller that cares about that keeps it.

   cc_key_generate() produces a key WITH its seeds, so a freshly generated
   identity can always be exported this way. A key loaded with cc_key_import()
   (the expanded form) has no knowable seed: cc_key_export_seed() returns
   CC_E_NOKEY for it. Neither wolfSSL nor this library can recover a seed from
   an expanded key, so a key that must be storable in seed form has to be
   created or joined in seed form in the first place.

   Zeroisation: the seeds are secrets. They live in cc_key_t and are wiped by
   cc_key_free(); both functions here wipe their local copies on every path,
   and the caller owns the buffers it passed in and should wipe them too (the
   same contract cc_key_export_private() has). */
int cc_key_export_seed(const cc_key_t* key, uint8_t sign_seed[CC_SIGN_SEED_SZ],
                       uint8_t kem_seed[CC_KEM_SEED_SZ]);
int cc_key_import_seed(cc_key_t* key, const uint8_t sign_seed[CC_SIGN_SEED_SZ],
                       const uint8_t kem_seed[CC_KEM_SEED_SZ]);
void cc_key_free(cc_key_t* key);

/* Address = SHA-256(sign_pubkey)[0:16] */
int cc_addr_from_sign_pubkey(const uint8_t pub[CC_SIGN_PUBKEY_SZ],
                             uint8_t addr[CC_ADDR_SZ]);
int cc_addr_from_key(const cc_key_t* key, uint8_t addr[CC_ADDR_SZ]);

/*
 * cc_revoked_t is one retired identity, caller-owned like cc_replay_t: 28
 * bytes (16 address + 4 sequence + 4 expiry + 1 used + padding). A caller that
 * tracks revocations keeps one per retired peer (or an array of them) and asks
 * cc_revoked_check() before trusting anything from that address. The library
 * never holds this state and never refuses anything on its own: policy stays
 * in the caller.
 */
typedef struct {
  uint8_t addr[CC_ADDR_SZ];
  uint32_t seq;    /* announce sequence of the revocation that retired it */
  uint32_t expiry; /* caller horizon: now > expiry frees the record */
  uint8_t used;
} cc_revoked_t;

/*
 * Replay protection (see CC_REPLAY_WINDOW and the class notes above). Both
 * calls read and write only the caller's state, so they are reentrant like the
 * rest of the library: one cc_replay_t per peer, and one caller-owned
 * cc_work_t per thread for the entry points that need scratch (see below).
 *
 * cc_replay_check() is for CC_REPLAY_UNSIGNED states only, i.e. presence and
 * key_req: it returns CC_E_ARG for an authenticated state, because an AUTHED
 * window is advanced only from inside cc_chat_parse() after the signature
 * verified. That split is what stops spoofed heartbeat traffic from ageing out
 * a peer's chat stream.
 */
int cc_replay_init(cc_replay_t* st, const uint8_t addr[CC_ADDR_SZ],
                   uint8_t cls);
int cc_replay_check(cc_replay_t* st, const uint8_t addr[CC_ADDR_SZ],
                    uint32_t counter);

/*
 * Wire format, v7 — one CBOR array per packet.
 *
 * The normative element sequence, per type, is the CC_PKT_LAYOUT table in
 * src/cosechat.c. This is the reader's guide to that table (sizes are for the
 * category-3 default and follow the macros):
 *
 *   announce [ver, type=0, hops, nonce, sign_pub, kem_pub, name, meta, admit,
 *             seq, expiry, sig]
 *     Self-signed: the packet carries the signing key whose signature it
 *     carries; the address is SHA-256(sign_pub)[0:16]. meta is a CBOR map with
 *     namespaced keys (see below); seq and expiry are signed, and so is
 *     admit, the 3-byte declaration of what this node asks senders to mine to
 *     reach it (see the PoW cost note below). The signature is a raw ML-DSA
 *     signature over the covered envelope bytes, not a COSE_Sign1 message
 *     (the COSE scope note near the parameter block says exactly where COSE is
 *     and is not used, and lists the ML-DSA-65 / AES-256-GCM / HKDF-SHA-256
 *     identifiers).
 *
 *   chat     [ver, type=1, hops, sender, recipient, kem_ct, counter, nonce,
 *             encrypt0, sig]
 *     The OPPORTUNISTIC one-shot path: signed, addressed to a known peer, no
 *     forward secrecy. Cost: one 3309-byte signature per message (19 fragments
 *     at 248 bytes, ~7.6 s of SF7/125 kHz airtime). Use a link instead for a
 *     conversation.
 *
 *   presence [ver, type=2, hops, seq, nonce, addr, name_hash]
 *     Unauthenticated liveness/first-contact hint (see cc_presence_t).
 *
 *   key_req  [ver, type=3, hops, addr, seq, nonce]
 *     Target answers with its CC_MSG_ANNOUNCE.
 *
 *   link_req    [ver, type=4, hops, nonce, suite, link_id, kem_ct]
 *     Initiator encapsulates to the responder's long-term ML-KEM key. Unsigned
 *     (the initiator may be anonymous); PoW-priced.
 *
 *   link_proof  [ver, type=5, hops, nonce, suite, link_id, sig]
 *     Responder proves identity by signing the handshake transcript with its
 *     ML-DSA key. PoW-priced.
 *
 *   link_data   [ver, type=6, hops, link_id, seq, encrypt0]
 *     One AEAD record. No sender, recipient, KEM ct, signature or PoW: the
 *     link key authenticates, the sequence is the replay defence. ~1 fragment.
 *
 *   identify    [ver, type=7, hops, link_id, seq, encrypt0]
 *     Same shape as link_data; the plaintext is an identity record. The
 *     encoder emits this type for an identify record (it used to fall back to
 *     link_data); a receiver accepts either, because the authenticated record
 *     kind decides the meaning.
 *
 *   link_close  [ver, type=8, hops, link_id, seq, encrypt0]
 *     Same shape as link_data; the plaintext is a close record. The packet
 *     type is a hint — the authenticated record kind decides the meaning.
 *
 *   rotate   [ver, type=9, hops, nonce, new_sign_pub, new_kem_pub, name, meta,
 *             prev_addr, seq, expiry, new_sig, cont_sig]
 *     The statement an announce makes (keys, name, meta, seq, expiry) plus
 *     proof that the new key continues the old address: cont_sig is the old
 *     key's signature over SHA-256("cosechat/rotate" | suite | prev_addr |
 *     new_addr | new_sign_pub | new_kem_pub) and new_sig is the new key's
 *     signature over the covered envelope (both signature elements are outside
 *     that coverage; the PoW still covers everything but hops and the nonce).
 *     The announce itself is unchanged
 *     and carries nothing extra, so a rotation costs the second signature only
 *     when it happens.
 *
 *   revoke   [ver, type=10, hops, nonce, addr, seq, expiry, sig]
 *     "Retire this identity." Signed by the key that hashes to addr, so only
 *     the identity can retire itself; terminal for that address for as long as
 *     the receiver remembers it.
 *
 * The link record plaintext is [kind, payload_bstr]; kinds are
 * CC_LINK_KIND_DATA / CLOSE / KEEPALIVE / IDENTIFY. The AEAD nonce is
 * direction-byte ‖ salt ‖ 8-byte little-endian sequence, so the sequence is
 * the replay defence and the key is the authentication.
 *
 * link_id is 8 random bytes, carried alone on data packets. It is the only
 * thing a link data packet reveals on the wire (plus hops); setup still names
 * the responder, but an anonymous initiator stays anonymous until it sends an
 * identify record. Collisions: 8 bytes are ample for a mesh's live links, and
 * a receiver that does not recognise a link_id answers CC_E_NOLINK so the
 * initiator re-handshakes.
 *
 * announce metadata: a definite-length CBOR map, conventionally keyed by
 * "<namespace>:<key>" (namespaces are first-claim; this library defines none
 * yet and a reader MUST ignore keys it does not know). The field is optional
 * and at most CC_MAX_META_SZ. The library validates the WHOLE map, in both
 * directions: definite-length items only (nothing indefinite, and only the
 * minimal-head subset cb_head accepts), keys in canonical order (RFC 8949
 * section 4.2.1: shorter encoded key first, then bytewise), no duplicate keys,
 * and no trailing bytes after the map. A map that breaks any of these is
 * CC_E_ARG when built and CC_E_FORMAT when parsed, before the signature is
 * even checked. The map is signed and propagated, so a malformed one would be
 * a liability for every receiver; what the keys MEAN stays application data —
 * the library does not know the namespaces.
 *
 * Each field's kind AND size contract lives in CC_PKT_LAYOUT and is enforced in
 * both directions: a signature is exactly CC_SIGN_SIG_SZ, kem_ct exactly
 * CC_KEM_CT_SZ, encrypt0 at most its derived bound, a name at most
 * CC_MAX_NAME_LEN, meta at most CC_MAX_META_SZ, the announce public keys
 * exactly CC_SIGN_PUBKEY_SZ/CC_KEM_PUBKEY_SZ, and every address exactly
 * CC_ADDR_SZ. A packet that breaks any of these is CC_E_FORMAT at decode,
 * before anything copies, hashes or signs it.
 *
 * Canonical form (RFC 8949 section 4.2, deterministic encoding): the envelope
 * is a definite-length array of unsigned integers, byte strings and text
 * strings, each with a minimal-length head, and it is exactly the array — no
 * trailing bytes. The reader rejects anything else with CC_E_FORMAT, so a
 * packet has exactly one valid byte string. That is what makes it sound to
 * take the PoW and the signature over the bytes on the wire.
 *
 * Coverage — one rule, the same for every type:
 *
 *   hops and the nonce are the ONLY elements outside these preimages, and each
 *   is outside for a reason: hops must stay mutable so a relay can re-stamp it
 *   (cc_hops_increment), and the nonce is what the PoW searches over, so it
 *   cannot be fixed before mining and is bound by the PoW instead of by the
 *   signature and the tag. Everything else is covered. Link data packets have
 *   no signature and no PoW: their coverage is the AEAD tag over the whole
 *   record, with hops still outside it (a relay may re-stamp the hops of a
 *   link packet too).
 *
 *   PoW (announce, chat, presence, key_req, link_req, link_proof), over the
 *   packet's own bytes:
 *     SHA-256(packet bytes with the hops and nonce elements removed
 *              ‖ nonce_le32),
 *     and its first CC_POW_DIFFICULTY_<TYPE> bytes must be zero. The handshake
 *     is where a link is priced; link_data/identify/close carry no PoW.
 *
 *   Signature (announce, chat): over the same bytes without the nonce trailer
 *   and without the signature itself. link_proof's signature is instead over
 *   the handshake transcript (see the key schedule below).
 *
 *   AEAD AAD (chat): the covered elements that exist when the tag is computed
 *   — everything except hops, the nonce, the ciphertext and the signature.
 *   link_data/identify/close use the nonce described above instead.
 *
 * hops is the only mutable element: a relay may re-stamp it without re-mining,
 * which is what makes multi-hop forwarding affordable. It is covered by
 * nothing — not the PoW, not the signature, not the AEAD — and MUST NOT be
 * trusted for anything but stale/loop suppression.
 *
 * Link key schedule — RFC 9180 section 5.1 (mode_base, no PSK), adapted because
 * no ML-KEM KEM ID is registered in HPKE (the ML-KEM HPKE draft expired and
 * draft-ietf-jose-pqc-kem still has TBD values), so the handshake carries an
 * explicit suite byte instead of a codepoint. With dh = the ML-KEM shared
 * secret, kem_context = the KEM ct, info = the handshake transcript:
 *
 *   suite_id     = "cosechat-v7" ‖ suite_byte
 *   transcript   = "cosechat/link" ‖ suite ‖ link_id ‖ kem_ct ‖
 * responder_addr eae_prk      = LabeledExtract("", "eae_prk", dh) shared =
 * LabeledExpand(eae_prk, "shared_secret", kem_context, 32) secret       =
 * LabeledExtract(shared, "secret", "") ks_ctx       = mode(0x00) ‖
 * LabeledExtract("", "psk_id_hash", "") ‖ LabeledExtract("", "info_hash", info)
 *   key_i2r      = LabeledExpand(secret, "key_i2r", ks_ctx, 32)
 *   salt_i2r     = LabeledExpand(secret, "salt_i2r", ks_ctx, 3)
 *   key_r2i      = LabeledExpand(secret, "key_r2i", ks_ctx, 32)
 *   salt_r2i     = LabeledExpand(secret, "salt_r2i", ks_ctx, 3)
 *
 *   LabeledExtract(salt,label,ikm) = Extract(salt, "HPKE-v1" ‖ suite_id ‖ label
 * ‖ ikm) LabeledExpand(prk,label,info,L) = Expand(prk, I2OSP(L,2) ‖ "HPKE-v1" ‖
 * suite_id ‖ label ‖ info, L)
 *
 * The responder's proof signature is ML-DSA over `transcript`, verified against
 * its announced key; the initiator's keys stay unusable until that proof
 * verifies. Per-direction keys and salts are the RFC 9180 shape (labelled
 * DeriveSecret outputs), extended with a direction label because the base
 * mode yields a single key. The per-message nonce is direction(1) ‖ salt(3) ‖
 * sequence(8 LE). The exporter_secret of section 5.1 is not used here.
 *
 * Reentrancy and threading: the implementation holds NO mutable global state.
 * Every entry point that needs working memory takes a caller-owned cc_work_t
 * as its first argument, so the library is reentrant: one context per thread
 * or per concurrent caller, and two contexts never interact. The only state
 * the library keeps between calls is the caller's own: cc_key_t, cc_replay_t,
 * cc_link_t and, of course, the packets. The decoder-style helpers that need
 * no working memory (cc_msg_type, cc_msg_hops, cc_msg_recipient,
 * cc_chat_sender, cc_link_id, cc_pow_verify, cc_hops_increment,
 * cc_announce_fresh, cc_name_hash, cc_presence_matches_announce, cc_suite,
 * cc_replay_init, cc_replay_check, cc_link_forget, cc_link_active) take no
 * context, and neither do the key and address helpers.
 */

int cc_announce_build(cc_work_t* w, const cc_key_t* key, const char* name,
                      size_t name_len, const uint8_t* meta, size_t meta_len,
                      const uint8_t* admit /* CC_ADMIT_SZ bytes, or NULL to
                                              declare this build's own
                                              requirements */
                      ,
                      uint32_t seq, uint32_t expiry, uint8_t* out,
                      size_t out_sz, size_t* out_len, WC_RNG* rng);
/* Fill a declaration with this build's own per-type requirements
   (CC_POW_DIFFICULTY_CHAT / _LINK_REQ / _KEY_REQ). */
void cc_admit_default(uint8_t admit[CC_ADMIT_SZ]);
/* The difficulty a sender should mine for this peer and this type:
   max(peer's declared cost, this build's own requirement) — the peer's price
   when it asked for more than this build would have mined anyway, and this
   build's own requirement when the peer declared CC_POW_NONE. CC_E_ARG for a
   broadcast type (announce, presence, link_data, identify, link_close, rotate
   and revoke have no single receiver to please), CC_E_SIG for an announce
   whose signature has not verified: the declaration is inside the signed
   coverage, but it is only trustworthy once that signature checks out, so
   verify first and mine second. A NULL announce means "no peer yet". */
int cc_admit_for(const cc_announce_t* ann, uint8_t type,
                 uint8_t* difficulty_out);
int cc_announce_parse(cc_work_t* w, const uint8_t* in, size_t in_sz,
                      cc_announce_t* ann);
/* The announce dedup / anti-replay / freshness rule: `fresh` is usable only if
   its sequence is newer than `known`'s (0 for an unknown peer) and `now` has
   not passed its expiry. CC_OK to use, CC_E_STALE to drop. */
/*
 * Identity rotation (revision 8). A node that rotates its ML-DSA signing key
 * publishes a rotation: the new identity, plus a signature by the OLD key over
 * a domain-separated statement binding
 *
 *   prev_addr -> new_addr, new_sign_pub, new_kem_pub
 *
 * so a peer that already holds the old address learns that the new address is
 * the same node and can move its trust (cached announce, name, replay state,
 * sequence high-water) across. A peer that does not know the old address
 * simply ignores the rotation and waits for the new identity's own announce.
 *
 * Wire (type 9, 13 elements):
 *   [ver, type, hops, nonce, new_sign_pub, new_kem_pub, name, meta,
 *    prev_addr, seq, expiry, new_sig, cont_sig]
 *
 *   new_sig   ML-DSA by the NEW key over the covered envelope (everything
 *             except hops, the nonce and the two signature elements: each
 *             signature authenticates itself, and the fields they are ABOUT
 *             are all covered).
 *   cont_sig  ML-DSA by the OLD key over the 32-byte continuity statement,
 *             which is not the envelope:
 *               SHA-256("cosechat/rotate" | suite | prev_addr(16)
 *                       | new_addr(16) | new_sign_pub | new_kem_pub)
 *   prev_addr SHA-256(old sign pub)[0:16]; new_addr is derived from
 *             new_sign_pub and bound by the statement, so a key that does not
 *             hash to the address the old key vouched for cannot be smuggled
 *             in, in either direction.
 *
 * cc_rotate_prev_addr() is the cheap peek a caller needs to find its cache
 * entry (no crypto); cc_rotate_parse() then verifies both signatures against
 * the key it holds for prev_addr; cc_rotate_accept() is the one acceptance
 * rule (the rotation must continue the identity we hold, its seq must be
 * strictly newer, it must not be expired, and its predecessor must not be
 * retired), mirroring cc_announce_fresh().
 *
 * Revision 8's first cut left the revocation half of that rule in prose only,
 * and the gap was real: a caller that recorded a revocation of X and then
 * accepted a rotation from X would trust the successor A while distrusting X —
 * exactly backwards for the leaked-key case revocation exists for. The rule is
 * now structural: cc_rotate_accept() takes the caller's cc_revoked_t (NULL if
 * the caller keeps none, which is a weaker configuration and is documented as
 * such) and returns CC_E_REVOKED — distinct from CC_E_STALE, so a caller can
 * count refusals that a revocation caused — for a rotation whose prev_addr is
 * retired.
 *
 * Ordering and the shape of the lifecycle, as the app must implement it:
 *   1. REVOCATION TERMINATES THE IDENTITY CHAIN. Neither order of revoke and
 *      rotate yields a trusted successor, and that is the property, not a
 *      puzzle: rotate-then-revoke gets the successor dropped by rule 4 below,
 *      and revoke-then-rotate is refused by cc_rotate_accept() with
 *      CC_E_REVOKED. A revoked node that wants to keep operating publishes a
 *      FRESH IDENTITY — a new keypair, a normal announce and no continuity
 *      claim at all — and its peers learn it the way they learn any stranger.
 *   2. So the operator order is ROTATE FIRST, THEN REVOKE: rotate while the
 *      old key is still trustworthy, then retire it. Or revoke and start
 *      fresh. A revocation is a tombstone for the whole chain, not a step in a
 *      handover, so do not revoke a key you intend to rotate away from.
 *   3. To accept a rotation, check the predecessor's retirement first (the
 *      revoked argument above), then the signatures, then the rule — and only
 *      for a peer the caller already holds (have != NULL), or a successor with
 *      no entry behind it is trusted on the strength of a predecessor that was
 *      never verified.
 *   4. When a revocation of X is recorded, drop every entry whose address or
 *      prev_addr is X: a successor that arrived as a rotation from X before the
 *      revocation landed is otherwise still trusted, and its prev_addr field
 *      is what lets the caller find it.
 *   5. A rotation moves the replay window too (cc_replay_move below). A
 *      successor that carries its counter space across passes
 *      CC_REPLAY_CONTINUES with the last counter the predecessor was accepted
 *      at — what a rotating node should do, and what the reference app does. A
 *      successor that restarts its counters is dropped as CC_E_STALE until it
 *      passes the old high-water, so it must either continue them
 *      (deliberately, with floor 0 meaning "counter 1 upward") or be a fresh
 *      identity as in rule 1; CC_REPLAY_RESTARTS is for state that was
 *      genuinely lost, and it takes on one replay opportunity, as that
 *      function's own note says.
 *
 * Residual, stated plainly because no number of extra signatures fixes it:
 * continuity is proven by signatures, so a holder of the old private key can
 * mint a successor its peers will trust. Refusing rotations from retired
 * predecessors closes that door only if the revocation reaches receivers
 * first, and only for as long as they remember it (see the revocation horizon
 * below). Treat a revoked-then-rotated identity as a compromise that has been
 * CONTAINED, not undone.
 *
 * Caller state: this library holds no peer directory, so what a caller keeps
 * per peer is exactly the state these rules need —
 *   cc_announce_t (3520 B at category 3, including the 16-byte prev_addr field
 *                  a rotation writes), cc_replay_t (32 B) and, if it tracks
 *                  revocations, cc_revoked_t (28 B): 3580 B per peer.
 * A rotation therefore adds no new per-peer allocation: the previous address
 * it must remember is one 16-byte field of the announce it already caches, and
 * the acceptance rule compares it against the address the entry is filed
 * under. Nothing else about a peer has to change when it rotates.
 *
 * Replay and downgrade: the rotation carries the node's own monotonic seq and
 * the receiver compares it against its cached announce, so replaying a
 * rotation is idempotent (CC_E_STALE, no state change), a rotation older than
 * what is stored cannot undo a later one, and a revoked identity is not
 * resurrected by replaying a rotation from it (the caller checks its
 * cc_revoked_t first).
 */
int cc_rotate_prev_addr(const uint8_t* pkt, size_t pkt_sz,
                        uint8_t prev_addr[CC_ADDR_SZ]);
int cc_rotate_build(cc_work_t* w, const cc_key_t* new_key,
                    const cc_key_t* old_key, const char* name, size_t name_len,
                    const uint8_t* meta, size_t meta_len, uint32_t seq,
                    uint32_t expiry, uint8_t* out, size_t out_sz,
                    size_t* out_len, WC_RNG* rng);
int cc_rotate_parse(cc_work_t* w, const uint8_t* in, size_t in_sz,
                    const uint8_t old_sign_pub[CC_SIGN_PUBKEY_SZ],
                    cc_announce_t* ann, uint8_t prev_addr[CC_ADDR_SZ]);
int cc_rotate_accept(const cc_announce_t* have, const cc_announce_t* rot,
                     const cc_revoked_t* revoked, uint32_t now);

/*
 * Revocation (revision 8). A node retires its OWN identity: the packet carries
 * an address and is signed by the key that hashes to it, so no one can revoke
 * anyone else, and a caller that passes the wrong cached key gets CC_E_NOKEY
 * rather than a false success.
 *
 * Wire (type 10, 8 elements): [ver, type, hops, nonce, addr, seq, expiry, sig]
 *
 * It is terminal for that address: a receiver drops the peer, refuses new
 * links to it, stops accepting its traffic, and refuses a rotation whose
 * prev_addr is retired. `seq` is the retired identity's announce sequence (so
 * an announce from the same address is recognisably older); `expiry` is the
 * caller's horizon for remembering the revocation, after which
 * cc_revoked_check() reports the address as free again — a deliberate bound on
 * state, and the reason a leaked key should be rotated away from rather than
 * merely revoked.
 *
 * The library holds no directory: cc_revoked_t is a caller-owned record (one
 * per retired peer, or a table of them) and cc_revoked_check() is the single
 * predicate a caller consults before trusting an announce, accepting a link,
 * parsing traffic from that address, or accepting a rotation from it as a
 * predecessor. It returns CC_E_REVOKED while the retirement stands and CC_OK
 * once the horizon has passed.
 *
 * Publish order matters, and it is the opposite of the obvious one: ROTATE
 * FIRST, THEN REVOKE. A revocation terminates the identity chain, so a node
 * that has been revoked continues with a fresh identity rather than a
 * successor (see the ordering rules in the rotation section above, including
 * what to drop when a revocation arrives late).
 */
int cc_revoke_build(cc_work_t* w, const cc_key_t* key, uint32_t seq,
                    uint32_t expiry, uint8_t* out, size_t out_sz,
                    size_t* out_len, WC_RNG* rng);
int cc_revoke_parse(cc_work_t* w, const uint8_t* in, size_t in_sz,
                    const uint8_t sign_pub[CC_SIGN_PUBKEY_SZ],
                    uint8_t addr[CC_ADDR_SZ], uint32_t* seq_out,
                    uint32_t* expiry_out);
int cc_revoked_init(cc_revoked_t* rv);
int cc_revoked_take(cc_revoked_t* rv, const uint8_t addr[CC_ADDR_SZ],
                    uint32_t seq, uint32_t expiry);
int cc_revoked_check(const cc_revoked_t* rv, const uint8_t addr[CC_ADDR_SZ],
                     uint32_t now);
int cc_revoked_forget(cc_revoked_t* rv);

/* How the successor's counter space relates to the one already seen. The
   choice is the caller's, and it has to be made explicitly because the two
   cases look identical from here. */
#define CC_REPLAY_CONTINUES 1 /* the successor kept counting */
#define CC_REPLAY_RESTARTS 0  /* the successor starts over at its own 1 */

/* Move replay state to a new address when an identity rotates.
 *
 * CC_REPLAY_CONTINUES: the successor carried its counter over (its own choice —
 * the counter is a signed field), so the newest accepted counter becomes
 * `floor`, is marked as seen, and everything below it ages out of the window
 * exactly as it would have at the old address. The node's last message cannot
 * be replayed into the new address.
 *
 * CC_REPLAY_RESTARTS: the successor is fresh state (a new device, a reset
 * counter), so no floor is meaningful and the window starts empty at the new
 * address. That knowingly accepts ONE replay opportunity — the successor's own
 * first message, if an attacker captured it — which is the honest cost of a
 * restart; traffic from the OLD address no longer verifies against the new key,
 * so nothing older than the successor is exposed. A node that can carry its
 * counter over should; a node that restarts deliberately can instead pass
 * CC_REPLAY_CONTINUES with floor 0, which marks the successor's counter 0 as
 * seen and accepts 1 upward.
 *
 * The old state's class is preserved either way, and the address is always
 * updated: after this call the old address's packets fail on the address
 * comparison, not on the window.
 *
 * Rule of thumb, and the reason both modes exist: a node that rotates carries
 * its counters across (CC_REPLAY_CONTINUES). A node whose counters restart is
 * either continuing them deliberately from zero or is a fresh identity with no
 * continuity claim at all — see rule 1 of the rotation ordering rules above. */
int cc_replay_move(cc_replay_t* st, const uint8_t addr[CC_ADDR_SZ],
                   uint32_t floor, uint8_t continues);

int cc_announce_fresh(const cc_announce_t* known, const cc_announce_t* fresh,
                      uint32_t now);

/*
 * Build a chat packet signed by sender_key, encapsulated to the recipient's
 * KEM key, with caller-supplied freshness counter.
 */
int cc_chat_build(cc_work_t* w, const cc_key_t* sender_key,
                  const uint8_t recipient_addr[CC_ADDR_SZ],
                  const uint8_t recipient_kem_pub[CC_KEM_PUBKEY_SZ],
                  uint32_t counter, const uint8_t* msg, size_t msg_len,
                  uint8_t difficulty /* 0 = this build's CC_POW_DIFFICULTY_CHAT;
                                       pass cc_admit_for()'s answer to pay the
                                       peer's price instead */
                  ,
                  uint8_t* out, size_t out_sz, size_t* out_len, WC_RNG* rng);
/*
 * Decrypt a chat packet. The caller MUST first check that the packet is
 * addressed to this node — cc_msg_recipient() is the intended filter, and
 * cc_chat_sender() gives the claimed sender for the peer lookup — and drop it
 * otherwise: this function deliberately does not compare the recipient field
 * against `my_key`, since the caller may route on it. Without the filter a node
 * spends ML-KEM decapsulation on traffic addressed to other peers; a forgery
 * cannot force that work at all, because the signature is checked first.
 *
 * sender_sign_pub is the claimed sender's announced ML-DSA key, looked up by
 * cc_chat_sender(). NULL, or a key that does not hash to the claimed address,
 * returns CC_E_NOKEY (the app should ask for an announce); a packet that
 * carries a valid-looking address but a bad signature returns CC_E_SIG.
 *
 * `replay` is required and MUST be a CC_REPLAY_AUTHED state for this sender
 * (CC_E_ARG otherwise): the window is advanced here, after the signature
 * verified, so no packet that fails authentication can age out this peer's
 * chat stream. Order of work: decode/version, PoW, sender key match, signature,
 * window peek (reject replays for free), ML-KEM decapsulation, AEAD,
 * inner-sender check, then the window commit — so replays cost no decapsulation
 * and no AEAD, and only a fully authenticated packet moves the window.
 */
int cc_chat_parse(cc_work_t* w, const cc_key_t* my_key,
                  const uint8_t sender_sign_pub[CC_SIGN_PUBKEY_SZ],
                  cc_replay_t* replay, const uint8_t* in, size_t in_sz,
                  cc_chat_t* chat);

/*
 * Presence — lightweight periodic heartbeat (~1 LoRa fragment, no signature).
 * counter must come from the caller (e.g. a persisted counter); feed the parsed
 * counter to cc_replay_check() with a CC_REPLAY_UNSIGNED state to reject
 * replays. That state is separate from the peer's chat window on purpose: a
 * spoofed heartbeat must not be able to age out chat traffic.
 */
int cc_presence_build(cc_work_t* w, const cc_key_t* key, const char* name,
                      size_t name_len, uint32_t seq, uint8_t* out,
                      size_t out_sz, size_t* out_len, WC_RNG* rng);
int cc_presence_parse(cc_work_t* w, const uint8_t* in, size_t in_sz,
                      cc_presence_t* p);
/* SHA-256(name)[0:CC_PRES_NAME_HASH_SZ], the value presence carries and the
   value an app computes from a verified announce's name. */
int cc_name_hash(const char* name, size_t name_len,
                 uint8_t out[CC_PRES_NAME_HASH_SZ]);
/* True only if a presence packet's address AND name_hash both match a verified
   announce; a mismatch means "ignore this hint", never "the peer changed". */
int cc_presence_matches_announce(const cc_presence_t* p,
                                 const cc_announce_t* ann);

/*
 * Key request — ask a node to re-send its full announce. Its counter is deduped
 * the same way as presence, in a CC_REPLAY_UNSIGNED state.
 */
int cc_key_req_build(cc_work_t* w, const uint8_t addr[CC_ADDR_SZ],
                     uint32_t counter,
                     uint8_t difficulty /* 0 = this build's default */,
                     uint8_t* out, size_t out_sz, size_t* out_len);
int cc_key_req_parse(cc_work_t* w, const uint8_t* in, size_t in_sz,
                     uint8_t addr[CC_ADDR_SZ], uint32_t* counter_out);

/* ---- Links ---- */

/* The crypto suite this build speaks (see CC_SUITE). */
uint8_t cc_suite(void);

/* Initiator: start a link to `peer` by encapsulating to its announced ML-KEM
   key. Emits a link_req; the link stays pending until cc_link_confirm() sees a
   proof. `now`/`idle_timeout` are caller-clock ticks and the idle policy. */
int cc_link_start(cc_work_t* w, cc_link_t* l,
                  const uint8_t peer_addr[CC_ADDR_SZ],
                  const uint8_t peer_kem_pub[CC_KEM_PUBKEY_SZ], uint32_t now,
                  uint32_t idle_timeout,
                  uint8_t difficulty /* 0 = this build's default */,
                  uint8_t* out, size_t out_sz, size_t* out_len, WC_RNG* rng);
/* Responder: process a link_req, decapsulate, derive the keys, and emit a
   link_proof signed with my_key. The link is open to the responder the moment
   this returns; the initiator's identity is unknown until an identify record.
 */
int cc_link_accept(cc_work_t* w, cc_link_t* l, const cc_key_t* my_key,
                   uint32_t now, uint32_t idle_timeout, const uint8_t* req,
                   size_t req_sz, uint8_t* out, size_t out_sz, size_t* out_len,
                   WC_RNG* rng);
/* Initiator: verify a link_proof against the peer's announced key; CC_OK opens
   the link, CC_E_SIG/CC_E_NOKEY otherwise. */
int cc_link_confirm(cc_work_t* w, cc_link_t* l,
                    const uint8_t peer_addr[CC_ADDR_SZ],
                    const uint8_t peer_sign_pub[CC_SIGN_PUBKEY_SZ],
                    const uint8_t* proof, size_t proof_sz);
/* Send one record (kind + payload) over an open link. DATA/CLOSE/KEEPALIVE. */
int cc_link_send(cc_work_t* w, cc_link_t* l, uint8_t kind,
                 const uint8_t* payload, size_t payload_len, uint32_t now,
                 uint8_t* out, size_t out_sz, size_t* out_len);
/* Receive one link packet. Returns the record kind in *kind_out and the
   payload; CC_E_NOLINK for an unknown/closed/expired link so the peer
   re-handshakes, CC_E_REPLAY / CC_E_STALE for the sequence window. */
int cc_link_recv(cc_work_t* w, cc_link_t* l, const uint8_t* in, size_t in_sz,
                 uint32_t now, uint8_t* kind_out, uint8_t* payload,
                 size_t payload_sz, size_t* payload_len);
/* Send an identify record proving my identity to the peer. */
int cc_link_identify(cc_work_t* w, cc_link_t* l, const cc_key_t* my_key,
                     uint32_t now, uint8_t* out, size_t out_sz, size_t* out_len,
                     WC_RNG* rng);
/* The link id a link packet carries, alone, for the caller's lookup. */
int cc_link_id(const uint8_t* pkt, size_t pkt_sz, uint8_t out[CC_LINK_ID_SZ]);

/* Verify an identify record's [addr ‖ signature] against the cached key. */
int cc_identify_verify(cc_work_t* w, const cc_link_t* l, const uint8_t* payload,
                       size_t payload_len,
                       const uint8_t peer_sign_pub[CC_SIGN_PUBKEY_SZ],
                       uint8_t addr_out[CC_ADDR_SZ]);
/* Send a close record; the link is forgotten on both sides. */
int cc_link_close(cc_work_t* w, cc_link_t* l, uint32_t now, uint8_t* out,
                  size_t out_sz, size_t* out_len);
/* Forget a link's state (either side may do this at any time). */
void cc_link_forget(cc_link_t* l);
/* Nonzero while the link is open and not idle-expired at `now`. */
int cc_link_active(const cc_link_t* l, uint32_t now);

/*
 * Routing helpers. cc_hops_increment() copies a packet with hops+1: hops is
 * the one element covered by nothing (see above), so the result stays valid
 * and neither the signature nor the AEAD tag is affected. Two caller duties:
 *   - `out` must have room for one byte MORE than the input: CBOR grows the
 *     hops unsigned int from 23 to 24 (1 byte to 2), so a packet built with
 *     hops=23 is not large enough in place;
 *   - `out` must not overlap `in`: the fields are read from `in` while `out` is
 *     written. Passing the same buffer is rejected with CC_E_ARG; any other
 *     overlap is a caller error.
 *   - the library imposes no hop limit. Deciding when a packet is too old to
 *     forward is consumer policy (a node with CC_MAX_HOPS drops on receive),
 *     except that hops == 255 returns CC_E_ARG since it cannot be incremented.
 *
 * cc_msg_type()/cc_msg_hops() decode only the array header and the leading
 * elements, so they also accept types this library does not implement (the
 * value is returned as-is, for routers to filter on) and packets truncated
 * after those elements. Both return CC_E_VERSION for a non-matching wire
 * revision, which is the cheap first filter. Everything else requires a
 * well-formed packet of a known type.
 */
int cc_msg_type(const uint8_t* pkt, size_t pkt_sz, uint8_t* type_out);
int cc_msg_hops(const uint8_t* pkt, size_t pkt_sz, uint8_t* hops_out);
int cc_msg_recipient(const uint8_t* pkt, size_t pkt_sz,
                     uint8_t addr[CC_ADDR_SZ]);
int cc_chat_sender(const uint8_t* pkt, size_t pkt_sz, uint8_t addr[CC_ADDR_SZ]);
int cc_hops_increment(const uint8_t* in, size_t in_sz, uint8_t* out,
                      size_t out_sz, size_t* out_len);
/* PoW, one rule in one place. The preimage is the encoded envelope minus hops
   and the nonce, and the difficulty is a parameter:
 *
 *   difficulty 0            this build's own CC_POW_DIFFICULTY_<TYPE> for the
 *                           packet's type (what cc_pow_verify() does)
 *   difficulty 1..CC_POW_MAX an explicit bar, e.g. the price a peer published
 *                           in its announce (cc_admit_for)
 *
 * A type that carries no nonce (link records) verifies trivially: there is
 * nothing to check. Anything else is refused with CC_E_POW, and a malformed
 * packet with CC_E_FORMAT / CC_E_VERSION exactly as cc_pow_verify() reports
 * them today. Any module that needs to check a packet against a difficulty
 * other than its own — the relay, enforcing a destination's declared
 * admission price — MUST call this rather than rebuilding the preimage: the
 * rule lives here, and a second copy of it silently mis-prices when the
 * envelope changes instead of failing to build.
 *
 * cc_pow_verify(pkt, sz) is exactly cc_pow_verify_at(pkt, sz, 0). */
int cc_pow_verify_at(const uint8_t* pkt, size_t pkt_sz, uint8_t difficulty);
int cc_pow_verify(const uint8_t* pkt, size_t pkt_sz);

#ifdef __cplusplus
}
#endif

#endif /* COSECHAT_H */
