// cosechat demo node — CardputerADV, on a road (`road_lora`, `road_wifi`,
// `road_ble` or `road_80211`).
//
// Default road is LoRa (M5 LoRa Cap 1262); build one of the other PlatformIO
// envs (wifi/ble/dot11) for a different road. The rest of the node is
// identical because the road hides framing and fragmentation.
//
//   Tab   = cycle peers        Enter = send chat to selected peer
//   Serial console: r rotate identity, x revoke it, n mint a new identity,
//   w wipe the card ('n' and 'w' ask for a confirmation key), p set or change
//   the store passphrase.
//
// SD, under /cc/, every file wrapped in a 9-byte magic+version+CRC envelope.
// The identity, the counter, the revocation list and each peer's replay window
// are additionally STORED SEALED: an AES-256-GCM container (magic "CCSP") whose
// key is derived from a passphrase typed on the device at boot, with NO
// recovery -- lose the passphrase and the identity is only recoverable by
// wiping the card and minting a new one.
//   key.bin         SEALED. <form byte><keys> -- the SEED form by default
//                   (sign_seed, kem_seed, sign_pub); the expanded form is
//                   written only for an identity that has no seed, i.e. one
//                   loaded from an expanded file.
//   counter.bin     SEALED. freshness counter, announce seq, retired flag
//   revoked.bin     SEALED. remembered retirements
//   peers/<addr_hex>.bin  PLAINTEXT. the cached announce (with a payload
//                   version byte). It is broadcast in the clear anyway, and
//                   keeping it readable is what lets the peer list be shown
//                   while the store is locked.
//   peers/<addr_hex>.rp   SEALED. that peer's two replay windows
// A card written before the store existed is still read as plaintext, and
// console 'p' seals it (that is the migration). The sealed files are opened by
// storeRead()/storeWrite() below and by nothing else; the plaintext of a
// container is the file exactly as it would be on a plaintext card, envelope
// and CRC included.
// Every peer's public keys are also cached in RAM; SD is the cold store.
//
// The SD card and the SX1262 share one SPI bus, so the demo creates a mutex
// and hands it to the LoRa road as `spi_mux`.

#include <Arduino.h>
#include <SD.h>
#include <SPI.h>
#include <esp_flash_encrypt.h>
#include <esp_secure_boot.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <stdarg.h>

#include "M5Cardputer.h"
#include "utility/PI4IOE5V6408_Class.hpp"

extern "C" {
#include "cosechat.h"
#include "cosechat_road.h"
#if defined(CC_RELAY)
#include "cosechat_relay.h"
#endif
#if defined(CC_ROAD_BLE)
#include "road_ble.h"
#elif defined(CC_ROAD_80211)
#include "road_80211.h"
#elif defined(CC_ROAD_WIFI)
#include "road_wifi.h"
#else
#include "road_lora.h"
#endif
#include <wolfssl/wolfcrypt/random.h>
/* The passphrase-encrypted store (see the layout note at the top of this file
 * and cc_store.h). Application policy, medium-free: it takes and returns byte
 * buffers, and every byte of the file I/O below is still this file's job. */
#include "cc_store.h"
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
#define SD_CS 12
#define KEY_FILE "/cc/key.bin"
// The key payload's first byte is its form, inside the CRC-covered payload (the
// envelope's version stays 1: the envelope is shared by six file kinds, so one
// file's payload gaining a shape byte is not an envelope change).
//   KEY_FORM_SEED:     form | sign_seed | kem_seed | sign_pub      (2081 B)
//   KEY_FORM_EXPANDED: form | sign_priv | sign_pub | kem_priv      (8385 B)
//
// The seed form is what this build writes: cc_key_generate() always produces
// seeds, and the two 64-byte seeds replace 4032 bytes of expanded signing key.
// It stores the KEM PRIVATE key neither as expanded bytes nor at all, and that
// is deliberate: both private keys are reconstructed from the seeds, so an
// expanded KEM key in the file would be a copy nothing can be checked against
// (the file stores no KEM public key to compare with, and validating one would
// need another 2400-byte scratch) -- an unverifiable 2400 bytes in the most
// exposure-sensitive file on the card. Deriving it instead removes the field
// and the hole with it. The sign_pub STAYS, because it is the one field that
// can be cross-checked cheaply: the seed must reproduce it, and it is also the
// preimage of the address every peer pins.
//
// The expanded form survives for exactly one case -- an identity imported from
// an expanded file has no recoverable seed (cc_key_export_seed() reports
// CC_E_NOKEY), so it can only be re-saved expanded. Writing that rather than
// skipping the save is what keeps "no seed" from becoming a silent hole:
// skipping would leave the PREVIOUS identity on the card while this node
// announces a new one. In that form the KEM half CANNOT be cross-checked (the
// payload carries no kem_pub); the sign half is, and the README says so.
#define KEY_FORM_SEED 1
#define KEY_FORM_EXPANDED 2
#define KEY_SEED_PAYLOAD_SZ \
  (1 + CC_SIGN_SEED_SZ + CC_KEM_SEED_SZ + CC_SIGN_PUBKEY_SZ)
#define KEY_EXP_PAYLOAD_SZ \
  (1 + CC_SIGN_PRIVKEY_SZ + CC_SIGN_PUBKEY_SZ + CC_KEM_PRIVKEY_SZ)
#define PEER_DIR "/cc/peers"
#define STATE_FILE "/cc/counter.bin" /* outbound freshness counter */

#define SPI_SCK 40
#define SPI_MISO 39
#define SPI_MOSI 14
#define SPI_CS 5 /* LoRa cap NSS; also the bus default CS */

#define MAX_PEERS 16
#define STATUS_H 16
#define ANNOUNCE_MS 60000UL
#define STATS_MS 30000UL /* road drop/tx counters log cadence */

// Persisted-state cadence. The outbound counter/seq and each peer's replay
// window are written at most this often: both live in RAM and only the saved
// copy lags, so a burst of sends cannot hammer the SD mutex. A failed write is
// not treated as saved, and STATE_SAVE_MIN_MS only bounds the retry rate.
// STATE_VERSION / REPLAY_VERSION tag the two on-disk formats.
#define STATE_SAVE_MS 5000UL
#define STATE_SAVE_MIN_MS 1000UL
#define REPLAY_SAVE_MS 5000UL
#define STATE_VERSION 3 /* v1 counter only; v2 added announce seq; v3 the
                           identity-retired flag (see revocationPublished) */
#define REPLAY_VERSION 1
#define PEER_VERSION 1 /* payload version of PEER_DIR/<hex>.bin */

// Link (session) layer. LINK_SESSION_MAX bounds concurrent sessions: this is a
// handheld with one selected peer at a time, so four covers the live
// conversation plus a handshake or two in flight, at 168 bytes each (672 B
// total) instead of the ~2.2 KiB sixteen would take. A fifth peer simply
// waits for a slot to free.
#define LINK_SESSION_MAX 4
// A responder-side handshake does NOT get a session slot. It is held in this
// tiny pending table with a short TTL and is only promoted into the session
// table once it has carried an authenticated record. Otherwise four
// unauthenticated link_reqs would fill the table, and because we keep our own
// links warm the junk would never idle out (the audit's reproducer):
// LINK_PENDING_MAX + LINK_PENDING_TTL_MS make a refused attacker's entry
// evaporate on its own.
#define LINK_PENDING_MAX 2
#define LINK_PENDING_TTL_MS 12000UL
// ...and responder-side links may hold at most this fraction of the session
// table, so our own outgoing handshakes can always find a slot.
#define LINK_RESPONDER_MAX 2
// Anonymous links are a deliberate library feature, but the reference app does
// not DISPLAY data from a link whose peer has not proven its identity with a
// verified identify record: an unauthenticated link_req must not buy a
// zero-PoW, unsigned message channel. Dropped records are counted. Set this to
// 0 to display them as [anon] instead (the library still supports it).
#define LINK_REQUIRE_IDENTIFY 1
// Idle policy. A link is dropped after LINK_IDLE_MS without any traffic in
// either direction, and we send a keepalive once it has been quiet for
// LINK_KEEPALIVE_MS so an open conversation does not needlessly re-handshake
// (a re-handshake costs a KEM decapsulation plus a signature at the peer). The
// values sit around the 60 s presence cadence: keepalives are cheaper than
// announces and do not disturb it.
#define LINK_IDLE_MS 180000UL
#define LINK_KEEPALIVE_MS 60000UL

// Handshake budget, applied before we do the responder's work (a KEM
// decapsulation plus an ML-DSA signature are the two most expensive things
// this node can be asked to do), so a link_req flood cannot turn the node into
// a signature oracle. Burst 4 per window: enough for a few peers to open
// sessions as they appear, far below what a flood produces.
#define LINK_ACCEPT_BURST 4
#define LINK_ACCEPT_WINDOW_MS 10000UL

// key_req limits, in both directions. A key_req is a small, unauthenticated,
// replayable byte string, and a presence is an unsigned ~30-byte packet that
// anyone in range can mint, so neither direction may run unbounded:
//   answering (REQ_ANSWER_*): one captured key_req would otherwise make this
//     node rebroadcast its whole ~6.5 KB signed announce on demand.
//   sending (REQ_SEND_*): a presence for an unknown address would otherwise
//     make this node emit one request per packet, turning it into an airtime
//     amplifier and luring real nodes into re-announcing.
// A key_req names only its target (us), so a node cannot tell two requesters
// apart: answers are budgeted globally, REQ_ANSWER_BURST per
// rolling REQ_ANSWER_WINDOW_MS. Outgoing requests are limited per address as
// well as globally, because the address asked about is on the wire.
#define REQ_ANSWER_WINDOW_MS 60000UL
#define REQ_ANSWER_BURST 4
#define REQ_SEND_MS 60000UL
#define REQ_SEND_WINDOW_MS 60000UL
#define REQ_SEND_BURST 4

// Inbound announce budget, applied BEFORE the ML-DSA verification. Parsing an
// announce is the most expensive per-packet work this node does, and an
// announce is unauthenticated until that verify succeeds, so a captured valid
// announce could otherwise be replayed at line rate to hold the receive path
// (announce mining is deliberately cheap here; see platformio.ini — replays
// pay no mining at all). The burst covers a whole peer table: if every node we
// know powers up together, all MAX_PEERS announces still land inside one
// window, while an attacker is held to MAX_PEERS verifies per window
// (16 per 4 s = 4/s sustained) instead of one per received packet.
#define ANN_VERIFY_BURST MAX_PEERS
#define ANN_VERIFY_WINDOW_MS 4000UL

// Inbound chat budget, spent BEFORE cc_chat_parse()'s ML-DSA-65 verification.
// A chat addressed to us from a cached sender costs one ML-DSA verify plus its
// replay window -- the most expensive per-packet work on a locally delivered
// packet -- and, unlike an announce, it is cheap to replay (a captured valid
// chat pays no mining), so on WiFi/802.11 an attacker can otherwise saturate
// the CPU at line rate. LoRa airtime (and the sender's mining) bounded it
// there; this bounds it everywhere. The trade-off is stated plainly: the burst
// also caps the legitimate chat rate, which is why it is generous -- a whole
// peer table, MAX_PEERS per 4 s (~4/s sustained), well above any human typing
// rate and well below a flood. A refused chat is dropped silently and counted
// (statChatDrop): it has already cost an address lookup, so drawing a line per
// refusal would hand an attacker the display.
#define CHAT_VERIFY_BURST MAX_PEERS
#define CHAT_VERIFY_WINDOW_MS 4000UL

// Identity control (rotation and revocation). A retired identity is remembered
// in a bounded table and persisted in one small file (REVOKED_MAX * 28 B plus a
// version byte), so a revocation survives a reboot for as long as the horizon
// says; expiry 0 means "remember indefinitely", which is the only horizon a
// node with no clock can honestly publish (the receiver compares the field
// against ITS clock).
#define REVOKED_MAX 8
#define REVOKED_FILE "/cc/revoked.bin"
#define REVOKED_VERSION 1
// ROTATE and REVOKE processing does real crypto (a rotation verifies two
// signatures), so it is budgeted like the announce verify: a flood of control
// packets claiming a predecessor we know must not pin the CPU.
#define CTL_VERIFY_BURST 4
#define CTL_VERIFY_WINDOW_MS 10000UL
// After rotating, the rotation packet is re-broadcast alongside our announce
// for this long, so peers that missed the first copy can still move their
// trust; after the grace period only the new identity is published.
#define ROTATE_GRACE_MS 300000UL

// A presence for a fresh address is cheap to mint and cannot be replay-checked
// (there is no window for an address we have never seen), so accepted presences
// are coalesced to at most one log line per PRES_LOG_MS: the canvas blit is
// ~45 KiB (232x99 at 16 bpp) and must not sit on an attacker's critical path.
#define PRES_LOG_MS 1000UL

// Client-side hop limit. The protocol does not enforce this; each node decides
// independently. Packets above this hop count are silently dropped rather than
// forwarded, preventing indefinite circulation in routing loops.
#define CC_MAX_HOPS 15

#if defined(CC_ROAD_BLE)
static const char NODE_NAME[] = "cc-ble";
#elif defined(CC_ROAD_80211)
static const char NODE_NAME[] = "cc-raw";
#elif defined(CC_ROAD_WIFI)
static const char NODE_NAME[] = "cc-wifi";

#ifndef WIFI_SSID
#define WIFI_SSID ""
#endif
#ifndef WIFI_PASS
#define WIFI_PASS ""
#endif
#else
static const char NODE_NAME[] = "cc-node";
#endif

// ---------------------------------------------------------------------------
// Hardware
// ---------------------------------------------------------------------------
m5::PI4IOE5V6408_Class ioe(0x43, 400000, &m5::In_I2C);
M5Canvas canvas(&M5Cardputer.Display);

// ---------------------------------------------------------------------------
// Road
// ---------------------------------------------------------------------------
#if defined(CC_ROAD_BLE)
static cc_road_ble_t roadImpl;
#elif defined(CC_ROAD_80211)
static cc_road_80211_t roadImpl;
#elif defined(CC_ROAD_WIFI)
static cc_road_wifi_t roadImpl;
#else
static cc_road_lora_t roadImpl;
#endif
static cc_road_t* road = &roadImpl.road;

static SemaphoreHandle_t spiMux;
static uint8_t rxPkt[CC_ROAD_PKT_BUF_SZ];

#if defined(CC_RELAY)
// The transmitting source the road attributed the packet rxPkt holds, captured
// with it in pumpRoad(). 0 length means "this medium cannot say" and must not
// be replaced by an address the packet itself claims.
static uint8_t rxSrc[CC_ROAD_SRC_SZ];
static uint8_t rxSrcLen = 0;
// PINNING, per road: the cosechat address a link-layer source speaks for. It is
// learned only from an announce that address itself sent at hops 0 (so it is
// signed by that address), and it is how the relay gets a neighbour ADDRESS for
// its next-hop table and for the hops==0 origin check on the two roads that
// attribute senders (802.11's MAC, WiFi's IPv4+port). It is not proof: an
// attacker who was there first, or who spoofs that source, still wins -- but it
// does refuse the cheap one-shot injection of a hops==0 announce from some
// other neighbour, which otherwise arrives with no evidence at all.
#define RELAY_PIN_MAX 8
// A pin TTL is a takeover window: once it lapses, whoever sends the next
// hops==0 announce for that address re-pins it. So it is derived from the
// module's own CC_RELAY_PATH_TTL (the hazard its path entries already document:
// an unrefreshed route is re-learned from whoever is heard first) rather than
// kept on a separate, possibly shorter clock. The relay's clock is seconds,
// hence the *1000.
#define RELAY_PIN_TTL_MS (CC_RELAY_PATH_TTL * 1000UL)
static uint32_t statRelayOrg =
    0; /* hops==0 announces refused for want of a pin */
static uint32_t statRelayRepin = 0; /* pins (re)taken, incl. after a lapse */
// NOTE for a mesh that mixes roads: a road that never attributes (ble, lora)
// can never pin anything, so a neighbour heard only over such a road stays
// reachable at hops >= 1 and never as a directly-checked origin.
static struct {
  uint8_t addr[CC_ADDR_SZ];
  uint8_t src[CC_ROAD_SRC_SZ];
  uint8_t src_len;
  uint32_t seen;
} relayPins[RELAY_PIN_MAX];
#endif

// ---------------------------------------------------------------------------
// Crypto / keys
// ---------------------------------------------------------------------------
static WC_RNG rng;
static cc_key_t myKey; /* ~13KB — static to stay off stack */
// The successor identity, live only while a rotation is being published (the
// old key must still exist to co-sign continuity). ~13 KB, so static.
static cc_key_t newKey;
static cc_chat_t tmpChat;
static cc_announce_t tmpAnn; /* scratch for RX parse and SD load */
// What this build asks senders to mine (cc_admit_default), published in our
// announce. The receive side never trusts a peer's declaration for anything:
// it always enforces its own configured CC_POW_DIFFICULTY_*.
static uint8_t myAdmit[CC_ADMIT_SZ];

// Working context for the library's reentrant entry points. Tens of KB, so it
// is static, never on the stack. ONE context is enough here because every
// library call is made from setup() or loop() (processPkt, pumpRoad,
// handleKeyboard, linkMaintain): the road's own tasks only touch the framing
// helpers in cosechat_road.c, which take no context and never call into this
// library, so nothing runs concurrently with these calls. cc_work_free(&work)
// is the teardown call; an Arduino sketch never returns from loop(), so the
// only teardown this node ever sees is a reboot (which clears RAM anyway).
static cc_work_t work;

static uint8_t myAddr[CC_ADDR_SZ];
// Whether this node has a usable identity. False only in two cases: the key
// file was present but did not load (damage -- see keyLoad() and setup()), or
// the operator wiped the card. While it is false the node is INERT: it
// announces nothing, sends nothing, answers nothing, and drops every packet
// before any work, so a damaged identity can never look like a new node to the
// mesh. The way out is explicit and confirmed: console 'n'.
static bool haveIdentity = false;

// ---------------------------------------------------------------------------
// Wire buffers
// ---------------------------------------------------------------------------
static uint8_t annBuf[CC_ANN_BUF_SZ];
static uint8_t chatBuf[CC_CHAT_BUF_SZ];
static uint8_t presBuf[CC_PRES_BUF_SZ];
static uint8_t keyReqBuf[CC_KEY_REQ_BUF_SZ];
// One TX scratch for every link packet (the biggest is an identify record) and
// one RX scratch for a link record payload (biggest is [addr ‖ signature]).
#define LINK_BUF_SZ CC_LINK_IDENTIFY_BUF_SZ
#define LINK_RECV_SZ CC_WORK_ID_SZ
static uint8_t linkBuf[LINK_BUF_SZ];
static uint8_t linkRx[LINK_RECV_SZ];
// Scratch for a published rotation or revocation (a rotation is larger than an
// announce), and the relay's re-broadcast buffer: one byte more than the
// largest packet it will hand back.
static uint8_t ctlBuf[CC_ROTATE_BUF_SZ];
#if defined(CC_RELAY)
static uint8_t relayBuf[CC_ANN_BUF_SZ + 1];
#endif

// ---------------------------------------------------------------------------
// Link table (sessions) and the pending handshake table. State is caller-owned;
// nothing is persisted, so a reboot forgets links and the peers simply
// re-handshake.
// ---------------------------------------------------------------------------
static cc_link_t links[LINK_SESSION_MAX];
// Responder-side handshakes waiting for their first authenticated record. A
// session slot is only ever maintained while its peer is known (see
// linkMaintain), which is what stops an unauthenticated request from being kept
// warm indefinitely.
static cc_link_t linkPend[LINK_PENDING_MAX];

#if defined(CC_RELAY)
// Relay state (a few KB, see CC_RELAY_* in platformio.ini). It only ever
// rewrites hops; link traffic is never offered to it (a link record carries no
// destination, and a link only exists between direct peers).
static cc_relay_t relay;
#endif

// ---------------------------------------------------------------------------
// Peer cache (addrs, names and public keys in RAM; full announce on SD)
// ---------------------------------------------------------------------------
static uint8_t peerAddrs[MAX_PEERS][CC_ADDR_SZ];
static char peerNames[MAX_PEERS][CC_MAX_NAME_LEN + 1];
static uint32_t peerHashes[MAX_PEERS]; /* announce content hash */
// Public keys are kept in RAM with the peer entry: the receive path must never
// touch SD (an SD read holds spiMux, which the radio also needs, so a forged
// chat could otherwise stall reception and wear the card). ~3.1 KB x 16
// peers; SD stays the cold store, read at boot and written on change.
static uint8_t peerSignPub[MAX_PEERS][CC_SIGN_PUBKEY_SZ];
static uint8_t peerKemPub[MAX_PEERS][CC_KEM_PUBKEY_SZ];
static uint32_t
    peerSeq[MAX_PEERS]; /* fresh announce seq of the cached announce */
// What the peer asked senders to mine (the announce `admit` bytes), and the
// address it rotated FROM (zero for a plain announce). prev_addr is what lets a
// revocation that arrives late find a successor we already trusted.
static uint8_t peerAdmit[MAX_PEERS][CC_ADMIT_SZ];
static uint8_t peerPrevAddr[MAX_PEERS][CC_ADDR_SZ];
static int peerCount = 0;
static int peerSel = -1;

// Recent retirements, one cc_revoked_t per retired identity (28 B) plus a
// version byte in one small file. Persisted: a revocation that a reboot forgot
// would let a retired identity walk straight back in.
static cc_revoked_t revoked[REVOKED_MAX];

// NOT an announce: a deliberately partial cc_announce_t, filled only so the
// library's two stateless predicates (cc_announce_fresh, cc_presence_matches_
// announce) have something to read. Only addr, name/name_len, seq and expiry
// are set; the keys and meta are empty, and nothing here may be handed to a
// function that treats it as a real announce. It exists because keeping
// sixteen ~3.5 KB announces in RAM would not fit; the peer cache holds the
// fields the predicates need.
static cc_announce_t annCheckView;
static void annCheckFill(int i) {
  memcpy(annCheckView.addr, peerAddrs[i], CC_ADDR_SZ);
  strncpy(annCheckView.name, peerNames[i], CC_MAX_NAME_LEN);
  annCheckView.name[CC_MAX_NAME_LEN] = '\0';
  annCheckView.name_len = strlen(annCheckView.name);
  annCheckView.seq = peerSeq[i];
  annCheckView.expiry = 0;
  memcpy(annCheckView.admit, peerAdmit[i], CC_ADMIT_SZ);
  memcpy(annCheckView.prev_addr, peerPrevAddr[i], CC_ADDR_SZ);
  // The cache only ever holds announces whose signature we verified (or that
  // came back from our own peer file, written after that verification), which
  // is exactly what cc_admit_for() requires before it will read a declaration.
  annCheckView.verified = 1;
}

// The difficulty to mine for peer `pi` and directed type `type`: the peer's
// published price when it asked for more than we would have mined anyway, our
// own requirement when it declared none. 0 (this build's default) when we have
// no verified announce for the peer, which is the only honest answer.
static uint8_t admitFor(int pi, uint8_t type) {
  if (pi < 0)
    return 0;
  annCheckFill(pi);
  uint8_t d = 0;
  return (cc_admit_for(&annCheckView, type, &d) == CC_OK) ? d : 0;
}

// ---------------------------------------------------------------------------
// Revocations. One cc_revoked_t per retired identity; a caller consults them
// before trusting an announce, accepting a link, parsing traffic from an
// address, or accepting a rotation from it as a predecessor.
// ---------------------------------------------------------------------------
static bool isRevoked(const uint8_t addr[CC_ADDR_SZ]) {
  uint32_t now = millis();
  for (int i = 0; i < REVOKED_MAX; i++) {
    if (revoked[i].used && cc_revoked_check(&revoked[i], addr, now) != CC_OK)
      return true; /* CC_E_REVOKED while the horizon stands */
  }
  return false;
}

// A single-record predicate for cc_rotate_accept(): it takes one cc_revoked_t,
// so look the predecessor up in the table and hand it over.
static const cc_revoked_t* revokedRecord(const uint8_t addr[CC_ADDR_SZ]) {
  uint32_t now = millis();
  for (int i = 0; i < REVOKED_MAX; i++) {
    if (revoked[i].used && cc_revoked_check(&revoked[i], addr, now) != CC_OK)
      return &revoked[i];
  }
  return nullptr;
}

// Per-peer replay windows: one for CC_REPLAY_UNSIGNED (presence/key_req) and
// one for CC_REPLAY_AUTHED (chat), never a shared window, so a spoofed
// unsigned packet cannot make a signed chat from the same peer look stale.
// Mirrored to PEER_DIR/<hex>.rp; without SD they live in RAM only, so a reboot
// forgets the window (an old packet may replay once more).
static cc_replay_t peerReplayUnsign[MAX_PEERS];
static cc_replay_t peerReplayAuthed[MAX_PEERS];
static uint32_t peerReplaySavedAt[MAX_PEERS];

// Bounded rate limiter for outgoing key_reqs: a fixed table of per-address
// timestamps (oldest reused when full) plus a rolling window of recent grants.
// Static storage, no heap.
template <int WIN>
struct RateLimiter {
  struct Entry {
    uint8_t addr[CC_ADDR_SZ];
    uint32_t last;
  };
  Entry seen[MAX_PEERS];
  int count;
  int next;
  uint32_t win[WIN];
  int winCount;
  int winNext;

  bool allow(const uint8_t addr[CC_ADDR_SZ], uint32_t per_addr_ms,
             uint32_t window_ms) {
    uint32_t now = millis();
    if (winCount >= WIN && (uint32_t)(now - win[winNext]) < window_ms)
      return false;
    int slot = -1;
    for (int i = 0; i < count; i++) {
      if (memcmp(seen[i].addr, addr, CC_ADDR_SZ) == 0) {
        slot = i;
        break;
      }
    }
    if (slot >= 0) {
      if ((uint32_t)(now - seen[slot].last) < per_addr_ms)
        return false;
    } else if (count < MAX_PEERS) {
      slot = count++;
      memcpy(seen[slot].addr, addr, CC_ADDR_SZ);
    } else {
      slot = next; /* full: reuse the oldest entry */
      next = (next + 1) % MAX_PEERS;
      memcpy(seen[slot].addr, addr, CC_ADDR_SZ);
    }
    seen[slot].last = now;
    win[winNext] = now;
    winNext = (winNext + 1) % WIN;
    if (winCount < WIN)
      winCount++;
    return true;
  }
};

static RateLimiter<REQ_SEND_BURST> reqSends;

// A rolling-window event budget: at most WIN events per window_ms, no address
// involved. Static storage, no heap.
template <int WIN>
struct WindowBudget {
  uint32_t win[WIN];
  int count;
  int next;

  bool allow(uint32_t window_ms) {
    uint32_t now = millis();
    if (count >= WIN && (uint32_t)(now - win[next]) < window_ms)
      return false;
    win[next] = now;
    next = (next + 1) % WIN;
    if (count < WIN)
      count++;
    return true;
  }
};

// Answer budget for key_reqs. A key_req carries only the target address, so
// there is no requester identity to key a per-address policy on: this node
// answers at most REQ_ANSWER_BURST times per rolling REQ_ANSWER_WINDOW_MS, for
// everyone.
static WindowBudget<REQ_ANSWER_BURST> answerBudget;

// Verify budget for inbound announces (see ANN_VERIFY_*).
static WindowBudget<ANN_VERIFY_BURST> annBudget;

// Handshake budget for inbound link_reqs (see LINK_ACCEPT_*): spent before the
// KEM decapsulation and proof signature, so a request flood cannot turn this
// node into a signature oracle.
static WindowBudget<LINK_ACCEPT_BURST> linkAcceptBudget;

// Verify budget for ROTATE/REVOKE processing (see CTL_VERIFY_*).
static WindowBudget<CTL_VERIFY_BURST> ctlVerifyBudget;

// Verify budget for inbound chats addressed to us (see CHAT_VERIFY_*), spent
// before cc_chat_parse() just as annBudget is spent before the announce parse.
static WindowBudget<CHAT_VERIFY_BURST> chatBudget;

// ---------------------------------------------------------------------------
// UI state
// ---------------------------------------------------------------------------
static String inputBuf;
static uint32_t lastAnn = 0;
static uint32_t lastStats = 0;
static bool sdReady = false;

// Presence log coalescing: last time a PRE line was drawn, and how many
// presences were folded into the next one.
static uint32_t presLogAt = 0;
static uint32_t presSkipped = 0;

// A published rotation is kept in ctlBuf and re-broadcast alongside our
// announce until rotUntil, so peers that missed the first copy still move their
// trust; a revocation is published once and then the operator re-keys.
static uint32_t rotUntil = 0;
static size_t rotLen = 0;

// Whether THIS identity has published a revocation. Once it has, no successor
// that claims continuity from it can be accepted by any peer (a retired
// predecessor is refused, and the revocation drops entries filed under its
// prev_addr), so `r` must stop building a rotation and publish a fresh
// identity instead. Reset when a fresh identity is adopted. Persisted in
// STATE_FILE (v3, bit 0), so a reboot between the revocation and the re-key
// does not re-enable the rotation this guards against.
static bool revocationPublished = false;

// Outbound freshness counters, persisted in STATE_FILE so a reboot resumes
// ahead of anything a peer may already have accepted — reusing a counter is
// exactly what the receiver's replay window rejects, and reusing an announce
// seq makes peers drop our announce as stale. Two independent monotonic
// streams: `counter` for chat/presence/key_req, `seq` for announce. Without a
// card they are seeded from the hardware RNG, so a reboot may repeat a value;
// the state file is the fix.
static uint32_t txCounter = 0;
static uint32_t txSeq = 0;
static uint32_t txCounterSaved = 0; /* only advanced by a save that succeeded */
static uint32_t txSeqSaved = 0;     /* likewise */
static uint32_t lastStateTry = 0;   /* last save attempt, success or not */

// Dispositions of received packets, for the periodic stats lines: without them
// the protections are invisible.
static uint32_t statReplay = 0;
static uint32_t statBadSig = 0;
static uint32_t statNoKey = 0;
static uint32_t statDecrypt = 0;
static uint32_t statAnnDrop = 0; /* announces refused before verification */
static uint32_t statOldWire = 0;
static uint32_t statLinkOpen = 0; /* links that reached OPEN */
static uint32_t statLinkDrop = 0; /* link packets refused or failed */
static uint32_t statRotated = 0;  /* rotations accepted for a cached peer */
static uint32_t statRevoked = 0;  /* packets/peers dropped as retired */
static uint32_t statCtlDrop = 0;  /* ROTATE/REVOKE refused or unverifiable */
static uint32_t statChatDrop = 0; /* chats refused by the chat verify budget */
static uint32_t statPeerBad = 0; /* cached peer files skipped as invalid */
static bool toldOldWire = false;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static const char HEXDIGITS[] = "0123456789abcdef";

static void toHex(const uint8_t* b, int n, char* out) {
  for (int i = 0; i < n; i++) {
    out[i * 2] = HEXDIGITS[b[i] >> 4];
    out[i * 2 + 1] = HEXDIGITS[b[i] & 0xf];
  }
  out[n * 2] = '\0';
}

// Overwrite a buffer that held key material. volatile so the compiler cannot
// drop the stores as dead.
static void wipe(void* p, size_t n) {
  volatile uint8_t* b = (volatile uint8_t*)p;
  while (n--) *b++ = 0;
}

static void logMsg(const char* who, const char* msg, uint16_t col = YELLOW) {
  canvas.setTextColor(col);
  canvas.print(who);
  canvas.setTextColor(WHITE);
  canvas.print(": ");
  canvas.println(msg);
  canvas.pushSprite(8, STATUS_H + 4);
  Serial.printf("%s: %s\n", who, msg);
}

// Log a short formatted line, so call sites do not each carry a scratch buffer.
// Not for chat text, which can exceed buf.
static void logMsgf(const char* who, uint16_t col, const char* fmt, ...) {
  char buf[160];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  logMsg(who, buf, col);
}

static void drawStatus() {
  char hex[9];
  if (haveIdentity) {
    toHex(myAddr, 4, hex); /* first 4 bytes = 8 chars */
  } else {
    snprintf(hex, sizeof(hex), "no id"); /* inert: see haveIdentity */
  }

  auto& D = M5Cardputer.Display;
  D.fillRect(0, 0, D.width(), STATUS_H, NAVY);
  D.setTextSize(1);
  D.setCursor(2, 4);
  D.setTextColor(CYAN);
  D.print(hex);
  D.setTextColor(DARKGREY);
  D.print(" ");
  D.print(road->name);
  D.setTextColor(WHITE);
  D.print(" -> ");
#ifdef CC_ROAD_WIFI
  const char* ip = cc_road_wifi_ip(&roadImpl);
  if (ip) {
    D.setTextColor(GREEN);
    D.print(ip);
  } else {
    D.setTextColor(RED);
    D.print("no wifi");
  }
  D.print(" ");
#endif
  if (peerSel >= 0 && peerSel < peerCount) {
    D.setTextColor(GREEN);
    D.print(peerNames[peerSel]);
    D.setTextColor(DARKGREY);
    char buf[16];
    snprintf(buf, sizeof(buf), " (%d/%d)", peerSel + 1, peerCount);
    D.print(buf);
  } else {
    D.setTextColor(DARKGREY);
    D.print("(no peer - Tab to scan)");
  }
}

static void drawInput() {
  auto& D = M5Cardputer.Display;
  int y = D.height() - 14;
  D.fillRect(0, y, D.width(), 14, BLACK);
  D.setCursor(2, y + 3);
  D.setTextColor(WHITE);
  D.print("> ");
  D.print(inputBuf.c_str());
}

static bool roadSend(const uint8_t* pkt, size_t len) {
  return road->send(road, pkt, len) == CC_ROAD_OK;
}

// ---------------------------------------------------------------------------
// Peer cache helpers
// ---------------------------------------------------------------------------
static void peerSet(int i, const cc_announce_t* ann) {
  memcpy(peerAddrs[i], ann->addr, CC_ADDR_SZ);
  memcpy(peerSignPub[i], ann->sign_pubkey, CC_SIGN_PUBKEY_SZ);
  memcpy(peerKemPub[i], ann->kem_pubkey, CC_KEM_PUBKEY_SZ);
  memcpy(peerAdmit[i], ann->admit, CC_ADMIT_SZ);
  memcpy(peerPrevAddr[i], ann->prev_addr, CC_ADDR_SZ);
  peerSeq[i] = ann->seq;
  strncpy(peerNames[i], ann->name, CC_MAX_NAME_LEN);
  peerNames[i][CC_MAX_NAME_LEN] = '\0';
}

static int peerFind(const uint8_t addr[CC_ADDR_SZ]) {
  for (int i = 0; i < peerCount; i++) {
    if (memcmp(peerAddrs[i], addr, CC_ADDR_SZ) == 0)
      return i;
  }
  return -1;
}

// FNV-1a over the announce's meaningful bytes (the struct itself has padding,
// and hops changes in flight, so neither is hashed). Field lengths are mixed
// in as well, so that e.g. name="AB"+meta="C" cannot collide with
// name="ABC"+meta="". Equal hash means the cached announce is byte-identical
// in everything that matters.
static uint32_t annHash(const cc_announce_t* ann) {
  uint32_t h = 2166136261u;
  auto mix = [&h](const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; i++) {
      h ^= p[i];
      h *= 16777619u;
    }
  };
  mix(ann->addr, CC_ADDR_SZ);
  mix(ann->sign_pubkey, CC_SIGN_PUBKEY_SZ);
  mix(ann->kem_pubkey, CC_KEM_PUBKEY_SZ);
  mix((const uint8_t*)ann->name, ann->name_len);
  mix((const uint8_t*)&ann->name_len, sizeof(ann->name_len));
  mix(ann->meta, ann->meta_len);
  mix((const uint8_t*)&ann->meta_len, sizeof(ann->meta_len));
  // A peer that only changed its admission declaration (or that arrived by
  // rotation) must still count as changed, or we would keep publishing the old
  // price.
  mix(ann->admit, CC_ADMIT_SZ);
  mix(ann->prev_addr, CC_ADDR_SZ);
  return h;
}

// ---------------------------------------------------------------------------
// SD helpers (sdAccess mounts the card and holds spiMux)
// ---------------------------------------------------------------------------
static bool sdInit() {
  if (sdReady)
    return true;
  xSemaphoreTake(spiMux, portMAX_DELAY);
  sdReady = SD.begin(SD_CS, SPI, 25000000);
  if (sdReady) {
    SD.mkdir("/cc");
    SD.mkdir(PEER_DIR);
  }
  xSemaphoreGive(spiMux);
  return sdReady;
}

// Mount the SD card and run fn with the mutex held; fn is handed the opened
// File and returns whether its operation succeeded.
template <class F>
static bool sdAccess(const char* path, const char* mode, F fn) {
  if (!sdInit())
    return false;
  xSemaphoreTake(spiMux, portMAX_DELAY);
  File f = SD.open(path, mode);
  bool ok = f && fn(f);
  if (f)
    f.close();
  xSemaphoreGive(spiMux);
  return ok;
}

static void peerPath(const uint8_t addr[CC_ADDR_SZ], const char* ext, char* out,
                     size_t out_sz) {
  char hex[CC_ADDR_SZ * 2 + 1];
  toHex(addr, CC_ADDR_SZ, hex);
  snprintf(out, out_sz, PEER_DIR "/%s%s", hex, ext);
}

static bool sdExists(const char* path) {
  if (!sdInit())
    return false;
  xSemaphoreTake(spiMux, portMAX_DELAY);
  bool e = SD.exists(path);
  xSemaphoreGive(spiMux);
  return e;
}

// What a load found. ABSENT and INVALID are different answers on purpose: one
// is a first boot, the other is damage. NOCARD is a third: there is no card to
// ask, which is NOT the same as an empty card and must never be read as one (a
// node powered on without its card would otherwise mint and announce a
// stranger identity). Named to avoid the POSIX F_OK macro.
enum {
  FILE_ST_ABSENT = 0,
  FILE_ST_OK = 1,
  FILE_ST_INVALID = 2,
  FILE_ST_NOCARD = 3
};

// Does a directory entry name one of OUR peer files -- 32 lowercase hex digits
// and a .bin or .rp extension? A card can carry anything (a .DS_Store, a
// foreign file), and "some file exists in /cc/peers" is not the same as "this
// node has state here".
static bool peerNameIsOurs(const char* nm) {
  if (!nm)
    return false;
  const char* base = strrchr(nm, '/');
  base = base ? base + 1 : nm;
  size_t n = strlen(base);
  if (n != (size_t)(CC_ADDR_SZ * 2) + 4)
    return false;
  if (strcmp(base + CC_ADDR_SZ * 2, ".bin") != 0 &&
      strcmp(base + CC_ADDR_SZ * 2, ".rp") != 0)
    return false;
  for (int i = 0; i < CC_ADDR_SZ * 2; i++) {
    char c = base[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
      return false;
  }
  return true;
}

// How many of OUR files are in PEER_DIR. Unlike countPeers-style helpers this
// opens no files, so it is safe on the wipe's verification path too.
static int peersOursCount() {
  int n = 0;
  sdAccess(PEER_DIR, FILE_READ, [&](File& dir) {
    while (true) {
      File e = dir.openNextFile();
      if (!e)
        break;
      if (!e.isDirectory() && peerNameIsOurs(e.name()))
        n++;
      e.close();
    }
    return true;
  });
  return n;
}

// Tri-state: is there state on this card that says this node has run before?
// NOCARD when there is no card to ask (which setup() must treat as "do not
// mint": a missing card is not an empty card), OK when our own files are there,
// ABSENT when the card carries nothing of ours. Used only to tell a fresh card
// apart from one whose identity file is gone.
static int cardHasState() {
  if (!sdInit())
    return FILE_ST_NOCARD;
  if (sdExists(STATE_FILE) || sdExists(REVOKED_FILE))
    return FILE_ST_OK;
  return peersOursCount() > 0 ? FILE_ST_OK : FILE_ST_ABSENT;
}

// ---------------------------------------------------------------------------
// Integrity envelope. Every small file this node writes carries the same
// 9-byte header in front of its payload:
//
//   <magic "CCFS"><version 1><crc32 little-endian of the payload><payload>
//
// The CRC detects corruption, it does NOT authenticate: anyone who can write
// the card can recompute it. What it buys is that a damaged, truncated or
// half-written file is *detected* rather than quietly misread -- which for the
// identity file is the difference between "this card is damaged, stop and say
// so" and "mint a new identity and never tell anyone". Each payload keeps the
// layout (and any inner version byte) it had before; the envelope only wraps
// it. A load that fails any of this is INVALID, never absent (see keyLoad()).
// ---------------------------------------------------------------------------
#define ENV_HDR_SZ 9
#define ENV_VERSION 1
static const uint8_t ENV_MAGIC[4] = {'C', 'C', 'F', 'S'};

// CRC-32 (IEEE, reflected, poly 0xEDB88320), bitwise: no 1 KB table, which
// matters more on an MCU than the few extra cycles on a file written every few
// minutes. Callers whose payload lives in several places chain crc32Update()
// and close with crc32Finish(), so no payload copy is ever made.
static uint32_t crc32Start(void) { return 0xFFFFFFFFu; }
static uint32_t crc32Finish(uint32_t c) { return c ^ 0xFFFFFFFFu; }
static uint32_t crc32Update(uint32_t c, const uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; i++) {
    c ^= p[i];
    for (int k = 0; k < 8; k++)
      c = (c >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(c & 1)));
  }
  return c;
}
static uint32_t crc32(const uint8_t* p, size_t n) {
  return crc32Finish(crc32Update(crc32Start(), p, n));
}

static void envWriteHeader(uint8_t h[ENV_HDR_SZ], uint32_t crc) {
  memcpy(h, ENV_MAGIC, 4);
  h[4] = ENV_VERSION;
  h[5] = (uint8_t)crc;
  h[6] = (uint8_t)(crc >> 8);
  h[7] = (uint8_t)(crc >> 16);
  h[8] = (uint8_t)(crc >> 24);
}

// Read the header and hand back the CRC it claims. False means "not one of our
// files" (wrong magic or version, or too short). The payload is checked by the
// caller, which is where the payload bytes are.
//
// Two forms of the same nine bytes: the store hands a whole file over as a
// buffer, while the peer cache (plaintext by design) still streams from a File.
static bool envReadHeader(const uint8_t* p, size_t n, uint32_t* crc_out) {
  if (n < ENV_HDR_SZ)
    return false;
  if (memcmp(p, ENV_MAGIC, 4) != 0 || p[4] != ENV_VERSION)
    return false;
  *crc_out = (uint32_t)p[5] | ((uint32_t)p[6] << 8) | ((uint32_t)p[7] << 16) |
             ((uint32_t)p[8] << 24);
  return true;
}

static bool envReadHeader(File& f, uint32_t* crc_out) {
  uint8_t h[ENV_HDR_SZ];
  if (f.read(h, ENV_HDR_SZ) != ENV_HDR_SZ)
    return false;
  return envReadHeader(h, ENV_HDR_SZ, crc_out);
}

// ---------------------------------------------------------------------------
// The passphrase store: the ONE place the two storage modes are decided.
//
// Four of the five file kinds are sealed (see the layout note at the top of
// this file); the whole difference between a plaintext card and a sealed one
// lives in storeRead()/storeWrite() below, and every reader and writer in this
// file goes through them instead of touching sdAccess or the envelope directly.
// That is what keeps the payload parsers, the inner version bytes and every
// size check above them unchanged: the plaintext of a container IS the file a
// plaintext card would have.
//
// The context a container is bound to is the path string itself -- both sides
// of every call pass the same expression (KEY_FILE, or the buffer peerPath()
// filled), so a container cannot be sealed for one name and opened under
// another by a mistyped literal.
//
// Atomicity: a sealed write never overwrites the live file in place. It seals
// into scratch, writes a temp file, RE-OPENS AND UNSEALS IT to prove it reads
// back, and only then replaces the real file. Any failure leaves the previous
// file where it was; a half-written temp file is detectable by magic and length
// alone, and a leftover ".tmp" is not a name any loader opens.
// ---------------------------------------------------------------------------
enum { STORE_PLAIN = 0, STORE_SEALED = 1 };
static int storeMode = STORE_PLAIN;

// The identity file is neither a container nor one of our plaintext files: it
// is damaged, or something else's. Tracked so the messages can say that instead
// of calling a file nothing can read "PLAINTEXT" -- a false statement about the
// operator's security posture -- while the decision (inert, never mint, no
// prompt) stays exactly what a damaged key file always did.
static bool storeDamaged = false;

// The unlocked key. RAM only, and zeroized (cc_store_lock) by the wipe path.
static cc_store_key_t storeKey;

// Scratch, sized from the file kinds themselves: the largest plaintext is the
// expanded-form identity file (ENV_HDR_SZ + KEY_EXP_PAYLOAD_SZ = 8394), and the
// largest container is that plus the store's overhead (8453). Two buffers, and
// they are the whole of the store's static cost:
//   storeCont  a container: what is read, what is sealed, what is written, and
//              the scratch the identity file's exports and its derived public
//              key are sunk into (7616 bytes of that are used at most)
//   storePlain a plaintext image: the destination of a read (the loaders parse
//              it in place) and the image keySave assembles and hands to
//              storeWrite
// No third buffer: a sealed write verifies itself by reading the temp file back
// and comparing it against storeCont, which is still holding the container it
// just sealed, so nothing needs a second plaintext-sized region.
#define STORE_PT_SZ (ENV_HDR_SZ + KEY_EXP_PAYLOAD_SZ)
static uint8_t storeCont[CC_STORE_SEALED_SZ(STORE_PT_SZ)]; /* a container */
static uint8_t storePlain[STORE_PT_SZ]; /* read destination; save image */

// A sealed store with no key (a wrong passphrase exhausted the attempts, or the
// card was wiped): the sealed kinds cannot be read at all, and calling a file
// "invalid" when it is merely locked would be a lie. The loaders ask this
// first and fall back to their own fail-safe; the boot path has already said
// why in the operator's words.
static bool storeLocked() {
  return storeMode == STORE_SEALED && !storeKey.unlocked;
}

// Read a whole file. The same three answers the loaders speak: ABSENT (no such
// file, or no card), OK, or INVALID (there but unusable -- unreadable, empty,
// or larger than the caller's buffer, which is a file this node could not open
// anyway; a truncated read would be the wrong verdict). Existence is asked
// separately from the open, because "it is not there" and "I cannot read it"
// lead to different decisions above (first boot vs damage).
static int fileReadAll(const char* path, uint8_t* buf, size_t cap,
                       size_t* len) {
  size_t n = 0;
  *len = 0;
  if (!sdInit())
    return FILE_ST_NOCARD;
  if (!sdExists(path))
    return FILE_ST_ABSENT;
  xSemaphoreTake(spiMux, portMAX_DELAY);
  File f = SD.open(path, FILE_READ);
  if (f && !f.isDirectory()) {
    size_t want = (size_t)f.size();
    if (want > 0 && want <= cap && f.read(buf, want) == want)
      n = want;
  }
  if (f)
    f.close();
  xSemaphoreGive(spiMux);
  *len = n;
  return n > 0 ? FILE_ST_OK : FILE_ST_INVALID;
}

// Write a whole file. False means the card refused it; the caller decides what
// that means (for a sealed write it means the old file stays).
static bool fileWriteAll(const char* path, const uint8_t* buf, size_t n) {
  if (!sdInit())
    return false;
  xSemaphoreTake(spiMux, portMAX_DELAY);
  File f = SD.open(path, FILE_WRITE);
  bool ok = f && f.write(buf, n) == n;
  if (f)
    f.close();
  xSemaphoreGive(spiMux);
  return ok;
}

static bool fileRemove(const char* path) {
  if (!sdInit())
    return false;
  xSemaphoreTake(spiMux, portMAX_DELAY);
  bool ok = SD.remove(path);
  xSemaphoreGive(spiMux);
  return ok;
}

static bool fileRename(const char* from, const char* to) {
  if (!sdInit())
    return false;
  xSemaphoreTake(spiMux, portMAX_DELAY);
  /* FS::rename is in the bundled framework (libraries/FS/src/FS.h) over the
   * VFS rename, which is the FAT driver's f_rename: a metadata move on the
   * same volume, and it does not follow symlinks or copy bytes. */
  bool ok = SD.rename(from, to);
  xSemaphoreGive(spiMux);
  return ok;
}

// OK / ABSENT / INVALID, the same three answers the loaders already speak: in
// plaintext mode this is the file verbatim, in sealed mode it is the container
// opened with the key in use. A container that does not open (damage, or a file
// from another key) is INVALID -- never ABSENT, because absence is what means
// "first boot" and decides whether this node mints.
static int storeRead(const char* path, const char* ctx, uint8_t* out,
                     size_t cap, size_t* len) {
  size_t n = 0;
  int rc = fileReadAll(path, storeCont, sizeof(storeCont), &n);
  if (rc != FILE_ST_OK)
    return rc;
  if (storeMode == STORE_PLAIN) {
    if (n > cap)
      return FILE_ST_INVALID;
    memcpy(out, storeCont, n);
    *len = n;
    return FILE_ST_OK;
  }
  cc_store_info_t info;
  if (storeLocked())
    return FILE_ST_INVALID;
  if (cc_store_probe(storeCont, n, &info) != CC_STORE_OK || info.plain_len > cap)
    return FILE_ST_INVALID;
  if (cc_store_unseal(&storeKey, ctx, storeCont, n, out, cap, len) !=
      CC_STORE_OK)
    return FILE_ST_INVALID;
  return FILE_ST_OK;
}

// Make a target name sane before writing beside it. A leftover "<path>.old" is
// either the previous copy of an interrupted replacement (the live name is
// gone: put it back, the interrupted write simply did not happen) or rubbish
// from a write that finished (drop it). A leftover "<path>.tmp" is a copy that
// never installed: it is not a name any loader reads, and this write is about
// to make its own. Either way both names are free afterwards, which is what
// keeps a crash from blocking every later write to that file.
static void storeTidy(const char* path) {
  char old[80], tmp[80];
  if (snprintf(old, sizeof(old), "%s.old", path) < (int)sizeof(old) &&
      sdExists(old)) {
    if (!sdExists(path) && fileRename(old, path))
      logMsgf("Sys", ORANGE, "store: recovered %s from an interrupted write",
              path);
    else
      fileRemove(old);
  }
  if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) < (int)sizeof(tmp))
    fileRemove(tmp);
}

// Does the file read back as exactly the bytes we meant to write? One pass, in
// bounded chunks on the stack, against a buffer the caller already holds -- no
// second plaintext-sized buffer, and the size is compared too, so a truncated
// or extended copy fails here as well.
static bool fileMatches(const char* path, const uint8_t* want, size_t n) {
  uint8_t buf[128];
  size_t off = 0;
  bool ok = false;
  if (!sdInit())
    return false;
  xSemaphoreTake(spiMux, portMAX_DELAY);
  File f = SD.open(path, FILE_READ);
  if (f && !f.isDirectory() && (size_t)f.size() == n) {
    ok = true;
    while (off < n) {
      size_t chunk = (n - off) < sizeof(buf) ? (n - off) : sizeof(buf);
      if (f.read(buf, chunk) != (int)chunk ||
          memcmp(buf, want + off, chunk) != 0) {
        ok = false;
        break;
      }
      off += chunk;
    }
  }
  if (f)
    f.close();
  xSemaphoreGive(spiMux);
  return ok;
}

// The write half. Plaintext mode is today's write. Sealed mode is: seal, write
// a temp, read the temp back and compare it byte for byte against the container
// in storeCont, then install it over the real name -- moving the live file
// aside first, so that a failure at any step leaves the previous file in place
// rather than leaving the name empty (FAT rename does not reliably replace an
// existing name, and "delete then rename" has a window in which there is no
// identity file at all).
//
// What the read-back check proves, and what it does not: it proves the CARD --
// the file exists, at the right size, holding exactly the container we just
// sealed. It does NOT decrypt; that would need a plaintext-sized buffer for the
// result, and this path deliberately has only two. The seal itself is covered
// where it belongs: the module's own round-trip, tamper and truncation tests,
// and the next boot's unseal, which is the first thing that has to work.
static bool storeWrite(const char* path, const char* ctx, const uint8_t* in,
                       size_t len) {
  if (storeMode == STORE_PLAIN)
    return fileWriteAll(path, in, len);
  if (!storeKey.unlocked || len > STORE_PT_SZ)
    return false;

  char tmp[80], old[80];
  if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp) ||
      snprintf(old, sizeof(old), "%s.old", path) >= (int)sizeof(old))
    return false;

  storeTidy(path);

  size_t clen = 0;
  if (cc_store_seal(&storeKey, &rng, ctx, in, len, storeCont, sizeof(storeCont),
                    &clen) != CC_STORE_OK) {
    logMsg("Sys", "store: seal FAILED, file not written", RED);
    return false;
  }
  {
    // Self-check the header the next boot will read: length, algorithms, work
    // factor and salt, against the key this was just sealed with. No buffer
    // needed, so it survives the budget. What no check here can do is verify
    // the GCM tag itself: that is deterministic over this key and this
    // context, and the module's own round-trip, tamper and truncation tests
    // pin it -- see the note above about what the read-back does not prove.
    cc_store_info_t info;
    if (cc_store_probe(storeCont, clen, &info) != CC_STORE_OK ||
        info.plain_len != (uint32_t)len ||
        info.iterations != storeKey.iterations ||
        memcmp(storeCont + CC_STORE_OFF_SALT, storeKey.salt,
               CC_STORE_SALT_SZ) != 0) {
      logMsg("Sys", "store: sealed header is not what this key expects", RED);
      return false;
    }
  }
  if (!fileWriteAll(tmp, storeCont, clen)) {
    logMsgf("Sys", RED, "store: write FAILED (%s)", tmp);
    fileRemove(tmp);
    return false;
  }
  if (!fileMatches(tmp, storeCont, clen)) {
    logMsgf("Sys", RED, "store: %s does not read back, kept the old file", tmp);
    fileRemove(tmp);
    return false;
  }

  // Install. The live file is moved aside rather than deleted, so that a failed
  // install can be undone and the name is never left empty.
  bool hadOld = sdExists(path);
  if (hadOld && !fileRename(path, old)) {
    logMsgf("Sys", RED, "store: cannot move %s aside, not replaced", path);
    fileRemove(tmp);
    return false;
  }
  if (!fileRename(tmp, path)) {
    if (hadOld && !fileRename(old, path))
      logMsgf("Sys", RED, "store: %s left as %s", path, old);
    logMsgf("Sys", RED, "store: install of %s FAILED", path);
    fileRemove(tmp);
    return false;
  }
  if (hadOld && !fileRemove(old))
    logMsgf("Sys", ORANGE, "store: %s left behind", old);
  return true;
}

// ---------------------------------------------------------------------------
// Outbound counter/seq (STATE_FILE) and per-peer replay state
// (PEER_DIR/<hex>.rp)
// ---------------------------------------------------------------------------
static uint32_t nextCounter() { return ++txCounter; }
static uint32_t nextSeq() { return ++txSeq; }

// STATE_FILE payload: <magic 0xCC><version><counter le32>[<seq le32>][<flags>],
// wrapped in the envelope. Version 1 held only the counter; v2 added the
// announce seq; v3 adds one flags byte, bit 0 = this identity has published a
// revocation. Older payloads are still read (missing fields default to 0) so an
// upgrade does not throw away the counter and start reusing it.
static bool stateLoad() {
  const uint8_t* b;
  size_t got = 0;
  uint32_t claim = 0;
  bool present = false;
  bool ok = false;
  int rc;
  // A locked store cannot be read at all: fall back to the RNG seed exactly as
  // for a first boot, and say nothing here -- the boot path already explained
  // why in the operator's words.
  if (storeLocked())
    return false;
  rc = storeRead(STATE_FILE, STATE_FILE, storePlain, sizeof(storePlain), &got);
  present = (rc != FILE_ST_ABSENT);
  if (rc == FILE_ST_OK) {
    b = storePlain + ENV_HDR_SZ;
    got -= ENV_HDR_SZ;
    ok = (got == 6 || got == 10 || got == 11) &&
         envReadHeader(storePlain, ENV_HDR_SZ, &claim) &&
         crc32(b, got) == claim && b[0] == 0xCC &&
         (b[1] == 1 || b[1] == STATE_VERSION);
  }
  if (!ok) {
    // Absent is a first boot and seeds from the RNG; present but invalid is
    // damage, and the fail-safe for a freshness counter is the same (treat it
    // as absent, reseed) -- but loudly, because the node will then reuse
    // counters after a power loss until it has moved past every peer's window.
    if (present)
      logMsg("Sys", "counter.bin invalid: reseeding counters", ORANGE);
    return false;
  }
  txCounter = (uint32_t)b[2] | ((uint32_t)b[3] << 8) | ((uint32_t)b[4] << 16) |
              ((uint32_t)b[5] << 24);
  txSeq = (got >= 10) ? ((uint32_t)b[6] | ((uint32_t)b[7] << 8) |
                         ((uint32_t)b[8] << 16) | ((uint32_t)b[9] << 24))
                      : 0;
  revocationPublished = (got == 11) && (b[10] & 1) != 0;
  // Skip past values that may have been used since the last save: a peer's
  // window is CC_REPLAY_WINDOW wide and an announce seq only has to be greater
  // than the last one the peer stored, so a jump that size cannot repeat one
  // after a power loss between saves.
  txCounter += CC_REPLAY_WINDOW;
  txSeq += CC_REPLAY_WINDOW;
  txCounterSaved = txCounter;
  txSeqSaved = txSeq;
  // Two honest limits of this scheme: a *valid but older* STATE_FILE
  // (rollback by anyone with physical access to the card) makes this node
  // reuse counters and announce sequences, and peers then reject its messages
  // until it passes their high-water marks again; and a valid older .rp
  // regresses a replay window, letting a captured packet replay once.
  // Persistence is what keeps replays out across reboots; it is not
  // tamper-proof against card access. The envelope detects damage, not a
  // deliberate rollback: an older-but-valid file passes it.
  return true;
}

static bool stateSave() {
  lastStateTry = millis();
  if (!sdReady)
    return false;
  uint32_t c = txCounter, s = txSeq;
  uint8_t b[ENV_HDR_SZ + 11];
  uint8_t payload[11] = {0xCC,
                         STATE_VERSION,
                         (uint8_t)c,
                         (uint8_t)(c >> 8),
                         (uint8_t)(c >> 16),
                         (uint8_t)(c >> 24),
                         (uint8_t)s,
                         (uint8_t)(s >> 8),
                         (uint8_t)(s >> 16),
                         (uint8_t)(s >> 24),
                         (uint8_t)(revocationPublished ? 1 : 0)};
  envWriteHeader(b, crc32(payload, sizeof(payload)));
  memcpy(b + ENV_HDR_SZ, payload, sizeof(payload));
  if (!storeWrite(STATE_FILE, STATE_FILE, b, sizeof(b)))
    return false; /* not saved: leave the saved markers alone so drift stays
                     visible */
  txCounterSaved = c;
  txSeqSaved = s;
  return true;
}

// Save once the cadence has elapsed, or once the counter or the announce seq
// has drifted a window's worth from what is actually on disk. Attempts are
// floored by STATE_SAVE_MIN_MS so a failing card is retried, not hammered.
static void stateMaybeSave() {
  // An inert node writes nothing: a wipe must leave the card as clean as the
  // operator made it, and there is no counter worth persisting without an
  // identity to spend it.
  if (!haveIdentity)
    return;
  if (millis() - lastStateTry < STATE_SAVE_MIN_MS)
    return;
  if (millis() - lastStateTry < STATE_SAVE_MS &&
      txCounter - txCounterSaved < CC_REPLAY_WINDOW &&
      txSeq - txSeqSaved < CC_REPLAY_WINDOW)
    return;
  stateSave();
}

// Replay file payload: <version><unsigned cc_replay_t><authed cc_replay_t>,
// wrapped in the envelope.
static bool replaySave(int i) {
  char path[64];
  uint8_t buf[ENV_HDR_SZ + 1 + 2 * sizeof(cc_replay_t)];
  peerPath(peerAddrs[i], ".rp", path, sizeof(path));
  const cc_replay_t* un = &peerReplayUnsign[i];
  const cc_replay_t* au = &peerReplayAuthed[i];
  uint8_t ver = REPLAY_VERSION;
  uint32_t c = crc32Update(crc32Start(), &ver, 1);
  c = crc32Update(c, (const uint8_t*)un, sizeof(cc_replay_t));
  c = crc32Update(c, (const uint8_t*)au, sizeof(cc_replay_t));
  envWriteHeader(buf, crc32Finish(c));
  buf[ENV_HDR_SZ] = ver;
  memcpy(buf + ENV_HDR_SZ + 1, un, sizeof(cc_replay_t));
  memcpy(buf + ENV_HDR_SZ + 1 + sizeof(cc_replay_t), au, sizeof(cc_replay_t));
  bool ok = storeWrite(path, path, buf, sizeof(buf));
  peerReplaySavedAt[i] = millis();
  return ok;
}

static void replayMaybeSave(int i) {
  if (millis() - peerReplaySavedAt[i] >= REPLAY_SAVE_MS)
    replaySave(i);
}

// Initialise both windows for peer i, then restore them from disk when a
// matching file is present; any mismatch -- including a failed envelope, i.e.
// damage -- leaves the fresh windows in place, which is this file's fail-safe:
// a replay window regressing only means a captured packet may replay once, and
// the peer is not muted over it. It is logged when it was present but bad,
// because that is the one case a capture could exploit.
static void replayLoad(int i) {
  const uint8_t* addr = peerAddrs[i];
  cc_replay_t un, au;
  cc_replay_init(&un, addr, CC_REPLAY_UNSIGNED);
  cc_replay_init(&au, addr, CC_REPLAY_AUTHED);
  char path[64];
  peerPath(addr, ".rp", path, sizeof(path));
  bool present = false;
  bool ok = false;
  size_t got = 0;
  uint32_t claim = 0;
  if (!storeLocked()) {
    int rc = storeRead(path, path, storePlain, sizeof(storePlain), &got);
    present = (rc != FILE_ST_ABSENT);
    if (rc == FILE_ST_OK &&
        got == ENV_HDR_SZ + 1 + 2 * sizeof(cc_replay_t) &&
        envReadHeader(storePlain, ENV_HDR_SZ, &claim) &&
        storePlain[ENV_HDR_SZ] == REPLAY_VERSION) {
      memcpy(&un, storePlain + ENV_HDR_SZ + 1, sizeof(un));
      memcpy(&au, storePlain + ENV_HDR_SZ + 1 + sizeof(un), sizeof(au));
      uint32_t c = crc32Update(crc32Start(), storePlain + ENV_HDR_SZ, 1);
      c = crc32Update(c, (const uint8_t*)&un, sizeof(un));
      c = crc32Update(c, (const uint8_t*)&au, sizeof(au));
      ok = (crc32Finish(c) == claim);
      // A state that belongs to another peer, or carries the other class, would
      // make every packet from this peer return CC_E_ARG: reject it and start
      // from fresh windows instead of muting the peer.
      if (ok && (memcmp(un.addr, addr, CC_ADDR_SZ) != 0 ||
                 memcmp(au.addr, addr, CC_ADDR_SZ) != 0 ||
                 un.cls != CC_REPLAY_UNSIGNED || au.cls != CC_REPLAY_AUTHED))
        ok = false;
    }
  }
  if (present && !ok) {
    char hex[CC_ADDR_SZ * 2 + 1];
    toHex(addr, 4, hex);
    logMsgf("Sys", ORANGE, "%s replay state invalid: fresh windows", hex);
  }
  peerReplayUnsign[i] = un;
  peerReplayAuthed[i] = au;
}

// Note the first wrong-revision packet once; every one is still counted, but
// not logged, so an old peer cannot flood the display.
static void oldWireSeen() {
  statOldWire++;
  if (!toldOldWire) {
    toldOldWire = true;
    logMsg("Sys", "ignoring other wire revisions", ORANGE);
  }
}

// KEY_FILE layout: <envelope>[<form>...], the CRC over the whole payload
// including the form byte. Two forms are read (see the constants above): the
// seed form this build writes, and the expanded form it wrote before, so an
// old card still boots.
//
// Three answers, not two. ABSENT is a first boot and the caller generates.
// INVALID -- present but the wrong size, unreadable, an unknown form, a failed
// CRC, or a seed and public key that disagree -- must NEVER be papered over by
// minting a new identity: that silently re-identifies the node, orphans its
// links, and looks to every peer like a stranger. The caller fails closed
// instead (see setup()).
static int keyLoad() {
  uint8_t* p;
  uint8_t* sign_seed;
  uint8_t* kem_seed;
  uint8_t* sign_priv;
  uint8_t* sign_pub;
  uint8_t* kem_priv;
  size_t got = 0;
  int rc;
  if (!sdInit())
    return FILE_ST_NOCARD; /* no card is not an empty card (see setup()) */
  // A locked store is not readable at all, and that is not damage, so it is
  // not reported as damage either: setup() has already said which it is.
  if (storeLocked())
    return FILE_ST_INVALID;
  // The three answers carry over from the file read: no card, no file, or a
  // file that is there and does not load -- and the last of those must never be
  // papered over by minting (see the note above).
  rc = storeRead(KEY_FILE, KEY_FILE, storePlain, sizeof(storePlain), &got);
  if (rc != FILE_ST_OK)
    return rc;

  // The key's pieces are POINTED AT in the file image, not copied out of it:
  // they are already in one buffer, and a second copy of an 8 KB private key
  // would be RAM, and one more thing to wipe, for nothing. Each form sets its
  // own pointers below, so none of them is ever formed outside the image.
  p = storePlain;
  sign_seed = NULL;
  kem_seed = NULL;
  sign_priv = NULL;
  sign_pub = NULL;
  kem_priv = NULL;

  uint32_t claim = 0;
  uint8_t form = 0;
  bool seed_form = false;
  bool ok = false;
  if (envReadHeader(p, got, &claim) &&
      (got == (size_t)(ENV_HDR_SZ + KEY_SEED_PAYLOAD_SZ) ||
       got == (size_t)(ENV_HDR_SZ + KEY_EXP_PAYLOAD_SZ))) {
    size_t off = ENV_HDR_SZ;
    form = p[off++];
    uint32_t c = crc32Update(crc32Start(), &form, 1);
    if (form == KEY_FORM_SEED) {
      // Trust each field, not just the file size.
      ok = got == (size_t)(ENV_HDR_SZ + KEY_SEED_PAYLOAD_SZ) &&
           got - off == CC_SIGN_SEED_SZ + CC_KEM_SEED_SZ + CC_SIGN_PUBKEY_SZ;
      if (ok) {
        sign_seed = p + off;
        kem_seed = sign_seed + CC_SIGN_SEED_SZ;
        sign_pub = kem_seed + CC_KEM_SEED_SZ;
        c = crc32Update(c, sign_seed, CC_SIGN_SEED_SZ);
        c = crc32Update(c, kem_seed, CC_KEM_SEED_SZ);
        c = crc32Update(c, sign_pub, CC_SIGN_PUBKEY_SZ);
        seed_form = true;
        ok = crc32Finish(c) == claim;
      }
    } else if (form == KEY_FORM_EXPANDED) {
      ok = got == (size_t)(ENV_HDR_SZ + KEY_EXP_PAYLOAD_SZ) &&
           got - off ==
               CC_SIGN_PRIVKEY_SZ + CC_SIGN_PUBKEY_SZ + CC_KEM_PRIVKEY_SZ;
      if (ok) {
        sign_priv = p + off;
        sign_pub = sign_priv + CC_SIGN_PRIVKEY_SZ;
        kem_priv = sign_pub + CC_SIGN_PUBKEY_SZ;
        c = crc32Update(c, sign_priv, CC_SIGN_PRIVKEY_SZ);
        c = crc32Update(c, sign_pub, CC_SIGN_PUBKEY_SZ);
        c = crc32Update(c, kem_priv, CC_KEM_PRIVKEY_SZ);
        ok = crc32Finish(c) == claim;
      }
    }
    /* Any other form falls through as a failure: not a form this build wrote. */
  }

  rc = FILE_ST_INVALID;
  if (ok) {
    bool imported =
        seed_form
            ? (cc_key_import_seed(&myKey, sign_seed, kem_seed) == CC_OK)
            : (cc_key_import(&myKey, sign_priv, sign_pub, kem_priv) == CC_OK);
    if (imported) {
      // Cross-check the sign half, in BOTH forms: the key must hold the signing
      // key whose public half is the `sign_pub` stored beside it, or this node
      // would announce one public key and sign with another (mute, and looking
      // healthy). The derived public key is sunk into storeCont: the container
      // it held has been opened already and is not needed again.
      imported = cc_key_export_public(&myKey, storeCont,
                                      storeCont + CC_SIGN_PUBKEY_SZ) == CC_OK &&
                 memcmp(storeCont, sign_pub, CC_SIGN_PUBKEY_SZ) == 0;
    }
    if (imported) {
      rc = FILE_ST_OK;
    } else {
      cc_key_free(&myKey); /* leave nothing half-imported behind */
      rc = FILE_ST_INVALID;
    }
  }
  // The identity file in the clear, in RAM: gone the moment it has been used.
  // Wiping the image covers the seeds and the expanded private halves with it.
  wipe(storePlain, got);
  return rc;
}

// Save the identity in the seed form when the key has a seed (always true for
// one this node generated), and in the expanded form when it does not. Returns
// true only when the file was written.
static bool keySave() {
  // The image is assembled IN the plaintext buffer, and every export writes
  // straight into the slot it belongs in, so this saver needs no scratch of its
  // own: the only outputs with no slot in the file are the public halves the
  // file does not carry (kem_pub, and sign_pub on the seed path), and those go
  // into storeCont, which is free until storeWrite seals this image into it.
  uint8_t* img = storePlain;
  uint8_t* kb = storeCont + CC_SIGN_PRIVKEY_SZ +
                CC_SIGN_PUBKEY_SZ; /* kem_pub: not stored */
  size_t payload = 0;              /* bytes after the form byte */
  uint8_t form = 0;
  bool ok = false;
  int sr;

  // Both halves must export for a save to be attempted at all, in either form:
  // the gate the previous revision had, kept as it was (its results are unused
  // here and are overwritten below by the exports that do land in the image).
  if (cc_key_export_private(&myKey, storeCont,
                            storeCont + CC_SIGN_PRIVKEY_SZ) != CC_OK ||
      cc_key_export_public(&myKey, storeCont + CC_SIGN_PRIVKEY_SZ, kb) !=
          CC_OK) {
    logMsg("Sys", "key export FAILED: not saved", RED);
    wipe(storePlain, sizeof(storePlain));
    wipe(storeCont, CC_SIGN_PRIVKEY_SZ + CC_SIGN_PUBKEY_SZ + CC_KEM_PUBKEY_SZ);
    return false;
  }

  sr = cc_key_export_seed(&myKey, img + ENV_HDR_SZ + 1,
                          img + ENV_HDR_SZ + 1 + CC_SIGN_SEED_SZ);
  if (sr == CC_OK) {
    // The seed form this build writes.
    form = KEY_FORM_SEED;
    payload = CC_SIGN_SEED_SZ + CC_KEM_SEED_SZ + CC_SIGN_PUBKEY_SZ;
    // sign_pub comes from the key, not from the seed, and it belongs in the
    // image: export it straight into its slot.
    if (cc_key_export_public(
            &myKey, img + ENV_HDR_SZ + 1 + CC_SIGN_SEED_SZ + CC_KEM_SEED_SZ,
            kb) != CC_OK) {
      logMsg("Sys", "key export FAILED: not saved", RED);
      form = 0;
    }
  } else if (sr == CC_E_NOKEY) {
    // Usable identity, no knowable seed (it was imported expanded). Save it the
    // only way it can be saved, and say so: it is ~3.9 KB larger, but saving
    // nothing here would leave the PREVIOUS identity on the card while this
    // node announces the new one.
    form = KEY_FORM_EXPANDED;
    logMsg("Sys", "key has no seed: saving the expanded form", ORANGE);
    payload = CC_SIGN_PRIVKEY_SZ + CC_SIGN_PUBKEY_SZ + CC_KEM_PRIVKEY_SZ;
    if (cc_key_export_private(&myKey, img + ENV_HDR_SZ + 1,
                              img + ENV_HDR_SZ + 1 + CC_SIGN_PRIVKEY_SZ +
                                  CC_SIGN_PUBKEY_SZ) != CC_OK ||
        cc_key_export_public(&myKey,
                             img + ENV_HDR_SZ + 1 + CC_SIGN_PRIVKEY_SZ,
                             kb) != CC_OK) {
      logMsg("Sys", "key export FAILED: not saved", RED);
      form = 0;
    }
  } else {
    logMsgf("Sys", RED, "key export failed (%d): not saved", sr);
  }

  if (form != 0) {
    // One contiguous image: envelope, form byte, then the key bytes, exactly
    // the file a plaintext card would hold. The CRC covers the form byte and
    // the payload, so it is computed once the payload is in place.
    img[ENV_HDR_SZ] = form;
    envWriteHeader(img, crc32(img + ENV_HDR_SZ, 1 + payload));
    ok = storeWrite(KEY_FILE, KEY_FILE, img, ENV_HDR_SZ + 1 + payload);
  }
  // The image is a private key in the clear, and storePlain is also the store's
  // read buffer: wipe it, and the scratch exports in the container buffer too.
  wipe(storePlain, sizeof(storePlain));
  wipe(storeCont, CC_SIGN_PRIVKEY_SZ + CC_SIGN_PUBKEY_SZ + CC_KEM_PUBKEY_SZ);
  return ok;
}

// PEER_DIR/<hex>.bin payload: <version><raw cc_announce_t>, wrapped in the
// envelope. The version byte is here for the same reason the other five kinds
// have one: cc_announce_t has grown twice, and without it an old file would be
// silently reinterpreted as the new shape. It is written only after the
// signature was verified, so the envelope is what catches a corrupted copy of
// it: the cached keys are used on the receive path without re-verifying the
// signature.
static void peerSave(const cc_announce_t* ann) {
  char path[64];
  uint8_t hdr[ENV_HDR_SZ];
  uint8_t ver = PEER_VERSION;
  peerPath(ann->addr, ".bin", path, sizeof(path));
  uint32_t c = crc32Update(crc32Start(), &ver, 1);
  c = crc32Update(c, (const uint8_t*)ann, sizeof(cc_announce_t));
  envWriteHeader(hdr, crc32Finish(c));
  sdAccess(path, FILE_WRITE, [&](File& f) {
    return f.write(hdr, ENV_HDR_SZ) == ENV_HDR_SZ && f.write(&ver, 1) == 1 &&
           f.write((const uint8_t*)ann, sizeof(cc_announce_t)) ==
               sizeof(cc_announce_t);
  });
}

// Cold store: read the cached announces once at boot. The keys needed on the
// receive/send paths are copied into RAM by peerSet(), so no runtime path
// opens the peer files. A file that is the wrong size, carries another payload
// version or fails its envelope is skipped with a note: the peer then
// re-announces, which is a re-learn rather than a loss.
static void peersFromSD() {
  const size_t want = ENV_HDR_SZ + 1 + sizeof(cc_announce_t);
  sdAccess(PEER_DIR, FILE_READ, [&](File& dir) {
    peerCount = 0;
    while (peerCount < MAX_PEERS) {
      File e = dir.openNextFile();
      if (!e)
        break;
      if (!e.isDirectory() && (size_t)e.size() == want) {
        cc_announce_t tmp;
        uint32_t claim = 0;
        uint8_t ver = 0;
        if (envReadHeader(e, &claim) && e.read(&ver, 1) == 1 &&
            ver == PEER_VERSION &&
            e.read((uint8_t*)&tmp, sizeof(cc_announce_t)) ==
                sizeof(cc_announce_t)) {
          uint32_t c = crc32Update(crc32Start(), &ver, 1);
          c = crc32Update(c, (const uint8_t*)&tmp, sizeof(cc_announce_t));
          if (crc32Finish(c) == claim) {
            peerSet(peerCount, &tmp);
            peerHashes[peerCount] = annHash(&tmp);
            replayLoad(peerCount);
            peerCount++;
          } else {
            statPeerBad++;
          }
        } else {
          statPeerBad++;
        }
      }
      e.close();
    }
    return true;
  });
  if (statPeerBad > 0)
    logMsgf("Sys", ORANGE, "%lu peer file(s) invalid: dropped",
            (unsigned long)statPeerBad);
}

// Cache an announce. Returns true when the cache actually changed, so callers
// can skip the SD write, log line and redraw for an identical replay.
static bool peerAddOrUpdate(const cc_announce_t* ann) {
  uint32_t h = annHash(ann);
  int i = peerFind(ann->addr);
  if (i >= 0) {
    // Freshness was checked by the caller; keep the high-water mark moving
    // even when the content is identical, so the same seq is never accepted
    // twice.
    peerSeq[i] = ann->seq;
    if (peerHashes[i] == h)
      return false; /* unchanged content: no SD write, log or redraw */
    peerSet(i, ann);
    peerHashes[i] = h;
    peerSave(ann);
    return true;
  }
  if (peerCount < MAX_PEERS) {
    peerSet(peerCount, ann);
    peerHashes[peerCount] = h;
    cc_replay_init(&peerReplayUnsign[peerCount], ann->addr, CC_REPLAY_UNSIGNED);
    cc_replay_init(&peerReplayAuthed[peerCount], ann->addr, CC_REPLAY_AUTHED);
    peerReplaySavedAt[peerCount] = 0;
    if (peerSel < 0)
      peerSel = peerCount;
    peerCount++;
    peerSave(ann);
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Announce / presence broadcast
// ---------------------------------------------------------------------------
static void broadcastAnnounce() {
  // No identity, no announce: an inert node must not look like a new one (see
  // haveIdentity). This is also the only send path that every caller shares.
  if (!haveIdentity)
    return;
  // A cosechat announce is ~6.5 KB and must be sent as ~27 fragments. If two
  // nodes transmit simultaneously their fragments interleave by msg_id,
  // causing both reassemblies to fail. A random pre-transmit delay (0-5 s)
  // spreads simultaneous boots and periodic re-announces across time so
  // collisions are rare. For a production mesh you would replace this with
  // proper TDMA slot assignment or carrier-sense backoff.
#if !defined(CC_ROAD_BLE) && !defined(CC_ROAD_80211) && !defined(CC_ROAD_WIFI)
  delay(random(0, 5000));
#endif

  size_t len = 0;
  // expiry 0 = no expiry: this node has no clock but millis(), so an absolute
  // wall-clock expiry would be a meaningless number. A receiver with a real
  // clock accepts it either way; the signed, monotonic seq (not the expiry) is
  // what stops an old announce from re-seeding a stale peer view.
  int ret = cc_announce_build(&work, &myKey, NODE_NAME, strlen(NODE_NAME),
                              nullptr, 0, myAdmit, nextSeq(), 0, annBuf,
                              sizeof(annBuf), &len, &rng);
  if (ret == CC_OK && len > 0 && roadSend(annBuf, len)) {
    logMsg("TX", "announce", CYAN);
  } else {
    logMsgf("Sys", RED, "announce failed (%d)", ret);
  }
}

static void broadcastPresence() {
  if (!haveIdentity)
    return;
  size_t len = 0;
  int ret =
      cc_presence_build(&work, &myKey, NODE_NAME, strlen(NODE_NAME),
                        nextCounter(), presBuf, sizeof(presBuf), &len, &rng);
  if (ret == CC_OK && len > 0 && roadSend(presBuf, len)) {
    logMsg("TX", "presence", CYAN);
  }
}

// Ask `addr` for its announce. Outgoing requests are rate-limited per address
// and globally; a suppressed request is dropped silently, because logging each
// one would itself be a cheap display/airtime sink.
static void requestAnnounce(const uint8_t addr[CC_ADDR_SZ]) {
  if (!reqSends.allow(addr, REQ_SEND_MS, REQ_SEND_WINDOW_MS))
    return;
  // Mine at the peer's published price when we hold a verified announce for it
  // (0 = this build's own default otherwise).
  size_t rlen = 0;
  if (cc_key_req_build(&work, addr, nextCounter(),
                       admitFor(peerFind(addr), CC_ADMIT_KEY_REQ), keyReqBuf,
                       sizeof(keyReqBuf), &rlen) == CC_OK &&
      roadSend(keyReqBuf, rlen)) {
    logMsg("TX", "key_req", CYAN);
  }
}

// ---------------------------------------------------------------------------
// Links. Routing note: a link packet carries no recipient, only a link_id, so
// cc_msg_recipient() cannot route it and there is no address to look up. Every
// LINK_*/IDENTIFY packet is routed here by cc_link_id() against this table,
// and only then handed to the library. The link key authenticates each record,
// so link traffic has no per-message signature and is never fed to the chat
// replay window: per-link sequence numbers inside cc_link_t are its replay
// defence.
// ---------------------------------------------------------------------------
static cc_link_t* linkFind(const uint8_t id[CC_LINK_ID_SZ]) {
  for (int i = 0; i < LINK_SESSION_MAX; i++) {
    if (links[i].used && memcmp(links[i].id, id, CC_LINK_ID_SZ) == 0)
      return &links[i];
  }
  return nullptr;
}

static cc_link_t* linkFindPeer(const uint8_t addr[CC_ADDR_SZ]) {
  for (int i = 0; i < LINK_SESSION_MAX; i++) {
    if (links[i].used && memcmp(links[i].peer, addr, CC_ADDR_SZ) == 0)
      return &links[i];
  }
  return nullptr;
}

// A link we accepted starts with no peer address: link_req is anonymous, and
// the initiator is only named by an identify record. Zero means "not known
// yet"; the first verified identify fills it in.
static bool linkPeerKnown(const cc_link_t* l) {
  for (int i = 0; i < CC_ADDR_SZ; i++) {
    if (l->peer[i])
      return true;
  }
  return false;
}

static int linkCountRole(uint8_t role) {
  int n = 0;
  for (int i = 0; i < LINK_SESSION_MAX; i++) {
    if (links[i].used && links[i].role == role)
      n++;
  }
  return n;
}

// A pending responder handshake, live only until its short TTL runs out. It is
// not a session: nothing is kept warm for it and no peer can send on it.
static int pendIndex(const uint8_t id[CC_LINK_ID_SZ]) {
  uint32_t now = millis();
  for (int i = 0; i < LINK_PENDING_MAX; i++) {
    if (linkPend[i].used && cc_link_active(&linkPend[i], now) &&
        memcmp(linkPend[i].id, id, CC_LINK_ID_SZ) == 0)
      return i;
  }
  return -1;
}

static cc_link_t* pendAlloc() {
  uint32_t now = millis();
  for (int i = 0; i < LINK_PENDING_MAX; i++) {
    if (!linkPend[i].used || !cc_link_active(&linkPend[i], now)) {
      cc_link_forget(&linkPend[i]);
      return &linkPend[i];
    }
  }
  return nullptr;
}

static void pendForget(int i) { cc_link_forget(&linkPend[i]); }

// A slot is free when it was never used, or has gone idle in either role (an
// unanswered handshake included).
static cc_link_t* linkAlloc() {
  uint32_t now = millis();
  for (int i = 0; i < LINK_SESSION_MAX; i++) {
    if (!links[i].used)
      return &links[i];
    if ((int32_t)(now - links[i].last_seen) > (int32_t)LINK_IDLE_MS) {
      cc_link_forget(&links[i]);
      return &links[i];
    }
  }
  return nullptr;
}

// Promote a pending responder handshake into a session slot, which only happens
// once the peer has proved itself by sending an authenticated record. Refused
// when responder-side links already hold their share of the table: our own
// handshakes must always find a slot.
static cc_link_t* linkAdopt(int pi) {
  if (linkCountRole(CC_LINK_ROLE_RESPONDER) >= LINK_RESPONDER_MAX)
    return nullptr;
  cc_link_t* s = linkAlloc();
  if (!s)
    return nullptr;
  *s = linkPend[pi];
  s->expiry = LINK_IDLE_MS; /* the handshake TTL becomes the idle policy */
  s->last_seen = millis();
  pendForget(pi);
  statLinkOpen++;
  return s;
}

// Start a handshake with the selected peer, unless one is already pending or
// open. The KEM key comes from the RAM cache, so no SD access.
static void linkStart(int si) {
  if (linkFindPeer(peerAddrs[si]))
    return;
  cc_link_t* l = linkAlloc();
  if (!l) {
    logMsg("Sys", "no free link slot", ORANGE);
    return;
  }
  size_t len = 0;
  int ret = cc_link_start(&work, l, peerAddrs[si], peerKemPub[si], millis(),
                          LINK_IDLE_MS, admitFor(si, CC_ADMIT_LINK_REQ),
                          linkBuf, sizeof(linkBuf), &len, &rng);
  if (ret != CC_OK) {
    cc_link_forget(l);
    logMsgf("Sys", RED, "link_start (%d)", ret);
    return;
  }
  if (len > 0 && roadSend(linkBuf, len)) {
    logMsg("TX", "link_req", CYAN);
  }
}

// Keep warm the sessions that have earned it, expiring everything else. A
// keepalive refreshes last_seen, so it must never be sent on behalf of a link
// that is not a known peer: otherwise an attacker's unauthenticated link_req
// would be kept alive by the victim forever. "Known" means we initiated the
// link (we filled l->peer ourselves) or a verified identify named it; a pending
// responder handshake only ever expires, and an adopted session that never
// identifies is left to go quiet.
static void linkMaintain() {
  // An inert node keeps nothing warm: with no identity there is nothing on the
  // other end worth a keepalive, and the tables were cleared by the wipe.
  if (!haveIdentity)
    return;
  uint32_t now = millis();
  for (int i = 0; i < LINK_SESSION_MAX; i++) {
    cc_link_t* l = &links[i];
    if (!l->used)
      continue;
    if (!cc_link_active(l, now)) {
      if ((int32_t)(now - l->last_seen) > (int32_t)LINK_IDLE_MS) {
        cc_link_forget(l);
        statLinkDrop++; /* counted as idle/dropped; see the stats line */
      }
      continue;
    }
    if (linkPeerKnown(l) &&
        (int32_t)(now - l->last_seen) >= (int32_t)LINK_KEEPALIVE_MS) {
      size_t len = 0;
      // The peer's idle timeout would otherwise close a wanted-but-quiet link;
      // a keepalive is one small AEAD record and refreshes both sides.
      if (cc_link_send(&work, l, CC_LINK_KIND_KEEPALIVE, linkRx, 0, now,
                       linkBuf, sizeof(linkBuf), &len) == CC_OK &&
          len > 0) {
        roadSend(linkBuf, len);
      }
    }
  }
  // Unanswered responder handshakes die on their own TTL, without ever having
  // occupied a session slot.
  for (int i = 0; i < LINK_PENDING_MAX; i++) {
    if (linkPend[i].used && !cc_link_active(&linkPend[i], now))
      pendForget(i);
  }
}

// An identify record proves the initiator's address. The payload layout is
// [addr ‖ signature]; verify it against the cached announce for the claimed
// address, and only then is that address treated as verified on this link.
static void identifyCheck(cc_link_t* l, const uint8_t* payload, size_t len) {
  if (len < CC_ADDR_SZ) {
    statLinkDrop++;
    return;
  }
  uint8_t claimed[CC_ADDR_SZ];
  memcpy(claimed, payload, CC_ADDR_SZ);
  int pi = peerFind(claimed);
  if (pi < 0) {
    statNoKey++; /* no announce to check the claim against */
    return;
  }
  if (isRevoked(claimed)) {
    statRevoked++;
    return; /* a retired identity cannot identify itself onto a link */
  }
  uint8_t addr_out[CC_ADDR_SZ];
  if (cc_identify_verify(&work, l, payload, len, peerSignPub[pi], addr_out) !=
          CC_OK ||
      memcmp(addr_out, claimed, CC_ADDR_SZ) != 0) {
    statLinkDrop++;
    return;
  }
  char hex[CC_ADDR_SZ * 2 + 1];
  toHex(claimed, 4, hex);
  if (!linkPeerKnown(l)) {
    memcpy(l->peer, claimed,
           CC_ADDR_SZ); /* this link now has a verified peer */
  } else if (memcmp(l->peer, claimed, CC_ADDR_SZ) != 0) {
    /* A link to someone else may not be relabelled by a record on it. */
    statLinkDrop++;
    return;
  }
  logMsgf("RX", GREEN, "%s identify verified", hex);
}

// LINK_DATA / IDENTIFY / LINK_CLOSE. The packet type is only a hint here; the
// authenticated record kind decides what the packet means.
static void handleLinkPacket(const uint8_t* pkt, size_t len) {
  uint8_t id[CC_LINK_ID_SZ];
  if (cc_link_id(pkt, len, id) != CC_OK) {
    statLinkDrop++;
    return;
  }
  cc_link_t* l = linkFind(id);
  if (!l) {
    // Not a session yet. It may be a responder-side handshake we answered from
    // the pending table; a record arriving on it is authentication, so that is
    // the moment it earns a session slot. An id we never handed out is simply
    // dropped (a replayed link_id must not shadow a live session).
    int pi = pendIndex(id);
    if (pi < 0) {
      statLinkDrop++;
      return;
    }
    l = linkAdopt(pi);
    if (!l) {
      statLinkDrop++;
      return;
    }
  }
  uint8_t kind = 0;
  size_t plen = 0;
  int ret = cc_link_recv(&work, l, pkt, len, millis(), &kind, linkRx,
                         sizeof(linkRx), &plen);
  if (ret != CC_OK) {
    if (ret == CC_E_NOLINK)
      cc_link_forget(l); /* expired or forgotten: clean the slot up */
    statLinkDrop++;
    return;
  }
  if (kind == CC_LINK_KIND_DATA) {
#if LINK_REQUIRE_IDENTIFY
    // Anonymous links are a library feature, but this app only displays a
    // message once the peer has proved its address with a verified identify:
    // an unauthenticated link_req must not buy a zero-PoW, unsigned channel.
    // Dropping here leaves a silent-but-authenticated socket, which is fine.
    if (!linkPeerKnown(l)) {
      statLinkDrop++;
      return;
    }
#endif
    // The link key authenticated this record, so the peer is authenticated by
    // the handshake; the record needs no signature of its own. (With
    // LINK_REQUIRE_IDENTIFY 0 an unidentified peer is shown as "anon".)
    char from[CC_ADDR_SZ * 2 + 1];
    if (linkPeerKnown(l))
      toHex(l->peer, 4, from);
    else
      snprintf(from, sizeof(from), "anon");
    char buf[CC_MAX_MSG_SZ + 16];
    snprintf(buf, sizeof(buf), "[%s] %.*s", from, (int)plen,
             (const char*)linkRx);
    logMsg("RX", buf, YELLOW);
  } else if (kind == CC_LINK_KIND_IDENTIFY) {
    identifyCheck(l, linkRx, plen);
  } else if (kind == CC_LINK_KIND_CLOSE) {
    logMsg("RX", "link close", ORANGE);
    cc_link_forget(l);
  }
  /* KEEPALIVE: nothing to do; cc_link_recv already refreshed last_seen. */
}

// ---------------------------------------------------------------------------
// Identity control: retirement bookkeeping, then the rotation/revocation
// commands. Ordering, as the header requires: a revocation must be published
// and land BEFORE a successor is, or the successor is trusted on the strength
// of the key that was retired.
//
// And once a revocation has gone out, a ROTATE can no longer work at all: a
// rotation claims continuity from the retired predecessor, but every peer
// refuses a rotation whose predecessor it holds retired (cc_rotate_accept()
// returns CC_E_REVOKED), and recording the revocation of X also drops any
// entry filed under X's prev_addr. So the successor that survives is a FRESH
// identity, with no continuity claim and nothing for the retired key to
// vouch for. The console enforces that order rather than inviting the wrong
// one: after `x`, `r` publishes a fresh identity instead of a doomed rotation
// (see publishRotation()).
// ---------------------------------------------------------------------------
// Remove one file and REPORT whether it is gone: SD.remove() returns false for
// a write-protected card, a failed mount or a stuck bus, and the wipe's whole
// job is to be able to say honestly that the files are gone (see wipeCard()).
static bool sdRemove(const char* path) {
  if (!sdInit())
    return false;
  xSemaphoreTake(spiMux, portMAX_DELAY);
  bool ok = SD.remove(path);
  xSemaphoreGive(spiMux);
  return ok;
}

// REVOKED_FILE payload: <version><REVOKED_MAX cc_revoked_t>, wrapped in the
// envelope.
//
// All-or-nothing: the whole payload is validated into a scratch copy and the
// table is replaced only if every byte of it read back and the envelope's CRC
// matches. Installing the prefix that happened to read (the earlier behaviour)
// fails open twice -- a truncated file silently drops the records past the cut,
// and a corrupt one leaves the table empty -- and either way silently
// un-revokes identities. The honest residual limit, which no amount of
// validation removes: this list is best-effort LOCAL state. A vanished or
// damaged card re-trusts every retired address it cannot read back, so the
// durable fix for a leaked key is to rotate away from it, not to rely on
// revocation (see the README).
static void revokedLoad() {
  for (int i = 0; i < REVOKED_MAX; i++) cc_revoked_init(&revoked[i]);
  static cc_revoked_t scratch[REVOKED_MAX]; /* no heap; see the RAM note */
  bool present = false;
  bool ok = false;
  size_t got = 0;
  uint32_t claim = 0;
  const size_t want = ENV_HDR_SZ + 1 + REVOKED_MAX * sizeof(cc_revoked_t);
  // A locked store cannot be read: fail closed (an unread revocation list is
  // not a reason to trust a retired identity) and stay quiet -- the boot
  // already said why.
  if (storeLocked())
    return;
  int rc = storeRead(REVOKED_FILE, REVOKED_FILE, storePlain,
                     sizeof(storePlain), &got);
  present = (rc != FILE_ST_ABSENT);
  if (rc == FILE_ST_OK && got == want &&
      envReadHeader(storePlain, ENV_HDR_SZ, &claim) &&
      storePlain[ENV_HDR_SZ] == REVOKED_VERSION) {
    memcpy(scratch, storePlain + ENV_HDR_SZ + 1, sizeof(scratch));
    uint32_t c = crc32Update(crc32Start(), storePlain + ENV_HDR_SZ, 1);
    c = crc32Update(c, (const uint8_t*)scratch, sizeof(scratch));
    ok = (crc32Finish(c) == claim);
    for (int i = 0; ok && i < REVOKED_MAX; i++) {
      if (scratch[i].used > 1)
        ok = false; /* not a record this app ever wrote */
    }
  }
  if (!ok) {
    if (present)
      logMsg("Sys", "revoked.bin invalid: list NOT loaded", ORANGE);
    return;
  }
  for (int i = 0; i < REVOKED_MAX; i++) revoked[i] = scratch[i];
}

static bool revokedSave() {
  uint8_t buf[ENV_HDR_SZ + 1 + REVOKED_MAX * sizeof(cc_revoked_t)];
  uint8_t ver = REVOKED_VERSION;
  uint32_t c = crc32Update(crc32Start(), &ver, 1);
  c = crc32Update(c, (const uint8_t*)revoked, sizeof(revoked));
  envWriteHeader(buf, crc32Finish(c));
  buf[ENV_HDR_SZ] = ver;
  memcpy(buf + ENV_HDR_SZ + 1, revoked, sizeof(revoked));
  return storeWrite(REVOKED_FILE, REVOKED_FILE, buf, sizeof(buf));
}

// Record a verified retirement. Security records are NOT a cache: a live
// record is never evicted for a DIFFERENT address. With REVOKED_MAX 8, a
// rotating cursor let an attacker publishing eight revocations for throwaway
// identities evict a legitimate one, after which a retired (possibly leaked)
// identity was trusted again for the price of eight keygens plus eight mined
// packets. So the slot order is: this address's own record, then a free slot,
// then a slot whose non-zero expiry has already passed (that address is free
// again by its own horizon), and otherwise refuse and log. Our own published
// revocations carry expiry 0 (remember indefinitely) and are never evicted.
//
// Returns whether the retirement is now recorded. Writes to SD ONLY when the
// record actually changed (address, seq or expiry differ), the same rule the
// peer announces apply: a revocation has no replay window -- it is idempotent
// -- so a captured revocation replay must not make this node rewrite
// /cc/revoked.bin up to CTL_VERIFY_BURST times per window, each write an
// open/write/close holding spiMux (the radio's SPI mutex on the lora env).
static bool revokedAdd(const uint8_t addr[CC_ADDR_SZ], uint32_t seq,
                       uint32_t expiry) {
  int slot = -1;
  for (int i = 0; i < REVOKED_MAX; i++) {
    if (revoked[i].used && memcmp(revoked[i].addr, addr, CC_ADDR_SZ) == 0) {
      slot = i; /* the record we already have */
      break;
    }
  }
  if (slot < 0) {
    for (int i = 0; i < REVOKED_MAX; i++) {
      if (!revoked[i].used) {
        slot = i;
        break;
      }
    }
  }
  if (slot < 0) {
    uint32_t now = millis();
    for (int i = 0; i < REVOKED_MAX; i++) {
      if (revoked[i].used && revoked[i].expiry != 0 &&
          now > revoked[i].expiry) {
        slot = i; /* expired by its own horizon; same rule cc_revoked_check */
        break;
      }
    }
  }
  if (slot < 0) {
    logMsg("Sys", "revocation table full; not stored", RED);
    return false;
  }
  // Idempotent replay: the same (addr, seq, expiry) is already recorded, so
  // there is nothing to change and nothing to write.
  if (revoked[slot].used &&
      memcmp(revoked[slot].addr, addr, CC_ADDR_SZ) == 0 &&
      revoked[slot].seq == seq && revoked[slot].expiry == expiry)
    return true;
  cc_revoked_take(&revoked[slot], addr, seq, expiry);
  revokedSave();
  return true;
}

// Drop peer `i`, shifting the cache down, and delete its files. Used for a
// retired address and for any successor that arrived as a rotation from it.
static void peerRemove(int i) {
  char path[64];
  peerPath(peerAddrs[i], ".bin", path, sizeof(path));
  sdRemove(path);
  peerPath(peerAddrs[i], ".rp", path, sizeof(path));
  sdRemove(path);
  int last = peerCount - 1;
  if (i != last) {
    memcpy(peerAddrs[i], peerAddrs[last], CC_ADDR_SZ);
    memcpy(peerNames[i], peerNames[last], sizeof(peerNames[last]));
    memcpy(peerSignPub[i], peerSignPub[last], CC_SIGN_PUBKEY_SZ);
    memcpy(peerKemPub[i], peerKemPub[last], CC_KEM_PUBKEY_SZ);
    memcpy(peerAdmit[i], peerAdmit[last], CC_ADMIT_SZ);
    memcpy(peerPrevAddr[i], peerPrevAddr[last], CC_ADDR_SZ);
    peerHashes[i] = peerHashes[last];
    peerSeq[i] = peerSeq[last];
    peerReplayUnsign[i] = peerReplayUnsign[last];
    peerReplayAuthed[i] = peerReplayAuthed[last];
    peerReplaySavedAt[i] = peerReplaySavedAt[last];
  }
  peerCount--;
  if (peerSel >= peerCount)
    peerSel = peerCount - 1;
}

// Forget any session with `addr`: a retired identity's live links must stop
// working. Pending handshakes carry no peer address (link_req is anonymous), so
// there is nothing to match there; they expire on their own TTL.
static void linkDropPeer(const uint8_t addr[CC_ADDR_SZ]) {
  for (int i = 0; i < LINK_SESSION_MAX; i++) {
    if (links[i].used && memcmp(links[i].peer, addr, CC_ADDR_SZ) == 0)
      cc_link_forget(&links[i]);
  }
}

// Move peer `i` onto its rotated identity: both replay windows follow the
// address, and the entry is persisted under the new address while the old
// files go. CC_REPLAY_CONTINUES is the right default here because our nodes
// carry their counter space across a rotation (the counter is a signed field),
// so a message sent just before the rotation cannot be replayed into the new
// address; the consequence is that a successor which RESTARTED its counter
// would be dropped as stale, and such a node should rotate with a fresh
// identity instead.
static void rekeyPeer(int i, const cc_announce_t* rot, uint32_t floorAuthed,
                      uint32_t floorUnsign) {
  uint8_t oldAddr[CC_ADDR_SZ];
  memcpy(oldAddr, peerAddrs[i], CC_ADDR_SZ);
  cc_replay_move(&peerReplayAuthed[i], rot->addr, floorAuthed,
                 CC_REPLAY_CONTINUES);
  cc_replay_move(&peerReplayUnsign[i], rot->addr, floorUnsign,
                 CC_REPLAY_CONTINUES);
  peerSet(i, rot);
  peerHashes[i] = annHash(rot);
  peerSave(rot);
  replaySave(i);
  // A link's keys are independent of the identity keys, so a rotation does not
  // invalidate an open session; the link just follows the address change.
  for (int j = 0; j < LINK_SESSION_MAX; j++) {
    if (links[j].used && memcmp(links[j].peer, oldAddr, CC_ADDR_SZ) == 0)
      memcpy(links[j].peer, rot->addr, CC_ADDR_SZ);
  }
  char path[64];
  peerPath(oldAddr, ".bin", path, sizeof(path));
  sdRemove(path);
  peerPath(oldAddr, ".rp", path, sizeof(path));
  sdRemove(path);
}

// Retire the current identity. The operator must then re-key, but ONLY with a
// fresh identity: a rotation that claims continuity from this key cannot work
// (see the section comment and publishRotation()).
static void publishRevocation() {
  if (!haveIdentity) {
    logMsg("Sys", "no identity: 'n' mints one", RED);
    return;
  }
  rotLen = 0; /* the rotation, if one is still in its grace window, is replaced:
                 a revocation must be the last word about this identity */
  size_t len = 0;
  // expiry 0 = remember indefinitely: the receiver compares this field against
  // ITS clock, and this node has no clock, so any other value would be a
  // meaningless number.
  int ret = cc_revoke_build(&work, &myKey, txSeq, 0, ctlBuf, sizeof(ctlBuf),
                            &len, &rng);
  if (ret != CC_OK || len == 0 || !roadSend(ctlBuf, len)) {
    logMsgf("Sys", RED, "revoke failed (%d)", ret);
    return;
  }
  logMsg("TX", "REVOKE (identity retired)", RED);
  revocationPublished = true;
  // Persist the flag now rather than at the next save cadence: a power loss
  // between `x` and `r` must not re-enable the rotation this fixes.
  stateSave();
  // Ordering, and why this text changed: the operator used to be told to
  // re-key with `r`, which then rotated FROM the key just revoked -- a
  // successor every peer refuses (cc_rotate_accept() rejects a retired
  // predecessor, and the revocation also drops entries filed under this
  // address as their prev_addr). The node believed it had rotated while the
  // mesh disagreed. So rotation is no longer offered here; a fresh identity is.
  logMsg("Sys", "re-key now: 'r' publishes a FRESH identity (no rotation)",
         ORANGE);
}

// Publish a successor that claims NO continuity with the current identity: a
// brand-new keypair, saved, adopted and announced. This is the only successor
// peers accept once this node has published a revocation, and it is also the
// safer one for a leaked key -- the retired key is never asked to vouch for
// anything. The old address stays retired on every peer that recorded the
// revocation; the new identity arrives as a peer nobody has seen before.
static void publishFreshIdentity() {
  if (cc_key_generate(&newKey, &rng) != CC_OK) {
    logMsg("Sys", "keygen FAILED", RED);
    return;
  }
  // Adopt as a move, exactly as a rotation does: free the old, take the new,
  // zero the slot so nothing can free the same key twice.
  cc_key_free(&myKey);
  myKey = newKey;
  memset(&newKey, 0, sizeof(newKey));
  keySave();
  cc_addr_from_key(&myKey, myAddr);
  rotLen = 0;   /* no rotation exists to re-broadcast */
  rotUntil = 0; /* ...and none to keep alive */
  revocationPublished = false; /* the new identity has retired nothing */
  stateSave();                 /* ...and that must survive a reboot too */
  broadcastAnnounce();
  logMsg("Sys", "fresh identity published (no continuity)", ORANGE);
  drawStatus();
}

// Publish a successor identity. The new key is minted first, the rotation is
// co-signed by the old key and sent, and only then is the old key dropped.
static void publishRotation() {
  if (!haveIdentity) {
    logMsg("Sys", "no identity: 'n' mints one", RED);
    return;
  }
  if (revocationPublished) {
    // A rotation from a retired predecessor is refused by every peer, so the
    // wrong order cannot be walked into: after a revocation `r` publishes a
    // fresh identity instead (see publishFreshIdentity()).
    logMsg("Sys", "predecessor retired: publishing FRESH identity", ORANGE);
    publishFreshIdentity();
    return;
  }
  if (cc_key_generate(&newKey, &rng) != CC_OK) {
    logMsg("Sys", "rot keygen FAILED", RED);
    return;
  }
  size_t len = 0;
  int ret = cc_rotate_build(&work, &newKey, &myKey, NODE_NAME,
                            strlen(NODE_NAME), nullptr, 0, nextSeq(), 0, ctlBuf,
                            sizeof(ctlBuf), &len, &rng);
  if (ret != CC_OK || len == 0 || !roadSend(ctlBuf, len)) {
    logMsgf("Sys", RED, "rotate failed (%d)", ret);
    cc_key_free(&newKey);
    return;
  }
  rotLen = len;
  rotUntil = millis() + ROTATE_GRACE_MS;
  logMsg("TX", "ROTATE (new identity)", CYAN);
  // Take ownership of the new key material as a move: free the old, adopt the
  // new, and zero the slot so nothing can free the same key twice.
  cc_key_free(&myKey);
  myKey = newKey;
  memset(&newKey, 0, sizeof(newKey));
  keySave();
  cc_addr_from_key(&myKey, myAddr);
  broadcastAnnounce(); /* the successor announces itself */
  logMsg("Sys", "identity rotated", ORANGE);
  drawStatus();
}

// ---------------------------------------------------------------------------
// The store's operator-facing half: the passphrase prompt, the boot decision,
// and the command that sets or changes the passphrase.
//
// There is NO recovery here, by design: the key is PBKDF2(passphrase, salt) and
// nothing else, so a forgotten passphrase means the sealed files are gone and
// the only way back is 'w' (wipe) followed by 'n' (mint). Nothing in this file
// may grow a hint, an escrow, a recovery phrase, or a second path to the key.
// ---------------------------------------------------------------------------
#define STORE_UNLOCK_TRIES 3
// A prompt with no keyboard input at all must not brick the boot: after this
// long the prompt gives up and leaves the caller in its fail-safe state.
#define STORE_PROMPT_MS 120000UL

// Read a secret from the keyboard, echoing a mask and nothing else. The
// passphrase never reaches inputBuf (which drawInput() puts on screen), never
// reaches logMsg, and is wiped by the caller. False means the operator could
// not be asked at all, which must leave the caller fail-safe rather than
// pretending an answer arrived.
static bool promptSecret(const char* label, char* out, size_t cap) {
  auto& D = M5Cardputer.Display;
  uint32_t started = millis();
  size_t len = 0;
  int y = D.height() - 14;
  out[0] = '\0';
  while ((uint32_t)(millis() - started) < STORE_PROMPT_MS) {
    M5Cardputer.update();
    if (!M5Cardputer.Keyboard.isChange() ||
        !M5Cardputer.Keyboard.isPressed()) {
      delay(20);
      continue;
    }
    auto ks = M5Cardputer.Keyboard.keysState();
    bool done = false;
    for (auto k : ks.word) {
      if (k == '\t')
        continue;
      if (len + 1 < cap)
        out[len++] = k;
    }
    if (ks.del && len > 0)
      len--;
    if (ks.enter)
      done = true;
    out[len] = '\0';
    // Only the prompt and a mask: the number of characters is visible, the
    // characters are not.
    D.fillRect(0, y, D.width(), 14, BLACK);
    D.setCursor(2, y + 3);
    D.setTextColor(YELLOW);
    D.print(label);
    D.print(": ");
    D.setTextColor(WHITE);
    for (size_t i = 0; i < len && i < 24; i++) D.print('*');
    if (done)
      return true;
  }
  logMsg("Sys", "passphrase prompt timed out", ORANGE);
  // Whatever was typed is a partial passphrase: it is the caller's buffer, and
  // the caller cannot know how much of it was written, so it goes now.
  wipe(out, cap);
  return false;
}

// Adopt a passphrase the operator just typed as the card's store key. An empty
// passphrase means "run this card in the clear": that is a choice, never a
// default, so the caller warns about it.
static bool storeAdoptPassphrase(const char* pass) {
  cc_store_lock(&storeKey);
  if (pass[0] == '\0') {
    // An empty answer is "run this card in the clear". It is a choice, so it
    // gets said out loud -- at every place that can take it -- rather than
    // being taken silently.
    storeMode = STORE_PLAIN;
    logMsg("Sys", "store PLAINTEXT: no passphrase set", ORANGE);
    logMsg("Sys", "key.bin will be readable by anyone with the card", RED);
    return true;
  }
  logMsg("Sys", "deriving key (PBKDF2, slow on this part)...", ORANGE);
  if (cc_store_new_key(&storeKey, &rng, 0, (const uint8_t*)pass, strlen(pass)) !=
      CC_STORE_OK) {
    cc_store_lock(&storeKey);
    logMsg("Sys", "store: key derivation FAILED", RED);
    return false;
  }
  storeMode = STORE_SEALED;
  return true;
}

// Ask for a new passphrase, and ask again to confirm it. allowEmpty is the
// fresh-card boot question ("no passphrase" is a legitimate answer there); the
// 'p' command refuses it, because that is not a way to remove a store that
// already exists -- 'w' erases the card, and removing the passphrase while
// keeping the identity is a silently weaker card.
static bool storePromptNew(const char* label, bool allowEmpty) {
  char a[CC_STORE_PASS_MAX + 1], b[CC_STORE_PASS_MAX + 1];
  bool ok = false;
  b[0] = '\0';
  if (!promptSecret(label, a, sizeof(a))) {
    // The prompt wiped a partial answer already; this covers the array itself.
    wipe(a, sizeof(a));
    return false;
  }
  if (a[0] == '\0') {
    if (!allowEmpty)
      logMsg("Sys", "empty passphrase refused ('w' erases the card)", RED);
    else
      ok = storeAdoptPassphrase(a);
  } else if (!promptSecret("again", b, sizeof(b))) {
    ok = false;
  } else if (strcmp(a, b) != 0) {
    logMsg("Sys", "passphrases differ: nothing changed", RED);
  } else {
    ok = storeAdoptPassphrase(a);
  }
  wipe(a, sizeof(a));
  wipe(b, sizeof(b));
  return ok;
}

// Prove the CURRENT passphrase before replacing the key. An unlocked store only
// means the passphrase was typed at boot, and the operator may have walked away
// from the device since; opening key.bin with it is the proof that costs
// nothing and weakens nothing.
static bool storeConfirmCurrent() {
  char pass[CC_STORE_PASS_MAX + 1];
  cc_store_key_t probe;
  size_t clen = 0, pt = 0;
  bool ok = false;
  if (!promptSecret("current passphrase", pass, sizeof(pass))) {
    wipe(pass, sizeof(pass)); /* the prompt wiped it; this covers the array */
    return false;
  }
  if (fileReadAll(KEY_FILE, storeCont, sizeof(storeCont), &clen) != FILE_ST_OK) {
    logMsg("Sys", "key.bin unreadable: not re-keyed", RED);
    wipe(pass, sizeof(pass));
    return false;
  }
  logMsg("Sys", "deriving key (PBKDF2, slow on this part)...", ORANGE);
  memset(&probe, 0, sizeof(probe));
  ok = cc_store_unlock(&probe, KEY_FILE, storeCont, clen,
                       (const uint8_t*)pass, strlen(pass), storePlain,
                       sizeof(storePlain), &pt) == CC_STORE_OK;
  cc_store_lock(&probe);
  wipe(&probe, sizeof(probe));
  wipe(storePlain, sizeof(storePlain)); /* the identity file in the clear */
  wipe(pass, sizeof(pass));
  if (!ok)
    logMsg("Sys", "passphrase not accepted: nothing changed", RED);
  return ok;
}

// Write every sealed kind again from the state in RAM: the peer windows, the
// revocation list, the counter, and the identity LAST -- key.bin is the file
// that decides the mode at the next boot, so the card never claims to be sealed
// before the other files are.
static bool storeSealAll() {
  for (int i = 0; i < peerCount; i++) {
    if (!replaySave(i))
      return false;
  }
  return revokedSave() && stateSave() && keySave();
}

// Put the card back the way it was after a failed rewrite: the same files, from
// the same RAM state, under whichever key and mode the caller restored first.
// A failed passphrase change must leave a working card, not half of one.
static bool storeRestoreAll() {
  bool ok = true;
  for (int i = 0; i < peerCount; i++) {
    if (!replaySave(i))
      ok = false;
  }
  if (!revokedSave())
    ok = false;
  if (!stateSave())
    ok = false;
  if (haveIdentity && !keySave())
    ok = false;
  if (!ok)
    logMsg("Sys", "ROLLBACK INCOMPLETE: 'w' then 'n' makes a new identity", RED);
  return ok;
}

// Console 'p': set the passphrase (sealing a plaintext card: the migration) or
// change it (re-keying a sealed one).
static void setPassphrase() {
  int wasMode;
  cc_store_key_t wasKey;

  if (!sdReady) {
    logMsg("Sys", "no card: nothing to seal", RED);
    return;
  }
  if (!haveIdentity) {
    logMsg("Sys", "no identity loaded: nothing to seal", RED);
    logMsg("Sys", "'w' wipes, 'n' mints a new identity", ORANGE);
    return;
  }
  if (storeLocked()) {
    logMsg("Sys", "store LOCKED: 'w' wipes and 'n' mints a new identity", RED);
    return;
  }
  // A sealed store insists on the passphrase it is sealed with before this
  // command replaces the key.
  if (storeMode == STORE_SEALED && !storeConfirmCurrent())
    return;

  // What a rollback needs: the mode and a copy of the key in use.
  wasMode = storeMode;
  memcpy(&wasKey, &storeKey, sizeof(wasKey));
  if (!storePromptNew("new passphrase", false)) {
    wipe(&wasKey, sizeof(wasKey));
    return; /* nothing typed, or nothing agreed: the card is untouched */
  }

  logMsg("Sys", "sealing every file...", ORANGE);
  if (storeSealAll()) {
    cc_store_lock(&wasKey);
    wipe(&wasKey, sizeof(wasKey));
    if (wasMode == STORE_PLAIN) {
      logMsg("Sys", "store SEALED: card migrated", GREEN);
    } else {
      logMsg("Sys", "store re-keyed", GREEN);
    }
    logMsg("Sys", "no recovery: forget it and 'w' then 'n' is the only way",
           RED);
    return;
  }

  // Half a rewrite is not a state this card may be left in: put the previous
  // key and mode back and write every file again.
  storeMode = wasMode;
  memcpy(&storeKey, &wasKey, sizeof(storeKey));
  wipe(&wasKey, sizeof(wasKey));
  logMsg("Sys", "sealing FAILED: restoring the previous files", RED);
  storeRestoreAll();
}

// Is any of the other sealed kinds a container? Asked only when key.bin is
// missing, to tell "this was a sealed card" from "this was a plaintext card":
// without it, minting a replacement identity for a sealed card whose key file
// was lost would silently write the new private key in the clear.
static bool storeAnySealed() {
  static const char* const paths[] = {STATE_FILE, REVOKED_FILE};
  size_t n = 0;
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    cc_store_info_t info;
    if (fileReadAll(paths[i], storeCont, sizeof(storeCont), &n) == FILE_ST_OK &&
        cc_store_probe(storeCont, n, &info) == CC_STORE_OK)
      return true;
  }
  return false;
}

// The boot half: decide the mode, and get the key before anything reads the
// card. Called from setup() between the display setup and keyLoad(), because
// the console only goes live in loop() while broadcastAnnounce() already fires
// at the end of setup(): a prompt anywhere else would mean the node had read a
// locked store, and announced, without ever asking.
static void storeBoot() {
  cc_store_info_t info;
  size_t n = 0;
  int rc, probe;
  static const char* const fixed[] = {KEY_FILE, STATE_FILE, REVOKED_FILE};
  if (!sdInit())
    return; /* keyLoad() reports the cardless case, as it always has */

  // Undo an interrupted sealed replacement before anything reads these files:
  // a crash between the two renames leaves the live name empty and the previous
  // copy at "<path>.old", and putting it back is the honest recovery (the
  // interrupted write simply did not happen).
  for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++)
    storeTidy(fixed[i]);

  rc = fileReadAll(KEY_FILE, storeCont, sizeof(storeCont), &n);
  if (rc == FILE_ST_ABSENT) {
    // No identity file. On a card with no state this is a fresh card, and the
    // passphrase is asked for BEFORE the first private key exists, so a key is
    // never written in the clear even for a moment. On a card that HAS state, a
    // missing key file is damage or a hand-deleted file, not a fresh start: no
    // prompt may turn it into a new identity (keyLoad() fails closed), and
    // nothing is asked now either.
    if (cardHasState() == FILE_ST_ABSENT) {
      if (storePromptNew("new passphrase (empty = plaintext)", true) &&
          storeMode == STORE_SEALED)
        logMsg("Sys", "store SEALED: no recovery if it is forgotten", ORANGE);
      return;
    }
    // If that state is sealed, this WAS a sealed card: remember it, so a later
    // 'n' asks for a passphrase instead of quietly writing the replacement
    // identity in the clear.
    if (storeAnySealed()) {
      storeMode = STORE_SEALED;
      logMsg("Sys", "store SEALED: key.bin missing, files not readable", RED);
    }
    return;
  }
  if (rc != FILE_ST_OK)
    return; /* unreadable: keyLoad() reports INVALID and the node fails closed */

  probe = cc_store_probe(storeCont, n, &info);
  if (probe == CC_STORE_E_VERSION) {
    // A container this firmware does not understand is not a plaintext card:
    // staying sealed (and locked) makes keyLoad() refuse, which is the honest
    // answer for a store written by a newer build.
    storeMode = STORE_SEALED;
    logMsg("Sys", "store: newer format than this firmware", RED);
    return;
  }
  if (probe != CC_STORE_OK) {
    // Not a container. Is it one of OUR plaintext files? That is recognisable:
    // the envelope every plaintext card wrote (magic + version). If it is, this
    // is a card from before the store existed: run it exactly as such a card
    // always ran, and say how to seal it.
    if (n >= ENV_HDR_SZ && memcmp(storeCont, ENV_MAGIC, 4) == 0 &&
        storeCont[4] == ENV_VERSION) {
      storeMode = STORE_PLAIN;
      logMsg("Sys", "store PLAINTEXT: 'p' sets a passphrase", ORANGE);
      return;
    }
    // Neither: damaged, half-written, or a file from something else. Saying
    // "PLAINTEXT" here would misstate the node's posture, and offering the
    // passphrase or migration prompt for a file nothing can read would be
    // worse. Mode stays plaintext so keyLoad() reaches its normal INVALID
    // answer and the node fails closed, exactly as a damaged key file always
    // has; only the wording knows the difference.
    storeDamaged = true;
    storeMode = STORE_PLAIN;
    logMsg("Sys", "key.bin UNREADABLE: not a store, not a plaintext file", RED);
    return;
  }

  storeMode = STORE_SEALED;
  logMsg("Sys", "store SEALED: key.bin needs the passphrase", ORANGE);
  {
    char pass[CC_STORE_PASS_MAX + 1];
    size_t clen = 0, pt = 0;
    for (int tries = 1; tries <= STORE_UNLOCK_TRIES; tries++) {
      if (!promptSecret("passphrase", pass, sizeof(pass)))
        break;
      if (pass[0] == '\0') {
        logMsgf("Sys", ORANGE, "empty passphrase (%d of %d)", tries,
                STORE_UNLOCK_TRIES);
        continue;
      }
      if (fileReadAll(KEY_FILE, storeCont, sizeof(storeCont), &clen) !=
          FILE_ST_OK)
        break;
      logMsg("Sys", "deriving key (PBKDF2, slow on this part)...", ORANGE);
      rc = cc_store_unlock(&storeKey, KEY_FILE, storeCont, clen,
                           (const uint8_t*)pass, strlen(pass), storePlain,
                           sizeof(storePlain), &pt);
      wipe(pass, sizeof(pass));
      wipe(storePlain, sizeof(storePlain)); /* the identity in the clear */
      if (rc == CC_STORE_OK) {
        logMsg("Sys", "store unlocked", GREEN);
        return;
      }
      logMsgf("Sys", ORANGE, "passphrase not accepted (%d of %d)", tries,
              STORE_UNLOCK_TRIES);
    }
    wipe(pass, sizeof(pass));
    // Fail closed, and never mint: three failed attempts are exactly as
    // unreadable as a damaged key file, and re-identifying the node over a typo
    // would be the worst possible answer to one.
    cc_store_lock(&storeKey);
    logMsg("Sys", "store LOCKED: key.bin was not read", RED);
    logMsg("Sys", "'w' wipes the card, 'n' mints a new identity", RED);
  }
}

// A locked store has no key, so a new identity would have nowhere sealed to go.
// Ask for a passphrase decision before writing one, rather than silently
// writing a new private key in the clear.
static void storeAskIfLocked() {
  if (storeMode != STORE_SEALED || storeKey.unlocked || !sdReady)
    return;
  if (storePromptNew("new passphrase (empty = plaintext)", true) &&
      storeMode == STORE_SEALED)
    logMsg("Sys", "store keyed: no recovery if it is forgotten", ORANGE);
}

// ---------------------------------------------------------------------------
// Identity lifecycle: mint a new one ('n') and wipe the card ('w'). Both act
// only after a confirmation keypress, because neither can be undone from here.
// ---------------------------------------------------------------------------

// Mint a new identity deliberately. The node becomes a stranger to the mesh:
// the address is new, so peers must re-learn it (an announce does that), and
// the old identity's rotation continuity and any revocation aimed at it are
// orphaned on the peers' side. This is what recovery from a damaged key file
// looks like.
static void mintNewIdentity() {
  // A locked store (unknown passphrase, or a card just wiped) has no key: the
  // new private key would have nowhere sealed to go. Ask before minting, so the
  // answer is the operator's and the file is never silently written in the
  // clear. On a sealed card that is still unlocked the passphrase has not
  // changed, so nothing is asked and the new identity is sealed under it.
  storeAskIfLocked();
  if (cc_key_generate(&myKey, &rng) != CC_OK) {
    logMsg("Sys", "keygen FAILED", RED);
    return;
  }
  cc_addr_from_key(&myKey, myAddr);
  haveIdentity = true;
  // A brand-new address has published no revocation: clear the flag the
  // previous identity's revocation would otherwise pin on this one.
  revocationPublished = false;
  rotLen = 0;
  rotUntil = 0;
  if (!keySave())
    logMsg("Sys", "WARNING: key.bin NOT saved", RED);
  stateSave();
  char hex[CC_ADDR_SZ * 2 + 1];
  toHex(myAddr, 4, hex);
  logMsgf("Sys", GREEN, "new identity %s", hex);
  logMsg("Sys", "peers must re-learn you", ORANGE);
  broadcastAnnounce();
  drawStatus();
}

// Remove every file in PEER_DIR, one entry per directory pass: the entry is
// closed and the mutex released before the remove, so nothing is deleting a
// file a live directory stream is sitting on. The guard bounds the loop if an
// entry somehow refuses to disappear.
static int peersWipeFiles() {
  int n = 0;
  for (int guard = 0; guard < MAX_PEERS * 2 + 8; guard++) {
    char path[64] = {0};
    sdAccess(PEER_DIR, FILE_READ, [&](File& dir) {
      File e = dir.openNextFile();
      if (!e)
        return true;
      if (!e.isDirectory()) {
        const char* nm = e.name();
        if (nm && nm[0] == '/')
          snprintf(path, sizeof(path), "%s", nm);
        else
          snprintf(path, sizeof(path), PEER_DIR "/%s", nm ? nm : "");
      }
      e.close();
      return true;
    });
    if (path[0] == '\0')
      break;
    sdRemove(path);
    n++;
  }
  return n;
}

static void wipeNote(char* left, size_t n, const char* name) {
  size_t used = strlen(left);
  if (used + strlen(name) + 2 < n)
    snprintf(left + used, n - used, "%s ", name);
}

// A sealed write goes through "<path>.tmp" and moves the live file to
// "<path>.old" while installing: either can survive a crash mid-write, and a
// wipe that left this node's own scratch on the card would not be a wipe. The
// peer directory is swept entry by entry (peersWipeFiles), so the peer files
// need nothing here.
static void wipeScratch(const char* path, char* left, size_t n) {
  static const char* const suffix[] = {".tmp", ".old"};
  char p[80];
  for (size_t i = 0; i < sizeof(suffix) / sizeof(suffix[0]); i++) {
    if (snprintf(p, sizeof(p), "%s%s", path, suffix[i]) >= (int)sizeof(p))
      continue;
    if (sdExists(p) && !sdRemove(p))
      wipeNote(left, n, suffix[i]);
  }
}

// Wipe every trace of this node's identity, from the card and from RAM: the
// key, the freshness counters, the revocation list, the peer cache with its
// replay state, the live sessions, and each of those files.
// This is the "retire the device / hand the card to someone else" path, and it
// is the honest counterpart to the README's "the card IS the identity".
//
// The file half can FAIL -- an unmounted card, a write-protected card, a stuck
// bus -- and a wipe that claims success it did not have is the one lie this
// path must never tell, so every removal is checked and the result is verified
// by existence afterwards. The RAM half cannot fail, and it happens either way:
// even with files left behind, the identity is gone from this node and it is
// inert until 'n'.
static void wipeCard() {
  char left[96] = {0};
  bool card = sdInit();
  int peers = 0;
  if (card) {
    peers = peersWipeFiles();
    if (!sdRemove(KEY_FILE))
      wipeNote(left, sizeof(left), "key.bin");
    if (!sdRemove(STATE_FILE))
      wipeNote(left, sizeof(left), "counter.bin");
    if (!sdRemove(REVOKED_FILE))
      wipeNote(left, sizeof(left), "revoked.bin");
    wipeScratch(KEY_FILE, left, sizeof(left));
    wipeScratch(STATE_FILE, left, sizeof(left));
    wipeScratch(REVOKED_FILE, left, sizeof(left));
    // Verify by existence rather than by SD.remove()'s return value alone: the
    // claim that matters is "the files are not there any more".
    if (sdExists(KEY_FILE))
      wipeNote(left, sizeof(left), "key.bin");
    if (sdExists(STATE_FILE))
      wipeNote(left, sizeof(left), "counter.bin");
    if (sdExists(REVOKED_FILE))
      wipeNote(left, sizeof(left), "revoked.bin");
    int peersLeft = peersOursCount();
    if (peersLeft > 0)
      wipeNote(left, sizeof(left), "peers/*");
  }

  // The store key goes with the identity: after a wipe there is nothing left on
  // the card for it to open, and leaving a derived key in RAM would be the one
  // piece of the old identity this path forgot to purge.
  cc_store_lock(&storeKey);
  memset(&storeKey, 0, sizeof(storeKey));
  // If the files are really gone the card holds no container at all and the
  // mode is plaintext. If the wipe did NOT finish, sealed files may still be
  // there: stay sealed-but-locked, so the next 'n' asks for a passphrase
  // instead of quietly writing the replacement identity in the clear.
  storeMode = (card && left[0] == '\0') ? STORE_PLAIN : storeMode;

  // RAM: identity (and the rotation slot, which holds a whole private key
  // whenever a rotation or a mint was staged), peers, sessions.
  cc_key_free(&myKey);
  cc_key_free(&newKey);
  memset(&newKey, 0, sizeof(newKey));
  memset(myAddr, 0, sizeof(myAddr));
  haveIdentity = false;
  for (int i = 0; i < REVOKED_MAX; i++) cc_revoked_init(&revoked[i]);
  peerCount = 0;
  peerSel = -1;
  for (int i = 0; i < MAX_PEERS; i++) {
    memset(peerAddrs[i], 0, CC_ADDR_SZ);
    cc_replay_init(&peerReplayUnsign[i], peerAddrs[i], CC_REPLAY_UNSIGNED);
    cc_replay_init(&peerReplayAuthed[i], peerAddrs[i], CC_REPLAY_AUTHED);
    peerReplaySavedAt[i] = 0;
  }
  for (int i = 0; i < LINK_SESSION_MAX; i++) cc_link_forget(&links[i]);
  for (int i = 0; i < LINK_PENDING_MAX; i++) cc_link_forget(&linkPend[i]);
  // Plaintext scratch that could still hold a message.
  memset(chatBuf, 0, sizeof(chatBuf));
  memset(linkRx, 0, sizeof(linkRx));
  // Fresh counters/seq, so nothing the old identity spent is carried forward
  // and the card leaves with no correlatable value on it. The saved markers
  // are levelled too, so nothing is written back until real traffic follows.
  txCounter = esp_random();
  txSeq = esp_random();
  txCounterSaved = txCounter;
  txSeqSaved = txSeq;
  revocationPublished = false;
  rotLen = 0;
  rotUntil = 0;

  if (!card) {
    logMsg("Sys", "WIPE: no card to erase; RAM purged anyway", ORANGE);
  } else if (left[0] == '\0') {
    logMsgf("Sys", RED, "WIPE: %d peer file(s), key/counter/revoked gone",
            peers);
    logMsg("Sys", "WIPE: identity and sessions gone from RAM", RED);
  } else {
    logMsgf("Sys", RED, "WIPE INCOMPLETE: still present: %s", left);
    logMsg("Sys", "RAM purged anyway; erase the card by hand", RED);
  }
  logMsg("Sys", "no identity: 'n' mints a new one", RED);
  drawStatus();
}

// A one-character console on the serial port, so the identity and
// card-lifecycle paths can actually be exercised: 'r' rotates (or, once this
// identity has been revoked, publishes a fresh identity instead), 'x' revokes,
// 'n' mints a new identity, 'w' wipes the card, 'p' sets or changes the store
// passphrase, 'i' prints the security posture, and 'y' (a capital 'Y' for the
// wipe) confirms an 'n' or a 'w'; any other key cancels, and a prompt left
// alone expires. See the README.
enum { CON_IDLE, CON_CONFIRM };
static int conMode = CON_IDLE;
static int conPending = 0; /* 1 = mint an identity, 2 = wipe the card */
static uint32_t conConfirmAt = 0; /* when the pending confirmation expires */
// A pending confirmation is cancelled after this long: a 'w' pressed and left
// alone must not be confirmed by a stray 'y' minutes later, and there is no
// other way for the operator to notice the prompt is still armed.
#define CONFIRM_MS 5000UL

// ---------------------------------------------------------------------------
// Platform security posture. This node REPORTS it and never gates on it: a
// plain build is a plain build, and the operator is the one who has to know
// which side of the line they are on (see the README's enablement section).
//
// Both queries are header-only inline functions in the bundled ESP-IDF
// (esp_flash_encrypt.h's esp_flash_encryption_enabled(), esp_secure_boot.h's
// esp_secure_boot_enabled()), so this adds no dependency and no library; the
// second one returns false when secure boot is not built into the bootloader,
// which is the honest answer for a build without it.
// ---------------------------------------------------------------------------
static bool secFlashEnc = false;
static bool secSecureBoot = false;

static void securityProbe() {
  secFlashEnc = esp_flash_encryption_enabled();
  secSecureBoot = esp_secure_boot_enabled();
}

// One boot line and one console command ('i'), a few lines at most: what is
// on, what is off, and the one consequence that matters for the files.
static void securityInfo(const char* what) {
  char id[CC_ADDR_SZ * 2 + 1];
  if (haveIdentity)
    toHex(myAddr, 4, id);
  else
    snprintf(id, sizeof(id), "no id");
  logMsgf("Sys", DARKGREY, "%s: id %s, sd %s", what, id,
          sdReady ? "mounted" : "ABSENT");
  logMsgf("Sys", (secFlashEnc && secSecureBoot) ? GREEN : ORANGE,
          "flash enc %s, secure boot %s", secFlashEnc ? "on" : "off",
          secSecureBoot ? "on" : "off");
  // How the sensitive files are stored, which is the part of the posture this
  // firmware can actually control: sealed with a passphrase, sealed but not
  // unlocked this session, plaintext, or -- reported as what it is -- an
  // identity file nothing can read.
  if (storeDamaged)
    logMsg("Sys", "store UNREADABLE: key.bin is not a store or plaintext file",
           RED);
  else if (storeMode == STORE_SEALED)
    logMsgf("Sys", storeKey.unlocked ? GREEN : RED, "store sealed: %s",
            storeKey.unlocked ? "unlocked" : "LOCKED");
  else
    logMsg("Sys", "store PLAINTEXT: no passphrase ('p' sets one)", ORANGE);
  logMsg("Sys", "protects: key.bin counter.bin revoked.bin peers/*.rp",
         DARKGREY);
  logMsg("Sys", "open: peers/*.bin (the cached announces) + the radio",
         DARKGREY);
  if (!secFlashEnc || !secSecureBoot)
    logMsg("Sys",
            "off: a card reader IS this node; files readable + rollback-able",
            RED);
}

// Called from loop(): a confirmation the operator walked away from expires.
static void consoleTick() {
  if (conMode == CON_CONFIRM && (int32_t)(millis() - conConfirmAt) > 0) {
    conMode = CON_IDLE;
    conPending = 0;
    logMsg("Sys", "confirmation timed out", ORANGE);
  }
}

static void handleConsole() {
  while (Serial.available() > 0) {
    int c = Serial.read();
    if (conMode == CON_CONFIRM) {
      int pending = conPending;
      // The wipe is irreversible and takes the card with it, so it wants a
      // deliberate key: uppercase 'Y' only. Minting an identity is recoverable
      // (wipe and try again), so 'y' or 'Y' does it.
      bool confirmed = (pending == 2) ? (c == 'Y') : (c == 'y' || c == 'Y');
      conMode = CON_IDLE;
      conPending = 0;
      if (confirmed) {
        if (pending == 1)
          mintNewIdentity();
        else
          wipeCard();
      } else {
        logMsg("Sys", "cancelled", ORANGE);
      }
      continue;
    }
    if (c == 'r' || c == 'R')
      publishRotation();
    else if (c == 'x' || c == 'X')
      publishRevocation();
    else if (c == 'i' || c == 'I')
      securityInfo("info");
    else if (c == 'p' || c == 'P')
      // Set or change the store passphrase. The passphrase itself is typed on
      // the device keyboard (masked), so this command only starts the flow.
      setPassphrase();
    else if (c == 'n' || c == 'N') {
      // Deliberate re-identification. Confirmed, because the old identity is
      // not recoverable from this node afterwards.
      conMode = CON_CONFIRM;
      conPending = 1;
      conConfirmAt = millis() + CONFIRM_MS;
      logMsg("Sys", "new identity: new address, peers must re-learn you",
             ORANGE);
      logMsg("Sys", "'y' confirms, any other key cancels (5 s)", ORANGE);
    } else if (c == 'w' || c == 'W') {
      // The card IS the identity (see the README): this is how you retire it.
      conMode = CON_CONFIRM;
      conPending = 2;
      conConfirmAt = millis() + CONFIRM_MS;
      logMsg("Sys", "WIPE: erases key, counter, revoked, peers", RED);
      logMsg("Sys", "'Y' (capital) confirms, any other key cancels (5 s)", RED);
    }
  }
}

#if defined(CC_RELAY)
// ---------------------------------------------------------------------------
// Relay (opt-in, CC_RELAY). The relay sees whole packets from the road, decides
// whether to re-broadcast them and hands back the bytes to send. It rewrites
// only the hops element; link traffic is never offered to it (a link record
// carries no destination and a link only exists between direct peers).
//
// On a medium that cannot attribute senders (last_src_len == 0: LoRa, and
// anonymous BLE) there is no link-layer source to hold an announce's hops == 0
// claim to, so the self-origin shortcut is inert: relayAnnounceAllowed() has
// no pin to check and simply refuses the claim (rxSrcLen == 0). What a route
// then rests on is the newest-announce-wins rule, which means an attacker in
// range must RE-RACE each announce to hold a route rather than claim it once
// -- and, because that is a contest rather than a proof, the three things that
// still bound it: the hops-excluded duplicate digest (a re-race must produce a
// new digest, not the same packet), the hops == 0 refusal above, and the two
// budgets (the global airtime budget and the per-destination data budget),
// which cap what any one route can spend in a window.
// ---------------------------------------------------------------------------

// The relay's clock is in seconds: the CC_RELAY_* defaults are expressed in
// ticks that the module documents as one second, and one SF7/125 kHz LoRa
// channel is this node's relay env.
static uint32_t relayNow() { return millis() / 1000; }

// Pinning: which cosechat address a link-layer source speaks for.
static int pinBySrc() {
  uint32_t now = millis();
  for (int i = 0; i < RELAY_PIN_MAX; i++) {
    if (!relayPins[i].src_len)
      continue;
    if ((uint32_t)(now - relayPins[i].seen) > RELAY_PIN_TTL_MS)
      continue; /* stale: a pin nobody refreshed proves nothing */
    if (relayPins[i].src_len == rxSrcLen &&
        memcmp(relayPins[i].src, rxSrc, rxSrcLen) == 0)
      return i;
  }
  return -1;
}

static int pinByAddr(const uint8_t addr[CC_ADDR_SZ]) {
  uint32_t now = millis();
  for (int i = 0; i < RELAY_PIN_MAX; i++) {
    if (relayPins[i].src_len &&
        (uint32_t)(now - relayPins[i].seen) <= RELAY_PIN_TTL_MS &&
        memcmp(relayPins[i].addr, addr, CC_ADDR_SZ) == 0)
      return i;
  }
  return -1;
}

static int pinByAddrRaw(const uint8_t addr[CC_ADDR_SZ]) {
  for (int i = 0; i < RELAY_PIN_MAX; i++) {
    if (relayPins[i].src_len &&
        memcmp(relayPins[i].addr, addr, CC_ADDR_SZ) == 0)
      return i;
  }
  return -1;
}

static void pinSet(const uint8_t addr[CC_ADDR_SZ]) {
  int slot = pinByAddr(addr);
  if (slot < 0) {
    slot = pinBySrc();
    if (slot < 0) {
      for (int i = 0; i < RELAY_PIN_MAX; i++) {
        if (!relayPins[i].src_len) {
          slot = i;
          break;
        }
      }
    }
  }
  if (slot < 0)
    slot = 0; /* full and all different: the oldest is simply reused */
  memcpy(relayPins[slot].addr, addr, CC_ADDR_SZ);
  memcpy(relayPins[slot].src, rxSrc, CC_ROAD_SRC_SZ);
  relayPins[slot].src_len = rxSrcLen;
  relayPins[slot].seen = millis();
}

// May this announce be offered to the relay? Only a hops==0 claim needs
// evidence, and the pin is it: the announce must have arrived from the source
// that address is pinned to, or from a source we have not seen it at all, in
// which case we pin it now -- that is what lets a neighbour's first announce
// through. A road that cannot attribute the sender gives no evidence, so the
// claim is refused here rather than believed.
static bool relayAnnounceAllowed(const cc_announce_t* ann) {
  if (ann->hops != 0)
    return true;
  if (rxSrcLen == 0)
    return false;
  int byAddr = pinByAddr(ann->addr);
  int bySrc = pinBySrc();
  if (byAddr >= 0 && byAddr != bySrc)
    return false; /* a different neighbour claiming a pinned address */
  // A live pin for this address and source: a refresh, not a new claim. A pin
  // that has LAPSED is a re-pin, and that is the takeover hazard made visible.
  if (byAddr < 0 && pinByAddrRaw(ann->addr) >= 0)
    statRelayRepin++;
  pinSet(ann->addr);
  return true;
}

// The neighbour address to hand the relay: the pin for the source this packet
// came from, or NULL ("no attribution") when there is none. Never derived from
// the packet's own contents.
static const uint8_t* relayFrom() {
  int i = pinBySrc();
  return (i >= 0) ? relayPins[i].addr : nullptr;
}

static void relayAnnounce(const uint8_t* pkt, size_t len, float rssi) {
  if (!relayAnnounceAllowed(&tmpAnn)) {
    statRelayOrg++;
    return;
  }
  int q = (int)(-rssi);
  if (q < 0)
    q = 0;
  if (q > 255)
    q = 255;
  size_t olen = 0;
  int rr =
      cc_relay_announce(&relay, &tmpAnn, relayFrom(), (uint8_t)q, relayNow(),
                        pkt, len, relayBuf, sizeof(relayBuf), &olen);
  if (rr == CC_RELAY_FWD && olen > 0 && roadSend(relayBuf, olen))
    logMsg("TX", "relay announce", DARKGREY);
}

static void relayForward(const uint8_t* pkt, size_t len) {
  size_t olen = 0;
  int rr = cc_relay_forward(&relay, pkt, len, relayNow(), relayBuf,
                            sizeof(relayBuf), &olen);
  if (rr == CC_RELAY_FWD && olen > 0 && roadSend(relayBuf, olen))
    logMsg("TX", "relay chat", DARKGREY);
}

// One compact line: what went out, and why the rest did not.
static void relayStatsLine() {
  cc_relay_stats_t s;
  if (cc_relay_stats(&relay, &s) != CC_OK)
    return;
  uint32_t other = s.e_arg + s.e_buf + s.e_format + s.e_version + s.e_maxhops +
                   s.e_expired + s.e_noimprove;
  logMsgf("Sys", DARKGREY,
          "relay fwd %lu rx %lu | dup %lu bud %lu unk %lu pow %lu org %lu "
          "pin %lu repin %lu oth %lu",
          (unsigned long)s.forwarded, (unsigned long)s.rx,
          (unsigned long)s.e_dup, (unsigned long)s.e_budget,
          (unsigned long)s.e_unknown, (unsigned long)s.e_pow,
          (unsigned long)s.e_origin, (unsigned long)statRelayOrg,
          (unsigned long)statRelayRepin, (unsigned long)other);
}
#endif

// ---------------------------------------------------------------------------
// Process a fully received cosechat packet
// ---------------------------------------------------------------------------
static void processPkt(const uint8_t* pkt, size_t len) {
  // Inert without an identity: nothing is accepted, so a damaged key file
  // cannot make this node answer, re-announce on a key_req, or display traffic
  // it can no longer authenticate as (see haveIdentity). Dropped before any
  // decode or crypto, so it costs nothing.
  if (!haveIdentity)
    return;
  uint8_t type = 0;
  int tr = cc_msg_type(pkt, len, &type);
  if (tr == CC_E_VERSION) {
    oldWireSeen();
    return;
  }
  if (tr != CC_OK)
    return;
  uint8_t hops = 0;
  int hr = cc_msg_hops(pkt, len, &hops);
  if (hr == CC_E_VERSION) {
    oldWireSeen();
    return;
  }
  if (hr != CC_OK || hops > CC_MAX_HOPS)
    return;  // drop; don't forward stale packets

  float rssi = road->last_rssi;

  if (type == CC_MSG_ANNOUNCE) {
    // Budget the verify itself, before paying for it: an announce is not
    // authenticated until cc_announce_parse() has checked the signature, so a
    // captured announce could otherwise be replayed at line rate to burn an
    // ML-DSA verify per packet. Refused announces are counted, not logged or
    // drawn (ANN_VERIFY_BURST per ANN_VERIFY_WINDOW_MS is generous enough for
    // a whole peer table to power up together).
    if (!annBudget.allow(ANN_VERIFY_WINDOW_MS)) {
      statAnnDrop++;
      return;
    }
    int ar = cc_announce_parse(&work, pkt, len, &tmpAnn);
    if (ar == CC_E_VERSION) {
      oldWireSeen();
      return;
    }
    if (ar != CC_OK)
      return;
    if (memcmp(tmpAnn.addr, myAddr, CC_ADDR_SZ) == 0)
      return;
    // A retired identity's announce is refused: revocation is terminal.
    if (isRevoked(tmpAnn.addr)) {
      statRevoked++;
      return;
    }
    // Announce lifecycle: accept only a strictly newer sequence (and honour an
    // advertised expiry). This is the dedup and anti-replay rule for
    // announces, which carry no replay-window counter of their own.
    int api = peerFind(tmpAnn.addr);
    const cc_announce_t* known = nullptr;
    if (api >= 0) {
      annCheckFill(api);
      known = &annCheckView;
    }
    if (cc_announce_fresh(known, &tmpAnn, millis()) != CC_OK) {
      statReplay++; /* older or expired announce: quiet drop */
      return;
    }
#if defined(CC_RELAY)
    relayAnnounce(pkt, len, rssi);
#endif
    // Unchanged content: no SD write, no log, no display refresh.
    if (!peerAddOrUpdate(&tmpAnn))
      return;
    char buf[CC_MAX_NAME_LEN + 24];
    snprintf(buf, sizeof(buf), "'%s' %.0fdBm (key)", tmpAnn.name, rssi);
    logMsg("ANN", buf, GREEN);
    drawStatus();

  } else if (type == CC_MSG_PRESENCE) {
    cc_presence_t pres;
    int pr = cc_presence_parse(&work, pkt, len, &pres);
    if (pr == CC_E_VERSION) {
      oldWireSeen();
      return;
    }
    if (pr != CC_OK)
      return;
    if (memcmp(pres.addr, myAddr, CC_ADDR_SZ) == 0)
      return;

    int known = peerFind(pres.addr);
    // Anti-replay for the unsigned class: dedup, not anti-spoofing (an attacker
    // can mine a seq for a claimed address), so a reject is a quiet drop.
    if (known >= 0) {
      if (cc_replay_check(&peerReplayUnsign[known], pres.addr, pres.seq) !=
          CC_OK) {
        statReplay++;
        return;
      }
      replayMaybeSave(known);
    }

    // A presence asserts nothing: it carries a name *hash*, not a name. It is
    // consistent only when both its address and that hash match the peer's
    // verified announce; a mismatch means "ignore this hint", never "the peer
    // renamed itself". The line is drawn at most once per PRES_LOG_MS with the
    // suppressed count folded in, because a fresh address cannot be
    // replay-checked and each accepted presence would otherwise buy the sender
    // a ~45 KiB display blit.
    bool consistent = false;
    if (known >= 0) {
      annCheckFill(known);
      consistent = cc_presence_matches_announce(&pres, &annCheckView) == CC_OK;
    }
    uint32_t now = millis();
    if (now - presLogAt >= PRES_LOG_MS) {
      presLogAt = now;
      char buf[CC_MAX_NAME_LEN + 48];
      if (consistent) {
        snprintf(buf, sizeof(buf), "'%s' %.0fdBm", peerNames[known], rssi);
      } else {
        char hex[CC_ADDR_SZ * 2 + 1];
        toHex(pres.addr, 4, hex);
        snprintf(buf, sizeof(buf), "%s (unverified) %.0fdBm", hex, rssi);
      }
      if (presSkipped > 0) {
        char more[24];
        snprintf(more, sizeof(more), " +%lu", (unsigned long)presSkipped);
        strncat(buf, more, sizeof(buf) - strlen(buf) - 1);
        presSkipped = 0;
      }
      logMsg("PRE", buf, ORANGE);
    } else {
      presSkipped++;
    }

    if (known < 0)
      requestAnnounce(pres.addr);

  } else if (type == CC_MSG_KEY_REQ) {
    uint8_t reqAddr[CC_ADDR_SZ];
    // The counter identifies a request, not a requester: it is that sender's
    // own counter, so it cannot be used to tell two requesters apart.
    uint32_t reqCounter = 0;
    int kr = cc_key_req_parse(&work, pkt, len, reqAddr, &reqCounter);
    (void)reqCounter;
    if (kr == CC_E_VERSION) {
      oldWireSeen();
      return;
    }
    if (kr != CC_OK)
      return;
    if (memcmp(reqAddr, myAddr, CC_ADDR_SZ) != 0)
      return;

    // A key_req names only its target, so there is no requester identity to
    // dedup on (this node's address is the one just checked, and it is never in
    // the peer list). Answers are therefore budgeted globally; a
    // rejected request is dropped silently, since logging it would hand an
    // attacker a cheap way to fill the display.
    if (answerBudget.allow(REQ_ANSWER_WINDOW_MS)) {
      logMsg("RX", "key_req (sending announce)", ORANGE);
      broadcastAnnounce();
    }

  } else if (type == CC_MSG_CHAT) {
    // Recipient first: never spend crypto on traffic for another node.
    uint8_t recip[CC_ADDR_SZ];
    if (cc_msg_recipient(pkt, len, recip) != CC_OK)
      return;
    if (memcmp(recip, myAddr, CC_ADDR_SZ) != 0) {
#if defined(CC_RELAY)
      // A chat for somebody else: this is the relay's business. A chat for us
      // is delivered locally and never re-broadcast.
      relayForward(pkt, len);
#endif
      return;
    }

    uint8_t sender[CC_ADDR_SZ];
    if (cc_chat_sender(pkt, len, sender) != CC_OK)
      return;
    char hex[CC_ADDR_SZ * 2 + 1];
    toHex(sender, 4, hex);

    // Terminal: no traffic from a retired address, cached or not.
    if (isRevoked(sender)) {
      statRevoked++;
      return;
    }

    int si = peerFind(sender);
    if (si < 0) {
      // No cached announce for the claimed sender: ask for it, and say so
      // without pretending a message arrived.
      statNoKey++;
      logMsgf("RX", ORANGE, "%s no key (key_req)", hex);
      requestAnnounce(sender);
      return;
    }
    // The sign key is already in RAM with the peer entry; the library checks
    // that it hashes to the claimed address and that the signature matches,
    // all before any decapsulation or display. No SD access on this path, so a
    // flood of forged chats cannot stall the SPI bus or wear the card. But the
    // ML-DSA verification is still the most expensive per-packet work here and
    // a valid chat is cheap to replay, so the budget is spent before it (see
    // CHAT_VERIFY_*); a refused chat is dropped and counted, like an announce
    // refused by annBudget.
    if (!chatBudget.allow(CHAT_VERIFY_WINDOW_MS)) {
      statChatDrop++;
      return;
    }
    int cr = cc_chat_parse(&work, &myKey, peerSignPub[si],
                           &peerReplayAuthed[si], pkt, len, &tmpChat);
    if (cr == CC_OK) {
      replayMaybeSave(si);
      char buf[CC_MAX_MSG_SZ + 16];
      snprintf(buf, sizeof(buf), "[%s] %.*s", hex, (int)tmpChat.msg_len,
               (const char*)tmpChat.msg);
      logMsg("RX", buf, YELLOW);
    } else if (cr == CC_E_NOKEY) {
      statNoKey++;
      logMsgf("RX", ORANGE, "%s no key (key_req)", hex);
      requestAnnounce(sender);
    } else if (cr == CC_E_SIG) {
      // Never display a message whose signature does not match the sender.
      statBadSig++;
      logMsgf("RX", RED, "%s bad signature", hex);
    } else if (cr == CC_E_REPLAY || cr == CC_E_STALE) {
      statReplay++;
    } else if (cr == CC_E_DECRYPT) {
      statDecrypt++;
      logMsgf("RX", RED, "%s decrypt failed", hex);
    } else if (cr == CC_E_VERSION) {
      oldWireSeen();
    } else {
      statDecrypt++; /* any other failure: counted, not shown */
    }

  } else if (type == CC_MSG_LINK_REQ) {
    // Accepting a handshake makes this node decapsulate and sign, so the
    // accept is budgeted before either: a link_req flood must not turn it into
    // a signature oracle.
    if (!linkAcceptBudget.allow(LINK_ACCEPT_WINDOW_MS)) {
      statLinkDrop++;
      return;
    }
    uint8_t rid[CC_LINK_ID_SZ];
    if (cc_link_id(pkt, len, rid) != CC_OK) {
      statLinkDrop++;
      return;
    }
    // Refuse an id that is already live or already pending: a replayed
    // link_req must not create a second slot that shadows the real session.
    if (linkFind(rid) || pendIndex(rid) >= 0) {
      statLinkDrop++;
      return;
    }
    // The answer goes into the pending table, NOT a session slot: an
    // unauthenticated request must not occupy (or be kept warm in) the table
    // the honest peers need. It is promoted only once it proves itself.
    cc_link_t* p = pendAlloc();
    if (!p) {
      statLinkDrop++;
      return;
    }
    size_t olen = 0;
    int ret = cc_link_accept(&work, p, &myKey, millis(), LINK_PENDING_TTL_MS,
                             pkt, len, linkBuf, sizeof(linkBuf), &olen, &rng);
    if (ret != CC_OK) {
      cc_link_forget(p);
      statLinkDrop++;
      return;
    }
    if (olen > 0 && roadSend(linkBuf, olen)) {
      logMsg("TX", "link_proof", CYAN);
    } else {
      pendForget((int)(p - linkPend));
      statLinkDrop++;
    }

  } else if (type == CC_MSG_LINK_PROOF) {
    uint8_t id[CC_LINK_ID_SZ];
    if (cc_link_id(pkt, len, id) != CC_OK) {
      statLinkDrop++;
      return;
    }
    cc_link_t* l = linkFind(id);
    if (!l) {
      statLinkDrop++;
      return;
    }
    // We initiated this link, so l->peer is known; without its cached announce
    // we cannot check the proof and the link is of no use to us.
    int pi = peerFind(l->peer);
    if (pi < 0) {
      cc_link_forget(l);
      statLinkDrop++;
      return;
    }
    int ret = cc_link_confirm(&work, l, l->peer, peerSignPub[pi], pkt, len);
    if (ret != CC_OK) {
      logMsgf("Sys", RED, "link_proof (%d)", ret);
      cc_link_forget(l);
      statLinkDrop++;
      return;
    }
    statLinkOpen++;
    logMsg("RX", "link open", GREEN);
    // Say who we are: the initiator's identity is not on the wire until an
    // identify record arrives, and the peer can only verify it against our
    // cached announce.
    {
      size_t olen = 0;
      if (cc_link_identify(&work, l, &myKey, millis(), linkBuf, sizeof(linkBuf),
                           &olen, &rng) == CC_OK &&
          olen > 0) {
        roadSend(linkBuf, olen);
      }
    }

  } else if (type == CC_MSG_LINK_DATA || type == CC_MSG_IDENTIFY ||
             type == CC_MSG_LINK_CLOSE) {
    handleLinkPacket(pkt, len);

  } else if (type == CC_MSG_ROTATE) {
    // A rotation verifies two signatures, so it is budgeted before either.
    if (!ctlVerifyBudget.allow(CTL_VERIFY_WINDOW_MS)) {
      statCtlDrop++;
      return;
    }
    uint8_t prev[CC_ADDR_SZ];
    if (cc_rotate_prev_addr(pkt, len, prev) != CC_OK) {
      statCtlDrop++;
      return;
    }
    int pi = peerFind(prev);
    if (pi < 0) {
      // A rotation from an identity we never cached: there is nothing to move,
      // and a successor must not be trusted on the word of a predecessor we
      // never verified. Wait for the new identity's own announce instead.
      statCtlDrop++;
      return;
    }
    // Reuse the announce scratch: nothing else is live on this path, and a
    // cc_announce_t must never go on this stack.
    uint8_t gotPrev[CC_ADDR_SZ];
    if (cc_rotate_parse(&work, pkt, len, peerSignPub[pi], &tmpAnn, gotPrev) !=
        CC_OK) {
      statCtlDrop++;
      return;
    }
    annCheckFill(pi);
    int acc =
        cc_rotate_accept(&annCheckView, &tmpAnn, revokedRecord(prev), millis());
    if (acc != CC_OK) {
      if (acc == CC_E_REVOKED)
        statRevoked++; /* a retired predecessor cannot vouch for a successor */
      statCtlDrop++;
      return;
    }
    // Move the entry onto the successor. Our nodes carry their counter space
    // across a rotation, so CONTINUES with the newest accepted counter as the
    // floor is the right rule (a successor that restarted its counter would be
    // dropped as stale -- such a node should use a fresh identity instead).
    uint32_t fa = peerReplayAuthed[pi].used ? peerReplayAuthed[pi].high : 0;
    uint32_t fu = peerReplayUnsign[pi].used ? peerReplayUnsign[pi].high : 0;
    rekeyPeer(pi, &tmpAnn, fa, fu);
    statRotated++;
    char hex[CC_ADDR_SZ * 2 + 1];
    toHex(tmpAnn.addr, 4, hex);
    logMsgf("RX", GREEN, "%s rotated (identity moved)", hex);
    drawStatus();

  } else if (type == CC_MSG_REVOKE) {
    if (!ctlVerifyBudget.allow(CTL_VERIFY_WINDOW_MS)) {
      statCtlDrop++;
      return;
    }
    // cc_revoke_parse wants the sign key of the address it revokes, and the
    // address is inside the packet. Trying our cached peers costs one CBOR
    // decode and address derivation each -- a wrong key answers CC_E_NOKEY
    // before any signature work -- so it is cheap and bounded.
    for (int i = 0; i < peerCount; i++) {
      uint8_t raddr[CC_ADDR_SZ];
      uint32_t rseq = 0, rexp = 0;
      int rr =
          cc_revoke_parse(&work, pkt, len, peerSignPub[i], raddr, &rseq, &rexp);
      if (rr == CC_E_NOKEY)
        continue; /* not this peer's key */
      if (rr != CC_OK) {
        statCtlDrop++;
        return;
      }
      // Record it. A refusal (table full of live records) is logged by
      // revokedAdd and still drops the peer below: the verified revocation is
      // a fact for this session even if it cannot be kept, and the operator
      // should know the retirement will not outlive the next announce.
      (void)revokedAdd(raddr, rseq, rexp);
      // Drop the retired identity AND any successor that arrived as a rotation
      // from it before this revocation landed: prev_addr is what finds those.
      for (int j = peerCount - 1; j >= 0; j--) {
        if (memcmp(peerAddrs[j], raddr, CC_ADDR_SZ) == 0 ||
            memcmp(peerPrevAddr[j], raddr, CC_ADDR_SZ) == 0) {
          linkDropPeer(peerAddrs[j]);
          peerRemove(j);
        }
      }
      statRevoked++;
      char hex[CC_ADDR_SZ * 2 + 1];
      toHex(raddr, 4, hex);
      logMsgf("RX", RED, "%s REVOKED", hex);
      drawStatus();
      return;
    }
    statCtlDrop++; /* nobody here to verify it */
  }
}

// ---------------------------------------------------------------------------
// Drain the road — whole packets only, framing is the road's business
// ---------------------------------------------------------------------------
static void pumpRoad() {
  size_t len;
  while (road->recv(road, rxPkt, sizeof(rxPkt), &len) == CC_ROAD_OK) {
#if defined(CC_RELAY)
    // Attribution belongs to this packet and nothing else consumes a packet
    // from the road before processPkt().
    rxSrcLen = road->last_src_len;
    if (rxSrcLen > 0)
      memcpy(rxSrc, road->last_src, CC_ROAD_SRC_SZ);
#endif
    processPkt(rxPkt, len);
  }
}

// ---------------------------------------------------------------------------
// Keyboard
// ---------------------------------------------------------------------------
static void handleKeyboard() {
  if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
    return;
  auto ks = M5Cardputer.Keyboard.keysState();

  bool tabPressed = false;
  for (auto k : ks.word) {
    if (k == '\t')
      tabPressed = true;
    else
      inputBuf += k;
  }

  if (ks.del && inputBuf.length() > 0) {
    inputBuf.remove(inputBuf.length() - 1);
  }

  // Tab: cycle peers
  if (tabPressed) {
    if (peerCount > 0) {
      peerSel = (peerSel + 1) % peerCount;
      drawStatus();
    }
    return;
  }

  if (ks.enter) {
    String msg = inputBuf;
    msg.trim();
    inputBuf = "";
    drawInput();

    if (msg.isEmpty())
      return;

    if (!haveIdentity) {
      logMsg("Sys", "no identity: 'n' mints one", RED);
      return;
    }

    if (peerSel < 0 || peerSel >= peerCount) {
      logMsg("Sys", "no peer selected (Tab)", RED);
      return;
    }

    // Preferred path: a live link to the selected peer. One AEAD record, no
    // per-message signature, one fragment for a line of text, and the link's
    // sequence window is the replay defence. Otherwise start a handshake and
    // send the opportunistic signed chat so the message still gets through
    // while the link is being set up.
    cc_link_t* link = linkFindPeer(peerAddrs[peerSel]);
    if (link && cc_link_active(link, millis())) {
      size_t len = 0;
      int ret = cc_link_send(&work, link, CC_LINK_KIND_DATA,
                             (const uint8_t*)msg.c_str(), msg.length(),
                             millis(), linkBuf, sizeof(linkBuf), &len);
      if (ret == CC_OK) {
        // The record is encoded and the sequence is committed: from here the
        // message exists, so a transmit failure is reported and NOT retried on
        // the signed path, which would deliver it twice.
        if (len > 0 && roadSend(linkBuf, len)) {
          char disp[CC_MAX_MSG_SZ + 32];
          snprintf(disp, sizeof(disp), "-> %s (link)", msg.c_str());
          logMsg("TX", disp, CYAN);
        } else {
          logMsg("Sys", "link record sent to the road FAILED", RED);
        }
        return;
      }
      // Only an encode/policy failure (e.g. the link went idle in between)
      // falls through, where nothing reached the medium.
      logMsgf("Sys", RED, "link send (%d), falling back", ret);
    } else {
      linkStart(peerSel);
    }

    size_t len = 0;
    int ret = cc_chat_build(
        &work, &myKey, peerAddrs[peerSel], peerKemPub[peerSel], nextCounter(),
        (const uint8_t*)msg.c_str(), msg.length(),
        admitFor(peerSel, CC_ADMIT_CHAT), chatBuf, sizeof(chatBuf), &len, &rng);
    if (ret == CC_OK && len > 0 && roadSend(chatBuf, len)) {
      char disp[CC_MAX_MSG_SZ + 32];
      snprintf(disp, sizeof(disp), "-> %s (signed)", msg.c_str());
      logMsg("TX", disp, CYAN);
    } else {
      logMsgf("Sys", RED, "chat failed (%d)", ret);
    }
    return;
  }

  drawInput();
}

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------
void setup() {
  auto cfg = M5.config();
  M5Cardputer.begin(cfg, true);
  M5Cardputer.Display.setRotation(1);
  Serial.begin(115200);

  // Shared SPI bus: SD card and LoRa cap both hang off it.
  SPI.begin(SPI_SCK, SPI_MISO, SPI_MOSI, SPI_CS);
  spiMux = xSemaphoreCreateMutex();

  // Display
  auto& D = M5Cardputer.Display;
  D.fillScreen(BLACK);
  D.setTextSize(1);

  // Canvas for scrolling log
  int canvasH = D.height() - STATUS_H - 6 - 14;
  canvas.createSprite(D.width() - 8, canvasH);
  canvas.setTextScroll(true);
  canvas.fillSprite(BLACK);
  canvas.setTextSize(1);

  // Crypto RNG. A missing RNG would make keygen silently weak, so it is a
  // hard failure rather than a warning.
  if (wc_InitRng(&rng) != 0) {
    logMsg("Sys", "RNG init FAILED", RED);
    while (true) delay(1000);
  }

  // Road
#if defined(CC_ROAD_BLE)
  cc_road_ble_cfg_t bleCfg;
  cc_road_ble_defaults(&bleCfg);
  int ret = cc_road_ble_init(&roadImpl, &bleCfg);
#elif defined(CC_ROAD_80211)
  cc_road_80211_cfg_t rawCfg;
  cc_road_80211_defaults(&rawCfg);
  int ret = cc_road_80211_init(&roadImpl, &rawCfg);
#elif defined(CC_ROAD_WIFI)
  cc_road_wifi_cfg_t wifiCfg;
  cc_road_wifi_defaults(&wifiCfg);
  wifiCfg.ssid = WIFI_SSID;
  wifiCfg.pass = WIFI_PASS;
  int ret = cc_road_wifi_init(&roadImpl, &wifiCfg);
#else
  // I2C for the port expander that drives the cap's antenna switch
  m5::In_I2C.begin(I2C_NUM_0, 8, 9);
  if (ioe.begin()) {
    ioe.setDirection(0, true);
    ioe.setHighImpedance(0, false);
    ioe.digitalWrite(0, true);  // antenna enable
    ioe.setDirection(7, true);
    ioe.setHighImpedance(7, false);
    ioe.digitalWrite(7, true);  // RX mode
  }

  cc_road_lora_cfg_t loraCfg;
  cc_road_lora_defaults(&loraCfg);
  loraCfg.pin_sck = -1;  // bus already begun above
  loraCfg.spi_mux = spiMux;
  loraCfg.antenna = [](int rx) {
    ioe.digitalWrite(7, rx);
    delay(2);
  };
  int ret = cc_road_lora_init(&roadImpl, &loraCfg);
#endif

  if (ret != CC_ROAD_OK) {
    logMsg("Sys", "road init FAILED", RED);
    logMsgf("Sys", RED, "err %d", ret);
    while (true) delay(1000);
  }

  // Store. The passphrase is asked for HERE -- after the display and the RNG,
  // and before anything reads the card -- because the order is forced: the
  // console only goes live in loop(), and broadcastAnnounce() already fires at
  // the end of setup(), so any later prompt would mean the node had read a
  // locked store and gone public without ever asking. With no card, or with a
  // card whose identity file is damaged, this does not prompt at all (see
  // storeBoot()).
  storeBoot();

  // Identity. Three answers, and the two that are not "loaded" must never be
  // answered with a fresh keypair: a key file that is PRESENT but does not load
  // is damage, and NO CARD AT ALL is not an empty card (minting on a cardless
  // boot used to be silent re-identification -- peers would see a stranger, the
  // operator would likely never notice, and the node's links and its
  // rotation/revocation continuity would be orphaned). In both cases the
  // node fails closed and says so; 'n' is the deliberate way out.
  int kr = keyLoad();
  if (kr == FILE_ST_NOCARD) {
    haveIdentity = false;
    logMsg("Sys", "no SD card: refusing to mint an identity", RED);
    logMsg("Sys", "insert the card, or 'n' to run without one", RED);
  } else if (kr == FILE_ST_OK) {
    haveIdentity = true;
    logMsg("Sys", "key loaded", ORANGE);
  } else {
    int cs = cardHasState();
    if (kr == FILE_ST_ABSENT && cs == FILE_ST_ABSENT) {
      logMsg("Sys", "generating key (fresh card)...", ORANGE);
      if (cc_key_generate(&myKey, &rng) != CC_OK) {
        logMsg("Sys", "keygen FAILED", RED);
        while (true) delay(1000);
      }
      haveIdentity = true;
      if (!keySave())
        logMsg("Sys", "WARNING: key.bin NOT saved", RED);
      logMsg("Sys", "key saved", ORANGE);
    } else {
      haveIdentity = false;
      if (cs == FILE_ST_NOCARD) {
        logMsg("Sys", "no SD card: refusing to mint an identity", RED);
        logMsg("Sys", "insert the card, or 'n' to run without one", RED);
      } else if (storeLocked()) {
        // Not readable because the store is locked, which is not the same claim
        // as a damaged file: the boot above already said the passphrase was not
        // accepted.
        logMsg("Sys", "key.bin not read: store LOCKED, refusing to run", RED);
        logMsg("Sys", "no identity: 'w' wipes, 'n' mints one, deliberately",
                RED);
      } else {
        logMsg("Sys", kr == FILE_ST_INVALID ?
                          "key.bin INVALID: refusing to run" :
                          "key.bin MISSING but the card has state",
                RED);
        logMsg("Sys", "no identity: 'n' mints one, deliberately", RED);
      }
    }
  }

  if (haveIdentity)
    cc_addr_from_key(&myKey, myAddr);
  else
    memset(myAddr, 0, sizeof(myAddr));

  // Outbound freshness values: resume from SD, else seed from the hardware RNG
  // so a reboot does not restart at values a peer already accepted. With no
  // card the seeds are not persisted, so a reboot can still repeat one; the
  // state file is the fix, and a peer's replay window (or its announce-seq
  // high-water mark) rejects the repeat.
  if (!stateLoad()) {
    txCounter = esp_random();
    txSeq = esp_random();
    txCounterSaved = txCounter;
    txSeqSaved = txSeq;
  }
  if (haveIdentity)
    stateSave(); /* persist the resumed/seeded values before the first send */

  // Announce our admission policy: what senders should mine for the directed
  // types they send us. This is congestion pricing, not a flood defence, and
  // the receive side never trusts a peer's declaration for anything -- it
  // always enforces its own CC_POW_DIFFICULTY_*.
  cc_admit_default(myAdmit);

  // Retirements, so a revoked identity stays revoked across a reboot.
  revokedLoad();

  // What posture this build is running under, in the operator's view: the
  // platform's flash-encryption and secure-boot fuses, and whether the card is
  // even there. Reported, never gated on (see securityInfo()).
  securityProbe();
  securityInfo("boot");

#if defined(CC_RELAY)
  cc_relay_init(&relay);
#endif

  // Load known peers from SD
  peersFromSD();
  logMsgf("Sys", ORANGE, "%d peers from SD", peerCount);
  if (peerCount > 0)
    peerSel = 0;

  drawStatus();
  drawInput();

  // Announce at boot (proves identity); presence sent periodically after
  broadcastAnnounce();
  lastAnn = millis();
  lastStats = millis();
}

// ---------------------------------------------------------------------------
// loop
// ---------------------------------------------------------------------------
void loop() {
  M5Cardputer.update();
  handleKeyboard();
  handleConsole();
  consoleTick();
  pumpRoad();
  linkMaintain();

  if (millis() - lastAnn >= ANNOUNCE_MS) {
    broadcastPresence();
    // Re-broadcast a recent rotation while it is in its grace window, so a peer
    // that missed the first copy can still move its trust to the new identity.
    if (rotLen > 0) {
      if ((int32_t)(millis() - rotUntil) < 0) {
        roadSend(ctlBuf, rotLen);
      } else {
        rotLen = 0;
      }
    }
    lastAnn = millis();
    drawStatus();
  }

  // Surface the road's fragment counters and this node's drop reasons every so
  // often: without them the medium's losses and the v9 protections are
  // invisible. All road structs carry the same stats fields.
  if (millis() - lastStats >= STATS_MS) {
    lastStats = millis();
    logMsgf("Sys", DARKGREY, "rx %lu drop %lu tx %lu fail %lu",
            (unsigned long)roadImpl.stats.rxFrag,
            (unsigned long)roadImpl.stats.rxDrop,
            (unsigned long)roadImpl.stats.txFrag,
            (unsigned long)roadImpl.stats.txFail);
    logMsgf("Sys", DARKGREY,
            "rp %lu sig %lu nokey %lu dec %lu cd %lu ann %lu v %lu "
            "link %lu/%lu rot %lu rev %lu ctl %lu",
            (unsigned long)statReplay, (unsigned long)statBadSig,
            (unsigned long)statNoKey, (unsigned long)statDecrypt,
            (unsigned long)statChatDrop, (unsigned long)statAnnDrop,
            (unsigned long)statOldWire,
            (unsigned long)statLinkOpen, (unsigned long)statLinkDrop,
            (unsigned long)statRotated, (unsigned long)statRevoked,
            (unsigned long)statCtlDrop);
#if defined(CC_RELAY)
    relayStatsLine();
#endif
  }

  // Persist the outbound counter/seq if either has drifted from the saved copy.
  stateMaybeSave();

  delay(5);
}
