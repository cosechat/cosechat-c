// cosechat demo node — CardputerADV, on a road (`road_lora`, `road_wifi`,
// `road_ble` or `road_80211`).
//
// Default road is LoRa (M5 LoRa Cap 1262); build one of the other PlatformIO
// envs (wifi/ble/dot11) for a different road. The rest of the node is
// identical because the road hides framing and fragmentation.
//
//   Tab   = cycle peers        Enter = send chat to selected peer
//   Serial console: r rotate identity, x revoke it, n mint a new identity,
//   w wipe the card, g create a group, j<hex> join one, s share its secret,
//   p<text> post to it ('n' and 'w' ask for a confirmation key).
//
// SD, under /cc/, every file wrapped in a 9-byte magic+version+CRC envelope:
//   key.bin         <form byte><keys> -- the SEED form by default
//                   (sign_seed, kem_seed, sign_pub); the expanded form is
//                   written only for an identity that has no seed, i.e. one
//                   loaded from an expanded file.
//   counter.bin     freshness counter, announce seq, identity-retired flag
//   revoked.bin     remembered retirements
//   group.bin       the group secret and our post sequence
//   peers/<addr_hex>.bin  the cached announce (with a payload version byte)
//   peers/<addr_hex>.rp   that peer's two replay windows
// Every peer's public keys are also cached in RAM; SD is the cold store.
//
// The SD card and the SX1262 share one SPI bus, so the demo creates a mutex
// and hands it to the LoRa road as `spi_mux`.

#include <Arduino.h>
#include <SD.h>
#include <SPI.h>
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

// Link (session) layer. LINK_MAX bounds concurrent sessions: this is a
// handheld with one selected peer at a time, so four covers the live
// conversation plus a handshake or two in flight, at 168 bytes each (672 B
// total) instead of the ~2.2 KiB sixteen would take. A fifth peer simply
// waits for a slot to free.
#define LINK_MAX 4
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

// Group messaging (one group per node; the library's CC_MSG_GROUP_DATA type).
// A group is a shared 32-byte secret and nothing else: no membership protocol,
// no epochs, and REMOVAL IS A NEW GROUP (a new secret, hence a new gid). A post
// is sealed under the group key, so a post that decrypts proves only that
// someone holding the key made it -- the poster field is self-claimed and
// non-binding (see the header, and the README's wording).
//
// The secret is persisted in one small file under /cc/ because a group that a
// reboot forgot would silently stop working; it sits there IN THE CLEAR, like
// the node key, so anyone who reads the card is a member -- the README says so
// plainly.
//
// GROUP_WIN_MAX is the per-poster replay state bound: one window per poster
// label, allocated only by a post that has AUTHENTICATED (so a stranger who has
// merely seen one post and learned the gid -- which is on the air -- cannot
// claim a slot at all), and released only by a group change. When the table is
// full, the LEAST RECENTLY VERIFIED label is evicted rather than a new label
// refused: refusing would let anyone who can mine a few packets fill the table
// and make this node permanently deaf to every unseen label -- a new member's
// first post, or an existing member's post after a rotation. Evicting loses
// that label's window, so its old post could be displayed a second time; a post
// mutates no app state, and the window exists to stop a *re*action, so a
// duplicate display is the cheap side of that trade. The gid and poster are
// inside each cc_group_win_t, so two groups or two labels can never share a
// sequence space.
#define GROUP_FILE "/cc/group.bin"
#define GROUP_VERSION 1
#define GROUP_WIN_MAX 8
// Group posts are budgeted before their work (a PoW check plus an AEAD attempt)
// exactly like a chat, and for the same reason: on WiFi/802.11 a broadcast post
// is cheap to replay and would otherwise keep the verifier busy. Refusals are
// counted (statGroupDrop) and dropped without a display line.
#define GROUP_VERIFY_BURST MAX_PEERS
#define GROUP_VERIFY_WINDOW_MS 4000UL
// The group file also carries our post sequence, saved on the same drift
// cadence the outbound counter uses: a reboot resumes CC_REPLAY_WINDOW past the
// saved value, so a repeated (gid, poster, seq) -- which a receiver treats as a
// replay, not a nonce reuse -- cannot happen across a power loss.
#define GROUP_SAVE_MIN_MS 1000UL

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
static cc_link_t links[LINK_MAX];
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

// ---------------------------------------------------------------------------
// Group state. ONE group per node: the secret (41 B), the per-poster replay
// windows the library hands over (GROUP_WIN_MAX of them, 56 B each), the
// decrypted-post scratch and the TX buffer. All static, no heap.
// ---------------------------------------------------------------------------
static cc_group_t group; /* used == 0 until we create or join one */
static cc_group_win_t groupWins[GROUP_WIN_MAX];
// The throwaway window an unseen label is parsed against: a slot in groupWins
// is claimed only when that parse AUTHENTICATES, so an outsider who has only
// seen one post (the gid is on the air) cannot exhaust the table with junk
// labels and silence members whose labels we have not seen yet.
static cc_group_win_t groupWinScratch;
// Slot occupancy. A slot is marked used only when an authenticated post claimed
// it, and a group change frees the slots of the group it left. The library's
// own `last_seen` stamp cannot carry this on its own: it is 0 both for a slot
// we have never used and (in principle) for one verified in the first
// millisecond after boot, and an eviction decision must not confuse the two.
static uint8_t groupWinUsed[GROUP_WIN_MAX];
static cc_group_msg_t groupMsg; /* a decrypted post: 552 B, so static */
static uint8_t groupBuf[CC_GROUP_BUF_SZ]; /* our own post, before it is sent */
// Our monotonic post counter. It is per (gid, poster) as far as receivers are
// concerned, but it is kept monotonic across groups as well, which is simpler
// and never hurts: a new gid starts every receiver's window from scratch.
static uint32_t groupSeq = 0;
static uint32_t groupSeqSaved = 0; /* the value on the card */
static uint32_t lastGroupSaveTry = 0;

// The receive paths are defined before these helpers, so forward-declare the
// two they call.
static void groupDropStaleWins();
static void groupSave();

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

// Verify budget for inbound group posts (see GROUP_VERIFY_*), spent before the
// PoW check and the AEAD attempt in cc_group_post_parse().
static WindowBudget<GROUP_VERIFY_BURST> groupBudget;

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
static uint32_t statGroupDrop =
    0; /* group posts refused: budget, label table full, or bad post */
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

// The inverse, for the console's `j<hex>` argument. Rejects anything that is
// not hex.
static int hexNibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static bool fromHex(const char* hex, size_t n, uint8_t* out) {
  for (size_t i = 0; i < n; i++) {
    int hi = hexNibble(hex[i * 2]), lo = hexNibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0)
      return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
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
  if (sdExists(STATE_FILE) || sdExists(GROUP_FILE) || sdExists(REVOKED_FILE))
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
static bool envReadHeader(File& f, uint32_t* crc_out) {
  uint8_t h[ENV_HDR_SZ];
  if (f.read(h, ENV_HDR_SZ) != ENV_HDR_SZ)
    return false;
  if (memcmp(h, ENV_MAGIC, 4) != 0 || h[4] != ENV_VERSION)
    return false;
  *crc_out = (uint32_t)h[5] | ((uint32_t)h[6] << 8) | ((uint32_t)h[7] << 16) |
             ((uint32_t)h[8] << 24);
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
  uint8_t b[11];
  size_t got = 0;
  bool present = false;
  uint32_t claim = 0;
  bool ok = sdAccess(STATE_FILE, FILE_READ, [&](File& f) {
    present = true;
    got = (size_t)f.size();
    if (got != ENV_HDR_SZ + 6 && got != ENV_HDR_SZ + 10 &&
        got != ENV_HDR_SZ + sizeof(b))
      return false;
    if (!envReadHeader(f, &claim))
      return false;
    got -= ENV_HDR_SZ;
    if (f.read(b, got) != got)
      return false;
    return crc32(b, got) == claim;
  });
  if (!ok || b[0] != 0xCC || (b[1] != 1 && b[1] != STATE_VERSION)) {
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
  revocationPublished = (got == sizeof(b)) && (b[10] & 1) != 0;
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

static void stateSave() {
  lastStateTry = millis();
  if (!sdReady)
    return;
  uint32_t c = txCounter, s = txSeq;
  uint8_t b[11] = {0xCC,
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
  uint8_t hdr[ENV_HDR_SZ];
  envWriteHeader(hdr, crc32(b, sizeof(b)));
  if (!sdAccess(STATE_FILE, FILE_WRITE, [&](File& f) {
        return f.write(hdr, ENV_HDR_SZ) == ENV_HDR_SZ &&
               f.write(b, sizeof(b)) == sizeof(b);
      }))
    return; /* not saved: leave the saved markers alone so drift stays visible
             */
  txCounterSaved = c;
  txSeqSaved = s;
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
static void replaySave(int i) {
  char path[64];
  peerPath(peerAddrs[i], ".rp", path, sizeof(path));
  const cc_replay_t* un = &peerReplayUnsign[i];
  const cc_replay_t* au = &peerReplayAuthed[i];
  uint8_t ver = REPLAY_VERSION;
  uint8_t hdr[ENV_HDR_SZ];
  uint32_t c = crc32Update(crc32Start(), &ver, 1);
  c = crc32Update(c, (const uint8_t*)un, sizeof(cc_replay_t));
  c = crc32Update(c, (const uint8_t*)au, sizeof(cc_replay_t));
  envWriteHeader(hdr, crc32Finish(c));
  sdAccess(path, FILE_WRITE, [&](File& f) {
    f.write(hdr, ENV_HDR_SZ);
    f.write(&ver, 1);
    f.write((const uint8_t*)un, sizeof(cc_replay_t));
    f.write((const uint8_t*)au, sizeof(cc_replay_t));
    return true;
  });
  peerReplaySavedAt[i] = millis();
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
  bool ok = sdAccess(path, FILE_READ, [&](File& f) {
    present = true;
    uint32_t claim = 0;
    if (!envReadHeader(f, &claim))
      return false;
    uint8_t ver = 0;
    if (f.read(&ver, 1) != 1 || ver != REPLAY_VERSION)
      return false;
    if (f.read((uint8_t*)&un, sizeof(un)) != sizeof(un))
      return false;
    if (f.read((uint8_t*)&au, sizeof(au)) != sizeof(au))
      return false;
    uint32_t c = crc32Update(crc32Start(), &ver, 1);
    c = crc32Update(c, (const uint8_t*)&un, sizeof(un));
    c = crc32Update(c, (const uint8_t*)&au, sizeof(au));
    if (crc32Finish(c) != claim)
      return false;
    // A state that belongs to another peer, or carries the other class, would
    // make every packet from this peer return CC_E_ARG: reject it and start
    // from fresh windows instead of muting the peer.
    if (memcmp(un.addr, addr, CC_ADDR_SZ) != 0 ||
        memcmp(au.addr, addr, CC_ADDR_SZ) != 0 ||
        un.cls != CC_REPLAY_UNSIGNED || au.cls != CC_REPLAY_AUTHED)
      return false;
    return true;
  });
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
// links and its group membership, and looks to every peer like a stranger. The
// caller fails closed instead (see setup()).
static int keyLoad() {
  static uint8_t ss[CC_SIGN_SEED_SZ], ks[CC_KEM_SEED_SZ];
  static uint8_t sp[CC_SIGN_PRIVKEY_SZ], sb[CC_SIGN_PUBKEY_SZ],
      kp[CC_KEM_PRIVKEY_SZ];
  if (!sdInit())
    return FILE_ST_NOCARD; /* no card is not an empty card (see setup()) */
  bool present = false;
  bool seed_form = false;
  bool ok = sdAccess(KEY_FILE, FILE_READ, [&](File& f) {
    present = true; /* it opened: a failure below is damage, not absence */
    size_t want = (size_t)f.size();
    if (want != (size_t)(ENV_HDR_SZ + KEY_SEED_PAYLOAD_SZ) &&
        want != (size_t)(ENV_HDR_SZ + KEY_EXP_PAYLOAD_SZ))
      return false;
    uint32_t claim = 0;
    if (!envReadHeader(f, &claim))
      return false;
    uint8_t form = 0;
    if (f.read(&form, 1) != 1)
      return false;
    uint32_t c = crc32Update(crc32Start(), &form, 1);
    if (form == KEY_FORM_SEED) {
      if (want != (size_t)(ENV_HDR_SZ + KEY_SEED_PAYLOAD_SZ))
        return false;
      // Trust each read, not just the file size.
      if (f.read(ss, sizeof(ss)) != sizeof(ss))
        return false;
      if (f.read(ks, sizeof(ks)) != sizeof(ks))
        return false;
      if (f.read(sb, CC_SIGN_PUBKEY_SZ) != CC_SIGN_PUBKEY_SZ)
        return false;
      c = crc32Update(c, ss, sizeof(ss));
      c = crc32Update(c, ks, sizeof(ks));
      c = crc32Update(c, sb, CC_SIGN_PUBKEY_SZ);
      seed_form = true;
    } else if (form == KEY_FORM_EXPANDED) {
      if (want != (size_t)(ENV_HDR_SZ + KEY_EXP_PAYLOAD_SZ))
        return false;
      if (f.read(sp, CC_SIGN_PRIVKEY_SZ) != CC_SIGN_PRIVKEY_SZ)
        return false;
      if (f.read(sb, CC_SIGN_PUBKEY_SZ) != CC_SIGN_PUBKEY_SZ)
        return false;
      if (f.read(kp, CC_KEM_PRIVKEY_SZ) != CC_KEM_PRIVKEY_SZ)
        return false;
      c = crc32Update(c, sp, CC_SIGN_PRIVKEY_SZ);
      c = crc32Update(c, sb, CC_SIGN_PUBKEY_SZ);
      c = crc32Update(c, kp, CC_KEM_PRIVKEY_SZ);
    } else {
      return false; /* not a form this build ever wrote */
    }
    return crc32Finish(c) == claim;
  });
  int rc = FILE_ST_INVALID;
  if (!present) {
    rc = FILE_ST_ABSENT;
  } else if (ok) {
    bool imported = seed_form ? (cc_key_import_seed(&myKey, ss, ks) == CC_OK)
                              : (cc_key_import(&myKey, sp, sb, kp) == CC_OK);
    if (imported) {
      // Cross-check the sign half, in BOTH forms: the key must hold the signing
      // key whose public half is the `sign_pub` stored beside it, or this node
      // would announce one public key and sign with another (mute, and looking
      // healthy). `sp` is the scratch for the derived public half: on the seed
      // path it holds no sign_priv, and on the expanded path the import has
      // already copied it into the key, so the two are never live at once.
      imported = cc_key_export_public(&myKey, sp, kp) == CC_OK &&
                 memcmp(sp, sb, CC_SIGN_PUBKEY_SZ) == 0;
    }
    if (imported) {
      rc = FILE_ST_OK;
    } else {
      cc_key_free(&myKey); /* leave nothing half-imported behind */
      rc = FILE_ST_INVALID;
    }
  }
  wipe(ss, sizeof(ss));
  wipe(ks, sizeof(ks));
  wipe(sp, sizeof(sp));
  wipe(sb, sizeof(sb));
  wipe(kp, sizeof(kp));
  return rc;
}

// Save the identity in the seed form when the key has a seed (always true for
// one this node generated), and in the expanded form when it does not. Returns
// true only when the file was written.
static bool keySave() {
  static uint8_t ss[CC_SIGN_SEED_SZ], ks[CC_KEM_SEED_SZ];
  static uint8_t sp[CC_SIGN_PRIVKEY_SZ], kp[CC_KEM_PRIVKEY_SZ];
  static uint8_t sb[CC_SIGN_PUBKEY_SZ], kb[CC_KEM_PUBKEY_SZ];
  uint8_t hdr[ENV_HDR_SZ];
  uint8_t form = 0;
  uint32_t c = crc32Start();
  bool ok = false;
  if (cc_key_export_private(&myKey, sp, kp) != CC_OK ||
      cc_key_export_public(&myKey, sb, kb) != CC_OK) {
    logMsg("Sys", "key export FAILED: not saved", RED);
  } else {
    int sr = cc_key_export_seed(&myKey, ss, ks);
    if (sr == CC_OK) {
      form = KEY_FORM_SEED;
      c = crc32Update(c, &form, 1);
      c = crc32Update(c, ss, sizeof(ss));
      c = crc32Update(c, ks, sizeof(ks));
      c = crc32Update(c, sb, CC_SIGN_PUBKEY_SZ);
    } else if (sr == CC_E_NOKEY) {
      // Usable identity, no knowable seed (it was imported expanded). Save it
      // the only way it can be saved, and say so: it is ~3.9 KB larger, but
      // saving nothing here would leave the PREVIOUS identity on the card while
      // this node announces the new one.
      form = KEY_FORM_EXPANDED;
      logMsg("Sys", "key has no seed: saving the expanded form", ORANGE);
      c = crc32Update(c, &form, 1);
      c = crc32Update(c, sp, CC_SIGN_PRIVKEY_SZ);
      c = crc32Update(c, sb, CC_SIGN_PUBKEY_SZ);
      c = crc32Update(c, kp, CC_KEM_PRIVKEY_SZ);
    } else {
      logMsgf("Sys", RED, "key export failed (%d): not saved", sr);
    }
    if (form != 0) {
      envWriteHeader(hdr, crc32Finish(c));
      ok = sdAccess(KEY_FILE, FILE_WRITE, [&](File& f) {
        if (f.write(hdr, ENV_HDR_SZ) != ENV_HDR_SZ || f.write(&form, 1) != 1)
          return false;
        if (form == KEY_FORM_SEED) {
          return f.write(ss, sizeof(ss)) == sizeof(ss) &&
                 f.write(ks, sizeof(ks)) == sizeof(ks) &&
                 f.write(sb, CC_SIGN_PUBKEY_SZ) == CC_SIGN_PUBKEY_SZ;
        }
        return f.write(sp, CC_SIGN_PRIVKEY_SZ) == CC_SIGN_PRIVKEY_SZ &&
               f.write(sb, CC_SIGN_PUBKEY_SZ) == CC_SIGN_PUBKEY_SZ &&
               f.write(kp, CC_KEM_PRIVKEY_SZ) == CC_KEM_PRIVKEY_SZ;
      });
    }
  }
  wipe(ss, sizeof(ss));
  wipe(ks, sizeof(ks));
  wipe(sp, sizeof(sp));
  wipe(sb, sizeof(sb));
  wipe(kp, sizeof(kp));
  wipe(kb, sizeof(kb));
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
  for (int i = 0; i < LINK_MAX; i++) {
    if (links[i].used && memcmp(links[i].id, id, CC_LINK_ID_SZ) == 0)
      return &links[i];
  }
  return nullptr;
}

static cc_link_t* linkFindPeer(const uint8_t addr[CC_ADDR_SZ]) {
  for (int i = 0; i < LINK_MAX; i++) {
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
  for (int i = 0; i < LINK_MAX; i++) {
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
  for (int i = 0; i < LINK_MAX; i++) {
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
  for (int i = 0; i < LINK_MAX; i++) {
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
  } else if (kind == CC_LINK_KIND_GROUP_KEY) {
    // Group-secret provisioning over an open link, a convenience beside the
    // typed-secret path. The link key authenticated the record and the link's
    // own sequence window is its replay defence, exactly as for DATA, so it
    // needs no budget of its own -- the handshake that opened the session was
    // the budgeted work. It does REPLACE this node's group, though, so a peer
    // that has not proved its address does not get to do that (the same
    // standard DATA is held to when LINK_REQUIRE_IDENTIFY is on).
    if (!linkPeerKnown(l)) {
      statLinkDrop++;
      return;
    }
    int gr = cc_group_secret_recv(&work, &group, l, linkRx, plen);
    if (gr == CC_OK) {
      groupDropStaleWins();
      groupSave();
      char gh[CC_GROUP_GID_SZ * 2 + 1];
      toHex(group.gid, CC_GROUP_GID_SZ, gh);
      logMsgf("RX", GREEN, "group %s over link", gh);
      drawStatus();
    } else {
      statLinkDrop++;
    }
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
  uint8_t ver = 0;
  bool present = false;
  bool ok = sdAccess(REVOKED_FILE, FILE_READ, [&](File& f) {
    present = true; /* it opened: a failure below is content, not absence */
    uint32_t claim = 0;
    if (!envReadHeader(f, &claim))
      return false;
    if ((size_t)f.size() != ENV_HDR_SZ + 1 + REVOKED_MAX * sizeof(cc_revoked_t))
      return false; /* short or oversized: do not install a prefix */
    if (f.read(&ver, 1) != 1 || ver != REVOKED_VERSION)
      return false;
    if (f.read((uint8_t*)scratch, sizeof(scratch)) != sizeof(scratch))
      return false;
    uint32_t c = crc32Update(crc32Start(), &ver, 1);
    c = crc32Update(c, (const uint8_t*)scratch, sizeof(scratch));
    if (crc32Finish(c) != claim)
      return false;
    for (int i = 0; i < REVOKED_MAX; i++) {
      if (scratch[i].used > 1)
        return false; /* not a record this app ever wrote */
    }
    return true;
  });
  if (!ok) {
    if (present)
      logMsg("Sys", "revoked.bin invalid: list NOT loaded", ORANGE);
    return;
  }
  for (int i = 0; i < REVOKED_MAX; i++) revoked[i] = scratch[i];
}

static void revokedSave() {
  uint8_t ver = REVOKED_VERSION;
  uint8_t hdr[ENV_HDR_SZ];
  uint32_t c = crc32Update(crc32Start(), &ver, 1);
  c = crc32Update(c, (const uint8_t*)revoked, sizeof(revoked));
  envWriteHeader(hdr, crc32Finish(c));
  sdAccess(REVOKED_FILE, FILE_WRITE, [&](File& f) {
    f.write(hdr, ENV_HDR_SZ);
    f.write(&ver, 1);
    f.write((const uint8_t*)revoked, sizeof(revoked));
    return true;
  });
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
  for (int i = 0; i < LINK_MAX; i++) {
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
  for (int j = 0; j < LINK_MAX; j++) {
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
// Group plumbing: the persisted secret, the per-poster windows, and the console
// commands that drive them. One group per node: `g` creates, `j<hex>` joins,
// `s` shares the secret over an open link, `p<text>` posts.
// ---------------------------------------------------------------------------

// GROUP_FILE payload: <version><secret 32><seq le32>, wrapped in the envelope.
// The seq is persisted so a reboot resumes past anything a receiver already
// accepted; the secret is in the clear, like the node key -- anyone who reads
// the card is a member.
static void groupSave() {
  lastGroupSaveTry = millis();
  if (!group.used)
    return; /* never joined: nothing to remember */
  uint8_t ver = GROUP_VERSION;
  uint32_t s = groupSeq;
  uint8_t b[4] = {(uint8_t)s, (uint8_t)(s >> 8), (uint8_t)(s >> 16),
                  (uint8_t)(s >> 24)};
  uint8_t hdr[ENV_HDR_SZ];
  uint32_t c = crc32Update(crc32Start(), &ver, 1);
  c = crc32Update(c, group.secret, CC_GROUP_SECRET_SZ);
  c = crc32Update(c, b, sizeof(b));
  envWriteHeader(hdr, crc32Finish(c));
  if (!sdAccess(GROUP_FILE, FILE_WRITE, [&](File& f) {
        return f.write(hdr, ENV_HDR_SZ) == ENV_HDR_SZ &&
               f.write(&ver, 1) == 1 &&
               f.write(group.secret, CC_GROUP_SECRET_SZ) ==
                   CC_GROUP_SECRET_SZ &&
               f.write(b, sizeof(b)) == sizeof(b);
      }))
    return; /* not saved: leave groupSeqSaved alone, so drift stays visible */
  groupSeqSaved = s;
}

// Drop the windows of a group we are no longer in. Windows for the CURRENT gid
// survive a re-join, so rejoining the same group does not forget what we have
// already accepted (and does not let an old post replay).
static void groupDropStaleWins() {
  for (int i = 0; i < GROUP_WIN_MAX; i++) {
    if (groupWinUsed[i] &&
        memcmp(groupWins[i].gid, group.gid, CC_GROUP_GID_SZ) != 0) {
      cc_group_win_forget(&groupWins[i]);
      groupWinUsed[i] = 0;
    }
  }
}

// Join (or create) the group and make it durable.
static void groupAdopt(const uint8_t* secret, size_t len, const char* how) {
  if (len != CC_GROUP_SECRET_SZ || cc_group_join(&group, secret) != CC_OK) {
    logMsg("Sys", "group join FAILED", RED);
    return;
  }
  groupDropStaleWins();
  groupSave();
  char gh[CC_GROUP_GID_SZ * 2 + 1];
  toHex(group.gid, CC_GROUP_GID_SZ, gh);
  logMsgf("Sys", GREEN, "%s: group %s", how, gh);
  logMsg("Sys", "plaintext secret on the card: reader == member", ORANGE);
  drawStatus();
}

// Load it at boot. All-or-nothing, like the revocation list: a short, corrupt
// or wrong-envelope file leaves this node in NO group -- group traffic is then
// refused (the receive path drops every post while group.used is 0) -- and says
// so loudly, with the way out, rather than silently dropping the membership.
static void groupLoad() {
  uint8_t secret[CC_GROUP_SECRET_SZ];
  uint32_t seq = 0;
  bool present = false;
  bool ok = sdAccess(GROUP_FILE, FILE_READ, [&](File& f) {
    present = true; /* it opened: a failure below is content, not absence */
    uint32_t claim = 0;
    if ((size_t)f.size() != ENV_HDR_SZ + 1 + CC_GROUP_SECRET_SZ + 4)
      return false;
    if (!envReadHeader(f, &claim))
      return false;
    uint8_t ver = 0;
    if (f.read(&ver, 1) != 1 || ver != GROUP_VERSION)
      return false;
    if (f.read(secret, CC_GROUP_SECRET_SZ) != CC_GROUP_SECRET_SZ)
      return false;
    uint8_t b[4];
    if (f.read(b, 4) != 4)
      return false;
    uint32_t c = crc32Update(crc32Start(), &ver, 1);
    c = crc32Update(c, secret, CC_GROUP_SECRET_SZ);
    c = crc32Update(c, b, 4);
    if (crc32Finish(c) != claim)
      return false;
    seq = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
          ((uint32_t)b[3] << 24);
    return true;
  });
  if (!present)
    return; /* no group was ever joined */
  if (!ok) {
    logMsg("Sys", "group.bin INVALID: no group loaded", RED);
    logMsg("Sys", "groups refused until 'j<hex>' or 'g'", ORANGE);
    return;
  }
  if (cc_group_join(&group, secret) != CC_OK)
    return; /* cc_group_join leaves the struct wiped: no group this boot */
  // The same discipline as the outbound counter: resume a whole replay window
  // past the saved value, so a post sent since the last save cannot come back
  // as a repeat.
  groupSeq = seq + CC_REPLAY_WINDOW;
  groupSeqSaved = groupSeq;
  char gh[CC_GROUP_GID_SZ * 2 + 1];
  toHex(group.gid, CC_GROUP_GID_SZ, gh);
  logMsgf("Sys", GREEN, "group %s loaded", gh);
}

// Save on the same cadence and drift rule as the outbound counter.
static void groupMaybeSave() {
  // Same reasoning as stateMaybeSave(): an inert node (wipe, or a damaged key)
  // writes nothing back to the card.
  if (!haveIdentity || !group.used)
    return;
  if (millis() - lastGroupSaveTry < GROUP_SAVE_MIN_MS)
    return;
  if (groupSeq - groupSeqSaved < CC_REPLAY_WINDOW)
    return;
  groupSave();
}

// The slot holding the committed window for a poster label, or -1 for a label
// we have never accepted a post from (and for a stale slot left by an earlier
// group, which a group change frees).
static int groupWinFind(const uint8_t poster[CC_ADDR_SZ]) {
  for (int i = 0; i < GROUP_WIN_MAX; i++) {
    if (groupWinUsed[i] &&
        memcmp(groupWins[i].gid, group.gid, CC_GROUP_GID_SZ) == 0 &&
        memcmp(groupWins[i].poster, poster, CC_ADDR_SZ) == 0)
      return i;
  }
  return -1;
}

// The slot for a label whose post just verified: the first free one, else the
// label that has gone longest without a verified post. It never refuses, since
// refusing is what made the table a permanent denial (see GROUP_WIN_MAX): a
// label's window is replay state, not a security record that must be kept, and
// losing one costs at most a duplicate display of a very old post. The order
// comes from the window's own `last_seen`, which cc_group_post_parse stamps on
// every verified post, so no parallel clock is needed; the subtraction is
// wrap-safe because millis() is.
static int groupWinClaim(void) {
  int oldest = -1;
  for (int i = 0; i < GROUP_WIN_MAX; i++) {
    if (!groupWinUsed[i])
      return i;
    if (groupWins[i].last_seen == 0)
      return i; /* never verified: the library's own first choice to drop */
    if (oldest < 0 ||
        (int32_t)(groupWins[i].last_seen - groupWins[oldest].last_seen) < 0)
      oldest = i;
  }
  return oldest;
}

static void createGroup() {
  cc_group_t fresh;
  uint8_t secret[CC_GROUP_SECRET_SZ];
  char hex[CC_GROUP_SECRET_SZ * 2 + 1];
  if (cc_group_create(&fresh, &rng) != CC_OK) {
    logMsg("Sys", "group create FAILED", RED);
    return;
  }
  cc_group_secret_export(&fresh, secret);
  toHex(secret, CC_GROUP_SECRET_SZ, hex);
  groupAdopt(secret, CC_GROUP_SECRET_SZ, "created");
  cc_group_free(&fresh);
  wipe(secret, sizeof(secret));
  // The only copy the operator gets: shared out of band, typed on the others.
  logMsg("Sys", "secret ('j' + this on another node):", CYAN);
  logMsg("Sys", hex, CYAN);
}

static void joinGroupHex(const char* hex, size_t len) {
  uint8_t secret[CC_GROUP_SECRET_SZ];
  if (len != CC_GROUP_SECRET_SZ * 2) {
    logMsgf("Sys", RED, "group join: want %d hex, got %d",
            CC_GROUP_SECRET_SZ * 2, (int)len);
    return;
  }
  if (!fromHex(hex, CC_GROUP_SECRET_SZ, secret)) {
    logMsg("Sys", "group join: not hex", RED);
    return;
  }
  groupAdopt(secret, CC_GROUP_SECRET_SZ, "joined");
  wipe(secret, sizeof(secret));
}

// Post to the group. A post is a broadcast sealed under the group key; the
// poster label is OUR address, which is a label and not proof of authorship.
static void postGroup(const char* text, size_t len) {
  if (!haveIdentity) {
    logMsg("Sys", "no identity: 'n' mints one", RED);
    return;
  }
  if (!group.used) {
    logMsg("Sys", "no group: 'g' creates one, 'j<hex>' joins", ORANGE);
    return;
  }
  if (len == 0)
    return;
  size_t outLen = 0;
  int ret = cc_group_post_build(&work, &group, myAddr, ++groupSeq,
                                (const uint8_t*)text, len, groupBuf,
                                sizeof(groupBuf), &outLen, &rng);
  if (ret == CC_OK && outLen > 0 && roadSend(groupBuf, outLen)) {
    char gh[CC_GROUP_GID_SZ * 2 + 1];
    char disp[CC_MAX_MSG_SZ + 48];
    toHex(group.gid, 4, gh);
    snprintf(disp, sizeof(disp), "[grp %s] %.*s", gh, (int)len, text);
    logMsg("TX", disp, CYAN);
  } else {
    logMsgf("Sys", RED, "group post failed (%d)", ret);
  }
}

// Share the secret over an OPEN link with the selected peer: a convenience
// beside the typed-secret path (out-of-band provisioning is what works when
// members are not adjacent).
static void shareGroup() {
  if (!haveIdentity) {
    logMsg("Sys", "no identity: 'n' mints one", RED);
    return;
  }
  if (!group.used) {
    logMsg("Sys", "no group to share", ORANGE);
    return;
  }
  if (peerSel < 0 || peerSel >= peerCount) {
    logMsg("Sys", "no peer selected (Tab)", RED);
    return;
  }
  cc_link_t* link = linkFindPeer(peerAddrs[peerSel]);
  if (!link || !cc_link_active(link, millis())) {
    logMsg("Sys", "no open link to the selected peer", ORANGE);
    return;
  }
  size_t len = 0;
  int ret = cc_group_secret_send(&work, &group, link, millis(), linkBuf,
                                 sizeof(linkBuf), &len);
  if (ret == CC_OK && len > 0 && roadSend(linkBuf, len))
    logMsg("TX", "group secret (link)", CYAN);
  else
    logMsgf("Sys", RED, "group share failed (%d)", ret);
}

// ---------------------------------------------------------------------------
// Identity lifecycle: mint a new one ('n') and wipe the card ('w'). Both act
// only after a confirmation keypress, because neither can be undone from here.
// ---------------------------------------------------------------------------

// Mint a new identity deliberately. The node becomes a stranger to the mesh:
// the address is new, so peers must re-learn it (an announce does that), the
// old identity's rotation continuity and any revocation aimed at it are
// orphaned on the peers' side, and the GROUP membership is unaffected -- the
// secret is independent of the identity, so our posts just carry a new poster
// label. This is what recovery from a damaged key file looks like.
static void mintNewIdentity() {
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
  logMsg("Sys", "peers must re-learn you: re-provision groups", ORANGE);
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

// Wipe every trace of this node's identity, from the card and from RAM: the
// key, the group secret, the freshness counters, the revocation list, the peer
// cache with its replay state, the live sessions, and each of those files.
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
    if (!sdRemove(GROUP_FILE))
      wipeNote(left, sizeof(left), "group.bin");
    if (!sdRemove(STATE_FILE))
      wipeNote(left, sizeof(left), "counter.bin");
    if (!sdRemove(REVOKED_FILE))
      wipeNote(left, sizeof(left), "revoked.bin");
    // Verify by existence rather than by SD.remove()'s return value alone: the
    // claim that matters is "the files are not there any more".
    if (sdExists(KEY_FILE))
      wipeNote(left, sizeof(left), "key.bin");
    if (sdExists(GROUP_FILE))
      wipeNote(left, sizeof(left), "group.bin");
    if (sdExists(STATE_FILE))
      wipeNote(left, sizeof(left), "counter.bin");
    if (sdExists(REVOKED_FILE))
      wipeNote(left, sizeof(left), "revoked.bin");
    int peersLeft = peersOursCount();
    if (peersLeft > 0)
      wipeNote(left, sizeof(left), "peers/*");
  }

  // RAM: identity (and the rotation slot, which holds a whole private key
  // whenever a rotation or a mint was staged), group, peers, sessions.
  cc_key_free(&myKey);
  cc_key_free(&newKey);
  memset(&newKey, 0, sizeof(newKey));
  memset(myAddr, 0, sizeof(myAddr));
  haveIdentity = false;
  cc_group_free(&group);
  for (int i = 0; i < GROUP_WIN_MAX; i++) {
    cc_group_win_forget(&groupWins[i]);
    groupWinUsed[i] = 0;
  }
  cc_group_win_forget(&groupWinScratch);
  for (int i = 0; i < REVOKED_MAX; i++) cc_revoked_init(&revoked[i]);
  peerCount = 0;
  peerSel = -1;
  for (int i = 0; i < MAX_PEERS; i++) {
    memset(peerAddrs[i], 0, CC_ADDR_SZ);
    cc_replay_init(&peerReplayUnsign[i], peerAddrs[i], CC_REPLAY_UNSIGNED);
    cc_replay_init(&peerReplayAuthed[i], peerAddrs[i], CC_REPLAY_AUTHED);
    peerReplaySavedAt[i] = 0;
  }
  for (int i = 0; i < LINK_MAX; i++) cc_link_forget(&links[i]);
  for (int i = 0; i < LINK_PENDING_MAX; i++) cc_link_forget(&linkPend[i]);
  // Plaintext scratch that could still hold a message or a decrypted post.
  memset(chatBuf, 0, sizeof(chatBuf));
  memset(groupBuf, 0, sizeof(groupBuf));
  memset(&groupMsg, 0, sizeof(groupMsg));
  memset(linkRx, 0, sizeof(linkRx));
  // Fresh counters/seq, so nothing the old identity spent is carried forward
  // and the card leaves with no correlatable value on it. The saved markers
  // are levelled too, so nothing is written back until real traffic follows.
  txCounter = esp_random();
  txSeq = esp_random();
  groupSeq = esp_random();
  txCounterSaved = txCounter;
  txSeqSaved = txSeq;
  groupSeqSaved = groupSeq;
  revocationPublished = false;
  rotLen = 0;
  rotUntil = 0;

  if (!card) {
    logMsg("Sys", "WIPE: no card to erase; RAM purged anyway", ORANGE);
  } else if (left[0] == '\0') {
    logMsgf("Sys", RED, "WIPE: %d peer file(s), key/group/counter/revoked gone",
            peers);
    logMsg("Sys", "WIPE: identity, group secret, sessions gone from RAM", RED);
  } else {
    logMsgf("Sys", RED, "WIPE INCOMPLETE: still present: %s", left);
    logMsg("Sys", "RAM purged anyway; erase the card by hand", RED);
  }
  logMsg("Sys", "no identity: 'n' mints a new one", RED);
  drawStatus();
}

// A one-character console on the serial port, so the identity, group and
// card-lifecycle paths can actually be exercised: 'r' rotates (or, once this
// identity has been revoked, publishes a fresh identity instead), 'x' revokes,
// 'g' creates a group, 'j' followed by 64 hex digits joins one, 's' shares the
// secret over an open link, 'p' followed by text and Enter posts to the group,
// 'n' mints a new identity, 'w' wipes the card, and 'y' confirms an 'n' or a
// 'w' (any other key cancels). 'j', 'p' and the two confirmations take an
// argument or a keypress, so the console collects it before acting. See the
// README.
enum { CON_IDLE, CON_JOIN, CON_POST, CON_CONFIRM };
static int conMode = CON_IDLE;
static int conPending = 0; /* 1 = mint an identity, 2 = wipe the card */
static uint32_t conConfirmAt = 0; /* when the pending confirmation expires */
// A pending confirmation is cancelled after this long: a 'w' pressed and left
// alone must not be confirmed by a stray 'y' minutes later, and there is no
// other way for the operator to notice the prompt is still armed.
#define CONFIRM_MS 5000UL
static char conBuf[CC_MAX_MSG_SZ + 1]; /* a 'p' line, before it is posted */
static size_t conLen = 0;
static char joinHex[CC_GROUP_SECRET_SZ * 2 + 1]; /* a 'j' argument */
static size_t joinLen = 0;

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
    if (conMode == CON_JOIN) {
      if (c == '\n' || c == '\r' || c == ' ' || c == '\t') {
        joinHex[joinLen] = '\0';
        joinGroupHex(joinHex, joinLen);
        conMode = CON_IDLE;
        joinLen = 0;
      } else if (joinLen < CC_GROUP_SECRET_SZ * 2) {
        joinHex[joinLen++] = (char)c;
        if (joinLen == CC_GROUP_SECRET_SZ * 2) {
          joinGroupHex(joinHex, joinLen); /* complete: no Enter needed */
          conMode = CON_IDLE;
          joinLen = 0;
        }
      }
      continue;
    }
    if (conMode == CON_POST) {
      if (c == '\n' || c == '\r') {
        conBuf[conLen] = '\0';
        postGroup(conBuf, conLen);
        conMode = CON_IDLE;
        conLen = 0;
      } else if (conLen < CC_MAX_MSG_SZ) {
        conBuf[conLen++] = (char)c;
      }
      continue;
    }
    if (c == 'r' || c == 'R')
      publishRotation();
    else if (c == 'x' || c == 'X')
      publishRevocation();
    else if (c == 'g' || c == 'G')
      createGroup();
    else if (c == 'j' || c == 'J') {
      conMode = CON_JOIN;
      joinLen = 0;
    } else if (c == 's' || c == 'S')
      shareGroup();
    else if (c == 'p' || c == 'P') {
      conMode = CON_POST;
      conLen = 0;
    } else if (c == 'n' || c == 'N') {
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
      logMsg("Sys", "WIPE: erases key, group secret, peers, state", RED);
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

// A group post is its own broadcast class in the module (its own airtime pool,
// a per-gid post budget, its own hop cap and its own keyless PoW gate), so it
// gets its own entry point here -- cc_relay_forward() is the wrong gate for it
// and stays closed to that type. Every refusal it can return is counted by the
// module itself (the e_* figures on the stats line), so a refusal is visible
// rather than silent.
static void relayGroup(const uint8_t* pkt, size_t len) {
  size_t olen = 0;
  int rr = cc_relay_group(&relay, pkt, len, relayNow(), relayBuf,
                          sizeof(relayBuf), &olen);
  if (rr == CC_RELAY_FWD && olen > 0 && roadSend(relayBuf, olen))
    logMsg("TX", "relay group", DARKGREY);
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
          "pin %lu repin %lu oth %lu | grp %lu",
          (unsigned long)s.forwarded, (unsigned long)s.rx,
          (unsigned long)s.e_dup, (unsigned long)s.e_budget,
          (unsigned long)s.e_unknown, (unsigned long)s.e_pow,
          (unsigned long)s.e_origin, (unsigned long)statRelayOrg,
          (unsigned long)statRelayRepin, (unsigned long)other,
          (unsigned long)s.window_group);
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

  } else if (type == CC_MSG_GROUP_DATA) {
#if defined(CC_RELAY)
    // Offered to the relay FIRST and unconditionally: the early returns below
    // (no group here, another group, a spent budget, a bad post) must never
    // stop the mesh's traffic being carried, and a relay carries a post for a
    // group it is not in. This node forwards its OWN group's posts too: a post
    // is fan-out, not a unicast to us, so members we cannot reach still need it
    // carried -- the duplicate is dropped downstream by a receiving member's
    // per-poster window and here by the module's duplicate cache. Same rule as
    // an announcement, which this app also learns from and re-broadcasts.
    relayGroup(pkt, len);
#endif
    // A group post is BROADCAST: there is no recipient field, so it cannot go
    // through the recipient-filtered chat branch above. No group joined means
    // there is nothing to match and no work to do -- the cheapest possible
    // drop, and it costs an attacker nothing because we spend nothing.
    if (!group.used)
      return;
    // Not for our group (or not a well-formed post): a quiet, cheap drop. The
    // gid is a plain decode and the gid is on the air in every post, so this
    // filter is not a secret -- it is here so a post for another group, or a
    // stranger's garbage, does not spend a slot of the budget that legitimate
    // posts need.
    uint8_t pgid[CC_GROUP_GID_SZ];
    if (cc_group_gid(pkt, len, pgid) != CC_OK ||
        memcmp(pgid, group.gid, CC_GROUP_GID_SZ) != 0)
      return;
    // Budget the verify before it, like every other expensive path: a post
    // costs a PoW check plus an AEAD attempt, and one that a member captured is
    // cheap to replay. A refusal is counted and dropped without a display line
    // (logging each one would hand an attacker the display).
    if (!groupBudget.allow(GROUP_VERIFY_WINDOW_MS)) {
      statGroupDrop++;
      return;
    }
    uint8_t poster[CC_ADDR_SZ];
    if (cc_group_poster(pkt, len, poster) != CC_OK) {
      statGroupDrop++;
      return;
    }
    // Every packet type pays for admission, and this one is checked with the
    // build's own group difficulty (a group has no single receiver to publish a
    // price for, so the sender's own table is the whole price). It is checked
    // BEFORE the window table is touched, so claiming a slot costs one mined
    // packet even though the slot itself is only claimed by a post that goes on
    // to authenticate.
    if (cc_pow_verify(pkt, len) != CC_OK) {
      statGroupDrop++;
      return;
    }
    // One replay window per poster LABEL, and a slot is claimed only by a post
    // that AUTHENTICATES. An UNSEEN label is parsed against a throwaway window
    // first, so a stranger -- anyone at all, who has merely SEEN one post and
    // thus knows the gid, which is on the air -- cannot take slots with junk
    // labels and make this node deaf to the members whose labels it has not
    // seen yet (a new member's first post, or a member's post after a
    // rotation). Nothing an outsider sends reaches the table at all.
    int wi = groupWinFind(poster);
    bool firstSight = (wi < 0);
    cc_group_win_t* gwin;
    if (firstSight) {
      cc_group_win_init(&groupWinScratch, group.gid, poster);
      gwin = &groupWinScratch;
    } else {
      gwin = &groupWins[wi];
    }
    // The AEAD is the authentication: a post that decrypts proves a key holder
    // sealed it, and the window commits only after the tag verifies. `now` is
    // this app's millis() clock, which the parse stamps into the window as
    // `last_seen` -- the ordering groupWinClaim() evicts by.
    int gr =
        cc_group_post_parse(&work, &group, gwin, pkt, len, millis(), &groupMsg);
    if (gr == CC_OK) {
      if (firstSight) {
        // A free slot, else the label whose window has gone longest without a
        // verified post (see GROUP_WIN_MAX: refusing instead would let the
        // table be filled into permanent deafness). There is no "uncommitted
        // slot" case to prefer here -- a slot is claimed only by a post that
        // just committed, so every used slot holds real replay state and the
        // oldest is the only one whose loss is cheapest.
        wi = groupWinClaim();
        groupWins[wi] = *gwin; /* carries the window the parse committed */
        groupWinUsed[wi] = 1;
      }
      char gh[CC_GROUP_GID_SZ * 2 + 1], ph[CC_ADDR_SZ * 2 + 1];
      char buf[CC_MAX_MSG_SZ + 48];
      toHex(groupMsg.gid, 4, gh);
      toHex(groupMsg.poster, 4, ph);
      // The poster label is what the SEALER claimed, not who it is: any member
      // can mint another member's label under the shared key.
      snprintf(buf, sizeof(buf), "[grp %s %s] %.*s", gh, ph,
               (int)groupMsg.msg_len, (const char*)groupMsg.msg);
      logMsg("RX", buf, MAGENTA);
    } else if (gr == CC_E_GROUP || gr == CC_E_ARG) {
      /* another group's window/label, or a malformed post: quiet drop */
    } else if (gr == CC_E_REPLAY || gr == CC_E_STALE) {
      statReplay++;
    } else {
      statGroupDrop++; /* a tag that did not verify, or any other failure */
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

  // Identity. Three answers, and the two that are not "loaded" must never be
  // answered with a fresh keypair: a key file that is PRESENT but does not load
  // is damage, and NO CARD AT ALL is not an empty card (minting on a cardless
  // boot used to be silent re-identification -- peers would see a stranger, the
  // operator would likely never notice, and the node's links, group membership
  // and rotation/revocation continuity would be orphaned). In both cases the
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

  // The group secret, so a joined group survives a reboot (it is stored in the
  // clear, like the node key: anyone who reads the card is a member).
  groupLoad();

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
            "link %lu/%lu rot %lu rev %lu ctl %lu grp %lu",
            (unsigned long)statReplay, (unsigned long)statBadSig,
            (unsigned long)statNoKey, (unsigned long)statDecrypt,
            (unsigned long)statChatDrop, (unsigned long)statAnnDrop,
            (unsigned long)statOldWire,
            (unsigned long)statLinkOpen, (unsigned long)statLinkDrop,
            (unsigned long)statRotated, (unsigned long)statRevoked,
            (unsigned long)statCtlDrop, (unsigned long)statGroupDrop);
#if defined(CC_RELAY)
    relayStatsLine();
#endif
  }

  // Persist the outbound counter/seq if either has drifted from the saved copy.
  stateMaybeSave();

  // Same rule for the group's post sequence, which lives in the group file.
  groupMaybeSave();

  delay(5);
}
