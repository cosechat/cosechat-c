# cardputer

cosechat node firmware for [CardputerADV](https://docs.m5stack.com/en/core/Cardputer-Adv).
It is a mesh chat peer on a *road* (transport): pick LoRa, WiFi/UDP, anonymous
BLE or raw 802.11 at build time; the node code is identical either way.

```sh
# LoRa: M5 LoRa Cap 1262
pio run -e lora --target upload --target monitor

# WiFi + UDP: set WIFI_SSID/WIFI_PASS in platformio.ini first
pio run -e wifi --target upload --target monitor

# Anonymous BLE 5 extended advertising (no connection, no address)
pio run -e ble --target upload --target monitor

# Unauthenticated 802.11 management frames (vendor-specific action frames)
pio run -e dot11 --target upload --target monitor
```

All four paths need a different radio, and BLE 5 extended advertising needs an
ESP32-S3 (or C3/C6); the cardputer is an S3. BLE and WiFi share the radio, so
run one road at a time.

Two nodes only hear each other on the same medium: both on channel 1 for
`dot11`, and both within BLE advertising range for `ble`. Neither road
acknowledges anything, so the big packets are the lossy part. An `announce` is
~6.5 KB (6472 B measured, ~27 LoRa fragments and ~27 BLE advertisements) and
the opportunistic `chat` is ~4.5 KB (4515 B, ~19 fragments, it carries a
per-message ML-DSA signature), but a **link** (session) pays that once:
`link_req` is ~5 fragments (1110 B), `link_proof` ~14 (3331 B), and then every
message is a single AEAD record — 45 B, one fragment. A presence is one
fragment either way (34 B), and a `key_req` is one (27 B). Those byte counts are
the `build/chat` tool's own measurement and they move by a byte or two between
runs, because the mined PoW nonce is CBOR-encoded and its width varies; the
fragment counts do not move.

## Controls

| Key | Action |
|-----|--------|
| letters | type a message |
| Tab | cycle peers (received via announce) |
| Enter | send the message to the selected peer |
| Del | backspace |

The serial console takes six commands: `r` (rotate identity), `x` (revoke it),
`p` (set or change the store passphrase — on a plaintext card this is the
migration, see "The passphrase store"), `n` (mint a new identity — the recovery
path for a damaged key file or a cardless run, see "What the card *is*"), `w`
(wipe the card) and `i` (print the security posture); `n` takes `y`, `w` takes a
capital `Y`, and either prompt is cancelled by any other key or by a five-second
timeout.

The status bar shows the first 4 bytes of this node's address, or `no id` while
the node is inert (no identity).

The log line shows `ANN`/`PRE` (announce/presence received), `TX` (something we
sent), and `RX`. A `TX` message says which path it took: `(link)` for a single
AEAD record on an open session, `(signed)` for the opportunistic signed chat
used while a handshake is still in flight. An `RX` chat line always means the
packet authenticated: a forged or replayed one never reaches the display, and
shows as `<hex> bad signature`, `<hex> no key (key_req)` or `<hex> decrypt
failed`, while replays are counted silently. Sessions
log `link_req`,
`link_proof`, `link open`, `link close` and `<hex> identify verified`; a data
record on a session we accepted is dropped (and counted) until a verified
identify names the peer, or shown as `[anon]` if `LINK_REQUIRE_IDENTIFY` is 0.
A `PRE`
shows a name only when the hint's address *and* name hash match a verified
announce; anything else is logged as `<hex> (unverified)`, and accepted
presences are folded into at most one `PRE` line per second (with a `+N`
count), so a presence flood cannot drive the display. A periodic pair of `Sys`
lines reports the road counters (`rx drop tx fail`) and the drop reasons
(`rp sig nokey dec cd ann v link rot rev ctl`), plus a third line when the
relay is compiled in (see Relay below). `cd` counts chats refused by the chat
verify budget.

## How it works

- On boot the node generates (or loads from SD) an ML-DSA-65 + ML-KEM-768
  keypair (NIST category 3; the sizes follow `CC_SIGN_LEVEL`/`CC_KEM_LEVEL`),
  broadcasts a signed **announce**, then sends an unsigned **presence**
  heartbeat every 60 s. A key file that is *present but invalid* is not
  regenerated: the node goes inert instead and waits for `n`, so a damaged card
  can never silently re-identify it (see "What the card *is*").
- **The card can be sealed with a passphrase.** `key.bin`, `counter.bin`,
  `revoked.bin` and each `peers/<hex>.rp` are then stored as authenticated
  containers instead of plaintext (see "The passphrase store"); the peer
  announce cache stays readable on purpose. A sealed card asks for the
  passphrase at boot, before anything reads the card, and three failures leave
  it locked and inert rather than guessing.
- Every packet carries the wire version; a packet from another revision is
  dropped, with a one-off `Sys` note, before any PoW or crypto work.
- **Announces have a lifecycle.** Each carries a signed monotonic `seq` and a
  signed `expiry`, and a receiver accepts only a strictly newer sequence. This
  node has no clock but `millis()`, so it sends `expiry = 0` (no expiry) rather
  than a meaningless absolute time; the `seq`, not the expiry, is what stops an
  old announce from re-seeding a stale peer view. Its own `seq` and its
  freshness counter are persisted so a reboot resumes ahead of both.
- **A presence is a hint, not a claim.** It carries an address and a name
  *hash*; the node trusts it only when both match a cached verified announce
  (`cc_presence_matches_announce`). A mismatch means "ignore the hint", never
  "the peer renamed itself", and the display only ever shows a name that came
  from a verified announce. The unsigned replay window dedups it.
- A **chat** is signed by the sender and its routing metadata is bound by the
  AEAD tag; the node looks the claimed sender up in the announce cache, verifies
  the signature against that peer's announced key, and only then decrypts and
  displays. A message whose signature does not match is never shown. This is the
  opportunistic path, used when no session is open.
- Each peer has two replay windows: a `CC_REPLAY_AUTHED` one for chat, advanced
  only by a fully verified packet, and a separate `CC_REPLAY_UNSIGNED` one for
  presence and key_req. They are never shared, so a spoofed heartbeat cannot age
  out a peer's chat stream.
- A presence from an unknown address triggers a **key_req**; the target answers
  by re-sending its announce. Outgoing requests are limited per address and
  globally; answers are budgeted globally only, because a `key_req` names just
  its target and even in v9 a node cannot tell two requesters apart.
- Peers' public keys (signing and KEM) are cached in RAM with the peer entry, so
  no receive path opens SD: an SD read holds the SPI mutex the radio also needs,
  and a forged packet must not be able to trigger one. SD stays the cold store,
  read at boot and written when an announce changes.
- All library calls go through one static `cc_work_t` (34752 B of scratch,
  statically reserved, never on the stack — wolfCrypt's own working buffers
  under `WOLFSSL_SMALL_STACK` are a separate story, see the RAM budget). One
  context is enough because the library is only called from `setup()`/`loop()`;
  the road tasks touch only the framing helpers in `cosechat_road.c` and never
  enter this library.
- **Admission pricing (v9).** An announce carries a three-byte declaration of
  what its owner asks senders to mine for the directed types (`chat`,
  `link_req`, `key_req`); this node publishes its own policy with
  `cc_admit_default()`. When it sends one of those to a peer whose announce it
  has verified, it mines at `cc_admit_for()`'s answer (the peer's price when
  that is higher than ours) and falls back to its own default when it has no
  verified announce for the peer. The *receive* side never trusts a declaration
  for anything: it always enforces its own configured `CC_POW_DIFFICULTY_*`. As
  the header says, this is congestion pricing — it makes bulk traffic pay for
  the air it uses — and not a flood defence, which is what the rate limits and
  budgets are.
- **Identities rotate and retire (v9).** `ROTATE` (9) moves an identity to a
  new key, co-signed by the old one; `REVOKE` (10) retires an identity
  permanently. Both are handled below.

## Links

A **link** is a forward-secret session with one peer: an ML-KEM encapsulation
per link, per-direction AES-256-GCM keys from the RFC 9180 schedule, and after
setup no per-message signature and no per-message PoW — the link key
authenticates each record and the per-link sequence numbers are the replay
defence:

1. the initiator sends `link_req` (an ephemeral KEM ciphertext; anonymous);
2. the responder decapsulates and proves its identity with a signed
   `link_proof`;
3. the initiator confirms that proof against the responder's cached announce,
   then sends an `identify` record so the responder can verify who it is.

Sending prefers an open link (one fragment, no per-message signature); when none
is open the node starts a handshake *and* sends the opportunistic signed chat,
so the message still gets through while the session is set up. A link is kept
warm with a keepalive after 60 s of quiet and is forgotten after 180 s idle;
`LINK_SESSION_MAX` is 4 sessions, which covers the one peer being talked to plus
a handshake or two in flight, at 168 bytes each. Links live in RAM only: a
reboot forgets them and the next message re-handshakes.

**A responder-side handshake does not get a session.** Answering a `link_req`
puts the half-open session in a two-entry pending table with a 12 s TTL instead
of the session table, and it is promoted only when an authenticated record
arrives on it (or, for our own handshakes, when we started it). Otherwise four
unauthenticated `link_req`s would fill the table and, since we keep our own
links warm, the junk would never idle out — an attacker's four requests would
deny the link layer to honest peers and then hand the attacker a session it can
write into for free (no PoW, no signature). Three further guards: responder-side
links may hold at most `LINK_RESPONDER_MAX` (2) of the 4 slots, so our own
handshakes always find one; a keepalive is only ever sent for a link we
initiated or one that has carried an authenticated record, so nothing
unauthenticated can be kept alive; and a `link_req` whose `link_id` is already
live or pending is refused, so a replayed id cannot create a second slot that
shadows a real session. An unanswered pending entry expires on its own and
never occupied a session slot.

Because anonymous links are a library feature but a `link_req` is free,
`LINK_REQUIRE_IDENTIFY` (default 1) makes the app *display* a data record only
once the sender has proved its address with a verified identify record.
Records from a still-anonymous link are dropped and counted, leaving a silent
but authenticated socket; set the macro to 0 to display them as `[anon]` again.
The trade is deliberate: the revision exists to make messaging cheap, and a
link nobody has authenticated should not be able to put text on the screen.

Link packets carry no recipient, only an 8-byte `link_id`, so they are routed
against the link table and never by `cc_msg_recipient`. Inbound `link_req` is
budgeted (`LINK_ACCEPT_BURST` per `LINK_ACCEPT_WINDOW_MS`) *before* the
decapsulation and the proof signature, so a request flood cannot turn the node
into a signature oracle.

RAM budget: the big static objects, measured with `nm` on a built `wifi` ELF,
are the `cc_work_t` scratch (34752 B), the peer key cache (`peerSignPub` 31232 B
+ `peerKemPub` 18944 B ≈ 50 KB), the **store buffers** (`storeCont` 8453 B +
`storePlain` 8394 B ≈ 16.5 KB — together the third-largest block after the two
above, and each one larger than every "small and named" item below), the two key
slots (`myKey` and `newKey`, 13072 B each; the rotation slot is statically
reserved even though it is only live while a rotation is published), the road
state (`roadImpl`, 15984 B on `wifi`), and the wire scratch (`ctlBuf` 10380 B,
`rxPkt` 7936 B, `annBuf` 7023 B, `chatBuf` 5421 B). The envs build at 66–75% of
the ESP32-S3's 320 KB DRAM, with `wifi` the tightest at ~74.4% (243704 B; lora
217800, lora-relay 226576, ble 228648, dot11 241700). The store came out
**1.3 KB smaller** per env than the buffers it replaced — it uses two buffers
where `keyLoad`/`keySave` used three, and the save path reuses the read buffer —
so RAM went down, not up, with the passphrase feature; `include/user_settings.h`
records the same measurement (217800 B for `lora`, 1296 B less than before the
store). The other additions from the security and card work are small and named:
the revocation-load scratch (224 B), the chat verify budget (72 B), the envelope
(a CRC with no table, locals only), and the console state.

Nothing in the sketch allocates, and no part of the app sizes itself at runtime:
every app buffer is a compile-time constant, and every table walk is bounded by
its array size. wolfCrypt is a different matter and it is worth being exact
about it: this build sets `WOLFSSL_SMALL_STACK` — the define, in
`examples/cardputer/include/user_settings.h`, next to `SINGLE_THREADED` and
below the `NO_PWDBASED` note (grep the name rather than trusting a line number:
that file's comment grew and moved it once already) — under which wolfCrypt
puts its working buffers on the heap through `XMALLOC` instead of on the stack,
so the heap is used under this build even though this sketch never calls it.
The passphrase store's PBKDF2 and the ML-KEM/ML-DSA paths are wolfCrypt's
allocation, not this sketch's.

## Identity: rotation and revocation

Four serial console commands drive the identity and card paths, because a path
nobody can exercise rots (`r` and `x` here, `n` and `w` under "Wipe and
re-key"):

| Command | What it does |
|---------|--------------|
| `r` | rotate: mint a new keypair, publish a `ROTATE` co-signed by the old key, adopt the new key, save it, announce the successor (after `x`, a fresh identity instead) |
| `x` | revoke: publish a `REVOKE` signed by the current key, retiring this identity |

**Order matters: `x` first, then a successor — but the successor cannot be a
rotation.** A successor published before the revocation lands would be trusted
on the strength of the very key being retired, so the app clears any rotation
still in its re-broadcast window when it publishes the revocation. After that,
a `ROTATE` from the retired key cannot work at all: the library refuses a
rotation whose predecessor is retired (`CC_E_REVOKED`), and recording the
revocation of X also drops every entry filed under X's `prev_addr` — so peers
would reject the successor while this node believed it had rotated. The console
therefore stops offering the wrong order: once this identity has published a
revocation, `r` mints and announces a **fresh identity** with no continuity
claim (and never asks the retired key to vouch for anything) instead of
logging "identity rotated". Before any revocation, `r` is a normal rotation.
The flag is persisted (`counter.bin`), so a reboot between `x` and `r` cannot
reopen the wrong order either.

Receive side, in the order the header states:

- **Revocations** are recorded in a bounded table (`REVOKED_MAX` = 8 entries,
  28 B each) that is **persisted** to `/cc/revoked.bin` — a revocation a reboot
  forgot would let a retired identity walk back in. Adding one is idempotent:
  a replayed revocation whose address, `seq` and `expiry` are already recorded
  changes nothing and does **not** rewrite the card (each write is an
  open/write/close holding the SPI mutex, which is the radio's mutex on the
  LoRa env). The table is security state, not a cache: a live record is never
  evicted for a different address, because with only eight slots a rotating
  cursor would let an attacker publishing eight throwaway revocations evict a
  real one and re-trust a retired identity for the price of eight keygens plus
  eight mined packets. A slot is reused only for its own address, an unused
  slot, or a record whose non-zero `expiry` has passed; otherwise the
  revocation is refused and logged. `cc_revoked_check()` decides whether an
  address is still retired; the record's own `expiry` ends that, and this node
  publishes `expiry = 0` (remember indefinitely) because it has no clock to
  express a horizon the receiver could compare against.
  The load is all-or-nothing: the whole file is validated before any of it is
  installed, so a short or corrupt card cannot silently un-revoke a prefix of
  the list. The honest limit that remains: **the revocation list is
  best-effort local state.** A vanished or damaged card re-trusts every retired
  address it cannot read back, so the durable fix for a leaked key is to rotate
  away from it, not to rely on revocation.
  A revocation is verified against the cached announce of the address it
  retires (`cc_revoke_parse` needs that key; a wrong one answers `CC_E_NOKEY`
  before any signature work). When one is recorded, every peer entry whose
  **address or `prev_addr`** equals the retired address is dropped, file and
  all, and any session with it is forgotten — `prev_addr` is what finds a
  successor that was learned from a rotation before the revocation landed.
- **Rotations** are peeked with `cc_rotate_prev_addr()` to find the cached
  predecessor; a rotation from an address we never cached is ignored (a
  successor must not be trusted on the word of a predecessor we never
  verified). Then `cc_rotate_parse()` verifies both signatures,
  `cc_rotate_accept()` applies the acceptance rule (strictly newer `seq`, not
  expired, predecessor not retired), and the peer entry is re-keyed: new
  address and public keys, name/meta/seq/`admit`, `prev_addr`, and **both**
  replay windows moved with `cc_replay_move(..., CC_REPLAY_CONTINUES)`. The
  choice of CONTINUES is deliberate: our nodes carry their counter space across
  a rotation, so a message sent just before the rotation cannot be replayed
  into the new address; the consequence is that a successor which *restarted*
  its counter would have its first messages dropped as stale, so such a node
  should rotate with a fresh identity instead. The peer is written under its
  new address and the old `.bin`/`.rp` are removed. Open sessions are not torn
  down — a link's keys are independent of the identity keys — they just follow
  the address change.
- Rotations and revocations are both budgeted (`CTL_VERIFY_BURST` per
  `CTL_VERIFY_WINDOW_MS`) before any crypto, since a rotation verifies two
  signatures.

A rotation is re-broadcast every announce interval for `ROTATE_GRACE_MS` (5 min)
so peers that missed the first copy can still move their trust.

## Relay (opt-in)

The `lora-relay` env defines `CC_RELAY` and compiles in `cc_relay_t` (a
path table, a duplicate cache, per-destination budgets and counters). It reuses
the `lora` road and flags, so a build break in the relay path is visible even
though the other four envs do not include it.

When it is on, every accepted (signature-verified) announce is offered to
`cc_relay_announce` and every chat **not addressed to us** to
`cc_relay_forward`; anything the module answers with `CC_RELAY_FWD` is sent with
the road. A chat for us is delivered locally and never re-broadcast, and our own
announce is never forwarded. **Link traffic is never offered at all**: a link
record carries no destination, and a link only exists between direct peers.

Tuning is in `platformio.ini`. The medium-modelling values are left at their
defaults because the defaults *are* this road — one SF7 / 125 kHz LoRa channel,
which the two airtime pools model together: `CC_RELAY_AIRTIME_ANNOUNCE`
16384 B and `CC_RELAY_AIRTIME_DATA` 24576 B per 60-tick window (40960 B per
window, ~683 B/s; two pools so that one 6.5 KB announce cannot black out relayed
data for the whole window), with `CC_RELAY_FWD_BUDGET` 3 per destination,
`CC_RELAY_DUP_TTL` 300, `CC_RELAY_PATH_TTL` 600, `CC_RELAY_WINDOW` 60 and
`CC_RELAY_MAX_HOPS` 8; the relay's clock is seconds (`millis() / 1000`) to match
those tick units. Only the RAM-shaped knobs are cut: `CC_RELAY_PATHS` 16,
`CC_RELAY_DUP` 16 and `CC_RELAY_BUDGETS` 8, which makes `cc_relay_t` 1380 B
instead of the default 4196 B (measured with `sizeof` under the env's defines:
16 paths × 48 B, 16 duplicate slots × 20 B, 8 budget slots × 24 B, the window,
the two pool counters and 88 B of counters), plus a 6.9 KB re-broadcast buffer
(`annBuf`, `CC_ANN_BUF_SZ` = 7023 B) and the 8-entry pin table.

The origin check depends on the road, and where the road can attribute a sender
the app pins it. `cc_road_t` reports the transmitting source it heard a packet
from (`last_src`/`last_src_len`), captured in `pumpRoad()` beside the packet;
this is *link-layer* identity (802.11's transmitter MAC, WiFi's IPv4+port), not
a cosechat address, so it is never passed to the relay directly. Instead the app
keeps a small pin table learned **only** from an announce that an address itself
sent at `hops == 0` — which is signed by that address — and:

- an announce at `hops == 0` is offered to the relay only if it arrived from the
  source that address is pinned to, or from a source we have not seen it at all
  (in which case it is pinned now, which is how a neighbour's first announce and
  our own next-hop table get their address);
- a `hops == 0` announce arriving from a *different* source than a pinned
  address claims is refused, and counted (`pin` in the relay stats line);
- a road that cannot attribute at all (`ble`, `lora`: `last_src_len == 0`) gives
  no evidence, so such a claim is refused — the `lora-relay` env therefore
  re-broadcasts only packets that already carry `hops >= 1`.

That is pinning, not proof: an attacker who was there first, or who spoofs the
transmitting source, still wins, and `hops` is outside every signature and tag
anyway. What it does close is the cheap one-shot injection of a `hops == 0`
announce from some other neighbour, which would otherwise arrive with no
evidence at all and could take over a live route.

Two honest limits, both visible in the stats rather than silent. A pin's TTL is
a *takeover window*: once it lapses, whoever sends the next `hops == 0` announce
for that address re-pins it, so the TTL is derived from the relay's own
`CC_RELAY_PATH_TTL` (the same re-learning hazard its path entries document)
rather than kept on a shorter private clock, and a pin taken after a lapse is
counted as `repin` so it does not look like a first sighting. And a road that
never attributes (`ble`, `lora`) can never pin anything, so a neighbour heard
only over such a road stays reachable at `hops >= 1` and never as a
directly-checked origin.

The third `Sys` line reports relay activity: `fwd`/`rx`, then the refusals
(`dup`, `bud` for budget, `unk` for no path, `pow` for unmined data, `org` for
the module's own origin check, `pin` for the hops-0 claims this app refused for
want of a pin, `repin` for pins taken after a lapse, `oth` for everything else),
so a drop reason is never invisible.

## SD card layout

Every file this node writes starts with the same 9-byte integrity envelope:

```
envelope               "CCFS" <version 1> <crc32 LE of the payload>
/cc/key.bin            envelope + <form><seeds><sign_pub>             (2090 B)
/cc/counter.bin        envelope + <magic 0xCC><version><counter le32> <seq le32> [<flags>]
/cc/revoked.bin        envelope + <version><REVOKED_MAX cc_revoked_t>  (retired identities)
/cc/peers/<hex>.bin    envelope + <version><raw cc_announce_t>
/cc/peers/<hex>.rp     envelope + <version><unsigned cc_replay_t><authed cc_replay_t>
```

Four of these five kinds are additionally wrapped in a passphrase container
(`CCSP`) when the store is sealed — `key.bin`, `counter.bin`, `revoked.bin` and
`peers/<hex>.rp` — while `peers/<hex>.bin` never is (see "The passphrase
store", which has the container layout and the sealed sizes).

`key.bin`'s payload starts with a form byte, and the identity is stored as
**seeds**, not as expanded private keys:

| Form | Payload | Size |
|------|---------|------|
| `1` seed (what this build writes) | `form` 1 + `sign_seed` 64 + `kem_seed` 64 + `sign_pub` 1952 | 2081 B (2090 B file) |
| `2` expanded (read for compatibility, written only when there is no seed) | `form` 2 + `sign_priv` 4032 + `sign_pub` 1952 + `kem_priv` 2400 | 8385 B (8394 B file) |

(Computed from the header's own size macros: `CC_SIGN_SEED_SZ` 64,
`CC_KEM_SEED_SZ` 64, `CC_SIGN_PUBKEY_SZ` 1952, `CC_SIGN_PRIVKEY_SZ` 4032,
`CC_KEM_PRIVKEY_SZ` 2400.) `cc_key_generate()` always produces seeds, so an
identity this node mints is always written in form 1 — **6304 B smaller
(−75.1%)** than the expanded form it replaced, and the most exposure-sensitive
file on the card shrinks with it.

Neither private key is stored in form 1. Both are reconstructed from the two
seeds by `cc_key_import_seed()`, and the KEM private key deliberately has no
expanded copy in the file: a copy that cannot be checked against anything (the
payload carries no KEM public key, and validating one would mean another
2400-byte scratch) is worse than no copy at all — deriving it removes both the
field and the hole. The `sign_pub` **stays**, because it is the one field that
can be cross-checked cheaply and it is the preimage of the address every peer
pins: `cc_key_import_seed()` rebuilds the key and the stored `sign_pub` must be
the one that seed produces, or the file is **invalid**.

The expanded form keeps its **sign** cross-check too (the imported key must
export the stored `sign_pub`). Its **KEM** half cannot be cross-checked in that
layout, because the payload carries no `kem_pub` to compare against — stated
here rather than left implied: in form 2 a mismatched KEM half would be a node
that works normally while advertising a public key it does not hold, which is
why form 1 (where there is nothing to mismatch) is what this build writes.

Form 2 exists for one case: an identity imported from an expanded file has no
recoverable seed, and `cc_key_export_seed()` says so with `CC_E_NOKEY`. That is
**not** corruption and must not fail closed, and it must not skip the save
either — skipping would leave the previous identity on the card while the node
announces the new one. The node saves the expanded form, logs `key has no seed:
saving the expanded form`, and carries on; the next key it generates is compact
again. (Nothing is deployed, so no card can be in that state today; the path
exists so that it cannot become a silent hole later.)

The CRC **detects damage, it does not authenticate**: anyone who can write the
card can recompute it. What it buys is that a damaged, truncated or
half-written file is *invalid* rather than quietly misread — and each loader
then takes the fail-safe that fits what the file holds (see below). A file that
is present but invalid is never the same answer as a file that is absent.

`counter.bin` holds both monotonic outbound values in one file — the freshness
counter (chat, presence, key_req) and the announce `seq` — plus, as of payload
version 3, one flags byte whose bit 0 records that this identity has published a
revocation. An older payload is still read (missing fields default to 0, so the
seq resumes from 0). An announce is cached as `<hex>.bin`; a repeat with
unchanged content is neither rewritten nor re-logged.

No SD card **stops the node minting**: with no card there is nothing to read, so
the node cannot tell "fresh card" from "my card is gone" — and the second case
is exactly the one that must not be answered with a new identity. It runs inert
with `no SD card: refusing to mint an identity` on the log and `no id` in the
status bar; insert the card, or press `n` to run without one (the key then lives
in RAM only and is not saved). Peers, replay windows and links are RAM-only
either way, and the counter and seq are seeded from the hardware RNG, so a
reboot may repeat a counter or a `seq`: peers reject that as a replay (or as a
stale announce) until a card carries the state file; the same applies to the
replay windows, which a peer could replay once more after our reboot.

### The passphrase store

`p` seals the card with a passphrase. Four of the five file kinds are then
written as containers instead of plaintext — `key.bin`, `counter.bin`,
`revoked.bin` and each `peers/<hex>.rp` — while **`peers/<hex>.bin` stays
plaintext on purpose**: its contents are the peer announces the mesh broadcasts
anyway (public keys, names, prices), and leaving it readable is what lets the
peer list and the display still work while the store is locked. The store is the
sketch's own policy: the radio, the wire and the library know nothing about it.

One container shape serves every sealed kind (format version 1); the module's
own table is the contract:

```
off  size  field              notes
---  ----  -----------------  -------------------------------------------
0    4     magic = "CCSP"     identifies the container, not the file kind
4    1     format version = 1
5    1     kdf id = 1         PBKDF2-HMAC-SHA256
6    4     kdf iterations     work factor, big-endian uint32
10   16    salt               RNG, per store (not per file: see below)
26   1     aead id = 1        AES-256-GCM
27   12    nonce              RNG, fresh for every seal, never reused
39   4     plaintext length   big-endian uint32, authenticated
43   N     ciphertext         N = plaintext length
43+N 16    tag                GCM tag
```

Header 43 + tag 16 means **N bytes of plaintext become exactly N + 59 bytes on
disk** — a compile-time constant, so every buffer is static and the exact-length
rule is part of the format (a truncated or extended container is rejected before
any crypto runs). That makes the sealed sizes:

| File | Plaintext | Sealed |
|------|-----------|--------|
| `key.bin`, seed form | 2090 | 2149 |
| `key.bin`, expanded form | 8394 | 8453 |
| `counter.bin` | 20 | 79 |
| `revoked.bin` | 234 | 293 |
| `peers/<hex>.rp` | 74 | 133 |
| `peers/<hex>.bin` | 3530 | not sealed |

How the key is derived: **PBKDF2-HMAC-SHA256**, 16-byte RNG salt, work factor
carried in the container header (default 100000 iterations; the accepted range
10000–2000000 is enforced on read too, so a forged cheap container is damage and
a very expensive one cannot become a denial of service). One salt per card and
one KDF run per unlock, not one per file — the freshness counter is rewritten
every few seconds, so per-file derivation would put a PBKDF2 in the write path;
each container is sealed under a per-file key derived with HKDF-SHA256 from the
master key, the salt and the context string, and the plaintext is sealed with
**AES-256-GCM** under a fresh 12-byte nonce. The context is the file's **path**,
not the node's address: an address changes on a rotation, and a container sealed
under the old address would then be unreadable by the node that owns it.

The header, the context and the ciphertext are all authenticated, so a container
cannot be moved to another file name, given a different work factor, or have its
length field edited. The two failure codes the operator can see are worth
knowing:

- `CC_STORE_E_AUTH` — the tag did not verify. **Wrong passphrase and tampering
  are indistinguishable by construction**, and the node does not pretend
  otherwise; "wrong passphrase or damaged file" is the truth.
- `CC_STORE_E_DAMAGE` — the public structure is wrong (not a container, a header
  that will not parse, a length that is not exactly header + plaintext + tag, an
  unknown algorithm id). Anyone holding the bytes can reach the same verdict, so
  saying it out loud reveals nothing.

**No recovery, by design.** The key comes from the passphrase and the salt and
from nothing else: there is no recovery phrase, no escrow, no hint and no
second path, and nothing here may grow one. Forget the passphrase and the sealed
files are gone — the only way back is `w` (wipe the card) and then `n` (mint a
new identity).

What it buys, and what it does not:

- It protects the card **at rest, with the device off and the card out**. That
  is the posture the SD-layout section calls "a card reader IS this node": with
  a passphrase set, the key and the state files are not readable without it.
- It does **not** protect a device that is running and unlocked, and it does not
  cover `peers/<hex>.bin` (see above) or the radio.
- It does **not** make the card's FAT forget bytes. Replacing a sealed file
  moves the live file aside as `<path>.old`, and that name is what a migration
  or a re-key briefly leaves behind; FAT unlinks the directory entry, it does
  not wipe the blocks, so a determined reader with the raw card can still
  recover a file that was replaced — sealed or plaintext. The wipe is the same
  story: it removes files, it does not shred the medium.
- The KDF cost is **unmeasured on this part**. The module only says PBKDF2 is
  not cheap ("HKDF is a few microseconds; PBKDF2 is not"), and the firmware
  prints `deriving key (PBKDF2, slow on this part)...` before every derivation
  precisely so the operator knows why the device pauses; no board was available
  to time it, so no number is quoted here.

The boot flow, in the order it happens:

- **A fresh card**: the passphrase is asked for **before the first private key
  exists**, so a key is never written in the clear even for a moment. An empty
  answer is a legitimate answer — it means "run this card in the clear" — and it
  is warned about out loud (`store PLAINTEXT: no passphrase set`, and that
  `key.bin` is readable by anyone with the card) rather than being taken
  silently.
- **A sealed card**: it prints `store SEALED: key.bin needs the passphrase` and
  asks, with three attempts. A derivation that does not open the identity file
  leaves the store **locked and the node inert** — never minting, because
  re-identifying the node over a typo would be the worst possible answer to one.
- **A legacy plaintext card**: recognised the way it can be recognised, by the
  envelope every plaintext file carries (`"CCFS"` + version), so it boots
  exactly as it always did, with `store PLAINTEXT: 'p' sets a passphrase` on the
  log. Migration is the operator's `p`, and it is never automatic.
- **A `key.bin` that is neither**: not a container and not one of our plaintext
  envelopes — truncated, half-written, or a file from something else — is
  reported as damaged (`key.bin UNREADABLE: not a store, not a plaintext file`)
  and the node refuses to run: no prompt, no passphrase offered, no migration
  prompt, and `key.bin INVALID: refusing to run` from the identity path, which
  is the same fail-closed answer a damaged key file has always had. Calling it
  "plaintext" here would misstate the node's posture, so it does not; only the
  wording knows the difference, and the mode stays plaintext solely so that the
  identity path reaches its normal INVALID answer.
- **A container from a newer firmware**: `store: newer format than this
  firmware`; it stays sealed and locked, so the node refuses to run rather than
  guessing at a format it does not know.
- **A missing `key.bin` on a card whose other files are sealed**: no prompt (a
  missing key file is damage, not a fresh start) but the store is remembered as
  sealed, so a later `n` asks for a passphrase instead of quietly writing the
  replacement identity in the clear.

The `p` command sets or changes the passphrase. On a plaintext card that is the
migration: it seals every file. On a sealed card it first asks for the **current
passphrase** and opens `key.bin` with it, because an unlocked store only means
the passphrase was typed at boot and the operator may have walked away since;
then it asks for the new passphrase **twice**, refuses an empty one (that is not
a way to remove a store that exists — `w` erases the card, and dropping the
passphrase while keeping the identity would be a silently weaker card), and
seals every file again — windows, revocation list, counter and the identity
**last**, because `key.bin` is the file that decides the mode at the next boot.
If any of that fails it puts the previous key and mode back and rewrites every
file, so a failed change leaves a working card and not half of one; if even the
rollback cannot complete it says `ROLLBACK INCOMPLETE: 'w' then 'n' makes a new
identity`. A passphrase change costs one KDF run plus one HKDF per file.

### What the card *is*

What a reader of the card gets depends on whether the store is sealed: with no
passphrase set, all of it is in the clear, and a reader of the card can be more
than a reader.

| File | Sealed? | Plaintext | With the passphrase |
|------|---------|-----------|---------------------|
| `/cc/key.bin` | yes | the node's private identity — the two 64-byte seeds the keys are rebuilt from; it can impersonate this node to every peer | a container: unreadable without the passphrase |
| `/cc/counter.bin` | yes | the values peers use to decide what is fresh, plus the retired flag | a container |
| `/cc/revoked.bin` | yes | which identities this node has retired | a container |
| `/cc/peers/<hex>.rp` | yes | the replay windows, i.e. how far each peer has counted | a container |
| `/cc/peers/<hex>.bin` | **no, on purpose** | every cached peer announce (public keys, name, price) | still readable — the mesh broadcasts this anyway, and the peer list has to work while the store is locked |

So: **the card is the identity**. With no passphrase, physical possession is the
whole security boundary and the files are crash-proof but not tamper-proof; with
one, possession gets you the ciphertext for four of the five kinds and the
passphrase is the boundary for those. Either way the card is the identity, which
is why the wipe exists.

Consequences, stated because they are real:

- **Rollback is possible and is not detected.** Copying an older-but-valid file
  back onto the card passes both the envelope and (if it is sealed) the
  container's own checks: it is a valid container under the same key. The
  effects: reused freshness counters and announce sequences (peers drop this
  node's traffic as a replay or a stale announce until it passes their
  high-water marks — the counter resumes `CC_REPLAY_WINDOW` past the saved
  value, which bounds it), an older `.rp` (one captured packet can replay once),
  and an older `revoked.bin` (a retired identity is trusted again on this node).
  The passphrase does not help here — it keeps a reader out, it does not make an
  old file detectable — and neither does the envelope. The durable fix is
  hardware: flash encryption and secure boot (see "Seeing the posture").
- **Damage and a missing card do not re-identify the node.** A `/cc/key.bin`
  that is present but invalid (wrong size, unreadable, unknown form, failing its
  CRC, or a seed that does not produce the stored `sign_pub`), and equally a
  boot with **no card at all**, makes the node enter a **no-identity** state
  instead of minting a new keypair: it announces nothing, sends nothing, answers
  nothing and drops every packet before any work, shows `no id` in the status
  bar, and says so on the log. `n` (then `y`) is the deliberate way out — it
  mints a new identity at a new address, which means peers must re-learn this
  node. The same state is entered after a wipe.
- **A missing `key.bin` on a card that has other state is damage, not a first
  boot.** The node generates a key automatically only when the card is empty of
  *our* files: `counter.bin`, `revoked.bin`, or peer files matching
  our own naming (`/cc/peers/<32 hex>.bin|.rp`). A stray foreign file in
  `/cc/peers` is not state and does not block a first boot.

The fail-safe chosen per file, so nothing is silent about it:

| File | Present but invalid | No card at all |
|------|---------------------|----------------|
| `key.bin` | fail closed: no identity, inert, `n` to recover (never auto-mint) | same: no identity, inert, `n` to run cardless |
| everything else | the node is inert, so nothing is read anyway | inert |

A sealed file that **will not open** is *invalid*, never *absent* — absence is
what decides whether this node mints, so a container that fails to authenticate
(freshly damaged, or sealed under another key) can never be read as "first boot".
A **locked** store is its own case: with no key in RAM the sealed kinds are
never decrypted and never judged on their bytes. `counter.bin`, `revoked.bin`
and `peers/*.rp` are skipped before any read and take their own fail-safe
silently (RNG-seeded counter, empty list, fresh windows), while `key.bin` comes
back **invalid from the lock itself**, not from its contents — which is what
makes the node inert. The boot block has already said why in the operator's
words (`store LOCKED: key.bin was not read`) before the identity path says
anything, and `i` reports `store sealed: LOCKED` for as long as it lasts.

Once the identity loads, the other files are read and each takes its own
fail-safe:

| File | Present but invalid |
|------|---------------------|
| `counter.bin` | treat as absent (reseed from the RNG) **and log it** — peers may reject traffic until the counters pass their windows |
| `revoked.bin` | treat as absent (empty list) **and log it** — retired identities are trusted again until they are revoked once more; the durable fix is to rotate away from a leaked key |
| `peers/<hex>.bin` | skip the file **and log a count**; an unknown payload version is treated the same way — the peer simply re-announces |
| `peers/<hex>.rp` | start fresh windows for that peer **and log it** — a captured packet may replay once |
| a sealed kind that will not open (wrong passphrase not yet given, or a container from another key) | never *absent*: the loader treats it as invalid, and `key.bin` failing closed is what makes the whole node inert until the passphrase is given or `w`/`n` is chosen |

### Seeing the posture (and turning it on)

The node **reports** the platform's security posture; it never gates on it. At
boot it prints a short block, and `i` prints the same on demand (the only
difference is the first word):

```
Sys: boot: id 1a2b3c4d, sd mounted
Sys: flash enc off, secure boot off
Sys: store PLAINTEXT: no passphrase ('p' sets one)
Sys: protects: key.bin counter.bin revoked.bin peers/*.rp
Sys: open: peers/*.bin (the cached announces) + the radio
Sys: off: a card reader IS this node; files readable + rollback-able
```

The third line is the part of the posture this firmware actually controls, and
it has four states: `store PLAINTEXT: no passphrase ('p' sets one)` (amber) on a
card with no passphrase, `store sealed: unlocked` (green) once the passphrase
has been given this session, `store sealed: LOCKED` (red) when the store is
sealed and no key is in RAM — the state a wiped card, an unknown passphrase or a
skipped prompt leaves behind — and `store UNREADABLE: key.bin is not a store or
plaintext file` (red) when the identity file is neither, which is the one state
where the node is inert *and* the posture is unknown rather than merely weak.
`protects:` is the list of sealed kinds and `open:` the one kind that stays
plaintext plus the radio (see "The passphrase store").

`flash enc on, secure boot on` is printed in green and the last line disappears;
anything else is amber plus that red line. `sd ABSENT` replaces `mounted` when
there is no card, and `id no id` when the node is inert.

The last red line is about the platform, not about the store, and it still
prints when the store is sealed: read it as "`peers/*.bin` and the radio are
readable, and everything this session has unlocked is unlocked because the
passphrase is in RAM". At rest, with the card out, the four sealed kinds are
not readable without the passphrase — which is exactly what the store line
above it says. The two lines answer different questions: the passphrase is this
firmware's protection, the fuses are the platform's.

Where the answers come from: `esp_flash_encryption_enabled()` (bundled ESP-IDF
`tools/sdk/esp32s3/include/bootloader_support/include/esp_flash_encrypt.h`,
static inline at line 48) reads the flash-encryption efuse; `esp_secure_boot_enabled()`
(same directory, `esp_secure_boot.h`, static inline at line 62) reads the
secure-boot state via the ROM, and returns false when secure boot is not built
into the bootloader. Both are header-only inlines in the framework this project
already uses, so the queries need no build flag, no dependency and no library —
and on a plain build they simply answer "off", which is the truth.

**Nothing here is enabled by default, and no code path in this node assumes it.**
A plain build is exactly today's behaviour: the boot line and `i` exist so the
operator can see which side of the line they are on rather than infer it from
prose.

Enabling them, for this board (`esp32-s3-devkitc-1`) with this framework
(PlatformIO `platform = espressif32@6.7.0`, `framework = arduino`,
arduino-esp32 2.0.17 / ESP-IDF 4.4.7 — read from the installed tree's
`cores/esp32/esp_arduino_version.h` and `tools/sdk/esp32s3/include/esp_common/
include/esp_idf_version.h`) — what I checked, and what it means:

- They are **bootloader and fuse** features, not application flags. In IDF terms
  the knobs are `CONFIG_SECURE_BOOT` and `CONFIG_SECURE_FLASH_ENC_ENABLED`.
- **They cannot be turned on from `platformio.ini` in this configuration.**
  The Arduino builder in this platform has no sdkconfig hook at all (no
  `sdkconfig` reference in `builder/frameworks/arduino.py` in the pinned 6.7.0
  platform, nor in 6.9.0, nor in the current 7.0.1), and the framework ships a
  **prebuilt** bootloader with a pre-generated config —
  `tools/sdk/esp32s3/bin/bootloader_*.elf` and a `tools/sdk/esp32s3/sdkconfig`
  that says `# CONFIG_SECURE_BOOT is not set` (line 83) and
  `# CONFIG_SECURE_FLASH_ENC_ENABLED is not set` (line 84). A bootloader you do
  not build is a bootloader you cannot configure.
- The path that does exist in this platform is the **`espidf` framework**, whose
  builder takes `board_build.esp-idf.sdkconfig_path` (defaulting to
  `sdkconfig.<env>`) and passes it to the build as `-DSDKCONFIG=…`. In the
  pinned 6.7.0 tree those are `builder/frameworks/espidf.py`'s
  `board.get("build.esp-idf.sdkconfig_path", … "sdkconfig.%s" …)` default and
  the `"-DSDKCONFIG=" + SDKCONFIG_PATH` entry in the CMake argument list (lines
  111-113 and 862 *there* — the numbers move between platform releases, so match
  the text, and note those paths are inside the platform package, not this
  repo). That is where the two `CONFIG_` options would be set, together with the
  partitions and the secure-boot key; arduino-esp32 as an IDF component is the
  equivalent route on newer arduino-esp32 releases.
- What each buys: flash encryption makes the app image, and anything else in
  flash, unreadable off-device; secure boot makes the ROM verify the bootloader
  and each image, so a modified image will not run. **Neither touches the SD
  card** — it is a separate, removable medium — and what covers the card is the
  passphrase store, at rest, for four of the five file kinds (see "The
  passphrase store").
- What each costs: **burning the efuses is irreversible**, enabling encryption
  means the flash must be re-flashed/encrypted from then on, and **a lost or
  wrong key means the device is bricked** — the chip will boot nothing. These
  are the owner's decisions, not this app's defaults.

What I could not determine here: the exact end-to-end fuse-burning and first
encrypted-flash sequence for this board (no hardware to try it on), and whether
a newer arduino-esp32 release exposes a smoother hook than the IDF-component
route above.

### Wipe and re-key

`w` then **`Y` (capital)** is the "retire the device / hand over the card" path
and it **verifies itself**: it removes `key.bin`, `counter.bin`, `revoked.bin`
and every file in `/cc/peers/` — including any `.tmp`/`.old` left by an
interrupted sealed write — then re-checks by existence that they are gone.
A removal the card refuses — a write-protected card, a failed mount, a stuck
bus — is reported as `WIPE INCOMPLETE: still present: …` in red rather than
claimed as done, and the operator is told to erase the card by hand. The RAM
half cannot fail and happens either way: the identity, the peer cache with its
replay windows, the revocation list, the live sessions, the rotation slot (a
whole staged private key), the store's derived key and the plaintext scratch
buffers are wiped, and the counters are reseeded from the hardware RNG — so even
a card that kept its files leaves a node that is inert and purged. It logs
exactly what it destroyed, and the node stays inert (`no id`) until `n`.

The store is handled with the same care: the derived key is zeroized, and if the
files really are gone the card is back to `STORE_PLAINTEXT`, while an
**incomplete** wipe stays sealed-but-locked — sealed files may still be out
there, so a later `n` asks for a passphrase rather than quietly writing the
replacement identity in the clear. The wipe removes files; it does not shred the
medium (see "The passphrase store").

`n` then `y` mints a new identity. It is the recovery path for a damaged or
missing key file, the way to run without a card, and the deliberate path for
"the old key is burned, give me a new one with no continuity". With a sealed but
**locked** store (unknown passphrase, or a card just wiped) it asks for a
passphrase decision first, so a replacement private key is never quietly written
in the clear. Both prompts are cancelled by any other key **or by a five-second
timeout**, so an abandoned `w` cannot be confirmed by a stray keypress later;
only the wipe needs the capital letter, because only it is unrecoverable.

Neither `n` nor `w` can be undone from the node. A wipe followed by a reboot
also mints on the next boot, because a card with nothing on it is a first boot —
if the card is being handed on, hand it on before rebooting.

## Proof of work

Every packet carries a proof of work whose difficulty is a *receiver* policy
(`CC_POW_DIFFICULTY_*` in `platformio.ini`): a stricter receiver drops what a
laxer sender mined, so both ends of a mesh must agree or they silently ignore
each other. Difficulty prices *minting* a fresh packet and nothing else: a
replay of a captured packet costs no mining at all, so replays are handled by
the replay windows and floods by the rate limits above, not by difficulty.
`platformio.ini` therefore puts the price on minting the small packets that
make a receiver do expensive work — a 34-byte presence, a 27-byte `key_req`, or
a `link_req`, which costs the responder a KEM decapsulation plus a signature —
rather than on the bulk packets this node must mine for itself (an announce,
the opportunistic chat, `link_proof` and `identify` all stay at difficulty 1;
a 4.5 KB chat at difficulty 2 is about a second of mining on a desktop host,
which an ESP32-S3 cannot afford per message). `link_data`, `identify` and
`link_close` carry no PoW at all: the handshake prices the session and each
message is then just an AEAD record.

Three inbound budgets back this up, all applied *before* the expensive work:
announces are budgeted before their ML-DSA verification (`ANN_VERIFY_BURST`
per `ANN_VERIFY_WINDOW_MS`, sized so a whole peer table powering up together
still gets through), `link_req` before the responder's decapsulation and
signature (`LINK_ACCEPT_BURST` per `LINK_ACCEPT_WINDOW_MS`), and a chat
addressed to this node before `cc_chat_parse()`'s ML-DSA verification
(`CHAT_VERIFY_BURST` per `CHAT_VERIFY_WINDOW_MS`, a whole peer table per 4 s).
The chat budget is what bounds the CPU on WiFi/802.11, where airtime does not:
a captured valid chat is cheap to replay, and without the budget an attacker
could keep the verifier saturated. The trade-off is stated plainly in the
source — it also caps the legitimate chat rate to that burst, which is why the
burst is generous (well above any human typing rate, well below a flood), and
refusals are counted in the stats line as `cd`.

## Roads

These four roads are the reference transports for cosechat. The `cc_road_t`
interface and the shared framing are part of the library
(`include/cosechat_road.h`, `src/cosechat_road.c`), so a road implementation
supplies only its medium: an `emit` callback (`cc_road_emit_fn`) that
`cc_road_send_pkt()` drives fragment by fragment, an `init`/`shutdown` pair,
and a non-blocking `recv()` that copies a completed packet out with
`cc_road_pkt_get()`. The RX path feeds fragments to a `cc_road_frag_t` through
`cc_road_rx_frag()`. The fragmentation and reassembly loop is shared rather
than copied per road, and nothing in the road layer allocates.

Every fragment is a 4-byte header (`magic, msg_id, frag_idx, frag_total`) plus
payload, and both ends must agree on the payload size because it is not
transmitted. LoRa, WiFi and 802.11 use the maximum `CC_ROAD_FRAG_PAYLOAD` (248
bytes — 252 on the wire with the header), while BLE advertising passes its own
243. Only the final fragment may be shorter than the agreed payload.

`road_lora` runs its own FreeRTOS task (RX except while transmitting) and
fragments packets to the SX1262 252-byte limit. `road_wifi` joins WiFi and
broadcasts the same fragments as UDP datagrams on port 4242, draining the
socket from the main loop.

`road_ble` sends each fragment as anonymous BLE 5 extended advertising data and
listens with a continuous passive scan; it needs no peer to connect to and
exposes no address. `road_80211` sends each fragment in a vendor-specific
action frame to the broadcast MAC and listens in promiscuous mode — no
association, no authentication, no ACK. Both reassemble received fragments in
the radio's own task and hand `recv()` complete packets, so nothing changes in
`main.cpp` but the road `#include` and the init call.

`road_lora` needs a mutex for the SPI bus it shares with the SD card; the demo
creates one and passes it as `spi_mux`. `road_ble` is the only road whose
`send()` blocks: the advertisement data is swapped per fragment, so an
announce takes `fragments × adv_ms` (27 × 120 ms ≈ 3.2 s by default).

The `ble` env pulls `NimBLE-Arduino` and turns on extended advertising with
`-DCONFIG_BT_NIMBLE_EXT_ADV=1`; the `dot11` env uses only the WiFi stack that
ships with the framework.

## Dependencies

`m5stack/M5Cardputer`, `jgromes/RadioLib` (the `lora` env), the local
`lib/wolfssl`, `wolfCOSE`, and — for the `ble` env — `NimBLE-Arduino ^1.4.3`.
The cosechat library itself is pulled in as `symlink://../..`, and its road
framing (`src/cosechat_road.c`) links into the firmware.

`wolfCOSE` ships no PlatformIO manifest, so PlatformIO never puts its
`include/` directory on the search path for the cosechat library's own
sources (the sketch compiles fine, `src/cosechat.c` does not). `[env]` adds it
explicitly:

```ini
-I${PROJECT_LIBDEPS_DIR}/${PIOENV}/wolfCOSE/include
```

## wolfSSL

The build needs **wolfSSL ≥ 5.8** for ML-KEM (`wolfssl/wolfcrypt/wc_mlkem.h`).
The PlatformIO registry package stops at 5.7.2, so a plain `lib_deps = wolfssl`
will not compile. `fetch-wolfssl.sh` fetches upstream v5.9.0-stable into
`lib/wolfssl/` (a gitignored local PlatformIO library compiled from the
wolfcrypt sources only) and pins `user_settings.h` next to it:

```sh
./fetch-wolfssl.sh
```

Re-run it after editing `include/user_settings.h`, since the library's own
sources cannot see the sketch's `include/` directory.

`user_settings.h` opts in to the experimental ML-DSA/ML-KEM code and `#undef`s
`WOLFSSL_ESPIDF`: PlatformIO defines `PLATFORMIO` and Arduino-ESP32 defines
`ESP_PLATFORM`, which makes wolfSSL's `settings.h` set `WOLFSSL_ESPIDF` even
for this Arduino build, and wolfSSL then rejects `ARDUINO` + `ESPIDF`.
