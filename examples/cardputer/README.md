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
~6.5 KB (6470 B measured, ~27 LoRa fragments and ~27 BLE advertisements) and
the opportunistic `chat` is ~4.5 KB (~19 fragments, it carries a per-message
ML-DSA signature), but a **link** (session) pays that once: `link_req` is ~5
fragments, `link_proof` ~14, and then every message is a single AEAD record —
one fragment. A presence is one fragment either way.

## Controls

| Key | Action |
|-----|--------|
| letters | type a message |
| Tab | cycle peers (received via announce) |
| Enter | send the message to the selected peer |
| Del | backspace |

The serial console takes eight commands:
- `r` (rotate identity), `x` (revoke it), `n` (mint a new identity — the
  recovery path for a damaged key file or a cardless run, see "What the card
  *is*"), and `w` (wipe the card); `n` takes `y`, `w` takes a capital `Y`, and
  either prompt is cancelled by any other key or by a five-second timeout.
- `g` (create a group), `j<hex>` (join one), `s` (share its secret over an open
  link), `p<text>` (post to it). See "Groups".

The status bar shows the first 4 bytes of this node's address, or `no id` while
the node is inert (no identity).

The log line shows `ANN`/`PRE` (announce/presence received), `TX` (something we
sent), and `RX`. A `TX` message says which path it took: `(link)` for a single
AEAD record on an open session, `(signed)` for the opportunistic signed chat
used while a handshake is still in flight. An `RX` chat line always means the
packet authenticated: a forged or replayed one never reaches the display, and
shows as `<hex> bad signature`, `<hex> no key (key_req)` or `<hex> decrypt
failed`, while replays are counted silently. A group post is shown as
`[grp <gid4> <poster4>] text` and is always a post that decrypted; the poster
half is a *self-claimed label*, not a verified identity (see Groups). Sessions
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
(`rp sig nokey dec cd ann v link rot rev ctl grp`), plus a third line when the
relay is compiled in (see Relay below). `cd` counts chats refused by the chat
verify budget and `grp` counts group posts refused (a spent verify budget, or a
post whose PoW or tag did not verify — a full label table no longer refuses
anything, it evicts the least recently verified label; see Groups).

## How it works

- On boot the node generates (or loads from SD) an ML-DSA-65 + ML-KEM-768
  keypair (NIST category 3; the sizes follow `CC_SIGN_LEVEL`/`CC_KEM_LEVEL`),
  broadcasts a signed **announce**, then sends an unsigned **presence**
  heartbeat every 60 s. A key file that is *present but invalid* is not
  regenerated: the node goes inert instead and waits for `n`, so a damaged card
  can never silently re-identify it (see "What the card *is*").
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
- All library calls go through one static `cc_work_t` (~34 KB of scratch,
  heap-free, never on the stack). One context is enough because the library is
  only called from `setup()`/`loop()`; the road tasks touch only the framing
  helpers in `cosechat_road.c` and never enter this library.
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
- **Groups (v0.10, still wire revision 9).** `GROUP_DATA` (11) is a broadcast
  post sealed under a shared 32-byte secret — a new *type* inside revision 9,
  which is why it is additive: a receiver that does not know the type drops it
  as `CC_E_FORMAT`, and so does a relay built before the type existed (group
  traffic therefore crosses a mesh only where every relay on the path knows it).
  This build does carry it. See "Groups" below.

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
`LINK_MAX` is 4 sessions, which covers the one peer being talked to plus a
handshake or two in flight, at 168 bytes each. Links live in RAM only: a reboot
forgets them and the next message re-handshakes.

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

RAM budget: the big static objects are the `cc_work_t` scratch (~34 KB), the
peer key cache (16 × (1952 + 1184) ≈ 50 KB), the rotation key (~13 KB, live
only while a rotation is published, but statically reserved) and the wire
scratch buffers; the envs build at 67–76% of the ESP32-S3's 320 KB DRAM, with
`wifi` the tightest at ~75.4%. Additions from the security and group work are
small and named: the revocation-load scratch (224 B), the chat and group verify
budgets (~136 B), and the group state — `cc_group_t` 44 B, `GROUP_WIN_MAX` 8
replay windows (8 × 64 B = 512 B), the throwaway window an unseen label is
parsed against (64 B), the decrypted-post scratch (552 B), the post TX buffer
(`CC_GROUP_BUF_SZ` 752 B) and the console text argument (513 B). The envelope,
the mint and the wipe add no static data of their own (a CRC with no table,
locals only): the card-hardening pass measures **+280 B** (`wifi` 247048 →
247328 B, 75.4% → 75.5%), the seed-form key file a further **+256 B** (`wifi`
247328 → 247584 B) — mostly the library's own `cc_key_t` growth (136 B) plus the
key-file scratch buffers — and the storage-audit fixes **+8 B** (`wifi` 247584 →
247592 B, 75.5% → **75.6%**). Nothing allocates.

## Identity: rotation and revocation

Two serial console commands drive the identity paths, because a path nobody can
exercise rots:

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

## Groups

A **group** is a set of members sharing one 32-byte secret. There is no
membership protocol, no epochs and no sender keys: the secret *is* the group and
the gid is derived from it (`SHA-256("cosechat/group gid" | secret)[0:8]`), so
membership changes never move the group's address. **Removal is a new group** —
a new secret, hence a new gid. Someone who has left still knows the old secret
and can still read (and mint) anything derived from it, so making a new group
and telling the others is the only thing that actually excludes them.

| Command | What it does |
|---------|--------------|
| `g` | create a group: mint a random secret, print it as hex, persist it, start listening |
| `j<hex>` | join with a typed 64-hex secret (Enter not required; a newline works too) |
| `s` | share the secret over an open link with the selected peer (a convenience, see below) |
| `p<text>` | post `<text>` to the group (line ends at Enter) |

The hex `g` prints is how the secret is shared out of band: read it on the other
node with `j`. It is stored in the clear in `/cc/group.bin`, like the node key
in `/cc/key.bin`; **anyone who reads the card is a member**, and the file is not
tamper-proof. The same file carries our post sequence, saved on the same drift
cadence as the outbound counter, so a reboot cannot repeat a `(gid, poster,
seq)` a receiver has already accepted.

Receive side. A group post (`CC_MSG_GROUP_DATA`) is **broadcast and carries no
recipient**, so it cannot go through the recipient-filtered chat branch; it has
one of its own:

- With **no group joined** it is dropped at the cheapest possible point: no
  budget is spent and no crypto runs, because the gid that would identify our
  group does not exist yet.
- With a group joined, the gid is compared first (a plain decode); the gid is
  on the air in every post, so this is a filter rather than a secret, and it is
  there so another group's post — or a stranger's garbage — never spends a
  verify-budget slot that legitimate posts need.
- A post for our group then spends a verify budget (`GROUP_VERIFY_BURST` per
  `GROUP_VERIFY_WINDOW_MS`, `MAX_PEERS` per 4 s) **before** the work. A post
  costs a PoW check (`CC_POW_DIFFICULTY_GROUP`) plus the AEAD attempt, and one a
  member captured is cheap to replay, so on WiFi/802.11 an unbudgeted verifier
  would be saturated. A refusal is counted (`grp` in the stats line) and dropped
  without a display line.
- An unseen poster label is parsed against a **throwaway window** first and
  claims a slot in the table only if that parse authenticates, so a stranger —
  anyone at all, who has merely seen one post and therefore knows the gid, which
  is on the air in every post — cannot take slots with junk labels and make the
  node deaf to members whose labels it has not seen yet (a new member's first
  post, or a member's post after a rotation). Nothing an outsider sends reaches
  the table. One mined packet is also spent before the table is touched
  (`CC_POW_DIFFICULTY_GROUP`), so churn costs the sender something.
- The bound is `GROUP_WIN_MAX` = 8 labels. When the table is full the **least
  recently verified** label's window is evicted rather than a new label refused:
  refusing would let anyone who can mine a few packets fill the table into
  permanent deafness, and eviction only loses that label's replay state — its
  old post could then be displayed a second time. The order comes from the
  window's own `last_seen`, which `cc_group_post_parse()` stamps on every
  verified post (a window that never verified is dropped first — the label-flood
  case), so no parallel clock is kept. That trade is deliberate and cheap: a post
  mutates no app state, and a replay window exists to stop a *re*action, not to
  suppress duplicate text. A window is never silently reset while it is live; it
  is replaced, and the replacement is what the least-recently-verified rule makes
  predictable.
- An accepted post is displayed as `[grp <gid4> <poster4>] text` in its own
  colour. **The poster label is self-claimed and NOT a verified identity**: every
  member holds the same key and can seal any label, so any member can mint
  another member's label. The library's own suite pins that limit as a test
  (`group_member_can_forge_another_label` in `test/test_cosechat.c`), and the
  residual is real in the other direction too — a member can silence another by
  minting a high sequence under its label. Only per-post signatures would change
  that, at ~3.3 KB per post, and they are deliberately out of scope. No policy
  in this app depends on the poster field.

Provisioning is **out of band** (`g` prints the secret, `j<hex>` takes it),
which is the path that works when members are not adjacent to each other. As a
convenience for peers that do happen to share an open link, `s` sends the secret
as one `CC_LINK_KIND_GROUP_KEY` link record, and a node that receives one joins
that group. The record is authenticated by the link key and the link's own
sequence window is its replay defence, exactly as for a data record (the
handshake that opened the session was the budgeted work); but because it
**replaces** this node's group, it is accepted only from a link whose peer has
already proved its address, the same standard `LINK_REQUIRE_IDENTIFY` holds
data to.

**The relay carries group posts.** Under `CC_RELAY`, every post — for our group
or another — is offered to `cc_relay_group()`, the module's own entry point for
this class: it has its own airtime pool (`CC_RELAY_AIRTIME_GROUP`), a per-gid
post budget (`CC_RELAY_GROUP_BUDGET`), its own hop cap
(`CC_RELAY_MAX_HOPS_GROUP`) and the keyless PoW gate (`CC_POW_DIFFICULTY_GROUP`)
before any budget is spent, and a refusal leaves the table and the budgets
untouched. The offer happens **first and unconditionally**, before anything
local: whether we join the group or not, and whether our own budget refuses the
post, changes nothing about the mesh's traffic being carried. Our own group's
posts are forwarded too (see the Relay section) — a post is fan-out, not a
unicast to us.

## Relay (opt-in)

The `lora-relay` env defines `CC_RELAY` and compiles in `cc_relay_t` (a
path table, a duplicate cache, per-destination budgets and counters). It reuses
the `lora` road and flags, so a build break in the relay path is visible even
though the other four envs do not include it.

When it is on, every accepted (signature-verified) announce is offered to
`cc_relay_announce`, every chat **not addressed to us** to
`cc_relay_forward`, and **every** group post — ours and another group's alike —
to `cc_relay_group`; anything the module answers with `CC_RELAY_FWD` is sent
with the road. A chat for us is delivered locally and never re-broadcast, and
our own announce is never forwarded. A group post is forwarded even when it is
for a group we are in: a post is fan-out rather than a unicast to us, so
members we cannot reach still need it carried, and the duplicate we create is
dropped downstream by a receiving member's per-poster window (and here by the
module's duplicate cache) — the same rule the app already follows for an
announce, which it both learns from and re-broadcasts. **Link traffic is never
offered at all**: a link record carries no destination, and a link only exists
between direct peers.

Tuning is in `platformio.ini`. The medium-modelling values are left at their
defaults because the defaults *are* this road — one SF7 / 125 kHz LoRa channel,
which the three airtime pools model together: `CC_RELAY_AIRTIME_ANNOUNCE`
16384 B, `CC_RELAY_AIRTIME_DATA` 16384 B and `CC_RELAY_AIRTIME_GROUP` 8192 B per
60-tick window (40960 B per window, ~683 B/s; three pools so that one 6.5 KB
announce cannot black out relayed data for the whole window and a post storm
cannot silence a conversation), with `CC_RELAY_FWD_BUDGET` 3 per destination,
`CC_RELAY_GROUP_BUDGET` 2 per group, `CC_RELAY_DUP_TTL` 300,
`CC_RELAY_PATH_TTL` 600, `CC_RELAY_MAX_HOPS` 8 and `CC_RELAY_MAX_HOPS_GROUP` 8;
the relay's clock is seconds (`millis() / 1000`) to match those tick units.
Only the RAM-shaped knobs are cut: `CC_RELAY_PATHS` 16, `CC_RELAY_DUP` 16,
`CC_RELAY_BUDGETS` 8 and `CC_RELAY_GIDS` 8, which makes `cc_relay_t` 1516 B
instead of the default 4460 B (measured with `sizeof` under the env's defines:
16 paths × 48 B, 16 duplicate slots × 20 B, 8 budget slots × 24 B, 8 group
slots × 16 B, the window and three pool counters, and 92 B of counters), plus a
7 KB re-broadcast buffer (`CC_ANN_BUF_SZ + 1` = 7024 B) and the 8-entry pin
table; the whole relay env costs 8928 B (~8.9 KB) of RAM over the plain lora
build (measured: 230080 B vs 221152 B).

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
so a drop reason is never invisible. It ends with the group class, which the
module accounts for in its own pool: `grp` is the group-post bytes relayed in the
current window against `CC_RELAY_AIRTIME_GROUP` (the counters in
`cc_relay_stats_t` are per class only for the pools; the cumulative figures are
total `airtime`, so the group pool's *window* figure is what the line shows).
Group refusals are counted in the same `e_*` fields as the other classes (`pow`
for an unmined post, `bud` for a spent per-group or pool budget, `dup` for a post
already forwarded, `oth` for `E_TYPE`/`E_MAXHOPS` and the rest), so the
per-class split is in the byte pools rather than in the refusal counters.

## SD card layout

Every file this node writes starts with the same 9-byte integrity envelope:

```
envelope               "CCFS" <version 1> <crc32 LE of the payload>
/cc/key.bin            envelope + <form><seeds><sign_pub>             (2090 B)
/cc/counter.bin        envelope + <magic 0xCC><version><counter le32> <seq le32> [<flags>]
/cc/revoked.bin        envelope + <version><REVOKED_MAX cc_revoked_t>  (retired identities)
/cc/group.bin          envelope + <version><secret 32><seq le32>      (the group secret)
/cc/peers/<hex>.bin    envelope + <version><raw cc_announce_t>
/cc/peers/<hex>.rp     envelope + <version><unsigned cc_replay_t><authed cc_replay_t>
```

`key.bin`'s payload starts with a form byte, and the identity is stored as
**seeds**, not as expanded private keys:

| Form | Payload | Size |
|------|---------|------|
| `1` seed (what this build writes) | `form` 1 + `sign_seed` 64 + `kem_seed` 64 + `sign_pub` 1952 | 2081 B (2090 B file) |
| `2` expanded (read for compatibility, written only when there is no seed) | `form` 1 + `sign_priv` 4032 + `sign_pub` 1952 + `kem_priv` 2400 | 8385 B (8394 B file) |

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

### What the card *is*

Everything persisted is in the clear, and a reader of the card can be more than
a reader:

| File | In the clear | What a card reader gets |
|------|--------------|--------------------------|
| `/cc/key.bin` | yes | the node's private identity — it holds the two 64-byte seeds the keys are rebuilt from, and it can impersonate this node to every peer |
| `/cc/group.bin` | yes | a group member — it can read and mint group posts |
| `/cc/counter.bin` | yes (not secret) | the values peers use to decide what is fresh, plus the retired flag |
| `/cc/revoked.bin` | yes | which identities this node has retired |
| `/cc/peers/<hex>.bin` | public data anyway | every cached peer announce (public keys, name, price) |
| `/cc/peers/<hex>.rp` | yes | the replay windows, i.e. how far each peer has counted |

So: **the card is the identity**, and a group secret on the card is a
membership. Physical possession is the security boundary; the files are
crash-proof, not tamper-proof.

Two consequences, stated because they are real:

- **Rollback is possible and is not detected.** Copying an older-but-valid file
  back onto the card passes the envelope. The effects: reused freshness
  counters and announce sequences (peers drop this node's traffic as a replay or
  a stale announce until it passes their high-water marks — the counter resumes
  `CC_REPLAY_WINDOW` past the saved value, which bounds it), an older `.rp` (one
  captured packet can replay once), and an older `revoked.bin` (a retired
  identity is trusted again on this node). The durable fixes are hardware —
  flash encryption and secure boot — or an operator passphrase that encrypts the
  key file; **the passphrase is not implemented** here.
- **Damage and a missing card do not re-identify the node.** A `/cc/key.bin`
  that is present but invalid (wrong size, unreadable, unknown form, failing its
  CRC, or a seed that does not produce the stored `sign_pub`), and equally a
  boot with **no card at all**, makes the node enter a **no-identity** state
  instead of minting a new keypair: it announces nothing, sends nothing, answers
  nothing and drops every packet before any work, shows `no id` in the status
  bar, and says so on the log. `n` (then `y`) is the deliberate way out — it
  mints a new identity at a new address, which means peers must re-learn this
  node and any group membership must be re-provisioned. The same state is
  entered after a wipe. `/cc/group.bin` that is present but invalid does the
  same for the group: group traffic is refused until the operator re-joins
  (`j<hex>`) or creates a new group (`g`).
- **A missing `key.bin` on a card that has other state is damage, not a first
  boot.** The node generates a key automatically only when the card is empty of
  *our* files: `counter.bin`, `group.bin`, `revoked.bin`, or peer files matching
  our own naming (`/cc/peers/<32 hex>.bin|.rp`). A stray foreign file in
  `/cc/peers` is not state and does not block a first boot.

The fail-safe chosen per file, so nothing is silent about it:

| File | Present but invalid | No card at all |
|------|---------------------|----------------|
| `key.bin` | fail closed: no identity, inert, `n` to recover (never auto-mint) | same: no identity, inert, `n` to run cardless |
| everything else | the node is inert, so nothing is read anyway | inert |

Once the identity loads, the other files are read and each takes its own
fail-safe:

| File | Present but invalid |
|------|---------------------|
| `group.bin` | refuse group traffic, loud log with the way out (`j`/`g`) |
| `counter.bin` | treat as absent (reseed from the RNG) **and log it** — peers may reject traffic until the counters pass their windows |
| `revoked.bin` | treat as absent (empty list) **and log it** — retired identities are trusted again until they are revoked once more; the durable fix is to rotate away from a leaked key |
| `peers/<hex>.bin` | skip the file **and log a count**; an unknown payload version is treated the same way — the peer simply re-announces |
| `peers/<hex>.rp` | start fresh windows for that peer **and log it** — a captured packet may replay once |

### Wipe and re-key

`w` then **`Y` (capital)** is the "retire the device / hand over the card" path
and it **verifies itself**: it removes `key.bin`, `group.bin`, `counter.bin`,
`revoked.bin` and every file in `/cc/peers/`, then re-checks by existence that
they are gone. A removal the card refuses — a write-protected card, a failed
mount, a stuck bus — is reported as `WIPE INCOMPLETE: still present: …` in red
rather than claimed as done, and the operator is told to erase the card by hand.
The RAM half cannot fail and happens either way: the identity, the group secret,
the peer cache with its replay windows, the revocation list, the live sessions,
the rotation slot (a whole staged private key) and the plaintext scratch buffers
are wiped, and the counters are reseeded from the hardware RNG — so even a card
that kept its files leaves a node that is inert and purged. It logs exactly what
it destroyed, and the node stays inert (`no id`) until `n`.

`n` then `y` mints a new identity. It is the recovery path for a damaged or
missing key file, the way to run without a card, and the deliberate path for
"the old key is burned, give me a new one with no continuity". Both prompts are
cancelled by any other key **or by a five-second timeout**, so an abandoned `w`
cannot be confirmed by a stray keypress later; only the wipe needs the capital
letter, because only it is unrecoverable.

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
the opportunistic chat, a group post, `link_proof` and `identify` all stay at
difficulty 1; a 4.5 KB chat at difficulty 2 is about a second of mining on a
desktop host, which an ESP32-S3 cannot afford per message). `link_data`,
`identify` and `link_close` carry no PoW at all: the handshake prices the
session and each message is then just an AEAD record. A group post
(`CC_POW_DIFFICULTY_GROUP`, set to 1 here beside `CC_POW_DIFFICULTY_CHAT`) is in
the same class: it is broadcast, so it has no single receiver to please, and the
receiver's own verifier is what the *budget* below protects.

Four inbound budgets back this up, all applied *before* the expensive work:
announces are budgeted before their ML-DSA verification (`ANN_VERIFY_BURST`
per `ANN_VERIFY_WINDOW_MS`, sized so a whole peer table powering up together
still gets through), `link_req` before the responder's decapsulation and
signature (`LINK_ACCEPT_BURST` per `LINK_ACCEPT_WINDOW_MS`), a chat
addressed to this node before `cc_chat_parse()`'s ML-DSA verification
(`CHAT_VERIFY_BURST` per `CHAT_VERIFY_WINDOW_MS`, a whole peer table per 4 s),
and a group post before its PoW check and AEAD attempt (`GROUP_VERIFY_BURST`
per `GROUP_VERIFY_WINDOW_MS`, the same size).
The chat and group budgets are what bound the CPU on WiFi/802.11, where airtime
does not:
a captured valid chat or post is cheap to replay, and without the budget an
attacker could keep the verifier saturated. The trade-off is stated plainly in
the source — it also caps the legitimate rate to that burst, which is why the
burst is generous (well above any human typing rate, well below a flood), and
refusals are counted in the stats line as `cd` (chat) and `grp` (group).

## Roads

These four roads are the reference transports for cosechat. The `cc_road_t`
interface and the shared framing are part of the library
(`include/cosechat_road.h`, `src/cosechat_road.c`), so a road implementation
supplies only its medium: an `emit` callback (`cc_road_emit_fn`) that
`cc_road_send_pkt()` drives fragment by fragment, an `init`/`shutdown` pair,
and a non-blocking `recv()` that copies a completed packet out with
`cc_road_pkt_get()`. The RX path feeds fragments to a `cc_road_frag_t` through
`cc_road_rx_frag()`. The fragmentation and reassembly loop is shared rather
than copied per road, and nothing here allocates.

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
