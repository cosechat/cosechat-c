# cosechat

Post-quantum mesh chat protocol for microcontrollers and desktop. Inspired by [Reticulum](https://reticulum.network/) / LXMF.

Portable C11: no platform headers, no dynamic allocation. The envelope is
deterministic CBOR (RFC 8949 §4.2), its algorithms are labelled with COSE
identifiers, and the opportunistic chat payload is a COSE_Encrypt0 structure;
everything else is this protocol's own envelope. The link (session) layer, the
relay, the road interface and its framing are part of the library too; only the
medium-specific code (radios, sockets, tasks) lives with the consumer.

This is library version 0.10.0, wire revision 9.

## Features

- **Addresses** — 16-byte, derived from the ML-DSA signing public key (`SHA-256(sign_pub)[0:16]`). A rotated signing key is a new address, bridged by a signed continuity statement (see [rotation and revocation](#identity-rotation-and-revocation)).
- **Category-3 defaults** — ML-DSA-65 and ML-KEM-768 out of the box; `CC_SIGN_LEVEL` (2/3/5) and `CC_KEM_LEVEL` (512/768/1024) override them, and every buffer macro below follows, so a downgrade changes the wire sizes.
- **Announces** — self-signed with raw ML-DSA over the canonical byte string, carrying name + KEM public key + a CBOR metadata map + a signed `admit` declaration, plus a signed monotonic `seq` and an absolute `expiry`; `cc_announce_fresh` is the dedup / anti-replay / freshness rule.
- **Chat (opportunistic)** — one-shot and addressed: ML-KEM encapsulation + AES-256-GCM with the payload in a COSE_Encrypt0 (RFC 9052 §5.2) structure, signed by the sender's raw ML-DSA key, with the receiver verifying that signature against the sender's *announced* key before any decapsulation, so an unknown sender is refused outright (`CC_E_NOKEY`).
- **Links (sessions)** — a handshake (LINK_REQ/LINK_PROOF) derives per-direction keys with forward secrecy, then a message is one small AEAD record named by `link_id` alone: no per-message signature, no per-message PoW, and neither address on the wire.
- **Groups** — a shared-secret broadcast: members hold one 32-byte secret, derive one key from it, and post to the group under a `gid` (the first 8 bytes of a hash of that secret). A post proves *a key holder* produced it, not which one (see [Group messaging](#group-messaging)).
- **Identity continuity** — ROTATE (9) moves an identity to a new signing key with the old key co-signing the move, and REVOKE (10) retires an address permanently; both are caller-driven, and the caller decides how long it remembers a revocation.
- **Replay protection** — a caller-owned, caller-persisted 32-byte sliding window (`cc_replay_t`) per peer and per traffic class; authenticated chat and unsigned presence/`key_req` never share a window. A link carries a 64-slot sequence window inside `cc_link_t`, and `cc_replay_move` carries a window across a rotation.
- **Admission pricing** — SHA-256 proof-of-work on the handshake and the directed packets, priced per packet type, plus an `admit` field in the announce where a node *declares* the price it asks of senders for chat, `link_req` and `key_req`. A receiver always enforces its own configured difficulty; the declaration only tells senders what to aim at.
- **Relay (multi-hop)** — an opt-in, key-free forwarding module (`include/cosechat_relay.h`): a best-effort next-hop table learned from announces, sequence-based route rules, duplicate suppression, separate announce and data airtime pools plus a per-destination data budget, and `cc_hops_increment` re-stamping so the PoW, signatures and AEAD tags survive a forward. It bounds the damage a false hop count can do; it does not authenticate distance.
- **Routing helpers** — inspect type, hops, and recipient address without decrypting; increment hops while keeping the packet valid.
- **Versioned wire** — every packet's first element is the revision (`CC_WIRE_VERSION` 9), and a packet from any other revision is rejected with `CC_E_VERSION` after reading that one element, before any PoW, signature or decryption work.
- **Transport-agnostic** — packets are whole byte strings, and the shared road framing (`cc_road_t` + the fragmentation helpers) ships in the library; only the medium code lives with the consumer (see [`examples/cardputer`](examples/cardputer) for four ESP32 roads).
- **Reentrant** — the library keeps no mutable global state: every entry point that needs working memory takes a caller-owned `cc_work_t`, so one context per thread (or per concurrent caller) is enough, and two contexts never interfere.
- **Embedded-safe** — large structs (`cc_key_t` ~13 KB, `cc_work_t` ~34 KB, `cc_announce_t`, `cc_relay_t`) use static/global storage; nothing allocates.

## Message types

| Type | Value | Description |
|------|-------|-------------|
| `CC_MSG_ANNOUNCE` | 0 | Node identity broadcast (raw ML-DSA signature) |
| `CC_MSG_CHAT` | 1 | Opportunistic signed directed message (payload COSE_Encrypt0) |
| `CC_MSG_PRESENCE` | 2 | Unsigned liveness hint |
| `CC_MSG_KEY_REQ` | 3 | Ask a node to re-send its full announce |
| `CC_MSG_LINK_REQ` | 4 | Link handshake, initiator → responder |
| `CC_MSG_LINK_PROOF` | 5 | Link handshake, responder proves identity (raw ML-DSA signature) |
| `CC_MSG_LINK_DATA` | 6 | One link AES-256-GCM record |
| `CC_MSG_IDENTIFY` | 7 | Link identity record (same packet shape as `LINK_DATA`) |
| `CC_MSG_LINK_CLOSE` | 8 | Link teardown record (same packet shape as `LINK_DATA`) |
| `CC_MSG_ROTATE` | 9 | Move the identity to a new signing key, old key co-signs |
| `CC_MSG_REVOKE` | 10 | Retire this identity (terminal for the address) |
| `CC_MSG_GROUP_DATA` | 11 | Group post, broadcast (payload COSE_Encrypt0 under the group key) |

`CC_MSG_COUNT` is 12.

The three link record packet types share one shape, and the *authenticated*
record kind — not the packet type — decides what a record means, so a receiver
accepts a link record under any of `CC_MSG_LINK_DATA` (6), `CC_MSG_IDENTIFY`
(7) or `CC_MSG_LINK_CLOSE` (8) and lets the kind inside decide.

## Wire format

Every packet is one CBOR array whose first element is the wire revision,
`CC_WIRE_VERSION` (9). A packet from another revision is rejected with
`CC_E_VERSION` after reading that one element and before any PoW, signature or
decryption work; the arity check that follows is a second line of defence.

The envelope is canonical CBOR (RFC 8949 §4.2, deterministic encoding): a
definite-length array of unsigned integers, byte strings and text strings, each
with a minimal-length head, and exactly the array with no trailing bytes.
Anything else is `CC_E_FORMAT`, so a packet has exactly one valid byte string —
which is what makes it sound to take the PoW and the signature over the bytes on
the wire.

The normative element sequence for each type is the `CC_PKT_LAYOUT` table in
`src/cosechat.c`; this is a reader's guide to it.

```
announce [ver, type=0, hops, nonce, sign_pub, kem_pub, name, meta, admit, seq, expiry, sig]
chat     [ver, type=1, hops, sender, recipient, kem_ct, counter, nonce, encrypt0, sig]

presence [ver, type=2, hops, seq, nonce, addr, name_hash]
key_req  [ver, type=3, hops, addr, seq, nonce]

link_req   [ver, type=4, hops, nonce, suite, link_id, kem_ct]
link_proof [ver, type=5, hops, nonce, suite, link_id, sig]
link_data  [ver, type=6, hops, link_id, seq, encrypt0]
identify   [ver, type=7, hops, link_id, seq, encrypt0]
link_close [ver, type=8, hops, link_id, seq, encrypt0]

rotate   [ver, type=9, hops, nonce, new_sign_pub, new_kem_pub, name, meta,
          prev_addr, seq, expiry, new_sig, cont_sig]
revoke   [ver, type=10, hops, nonce, addr, seq, expiry, sig]

group_data [ver, type=11, hops, gid, poster, seq, nonce, encrypt0]

  link record plaintext: [kind, payload_bstr]
    kind = CC_LINK_KIND_DATA / CLOSE / KEEPALIVE / IDENTIFY / GROUP_KEY
```

- **announce** is self-signed: the packet carries the signing key whose
  signature it carries — a raw ML-DSA signature over the canonical byte string
  — and the address is `SHA-256(sign_pub)[0:16]`. `meta` is a CBOR map with
  namespaced text keys (a reader ignores keys it does not know; this library
  defines none yet). `seq`, `expiry` and `admit` are signed.
- **chat** is the opportunistic one-shot path: `kem_ct` carries the ML-KEM
  encapsulation, `encrypt0` the COSE Encrypt0 blob over the plaintext
  `[sender_addr, message]`, keyed with
  `HKDF-SHA-256(shared secret, info="cosechat")`.
- **presence** has no name on the wire, only `name_hash` — `SHA-256(name)` of
  the name in that address's announce, truncated to
  `CC_PRES_NAME_HASH_SZ` (8) bytes.
- **link_data**, **identify** and **link_close** share one shape — a raw
  AES-256-GCM record whose plaintext is `[kind, payload]`. The packet type is a
  routing hint; 6, 7 and 8 are all accepted for a link record, and the
  authenticated kind decides.
- **rotate** and **revoke** carry the identity lifecycle; see
  [rotation and revocation](#identity-rotation-and-revocation).

### Coverage — one rule

`hops` and the PoW `nonce` are the only elements outside the signature and the
AEAD AAD, and each is outside for a reason: `hops` must stay mutable so a relay
can re-stamp it (`cc_hops_increment`), and the nonce is what the PoW searches
over, so it cannot be fixed before mining. Everything else is covered. Link
data packets have no signature and no PoW at all: their coverage is the AEAD tag
over the whole record, with `hops` still outside it.

```
PoW       SHA-256(packet bytes with the hops and nonce elements removed ‖ nonce_le32)
            must have CC_POW_DIFFICULTY_<TYPE> leading zero bytes
            (announce, chat, presence, key_req, link_req, link_proof, rotate, revoke,
            group_data)
Signature announce, chat, rotate: over the packet bytes without the nonce trailer
            and without the signature elements themselves; link_proof signs the
            handshake transcript instead
AEAD AAD  chat and group_data: everything except hops, the nonce and the ciphertext
            (chat also excludes its signature element)
```

`hops` is the only mutable element: it is covered by nothing — not the PoW, not
the signature, not the AEAD — and must not be trusted for anything but
stale/loop suppression. The library imposes no hop limit; capping is consumer
policy. `cc_hops_increment` needs an output buffer one byte larger than the
input, since the CBOR hops uint can grow from 1 byte to 2 (hops 23→24), and its
input and output must not overlap.

### Admission pricing (`admit`)

Revision 9 splits the cost of a packet into two separate things:

- **Enforcement** is local and stays local. A receiver always checks against
  `CC_POW_DIFFICULTY_<TYPE>` from its own build, never against what the packet's
  sender declared, so no field in any packet can lower a receiver's own bar.
- **The declaration** is what a node asks senders to aim at. It is the 3-byte
  `admit` field of an announce — one byte per *directed* type, in the order
  chat, `link_req`, `key_req` — each 1..32, or `CC_POW_NONE` (0) for "no
  preference, use your own policy". It is inside the signed coverage, so a peer
  cannot have it altered in flight.

`cc_admit_default()` fills a declaration with this build's own per-type
requirements; `cc_admit_for(ann, type, &d)` returns the price a sender should
pay — `max(peer's declared cost, this build's own requirement)` — and refuses a
broadcast type with `CC_E_ARG` and an announce whose signature has not verified
with `CC_E_SIG` (the `verified` flag is set only by `cc_announce_parse()` /
`cc_rotate_parse()`, so verify first, then mine). `cc_chat_build()`,
`cc_key_req_build()` and `cc_link_start()` take a `difficulty` argument, where
`0` means this build's default and the value from `cc_admit_for()` pays the
peer's price instead. Broadcast types (announce, presence) declare nothing and
are mined at the sender's own difficulty.

The check itself lives in one place: `cc_pow_verify_at(pkt, sz, difficulty)`,
where `difficulty` 0 means this build's `CC_POW_DIFFICULTY_<TYPE>` for the
packet's type and 1..`CC_POW_MAX` an explicit bar — for instance the price a
peer published in its announce. `cc_pow_verify(pkt, sz)` is exactly
`cc_pow_verify_at(pkt, sz, 0)`. The relay calls the `_at` form to enforce a
destination's declared price instead of rebuilding the preimage itself, so the
rule cannot drift out of sync with the envelope.

What this buys is honest and bounded: it lets a node price admission to itself
and a sender pay the asked price. It does not turn PoW into a flood defence —
an attacker on a laptop mines orders of magnitude faster than a LoRa node can
transmit, and difficulty scales with the packet's own size, so the cheapest
attack is still a small packet. Treat the declaration as congestion pricing and
a speed bump, not a barrier.

### Announce lifecycle

An announce carries a signed monotonic `seq` and an absolute `expiry`;
`cc_announce_fresh(known, fresh, now)` is the whole rule — use the new announce
only if its `seq` is newer than the one held and `now` has not passed its
`expiry`, else `CC_E_STALE`. That is dedup, anti-replay, and the freshness
signal the relay needs.

### Identity rotation and revocation

The address is `SHA-256(sign_pub)[0:16]`, so a new signing key is a new address.
ROTATE (type 9) is how a node carries its identity across that change: it
carries the statement an announce makes (new keys, name, meta, `seq`, `expiry`)
plus two signatures —

- `cont_sig`, by the OLD key, over the domain-separated 32-byte statement
  `SHA-256("cosechat/v8 rotate" | suite | prev_addr | new_addr | new_sign_pub |
  new_kem_pub)`, which is what proves the new address is the same node; and
- `new_sig`, by the NEW key, over the covered envelope.

`prev_addr` is bound by the statement, and `new_addr` is derived from
`new_sign_pub`, so a key that does not hash to the address the old key vouched
for cannot be smuggled in, in either direction. `cc_rotate_prev_addr()` is the
cheap non-crypto peek a caller uses to find its cache entry;
`cc_rotate_parse()` verifies both signatures; `cc_rotate_accept()` is the one
acceptance rule — the rotation must continue the identity the caller holds, its
`seq` must be strictly newer than the cached announce's, it must not be expired,
and its predecessor must not be retired (`CC_E_REVOKED`).

REVOKE (type 10) retires an address: it is signed by the key that hashes to
`addr`, so only the identity can retire itself, and it is terminal for that
address for as long as the receiver remembers it. `expiry` is the caller's
horizon — after it, `cc_revoked_check()` reports the address as free again — and
`0` means terminal. `cc_revoked_t` is a 28-byte caller-owned record and the
library holds no directory, so the policy stays with the caller.

Three ordering rules are the app's to keep:

1. **Rotate first, then revoke.** A revocation terminates the identity chain:
   revoke-then-rotate is refused with `CC_E_REVOKED`, and a successor that
   inherited `prev_addr == the retired address` is dropped when the revocation
   lands. So rotate while the old key is still trustworthy and retire it
   afterwards, or revoke and continue as a *fresh identity* with no continuity
   claim at all. A revocation is a tombstone for the chain, not a step in a
   handover — do not revoke a key you intend to rotate away from.
2. **Only a peer you already hold.** Accept a rotation only for an address the
   caller has an entry for (`have != NULL`), or a successor with no entry behind
   it is trusted on the strength of a predecessor that was never verified.
3. **Drop on revocation.** When a revocation of X is recorded, drop every entry
   whose `addr` *or* `prev_addr` is X — an entry that arrived as a rotation from
   X before the revocation landed is otherwise still trusted, and `prev_addr` is
   what lets the caller find it.

When an identity rotates, its replay state has to move with it:
`cc_replay_move(st, new_addr, floor, continues)` takes an explicit
`CC_REPLAY_CONTINUES` (the successor kept counting, so the newest accepted
counter becomes a floor and the peer's last message cannot be replayed into the
new address) or `CC_REPLAY_RESTARTS` (fresh state; the window starts empty,
which knowingly accepts one replay opportunity — the successor's own first
message — as the honest cost of a restart). The old state's class is preserved
and the address is always updated.

The residual is stated plainly because no number of extra signatures fixes it:
continuity is proven by signatures, so a holder of the old private key can mint
a successor its peers will trust. A revocation terminates the chain, so it
contains that compromise for as long as a receiver remembers the retirement —
and only that long, because past the horizon in `expiry` the address is free
again.

### Presence is a hint

A presence asserts nothing. Its only trusted output is "an address I already
hold a signed announce for is still transmitting": check it with
`cc_presence_matches_announce()`, which compares both `addr` and `name_hash`
against a verified announce. A mismatch means ignore the hint, never "the peer
changed". An unknown address is first contact — send a `key_req` and wait for
the announce.

### Measured sizes

Default build (ML-DSA-65 + ML-KEM-768, difficulty 2, short names), from
`examples/announce.c`, `examples/chat.c` and a host build of
`cc_rotate_build()`/`cc_revoke_build()`/`cc_group_post_build()`; a LoRa fragment
carries 248 bytes, a BLE advertisement 243. The mined nonce is a
minimally-encoded uint, so a packet can shift by a byte or two between runs.

| Packet | Bytes | LoRa fragments |
|--------|-------|----------------|
| rotate | 9799 | 40 |
| announce | 6470 | 27 |
| chat (opportunistic) | 4515 | 19 |
| identify | 3363 | 14 |
| revoke | 3338 | 14 |
| link_proof | 3331 | 14 |
| link_req | 1108 | 5 |
| group post (max message) | 589 | 3 |
| group post (tiny message) | 76 | 1 |
| group key record (link) | 80 | 1 |
| link_data | 45 | 1 |
| presence | 34 | 1 |
| key_req | 25 | 1 |

A group post carries no per-post signature, so it costs a fragment or three
where the opportunistic chat of the same message size costs nineteen, and the
key-distribution record is one link record of 80 bytes. One link handshake is 19
fragments once (link_req + link_proof), and then every message is a
1-fragment link_data record; the opportunistic chat is 19 fragments for every
message. Linking therefore pays for itself at the second message — after the
first, one handshake plus *n* one-fragment messages beats *n* signed messages.

## Links (sessions)

A link is bidirectional and forward-secret. `cc_link_start()` encapsulates to
the responder's announced ML-KEM key and emits a `link_req`; `cc_link_accept()`
decapsulates it and answers with a `link_proof` signed by the responder's
ML-DSA key; `cc_link_confirm()` verifies that proof against the peer's announced
key, and the initiator's keys stay unusable until it does. `link_req` is
unsigned, so the initiator may stay anonymous; the responder proves identity,
and either side may follow up with an optional IDENTIFY record
(`cc_link_identify` / `cc_identify_verify`).

The key schedule is RFC 9180 §5.1 in shape (`mode_base`, no PSK): labelled
`Extract`/`Expand` over `suite_id = "cosechat-v7" ‖ suite_byte`, with the ML-KEM
shared secret as `dh` and the KEM ciphertext as `kem_context`, deriving
`key_i2r`/`salt_i2r` and `key_r2i`/`salt_r2i`. The base mode yields a single
key, so the per-direction outputs are the labelled `DeriveSecret` extension.
The per-message AEAD nonce is `direction(1) ‖ salt(3) ‖ sequence(8, little
endian)`: the sequence is the replay defence and the key is the
authentication, which is why a link record needs no signature and no PoW.

`link_data` carries `link_id` alone (plus `hops`), so an observer sees neither
sender nor recipient; only setup names the responder, and an anonymous initiator
stays anonymous until it sends an identify record.

The handshake carries an explicit suite byte (`cc_suite()`, `CC_SUITE`) rather
than a KEM codepoint, because no ML-KEM KEM ID is registered in HPKE — the
ML-KEM HPKE draft expired and `draft-ietf-jose-pqc-kem` still has TBD values —
so the byte is provisional; a handshake whose suite byte differs is
`CC_E_SUITE`.

`cc_link_t` is 168 bytes, caller-owned and heap-free (8 concurrent links
≈ 1.3 KiB, 16 ≈ 2.6 KiB, 64 ≈ 10.5 KiB — small against the ~13 KB of one
`cc_key_t`). `cc_link_recv()` answers `CC_E_NOLINK` for an unknown, closed or
idle-expired link so the peer re-handshakes, and `CC_E_REPLAY` / `CC_E_STALE`
from the sequence window.

## Group messaging

A group is a set of members who share one 32-byte secret. There is no membership
protocol on the wire, no epochs and no sender keys: the secret **is** the group,
and its `gid` is `SHA-256("cosechat/group gid" | secret)[0:8]`. One key per
group is derived from the secret with the same labelled `Extract`/`Expand` shape
the link uses but labels of its own (`"cosechat/group prk"`, then
`"cosechat/group key"`), so a group key can never be confused with a link key.

A post (`CC_MSG_GROUP_DATA`, type 11) is a broadcast: `gid`, the poster label,
the sequence and a COSE_Encrypt0 (RFC 9052 §5.2) blob sealed under the group key
with a random per-post IV. The AEAD tag and the PoW both cover `gid`, `poster`
and `seq`, so those are the values the producer actually sealed. There is no
per-post signature. Replay is per `(gid, poster)`: `cc_group_post_parse()`
peeks that label's window before the AEAD and commits it only once the tag
verifies, so a post that fails the tag cannot move anyone's window (a
`cc_group_win_t` carries the `gid` and the poster with the `cc_replay_t`, so a
caller cannot key a window by address alone and blend two groups into one
sequence space).

### What a post proves

Bluntly: a post that decrypts proves that **someone holding the group key**
produced it, and that `gid`, `poster` and `seq` are the values its producer
sealed. It does **not** prove which member sent it. The `poster` field is a
self-claimed, non-binding label: every member holds the same key and can seal
any other member's label, and because the window is per label, a member can
silence another member's label by minting a high sequence under it. No policy
may depend on the poster label — it exists only so members can partition their
own sequence spaces and a receiver can keep one window per label. Attribution
would need a per-post ML-DSA signature over the routing fields (the chat
pattern, ~+3.3 KB per post, about 14 fragments) and is deliberately not
implemented.

### Membership and removal

Membership is "who knows the secret". There is no cryptographic removal:
someone who has left still knows the old secret, so everything derived from it
remains theirs to derive. The way to remove a member is to **create a new
group** — a new secret, hence a new and unlinkable `gid` — and provision the
remaining members. And a group has no forward secrecy *within* itself: whoever
holds the secret can read every post for as long as the group exists, and a
compromised member reads and can forge posts. Replacing the group is the only
remedy, which is also why the address never moves for a membership change (the
`gid` follows the secret, not the roster).

### Provisioning

The secret is exported and imported as 32 raw bytes
(`cc_group_secret_export()` / `cc_group_join()`), and provisioning is out of
band by design: the operator types it in, scans it, or the app arranges
something else — that is the path that works when members are not adjacent.
Sending it over an existing authenticated link is offered as a convenience
(`cc_group_secret_send()` / `cc_group_secret_recv()`, one link record of kind
`CC_LINK_KIND_GROUP_KEY`), but a link is not required. There is no
unauthenticated distribution path: whoever receives the secret is the group.
The library holds no group directory — `cc_group_t` is 41 bytes of caller-owned
state (the secret, wiped by `cc_group_free()`, plus the derived `gid`) — so the
app persists the exported secret wherever it keeps key material, and whoever can
read that store is a member.

### Wire revision

The library version is 0.10.0 but the wire revision stays **9**: a new type
changes no existing shape, and bumping the revision would make every older node
reject *every* packet — announces, chats and links included — on a partially
upgraded mesh, which is a far worse failure than the one it would fix. The
consequence is honest and unavoidable: a revision-9 receiver that predates
groups drops a post as an unknown type (`CC_E_FORMAT`), and a revision-9 relay
will not forward group traffic, so a group message only crosses a path where
every hop understands it. A relay that does carry the type forwards posts
through its own entry point (`cc_relay_group()`) with a group airtime pool, a
per-`gid` budget and its own hop cap — see [Relay (multi-hop)](#relay-multi-hop).

## Relay (multi-hop)

`include/cosechat_relay.h` is the piece that makes a mesh: the app receives a
whole packet from a road, hands it to the relay, and sends whatever comes back
with `CC_RELAY_FWD`. It is bounded, heap-free and caller-owned (`cc_relay_t`,
`cc_relay_bytes()`) with no keys, no allocation, no globals and no threads —
**one `cc_relay_t` per thread or concurrent caller**, reentrant like the rest of
the library.

- **Path learning is announce-only.** `cc_relay_announce()` takes an announce
  that has been through `cc_announce_parse()` (so its address comes from a
  signature that verified). A data packet's sender field cannot be verified by
  a node that cannot decrypt it, so data traffic consumes the table and never
  writes to it — no reverse-path learning, and unsigned data can never poison
  the table.
- **Attribution, and where it is absent.** `from` is the *link-layer* source
  the packet arrived from — never the address the announcement names, which
  would make the origin check vacuous. The road layer publishes it:
  `cc_road_t.last_src` / `last_src_len` name the sender of the packet `recv()`
  last delivered (`cc_road_src_take()` copies them out with the packet), and
  an unattributable medium reports length 0 rather than a stale value.
  `road_80211` fills in the frame's transmitter MAC, `road_wifi` the datagram's
  source address and port; `road_ble` (anonymous by design) and `road_lora` (no
  source field) always report 0.
- **Route rules.** Route age is decided by the announcement's signed `seq`,
  never by the hop count, which nothing covers. An announcement the relay has
  already seen cannot move or resurrect a route (`CC_RELAY_E_NOIMPROVE`,
  whatever hop count it claims and whoever relays it), so a replay with a
  rewritten `hops` is a no-op — that is what closes the hijack, and it closes
  it without making a live route sticky. A strictly newer `seq` may move the
  route to any attributed neighbour, so it is never stuck on one that went
  away; an announcement at `hops == 0` arriving from the address it announces
  is the origin speaking for itself, always wins whatever the table held, and
  is how an owner reclaims a route after anything else took it; an
  equal-sequence announcement from the neighbour the route points at refreshes
  liveness without a forward.
- **Forwarding.** Data is forwarded by `cc_msg_recipient()` lookup and
  re-stamped with `cc_hops_increment()`, which rewrites only the hops byte — so
  the PoW, signature and AEAD tag survive. Nothing re-signs, re-mines or
  re-encrypts anything.
- **Duplicate cache.** A re-broadcast within `CC_RELAY_DUP_TTL` is
  `CC_RELAY_E_DUP`, whatever its hop count: the digest is the first 16 bytes of
  SHA-256 over the packet with the hops element *removed*, so a re-stamped copy
  is recognised for what it is. The TTL is long on purpose (half
  `CC_RELAY_PATH_TTL`), because a repeat can only be a replay — chats and
  announces both carry an authenticated freshness value their sender never
  repeats byte-for-byte — so a short TTL would let one captured packet be
  re-injected once per TTL at every relay it passes. The trade is cache
  pressure: the cache evicts its oldest digest when full, so under heavy
  traffic the effective window is shorter than the TTL — size `CC_RELAY_DUP` to
  the packet rate you want to cover.
- **Budgets: three airtime pools, a per-destination data budget and a per-group
  post budget.** All are per `CC_RELAY_WINDOW` ticks (60 by default), all refuse
  with `CC_RELAY_E_BUDGET`, and all recover on the next window.
  `CC_RELAY_AIRTIME_ANNOUNCE` (16384 B), `CC_RELAY_AIRTIME_DATA` (16384 B) and
  `CC_RELAY_AIRTIME_GROUP` (8192 B) are separate pools because one pool makes
  bulk traffic starve the traffic a relay exists for: an announce is ~6.5 KB, so
  a single channel-sized pool would admit an announce *or* some data, and one
  announce from anyone would black out relayed data mesh-wide for the window.
  `CC_RELAY_FWD_BUDGET` is 3 *data* packets per destination per window —
  fairness, so one destination cannot take the data pool, and enough for two
  messages out and one back through this relay in a minute; the byte pool is
  the real bound (three ~4.5 KB chats are well under it). `CC_RELAY_GROUP_BUDGET`
  is 2 posts per `gid` per window, the broadcast analogue: a post is one packet
  that serves the whole group, so two is generous for a feed. Per-destination
  counters live in their own table keyed by address and per-group counters in
  one keyed by `gid`, so losing a route to table pressure does not hand that
  destination or group a fresh budget.
- **Group posts have their own forwarding path.** A post has no recipient, so
  `cc_relay_forward()` stays closed to it and `cc_relay_group()` is its own
  entry point with its own limits: its own hop cap
  (`CC_RELAY_MAX_HOPS_GROUP`, defaulting to `CC_RELAY_MAX_HOPS`, so broadcast
  reach can be raised without loosening what a conversation costs), the group
  airtime pool, and the per-`gid` budget. The keyless PoW gate runs first here
  too, but a broadcast has no destination to declare a price, so a post is
  charged this build's `CC_POW_DIFFICULTY_GROUP` rather than a peer's `admit`
  byte. `cc_relay_gid_get()` reports what a group has spent.
- **Every relay re-prices.** The price a sender effectively pays is the
  strictest relay on its path, not its own: each relay checks the packet
  against the destination's declared price or its own floor, and nothing carries
  a receipt for work already done.
- **Sizing.** The three pools model one SF7 / 125 kHz LoRa channel: 16384 B is
  ~2.5 announces, 16384 B ~3.6 chats and 8192 B ~10 group posts per window,
  ~683 B/s together — inside that channel's payload rate (preamble and framing
  included) and leaving the rest of the channel to the node's own traffic. A
  WiFi or Ethernet road raises all three pools, `CC_RELAY_FWD_BUDGET`,
  `CC_RELAY_GROUP_BUDGET`, `CC_RELAY_BUDGETS` and `CC_RELAY_GIDS` together.
- **Keyless PoW gate first.** With `CC_RELAY_REQUIRE_POW` (the default) a chat
  must pay the price the destination's own announcement declares (its signed
  `admit` byte for chat), with this build's `CC_POW_DIFFICULTY_CHAT` as a
  floor, and a group post must pay this build's `CC_POW_DIFFICULTY_GROUP` —
  both checked with `cc_pow_verify_at()` before a cache slot or any budget is
  spent (`CC_RELAY_E_POW`). The check needs no keys, and without it hand-crafted
  unmined envelopes would burn a destination's window for free.
- **Default state.** `CC_RELAY_PATHS` 64 → 3 KiB (48 B each), `CC_RELAY_DUP`
  32 → 640 B (20 B each), `CC_RELAY_BUDGETS` 16 → 384 B (24 B each),
  `CC_RELAY_GIDS` 16 → 256 B (16 B each), plus the window, the three pool
  counters and the stats: `cc_relay_t` is 4460 bytes at the defaults, and every
  byte follows from those compile-time knobs. A consumer that lowers the
  capacities gets a smaller struct — the reference firmware's relay env sets
  `CC_RELAY_PATHS=16`, `CC_RELAY_DUP=16` and `CC_RELAY_BUDGETS=8`, which is
  1644 bytes. `CC_RELAY_MAX_HOPS` is 8 (and `CC_RELAY_MAX_HOPS_GROUP` defaults
  to it), `CC_RELAY_PATH_TTL` 600 ticks, `CC_RELAY_DUP_TTL` 300 ticks.
- **Refusals are countable and inert.** Every drop has its own `CC_RELAY_E_*`
  code and its own counter in `cc_relay_stats_t`; a refusal never modifies the
  packet, the table or the cache, and sets `*out_len` to 0 so a stale buffer
  cannot be forwarded by accident.

The honest limits: this is a learned, best-effort next-hop table, **not a
routing protocol** — no metrics, no advertisements of its own, no cost, no
per-destination queues and no retransmission. Since `hops` is unauthenticated, a
node that re-stamps an announcement the relay has never seen before can still
advertise a shorter path than it has; the sequence rules bound what that buys an
attacker, and closing it entirely would need authenticated distance, i.e. a
different protocol. On a medium that cannot attribute senders (anonymous BLE
advertising, plain LoRa broadcast) the origin rule is simply unavailable: every
announcement there must be treated as relayed, the sequence rules are what
protect the table (a replay cannot move or resurrect a route, and the owner
reclaims by announcing a newer sequence), and route reclaim comes from those
rules rather than from the hops-0 shortcut.

The reference firmware takes exactly that position: it passes "unknown" for
every packet instead of resolving `last_src` to a cosechat address, because the
only mapping available would rest on the hops claim the check is testing, and it
never substitutes an address the packet itself claims. That is a documented
policy, not an oversight: on the shipped firmware the origin shortcut is inert,
and the sequence rules carry the table.

And link traffic is **not routed**: `link_req` carries no destination to route
on, and a link record's `link_id` only means anything to two nodes whose
handshake already completed, so an app that wants a conversation across a mesh
uses chat (or runs its own multi-hop link rendezvous).

The relay is opt-in: nothing forwards unless the app calls it. The reference
firmware wires it behind `CC_RELAY` (the `lora-relay` PlatformIO env), and the
default envs do not compile it. It is host-tested by
[`test/test_relay.c`](test/test_relay.c) and built as its own CMake target
(`cosechat_relay`).

## Standards

The protocol labels its algorithms with COSE identifiers and uses one COSE
structure; the envelope itself is this protocol's own over deterministic CBOR.

- **Algorithm identifiers (COSE)** — ML-DSA-65 is `-49`
  (`draft-ietf-cose-dilithium-11`, in AUTH48 as RFC 9964), AES-256-GCM is `3`
  and HKDF-SHA-256 is `5` (RFC 9053).
- **COSE_Encrypt0** — the opportunistic chat's payload and a group post are
  COSE_Encrypt0 structures (RFC 9052 §5.2), whose AEAD `external_aad` binds the
  envelope fields around them (for a post, `gid`, `poster` and `seq`). They are
  the only COSE structures on the wire.
- **Everything else is raw and this protocol's own** — the announce, chat,
  rotate and link_proof signatures are plain ML-DSA signatures over the
  canonical byte string, link records are plain AES-256-GCM records, and there
  is no COSE_Sign1 anywhere.
- **Canonical CBOR** — RFC 8949 §4.2.
- **Link and group key schedules** — RFC 9180 §5.1 in shape, adapted with an
  explicit suite byte in place of the unregistered ML-KEM KEM ID; the group
  schedule uses the same labelled construction with `"cosechat/group ..."`
  labels of its own.
- **Not covered by any standard** — the envelope shape, `hops`, the PoW
  mechanism, admission pricing, the replay window, the continuity statement, the
  group `gid` and its shared-secret membership model, and the road framing are
  this protocol's own.

## Dependencies

- [wolfSSL](https://www.wolfssl.com/) ≥ 5.8.0 — ML-DSA, ML-KEM, AES-GCM, HKDF, SHA-256, SHA-3
- [wolfCOSE](https://github.com/konsumer/wolfCOSE) — COSE_Encrypt0 and CBOR (this repo pins the `konsumer/wolfCOSE` fork at `124ee3c`)

Only these two are required; the library itself has no platform dependency.

## Build (desktop)

```sh
make configure
make build
make test
```

## PlatformIO

Add to `platformio.ini`:

```ini
lib_deps =
  wolfssl
  https://github.com/konsumer/wolfCOSE.git#124ee3c
  https://github.com/cosechat/cosechat-c
```

Required wolfSSL build flags (kept in sync with `library.json`):

```
-DHAVE_DILITHIUM -DWOLFSSL_WC_DILITHIUM
-DWOLFSSL_HAVE_MLKEM -DWOLFSSL_WC_MLKEM
-DHAVE_AESGCM -DHAVE_HKDF -DWOLFSSL_SHA256 -DWOLFSSL_SHA3
-DHAVE_SHAKE256 -DWOLFSSL_KEY_GEN
```

Targets: any platform with wolfSSL + wolfCOSE (desktop, WASI, ESP32, other
MCUs). The library has no framework or platform manifest restriction; the
reference transports under [`examples/cardputer`](examples/cardputer) are
ESP32-only.

**wolfSSL ≥ 5.8 is required** (`wolfssl/wolfcrypt/wc_mlkem.h` landed in 5.8).
The PlatformIO registry package tops out at 5.7.2, so a registry-only
`lib_deps = wolfssl` cannot provide ML-KEM — point at a wolfSSL ≥ 5.8 source
(see [`examples/cardputer/fetch-wolfssl.sh`](examples/cardputer/fetch-wolfssl.sh)).

## Transports (roads)

The library turns application data into whole packet byte strings and back. A
*road* is the consumer's transport: it implements the medium (radio setup,
sockets, tasks, queues) and nothing else. `cc_road_t` and the shared framing
ship with the library ([`include/cosechat_road.h`](include/cosechat_road.h)),
so the application only ever sees complete packets:

```c
extern cc_road_t* road;

road->send(road, pkt, len);

uint8_t buf[CC_ROAD_PKT_BUF_SZ];
size_t len;
while (road->recv(road, buf, sizeof(buf), &len) == CC_ROAD_OK) {
  /* cc_msg_type() / cc_announce_parse() / cc_chat_parse() / cc_link_recv() ... */
}
```

[`examples/cardputer`](examples/cardputer) is the reference implementation of
the medium side — four roads, each supplying an `emit` callback
(`cc_road_emit_fn`) that `cc_road_send_pkt()` drives fragment by fragment, an RX
callback that feeds fragments to `cc_road_rx_frag()`, a non-blocking `recv()`
that copies a completed packet out with `cc_road_pkt_get()`, and
init/shutdown/defaults:

| Road | Medium |
|------|--------|
| `road_lora` | SX1262 LoRa via [RadioLib](https://github.com/jgromes/RadioLib) |
| `road_wifi` | WiFi + UDP (ESP32 Arduino) |
| `road_ble` | Anonymous BLE 5 extended advertising via [NimBLE-Arduino](https://github.com/h2zero/NimBLE-Arduino) |
| `road_80211` | Unauthenticated 802.11 management frames (ESP32) |

All four share one framing: a fragment is `[magic=0xCC, msg_id, frag_idx,
frag_total, payload]`. Only the final fragment may be short; a repeated
fragment is idempotent and a repeat that conflicts with bytes already received
is rejected; an encode that cannot fit the packet in `frag_total` fragments is
refused rather than truncated. The payload size is not transmitted, so both
ends must agree on it: `CC_ROAD_FRAG_PAYLOAD` is 248, the largest any road uses
(the SX1262's 252-byte packet limit minus the 4-byte header), and a road with a
smaller MTU passes its own value — `road_ble` uses 243 bytes so each fragment
fits one extended advertisement. One `cc_road_frag_t` reassembles one stream
from one transmitter, because `msg_id` is an unauthenticated 8-bit sender
value; a receiver expecting several transmitters at once keeps one reassembly
state per source. Each implementation is gated by `__has_include`, so it is a
no-op empty translation unit wherever its radio stack is absent.

A road also publishes who sent the packet it just delivered: `cc_road_t`
carries `last_src` / `last_src_len`, and `cc_road_src_take()` copies the
slot's link-layer source into them alongside the packet. That source is
link-layer identity only — a MAC, a UDP peer, a per-link identity the app
verified out of band — 6 bytes (`CC_ROAD_SRC_SZ`, the width of an IEEE MAC
address), and it is never a cosechat address. The invariant is that a medium
which cannot attribute the sender reports length 0 rather than a stale value,
and a caller must read length 0 as "sender unknown": `road_80211` fills in the
frame's transmitter MAC, `road_wifi` the datagram's source address and port,
and `road_ble` (anonymous by design) and `road_lora` (no source field) always
report 0. The relay's origin rule is the consumer of this — and on BLE and
LoRa, where it is unavailable, every announce must be treated as relayed.

A new transport does not have to live here: a desktop, WASI or MCU client links
the library's framing (exercised on the host by
[`test/test_road.c`](test/test_road.c)) and implements only its own medium code,
over TCP, WebSocket, serial, files, whatever — the protocol does not care.

### Opportunistic roads

`road_ble` and `road_80211` piggyback on radios a device already has, without
joining anything:

- **`road_ble`** carries each fragment as manufacturer-specific data in a
  non-connectable, non-scannable, *anonymous* BLE 5 extended advertisement (no
  advertiser address, no scan response, no connection). RX is a continuous
  passive scan. One advertisement holds 251 bytes of data, minus the AD header,
  company id and road header — 243 payload bytes, so a full announce (name and
  metadata at their limits) is 27 advertisements. `send()` blocks while each
  fragment advertises (`cfg.adv_ms`); the NimBLE host task does RX.
- **`road_80211`** carries each fragment in a vendor-specific action frame
  (category 127) sent to the broadcast MAC — a plain management frame that
  needs no association, authentication or ACK. The source address is a random
  locally-administered MAC. RX is promiscuous-mode capture, so both ends must
  sit on the same channel (`cfg.channel`). The promiscuous callback runs in the
  WiFi task and reassembles there.

Both are lossy and unacknowledged, like any broadcast medium: announces (27
fragments), rotations (40) and the opportunistic chat (19) are the expensive
cases, while presence, `key_req` and an ordinary link data record fit in one
fragment.

```c
static cc_road_lora_t lora;          /* ~16 KB — static/global */
cc_road_lora_cfg_t cfg;
cc_road_lora_defaults(&cfg);         /* CardputerADV + LoRa Cap 1262 */
cfg.spi_mux = bus_mutex;             /* SD card shares the SPI bus */
cfg.antenna = antenna_switch;        /* cap RF switch, if any */
cc_road_lora_init(&lora, &cfg);
cc_road_t* road = &lora.road;

static cc_road_wifi_t wifi;
cc_road_wifi_cfg_t wifi_cfg;
cc_road_wifi_defaults(&wifi_cfg);    /* port 4242, broadcast */
wifi_cfg.ssid = "my-ssid";
wifi_cfg.pass = "my-pass";
cc_road_wifi_init(&wifi, &wifi_cfg);

static cc_road_ble_t ble;
cc_road_ble_cfg_t ble_cfg;
cc_road_ble_defaults(&ble_cfg);      /* 0 dBm, 20 ms interval, 120 ms/frag */
cc_road_ble_init(&ble, &ble_cfg);

static cc_road_80211_t raw;
cc_road_80211_cfg_t raw_cfg;
cc_road_80211_defaults(&raw_cfg);    /* channel 1 */
cc_road_80211_init(&raw, &raw_cfg);
```

`road_lora` runs its own FreeRTOS task (RX except during TX); `road_wifi` has
no task and drains the socket inside `recv()`; `road_ble` and `road_80211`
reassemble inside the NimBLE / WiFi task and hand `recv()` a completed packet.

## Embedded notes

`cc_key_t` is 13112 bytes (~13 KB) at the category-3 defaults, `cc_work_t` is
34792 bytes (~34 KB) and `cc_announce_t` is 3520 bytes. Declare those **static
or global** on MCUs — never as stack locals. `cc_relay_t` (4460 bytes at the
default capacities) is the same kind of object, while `cc_link_t` (168 bytes),
`cc_replay_t` (32 bytes) and `cc_revoked_t` (28 bytes) are small enough to live
wherever the app keeps its peer table. Group state is small too: `cc_group_t` is
41 bytes (the secret and the `gid` derived from it), `cc_group_win_t` 56 bytes
per poster label (`gid` + poster + the 32-byte replay window) and a decrypted
post 552 bytes, so an 8-member group costs 41 + 7 × 56 = 433 bytes plus one
window per label the app chooses to police. A rotation costs no new per-peer
state:
the predecessor address a rotation must be checked against is the 16-byte
`prev_addr` field of the announce the caller already caches (so one cached peer
is 3580 bytes with its replay and revocation records).

The library is **reentrant**: every entry point that needs working memory takes
a caller-owned `cc_work_t` and holds no mutable global state, so give each
thread (or each concurrent caller) its own context and the calls do not
interfere. One context can also be reused from several call sites of one thread,
one call at a time. Call `cc_work_free()` at teardown or after a key change.
Everything is heap-free.

The reference firmware (`examples/cardputer`, ESP32-S3, 327680 B RAM and
3342336 B of flash partition) builds with this footprint — `lora-relay` is the
`lora` road with `CC_RELAY` on, and **wifi is the tightest of the five**:

| Env | RAM | Flash |
|-----|-----|-------|
| `lora` | 221696 B (67.7%) | 668565 B (20.0%) |
| `lora-relay` | 230624 B (70.4%) | 675129 B (20.2%) |
| `ble` | 232544 B (71.0%) | 865089 B (25.9%) |
| `dot11` | 245596 B (74.9%) | 1017349 B (30.4%) |
| `wifi` | 247592 B (75.6%) | 1057881 B (31.7%) |

## Storage posture

A reference node keeps its whole durable state in the clear on a removable SD
card under `/cc/` — see [`examples/cardputer`](examples/cardputer) for the
firmware's own account of the files, the fail-safes and the console commands:

- **`/cc/key.bin` is the identity**, and it is stored as seeds: a form byte,
  the two 64-byte seeds and `sign_pub` (the form the firmware writes), so
  reading the card makes you that node to every peer. **`/cc/group.bin` is a
  membership**: the group secret sits beside the identity, so a card reader is
  also a group member, able to read and mint posts.
- **Rollback is possible and is not detected.** `counter.bin`,
  `peers/<hex>.rp` and `revoked.bin` are trusted as read, so a *valid older*
  copy passes the envelope: a reused counter or `seq` makes peers drop this
  node's traffic as a replay or a stale announce until it passes their
  high-water marks, an older `.rp` lets one captured packet replay once, and an
  older revocation file re-trusts a retired identity on this node. Two of the
  files matter more than those three: an older `key.bin` reinstates an identity
  the node has rotated (or revoked) away from — peers that recorded the rotation
  or the revocation refuse it, so the node is mute until it rotates again — and
  an older `group.bin` re-joins a group that may have been superseded, which
  under "removal is a new group" can pull the node back into a conversation it
  believed it had left, including one containing a member removed from the newer
  group.
- **Every file carries a 9-byte envelope** — `"CCFS"`, a version and a CRC32 of
  the payload. The CRC **detects damage rather than authenticating**: anyone who
  can write the card can recompute it. What it buys is that a truncated or
  half-written file is *invalid* rather than quietly misread; a cached peer file
  whose payload version is unknown is treated the same way, and the peer simply
  re-announces.
- **A damaged identity — or no card — fails closed.** A `/cc/key.bin` that is
  present but invalid (wrong size, unreadable, an unknown form byte, a failing
  CRC, or a seed that does not produce the stored `sign_pub`) puts the node into
  a no-identity state — it announces nothing, sends nothing, answers nothing and
  drops every packet — instead of minting a new identity behind the operator's
  back, and a boot with **no card at all** takes the same state rather than
  assuming a fresh card. The way out is deliberate: `n` (then `y`) re-keys into
  a new identity at a new address (or runs cardless, with the key in RAM only),
  and `w` (then **`Y`**) wipes the card for hand-over, re-checking by existence
  and reporting `WIPE INCOMPLETE: still present: …` rather than claiming
  success. Both prompts are cancelled by any other key or by a five-second
  timeout. Neither is undoable from the node.

**Seed form.** The canonical FIPS 204 / FIPS 203 form of these keys is a seed
they are re-derived from at load, not the expanded key material:
`cc_key_export_seed()` / `cc_key_import_seed()` take 64-byte seeds
(`CC_SIGN_SEED_SZ`, `CC_KEM_SEED_SZ`, level-independent at the ML-DSA and ML-KEM
levels this builds speak). `cc_key_t` keeps the seeds beside the expanded keys
with a `has_seed` flag whose invariant the library states: it is 1 exactly when
the stored seeds reproduce the stored keys. `cc_key_generate()` and
`cc_key_import_seed()` set it, `cc_key_import()` (the expanded form) leaves it
0 because that key's seed is unknowable — and then `cc_key_export_seed()`
answers `CC_E_NOKEY` rather than inventing one. Neither wolfSSL nor this library
can recover a seed from an expanded key.

The firmware stores the identity in one of two forms, chosen by a leading form
byte in the payload:

| Form | Payload | File |
|------|---------|------|
| `1` seed (what this build writes) | `form` 1 + `sign_seed` 64 + `kem_seed` 64 + `sign_pub` 1952 = 2081 B | 2090 B |
| `2` expanded (the fallback) | `form` 1 + `sign_priv` 4032 + `sign_pub` 1952 + `kem_priv` 2400 = 8385 B | 8394 B |

Form 1 stores no private key at all: both are rebuilt from the seeds by
`cc_key_import_seed()`. It keeps `sign_pub` because that is the one field that
can be cross-checked cheaply — the seed must reproduce it or the file is
invalid — and because it is the preimage of the address every peer pins;
dropping it would leave a ~129 B payload and give up the only cheap check. Form
2 is written only when the identity has no seed to save
(`cc_key_export_seed()` answering `CC_E_NOKEY`, i.e. a key imported in expanded
form): that is not corruption, so the node saves the expanded form, logs it and
carries on, and the next identity it generates is compact again.

**The honest limits.** No flash encryption, no secure boot and no passphrase are
implemented; those are deployment and hardware decisions. Until one of them is
in place, physical possession of the card is the security boundary, and the
files are crash-proof, not tamper-proof.

## Examples & tests

- [`examples/keygen.c`](examples/keygen.c) — generate keys, export public/private halves, re-import
- [`examples/announce.c`](examples/announce.c) — build and parse an announce (and read back the PoW cost it declares), presence, and key_req
- [`examples/chat.c`](examples/chat.c) — Alice→Bob end to end: presence → key_req → announce → `cc_admit_for()` price → opportunistic chat (with a replay and a forged-sender rejection), then the link path (handshake, data both ways, identify, close)
- [`examples/cardputer`](examples/cardputer) — node firmware for CardputerADV (LoRa cap, WiFi/UDP, anonymous BLE, or raw 802.11), plus a `lora-relay` env that compiles the relay behind `CC_RELAY`
- [`test/test_cosechat.c`](test/test_cosechat.c) — protocol test suite (canonical form, field size contracts, coverage, replay classes, announce/presence lifecycles, link handshake and sequence window, rotation and revocation, group posts and their windows)
- [`test/test_road.c`](test/test_road.c) — road framing (fragmentation/reassembly) tests
- [`test/test_relay.c`](test/test_relay.c) — relay path learning, forwarding, hijack attempts, budgets, table pressure and a two-hop chain

## Known limitations

What this revision of the code does and does not defend:

- **`hops` is unauthenticated, and the relay's reach depends on it** — it sits
  outside the PoW, the signature and the AEAD tag by design, so anyone on the
  path can rewrite it. The relay bounds the damage (route age is decided by the
  signed `seq`, so a replayed announcement cannot move or resurrect a route;
  the duplicate digest ignores hops; a hops-0 claim is refused unless it arrived
  from the address it announces), but a node that re-stamps an announcement the
  relay has never seen before can still advertise a shorter path than it has.
  Treat the hop count as a claim, never as evidence beyond stale/loop
  suppression.
- **Source attribution is per-medium, and absent where the medium is anonymous**
  — the relay's origin rule needs the link-layer source a road can only supply
  on an attributing medium (`road_80211`'s transmitter MAC, `road_wifi`'s
  datagram source; never on `road_ble` or `road_lora`, which report length 0).
  On those media every announce must be treated as relayed and the sequence
  rules are what protect the table. The reference firmware goes further and
  passes "unknown" on *every* road, because the only mapping from `last_src` to
  a cosechat address would rest on the hops claim the check is testing — so on
  the shipped firmware the origin shortcut is inert by policy, and route
  reclaim comes from the sequence rules.
- **The relay is a best-effort learning table, not a routing protocol** — no
  metrics, no advertisements of its own, no queues and no retransmission. It is
  opt-in: the app drives it, nothing forwards on its own, and link records are
  not routed at all.
- **PoW cannot price a small packet or a replay** — difficulty scales with the
  packet's own size and a captured packet needs no mining at all, so the cheap
  attacks stay cheap. The `admit` declaration prices admission but is a speed
  bump, not a barrier; the relay's budgets and the app's rate limits are what
  actually bound a flood.
- **A group post proves a key holder, not which member sent it** — the `poster`
  field is self-claimed and non-binding: every member holds the same key and can
  seal any other member's label, and because the sequence window is per label, a
  member can silence another member's label by minting a high sequence under it.
  Per-post signatures (the chat pattern, ~+3.3 KB or about 14 fragments) are
  deliberately not implemented, so no policy may depend on the poster label.
- **Membership is the secret, with no removal and no forward secrecy inside the
  group** — there is no cryptographic removal: someone who has left still knows
  the old secret, so the way to remove a member is to create a new group (new
  secret, new unlinkable `gid`) and provision the remaining members. Whoever
  holds the secret reads every post for as long as the group exists, a
  compromised member reads and can forge posts, and whoever can read the store
  the app keeps the exported secret in is a member.
- **Older nodes and relays drop group traffic** — a revision-9 receiver that
  predates the type answers `CC_E_FORMAT` (unknown type) and a revision-9 relay
  will not forward it, so a group post only crosses a path where every hop
  understands it.
- **Presence and `key_req` are unauthenticated** — a presence is a hint, not a
  claim: it carries `addr` and `name_hash` and nothing signed, and its only
  trusted output is that an address we already hold a verified announce for is
  still transmitting. A `key_req`'s target is unverified too.
- **The opportunistic chat still names both parties on the wire** — `sender`
  and `recipient` are in the clear, so an observer in range sees who talks to
  whom, how often, and when, and each message costs a fresh ML-DSA signature to
  authenticate. A link is the answer to both: `link_data` carries `link_id`
  alone and one AEAD tag per message.
- **First contact is trust-on-first-use** — a node with no persisted state
  accepts the first `seq` it sees from a peer (and the first announce it hears
  for an address), so a captured packet can be replayed as that peer's "first".
- **Continuity is proven by keys, so a compromised key can still mint a
  successor** — a revocation terminates the identity chain (neither order of
  revoke and rotate yields a trusted successor), so it contains a leak only for
  as long as a receiver remembers the retirement: `expiry` is the caller's
  horizon, `0` means terminal, and past the horizon the address is free again.
- **`key_req` amplifies** — a 25-byte request (PoW-gated) is answered with a
  ~6.5 KB signed announce. The reference node rate-limits re-broadcasts, but a
  replayed `key_req` still costs the target a fresh announce (amplification,
  battery and channel denial).
- **PoW is priced for this device, not against a flood** — `examples/cardputer`
  mines its own bulk traffic at one leading zero byte
  (`CC_POW_DIFFICULTY_ANNOUNCE=1`, `_CHAT=1`), because a ~6.5 KB announce at
  difficulty 2 costs about a second on a desktop host and an ESP32-S3 cannot
  afford that per answer, and mines the small, cheap-to-mint inputs higher
  (`_PRESENCE=2`, `_KEY_REQ=2`, `_LINK_REQ=2`).
- **Reassembly keys on an unauthenticated `msg_id`** — `msg_id` is an
  unauthenticated 8-bit sender value, so a receiver keeps one reassembly state
  per transmitter; two transmitters (or an injector) can disrupt an in-flight
  packet, a repeat is idempotent and a conflicting repeat is rejected, but
  there is no per-sender demultiplexing by design.
- **The card is the identity, in the clear, and its files are not tamper-proof**
  — `/cc/key.bin` holds the identity unencrypted as seeds (the two 64-byte seeds
  and `sign_pub`) and `/cc/group.bin` sits beside it, so physical access to the
  card is permanent impersonation plus a group membership plus retroactive
  decryption of anything captured. The counter, replay and revocation files are
  trusted as read, so an older-but-valid copy is accepted (reused counters, one
  replayed packet, a re-trusted retired identity, a rotated-away key, a
  superseded group), and the per-file envelope's CRC detects damage rather than
  authenticating it. A damaged key file — or no card at all — fails closed
  rather than re-identifying the node. The full picture, including the two
  key-file forms and what is not implemented (no flash encryption, no secure
  boot, no passphrase), is in [Storage posture](#storage-posture).
- **The radios are untested on hardware here** — this repo's host tests cover
  the protocol, the framing and the relay only, not any radio path on a device.
- **The `link_id` and suite byte are provisional** — the handshake carries an
  explicit `CC_SUITE` byte because no ML-KEM KEM ID is registered in HPKE (the
  ML-KEM HPKE draft expired, `draft-ietf-jose-pqc-kem` is still TBD), and an
  8-byte `link_id` with no other identifier is this protocol's own choice; both
  may change when the COSE ML-KEM story settles.

## Error codes

| Code | Value | Meaning |
|------|-------|---------|
| `CC_OK` | 0 | Success |
| `CC_E_ARG` | -1 | Bad argument |
| `CC_E_BUF` | -2 | Buffer too small |
| `CC_E_CRYPTO` | -3 | Crypto operation failed |
| `CC_E_FORMAT` | -4 | Malformed packet (including non-canonical CBOR) |
| `CC_E_SIG` | -5 | Signature verification failed |
| `CC_E_POW` | -6 | Proof-of-work check failed |
| `CC_E_DECRYPT` | -7 | Decryption failed |
| `CC_E_NOKEY` | -8 | Sender key unknown (no announce cached for the claimed sender) |
| `CC_E_REPLAY` | -9 | Counter or sequence already accepted (replay) |
| `CC_E_STALE` | -10 | Counter, sequence or announce older than the window / expiry |
| `CC_E_VERSION` | -11 | Not the current wire revision |
| `CC_E_NOLINK` | -12 | Link id unknown, closed or expired — re-handshake |
| `CC_E_SUITE` | -13 | Handshake suite byte is not `cc_suite()` |
| `CC_E_REVOKED` | -14 | This address is retired — drop it, refuse links and rotations |
| `CC_E_GROUP` | -15 | Not this group: a group post or record for a `gid` we do not hold |

The road helpers return their own codes (`include/cosechat_road.h`):
`CC_ROAD_OK` 0, `CC_ROAD_EMPTY` -1 (nothing waiting), `CC_ROAD_ERR` -2, plus the
`CC_ROAD_RX_MORE`/`READY`/`BUSY`/`BAD` results from `cc_road_rx_frag()`.

The relay returns its own range, `CC_RELAY_FWD` 0 and `CC_RELAY_E_*` from -20 to
-32 (`include/cosechat_relay.h` lists them: `E_ARG`, `E_BUF`, `E_FORMAT`,
`E_VERSION`, `E_UNKNOWN`, `E_MAXHOPS`, `E_EXPIRED`, `E_DUP`, `E_BUDGET`,
`E_NOIMPROVE`, `E_TYPE`, `E_ORIGIN`, `E_POW`). They are deliberately distinct
from `CC_E_*` so a caller cannot mistake one range for the other, and each has
its own counter in `cc_relay_stats_t`.

## License

[Zlib](https://opensource.org/license/ZLIB)
