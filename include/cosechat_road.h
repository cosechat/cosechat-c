#ifndef CC_COSECHAT_ROAD_H
#define CC_COSECHAT_ROAD_H

/*
 * Roads — the transport layer shipped with cosechat.
 *
 * A "road" carries whole cosechat packets between nodes over one medium (LoRa,
 * WiFi/UDP, BLE advertising, raw 802.11 management frames). This interface and
 * the wire framing below are part of the library, not of any one client: a
 * desktop, WASI or MCU client uses them instead of copying them, and the
 * medium-specific parts (radio setup, sockets, tasks, queues) live in the road
 * implementation. The road hides framing and fragmentation from the
 * application:
 *
 *     cc_road_t* road = ...;
 *     road->send(road, pkt, len);
 *     if (road->recv(road, buf, sizeof(buf), &len) == CC_ROAD_OK) { ... }
 *
 * Reference implementations are in examples/cardputer: road_lora.h (SX1262),
 * road_wifi.h (WiFi + UDP), road_ble.h (anonymous BLE extended advertising),
 * road_80211.h (unauthenticated 802.11 management frames).
 *
 * ---- wire framing ----
 *
 * Every road shares one framing, so fragmentation and reassembly are common. A
 * fragment is a 4-byte header plus payload:
 *
 *     [magic=0xCC, msg_id, frag_idx, frag_total, payload...]
 *
 * msg_id is chosen by the sender and is only meaningful while a packet is in
 * flight; a new msg_id abandons whatever partial assembly is in progress.
 * frag_total is at most CC_ROAD_FRAG_MAX_TOTAL and every fragment except the
 * last carries exactly `payload` bytes. A repeated fragment is idempotent; a
 * repeat that conflicts with bytes already received is rejected.
 *
 * ONE cc_road_frag_t REASSEMBLES ONE STREAM FROM ONE TRANSMITTER. msg_id is an
 * 8-bit sender-chosen value that is not authenticated, so two transmitters in
 * range of the same receiver interleave fragments into (and thereby destroy)
 * the same assembly, and a sender whose counter wraps can collide with a stale
 * partial assembly. A receiver that expects several transmitters at once must
 * keep one cc_road_frag_t per source — demultiplexing inside the framing would
 * need a sender identity in the header, i.e. a fragment-format change, which
 * this framing deliberately does not make (a medium that already carries an
 * address, like 802.11's MAC, is the place to get one).
 *
 * Both ends of a road MUST agree on `payload`, because it is not transmitted.
 * CC_ROAD_FRAG_PAYLOAD is the largest payload any road uses; a road with a
 * smaller MTU (BLE advertising, 243 bytes) passes its own value to every call,
 * and a peer that assumes a different value rejects the stream. payload must
 * be 1..CC_ROAD_FRAG_PAYLOAD; anything else is rejected by count/encode/feed.
 *
 * The framing has no clock, and that is by design: nothing here decides that a
 * partial assembly is stale, because the only reliable notion of time lives in
 * the road (a task tick, a socket, a millis() loop). An abandoned partial
 * assembly is dropped by a new msg_id, or explicitly by the road calling
 * cc_road_frag_init() from its own timeout.
 *
 * Nothing here allocates, and nothing here includes a platform header, so the
 * helpers are usable from a radio task/callback and from a main loop alike.
 *
 * Reassembly buffers are ~8 KB. Declare roads static/global on embedded.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CC_ROAD_OK 0
#define CC_ROAD_EMPTY (-1) /* recv: nothing waiting */
#define CC_ROAD_ERR (-2)

/* ---- fragmentation framing ---- */

#define CC_ROAD_FRAG_MAGIC 0xCC
#define CC_ROAD_FRAG_HDR 4 /* magic, msg_id, frag_idx, frag_total */
#define CC_ROAD_FRAG_PAYLOAD \
  248 /* largest per-fragment payload any road uses */
#define CC_ROAD_FRAG_MAX_TOTAL 32
#define CC_ROAD_PKT_BUF_SZ \
  (CC_ROAD_FRAG_PAYLOAD * CC_ROAD_FRAG_MAX_TOTAL) /* 7936 */

/*
 * Link-layer source of a packet, as handed to the application in
 * cc_road_t.last_src: 6 bytes, the width of an IEEE MAC address — the whole
 * source field of an 802.11 frame, which is the widest link-layer identity any
 * road here has. An IPv4 sender address and its UDP port fit in the same 6
 * bytes (road_wifi). A source longer than this is reported as unknown rather
 * than truncated, because a truncated identity is a different identity.
 */
#define CC_ROAD_SRC_SZ 6

/* Result codes from cc_road_rx_frag(). */
#define CC_ROAD_RX_MORE 0   /* fragment stored, packet still incomplete */
#define CC_ROAD_RX_READY 1  /* packet complete and stored in the slot */
#define CC_ROAD_RX_BUSY 2   /* packet complete, slot still occupied: dropped */
#define CC_ROAD_RX_BAD (-1) /* malformed fragment */

typedef struct {
  uint8_t buf[CC_ROAD_PKT_BUF_SZ];
  size_t len;     /* completed packet length */
  size_t last_sz; /* payload size of the final fragment */
  uint32_t mask;  /* received-fragment bitmap */
  uint8_t id;     /* message id being assembled */
  uint8_t total;  /* fragment count of that message */
  int active;     /* an assembly is in progress */
} cc_road_frag_t;

/* Reassembly holds no state outside this struct. Call this before use, and
 * again to abandon a partial packet. */
void cc_road_frag_init(cc_road_frag_t* f);

/* Fragment count for a `len`-byte packet at `payload` bytes per fragment. 0
 * when the packet cannot be fragmented (len 0, payload 0, or more than
 * CC_ROAD_FRAG_MAX_TOTAL fragments needed). */
size_t cc_road_frag_count(size_t len, size_t payload);

/* Encode fragment `idx` of `total` into `out`, which must hold payload +
 * CC_ROAD_FRAG_HDR bytes. Returns the fragment length, or 0 when the arguments
 * are invalid — including a `total` too small to hold `len`, which would
 * otherwise truncate the packet silently. */
size_t cc_road_frag_encode(const uint8_t* pkt, size_t len, uint8_t id,
                           uint8_t idx, uint8_t total, size_t payload,
                           uint8_t* out);

/*
 * Feed one received fragment carrying `payload` bytes per fragment, and read
 * the packet back from f->buf / f->len when one completes. Returns a
 * CC_ROAD_RX_* code.
 *
 * Rejection rules (all return CC_ROAD_RX_BAD and change no reassembled bytes):
 * a malformed fragment is never stored, so it can neither leave a hole in an
 * assembly nor complete one; a fragment for an index already received is
 * accepted only when its length and bytes match what is stored (an idempotent
 * retransmission, which a lossy broadcast medium will produce), so a repeat
 * cannot rewrite bytes or resize the packet.
 */
int cc_road_frag_feed(cc_road_frag_t* f, const uint8_t* data, size_t len,
                      size_t payload);

/* ---- shared send/receive helpers ---- */

/*
 * Emit one fragment: the bytes the medium accepted, or 0 on failure. Both
 * cc_road_send_pkt() and the road's statistics live on top of this.
 */
typedef size_t (*cc_road_emit_fn)(void* ctx, const uint8_t* frag, size_t len);

/*
 * Fragment `pkt` and hand every fragment to `emit` in order, `payload` bytes
 * per fragment. Returns CC_ROAD_OK, or CC_ROAD_ERR as soon as a fragment
 * cannot be emitted (send() then returns the same). No allocation: the
 * fragment buffer is on this frame.
 */
int cc_road_send_pkt(const uint8_t* pkt, size_t len, uint8_t id, size_t payload,
                     cc_road_emit_fn emit, void* ctx);

/* A single-slot holder for one completed packet: buf is valid while len != 0.
 * The road that owns it clears len after copying the packet out. src/src_len
 * are the link-layer source the packet arrived from (src_len == 0 when the
 * medium cannot attribute the sender): cc_road_rx_frag() records them with the
 * packet, and cc_road_src_take() hands them to the application. */
typedef struct {
  uint8_t buf[CC_ROAD_PKT_BUF_SZ];
  size_t len;
  uint8_t src[CC_ROAD_SRC_SZ];
  uint8_t src_len;
} cc_road_pkt_t;

/*
 * Reassemble one received fragment into `slot`. `src`/`src_len` are the
 * link-layer source of the frame the fragment arrived in (NULL/0 when the
 * medium cannot attribute the sender); they become the source of the packet
 * when one completes — the frame that carried the completing fragment, and
 * since one assembly is one transmitter's stream (see above) that is the
 * packet's sender — and a source longer than CC_ROAD_SRC_SZ is recorded as
 * unknown rather than truncated. Returns
 *   CC_ROAD_RX_READY  packet complete, copied into slot
 *   CC_ROAD_RX_MORE   fragment stored, more needed
 *   CC_ROAD_RX_BAD    malformed fragment
 *   CC_ROAD_RX_BUSY   packet complete but `slot` still held an uncollected
 *                     packet, so this one was dropped — the packet already
 *                     waiting, and its source, are never overwritten
 * Safe to call from a radio task/callback or a main loop.
 */
int cc_road_rx_frag(cc_road_frag_t* f, const uint8_t* frag, size_t len,
                    size_t payload, const uint8_t* src, size_t src_len,
                    cc_road_pkt_t* slot);

/* Copy the pending packet out of `slot` (CC_ROAD_OK), or CC_ROAD_ERR when the
 * slot is empty, the arguments are NULL, or buf_sz is too small. */
int cc_road_pkt_get(const cc_road_pkt_t* slot, uint8_t* buf, size_t buf_sz,
                    size_t* len_out);

/* ---- road interface ---- */

typedef struct cc_road cc_road_t;

struct cc_road {
  const char* name;
  void* ctx;
  /* Send a whole cosechat packet (road fragments as needed). CC_ROAD_OK/ERR. */
  int (*send)(cc_road_t* road, const uint8_t* pkt, size_t len);
  /* Non-blocking. Copies the next complete packet into buf. */
  int (*recv)(cc_road_t* road, uint8_t* buf, size_t buf_sz, size_t* len_out);
  /* Signal quality of the last received packet (0 when unknown; RSSI dBm +
   * SNR dB for radio roads). */
  float last_rssi;
  float last_snr;
  /*
   * Link-layer source of the packet recv() last delivered: last_src_len bytes
   * of last_src, or 0 when this medium cannot attribute the sender.
   *
   * It describes exactly that packet: the field is stored with the packet, and
   * a recv() that returns CC_ROAD_EMPTY changes nothing, so read it right after
   * recv() returned CC_ROAD_OK. It is filled only from the medium's own
   * addressing (a frame's source address, a datagram's sender) — never from
   * anything the sender claims inside the cosechat payload — and it is 0
   * whenever the road cannot attribute the sender, never a value left over
   * from an earlier packet. Compare it only with another source from the SAME
   * road: it names a neighbour on that medium, never a cosechat address, and
   * two media do not share a source space.
   *
   * A caller MUST treat last_src_len == 0 as "sender unknown". Any rule keyed
   * on sender identity — the relay's "an announce at hops 0 must have arrived
   * from the address it announces" — is then UNAVAILABLE, and the address the
   * packet announces must never be substituted for the missing source: that
   * substitution is exactly what an unattributable medium would let a hijacker
   * do. Anonymous BLE advertising and LoRa are such media (no advertiser
   * address, no source field in the frame), so they always report 0.
   */
  uint8_t last_src[CC_ROAD_SRC_SZ];
  uint8_t last_src_len;
};

/* Hand the delivered packet's source to the application: copies slot->src /
 * slot->src_len into road->last_src / road->last_src_len, and reports
 * last_src_len == 0 whenever there is no usable source — no packet in the slot,
 * no source recorded for it, or a source that could not be stored as this
 * road's identity. A value from an earlier packet can therefore never survive a
 * delivery. A road's recv() calls this where it hands the packet over, before
 * releasing the slot. */
void cc_road_src_take(const cc_road_pkt_t* slot, cc_road_t* road);

#ifdef __cplusplus
}
#endif

#endif /* CC_COSECHAT_ROAD_H */
