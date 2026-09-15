#ifndef CC_ROAD_H
#define CC_ROAD_H

/*
 * Roads — transport abstraction for cosechat.
 *
 * A "road" carries whole cosechat packets between nodes. Each road handles
 * its own framing and (where the medium needs it) fragmentation, so the
 * application only ever deals with complete packets:
 *
 *     cc_road_t* road = &lora_road.road;
 *     road->send(road, pkt, len);
 *     if (road->recv(road, buf, sizeof(buf), &len) == CC_ROAD_OK) { ... }
 *
 * Implementations: road_lora.h (SX1262), road_wifi.h (WiFi + UDP),
 * road_ble.h (anonymous BLE extended advertising), road_80211.h
 * (unauthenticated 802.11 management frames).
 *
 * All roads share one wire framing so fragmentation/reassembly logic is
 * common. A fragment is 4-byte header + payload:
 *
 *     [magic=0xCC, msg_id, frag_idx, frag_total, payload...]
 *
 * CC_ROAD_FRAG_MAX_PAYLOAD (248) is the largest payload any road uses; the
 * helper set below also takes an explicit per-fragment payload so a road with
 * a smaller MTU (BLE extended advertising, 251-byte advertisements) reuses the
 * same framing. Both ends of a road must agree on the payload size — it is not
 * transmitted.
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
#define CC_ROAD_FRAG_MAX_PAYLOAD 248
#define CC_ROAD_FRAG_MAX_TOTAL 32
#define CC_ROAD_PKT_BUF_SZ \
  (CC_ROAD_FRAG_MAX_PAYLOAD * CC_ROAD_FRAG_MAX_TOTAL) /* 7936 */

typedef struct {
  uint8_t buf[CC_ROAD_PKT_BUF_SZ];
  size_t len;     /* completed packet length */
  size_t last_sz; /* payload size of the final fragment */
  uint32_t mask;  /* received-fragment bitmap */
  uint8_t id;     /* message id being assembled */
  uint8_t total;  /* fragment count of that message */
  int active;     /* an assembly is in progress */
} cc_road_frag_t;

static inline void cc_road_frag_init(cc_road_frag_t* f) {
  f->len = 0;
  f->last_sz = 0;
  f->mask = 0;
  f->id = 0;
  f->total = 0;
  f->active = 0;
}

/*
 * Fragment count for `len` with an explicit fragment payload size. Roads whose
 * MTU differs from CC_ROAD_FRAG_MAX_PAYLOAD (e.g. BLE advertising) pass their
 * own payload here.
 */
static inline size_t cc_road_frag_count_n(size_t len, size_t payload) {
  size_t n;
  if (len == 0 || payload == 0)
    return 0;
  n = (len + payload - 1) / payload;
  return (n <= CC_ROAD_FRAG_MAX_TOTAL) ? n : 0;
}

/* Fragment count for a packet, 0 if it cannot be fragmented. */
static inline size_t cc_road_frag_count(size_t len) {
  return cc_road_frag_count_n(len, CC_ROAD_FRAG_MAX_PAYLOAD);
}

/*
 * Encode fragment `idx` of `total` into out, which must hold
 * payload + CC_ROAD_FRAG_HDR bytes. Returns fragment length, or 0 on invalid
 * arguments.
 */
static inline size_t cc_road_frag_encode_n(const uint8_t* pkt, size_t len,
                                           uint8_t id, uint8_t idx,
                                           uint8_t total, size_t payload,
                                           uint8_t* out) {
  size_t off, psz;
  if (!pkt || !out || payload == 0 || total == 0 ||
      total > CC_ROAD_FRAG_MAX_TOTAL)
    return 0;
  if (idx >= total)
    return 0;
  off = (size_t)idx * payload;
  if (off >= len)
    return 0;
  psz = len - off;
  if (psz > payload)
    psz = payload;
  out[0] = CC_ROAD_FRAG_MAGIC;
  out[1] = id;
  out[2] = idx;
  out[3] = total;
  for (size_t i = 0; i < psz; i++) out[CC_ROAD_FRAG_HDR + i] = pkt[off + i];
  return CC_ROAD_FRAG_HDR + psz;
}

/*
 * Encode fragment `idx` of `total` into out, which must hold
 * CC_ROAD_FRAG_MAX_PAYLOAD + CC_ROAD_FRAG_HDR bytes. Returns fragment
 * length, or 0 on invalid arguments.
 */
static inline size_t cc_road_frag_encode(const uint8_t* pkt, size_t len,
                                         uint8_t id, uint8_t idx, uint8_t total,
                                         uint8_t* out) {
  return cc_road_frag_encode_n(pkt, len, id, idx, total,
                               CC_ROAD_FRAG_MAX_PAYLOAD, out);
}

/*
 * Feed one received fragment carrying `payload` bytes per fragment. Returns 1
 * when a packet is complete (read f->buf / f->len), 0 when more fragments are
 * needed, -1 when the fragment is malformed, sized for a different payload, or
 * out of order for the current assembly.
 */
static inline int cc_road_frag_feed_n(cc_road_frag_t* f, const uint8_t* data,
                                      size_t len, size_t payload) {
  uint8_t id, idx, total;
  size_t psz, off;
  uint32_t full;

  if (!f || !data || payload == 0 || len <= CC_ROAD_FRAG_HDR)
    return -1;
  if (data[0] != CC_ROAD_FRAG_MAGIC)
    return -1;

  id = data[1];
  idx = data[2];
  total = data[3];
  if (total == 0 || total > CC_ROAD_FRAG_MAX_TOTAL || idx >= total)
    return -1;

  if (!f->active || f->id != id) {
    f->id = id;
    f->total = total;
    f->mask = 0;
    f->last_sz = 0;
    f->active = 1;
  } else if (f->total != total) {
    return -1;
  }

  psz = len - CC_ROAD_FRAG_HDR;
  if (psz > payload)
    return -1;
  off = (size_t)idx * payload;
  if (off + psz > sizeof(f->buf))
    return -1;
  for (size_t i = 0; i < psz; i++) f->buf[off + i] = data[CC_ROAD_FRAG_HDR + i];
  f->mask |= (1u << idx);
  if (idx == total - 1)
    f->last_sz = psz;

  full = (total == 32) ? 0xFFFFFFFFu : ((1u << total) - 1);
  if ((f->mask & full) == full) {
    f->active = 0;
    f->len = (size_t)(total - 1) * payload + f->last_sz;
    return 1;
  }
  return 0;
}

/*
 * Feed one received fragment. Returns 1 when a packet is complete (read
 * f->buf / f->len), 0 when more fragments are needed, -1 when the fragment
 * is malformed or out of order for the current assembly.
 */
static inline int cc_road_frag_feed(cc_road_frag_t* f, const uint8_t* data,
                                    size_t len) {
  return cc_road_frag_feed_n(f, data, len, CC_ROAD_FRAG_MAX_PAYLOAD);
}

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
};

#ifdef __cplusplus
}
#endif

#endif /* CC_ROAD_H */
