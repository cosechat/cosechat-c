/*
 * cosechat_road — road framing shared by every transport.
 *
 * Plain C on top of nothing: no allocation, no platform headers, so this
 * compiles for a host, a WASI target, and an ESP32 alike, and the same code
 * runs in a radio task/callback and in a main loop. See cosechat_road.h for
 * the wire format and the invariants both ends of a road must agree on.
 */

#include "cosechat_road.h"

#include <string.h>

void cc_road_frag_init(cc_road_frag_t* f) {
  f->len = 0;
  f->last_sz = 0;
  f->mask = 0;
  f->id = 0;
  f->total = 0;
  f->active = 0;
}

size_t cc_road_frag_count(size_t len, size_t payload) {
  size_t n;
  if (len == 0 || payload == 0 || payload > CC_ROAD_FRAG_PAYLOAD)
    return 0;
  n = (len + payload - 1) / payload;
  return (n <= CC_ROAD_FRAG_MAX_TOTAL) ? n : 0;
}

size_t cc_road_frag_encode(const uint8_t* pkt, size_t len, uint8_t id,
                           uint8_t idx, uint8_t total, size_t payload,
                           uint8_t* out) {
  size_t off, psz;
  if (!pkt || !out || payload == 0 || payload > CC_ROAD_FRAG_PAYLOAD)
    return 0;
  if (total == 0 || total > CC_ROAD_FRAG_MAX_TOTAL || idx >= total)
    return 0;
  /* Refuse to encode a packet that `total` fragments cannot hold: the short
   * final fragment would silently truncate it. */
  if (len > (size_t)total * payload)
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

int cc_road_frag_feed(cc_road_frag_t* f, const uint8_t* data, size_t len,
                      size_t payload) {
  uint8_t id, idx, total;
  size_t psz, off;
  uint32_t full;

  /* Out-of-range arguments are the caller's bug, never data on the wire: both
   * ends must be configured with the same payload, and it must fit one
   * fragment buffer. */
  if (!f || !data || payload == 0 || payload > CC_ROAD_FRAG_PAYLOAD ||
      len <= CC_ROAD_FRAG_HDR)
    return CC_ROAD_RX_BAD;
  if (data[0] != CC_ROAD_FRAG_MAGIC)
    return CC_ROAD_RX_BAD;

  id = data[1];
  idx = data[2];
  total = data[3];
  if (total == 0 || total > CC_ROAD_FRAG_MAX_TOTAL || idx >= total)
    return CC_ROAD_RX_BAD;

  psz = len - CC_ROAD_FRAG_HDR;
  if (psz > payload)
    return CC_ROAD_RX_BAD;
  /* Only the final fragment may be short: a short middle fragment would leave
   * a hole that the packet length cannot distinguish from data. Reject it
   * without storing it, so the fragment can be retransmitted correctly and the
   * assembly is never completed around a gap. */
  if (idx != total - 1 && psz != payload)
    return CC_ROAD_RX_BAD;

  if (!f->active || f->id != id) {
    f->id = id;
    f->total = total;
    f->mask = 0;
    f->last_sz = 0;
    f->active = 1;
  } else if (f->total != total) {
    return CC_ROAD_RX_BAD;
  }

  off = (size_t)idx * payload;
  if (off + psz > sizeof(f->buf))
    return CC_ROAD_RX_BAD;
  if (f->mask & (1u << idx)) {
    /* Already have this index. A broadcast medium repeats fragments, so an
     * identical retransmission is a no-op; a conflicting one (different bytes
     * or length, including a shorter "final" fragment that would truncate the
     * packet) is rejected and the reassembled bytes are left alone: whoever
     * got there first decides what this packet is. */
    size_t have = (idx == total - 1) ? f->last_sz : payload;
    if (have != psz || memcmp(f->buf + off, data + CC_ROAD_FRAG_HDR, psz) != 0)
      return CC_ROAD_RX_BAD;
  } else {
    for (size_t i = 0; i < psz; i++)
      f->buf[off + i] = data[CC_ROAD_FRAG_HDR + i];
    f->mask |= (1u << idx);
    if (idx == total - 1)
      f->last_sz = psz;
  }

  full = (total == CC_ROAD_FRAG_MAX_TOTAL) ? 0xFFFFFFFFu : ((1u << total) - 1);
  if ((f->mask & full) == full) {
    f->active = 0;
    f->len = (size_t)(total - 1) * payload + f->last_sz;
    return CC_ROAD_RX_READY;
  }
  return CC_ROAD_RX_MORE;
}

int cc_road_send_pkt(const uint8_t* pkt, size_t len, uint8_t id, size_t payload,
                     cc_road_emit_fn emit, void* ctx) {
  uint8_t frag[CC_ROAD_FRAG_HDR + CC_ROAD_FRAG_PAYLOAD];
  size_t total, i;

  if (!pkt || !emit)
    return CC_ROAD_ERR;
  total = cc_road_frag_count(len, payload);
  if (total == 0)
    return CC_ROAD_ERR;

  for (i = 0; i < total; i++) {
    size_t n = cc_road_frag_encode(pkt, len, id, (uint8_t)i, (uint8_t)total,
                                   payload, frag);
    if (n == 0)
      return CC_ROAD_ERR;
    if (emit(ctx, frag, n) != n)
      return CC_ROAD_ERR;
  }
  return CC_ROAD_OK;
}

/* Store a link-layer source, reporting "unknown" (length 0) for anything that
 * is not a usable source: no source at all, or one too long to be this road's
 * identity — truncating it would name a different neighbour. */
static void src_store(uint8_t* dst, uint8_t* dst_len, const uint8_t* src,
                      size_t src_len) {
  memset(dst, 0, CC_ROAD_SRC_SZ);
  if (!src || src_len == 0 || src_len > CC_ROAD_SRC_SZ) {
    *dst_len = 0;
    return;
  }
  memcpy(dst, src, src_len);
  *dst_len = (uint8_t)src_len;
}

int cc_road_rx_frag(cc_road_frag_t* f, const uint8_t* frag, size_t len,
                    size_t payload, const uint8_t* src, size_t src_len,
                    cc_road_pkt_t* slot) {
  int done;
  size_t n;

  if (!slot)
    return CC_ROAD_RX_BAD;
  done = cc_road_frag_feed(f, frag, len, payload);
  if (done != CC_ROAD_RX_READY)
    return done;
  /* The slot is one packet deep: keep the packet already waiting for recv()
   * instead of overwriting it (and with it, the source it arrived from). */
  if (slot->len != 0)
    return CC_ROAD_RX_BUSY;
  n = f->len;
  memcpy(slot->buf, f->buf, n);
  /* Store the source before publishing the packet, so recv() can only ever see
   * a packet together with its own source. */
  src_store(slot->src, &slot->src_len, src, src_len);
  slot->len = n;
  return CC_ROAD_RX_READY;
}

void cc_road_src_take(const cc_road_pkt_t* slot, cc_road_t* road) {
  if (!road)
    return;
  /* An empty slot holds no packet, so it has no source: report unknown rather
   * than whatever the packet that used to be in it came from. */
  if (!slot || slot->len == 0) {
    src_store(road->last_src, &road->last_src_len, NULL, 0);
    return;
  }
  src_store(road->last_src, &road->last_src_len, slot->src, slot->src_len);
}

int cc_road_pkt_get(const cc_road_pkt_t* slot, uint8_t* buf, size_t buf_sz,
                    size_t* len_out) {
  if (!slot || !buf || !len_out || slot->len == 0 || slot->len > buf_sz)
    return CC_ROAD_ERR;
  memcpy(buf, slot->buf, slot->len);
  *len_out = slot->len;
  return CC_ROAD_OK;
}
