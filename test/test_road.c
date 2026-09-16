/* test_road.c — road framing contract (fragmentation, reassembly, packet
 * slot).
 *
 * The road framing is part of the library (include/cosechat_road.h) and is
 * shared by every road, so it is exercised here on the host rather than on
 * hardware. The send helper and the packet slot are covered end to end,
 * because all four roads are built on them. */
#include <stdio.h>
#include <string.h>

#include "cosechat_road.h"

#define FRAGBUF_SZ (CC_ROAD_FRAG_PAYLOAD + CC_ROAD_FRAG_HDR)
#define BLE_PAYLOAD 243 /* CC_ROAD_BLE_FRAG_PAYLOAD */

static int g_passed = 0, g_failed = 0;

#define T(name, cond)               \
  do {                              \
    if (cond) {                     \
      printf("  pass: %s\n", name); \
      g_passed++;                   \
    } else {                        \
      printf("  FAIL: %s\n", name); \
      g_failed++;                   \
    }                               \
  } while (0)

static void test_count(void) {
  printf("fragment count:\n");
  T("zero", cc_road_frag_count(0, CC_ROAD_FRAG_PAYLOAD) == 0);
  T("one byte", cc_road_frag_count(1, CC_ROAD_FRAG_PAYLOAD) == 1);
  T("exact payload",
    cc_road_frag_count(CC_ROAD_FRAG_PAYLOAD, CC_ROAD_FRAG_PAYLOAD) == 1);
  T("payload+1",
    cc_road_frag_count(CC_ROAD_FRAG_PAYLOAD + 1, CC_ROAD_FRAG_PAYLOAD) == 2);
  /* A full announce (name and metadata at their limits) is 4886 bytes on the
   * wire, i.e. 20 fragments. */
  T("full announce", cc_road_frag_count(4886, CC_ROAD_FRAG_PAYLOAD) == 20);
  T("max", cc_road_frag_count(CC_ROAD_PKT_BUF_SZ, CC_ROAD_FRAG_PAYLOAD) ==
               CC_ROAD_FRAG_MAX_TOTAL);
  T("too big",
    cc_road_frag_count(CC_ROAD_PKT_BUF_SZ + 1, CC_ROAD_FRAG_PAYLOAD) == 0);
  T("zero payload", cc_road_frag_count(100, 0) == 0);
  /* A payload larger than one fragment buffer would overflow every caller. */
  T("payload over max", cc_road_frag_count(100, CC_ROAD_FRAG_PAYLOAD + 1) == 0);
}

static void test_encode_rejects(void) {
  uint8_t pkt[8] = {0};
  uint8_t out[FRAGBUF_SZ];
  printf("encode:\n");
  T("idx >= total", cc_road_frag_encode(pkt, sizeof(pkt), 1, 1, 1,
                                        CC_ROAD_FRAG_PAYLOAD, out) == 0);
  T("total 0", cc_road_frag_encode(pkt, sizeof(pkt), 1, 0, 0,
                                   CC_ROAD_FRAG_PAYLOAD, out) == 0);
  T("null pkt", cc_road_frag_encode(NULL, sizeof(pkt), 1, 0, 1,
                                    CC_ROAD_FRAG_PAYLOAD, out) == 0);
  T("offset past end",
    cc_road_frag_encode(pkt, 1, 1, 1, 2, CC_ROAD_FRAG_PAYLOAD, out) == 0);
  /* A `total` too small would silently truncate the packet. */
  T("total cannot hold packet",
    cc_road_frag_encode(pkt, sizeof(pkt), 1, 0, 1, 4, out) == 0);
  T("payload 0", cc_road_frag_encode(pkt, sizeof(pkt), 1, 0, 1, 0, out) == 0);
  T("payload over max",
    cc_road_frag_encode(pkt, sizeof(pkt), 1, 0, 1, CC_ROAD_FRAG_PAYLOAD + 1,
                        out) == 0);
}

/* Feed fragments out of order and confirm the packet is rebuilt byte-exact. */
static void test_roundtrip_out_of_order(void) {
  static cc_road_frag_t f;
  static cc_road_pkt_t slot;
  static uint8_t pkt[5000];
  static uint8_t frag[FRAGBUF_SZ];
  size_t total, i;
  int done = 0;

  for (i = 0; i < sizeof(pkt); i++) pkt[i] = (uint8_t)(i * 7 + 3);
  total = cc_road_frag_count(sizeof(pkt), CC_ROAD_FRAG_PAYLOAD);

  printf("round-trip (reversed order):\n");
  cc_road_frag_init(&f);
  int bad_len = 0, early = 0;
  for (i = total; i-- > 0;) {
    size_t n = cc_road_frag_encode(pkt, sizeof(pkt), 42, (uint8_t)i,
                                   (uint8_t)total, CC_ROAD_FRAG_PAYLOAD, frag);
    if (n <= CC_ROAD_FRAG_HDR || n > FRAGBUF_SZ)
      bad_len = 1;
    done = cc_road_rx_frag(&f, frag, n, CC_ROAD_FRAG_PAYLOAD, NULL, 0, &slot);
    if (i != 0 && done != CC_ROAD_RX_MORE)
      early = 1;
  }
  T("fragment lengths sane", !bad_len);
  T("incomplete until first frag", !early);
  T("complete in slot", done == CC_ROAD_RX_READY);
  T("slot length", slot.len == sizeof(pkt));
  T("slot bytes identical", memcmp(slot.buf, pkt, sizeof(pkt)) == 0);
  T("state matches",
    f.len == sizeof(pkt) && memcmp(f.buf, pkt, sizeof(pkt)) == 0);
}

/* Duplicate fragments must not corrupt or complete early. */
static void test_duplicates(void) {
  static cc_road_frag_t f;
  static cc_road_pkt_t slot;
  static uint8_t pkt[600];
  static uint8_t frag[FRAGBUF_SZ];
  size_t total = cc_road_frag_count(sizeof(pkt), CC_ROAD_FRAG_PAYLOAD);
  size_t i, n;
  int done = CC_ROAD_RX_MORE;

  for (i = 0; i < sizeof(pkt); i++) pkt[i] = (uint8_t)i;
  printf("duplicates:\n");
  cc_road_frag_init(&f);
  slot.len = 0;
  for (i = 0; i < total; i++) {
    n = cc_road_frag_encode(pkt, sizeof(pkt), 7, (uint8_t)i, (uint8_t)total,
                            CC_ROAD_FRAG_PAYLOAD, frag);
    done = cc_road_rx_frag(&f, frag, n, CC_ROAD_FRAG_PAYLOAD, NULL, 0, &slot);
    if (i + 1 < total) {
      /* resend a non-final fragment; must be idempotent */
      done = cc_road_rx_frag(&f, frag, n, CC_ROAD_FRAG_PAYLOAD, NULL, 0, &slot);
      T("duplicate does not complete", done == CC_ROAD_RX_MORE);
    }
  }
  T("complete", done == CC_ROAD_RX_READY);
  T("bytes identical", memcmp(slot.buf, pkt, sizeof(pkt)) == 0);
}

/* A repeat of an index already received must be idempotent when it is the same
 * fragment, and must never rewrite reassembled bytes or resize the packet when
 * it is not. */
static void test_duplicate_conflict(void) {
  static cc_road_frag_t f;
  static uint8_t pkt[600]; /* 3 fragments at 248: 248, 248, 104 */
  static uint8_t frag[FRAGBUF_SZ];
  static uint8_t evil[FRAGBUF_SZ];
  size_t total = cc_road_frag_count(sizeof(pkt), CC_ROAD_FRAG_PAYLOAD);
  size_t n;

  for (size_t i = 0; i < sizeof(pkt); i++) pkt[i] = (uint8_t)(i * 5 + 9);
  printf("duplicate fragments:\n");
  cc_road_frag_init(&f);

  n = cc_road_frag_encode(pkt, sizeof(pkt), 30, 1, (uint8_t)total,
                          CC_ROAD_FRAG_PAYLOAD, frag);
  T("middle fragment stored",
    cc_road_frag_feed(&f, frag, n, CC_ROAD_FRAG_PAYLOAD) == CC_ROAD_RX_MORE);
  T("identical repeat is accepted",
    cc_road_frag_feed(&f, frag, n, CC_ROAD_FRAG_PAYLOAD) == CC_ROAD_RX_MORE);

  memcpy(evil, frag, n);
  evil[CC_ROAD_FRAG_HDR + 7] ^= 0xff;
  T("conflicting repeat rejected",
    cc_road_frag_feed(&f, evil, n, CC_ROAD_FRAG_PAYLOAD) == CC_ROAD_RX_BAD);

  /* The final fragment decides the packet length: a repeat must not shrink it.
   */
  n = cc_road_frag_encode(pkt, sizeof(pkt), 30, 2, (uint8_t)total,
                          CC_ROAD_FRAG_PAYLOAD, frag);
  T("final fragment stored",
    cc_road_frag_feed(&f, frag, n, CC_ROAD_FRAG_PAYLOAD) == CC_ROAD_RX_MORE);
  T("short repeat of the final fragment rejected",
    cc_road_frag_feed(&f, frag, n - 5, CC_ROAD_FRAG_PAYLOAD) == CC_ROAD_RX_BAD);
  T("final size untouched",
    f.last_sz == sizeof(pkt) - 2 * CC_ROAD_FRAG_PAYLOAD);

  n = cc_road_frag_encode(pkt, sizeof(pkt), 30, 0, (uint8_t)total,
                          CC_ROAD_FRAG_PAYLOAD, frag);
  T("first fragment",
    cc_road_frag_feed(&f, frag, n, CC_ROAD_FRAG_PAYLOAD) == CC_ROAD_RX_READY);
  T("length untouched", f.len == sizeof(pkt));
  T("bytes untouched", memcmp(f.buf, pkt, sizeof(pkt)) == 0);
}

/* A malformed fragment is rejected without being stored, so it can neither
 * complete a packet early nor leave a hole that later reads as data. */
static void test_short_fragment(void) {
  static cc_road_frag_t f;
  static cc_road_pkt_t slot;
  static uint8_t pkt[600]; /* 3 fragments at 248: 248, 248, 104 */
  static uint8_t frag[FRAGBUF_SZ];
  size_t total = cc_road_frag_count(sizeof(pkt), CC_ROAD_FRAG_PAYLOAD);
  size_t n;

  for (size_t i = 0; i < sizeof(pkt); i++) pkt[i] = (uint8_t)(i * 3 + 1);
  printf("short middle fragment:\n");
  cc_road_frag_init(&f);
  slot.len = 0;

  /* idx 1 carries 248 bytes; truncate it to 100 and offer it first. */
  n = cc_road_frag_encode(pkt, sizeof(pkt), 8, 1, (uint8_t)total,
                          CC_ROAD_FRAG_PAYLOAD, frag);
  T("encoded", n == CC_ROAD_FRAG_HDR + CC_ROAD_FRAG_PAYLOAD);
  T("short middle rejected",
    cc_road_rx_frag(&f, frag, CC_ROAD_FRAG_HDR + 100, CC_ROAD_FRAG_PAYLOAD,
                    NULL, 0, &slot) == CC_ROAD_RX_BAD);

  /* The good fragment still completes the packet: no hole was left behind. */
  n = cc_road_frag_encode(pkt, sizeof(pkt), 8, 1, (uint8_t)total,
                          CC_ROAD_FRAG_PAYLOAD, frag);
  T("retry stored", cc_road_rx_frag(&f, frag, n, CC_ROAD_FRAG_PAYLOAD, NULL, 0,
                                    &slot) == CC_ROAD_RX_MORE);
  n = cc_road_frag_encode(pkt, sizeof(pkt), 8, 0, (uint8_t)total,
                          CC_ROAD_FRAG_PAYLOAD, frag);
  T("first fragment", cc_road_rx_frag(&f, frag, n, CC_ROAD_FRAG_PAYLOAD, NULL,
                                      0, &slot) == CC_ROAD_RX_MORE);
  n = cc_road_frag_encode(pkt, sizeof(pkt), 8, 2, (uint8_t)total,
                          CC_ROAD_FRAG_PAYLOAD, frag);
  T("last fragment", cc_road_rx_frag(&f, frag, n, CC_ROAD_FRAG_PAYLOAD, NULL, 0,
                                     &slot) == CC_ROAD_RX_READY);
  T("length", slot.len == sizeof(pkt));
  T("bytes identical", memcmp(slot.buf, pkt, sizeof(pkt)) == 0);
}

static void test_rejects(void) {
  static cc_road_frag_t f;
  uint8_t frag[FRAGBUF_SZ];
  uint8_t pkt[300];
  size_t total = cc_road_frag_count(sizeof(pkt), CC_ROAD_FRAG_PAYLOAD);
  size_t n0 = cc_road_frag_encode(pkt, sizeof(pkt), 1, 0, (uint8_t)total,
                                  CC_ROAD_FRAG_PAYLOAD, frag);
  size_t n1 = cc_road_frag_encode(pkt, sizeof(pkt), 1, 1, (uint8_t)total,
                                  CC_ROAD_FRAG_PAYLOAD, frag);

  printf("rejects:\n");
  cc_road_frag_init(&f);
  T("short packet", cc_road_frag_feed(&f, frag, CC_ROAD_FRAG_HDR,
                                      CC_ROAD_FRAG_PAYLOAD) == CC_ROAD_RX_BAD);

  frag[0] = 0x00;
  T("bad magic",
    cc_road_frag_feed(&f, frag, n0, CC_ROAD_FRAG_PAYLOAD) == CC_ROAD_RX_BAD);

  cc_road_frag_init(&f);
  n0 = cc_road_frag_encode(pkt, sizeof(pkt), 1, 0, (uint8_t)total,
                           CC_ROAD_FRAG_PAYLOAD, frag);
  n1 = cc_road_frag_encode(pkt, sizeof(pkt), 1, 1, (uint8_t)total,
                           CC_ROAD_FRAG_PAYLOAD, frag);
  frag[2] = (uint8_t)total; /* idx == total */
  T("idx out of range",
    cc_road_frag_feed(&f, frag, n0, CC_ROAD_FRAG_PAYLOAD) == CC_ROAD_RX_BAD);

  cc_road_frag_init(&f);
  n0 = cc_road_frag_encode(pkt, sizeof(pkt), 1, 0, (uint8_t)total,
                           CC_ROAD_FRAG_PAYLOAD, frag);
  cc_road_frag_feed(&f, frag, n0, CC_ROAD_FRAG_PAYLOAD);
  frag[3] = (uint8_t)(total + 1); /* same msg_id, different total */
  T("total changed mid-assembly",
    cc_road_frag_feed(&f, frag, n1, CC_ROAD_FRAG_PAYLOAD) == CC_ROAD_RX_BAD);
}

/* A new msg_id abandons the partial assembly and starts fresh. */
static void test_interleave(void) {
  static cc_road_frag_t f;
  static cc_road_pkt_t slot;
  static uint8_t pkt[600];
  static uint8_t frag[FRAGBUF_SZ];
  size_t total = cc_road_frag_count(sizeof(pkt), CC_ROAD_FRAG_PAYLOAD);
  size_t i, n;
  int done = 0;

  for (i = 0; i < sizeof(pkt); i++) pkt[i] = (uint8_t)(255 - i);
  printf("interleaved msg ids:\n");
  cc_road_frag_init(&f);
  slot.len = 0;
  /* first fragment of message 1, never completed */
  n = cc_road_frag_encode(pkt, sizeof(pkt), 1, 0, (uint8_t)total,
                          CC_ROAD_FRAG_PAYLOAD, frag);
  cc_road_rx_frag(&f, frag, n, CC_ROAD_FRAG_PAYLOAD, NULL, 0, &slot);
  /* all of message 2 */
  for (i = 0; i < total; i++) {
    n = cc_road_frag_encode(pkt, sizeof(pkt), 2, (uint8_t)i, (uint8_t)total,
                            CC_ROAD_FRAG_PAYLOAD, frag);
    done = cc_road_rx_frag(&f, frag, n, CC_ROAD_FRAG_PAYLOAD, NULL, 0, &slot);
  }
  T("complete", done == CC_ROAD_RX_READY);
  T("bytes identical", memcmp(slot.buf, pkt, sizeof(pkt)) == 0);
}

/* A road whose MTU is smaller than the default payload (BLE advertising) uses
 * the same framing with an explicit fragment payload. */
static void test_generic_payload(void) {
  static cc_road_frag_t f;
  static cc_road_pkt_t slot;
  static uint8_t pkt[5000];
  uint8_t frag[FRAGBUF_SZ];
  size_t total, i, n;
  int done = 0, bad_len = 0;

  for (i = 0; i < sizeof(pkt); i++) pkt[i] = (uint8_t)(i * 31 + 5);
  total = cc_road_frag_count(sizeof(pkt), BLE_PAYLOAD);

  printf("generic payload (243):\n");
  T("count", total == (sizeof(pkt) + BLE_PAYLOAD - 1) / BLE_PAYLOAD);
  /* The same full announce is 21 advertisements, per road_ble's MTU. */
  T("full announce", cc_road_frag_count(4886, BLE_PAYLOAD) == 21);

  cc_road_frag_init(&f);
  slot.len = 0;
  for (i = 0; i < total; i++) {
    n = cc_road_frag_encode(pkt, sizeof(pkt), 3, (uint8_t)i, (uint8_t)total,
                            BLE_PAYLOAD, frag);
    if (n <= CC_ROAD_FRAG_HDR || n > BLE_PAYLOAD + CC_ROAD_FRAG_HDR)
      bad_len = 1;
    done = cc_road_rx_frag(&f, frag, n, BLE_PAYLOAD, NULL, 0, &slot);
  }
  T("fragment lengths bounded", !bad_len);
  T("complete", done == CC_ROAD_RX_READY);
  T("length", slot.len == sizeof(pkt));
  T("bytes identical", memcmp(slot.buf, pkt, sizeof(pkt)) == 0);

  /* A fragment encoded for one MTU must not be accepted by another: the
   * payload size is not on the wire, so both ends must agree. */
  cc_road_frag_init(&f);
  slot.len = 0;
  n = cc_road_frag_encode(
      pkt, sizeof(pkt), 4, 0,
      (uint8_t)cc_road_frag_count(sizeof(pkt), CC_ROAD_FRAG_PAYLOAD),
      CC_ROAD_FRAG_PAYLOAD, frag);
  T("full-MTU fragment offered to a small-MTU peer",
    cc_road_rx_frag(&f, frag, n, BLE_PAYLOAD, NULL, 0, &slot) ==
        CC_ROAD_RX_BAD);
  cc_road_frag_init(&f);
  n = cc_road_frag_encode(pkt, sizeof(pkt), 5, 0,
                          (uint8_t)cc_road_frag_count(sizeof(pkt), BLE_PAYLOAD),
                          BLE_PAYLOAD, frag);
  T("small-MTU fragment accepted",
    cc_road_rx_frag(&f, frag, n, BLE_PAYLOAD, NULL, 0, &slot) ==
        CC_ROAD_RX_MORE);
}

/* The shared send loop, with a far end that reassembles what it hears. */
typedef struct {
  cc_road_frag_t frag;
  cc_road_pkt_t pkt;
  size_t payload;
  size_t emitted; /* fragments handed to the medium */
  size_t fail_at; /* refuse this fragment (1-based); 0 = never */
  int done;       /* last reassembly result */
} FarEnd;

static size_t far_emit(void* ctx, const uint8_t* frag, size_t len) {
  FarEnd* fe = (FarEnd*)ctx;
  fe->emitted++;
  if (fe->fail_at && fe->emitted == fe->fail_at)
    return 0; /* medium refused the fragment */
  fe->done =
      cc_road_rx_frag(&fe->frag, frag, len, fe->payload, NULL, 0, &fe->pkt);
  return len;
}

static void far_init(FarEnd* fe, size_t payload) {
  memset(fe, 0, sizeof(*fe));
  fe->payload = payload;
  cc_road_frag_init(&fe->frag);
}

static void test_send_pkt(void) {
  static uint8_t pkt[5000];
  static uint8_t big[CC_ROAD_PKT_BUF_SZ + 1];
  static FarEnd fe;
  size_t i;

  for (i = 0; i < sizeof(pkt); i++) pkt[i] = (uint8_t)(i * 11 + 7);
  printf("send helper:\n");

  far_init(&fe, CC_ROAD_FRAG_PAYLOAD);
  T("send ok", cc_road_send_pkt(pkt, sizeof(pkt), 9, CC_ROAD_FRAG_PAYLOAD,
                                far_emit, &fe) == CC_ROAD_OK);
  T("all fragments emitted",
    fe.emitted == cc_road_frag_count(sizeof(pkt), CC_ROAD_FRAG_PAYLOAD));
  T("far end complete", fe.done == CC_ROAD_RX_READY);
  T("packet received", fe.pkt.len == sizeof(pkt));
  T("bytes identical", memcmp(fe.pkt.buf, pkt, sizeof(pkt)) == 0);

  far_init(&fe, BLE_PAYLOAD);
  T("small MTU send ok", cc_road_send_pkt(pkt, sizeof(pkt), 10, BLE_PAYLOAD,
                                          far_emit, &fe) == CC_ROAD_OK);
  T("small MTU fragment count",
    fe.emitted == cc_road_frag_count(sizeof(pkt), BLE_PAYLOAD));
  T("small MTU received",
    fe.done == CC_ROAD_RX_READY && memcmp(fe.pkt.buf, pkt, sizeof(pkt)) == 0);

  far_init(&fe, CC_ROAD_FRAG_PAYLOAD);
  fe.fail_at = 3;
  T("emit failure fails the send",
    cc_road_send_pkt(pkt, sizeof(pkt), 11, CC_ROAD_FRAG_PAYLOAD, far_emit,
                     &fe) == CC_ROAD_ERR);
  T("stops at the failing fragment", fe.emitted == 3);

  far_init(&fe, CC_ROAD_FRAG_PAYLOAD);
  T("empty packet rejected", cc_road_send_pkt(pkt, 0, 12, CC_ROAD_FRAG_PAYLOAD,
                                              far_emit, &fe) == CC_ROAD_ERR);
  T("unfragmentable packet rejected",
    cc_road_send_pkt(big, sizeof(big), 13, CC_ROAD_FRAG_PAYLOAD, far_emit,
                     &fe) == CC_ROAD_ERR);
  T("nothing emitted", fe.emitted == 0);
  T("null emit rejected",
    cc_road_send_pkt(pkt, sizeof(pkt), 14, CC_ROAD_FRAG_PAYLOAD, NULL, &fe) ==
        CC_ROAD_ERR);
}

/* The slot holds one packet: a completion that recv() has not collected is
 * kept, and the newer packet is dropped instead of overwriting it. */
static void test_slot(void) {
  static cc_road_frag_t f;
  static cc_road_pkt_t slot;
  static uint8_t one[300], two[300], frag[FRAGBUF_SZ];
  static uint8_t out[CC_ROAD_PKT_BUF_SZ];
  static FarEnd fe;
  size_t len = 0, n;

  for (size_t i = 0; i < sizeof(one); i++) {
    one[i] = (uint8_t)(i + 1);
    two[i] = (uint8_t)(0xF0 - i);
  }
  printf("packet slot:\n");
  far_init(&fe, CC_ROAD_FRAG_PAYLOAD);
  T("empty slot read",
    cc_road_pkt_get(&fe.pkt, out, sizeof(out), &len) == CC_ROAD_ERR);

  cc_road_frag_init(&f);
  slot.len = 0;
  n = cc_road_frag_encode(one, sizeof(one), 20, 0, 2, CC_ROAD_FRAG_PAYLOAD,
                          frag);
  T("first packet part", cc_road_rx_frag(&f, frag, n, CC_ROAD_FRAG_PAYLOAD,
                                         NULL, 0, &slot) == CC_ROAD_RX_MORE);
  n = cc_road_frag_encode(one, sizeof(one), 20, 1, 2, CC_ROAD_FRAG_PAYLOAD,
                          frag);
  T("first packet complete",
    cc_road_rx_frag(&f, frag, n, CC_ROAD_FRAG_PAYLOAD, NULL, 0, &slot) ==
        CC_ROAD_RX_READY);
  T("read it back",
    cc_road_pkt_get(&slot, out, sizeof(out), &len) == CC_ROAD_OK &&
        len == sizeof(one) && memcmp(out, one, sizeof(one)) == 0);
  T("too small a buffer",
    cc_road_pkt_get(&slot, out, sizeof(one) - 1, &len) == CC_ROAD_ERR);

  /* A second packet completing while the slot is still occupied is dropped. */
  cc_road_frag_init(&f);
  n = cc_road_frag_encode(two, sizeof(two), 21, 0, 2, CC_ROAD_FRAG_PAYLOAD,
                          frag);
  T("second packet part", cc_road_rx_frag(&f, frag, n, CC_ROAD_FRAG_PAYLOAD,
                                          NULL, 0, &slot) == CC_ROAD_RX_MORE);
  n = cc_road_frag_encode(two, sizeof(two), 21, 1, 2, CC_ROAD_FRAG_PAYLOAD,
                          frag);
  T("busy slot drops the packet",
    cc_road_rx_frag(&f, frag, n, CC_ROAD_FRAG_PAYLOAD, NULL, 0, &slot) ==
        CC_ROAD_RX_BUSY);
  T("uncollected packet survives",
    slot.len == sizeof(one) && memcmp(slot.buf, one, sizeof(one)) == 0);

  /* recv() collecting it frees the slot for the next packet. */
  slot.len = 0;
  T("slot released",
    cc_road_pkt_get(&slot, out, sizeof(out), &len) == CC_ROAD_ERR);
  n = cc_road_frag_encode(two, sizeof(two), 22, 0, 2, CC_ROAD_FRAG_PAYLOAD,
                          frag);
  T("slot free again", cc_road_rx_frag(&f, frag, n, CC_ROAD_FRAG_PAYLOAD, NULL,
                                       0, &slot) == CC_ROAD_RX_MORE);
  n = cc_road_frag_encode(two, sizeof(two), 22, 1, 2, CC_ROAD_FRAG_PAYLOAD,
                          frag);
  T("next packet stored", cc_road_rx_frag(&f, frag, n, CC_ROAD_FRAG_PAYLOAD,
                                          NULL, 0, &slot) == CC_ROAD_RX_READY);
  T("second packet in slot",
    slot.len == sizeof(two) && memcmp(slot.buf, two, sizeof(two)) == 0);
}

/* The link-layer source contract, exercised the way an application sees it: a
 * fake road with the same shape as the four real ones — one slot, and a recv()
 * that hands the packet over together with its source. The real roads cannot
 * run on the host (their media are behind __has_include), so this is what
 * fixes the contract they implement. */
typedef struct {
  cc_road_t road;
  cc_road_frag_t frag;
  cc_road_pkt_t pkt;
} SrcRoad;

static int src_road_recv(cc_road_t* road, uint8_t* buf, size_t buf_sz,
                         size_t* len_out) {
  SrcRoad* sr = (SrcRoad*)road->ctx;
  int ret;

  if (sr->pkt.len == 0)
    return CC_ROAD_EMPTY;
  ret = cc_road_pkt_get(&sr->pkt, buf, buf_sz, len_out);
  if (ret == CC_ROAD_OK)
    cc_road_src_take(&sr->pkt, road);
  sr->pkt.len = 0; /* release the slot */
  return ret;
}

/* One single-fragment packet arriving, optionally attributed to `src`. */
static int src_road_rx(SrcRoad* sr, const uint8_t* pkt, size_t len,
                       const uint8_t* src, size_t src_len, uint8_t id) {
  uint8_t frag[FRAGBUF_SZ];
  size_t n =
      cc_road_frag_encode(pkt, len, id, 0, 1, CC_ROAD_FRAG_PAYLOAD, frag);

  cc_road_frag_init(&sr->frag);
  if (n == 0)
    return CC_ROAD_RX_BAD;
  return cc_road_rx_frag(&sr->frag, frag, n, CC_ROAD_FRAG_PAYLOAD, src, src_len,
                         &sr->pkt);
}

static void test_source_contract(void) {
  static SrcRoad sr;
  static uint8_t pkt[600], out[128];
  static const uint8_t mac[CC_ROAD_SRC_SZ] = {0x02, 0x11, 0x22,
                                              0x33, 0x44, 0x55};
  static const uint8_t other[CC_ROAD_SRC_SZ] = {0x02, 0xaa, 0xbb,
                                                0xcc, 0xdd, 0xee};
  uint8_t toolong[CC_ROAD_SRC_SZ + 1] = {1, 2, 3, 4, 5, 6, 7};
  const size_t small = 100; /* one fragment */
  size_t len = 0;

  memset(&sr, 0, sizeof(sr));
  sr.road.name = "fake";
  sr.road.ctx = &sr;
  sr.road.recv = src_road_recv;
  memset(pkt, 0x5a, sizeof(pkt));

  printf("link-layer source:\n");
  T("documented size", CC_ROAD_SRC_SZ == 6);
  T("field size", sizeof(sr.road.last_src) == CC_ROAD_SRC_SZ);
  T("starts unknown", sr.road.last_src_len == 0);

  /* A road whose medium can attribute: the source arrives with the packet and
   * is readable through cc_road_t. */
  T("attributed packet stored",
    src_road_rx(&sr, pkt, small, mac, sizeof(mac), 40) == CC_ROAD_RX_READY);
  T("readable through the interface",
    src_road_recv(&sr.road, out, sizeof(out), &len) == CC_ROAD_OK &&
        len == small);
  T("source length", sr.road.last_src_len == sizeof(mac));
  T("source bytes", memcmp(sr.road.last_src, mac, sizeof(mac)) == 0);

  /* The source follows the packet, not the road's history. */
  T("second attributed packet",
    src_road_rx(&sr, pkt, small, other, sizeof(other), 41) == CC_ROAD_RX_READY);
  src_road_recv(&sr.road, out, sizeof(out), &len);
  T("source follows the packet",
    sr.road.last_src_len == sizeof(other) &&
        memcmp(sr.road.last_src, other, sizeof(other)) == 0);

  /* A medium that cannot attribute says so instead of leaving the previous
   * packet's source in place. */
  T("unattributed packet stored",
    src_road_rx(&sr, pkt, small, NULL, 0, 42) == CC_ROAD_RX_READY);
  T("unknown, not stale",
    src_road_recv(&sr.road, out, sizeof(out), &len) == CC_ROAD_OK &&
        sr.road.last_src_len == 0);

  /* An over-long source is unknown, never a truncated (colliding) identity. */
  T("over-long source stored",
    src_road_rx(&sr, pkt, small, toolong, sizeof(toolong), 43) ==
        CC_ROAD_RX_READY);
  src_road_recv(&sr.road, out, sizeof(out), &len);
  T("over-long source is unknown", sr.road.last_src_len == 0);

  /* A recv() with nothing waiting hands over nothing: the field keeps
   * describing the last packet that was actually delivered. */
  T("attributed again",
    src_road_rx(&sr, pkt, small, mac, sizeof(mac), 44) == CC_ROAD_RX_READY);
  src_road_recv(&sr.road, out, sizeof(out), &len);
  T("empty recv",
    src_road_recv(&sr.road, out, sizeof(out), &len) == CC_ROAD_EMPTY);
  T("empty recv changes nothing",
    sr.road.last_src_len == sizeof(mac) &&
        memcmp(sr.road.last_src, mac, sizeof(mac)) == 0);

  /* A packet dropped because the slot was still full must not re-attribute the
   * packet still waiting for recv(). */
  T("packet waiting",
    src_road_rx(&sr, pkt, small, mac, sizeof(mac), 45) == CC_ROAD_RX_READY);
  T("second completion dropped",
    src_road_rx(&sr, pkt, small, other, sizeof(other), 46) == CC_ROAD_RX_BUSY);
  src_road_recv(&sr.road, out, sizeof(out), &len);
  T("dropped packet did not re-attribute",
    sr.road.last_src_len == sizeof(mac) &&
        memcmp(sr.road.last_src, mac, sizeof(mac)) == 0);

  /* A half-arrived packet carries no source: nothing was delivered, and the
   * field still describes the last packet that was. */
  cc_road_frag_init(&sr.frag);
  {
    uint8_t frag[FRAGBUF_SZ];
    size_t half = cc_road_frag_encode(pkt, small * 3, 47, 0, 2,
                                      CC_ROAD_FRAG_PAYLOAD, frag);
    T("partial fragment stored",
      cc_road_rx_frag(&sr.frag, frag, half, CC_ROAD_FRAG_PAYLOAD, other,
                      sizeof(other), &sr.pkt) == CC_ROAD_RX_MORE);
  }
  T("nothing published by a fragment", sr.pkt.len == 0);
  T("last delivered packet unchanged",
    sr.road.last_src_len == sizeof(mac) &&
        memcmp(sr.road.last_src, mac, sizeof(mac)) == 0);

  /* A slot holding no packet has no source to hand over, even though the
   * packet that was in it came from somewhere. */
  sr.pkt.len = 0;
  cc_road_src_take(&sr.pkt, &sr.road);
  T("empty slot reports unknown", sr.road.last_src_len == 0);
}

int main(void) {
  test_count();
  test_encode_rejects();
  test_roundtrip_out_of_order();
  test_duplicates();
  test_duplicate_conflict();
  test_short_fragment();
  test_rejects();
  test_interleave();
  test_generic_payload();
  test_send_pkt();
  test_slot();
  test_source_contract();
  printf("\n%d passed, %d failed\n", g_passed, g_failed);
  return g_failed == 0 ? 0 : 1;
}
