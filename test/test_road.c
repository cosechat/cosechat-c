/* test_road.c — road framing (fragmentation + reassembly) contract.
 *
 * The road framing lives in include/road.h and is shared by road_lora and
 * road_wifi, so it is exercised here on the host rather than on hardware. */
#include <stdio.h>
#include <string.h>

#include "road.h"

#define FRAGBUF_SZ (CC_ROAD_FRAG_MAX_PAYLOAD + CC_ROAD_FRAG_HDR)

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
  T("zero", cc_road_frag_count(0) == 0);
  T("one byte", cc_road_frag_count(1) == 1);
  T("exact payload", cc_road_frag_count(CC_ROAD_FRAG_MAX_PAYLOAD) == 1);
  T("payload+1", cc_road_frag_count(CC_ROAD_FRAG_MAX_PAYLOAD + 1) == 2);
  T("announce sized", cc_road_frag_count(5000) == 21);
  T("max", cc_road_frag_count(CC_ROAD_PKT_BUF_SZ) == CC_ROAD_FRAG_MAX_TOTAL);
  T("too big", cc_road_frag_count(CC_ROAD_PKT_BUF_SZ + 1) == 0);
}

static void test_encode_rejects(void) {
  uint8_t pkt[8] = {0};
  uint8_t out[FRAGBUF_SZ];
  printf("encode:\n");
  T("idx >= total", cc_road_frag_encode(pkt, sizeof(pkt), 1, 1, 1, out) == 0);
  T("total 0", cc_road_frag_encode(pkt, sizeof(pkt), 1, 0, 0, out) == 0);
  T("null pkt", cc_road_frag_encode(NULL, sizeof(pkt), 1, 0, 1, out) == 0);
  T("offset past end", cc_road_frag_encode(pkt, 1, 1, 1, 2, out) == 0);
}

/* Feed fragments out of order and confirm the packet is rebuilt byte-exact. */
static void test_roundtrip_out_of_order(void) {
  static cc_road_frag_t f;
  static uint8_t pkt[5000];
  static uint8_t frag[FRAGBUF_SZ];
  size_t total, i;
  int done = 0;

  for (i = 0; i < sizeof(pkt); i++) pkt[i] = (uint8_t)(i * 7 + 3);
  total = cc_road_frag_count(sizeof(pkt));

  printf("round-trip (reversed order):\n");
  cc_road_frag_init(&f);
  int bad_len = 0, early = 0;
  for (i = total; i-- > 0;) {
    size_t n = cc_road_frag_encode(pkt, sizeof(pkt), 42, (uint8_t)i,
                                   (uint8_t)total, frag);
    if (n <= CC_ROAD_FRAG_HDR || n > FRAGBUF_SZ)
      bad_len = 1;
    done = cc_road_frag_feed(&f, frag, n);
    if (i != 0 && done != 0)
      early = 1;
  }
  T("fragment lengths sane", !bad_len);
  T("incomplete until first frag", !early);
  T("complete", done == 1);
  T("length", f.len == sizeof(pkt));
  T("bytes identical", memcmp(f.buf, pkt, sizeof(pkt)) == 0);
}

/* Duplicate fragments must not corrupt or complete early. */
static void test_duplicates(void) {
  static cc_road_frag_t f;
  static uint8_t pkt[600];
  static uint8_t frag[FRAGBUF_SZ];
  size_t total = cc_road_frag_count(sizeof(pkt));
  size_t i, n;
  int done = 0;

  for (i = 0; i < sizeof(pkt); i++) pkt[i] = (uint8_t)i;
  printf("duplicates:\n");
  cc_road_frag_init(&f);
  for (i = 0; i < total; i++) {
    n = cc_road_frag_encode(pkt, sizeof(pkt), 7, (uint8_t)i, (uint8_t)total,
                            frag);
    done = cc_road_frag_feed(&f, frag, n);
    if (i + 1 < total) {
      /* resend a non-final fragment; must be idempotent */
      done = cc_road_frag_feed(&f, frag, n);
      T("duplicate does not complete", done == 0);
    }
  }
  T("complete", done == 1);
  T("bytes identical", memcmp(f.buf, pkt, sizeof(pkt)) == 0);
}

static void test_rejects(void) {
  static cc_road_frag_t f;
  uint8_t frag[FRAGBUF_SZ];
  uint8_t pkt[300];
  size_t total = cc_road_frag_count(sizeof(pkt));
  size_t n0 = cc_road_frag_encode(pkt, sizeof(pkt), 1, 0, (uint8_t)total, frag);
  size_t n1 = cc_road_frag_encode(pkt, sizeof(pkt), 1, 1, (uint8_t)total, frag);

  printf("rejects:\n");
  cc_road_frag_init(&f);
  T("short packet", cc_road_frag_feed(&f, frag, CC_ROAD_FRAG_HDR) == -1);

  frag[0] = 0x00;
  T("bad magic", cc_road_frag_feed(&f, frag, n0) == -1);

  cc_road_frag_init(&f);
  n0 = cc_road_frag_encode(pkt, sizeof(pkt), 1, 0, (uint8_t)total, frag);
  n1 = cc_road_frag_encode(pkt, sizeof(pkt), 1, 1, (uint8_t)total, frag);
  frag[2] = total; /* idx == total */
  T("idx out of range", cc_road_frag_feed(&f, frag, n0) == -1);

  cc_road_frag_init(&f);
  n0 = cc_road_frag_encode(pkt, sizeof(pkt), 1, 0, (uint8_t)total, frag);
  cc_road_frag_feed(&f, frag, n0);
  frag[3] = (uint8_t)(total + 1); /* same msg_id, different total */
  T("total changed mid-assembly", cc_road_frag_feed(&f, frag, n1) == -1);
}

/* A new msg_id abandons the partial assembly and starts fresh. */
static void test_interleave(void) {
  static cc_road_frag_t f;
  static uint8_t pkt[600];
  static uint8_t frag[FRAGBUF_SZ];
  size_t total = cc_road_frag_count(sizeof(pkt));
  size_t i, n;
  int done = 0;

  for (i = 0; i < sizeof(pkt); i++) pkt[i] = (uint8_t)(255 - i);
  printf("interleaved msg ids:\n");
  cc_road_frag_init(&f);
  /* first fragment of message 1, never completed */
  n = cc_road_frag_encode(pkt, sizeof(pkt), 1, 0, (uint8_t)total, frag);
  cc_road_frag_feed(&f, frag, n);
  /* all of message 2 */
  for (i = 0; i < total; i++) {
    n = cc_road_frag_encode(pkt, sizeof(pkt), 2, (uint8_t)i, (uint8_t)total,
                            frag);
    done = cc_road_frag_feed(&f, frag, n);
  }
  T("complete", done == 1);
  T("bytes identical", memcmp(f.buf, pkt, sizeof(pkt)) == 0);
}

/* A road whose MTU is smaller than the default payload (BLE advertising) uses
 * the same framing with an explicit fragment payload. */
static void test_generic_payload(void) {
  static cc_road_frag_t f;
  static uint8_t pkt[5000];
  uint8_t frag[CC_ROAD_FRAG_HDR + CC_ROAD_FRAG_MAX_PAYLOAD];
  const size_t payload = 243; /* CC_ROAD_BLE_FRAG_PAYLOAD */
  size_t total, i, n;
  int done = 0, bad_len = 0;

  for (i = 0; i < sizeof(pkt); i++) pkt[i] = (uint8_t)(i * 31 + 5);
  total = cc_road_frag_count_n(sizeof(pkt), payload);

  printf("generic payload (243):\n");
  T("count", total == (sizeof(pkt) + payload - 1) / payload);
  T("zero payload rejected", cc_road_frag_count_n(sizeof(pkt), 0) == 0);
  T("zero length", cc_road_frag_count_n(0, payload) == 0);

  cc_road_frag_init(&f);
  for (i = 0; i < total; i++) {
    n = cc_road_frag_encode_n(pkt, sizeof(pkt), 3, (uint8_t)i, (uint8_t)total,
                              payload, frag);
    if (n <= CC_ROAD_FRAG_HDR || n > payload + CC_ROAD_FRAG_HDR)
      bad_len = 1;
    done = cc_road_frag_feed_n(&f, frag, n, payload);
  }
  T("fragment lengths bounded", !bad_len);
  T("complete", done == 1);
  T("length", f.len == sizeof(pkt));
  T("bytes identical", memcmp(f.buf, pkt, sizeof(pkt)) == 0);

  /* A fragment encoded for one MTU must not be accepted by another. */
  cc_road_frag_init(&f);
  n = cc_road_frag_encode(pkt, sizeof(pkt), 4, 0, 2, frag);
  T("foreign MTU rejected", cc_road_frag_feed_n(&f, frag, n, payload) == -1);
  cc_road_frag_init(&f);
  n = cc_road_frag_encode_n(pkt, sizeof(pkt), 5, 0, 2, payload, frag);
  T("own MTU accepted", cc_road_frag_feed_n(&f, frag, n, payload) == 0);
}

int main(void) {
  test_count();
  test_encode_rejects();
  test_roundtrip_out_of_order();
  test_duplicates();
  test_rejects();
  test_interleave();
  test_generic_payload();
  printf("\n%d passed, %d failed\n", g_passed, g_failed);
  return g_failed == 0 ? 0 : 1;
}
