#include <stdio.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/random.h>

#include "cosechat.h"

int main(void) {
  WC_RNG rng;
  cc_key_t key;
  uint8_t pkt[1024];
  size_t pkt_len = 0;
  cc_announce_t ann;
  uint8_t pkt2[1024];
  size_t pkt2_len = 0;
  uint8_t type;
  uint8_t hops;
  int i, ret;

  wc_InitRng(&rng);
  cc_key_generate(&key, &rng);

  /* Build announce with name "Alice" and no extra metadata */
  ret = cc_announce_build(&key, "Alice", 5, NULL, 0, pkt, sizeof(pkt), &pkt_len,
                          &rng);
  if (ret != CC_OK) {
    printf("build error: %d\n", ret);
    return 1;
  }
  printf("announce: %zu bytes\n", pkt_len);

  cc_msg_type(pkt, pkt_len, &type);
  printf("type: %s\n", type == CC_MSG_ANNOUNCE ? "ANNOUNCE" : "?");

  /* Parse — verifies PoW and signature */
  ret = cc_announce_parse(pkt, pkt_len, &ann);
  if (ret != CC_OK) {
    printf("parse error: %d\n", ret);
    return 1;
  }

  printf("name: %.*s\n", (int)ann.name_len, ann.name);
  printf("hops: %d\n", ann.hops);
  printf("addr: ");
  for (i = 0; i < CC_ADDR_SZ; i++) printf("%02x", ann.addr[i]);
  printf("\n");

  /* Simulate router incrementing hops */
  cc_hops_increment(pkt, pkt_len, pkt2, sizeof(pkt2), &pkt2_len);
  cc_msg_hops(pkt2, pkt2_len, &hops);
  printf("after hop: hops=%d, parses_ok=%s\n", hops,
         cc_announce_parse(pkt2, pkt2_len, &ann) == CC_OK ? "yes" : "no");

  cc_key_free(&key);
  wc_FreeRng(&rng);
  return 0;
}
