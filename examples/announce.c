/* announce.c — demonstrates full-announce (boot) + presence (periodic) split.
 *
 * In a real mesh node:
 *   - Send cc_announce once at boot (and when responding to CC_MSG_KEY_REQ).
 *   - Send cc_presence every ~60 s to signal you are reachable.
 *   - Nodes that receive a presence for an unknown addr send CC_MSG_KEY_REQ.
 */
#include <stdio.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/random.h>

#include "cosechat.h"

#define ANN_BUF_SZ  6144
#define PRES_BUF_SZ  128
#define KEY_REQ_SZ    32

int main(void) {
  WC_RNG rng;
  static cc_key_t key;
  static cc_announce_t ann;
  cc_presence_t pres;
  static uint8_t ann_pkt[ANN_BUF_SZ];
  uint8_t pres_pkt[PRES_BUF_SZ];
  uint8_t req_pkt[KEY_REQ_SZ];
  size_t ann_len = 0, pres_len = 0, req_len = 0;
  uint8_t addr[CC_ADDR_SZ];
  uint8_t parsed_req_addr[CC_ADDR_SZ];
  int i, ret;

  wc_InitRng(&rng);
  cc_key_generate(&key, &rng);
  cc_addr_from_key(&key, addr);

  printf("addr: ");
  for (i = 0; i < CC_ADDR_SZ; i++) printf("%02x", addr[i]);
  printf("\n");

  /* --- Full announce (sent at boot / in response to key_req) --- */
  ret = cc_announce_build(&key, "Alice", 5, NULL, 0,
                          ann_pkt, sizeof(ann_pkt), &ann_len, &rng);
  printf("announce: %s (%zu bytes, ~%zu LoRa fragments)\n",
         ret == CC_OK ? "ok" : "FAILED", ann_len,
         (ann_len + 247) / 248);

  ret = cc_announce_parse(ann_pkt, ann_len, &ann);
  printf("announce parse: %s, name='%.*s'\n",
         ret == CC_OK ? "ok" : "FAILED", (int)ann.name_len, ann.name);

  /* --- Presence (sent every ~60 s) --- */
  ret = cc_presence_build(&key, "Alice", 5,
                          pres_pkt, sizeof(pres_pkt), &pres_len, &rng);
  printf("presence: %s (%zu bytes, fits in 1 LoRa fragment)\n",
         ret == CC_OK ? "ok" : "FAILED", pres_len);

  ret = cc_presence_parse(pres_pkt, pres_len, &pres);
  printf("presence parse: %s, name='%.*s', addr_match=%s\n",
         ret == CC_OK ? "ok" : "FAILED",
         (int)pres.name_len, pres.name,
         memcmp(pres.addr, addr, CC_ADDR_SZ) == 0 ? "yes" : "no");

  /* --- Key request (sent when a presence arrives for an unknown addr) --- */
  ret = cc_key_req_build(addr, req_pkt, sizeof(req_pkt), &req_len);
  printf("key_req: %s (%zu bytes)\n",
         ret == CC_OK ? "ok" : "FAILED", req_len);

  ret = cc_key_req_parse(req_pkt, req_len, parsed_req_addr);
  printf("key_req parse: %s, addr_match=%s\n",
         ret == CC_OK ? "ok" : "FAILED",
         memcmp(parsed_req_addr, addr, CC_ADDR_SZ) == 0 ? "yes" : "no");

  cc_key_free(&key);
  wc_FreeRng(&rng);
  return 0;
}
