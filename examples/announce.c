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

int main(void) {
  /* The library keeps no state of its own: this is the per-caller
     working memory (static here, as it must be on an MCU). */
  static cc_work_t w;
  WC_RNG rng;
  static cc_key_t key;
  static cc_announce_t ann;
  cc_presence_t pres;
  static uint8_t ann_pkt[CC_ANN_BUF_SZ];
  uint8_t pres_pkt[CC_PRES_BUF_SZ];
  uint8_t req_pkt[CC_KEY_REQ_BUF_SZ];
  size_t ann_len = 0, pres_len = 0, req_len = 0;
  /* Freshness counters must increase per packet; a real node persists them
   * across reboots so a receiver's replay window survives a restart. */
  uint32_t pres_counter = 1, req_counter = 2, parsed_req_counter = 0;
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
  ret = cc_announce_build(&w, &key, "Alice", 5, NULL, 0, NULL, 1, 0, ann_pkt,
                          sizeof(ann_pkt), &ann_len, &rng);
  printf("announce: %s (%zu bytes, ~%zu LoRa fragments)\n",
         ret == CC_OK ? "ok" : "FAILED", ann_len, (ann_len + 247) / 248);

  ret = cc_announce_parse(&w, ann_pkt, ann_len, &ann);
  printf("announce parse: %s, name='%.*s'\n", ret == CC_OK ? "ok" : "FAILED",
         (int)ann.name_len, ann.name);
  /* The announce also publishes what this node asks senders to mine for the
     directed types: chat, link_req, key_req. */
  printf("declared PoW cost: chat=%u link_req=%u key_req=%u\n",
         ann.admit[CC_ADMIT_CHAT], ann.admit[CC_ADMIT_LINK_REQ],
         ann.admit[CC_ADMIT_KEY_REQ]);

  /* --- Presence (sent every ~60 s) --- */
  ret = cc_presence_build(&w, &key, "Alice", 5, pres_counter, pres_pkt,
                          sizeof(pres_pkt), &pres_len, &rng);
  printf("presence: %s (%zu bytes, fits in 1 LoRa fragment, seq=%u)\n",
         ret == CC_OK ? "ok" : "FAILED", pres_len, pres_counter);

  ret = cc_presence_parse(&w, pres_pkt, pres_len, &pres);
  printf("presence parse: %s, addr_match=%s, seq=%u\n",
         ret == CC_OK ? "ok" : "FAILED",
         memcmp(pres.addr, addr, CC_ADDR_SZ) == 0 ? "yes" : "no", pres.seq);
  /* The name is not in the packet: it carries a hash to check against the
     announce we already verified. */
  printf("name_hash matches the verified announce: %s\n",
         cc_presence_matches_announce(&pres, &ann) == CC_OK ? "yes" : "no");

  /* --- Key request (sent when a presence arrives for an unknown addr) --- */
  ret = cc_key_req_build(&w, addr, req_counter, 0, req_pkt, sizeof(req_pkt),
                         &req_len);
  printf("key_req: %s (%zu bytes, counter=%u)\n",
         ret == CC_OK ? "ok" : "FAILED", req_len, req_counter);

  ret = cc_key_req_parse(&w, req_pkt, req_len, parsed_req_addr,
                         &parsed_req_counter);
  printf("key_req parse: %s, addr_match=%s, counter=%u\n",
         ret == CC_OK ? "ok" : "FAILED",
         memcmp(parsed_req_addr, addr, CC_ADDR_SZ) == 0 ? "yes" : "no",
         parsed_req_counter);

  cc_key_free(&key);
  wc_FreeRng(&rng);
  return 0;
}
