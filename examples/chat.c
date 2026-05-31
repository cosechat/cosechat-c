/* chat.c — end-to-end flow using the announce/presence split:
 *
 *   1. Bob builds a full announce (boot).
 *   2. Bob later sends a presence (periodic heartbeat).
 *   3. Alice receives Bob's presence for an unknown addr → sends key_req.
 *   4. Bob receives the key_req for his addr → re-sends his announce.
 *   5. Alice parses the announce and now has Bob's keys.
 *   6. Alice sends a chat to Bob.
 *   7. Bob decrypts and verifies sender addr.
 */
#include <stdio.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/random.h>

#include "cosechat.h"

#define ANN_BUF_SZ 6144
#define CHAT_BUF_SZ 2048
#define PRES_BUF_SZ 128
#define KEY_REQ_SZ 32

int main(void) {
  WC_RNG rng;
  static cc_key_t alice, bob;
  static cc_announce_t bob_ann;
  static cc_chat_t chat;
  cc_presence_t bob_pres;
  static uint8_t ann_pkt[ANN_BUF_SZ];
  static uint8_t chat_pkt[CHAT_BUF_SZ];
  uint8_t pres_pkt[PRES_BUF_SZ];
  uint8_t req_pkt[KEY_REQ_SZ];
  uint8_t req_addr[CC_ADDR_SZ];
  uint8_t bob_addr[CC_ADDR_SZ], alice_addr[CC_ADDR_SZ], recip[CC_ADDR_SZ];
  size_t ann_len = 0, chat_len = 0, pres_len = 0, req_len = 0;
  static const char msg[] = "Hello Bob!";
  int i, ret;

  wc_InitRng(&rng);
  cc_key_generate(&alice, &rng);
  cc_key_generate(&bob, &rng);
  cc_addr_from_key(&bob, bob_addr);
  cc_addr_from_key(&alice, alice_addr);

  printf("bob addr:   ");
  for (i = 0; i < CC_ADDR_SZ; i++) printf("%02x", bob_addr[i]);
  printf("\nalice addr: ");
  for (i = 0; i < CC_ADDR_SZ; i++) printf("%02x", alice_addr[i]);
  printf("\n\n");

  /* 1. Bob announces at boot (~21 LoRa fragments) */
  ret = cc_announce_build(&bob, "Bob", 3, NULL, 0, ann_pkt, sizeof(ann_pkt),
                          &ann_len, &rng);
  printf("1. bob announce: %s (%zu bytes, ~%zu frags)\n",
         ret == CC_OK ? "ok" : "FAILED", ann_len, (ann_len + 247) / 248);

  /* 2. Bob sends periodic presence (~1 LoRa fragment) */
  ret = cc_presence_build(&bob, "Bob", 3, pres_pkt, sizeof(pres_pkt), &pres_len,
                          &rng);
  printf("2. bob presence: %s (%zu bytes, 1 frag)\n",
         ret == CC_OK ? "ok" : "FAILED", pres_len);

  /* 3. Alice receives presence for unknown addr → builds key_req */
  ret = cc_presence_parse(pres_pkt, pres_len, &bob_pres);
  printf("3. alice parses presence: %s, name='%.*s'\n",
         ret == CC_OK ? "ok" : "FAILED", (int)bob_pres.name_len, bob_pres.name);

  ret = cc_key_req_build(bob_pres.addr, req_pkt, sizeof(req_pkt), &req_len);
  printf("   alice sends key_req: %s (%zu bytes)\n",
         ret == CC_OK ? "ok" : "FAILED", req_len);

  /* 4. Bob receives key_req for his addr → re-sends announce */
  ret = cc_key_req_parse(req_pkt, req_len, req_addr);
  printf("4. bob parses key_req: %s, for_me=%s\n",
         ret == CC_OK ? "ok" : "FAILED",
         memcmp(req_addr, bob_addr, CC_ADDR_SZ) == 0 ? "yes" : "no");
  /* Bob re-sends his announce (already built above, would retransmit ann_pkt)
   */

  /* 5. Alice parses bob's announce, now has his keys */
  ret = cc_announce_parse(ann_pkt, ann_len, &bob_ann);
  printf("5. alice parses announce: %s\n", ret == CC_OK ? "ok" : "FAILED");

  /* 6. Alice sends chat to Bob using addr + KEM pubkey from announce */
  ret = cc_chat_build(&alice, bob_ann.addr, bob_ann.kem_pubkey,
                      (const uint8_t*)msg, strlen(msg), chat_pkt,
                      sizeof(chat_pkt), &chat_len, &rng);
  printf("6. alice sends chat: %s (%zu bytes, ~%zu frags)\n",
         ret == CC_OK ? "ok" : "FAILED", chat_len, (chat_len + 247) / 248);

  cc_msg_recipient(chat_pkt, chat_len, recip);
  printf("   recipient matches bob: %s\n",
         memcmp(recip, bob_addr, CC_ADDR_SZ) == 0 ? "yes" : "no");

  /* 7. Bob decrypts */
  ret = cc_chat_parse(&bob, chat_pkt, chat_len, &chat);
  printf("7. bob decrypts: %s\n", ret == CC_OK ? "ok" : "FAILED");
  if (ret == CC_OK) {
    printf("   message: %.*s\n", (int)chat.msg_len, (char*)chat.msg);
    printf(
        "   sender is alice: %s\n",
        memcmp(chat.sender_addr, alice_addr, CC_ADDR_SZ) == 0 ? "yes" : "no");
  }

  cc_key_free(&alice);
  cc_key_free(&bob);
  wc_FreeRng(&rng);
  return 0;
}
